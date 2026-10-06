package audit

import (
	"errors"
	"os"
	"testing"
)

// 崩溃恢复：最后一条记录只写了一半，重启后不得读到半条记录，
// 且后续追加的序号不得跳跃。
func TestRecoveryTruncatesPartialFrame(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append("a", "op", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	// 模拟崩溃：向活跃段写入半帧。
	segs, _ := listSegments(dir)
	f, err := os.OpenFile(segs[len(segs)-1].path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0, 0, 0, 50, 1, 2, 3}) // 声明 50 字节但只写了 3 字节
	f.Close()

	l2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	if l2.LastSeq() != 5 {
		t.Fatalf("lastSeq = %d, want 5", l2.LastSeq())
	}
	// 序号继续递增，无跳跃。
	seq, err := l2.Append("a", "op", []byte{9})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 6 {
		t.Fatalf("seq after recovery = %d, want 6", seq)
	}
	if err := l2.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 第一条记录就不完整 → 一条记录都不保留。
func TestRecoveryAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir}
	l, _ := Open(cfg)
	l.Append("a", "op", []byte("payload-bytes"))
	l.Close()

	segs, _ := listSegments(dir)
	// 把唯一段截断到第一帧中间。
	data, _ := os.ReadFile(segs[0].path)
	os.WriteFile(segs[0].path, data[:len(data)/2], 0o644)

	l2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	if l2.LastSeq() != 0 {
		t.Fatalf("lastSeq = %d, want 0", l2.LastSeq())
	}
	if err := l2.Verify(); err != nil {
		t.Fatalf("verify empty: %v", err)
	}
}

// 非末尾段出现半帧 → 恢复不一致，报可区分错误。
func TestRecoveryInconsistentMiddleSegment(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SegmentMaxBytes: 128, SyncEveryWrite: true}
	l, _ := Open(cfg)
	for i := 0; i < 20; i++ {
		l.Append("a", "op", []byte{byte(i), byte(i), byte(i)})
	}
	l.Close()
	segs, _ := listSegments(dir)
	if len(segs) < 2 {
		t.Fatalf("want multiple segments, got %d", len(segs))
	}
	// 在第一个（已封存）段尾部追加垃圾。
	f, _ := os.OpenFile(segs[0].path, os.O_WRONLY|os.O_APPEND, 0o644)
	f.Write([]byte{0, 0})
	f.Close()

	_, err := Open(cfg)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeRecover {
		t.Fatalf("want recover error, got %v", err)
	}
}

// 篡改检测：改写已提交记录的内容，Verify 必须定位到该条。
func TestTamperDetection(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, _ := Open(cfg)
	l.Append("alice", "transfer", []byte("amount=100"))
	l.Append("alice", "transfer", []byte("amount=200"))
	l.Append("alice", "transfer", []byte("amount=300"))

	// 打开状态下直接改盘：把 "amount=200" 改成 "amount=900"。
	segs, _ := listSegments(dir)
	data, _ := os.ReadFile(segs[0].path)
	idx := -1
	for i := 0; i+3 <= len(data); i++ {
		if string(data[i:i+3]) == "200" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("marker not found")
	}
	data[idx] = '9'
	os.WriteFile(segs[0].path, data, 0o644)

	err := l.Verify()
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeVerify {
		t.Fatalf("want verify error, got %v", err)
	}
	if ae.Seq != 2 {
		t.Fatalf("tamper located at seq %d, want 2", ae.Seq)
	}
}

// 删除历史记录（截断段文件）必须被检测。
func TestDeletionDetection(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, _ := Open(cfg)
	for i := 0; i < 5; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	segs, _ := listSegments(dir)
	info, _ := os.Stat(segs[0].path)
	os.Truncate(segs[0].path, info.Size()-10) // 砍掉最后一帧的尾巴

	err := l.Verify()
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeVerify {
		t.Fatalf("want verify error, got %v", err)
	}
	if ae.Seq != 5 {
		t.Fatalf("deletion located at seq %d, want 5", ae.Seq)
	}
}

// 改写一条记录并重算其哈希（聪明攻击者）→ 链在下一条断裂。
func TestRewrittenHashChainBreaks(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, _ := Open(cfg)
	for i := 0; i < 4; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	l.Close()

	segs, _ := listSegments(dir)
	recs, err := readSegment(segs[0].path)
	if err != nil {
		t.Fatal(err)
	}
	// 攻击者改写第 2 条并重算哈希，但无法修正第 3 条的 PrevHash。
	recs[1].Payload = []byte{0xFF}
	recs[1].Hash = computeHash(recs[1].PrevHash, recs[1].Seq, recs[1].Timestamp,
		recs[1].Actor, recs[1].Action, recs[1].Payload)
	var out []byte
	for _, r := range recs {
		out = append(out, encodeRecord(r)...)
	}
	os.WriteFile(segs[0].path, out, 0o644)

	_, err = Open(cfg)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeRecover {
		t.Fatalf("want recover error, got %v", err)
	}
	if ae.Seq != 3 {
		t.Fatalf("chain break located at seq %d, want 3", ae.Seq)
	}
}
