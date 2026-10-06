package audit

import (
	"errors"
	"os"
	"testing"
	"time"
)

// 旧段删除：剩余部分仍可校验，截断证明保留被删历史的链头。
func TestRetentionDeletesExpiredSegments(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:             dir,
		SegmentMaxBytes: 200, // 小段，强制轮转
		RetentionAge:    time.Millisecond,
		SyncEveryWrite:  true,
	}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if _, err := l.Append("a", "op", []byte{byte(i), byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	segsBefore, _ := listSegments(dir)
	if len(segsBefore) < 3 {
		t.Fatalf("want >=3 segments, got %d", len(segsBefore))
	}
	// 让所有封存段都过期。
	time.Sleep(5 * time.Millisecond)

	l2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if err := l2.ApplyRetention(); err != nil {
		t.Fatalf("retention: %v", err)
	}
	segsAfter, _ := listSegments(dir)
	if len(segsAfter) >= len(segsBefore) {
		t.Fatalf("segments not deleted: before=%d after=%d", len(segsBefore), len(segsAfter))
	}
	// 活跃段永不删除。
	if l2.LastSeq() != 30 {
		t.Fatalf("lastSeq = %d, want 30", l2.LastSeq())
	}
	// 剩余链仍可校验（以截断证明为起点）。
	if err := l2.Verify(); err != nil {
		t.Fatalf("verify after retention: %v", err)
	}
	// 截断证明必须存在且能证明被删历史确实提交过。
	proof, err := loadTruncationProof(dir)
	if err != nil {
		t.Fatal(err)
	}
	if proof.LastSeq == 0 || proof.LastSeq >= 30 {
		t.Fatalf("bad truncation proof: %+v", proof)
	}
	// 被删记录读不到。
	if _, err := l2.Get(1); err == nil {
		t.Fatal("deleted record should not be readable")
	}
	// 剩余记录可读。
	r, err := l2.Get(30)
	if err != nil || r.Seq != 30 {
		t.Fatalf("get last: %v", err)
	}
	// 重启后仍一致。
	l2.Close()
	l3, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen after retention: %v", err)
	}
	defer l3.Close()
	if l3.LastSeq() != 30 {
		t.Fatalf("lastSeq after reopen = %d", l3.LastSeq())
	}
	if err := l3.Verify(); err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
	// 删除被删前缀中的记录会留下空文件句柄风险——此处确认段文件确实减少。
	if _, err := os.Stat(segsBefore[0].path); !os.IsNotExist(err) {
		t.Fatalf("expired segment still exists")
	}
}

// 校验点：固化后校验可从校验点开始；篡改校验点之后的数据可被定位。
func TestCheckpointAndVerifyFrom(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, _ := Open(cfg)
	for i := 0; i < 5; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	cp, err := l.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp.Seq != 5 {
		t.Fatalf("cp.Seq = %d, want 5", cp.Seq)
	}
	for i := 5; i < 10; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	// 从校验点校验到链尾。
	if err := l.VerifyFrom(cp); err != nil {
		t.Fatalf("verify from cp: %v", err)
	}
	// 校验点链自洽。
	if err := l.VerifyCheckpointChain(); err != nil {
		t.Fatalf("cp chain: %v", err)
	}
	// 篡改校验点之后的记录。
	segs, _ := listSegments(dir)
	data, _ := os.ReadFile(segs[len(segs)-1].path)
	data[len(data)-10] ^= 0xFF
	os.WriteFile(segs[len(segs)-1].path, data, 0o644)
	err = l.VerifyFrom(cp)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeVerify {
		t.Fatalf("want verify error, got %v", err)
	}
	if ae.Seq <= cp.Seq {
		t.Fatalf("tamper should be after checkpoint, got seq %d", ae.Seq)
	}
}

// 篡改校验点之前的历史 → 锚定失败（证明链条被回退/改写）。
func TestCheckpointAnchorDetectsRollback(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, _ := Open(cfg)
	for i := 0; i < 6; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	cp, _ := l.CreateCheckpoint()

	// 回退攻击：篡改第 2 条（校验点之前）并重算其后整条链，
	// 使文件内部自洽——但链头哈希必然偏离校验点固化值。
	segs, _ := listSegments(dir)
	recs, _ := readSegment(segs[0].path)
	recs[1].Payload = []byte{0xAA}
	for i := 1; i < len(recs); i++ {
		recs[i].Hash = computeHash(recs[i].PrevHash, recs[i].Seq, recs[i].Timestamp,
			recs[i].Actor, recs[i].Action, recs[i].Payload)
		if i+1 < len(recs) {
			recs[i+1].PrevHash = recs[i].Hash
		}
	}
	var out []byte
	for _, r := range recs {
		out = append(out, encodeRecord(r)...)
	}
	os.WriteFile(segs[0].path, out, 0o644)

	err := l.VerifyFrom(cp)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeVerify {
		t.Fatalf("want verify error, got %v", err)
	}
	// 锚定记录（seq 6）的哈希不再等于校验点固化值 → 检测到回退。
	if ae.Seq != cp.Seq {
		t.Fatalf("anchor mismatch at seq %d, want %d", ae.Seq, cp.Seq)
	}
}

// 校验点不可改写：同位置重复创建复用已有校验点，文件不被覆盖。
func TestCheckpointImmutable(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SyncEveryWrite: true}
	l, _ := Open(cfg)
	l.Append("a", "op", nil)
	cp1, err := l.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := l.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp1.CpHash != cp2.CpHash {
		t.Fatal("same-position checkpoint should be reused")
	}
	// 手工篡改校验点文件应被自洽性校验发现。
	path := dir + "/" + checkpointName(cp1.Seq)
	data, _ := os.ReadFile(path)
	os.Chmod(path, 0o644)
	data[len(data)-5] ^= 0xFF
	os.WriteFile(path, data, 0o644)
	if _, err := loadCheckpoint(path); err == nil {
		// JSON 仍可能解析成功，但 VerifyFrom 的自洽校验必须失败。
		cpBad, _ := loadCheckpoint(path)
		if cpBad != nil {
			if err := l.VerifyFrom(cpBad); err == nil {
				t.Fatal("tampered checkpoint must fail verification")
			}
		}
	}
}

// 校验点复用：删除旧段后，从旧校验点之后的校验点继续校验。
func TestCheckpointReuseAfterRetention(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:             dir,
		SegmentMaxBytes: 200,
		RetentionAge:    time.Millisecond,
		SyncEveryWrite:  true,
	}
	l, _ := Open(cfg)
	for i := 0; i < 10; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	cp1, err := l.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	for i := 10; i < 30; i++ {
		l.Append("a", "op", []byte{byte(i)})
	}
	cp2, err := l.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	time.Sleep(5 * time.Millisecond)

	l2, _ := Open(cfg)
	defer l2.Close()
	if err := l2.ApplyRetention(); err != nil {
		t.Fatal(err)
	}
	// 校验点链仍然完整可验。
	if err := l2.VerifyCheckpointChain(); err != nil {
		t.Fatalf("cp chain after retention: %v", err)
	}
	// cp1 指向的记录可能已被删除：VerifyFrom(cp1) 应报锚定失败或回退，
	// 而最新校验点 cp2 若仍在留存范围内则必须校验通过。
	latest, err := l2.LatestCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if latest.Seq != cp2.Seq {
		t.Fatalf("latest cp = %d, want %d", latest.Seq, cp2.Seq)
	}
	if latest.PrevCpHash != cp1.CpHash {
		t.Fatal("checkpoint chain link broken")
	}
	if err := l2.VerifyFrom(latest); err != nil {
		t.Fatalf("verify from latest cp: %v", err)
	}
}
