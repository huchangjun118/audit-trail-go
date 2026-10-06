package audit

import (
	"path/filepath"
	"testing"
	"time"
)

// 过期段删除后：剩余链仍可校验，保留锚点证明被删历史已提交。
func TestRetentionDeleteAndVerify(t *testing.T) {
	cfg := testConfig(t)
	cfg.SegmentMaxBytes = 300 // 每条左右即切段
	cfg.RetentionPeriod = time.Millisecond
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := s.Append("a", "op", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(5 * time.Millisecond)

	anchors, err := s.ApplyRetention(time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) == 0 {
		t.Fatal("expect some segments deleted")
	}
	// 锚点连续衔接，覆盖被删前缀。
	var covered uint64
	for _, a := range anchors {
		if a.BaseSeq != covered+1 {
			t.Fatalf("anchor gap at %d", a.BaseSeq)
		}
		covered = a.EndSeq
	}
	// 活跃段不删，剩余记录仍连续到 20。
	if got := s.LastSeq(); got != 20 {
		t.Fatalf("LastSeq = %d, want 20", got)
	}
	rep, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("verify after retention failed: %+v", rep)
	}
	if rep.Checked != 20-covered {
		t.Fatalf("checked %d, want %d", rep.Checked, 20-covered)
	}

	// 重启后锚点持久化，校验仍通过。
	s.Close()
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := len(s2.RetentionAnchors()); got != len(anchors) {
		t.Fatalf("anchors not persisted: %d vs %d", got, len(anchors))
	}
	rep, _ = s2.Verify()
	if !rep.OK {
		t.Fatalf("verify after reopen failed: %+v", rep)
	}
}

// 归档模式：段被移动到归档目录而非删除。
func TestRetentionArchive(t *testing.T) {
	cfg := testConfig(t)
	cfg.SegmentMaxBytes = 300
	cfg.RetentionPeriod = time.Millisecond
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		s.Append("a", "op", []byte{byte(i)})
	}
	time.Sleep(5 * time.Millisecond)
	archive := filepath.Join(t.TempDir(), "archive")
	anchors, err := s.ApplyRetention(time.Now(), archive)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(anchors) == 0 {
		t.Fatal("expect archived segments")
	}
	files, _ := filepath.Glob(filepath.Join(archive, segmentFilePattern))
	if len(files) != len(anchors) {
		t.Fatalf("archived files %d != anchors %d", len(files), len(anchors))
	}
	if rep, _ := s.Verify(); !rep.OK {
		t.Fatal("verify failed after archive")
	}
}

// 校验点：生成后不被改写，之后校验从校验点开始（Checked 只数增量）。
func TestCheckpointReuse(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 10; i++ {
		s.Append("a", "op", nil)
	}
	cp1, err := s.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp1.Seq != 10 || cp1.Index != 1 {
		t.Fatalf("bad checkpoint: %+v", cp1)
	}
	a1 := s.Anchor()
	for i := 0; i < 5; i++ {
		s.Append("a", "op", nil)
	}
	rep, _ := s.Verify()
	if !rep.OK {
		t.Fatalf("verify failed: %+v", rep)
	}
	if rep.Checked != 5 {
		t.Fatalf("verify should start from checkpoint, checked %d want 5", rep.Checked)
	}

	// 第二个校验点链接第一个，锚定值随之前进且不回退。
	cp2, err := s.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp2.Index != 2 || cp2.PrevHash != cp1.hash() {
		t.Fatalf("checkpoint chain broken: %+v", cp2)
	}
	if s.Anchor() == a1 {
		t.Fatal("anchor should advance after new checkpoint")
	}

	// 重启后校验点链恢复，校验仍从最近校验点开始。
	s.Close()
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	latest := s2.LatestCheckpoint()
	if latest == nil || latest.Seq != 15 {
		t.Fatalf("latest checkpoint = %+v", latest)
	}
	rep, _ = s2.Verify()
	if !rep.OK || rep.Checked != 0 {
		t.Fatalf("verify from checkpoint: %+v", rep)
	}
}

// 校验点文件只追加不改写。
func TestCheckpointFileAppendOnly(t *testing.T) {
	cfg := testConfig(t)
	s, _ := Open(cfg)
	for i := 0; i < 3; i++ {
		s.Append("a", "op", nil)
	}
	s.CreateCheckpoint()
	for i := 0; i < 3; i++ {
		s.Append("a", "op", nil)
	}
	s.CreateCheckpoint()
	s.Close()
	cps, err := loadCheckpoints(cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 2 || cps[0].Seq != 3 || cps[1].Seq != 6 {
		t.Fatalf("checkpoints = %+v", cps)
	}
}
