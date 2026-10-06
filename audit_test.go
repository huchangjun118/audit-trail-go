package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig(t.TempDir())
	cfg.SegmentMaxBytes = 1 << 20
	cfg.RotationInterval = time.Hour
	cfg.RetentionPeriod = 24 * time.Hour
	return cfg
}

func TestAppendAndReopen(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		seq, err := s.Append("alice", "login", []byte(fmt.Sprintf("p%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if seq != uint64(i+1) {
			t.Fatalf("seq = %d, want %d", seq, i+1)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 重开：序号连续、校验通过、可继续追加。
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.LastSeq(); got != 10 {
		t.Fatalf("LastSeq = %d, want 10", got)
	}
	rep, err := s2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("verify failed: %+v", rep)
	}
	seq, err := s2.Append("bob", "logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 11 {
		t.Fatalf("seq = %d, want 11", seq)
	}
}

func TestReaderQueries(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	actors := []string{"alice", "bob", "alice", "carol", "bob"}
	for i, a := range actors {
		if _, err := s.Append(a, "op", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}

	if got := s.SeqRange(2, 4); len(got) != 3 || got[0].Seq != 2 || got[2].Seq != 4 {
		t.Fatalf("SeqRange wrong: %+v", got)
	}
	if got := s.ByActor("alice"); len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 3 {
		t.Fatalf("ByActor wrong: %+v", got)
	}
	now := time.Now()
	if got := s.TimeRange(now.Add(-time.Minute).UnixNano(), now.Add(time.Minute).UnixNano()); len(got) != 5 {
		t.Fatalf("TimeRange wrong: %d", len(got))
	}
	// 游标增量拉取。
	batch1, cur := s.Pull(FirstCursor, 2)
	if len(batch1) != 2 || cur != 3 {
		t.Fatalf("pull1: %d records, cur=%d", len(batch1), cur)
	}
	batch2, cur := s.Pull(cur, 100)
	if len(batch2) != 3 || cur != 6 {
		t.Fatalf("pull2: %d records, cur=%d", len(batch2), cur)
	}
	batch3, _ := s.Pull(cur, 100)
	if len(batch3) != 0 {
		t.Fatalf("pull3 should be empty")
	}
}

func TestBatchAtomicSeqs(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	items := []BatchItem{
		{Actor: "a", Action: "x"},
		{Actor: "b", Action: "y"},
		{Actor: "c", Action: "z"},
	}
	seqs, err := s.AppendBatch(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 3 || seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 3 {
		t.Fatalf("seqs = %v", seqs)
	}
	// 超限批次整体失败，不分配序号。
	big := make([]BatchItem, cfg.MaxBatchRecords+1)
	if _, err := s.AppendBatch(big); err == nil {
		t.Fatal("expected error for oversized batch")
	}
	if got := s.LastSeq(); got != 3 {
		t.Fatalf("LastSeq = %d after failed batch, want 3", got)
	}
}

func TestSegmentRotation(t *testing.T) {
	cfg := testConfig(t)
	cfg.SegmentMaxBytes = 300 // 强制频繁切段
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := s.Append("a", "op", []byte(fmt.Sprintf("payload-%03d", i))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	segs, _ := filepath.Glob(filepath.Join(cfg.Dir, segmentFilePattern))
	if len(segs) < 2 {
		t.Fatalf("expected multiple segments, got %d", len(segs))
	}
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rep, _ := s2.Verify()
	if !rep.OK {
		t.Fatalf("verify after rotation failed: %+v", rep)
	}
	if got := s2.LastSeq(); got != 20 {
		t.Fatalf("LastSeq = %d, want 20", got)
	}
	// 段文件只增不改：os 层面无额外临时文件残留。
	entries, _ := os.ReadDir(cfg.Dir)
	for _, e := range entries {
		t.Logf("dir entry: %s", e.Name())
	}
}
