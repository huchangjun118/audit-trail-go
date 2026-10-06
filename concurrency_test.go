package audit

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// 多写入方并发追加：序号必须严格递增、无空洞、无重复。
func TestConcurrentAppend(t *testing.T) {
	cfg := testConfig(t)
	cfg.SegmentMaxBytes = 4096 // 并发中触发轮转
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const writers = 8
	const perWriter = 50
	seqCh := make(chan uint64, writers*perWriter)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				seq, err := s.Append(fmt.Sprintf("writer-%d", id), "op", []byte{byte(i)})
				if err != nil {
					t.Error(err)
					return
				}
				seqCh <- seq
			}
		}(w)
	}
	wg.Wait()
	close(seqCh)

	seen := make(map[uint64]bool)
	for seq := range seqCh {
		if seen[seq] {
			t.Fatalf("duplicate seq %d", seq)
		}
		seen[seq] = true
	}
	for i := uint64(1); i <= writers*perWriter; i++ {
		if !seen[i] {
			t.Fatalf("missing seq %d", i)
		}
	}
	if got := s.LastSeq(); got != writers*perWriter {
		t.Fatalf("LastSeq = %d, want %d", got, writers*perWriter)
	}
	rep, _ := s.Verify()
	if !rep.OK {
		t.Fatalf("verify failed: %+v", rep)
	}
}

// 并发批量提交：同一批次内序号连续，整批原子可见。
func TestConcurrentBatchAppend(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const writers = 6
	const batches = 10
	const batchSize = 5
	seqCh := make(chan []uint64, writers*batches)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for b := 0; b < batches; b++ {
				items := make([]BatchItem, batchSize)
				for i := range items {
					items[i] = BatchItem{Actor: fmt.Sprintf("w%d", id), Action: "batch"}
				}
				seqs, err := s.AppendBatch(items)
				if err != nil {
					t.Error(err)
					return
				}
				seqCh <- seqs
			}
		}(w)
	}
	wg.Wait()
	close(seqCh)

	seen := make(map[uint64]bool)
	for seqs := range seqCh {
		// 批内连续。
		for i := 1; i < len(seqs); i++ {
			if seqs[i] != seqs[i-1]+1 {
				t.Fatalf("batch seqs not contiguous: %v", seqs)
			}
		}
		for _, q := range seqs {
			if seen[q] {
				t.Fatalf("duplicate seq %d", q)
			}
			seen[q] = true
		}
	}
	total := uint64(writers * batches * batchSize)
	for i := uint64(1); i <= total; i++ {
		if !seen[i] {
			t.Fatalf("missing seq %d", i)
		}
	}
}

// 崩溃恢复：撕裂的尾部帧被裁掉，完整记录保留，序号不跳跃。
func TestCrashRecoveryTornTail(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.Append("a", "op", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// 模拟崩溃：不 Close，直接向活跃段写入半帧垃圾。
	segPath := segmentPath(cfg.Dir, 1)
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0x05, 0x00, 0x00}) // 半个帧头
	f.Sync()
	f.Close()
	s.Close() // 尽力关闭（不保证垃圾被清理）

	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.LastSeq(); got != 5 {
		t.Fatalf("LastSeq = %d, want 5 (torn tail must be dropped)", got)
	}
	rep, _ := s2.Verify()
	if !rep.OK {
		t.Fatalf("verify failed after recovery: %+v", rep)
	}
	// 恢复后继续追加，序号从 6 开始无跳跃。
	seq, err := s2.Append("a", "op", nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 6 {
		t.Fatalf("seq = %d, want 6", seq)
	}
}

// 慢读取不阻塞写入推进。
func TestSlowReaderDoesNotBlockWriter(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	stop := make(chan struct{})
	var rwg sync.WaitGroup
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		cur := FirstCursor
		for {
			select {
			case <-stop:
				return
			default:
			}
			recs, next := s.Pull(cur, 10)
			cur = next
			for range recs {
				time.Sleep(time.Millisecond) // 慢处理
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := s.Append("w", "op", nil); err != nil {
				t.Error(err)
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writer blocked by slow reader")
	}
	close(stop)
	rwg.Wait()
	if got := s.LastSeq(); got != 100 {
		t.Fatalf("LastSeq = %d, want 100", got)
	}
}
