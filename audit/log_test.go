package audit

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T, mutate func(*Config)) *Log {
	t.Helper()
	cfg := Config{Dir: t.TempDir(), SyncEveryWrite: true}
	if mutate != nil {
		mutate(&cfg)
	}
	l, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestAppendAssignsSequentialSeqs(t *testing.T) {
	l := openTemp(t, nil)
	for i := 1; i <= 10; i++ {
		seq, err := l.Append("alice", "login", []byte("ok"))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if seq != uint64(i) {
			t.Fatalf("got seq %d, want %d", seq, i)
		}
	}
	if l.LastSeq() != 10 {
		t.Fatalf("last seq = %d", l.LastSeq())
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBatchGetsContiguousSeqs(t *testing.T) {
	l := openTemp(t, nil)
	if _, err := l.Append("a", "x", nil); err != nil {
		t.Fatal(err)
	}
	seqs, err := l.AppendBatch([]Entry{
		{Actor: "b", Action: "y"},
		{Actor: "c", Action: "z"},
		{Actor: "d", Action: "w"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint64{2, 3, 4}
	for i := range want {
		if seqs[i] != want[i] {
			t.Fatalf("seqs = %v, want %v", seqs, want)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBatchSizeLimit(t *testing.T) {
	l := openTemp(t, func(c *Config) { c.MaxBatchSize = 2 })
	_, err := l.AppendBatch([]Entry{{Actor: "a"}, {Actor: "b"}, {Actor: "c"}})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != ErrCodeWrite {
		t.Fatalf("want write error, got %v", err)
	}
	if l.LastSeq() != 0 {
		t.Fatalf("rejected batch must not be visible, lastSeq=%d", l.LastSeq())
	}
}

// 并发追加：序号必须严格递增、无空洞、无重复。
func TestConcurrentAppend(t *testing.T) {
	l := openTemp(t, nil)
	const writers = 8
	const perWriter = 50
	var wg sync.WaitGroup
	results := make([][]uint64, writers)
	errs := make([]error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				seq, err := l.Append(fmt.Sprintf("actor-%d", w), "op", []byte{byte(i)})
				if err != nil {
					errs[w] = err
					return
				}
				results[w] = append(results[w], seq)
			}
		}(w)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", w, err)
		}
	}
	seen := make(map[uint64]bool)
	for w := 0; w < writers; w++ {
		for _, s := range results[w] {
			if seen[s] {
				t.Fatalf("duplicate seq %d", s)
			}
			seen[s] = true
		}
	}
	total := uint64(writers * perWriter)
	for s := uint64(1); s <= total; s++ {
		if !seen[s] {
			t.Fatalf("gap at seq %d", s)
		}
	}
	if l.LastSeq() != total {
		t.Fatalf("lastSeq = %d, want %d", l.LastSeq(), total)
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 相同输入与相同提交批次 → 相同序号与链哈希（固定时钟下可复现）。
func TestDeterministicBatches(t *testing.T) {
	fixed := nowUTC()
	defer func() { nowUTC = func() time.Time { return fixed } }()
	nowUTC = func() time.Time { return fixed }

	run := func() []Record {
		l := openTemp(t, nil)
		defer l.Close()
		l.AppendBatch([]Entry{{Actor: "a", Action: "x", Payload: []byte("1")}})
		l.AppendBatch([]Entry{{Actor: "b", Action: "y"}, {Actor: "c", Action: "z"}})
		var out []Record
		for s := uint64(1); s <= 3; s++ {
			r, err := l.Get(s)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, *r)
		}
		return out
	}
	r1, r2 := run(), run()
	for i := range r1 {
		if r1[i].Hash != r2[i].Hash || r1[i].Seq != r2[i].Seq {
			t.Fatalf("record %d not reproducible", i)
		}
	}
}

// 并发读写：慢读者不得阻塞写入，且只能看到已提交记录。
func TestConcurrentReadWrite(t *testing.T) {
	l := openTemp(t, nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cursor := uint64(0)
		for {
			select {
			case <-stop:
				return
			default:
			}
			recs, next, err := l.Fetch(cursor, 10)
			if err != nil {
				t.Errorf("fetch: %v", err)
				return
			}
			for _, r := range recs {
				if r.Seq <= cursor {
					t.Errorf("fetch returned uncommitted/duplicate seq %d", r.Seq)
					return
				}
			}
			cursor = next
		}
	}()
	for i := 0; i < 200; i++ {
		if _, err := l.Append("writer", "op", []byte{byte(i)}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	if err := l.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestQueryFilters(t *testing.T) {
	l := openTemp(t, nil)
	l.Append("alice", "login", nil)
	l.Append("bob", "read", nil)
	l.Append("alice", "write", nil)
	l.Append("alice", "logout", nil)

	recs, err := l.Query(Query{Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("actor filter: got %d", len(recs))
	}
	recs, err = l.Query(Query{SeqFrom: 2, SeqTo: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Seq != 2 || recs[1].Seq != 3 {
		t.Fatalf("seq range: %+v", recs)
	}
	r2, _ := l.Get(2)
	recs, err = l.Query(Query{TimeFrom: r2.Timestamp, TimeTo: r2.Timestamp})
	if err != nil {
		t.Fatal(err)
	}
	// 同一批/相邻提交时间可能相同，至少应包含 seq 2。
	found := false
	for _, r := range recs {
		if r.Seq == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("time range query missing seq 2")
	}
	// 游标增量拉取。
	var all []uint64
	cursor := uint64(0)
	for {
		batch, next, err := l.Fetch(cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			all = append(all, r.Seq)
		}
		cursor = next
	}
	if len(all) != 4 {
		t.Fatalf("fetch all: got %v", all)
	}
	if _, err := l.Get(99); !errors.Is(err, &Error{Code: ErrCodeNotFound}) {
		var ae *Error
		if !errors.As(err, &ae) || ae.Code != ErrCodeNotFound {
			t.Fatalf("want not found, got %v", err)
		}
	}
}
