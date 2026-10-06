package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rewriteSegment 用 doctor 加工后的记录重写唯一段文件（模拟高水平篡改：
// 帧长与 CRC 均合法，只有链式哈希能发现）。
func rewriteSegment(t *testing.T, dir string, doctor func([]Record) []Record) {
	t.Helper()
	segs, err := filepath.Glob(filepath.Join(dir, segmentFilePattern))
	if err != nil || len(segs) != 1 {
		t.Fatalf("expect 1 segment, got %v %v", segs, err)
	}
	recs, _, err := readSegmentRecords(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	recs = doctor(recs)
	var buf []byte
	for i := range recs {
		frame, err := encodeFrame(&recs[i])
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, frame...)
	}
	if err := os.WriteFile(segs[0], buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

// openStoreWith10 建一个含 10 条记录的打开中的 Store。
func openStoreWith10(t *testing.T) (Config, *Store) {
	t.Helper()
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := s.Append("alice", "op", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { s.Close() })
	return cfg, s
}

func TestTamperModify(t *testing.T) {
	cfg, s := openStoreWith10(t)
	rewriteSegment(t, cfg.Dir, func(recs []Record) []Record {
		recs[4].Payload = []byte("forged") // 改内容但保留原哈希
		return recs
	})
	rep, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || rep.FirstBadSeq != 5 || !strings.Contains(rep.Reason, "modify") {
		t.Fatalf("expect modify at seq 5, got %+v", rep)
	}
}

func TestTamperDelete(t *testing.T) {
	cfg, s := openStoreWith10(t)
	rewriteSegment(t, cfg.Dir, func(recs []Record) []Record {
		return append(recs[:4], recs[5:]...) // 抽走第 5 条
	})
	rep, _ := s.Verify()
	if rep.OK || rep.FirstBadSeq != 5 || !strings.Contains(rep.Reason, "delete") {
		t.Fatalf("expect delete at seq 5, got %+v", rep)
	}
}

func TestTamperInsert(t *testing.T) {
	cfg, s := openStoreWith10(t)
	rewriteSegment(t, cfg.Dir, func(recs []Record) []Record {
		dup := recs[4]
		out := append([]Record{}, recs[:5]...)
		out = append(out, dup) // 插入一条重复记录
		return append(out, recs[5:]...)
	})
	rep, _ := s.Verify()
	if rep.OK || rep.FirstBadSeq != 5 || !strings.Contains(rep.Reason, "insert") {
		t.Fatalf("expect insert at seq 5, got %+v", rep)
	}
}

func TestTamperTruncate(t *testing.T) {
	cfg, s := openStoreWith10(t)
	rewriteSegment(t, cfg.Dir, func(recs []Record) []Record {
		return recs[:7] // 砍掉尾部 3 条
	})
	rep, _ := s.Verify()
	if rep.OK || rep.FirstBadSeq != 8 || !strings.Contains(rep.Reason, "truncate") {
		t.Fatalf("expect truncate at seq 8, got %+v", rep)
	}
}

// 重启时的恢复同样能定位被篡改的位置（可区分的 KindRecover 错误）。
func TestTamperDetectedOnRecover(t *testing.T) {
	cfg, s := openStoreWith10(t)
	s.Close()
	rewriteSegment(t, cfg.Dir, func(recs []Record) []Record {
		recs[4].Payload = []byte("forged")
		return recs
	})
	_, err := Open(cfg)
	if err == nil {
		t.Fatal("expect recover error")
	}
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("expect *Error, got %T", err)
	}
	if ae.Kind != KindRecover || !ae.HasSeq || ae.Seq != 5 {
		t.Fatalf("expect recover error at seq 5, got %+v", ae)
	}
}

// 链式重哈希也逃不过校验点锚定：攻击者重算整条链，但校验点哈希对不上。
func TestTamperRehashChainCaughtByCheckpoint(t *testing.T) {
	cfg, s := openStoreWith10(t)
	if _, err := s.CreateCheckpoint(); err != nil {
		t.Fatal(err)
	}
	anchor := s.Anchor()
	s.Close()

	// 攻击者改写第 5 条并重算后续整条哈希链（帧完全合法）。
	rewriteSegment(t, cfg.Dir, func(recs []Record) []Record {
		recs[4].Payload = []byte("forged")
		prev := recs[3].Hash
		for i := 4; i < len(recs); i++ {
			recs[i].seal(prev)
			prev = recs[i].Hash
		}
		return recs
	})

	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Anchor() != anchor {
		t.Fatal("anchor should be loaded from checkpoint file, not recomputed")
	}
	rep, _ := s2.Verify()
	if rep.OK || rep.FirstBadSeq != 10 || !strings.Contains(rep.Reason, "rollback") {
		t.Fatalf("expect rollback at checkpoint seq 10, got %+v", rep)
	}
}
