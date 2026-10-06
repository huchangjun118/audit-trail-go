package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RetentionAnchor 记录已删除段的链头，证明被删历史确实提交过，
// 并使删除旧段后剩余链条仍可完成校验。
type RetentionAnchor struct {
	BaseSeq   uint64    `json:"base_seq"`
	EndSeq    uint64    `json:"end_seq"`
	LastHash  Hash      `json:"last_hash"` // 被删前缀的链头（末条记录哈希）
	DeletedAt time.Time `json:"deleted_at"`
}

const retentionFileName = "retention.log"

func retentionPath(dir string) string { return filepath.Join(dir, retentionFileName) }

// loadRetentionAnchors 读取保留锚点（Open 时调用），校验其单调衔接。
func loadRetentionAnchors(dir string) ([]RetentionAnchor, error) {
	data, err := os.ReadFile(retentionPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr(KindRecover, "load-retention", err)
	}
	var anchors []RetentionAnchor
	start := 0
	for i, b := range data {
		if b != '\n' {
			continue
		}
		line := data[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var a RetentionAnchor
		if json.Unmarshal(line, &a) != nil {
			if start >= len(data) {
				break // 尾行撕裂
			}
			return nil, seqErr(KindRecover, "load-retention", 0, errors.New("corrupt anchor line"))
		}
		if len(anchors) > 0 && a.BaseSeq != anchors[len(anchors)-1].EndSeq+1 {
			return nil, seqErr(KindRecover, "load-retention", a.BaseSeq,
				errors.New("retention anchors not contiguous"))
		}
		anchors = append(anchors, a)
	}
	return anchors, nil
}

// ApplyRetention 删除（或归档到 archiveDir）过期且已封存的段，
// 并为每个被删段写入保留锚点。活跃段永不删除。
func (s *Store) ApplyRetention(now time.Time, archiveDir string) ([]RetentionAnchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, wrapErr(KindWrite, "retention", errors.New("store closed"))
	}
	cutoff := now.Add(-s.cfg.RetentionPeriod)

	paths, err := filepath.Glob(filepath.Join(s.cfg.Dir, segmentFilePattern))
	if err != nil {
		return nil, wrapErr(KindWrite, "retention", err)
	}
	sort.Strings(paths)

	var removed []RetentionAnchor
	for _, p := range paths {
		if s.seg != nil && p == s.seg.path {
			continue // 活跃段
		}
		recs, _, err := readSegmentRecords(p)
		if err != nil {
			return nil, wrapErr(KindVerify, "retention", err)
		}
		if len(recs) == 0 {
			continue
		}
		last := recs[len(recs)-1]
		if last.Timestamp.After(cutoff) {
			continue // 未过期
		}
		anchor := RetentionAnchor{
			BaseSeq:   recs[0].Seq,
			EndSeq:    last.Seq,
			LastHash:  last.Hash,
			DeletedAt: now,
		}
		if archiveDir != "" {
			if err := os.MkdirAll(archiveDir, 0o755); err != nil {
				return nil, wrapErr(KindWrite, "retention", err)
			}
			if err := os.Rename(p, filepath.Join(archiveDir, filepath.Base(p))); err != nil {
				return nil, wrapErr(KindWrite, "retention", err)
			}
		} else {
			if err := os.Remove(p); err != nil {
				return nil, wrapErr(KindWrite, "retention", err)
			}
		}
		if err := s.appendAnchorLocked(anchor); err != nil {
			return nil, err
		}
		removed = append(removed, anchor)
	}
	return removed, nil
}

// appendAnchorLocked 追加保留锚点并落盘。调用方须持有 s.mu。
func (s *Store) appendAnchorLocked(a RetentionAnchor) error {
	if len(s.anchors) > 0 && a.BaseSeq != s.anchors[len(s.anchors)-1].EndSeq+1 {
		return seqErr(KindWrite, "retention", a.BaseSeq,
			fmt.Errorf("anchor gap: expected base %d", s.anchors[len(s.anchors)-1].EndSeq+1))
	}
	line, err := json.Marshal(a)
	if err != nil {
		return wrapErr(KindWrite, "retention", err)
	}
	f, err := os.OpenFile(retentionPath(s.cfg.Dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return wrapErr(KindWrite, "retention", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return wrapErr(KindWrite, "retention", err)
	}
	if err := f.Sync(); err != nil {
		return wrapErr(KindWrite, "retention", err)
	}
	s.anchors = append(s.anchors, a)
	return nil
}

// RetentionAnchors 返回全部保留锚点。
func (s *Store) RetentionAnchors() []RetentionAnchor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RetentionAnchor, len(s.anchors))
	copy(out, s.anchors)
	return out
}
