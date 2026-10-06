package audit

import (
	"path/filepath"
	"sort"
)

// VerifyReport 描述一次链校验结果。
type VerifyReport struct {
	OK          bool   // 链完整无误
	FirstBadSeq uint64 // 最早出问题的记录序号
	Reason      string // modify/insert/delete/truncate/rollback
	Checked     uint64 // 本次校验的记录条数
}

// Verify 从最近的校验点（或保留锚点、或创世）重新读取磁盘段文件，
// 校验到当前已提交链尾。任何改写、插入、删除、截断、回退都会被检测，
// 并报告最早出问题的记录序号。
func (s *Store) Verify() (*VerifyReport, error) {
	committed := s.snapshot()
	var tail uint64
	if len(committed) > 0 {
		tail = committed[len(committed)-1].Seq
	}
	cp := s.LatestCheckpoint()
	anchors := s.RetentionAnchors()

	// 确定校验起点：优先最近校验点，其次保留锚点，否则创世。
	// 从锚点起步时锚点记录本身已被删除，无需在盘上核对；
	// 从校验点起步时该校验点记录必须仍在盘上且哈希一致。
	startSeq, startHash := uint64(0), GenesisHash
	startFromAnchor := false
	if n := len(anchors); n > 0 {
		startSeq, startHash = anchors[n-1].EndSeq, anchors[n-1].LastHash
		startFromAnchor = true
	}
	if cp != nil && cp.Seq > startSeq {
		startSeq, startHash = cp.Seq, cp.Hash
		startFromAnchor = false
	}
	if cp != nil && cp.Seq > tail {
		return &VerifyReport{FirstBadSeq: cp.Seq,
			Reason: "rollback: checkpoint beyond committed tail"}, nil
	}

	// 从磁盘重读全部段（只读，不阻塞写入）。
	paths, err := filepath.Glob(filepath.Join(s.cfg.Dir, segmentFilePattern))
	if err != nil {
		return nil, wrapErr(KindVerify, "verify", err)
	}
	sort.Strings(paths)
	var disk []Record
	for _, p := range paths {
		recs, _, rerr := readSegmentRecords(p)
		if rerr != nil {
			return nil, wrapErr(KindVerify, "verify", rerr)
		}
		disk = append(disk, recs...)
	}

	rep := &VerifyReport{}
	fail := func(seq uint64, reason string) *VerifyReport {
		rep.FirstBadSeq = seq
		rep.Reason = reason
		return rep
	}

	expected := startSeq + 1
	prev := startHash
	startChecked := startSeq == 0 || startFromAnchor
	for _, r := range disk {
		if r.Seq <= startSeq {
			if r.Seq == startSeq {
				if startChecked {
					return fail(r.Seq, "insert: duplicate or injected record"), nil
				}
				if r.Hash != startHash {
					return fail(r.Seq, "rollback: anchor/checkpoint record hash mismatch"), nil
				}
				startChecked = true
			}
			continue
		}
		if r.Seq < expected {
			return fail(r.Seq, "insert: duplicate or injected record"), nil
		}
		if expected > tail {
			break // 只校验到已提交链尾，忽略在途未提交帧
		}
		if r.Seq > expected {
			return fail(expected, "delete: records removed"), nil
		}
		if r.PrevHash != prev || !r.verifyHash() {
			return fail(r.Seq, "modify: record content altered"), nil
		}
		prev = r.Hash
		expected++
		rep.Checked++
	}
	if !startChecked {
		return fail(startSeq, "delete: anchor/checkpoint record missing"), nil
	}
	if expected <= tail {
		return fail(expected, "truncate: committed records missing from disk"), nil
	}
	rep.OK = true
	return rep, nil
}
