package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Verify 从头校验整条链。
// 起点是截断证明（无删除时为创世），逐条重放哈希链，
// 任何改写、插入、删除、截断都会在此暴露；
// 返回的 *Error 携带最早出问题的序号。
func (l *Log) Verify() error {
	l.rmu.RLock()
	if l.closed {
		l.rmu.RUnlock()
		return &Error{Code: ErrCodeClosed, Msg: "log is closed"}
	}
	start := l.trunc.LastSeq + 1
	end := l.lastSeq
	prev := l.trunc.LastHash
	truncSeq := l.trunc.LastSeq
	l.rmu.RUnlock()
	return l.verifyRange(start, end, prev, truncSeq)
}

// verifyRange 校验 [from, to] 区间的链，prev 为 from-1 的链哈希。
func (l *Log) verifyRange(from, to uint64, prev Hash, truncSeq uint64) error {
	if from > to {
		return nil
	}
	recs, err := l.Query(Query{SeqFrom: from, SeqTo: to})
	if err != nil {
		return err
	}
	if uint64(len(recs)) != to-from+1 {
		// 区间内有缺失：定位第一条缺失的序号。
		got := make(map[uint64]bool, len(recs))
		for _, r := range recs {
			got[r.Seq] = true
		}
		for s := from; s <= to; s++ {
			if !got[s] {
				return verifyErr(s, "record missing (deleted or truncated)")
			}
		}
		return verifyErr(from, "record count mismatch")
	}
	for _, r := range recs {
		if r.Seq <= truncSeq {
			return verifyErr(r.Seq, "record overlaps truncated prefix")
		}
		if r.PrevHash != prev {
			return verifyErr(r.Seq, "prev hash mismatch (insertion or rewrite detected)")
		}
		if computeHash(r.PrevHash, r.Seq, r.Timestamp, r.Actor, r.Action, r.Payload) != r.Hash {
			return verifyErr(r.Seq, "hash mismatch (record content modified)")
		}
		prev = r.Hash
	}
	return nil
}

// VerifyFrom 从校验点开始校验到链尾。
// 先锚定：校验点自身哈希必须自洽，且 cp.Seq 处的记录哈希
// 必须等于校验点固化的哈希——这证明该位置的链条没有被回退过；
// 再校验 cp.Seq 之后的链。
func (l *Log) VerifyFrom(cp *Checkpoint) error {
	if cp == nil {
		return l.Verify()
	}
	// 校验点自洽。
	want := computeCpHash(cp.Seq, cp.Hash, cp.PrevCpHash, cp.TruncatedSeq, cp.TruncatedHash)
	if want != cp.CpHash {
		return verifyErr(cp.Seq, "checkpoint hash self-inconsistent")
	}
	// 锚定：该位置记录必须仍是校验点固化的哈希。
	if cp.Seq > 0 {
		r, err := l.Get(cp.Seq)
		if err != nil {
			var ae *Error
			if errors.As(err, &ae) && ae.Code == ErrCodeNotFound {
				return verifyErr(cp.Seq, "checkpointed record missing (chain rolled back or truncated)")
			}
			return err
		}
		if r.Hash != cp.Hash {
			return verifyErr(cp.Seq, "checkpoint anchor mismatch (history before checkpoint rewritten)")
		}
	}
	l.rmu.RLock()
	end := l.lastSeq
	l.rmu.RUnlock()
	return l.verifyRange(cp.Seq+1, end, cp.Hash, cp.TruncatedSeq)
}

// CreateCheckpoint 在当前链头固化一个校验点。
// 校验点文件排他创建，生成后不会被后续写入改写。
func (l *Log) CreateCheckpoint() (*Checkpoint, error) {
	l.mu.Lock() // 与提交互斥，固化的是稳定链头
	defer l.mu.Unlock()

	l.rmu.RLock()
	if l.closed {
		l.rmu.RUnlock()
		return nil, &Error{Code: ErrCodeClosed, Msg: "log is closed"}
	}
	cp := &Checkpoint{
		Seq:           l.lastSeq,
		Hash:          l.lastHash,
		CreatedAt:     nowUTC(),
		TruncatedSeq:  l.trunc.LastSeq,
		TruncatedHash: l.trunc.LastHash,
	}
	l.rmu.RUnlock()

	// 链接上一个校验点，形成校验点链。
	prev, err := l.latestCheckpointLocked()
	if err != nil {
		return nil, writeErr(cp.Seq, "load previous checkpoint", err)
	}
	if prev != nil {
		if prev.Seq >= cp.Seq && cp.Seq != 0 {
			// 已有覆盖当前位置的校验点，直接复用最新一个。
			return prev, nil
		}
		cp.PrevCpHash = prev.CpHash
	}
	cp.CpHash = computeCpHash(cp.Seq, cp.Hash, cp.PrevCpHash, cp.TruncatedSeq, cp.TruncatedHash)
	if err := saveCheckpoint(l.cfg.Dir, cp); err != nil {
		if os.IsExist(err) {
			return nil, writeErr(cp.Seq, "checkpoint already exists (must not be rewritten)", err)
		}
		return nil, writeErr(cp.Seq, "save checkpoint", err)
	}
	return cp, nil
}

// LatestCheckpoint 读取最新的校验点，没有则返回 nil。
func (l *Log) LatestCheckpoint() (*Checkpoint, error) {
	return l.latestCheckpointLocked()
}

func (l *Log) latestCheckpointLocked() (*Checkpoint, error) {
	paths, err := listCheckpoints(l.cfg.Dir)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}
	return loadCheckpoint(paths[len(paths)-1])
}

// VerifyCheckpointChain 校验全部校验点构成的链，
// 证明校验点序列本身没有被回退或替换。
func (l *Log) VerifyCheckpointChain() error {
	paths, err := listCheckpoints(l.cfg.Dir)
	if err != nil {
		return err
	}
	var prevCp Hash
	var prevSeq uint64
	for _, p := range paths {
		cp, err := loadCheckpoint(p)
		if err != nil {
			return recoverErr(0, "load checkpoint "+filepath.Base(p), err)
		}
		if cp.Seq < prevSeq {
			return verifyErr(cp.Seq, "checkpoint sequence regressed")
		}
		if cp.PrevCpHash != prevCp {
			return verifyErr(cp.Seq, fmt.Sprintf("checkpoint chain broken (expected prev %x)", prevCp[:8]))
		}
		if computeCpHash(cp.Seq, cp.Hash, cp.PrevCpHash, cp.TruncatedSeq, cp.TruncatedHash) != cp.CpHash {
			return verifyErr(cp.Seq, "checkpoint hash mismatch")
		}
		prevCp = cp.CpHash
		prevSeq = cp.Seq
	}
	return nil
}
