package audit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const truncationFile = "truncation.json"

// TruncationProof 是被删前缀的存在性证明：
// 删除旧段后，剩余链以该哈希为起点，可证明被删历史确实被提交过。
type TruncationProof struct {
	LastSeq  uint64 `json:"lastSeq"`
	LastHash Hash   `json:"lastHash"`
}

type truncationJSON struct {
	LastSeq  uint64 `json:"lastSeq"`
	LastHash string `json:"lastHash"`
}

func loadTruncationProof(dir string) (TruncationProof, error) {
	data, err := os.ReadFile(filepath.Join(dir, truncationFile))
	if errors.Is(err, os.ErrNotExist) {
		return TruncationProof{}, nil
	}
	if err != nil {
		return TruncationProof{}, err
	}
	var tj truncationJSON
	if err := json.Unmarshal(data, &tj); err != nil {
		return TruncationProof{}, err
	}
	raw, err := hex.DecodeString(tj.LastHash)
	if err != nil || len(raw) != HashLen {
		return TruncationProof{}, errors.New("audit: bad truncation hash")
	}
	var h Hash
	copy(h[:], raw)
	return TruncationProof{LastSeq: tj.LastSeq, LastHash: h}, nil
}

func saveTruncationProof(dir string, p TruncationProof) error {
	data, err := json.Marshal(truncationJSON{
		LastSeq:  p.LastSeq,
		LastHash: hex.EncodeToString(p.LastHash[:]),
	})
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, truncationFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, truncationFile))
}

// ApplyRetention 删除超过保留时长的已封存段。
// 删除前先把被删前缀的链头哈希写入截断证明，
// 保证剩余部分仍可校验，且能证明被删历史确实被提交过。
// 活跃段永不删除。
func (l *Log) ApplyRetention() error {
	if l.cfg.RetentionAge <= 0 {
		return nil // 未配置保留时长，不删除
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.rmu.RLock()
	if l.closed {
		l.rmu.RUnlock()
		return &Error{Code: ErrCodeClosed, Msg: "log is closed"}
	}
	segs := make([]*segment, len(l.segs))
	copy(segs, l.segs)
	l.rmu.RUnlock()

	cutoff := time.Now().Add(-l.cfg.RetentionAge)
	var deleteUpto int // segs[:deleteUpto] 将被删除
	for i, s := range segs {
		if !s.sealed || s.createdAt.After(cutoff) {
			break
		}
		deleteUpto = i + 1
	}
	if deleteUpto == 0 {
		return nil
	}

	// 先持久化截断证明，再删段：任何时刻都不会既丢段又丢证明。
	l.rmu.RLock()
	lastHead := l.heads[deleteUptoSeq(l, segs[deleteUpto-1].lastSeq)]
	proof := TruncationProof{LastSeq: lastHead.seq, LastHash: lastHead.hash}
	l.rmu.RUnlock()
	if err := saveTruncationProof(l.cfg.Dir, proof); err != nil {
		return writeErr(proof.LastSeq, "save truncation proof", err)
	}
	for _, s := range segs[:deleteUpto] {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return writeErr(s.firstSeq, "remove expired segment", err)
		}
	}

	l.rmu.Lock()
	l.segs = l.segs[deleteUpto:]
	l.trunc = proof
	// 丢弃已删除前缀的索引。
	keep := int(l.lastSeq - proof.LastSeq)
	l.heads = append([]recordHeader(nil), l.heads[len(l.heads)-keep:]...)
	// 段下标整体前移。
	for i := range l.heads {
		l.heads[i].segIdx -= deleteUpto
	}
	l.rmu.Unlock()
	return nil
}

// deleteUptoSeq 辅助：返回 lastSeq 对应的 heads 下标。调用方须持有 rmu。
func deleteUptoSeq(l *Log, lastSeq uint64) int {
	return int(lastSeq - l.trunc.LastSeq - 1)
}
