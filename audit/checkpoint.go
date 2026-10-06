package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Checkpoint 固化某个位置的链头哈希，之后的校验可从这里开始。
// 校验点之间也构成哈希链，用于证明链条未被回退；
// 校验点文件一旦写入即不可改写（O_EXCL 创建）。
type Checkpoint struct {
	Seq           uint64    `json:"seq"`           // 固化到的序号
	Hash          Hash      `json:"hash"`          // 该序号记录的链哈希
	PrevCpHash    Hash      `json:"prevCpHash"`    // 上一个校验点的哈希（校验点链）
	CpHash        Hash      `json:"cpHash"`        // 本校验点的哈希
	CreatedAt     time.Time `json:"createdAt"`     // 创建时间
	TruncatedSeq  uint64    `json:"truncatedSeq"`  // 创建时已删除前缀的最大序号（0 表示无删除）
	TruncatedHash Hash      `json:"truncatedHash"` // 被删前缀末条记录的链哈希
}

// computeCpHash 计算校验点哈希，把链头与上一校验点绑定。
func computeCpHash(seq uint64, hash Hash, prevCp Hash, truncSeq uint64, truncHash Hash) Hash {
	h := sha256.New()
	h.Write([]byte("AUDITCP1"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	h.Write(b[:])
	h.Write(hash[:])
	h.Write(prevCp[:])
	binary.BigEndian.PutUint64(b[:], truncSeq)
	h.Write(b[:])
	h.Write(truncHash[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

func checkpointName(seq uint64) string { return fmt.Sprintf("cp-%020d.json", seq) }

type checkpointJSON struct {
	Seq           uint64 `json:"seq"`
	Hash          string `json:"hash"`
	PrevCpHash    string `json:"prevCpHash"`
	CpHash        string `json:"cpHash"`
	CreatedAt     int64  `json:"createdAt"`
	TruncatedSeq  uint64 `json:"truncatedSeq"`
	TruncatedHash string `json:"truncatedHash"`
}

func decodeHashHex(s string) (Hash, error) {
	var h Hash
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != HashLen {
		return h, errors.New("audit: bad hash hex")
	}
	copy(h[:], raw)
	return h, nil
}

// saveCheckpoint 以排他创建方式写入校验点，已存在则拒绝覆盖。
func saveCheckpoint(dir string, cp *Checkpoint) error {
	data, err := json.Marshal(checkpointJSON{
		Seq:           cp.Seq,
		Hash:          hex.EncodeToString(cp.Hash[:]),
		PrevCpHash:    hex.EncodeToString(cp.PrevCpHash[:]),
		CpHash:        hex.EncodeToString(cp.CpHash[:]),
		CreatedAt:     cp.CreatedAt.UnixNano(),
		TruncatedSeq:  cp.TruncatedSeq,
		TruncatedHash: hex.EncodeToString(cp.TruncatedHash[:]),
	})
	if err != nil {
		return err
	}
	path := filepath.Join(dir, checkpointName(cp.Seq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadCheckpoint(path string) (*Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cj checkpointJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, err
	}
	cp := &Checkpoint{Seq: cj.Seq, TruncatedSeq: cj.TruncatedSeq,
		CreatedAt: time.Unix(0, cj.CreatedAt).UTC()}
	var errH error
	if cp.Hash, errH = decodeHashHex(cj.Hash); errH != nil {
		return nil, errH
	}
	if cp.PrevCpHash, errH = decodeHashHex(cj.PrevCpHash); errH != nil {
		return nil, errH
	}
	if cp.CpHash, errH = decodeHashHex(cj.CpHash); errH != nil {
		return nil, errH
	}
	if cp.TruncatedHash, errH = decodeHashHex(cj.TruncatedHash); errH != nil {
		return nil, errH
	}
	return cp, nil
}

// listCheckpoints 按序号升序列出所有校验点文件路径。
func listCheckpoints(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var seqs []uint64
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "cp-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "cp-"), ".json"), 10, 64)
		if err != nil {
			continue
		}
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	paths := make([]string, len(seqs))
	for i, s := range seqs {
		paths[i] = filepath.Join(dir, checkpointName(s))
	}
	return paths, nil
}
