package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Checkpoint 固化某个位置的链头哈希。校验点之间也成链（PrevHash），
// 生成后文件只追加不改写，可证明链未被回退。
type Checkpoint struct {
	Index    uint64    `json:"index"`
	Seq      uint64    `json:"seq"`
	Hash     Hash      `json:"hash"` // 链尾记录哈希
	PrevHash Hash      `json:"prev"` // 上一个校验点的哈希
	Time     time.Time `json:"time"`
}

// hash 计算校验点自身哈希（校验点链的链接值）。
func (c Checkpoint) hash() Hash {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], c.Index)
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], c.Seq)
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(c.Time.UnixNano()))
	h.Write(buf[:])
	h.Write(c.Hash[:])
	h.Write(c.PrevHash[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

const checkpointFileName = "checkpoints.log"

func checkpointPath(dir string) string { return filepath.Join(dir, checkpointFileName) }

// loadCheckpoints 读取并校验校验点链（Open 时调用）。
func loadCheckpoints(dir string) ([]Checkpoint, error) {
	data, err := os.ReadFile(checkpointPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapErr(KindRecover, "load-checkpoints", err)
	}
	var cps []Checkpoint
	prev := GenesisHash
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
		var cp Checkpoint
		if json.Unmarshal(line, &cp) != nil {
			// 尾行撕裂：忽略不完整行。
			if start >= len(data) {
				break
			}
			return nil, seqErr(KindRecover, "load-checkpoints", 0, errors.New("corrupt checkpoint line"))
		}
		want := uint64(1)
		if len(cps) > 0 {
			want = cps[len(cps)-1].Index + 1
		}
		if cp.Index != want || cp.PrevHash != prev {
			return nil, seqErr(KindRecover, "load-checkpoints", cp.Seq,
				fmt.Errorf("checkpoint chain broken at index %d", cp.Index))
		}
		prev = cp.hash()
		cps = append(cps, cp)
	}
	return cps, nil
}

// CreateCheckpoint 在当前链尾生成校验点并持久化（只追加，不改写历史校验点）。
func (s *Store) CreateCheckpoint() (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, wrapErr(KindWrite, "checkpoint", errors.New("store closed"))
	}
	if s.nextSeq == 1 {
		return nil, wrapErr(KindWrite, "checkpoint", errors.New("no records to checkpoint"))
	}
	cp := Checkpoint{
		Seq:  s.nextSeq - 1,
		Hash: s.lastHash,
		Time: time.Now(),
	}
	if n := len(s.checkpoints); n > 0 {
		cp.Index = s.checkpoints[n-1].Index + 1
		cp.PrevHash = s.checkpoints[n-1].hash()
	} else {
		cp.Index = 1
		cp.PrevHash = GenesisHash
	}
	line, err := json.Marshal(cp)
	if err != nil {
		return nil, wrapErr(KindWrite, "checkpoint", err)
	}
	f, err := os.OpenFile(checkpointPath(s.cfg.Dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, wrapErr(KindWrite, "checkpoint", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, wrapErr(KindWrite, "checkpoint", err)
	}
	if err := f.Sync(); err != nil {
		return nil, wrapErr(KindWrite, "checkpoint", err)
	}
	s.checkpoints = append(s.checkpoints, cp)
	out := cp
	return &out, nil
}

// LatestCheckpoint 返回最近的校验点，无则返回 nil。
func (s *Store) LatestCheckpoint() *Checkpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.checkpoints) == 0 {
		return nil
	}
	cp := s.checkpoints[len(s.checkpoints)-1]
	return &cp
}

// Anchor 返回本地锚定值：最近校验点的链式哈希。
// 对外发布该值即可证明此位置之前的链条未被回退或改写。
func (s *Store) Anchor() Hash {
	if cp := s.LatestCheckpoint(); cp != nil {
		return cp.hash()
	}
	return GenesisHash
}
