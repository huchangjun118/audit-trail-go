package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store 是只追加留痕存储，支持并发追加与并发读取。
type Store struct {
	cfg Config

	mu      sync.Mutex // 序列化提交，保证序号严格递增无空洞
	viewMu  sync.RWMutex
	records []Record // 已提交记录（内存索引，只增不改）

	seg      *segment
	nextSeq  uint64
	lastHash Hash
	segStart time.Time

	checkpoints []Checkpoint
	anchors     []RetentionAnchor

	closed bool
}

const segmentFilePattern = "seg-*.log"

func segmentPath(dir string, baseSeq uint64) string {
	return filepath.Join(dir, fmt.Sprintf("seg-%020d.log", baseSeq))
}

// Open 打开（必要时创建）存储并执行崩溃恢复：
// 截断最后段的撕裂尾部，校验全链序号连续与哈希链一致。
func Open(cfg Config) (*Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, wrapErr(KindWrite, "open", err)
	}
	s := &Store{cfg: cfg, nextSeq: 1, lastHash: GenesisHash}

	paths, err := filepath.Glob(filepath.Join(cfg.Dir, segmentFilePattern))
	if err != nil {
		return nil, wrapErr(KindRecover, "open", err)
	}
	sort.Strings(paths) // 文件名零填充，字典序即序号序

	for i, p := range paths {
		base, err := parseSegmentBase(p)
		if err != nil {
			return nil, wrapErr(KindRecover, "open", err)
		}
		recs, goodBytes, rerr := readSegmentRecords(p)
		if rerr != nil {
			return nil, wrapErr(KindRecover, "open", rerr)
		}
		fi, statErr := os.Stat(p)
		if statErr != nil {
			return nil, wrapErr(KindRecover, "open", statErr)
		}
		torn := fi.Size() != goodBytes
		if torn && i != len(paths)-1 {
			// 非末段出现撕裂尾：恢复不一致，定位到该段首条。
			return nil, seqErr(KindRecover, "open", base,
				errors.New("torn tail in non-final segment"))
		}
		// 校验序号连续与哈希链。
		for _, r := range recs {
			if r.Seq != s.nextSeq {
				return nil, seqErr(KindRecover, "open", s.nextSeq,
					fmt.Errorf("sequence gap: expected %d, found %d", s.nextSeq, r.Seq))
			}
			if r.PrevHash != s.lastHash || !r.verifyHash() {
				return nil, seqErr(KindRecover, "open", r.Seq,
					errors.New("hash chain broken"))
			}
			s.records = append(s.records, r)
			s.lastHash = r.Hash
			s.nextSeq++
		}
		if torn {
			if err := os.Truncate(p, goodBytes); err != nil {
				return nil, wrapErr(KindRecover, "open", err)
			}
		}
	}

	// 加载校验点链与保留锚点。
	cps, err := loadCheckpoints(cfg.Dir)
	if err != nil {
		return nil, err
	}
	s.checkpoints = cps
	anchors, err := loadRetentionAnchors(cfg.Dir)
	if err != nil {
		return nil, err
	}
	s.anchors = anchors

	// 打开当前活跃段（复用末段或新建）。
	if len(paths) > 0 {
		last := paths[len(paths)-1]
		base, _ := parseSegmentBase(last)
		recs, _, err := readSegmentRecords(last)
		if err != nil {
			return nil, wrapErr(KindRecover, "open", err)
		}
		seg, _, err := openSegmentForAppend(last, base)
		if err != nil {
			return nil, wrapErr(KindRecover, "open", err)
		}
		_ = recs
		s.seg = seg
	} else {
		if err := s.rotateLocked(); err != nil {
			return nil, err
		}
	}
	s.segStart = time.Now()
	return s, nil
}

func parseSegmentBase(path string) (uint64, error) {
	name := filepath.Base(path)
	name = strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ".log")
	base, err := strconv.ParseUint(name, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad segment name %q", path)
	}
	return base, nil
}

// rotateLocked 封存当前段并开启新段。调用方须持有 s.mu。
func (s *Store) rotateLocked() error {
	if s.seg != nil {
		if err := s.seg.seal(); err != nil {
			return wrapErr(KindWrite, "rotate", err)
		}
	}
	seg, _, err := openSegmentForAppend(segmentPath(s.cfg.Dir, s.nextSeq), s.nextSeq)
	if err != nil {
		return wrapErr(KindWrite, "rotate", err)
	}
	s.seg = seg
	s.segStart = time.Now()
	return nil
}

// BatchItem 是批量追加的单条输入。
type BatchItem struct {
	Actor   string
	Action  string
	Payload []byte
}

// Append 追加一条记录，返回分配的序号。
func (s *Store) Append(actor, action string, payload []byte) (uint64, error) {
	seqs, err := s.AppendBatch([]BatchItem{{Actor: actor, Action: action, Payload: payload}})
	if err != nil {
		return 0, err
	}
	return seqs[0], nil
}

// AppendBatch 原子追加一批记录：序号按切片顺序连续分配，
// 整批要么全部提交并对读者可见，要么全部失败且不留脏数据。
// 结果只取决于提交批次内容与提交顺序，与并发调度、遍历顺序无关。
func (s *Store) AppendBatch(items []BatchItem) ([]uint64, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > s.cfg.MaxBatchRecords {
		return nil, wrapErr(KindWrite, "append",
			fmt.Errorf("batch size %d exceeds MaxBatchRecords %d", len(items), s.cfg.MaxBatchRecords))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, wrapErr(KindWrite, "append", errors.New("store closed"))
	}

	now := time.Now()
	// 构造本批记录（序号连续、链式哈希）。
	recs := make([]Record, len(items))
	prev := s.lastHash
	for i, it := range items {
		recs[i] = Record{
			Seq:       s.nextSeq + uint64(i),
			Timestamp: now,
			Actor:     it.Actor,
			Action:    it.Action,
			Payload:   it.Payload,
		}
		recs[i].seal(prev)
		prev = recs[i].Hash
	}

	// 写入当前段；失败则截断回批前位置，保证不留下半批脏数据。
	startSize := s.seg.size
	written := 0
	fail := func(err error) error {
		if terr := os.Truncate(s.seg.path, startSize); terr == nil {
			s.seg.size = startSize
		}
		return wrapErr(KindWrite, "append", err)
	}
	for i := range recs {
		if err := s.seg.appendRecord(&recs[i]); err != nil {
			return nil, fail(err)
		}
		written++
	}
	if s.cfg.Fsync {
		if err := s.seg.sync(); err != nil {
			return nil, fail(err)
		}
	}

	// 落盘成功后发布：读者此刻起可见完整批次。
	s.viewMu.Lock()
	s.records = append(s.records, recs...)
	s.viewMu.Unlock()
	s.lastHash = prev
	s.nextSeq += uint64(len(recs))

	// 段轮转：大小或周期超限且当前段非空。
	if s.seg.size >= s.cfg.SegmentMaxBytes || time.Since(s.segStart) >= s.cfg.RotationInterval {
		if err := s.rotateLocked(); err != nil {
			return nil, err
		}
	}

	seqs := make([]uint64, len(recs))
	for i := range recs {
		seqs[i] = recs[i].Seq
	}
	return seqs, nil
}

// Close 封存当前段并关闭存储。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.seg != nil {
		if err := s.seg.seal(); err != nil {
			return wrapErr(KindWrite, "close", err)
		}
	}
	return nil
}
