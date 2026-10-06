package audit

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// recordHeader 是已提交记录的内存索引项。
type recordHeader struct {
	seq      uint64
	ts       time.Time
	actor    string
	segIdx   int   // 所属段在 segs 中的下标
	offset   int64 // 帧在段文件中的偏移
	length   int   // 帧长度
	hash     Hash
	prevHash Hash
}

// Log 是只追加的操作留痕日志。
//
// 并发模型：mu 串行化提交（保证序号严格递增、无空洞、无重复）；
// rmu 保护已提交索引，读者仅在取快照时短暂持有读锁，
// 随后直接读段文件，慢读者不阻塞写入。
type Log struct {
	cfg Config

	mu     sync.Mutex // 提交锁
	writer *segmentWriter

	rmu      sync.RWMutex
	heads    []recordHeader
	segs     []*segment
	lastSeq  uint64
	lastHash Hash
	trunc    TruncationProof // 已删除前缀的证明（无删除时 LastSeq==0）
	closed   bool
}

// Open 打开（必要时创建）日志，并执行崩溃恢复：
// 扫描所有段，截断最后一条完整记录之后的半帧；
// 若链校验不一致则返回可定位序号的恢复错误。
func Open(cfg Config) (*Log, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, recoverErr(0, "create dir", err)
	}
	l := &Log{cfg: cfg}

	// 加载截断证明：被删前缀构成链的起点。
	trunc, err := loadTruncationProof(cfg.Dir)
	if err != nil {
		return nil, recoverErr(0, "load truncation proof", err)
	}
	l.trunc = trunc
	l.lastSeq = trunc.LastSeq
	l.lastHash = trunc.LastHash

	segs, err := listSegments(cfg.Dir)
	if err != nil {
		return nil, recoverErr(0, "list segments", err)
	}

	expectSeq := trunc.LastSeq + 1
	prevHash := trunc.LastHash
	for i, seg := range segs {
		recs, validLen, err := scanSegment(seg.path)
		if err != nil {
			return nil, recoverErr(0, "scan segment "+seg.path, err)
		}
		info, err := os.Stat(seg.path)
		if err != nil {
			return nil, recoverErr(0, "stat segment", err)
		}
		if validLen < info.Size() {
			// 崩溃残留的半帧：只允许出现在最后一个段。
			if i != len(segs)-1 {
				return nil, recoverErr(seg.firstSeq,
					"non-final segment has incomplete tail", nil)
			}
			if err := os.Truncate(seg.path, validLen); err != nil {
				return nil, recoverErr(seg.firstSeq, "truncate partial tail", err)
			}
			seg.size = validLen
		}
		off := int64(0)
		for _, r := range recs {
			if r.Seq != expectSeq {
				return nil, recoverErr(r.Seq,
					fmt.Sprintf("sequence gap: expected %d", expectSeq), nil)
			}
			if r.PrevHash != prevHash {
				return nil, recoverErr(r.Seq, "prev hash mismatch", nil)
			}
			if computeHash(r.PrevHash, r.Seq, r.Timestamp, r.Actor, r.Action, r.Payload) != r.Hash {
				return nil, recoverErr(r.Seq, "hash mismatch", nil)
			}
			l.heads = append(l.heads, recordHeader{
				seq: r.Seq, ts: r.Timestamp, actor: r.Actor,
				segIdx: i, offset: off, length: len(encodeRecord(r)),
				hash: r.Hash, prevHash: r.PrevHash,
			})
			off += int64(len(encodeRecord(r)))
			prevHash = r.Hash
			expectSeq++
		}
		seg.lastSeq = expectSeq - 1
		seg.sealed = i != len(segs)-1
		l.segs = append(l.segs, seg)
	}
	l.lastSeq = expectSeq - 1
	l.lastHash = prevHash

	// 打开（或创建）活跃段。
	if len(l.segs) == 0 {
		w, err := createSegment(cfg.Dir, l.lastSeq+1)
		if err != nil {
			return nil, recoverErr(0, "create first segment", err)
		}
		l.writer = w
		l.segs = append(l.segs, w.seg)
	} else {
		last := l.segs[len(l.segs)-1]
		w, err := openSegmentAppend(last.path, last)
		if err != nil {
			return nil, recoverErr(last.firstSeq, "open active segment", err)
		}
		l.writer = w
	}
	return l, nil
}

// Append 追加一条记录，返回其提交序号。
func (l *Log) Append(actor, action string, payload []byte) (uint64, error) {
	seqs, err := l.AppendBatch([]Entry{{Actor: actor, Action: action, Payload: payload}})
	if err != nil {
		return 0, err
	}
	return seqs[0], nil
}

// AppendBatch 原子追加一批记录：整批获得连续序号，
// 批内顺序即切片顺序，与并发调度无关。
func (l *Log) AppendBatch(entries []Entry) ([]uint64, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.rmu.RLock()
	closed := l.closed
	l.rmu.RUnlock()
	if closed {
		return nil, &Error{Code: ErrCodeClosed, Msg: "log is closed"}
	}
	if len(entries) > l.cfg.MaxBatchSize {
		return nil, writeErr(0, fmt.Sprintf("batch size %d exceeds max %d",
			len(entries), l.cfg.MaxBatchSize), nil)
	}

	// 在提交锁内构造记录：序号连续、链式哈希。
	now := nowUTC()
	recs := make([]*Record, len(entries))
	seq := l.lastSeq
	prev := l.lastHash
	for i, e := range entries {
		seq++
		r := &Record{
			Seq: seq, Timestamp: now, Actor: e.Actor,
			Action: e.Action, Payload: e.Payload, PrevHash: prev,
		}
		r.Hash = computeHash(prev, r.Seq, now, e.Actor, e.Action, e.Payload)
		prev = r.Hash
		recs[i] = r
	}

	// 段轮转：按大小或存活时间。
	frames := make([][]byte, len(recs))
	var batchBytes int64
	for i, r := range recs {
		frames[i] = encodeRecord(r)
		batchBytes += int64(len(frames[i]))
	}
	if l.writer.seg.size > 0 &&
		(l.writer.seg.size+batchBytes > l.cfg.SegmentMaxBytes ||
			time.Since(l.writer.seg.createdAt) > l.cfg.SegmentMaxAge) {
		if err := l.rotate(); err != nil {
			return nil, writeErr(seq-uint64(len(recs))+1, "rotate segment", err)
		}
	}

	// 写盘：整批写入当前段；失败返回可定位序号的写错误。
	baseOff := l.writer.seg.size
	for i, f := range frames {
		if err := l.writer.appendFrame(f, recs[i].Seq); err != nil {
			return nil, writeErr(recs[i].Seq, "append frame", err)
		}
	}
	if l.cfg.SyncEveryWrite {
		if err := l.writer.sync(); err != nil {
			return nil, writeErr(recs[0].Seq, "fsync", err)
		}
	}

	// 发布：提交后才对读者可见。
	l.rmu.Lock()
	segIdx := len(l.segs) - 1
	off := baseOff
	for i, r := range recs {
		l.heads = append(l.heads, recordHeader{
			seq: r.Seq, ts: r.Timestamp, actor: r.Actor,
			segIdx: segIdx, offset: off, length: len(frames[i]),
			hash: r.Hash, prevHash: r.PrevHash,
		})
		off += int64(len(frames[i]))
	}
	l.lastSeq = recs[len(recs)-1].Seq
	l.lastHash = recs[len(recs)-1].Hash
	l.rmu.Unlock()

	seqs := make([]uint64, len(recs))
	for i, r := range recs {
		seqs[i] = r.Seq
	}
	return seqs, nil
}

// rotate 封存当前段并开启新段。调用方须持有 mu。
func (l *Log) rotate() error {
	if err := l.writer.sync(); err != nil {
		return err
	}
	if err := l.writer.close(); err != nil {
		return err
	}
	l.writer.seg.sealed = true
	w, err := createSegment(l.cfg.Dir, l.lastSeq+1)
	if err != nil {
		return err
	}
	l.rmu.Lock()
	l.segs = append(l.segs, w.seg)
	l.rmu.Unlock()
	l.writer = w
	return nil
}

// Get 按序号读取单条已提交记录。
func (l *Log) Get(seq uint64) (*Record, error) {
	l.rmu.RLock()
	if l.closed {
		l.rmu.RUnlock()
		return nil, &Error{Code: ErrCodeClosed, Msg: "log is closed"}
	}
	idx := l.headIndex(seq)
	if idx < 0 {
		l.rmu.RUnlock()
		return nil, notFoundErr(seq)
	}
	h := l.heads[idx]
	path := l.segs[h.segIdx].path
	l.rmu.RUnlock()
	return readFrameAt(path, h.offset, h.length)
}

// headIndex 返回 seq 在 heads 中的下标，不存在返回 -1。调用方须持有 rmu。
func (l *Log) headIndex(seq uint64) int {
	if seq <= l.trunc.LastSeq || seq > l.lastSeq {
		return -1
	}
	return int(seq - l.trunc.LastSeq - 1)
}

// readFrameAt 从段文件的指定偏移读取一帧。读者独立打开文件，
// 不与写入方共享句柄，因此慢读者不阻塞写入。
func readFrameAt(path string, off int64, length int) (*Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, off); err != nil {
		return nil, err
	}
	r, _, err := decodeFrame(buf)
	return r, err
}

// LastSeq 返回当前已提交的最大序号（0 表示空）。
func (l *Log) LastSeq() uint64 {
	l.rmu.RLock()
	defer l.rmu.RUnlock()
	return l.lastSeq
}

// Close 关闭日志：刷盘并关闭活跃段。
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rmu.Lock()
	if l.closed {
		l.rmu.Unlock()
		return nil
	}
	l.closed = true
	l.rmu.Unlock()
	if l.writer != nil {
		if err := l.writer.sync(); err != nil {
			l.writer.close()
			return writeErr(0, "final fsync", err)
		}
		return l.writer.close()
	}
	return nil
}

// nowUTC 返回当前 UTC 时间，便于测试替换。
var nowUTC = func() time.Time { return time.Now().UTC() }
