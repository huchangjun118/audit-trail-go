package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const segmentFileExt = ".seg"

// segment 描述一个段文件的元信息。
type segment struct {
	firstSeq  uint64
	lastSeq   uint64
	path      string
	size      int64
	createdAt time.Time
	sealed    bool // 已轮转（只读）
}

func segmentName(firstSeq uint64) string {
	return fmt.Sprintf("%020d%s", firstSeq, segmentFileExt)
}

// listSegments 按首序号升序列出目录下所有段文件。
func listSegments(dir string) ([]*segment, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var segs []*segment
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, segmentFileExt) {
			continue
		}
		first, err := strconv.ParseUint(strings.TrimSuffix(name, segmentFileExt), 10, 64)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		segs = append(segs, &segment{
			firstSeq:  first,
			path:      filepath.Join(dir, name),
			size:      info.Size(),
			createdAt: info.ModTime(),
		})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].firstSeq < segs[j].firstSeq })
	return segs, nil
}

// segmentWriter 负责向当前活跃段追加帧。
type segmentWriter struct {
	f   *os.File
	seg *segment
}

func createSegment(dir string, firstSeq uint64) (*segmentWriter, error) {
	path := filepath.Join(dir, segmentName(firstSeq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &segmentWriter{f: f, seg: &segment{firstSeq: firstSeq, path: path, createdAt: time.Now()}}, nil
}

func openSegmentAppend(path string, seg *segment) (*segmentWriter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &segmentWriter{f: f, seg: seg}, nil
}

// appendFrame 写入一帧并更新段元信息。
func (w *segmentWriter) appendFrame(frame []byte, seq uint64) error {
	if _, err := w.f.Write(frame); err != nil {
		return err
	}
	w.seg.size += int64(len(frame))
	w.seg.lastSeq = seq
	return nil
}

func (w *segmentWriter) sync() error  { return w.f.Sync() }
func (w *segmentWriter) close() error { return w.f.Close() }

// readSegment 顺序读取一个段内的所有完整记录。
// 用于正常读取；遇到不完整数据返回错误。
func readSegment(path string) ([]*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*Record
	for off := 0; off < len(data); {
		r, n, err := decodeFrame(data[off:])
		if err != nil {
			return nil, fmt.Errorf("segment %s offset %d: %w", path, off, err)
		}
		out = append(out, r)
		off += n
	}
	return out, nil
}

// scanSegment 扫描段文件，返回所有完整记录与有效字节数。
// 遇到半帧（崩溃残留）时停止，validLen 指向最后一条完整记录的末尾，
// 调用方可据此截断。CRC 错误同样视为截断点。
func scanSegment(path string) (recs []*Record, validLen int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	off := 0
	for off < len(data) {
		r, n, derr := decodeFrame(data[off:])
		if derr != nil {
			// 半帧或损坏：有效数据到此为止
			break
		}
		recs = append(recs, r)
		off += n
	}
	return recs, int64(off), nil
}
