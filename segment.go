package audit

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
)

// segment 是单个只追加段文件的写入句柄。
type segment struct {
	f       *os.File
	path    string
	baseSeq uint64 // 段内第一条记录的序号（空段为下一条将写入的序号）
	size    int64
	sealed  bool
}

// frameHeaderLen 是每条记录帧头长度：4 字节长度 + 4 字节 CRC32。
const frameHeaderLen = 8

// encodeFrame 将记录编码为一帧：[len uint32][crc32 uint32][json payload]。
func encodeFrame(r *Record) ([]byte, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, frameHeaderLen+len(payload))
	binary.LittleEndian.PutUint32(frame[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(frame[4:8], crc32.ChecksumIEEE(payload))
	copy(frame[frameHeaderLen:], payload)
	return frame, nil
}

// openSegmentForAppend 打开或创建段文件，扫描并截掉不完整/损坏的尾部帧，
// 返回段对象与该段内全部完整记录（用于崩溃恢复）。
func openSegmentForAppend(path string, baseSeq uint64) (*segment, []Record, error) {
	recs, goodBytes, err := readSegmentRecords(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, err
	}
	// 截断到最后一条完整记录处，消除半帧。
	if err := f.Truncate(goodBytes); err != nil {
		f.Close()
		return nil, nil, err
	}
	return &segment{f: f, path: path, baseSeq: baseSeq, size: goodBytes}, recs, nil
}

// appendRecord 追加一条记录帧（不 fsync，由调用方统一 sync）。
func (s *segment) appendRecord(r *Record) error {
	if s.sealed {
		return errors.New("append on sealed segment")
	}
	frame, err := encodeFrame(r)
	if err != nil {
		return err
	}
	if _, err := s.f.Write(frame); err != nil {
		return err
	}
	s.size += int64(len(frame))
	return nil
}

// sync 将段数据落盘。
func (s *segment) sync() error {
	return s.f.Sync()
}

// seal 关闭写入并将段标记为封存。
func (s *segment) seal() error {
	if s.sealed {
		return nil
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.sealed = true
	return s.f.Close()
}

// readSegmentRecords 顺序读取段内全部完整记录；遇坏帧（长度非法、CRC 不符、
// JSON 解析失败、文件截断）即停，返回已读完整记录与最后一个好帧的字节偏移。
func readSegmentRecords(path string) (recs []Record, goodBytes int64, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var off int64
	for {
		hdr := make([]byte, frameHeaderLen)
		n, rerr := io.ReadFull(f, hdr)
		if rerr != nil {
			if rerr == io.EOF && n == 0 {
				break // 干净结束
			}
			break // 半帧：停在此处
		}
		l := binary.LittleEndian.Uint32(hdr[0:4])
		crc := binary.LittleEndian.Uint32(hdr[4:8])
		if l == 0 || l > 64<<20 {
			break // 长度非法
		}
		payload := make([]byte, l)
		if _, rerr := io.ReadFull(f, payload); rerr != nil {
			break // 截断的 payload
		}
		if crc32.ChecksumIEEE(payload) != crc {
			break // CRC 不符
		}
		var r Record
		if json.Unmarshal(payload, &r) != nil {
			break // 内容损坏
		}
		recs = append(recs, r)
		off += int64(frameHeaderLen) + int64(l)
	}
	return recs, off, nil
}
