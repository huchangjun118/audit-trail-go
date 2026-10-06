package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"time"
)

// HashLen 是链哈希的字节长度（SHA-256）。
const HashLen = 32

// Hash 是记录链哈希类型。
type Hash [HashLen]byte

// Record 是一条不可变的操作留痕记录。
type Record struct {
	Seq       uint64    // 严格递增、无空洞的提交序号
	Timestamp time.Time // 提交时间（UTC）
	Actor     string    // 操作主体
	Action    string    // 操作类型
	Payload   []byte    // 操作内容
	PrevHash  Hash      // 前一条记录的链哈希
	Hash      Hash      // 本记录的链哈希
}

// Entry 是追加时的输入（序号、时间、哈希由日志在提交时填充）。
type Entry struct {
	Actor   string
	Action  string
	Payload []byte
}

var (
	errFrameShort = errors.New("audit: incomplete frame")
	errFrameCRC   = errors.New("audit: frame crc mismatch")
)

const (
	frameLenSize = 4
	frameCRCSize = 4
)

// computeHash 计算记录链哈希：H(prev || seq || ts || actor || action || payload)。
// 全部使用定长前缀编码，避免拼接歧义，结果与遍历顺序无关。
func computeHash(prev Hash, seq uint64, ts time.Time, actor, action string, payload []byte) Hash {
	h := sha256.New()
	h.Write([]byte("AUDITREC1"))
	h.Write(prev[:])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(ts.UnixNano()))
	h.Write(b[:])
	writeLenPrefixed(h, []byte(actor))
	writeLenPrefixed(h, []byte(action))
	writeLenPrefixed(h, payload)
	var out Hash
	h.Sum(out[:0])
	return out
}

func writeLenPrefixed(w interface{ Write([]byte) (int, error) }, p []byte) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(p)))
	w.Write(b[:])
	w.Write(p)
}

// encodeRecord 将记录编码为一帧：[4B 长度][主体][4B CRC32(主体)]。
// 主体为记录的规范二进制编码（含链哈希）。
func encodeRecord(r *Record) []byte {
	body := encodeBody(r)
	frame := make([]byte, 0, frameLenSize+len(body)+frameCRCSize)
	var lb [frameLenSize]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(body)))
	frame = append(frame, lb[:]...)
	frame = append(frame, body...)
	var cb [frameCRCSize]byte
	binary.BigEndian.PutUint32(cb[:], crc32.ChecksumIEEE(body))
	frame = append(frame, cb[:]...)
	return frame
}

func encodeBody(r *Record) []byte {
	buf := make([]byte, 0, 64+len(r.Actor)+len(r.Action)+len(r.Payload))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], r.Seq)
	buf = append(buf, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(r.Timestamp.UnixNano()))
	buf = append(buf, b[:]...)
	buf = appendLenPrefixed(buf, []byte(r.Actor))
	buf = appendLenPrefixed(buf, []byte(r.Action))
	buf = appendLenPrefixed(buf, r.Payload)
	buf = append(buf, r.PrevHash[:]...)
	buf = append(buf, r.Hash[:]...)
	return buf
}

func appendLenPrefixed(buf, p []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(p)))
	buf = append(buf, b[:]...)
	return append(buf, p...)
}

// decodeFrame 从 buf 起始处解析一帧，返回记录与消耗字节数。
// 数据不足返回 errFrameShort，CRC 不符返回 errFrameCRC。
func decodeFrame(buf []byte) (*Record, int, error) {
	if len(buf) < frameLenSize {
		return nil, 0, errFrameShort
	}
	bodyLen := int(binary.BigEndian.Uint32(buf[:frameLenSize]))
	total := frameLenSize + bodyLen + frameCRCSize
	if len(buf) < total {
		return nil, 0, errFrameShort
	}
	body := buf[frameLenSize : frameLenSize+bodyLen]
	crc := binary.BigEndian.Uint32(buf[frameLenSize+bodyLen : total])
	if crc32.ChecksumIEEE(body) != crc {
		return nil, 0, errFrameCRC
	}
	r, err := decodeBody(body)
	if err != nil {
		return nil, 0, err
	}
	return r, total, nil
}

func decodeBody(body []byte) (*Record, error) {
	r := &Record{}
	p := parser{buf: body}
	var ok bool
	if r.Seq, ok = p.u64(); !ok {
		return nil, errFrameShort
	}
	nanos, ok := p.u64()
	if !ok {
		return nil, errFrameShort
	}
	r.Timestamp = time.Unix(0, int64(nanos)).UTC()
	if r.Actor, ok = p.str(); !ok {
		return nil, errFrameShort
	}
	if r.Action, ok = p.str(); !ok {
		return nil, errFrameShort
	}
	if r.Payload, ok = p.bytes(); !ok {
		return nil, errFrameShort
	}
	if !p.hash(&r.PrevHash) || !p.hash(&r.Hash) {
		return nil, errFrameShort
	}
	if p.off != len(body) {
		return nil, errors.New("audit: trailing bytes in frame body")
	}
	return r, nil
}

type parser struct {
	buf []byte
	off int
}

func (p *parser) u64() (uint64, bool) {
	if p.off+8 > len(p.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(p.buf[p.off:])
	p.off += 8
	return v, true
}

func (p *parser) bytes() ([]byte, bool) {
	if p.off+4 > len(p.buf) {
		return nil, false
	}
	n := int(binary.BigEndian.Uint32(p.buf[p.off:]))
	p.off += 4
	if p.off+n > len(p.buf) {
		return nil, false
	}
	v := p.buf[p.off : p.off+n]
	p.off += n
	return v, true
}

func (p *parser) str() (string, bool) {
	b, ok := p.bytes()
	return string(b), ok
}

func (p *parser) hash(h *Hash) bool {
	if p.off+HashLen > len(p.buf) {
		return false
	}
	copy(h[:], p.buf[p.off:p.off+HashLen])
	p.off += HashLen
	return true
}
