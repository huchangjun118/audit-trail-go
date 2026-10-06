package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// HashLen 是链式哈希的字节长度（SHA-256）。
const HashLen = sha256.Size

// Hash 是记录链哈希值。
type Hash [HashLen]byte

// GenesisHash 是第一条记录的 PrevHash。
var GenesisHash Hash

// Record 是一条已提交的留痕记录，写入后不可变。
type Record struct {
	Seq       uint64    `json:"seq"`
	Timestamp time.Time `json:"ts"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Payload   []byte    `json:"payload,omitempty"`
	PrevHash  Hash      `json:"prev"`
	Hash      Hash      `json:"hash"`
}

// computeHash 对记录内容做规范化哈希（不含 Hash 字段本身）。
func computeHash(seq uint64, ts time.Time, actor, action string, payload []byte, prev Hash) Hash {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], seq)
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(ts.UnixNano()))
	h.Write(buf[:])
	writeStr(h, actor)
	writeStr(h, action)
	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], uint32(len(payload)))
	h.Write(lb[:])
	h.Write(payload)
	h.Write(prev[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func writeStr(h interface{ Write([]byte) (int, error) }, s string) {
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(len(s)))
	h.Write(lb[:])
	h.Write([]byte(s))
}

// compute 填充 PrevHash 与 Hash。
func (r *Record) seal(prev Hash) {
	r.PrevHash = prev
	r.Hash = computeHash(r.Seq, r.Timestamp, r.Actor, r.Action, r.Payload, prev)
}

// verifyHash 校验记录自身哈希是否匹配。
func (r *Record) verifyHash() bool {
	return r.Hash == computeHash(r.Seq, r.Timestamp, r.Actor, r.Action, r.Payload, r.PrevHash)
}
