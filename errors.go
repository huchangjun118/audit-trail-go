package audit

import "fmt"

// ErrKind 区分可区分的错误类别。
type ErrKind string

const (
	KindWrite    ErrKind = "write"   // 写入失败
	KindVerify   ErrKind = "verify"  // 校验失败（检测到篡改）
	KindRecover  ErrKind = "recover" // 恢复不一致
	KindConfig   ErrKind = "config"  // 配置非法
	KindNotFound ErrKind = "notfound"
)

// Error 是可定位到具体记录序号的错误。
type Error struct {
	Kind   ErrKind
	Op     string // 出错的操作
	Seq    uint64 // 相关记录序号（最早出问题的位置），无则为 0 且 HasSeq=false
	HasSeq bool
	Err    error
}

func (e *Error) Error() string {
	if e.HasSeq {
		return fmt.Sprintf("audit: %s %s at seq %d: %v", e.Kind, e.Op, e.Seq, e.Err)
	}
	return fmt.Sprintf("audit: %s %s: %v", e.Kind, e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func wrapErr(kind ErrKind, op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Kind: kind, Op: op, Err: err}
}

func seqErr(kind ErrKind, op string, seq uint64, err error) error {
	return &Error{Kind: kind, Op: op, Seq: seq, HasSeq: true, Err: err}
}
