package audit

import "fmt"

// ErrCode 区分可区分的错误类别。
type ErrCode int

const (
	ErrCodeWrite    ErrCode = iota + 1 // 写入失败
	ErrCodeVerify                      // 校验失败（检测到篡改）
	ErrCodeRecover                     // 恢复不一致
	ErrCodeNotFound                    // 记录不存在
	ErrCodeConfig                      // 配置非法
	ErrCodeClosed                      // 对已关闭的日志操作
)

// Error 是可区分的错误类型，携带出错的序号定位。
type Error struct {
	Code ErrCode
	Seq  uint64 // 相关记录序号，0 表示不适用
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("audit: code=%d seq=%d: %s: %v", e.Code, e.Seq, e.Msg, e.Err)
	}
	return fmt.Sprintf("audit: code=%d seq=%d: %s", e.Code, e.Seq, e.Msg)
}

func (e *Error) Unwrap() error { return e.Err }

func writeErr(seq uint64, msg string, err error) *Error {
	return &Error{Code: ErrCodeWrite, Seq: seq, Msg: msg, Err: err}
}
func verifyErr(seq uint64, msg string) *Error {
	return &Error{Code: ErrCodeVerify, Seq: seq, Msg: msg}
}
func recoverErr(seq uint64, msg string, err error) *Error {
	return &Error{Code: ErrCodeRecover, Seq: seq, Msg: msg, Err: err}
}
func notFoundErr(seq uint64) *Error {
	return &Error{Code: ErrCodeNotFound, Seq: seq, Msg: "record not found"}
}
