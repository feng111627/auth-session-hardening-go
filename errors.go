package auth

import "errors"

// Reason 是可区分的内部失败原因，仅用于日志与测试，
// 对外响应时必须映射为不泄露账号信息的通用文案。
type Reason string

const (
	ReasonBadCredentials Reason = "bad_credentials"
	ReasonRateLimited    Reason = "rate_limited"
	ReasonCSRFInvalid    Reason = "csrf_invalid"
	ReasonSessionExpired Reason = "session_expired"
	ReasonSessionRevoked Reason = "session_revoked"
	ReasonSessionUnknown Reason = "session_unknown"
	ReasonForbidden      Reason = "forbidden"
)

// Error 携带内部原因，errors.Is/As 可判定。
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func reasonErr(r Reason, msg string) *Error {
	return &Error{Reason: r, Err: errors.New(msg)}
}

// ReasonOf 从错误中提取内部原因；非本包错误返回空串。
func ReasonOf(err error) Reason {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ""
}
