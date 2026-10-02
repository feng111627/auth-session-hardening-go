package auth

import (
	"errors"

	"github.com/feng111627/auth-session-hardening-go/internal/csrf"
	"github.com/feng111627/auth-session-hardening-go/internal/ratelimit"
	"github.com/feng111627/auth-session-hardening-go/internal/rbac"
	"github.com/feng111627/auth-session-hardening-go/internal/session"
)

// ErrorCode 是可程序化区分的拒绝原因，供内部日志/测试断言使用。
// 对外呈现时统一使用不含账号存在性信息的文案（见 httpapi）。
type ErrorCode string

const (
	// ErrInvalidCredentials 账号或密码错误；账号不存在与密码错误共用此码。
	ErrInvalidCredentials ErrorCode = "invalid_credentials"
	// ErrRateLimited 命中登录失败限流。
	ErrRateLimited ErrorCode = "rate_limited"
	// ErrCSRFInvalid CSRF 令牌缺失/错误/绑定不匹配。
	ErrCSRFInvalid ErrorCode = "csrf_invalid"
	// ErrSessionInvalid 会话不存在、已过期或已撤销。
	ErrSessionInvalid ErrorCode = "session_invalid"
	// ErrForbidden 已登录但缺少访问该资源所需角色。
	ErrForbidden ErrorCode = "forbidden"
)

// Error 携带可区分错误码与内部原因说明。
type Error struct {
	Code   ErrorCode
	Reason string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Reason }

func authError(code ErrorCode, reason string) *Error {
	return &Error{Code: code, Reason: reason}
}

// CodeOf 从任意 error 中提取 ErrorCode；非 *Error 返回空串。
func CodeOf(err error) ErrorCode {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// UserDirectory 抽象账号存储。
// exists=false 表示账号不存在；此信息仅用于内部，不得直接回传给客户端。
type UserDirectory interface {
	Authenticate(username, password string) (userID string, roles []string, exists bool, err error)
}

// LoginResult 是登录成功后的返回内容。
type LoginResult struct {
	SessionID string
	UserID    string
	Username  string
	Roles     []string
	CSRFToken string
}

// Service 组合会话、限流、CSRF 与 RBAC，提供登录与请求鉴权。
type Service struct {
	dir      UserDirectory
	sessions *session.Manager
	limiter  *ratelimit.Limiter
	csrf     *csrf.Protector
	authz    *rbac.Authorizer
}

func NewService(dir UserDirectory, sessions *session.Manager, limiter *ratelimit.Limiter,
	protector *csrf.Protector, authz *rbac.Authorizer) *Service {
	return &Service{dir: dir, sessions: sessions, limiter: limiter, csrf: protector, authz: authz}
}

// Login 执行登录：
//  1. 校验 CSRF（登录前令牌绑定匿名票据，防止跨站登录伪造）；
//  2. 检查限流，封禁期稳定拒绝；
//  3. 认证账号：账号不存在与密码错误返回完全相同的错误；
//  4. 成功后轮换为全新会话 ID（防会话固定），并签发绑定新会话的 CSRF 令牌。
func (s *Service) Login(source, username, password, csrfBinding, csrfToken string) (*LoginResult, error) {
	if !s.csrf.Validate(csrfBinding, csrfToken) {
		return nil, authError(ErrCSRFInvalid, "missing or invalid CSRF token")
	}

	key := ratelimit.Key(source, username)
	if !s.limiter.Allow(key) {
		return nil, authError(ErrRateLimited, "too many failed attempts; please try again later")
	}

	userID, roles, exists, err := s.dir.Authenticate(username, password)
	if err != nil {
		// 存储层故障不泄露细节，也不消耗失败计数。
		return nil, authError(ErrInvalidCredentials, "authentication unavailable")
	}
	if !exists || userID == "" {
		// 与密码错误完全相同的返回，避免账号枚举。
		s.limiter.RecordFailure(key)
		return nil, authError(ErrInvalidCredentials, "invalid username or password")
	}

	// 登录成功：清除该来源+账号的失败计数，创建全新会话（不复用登录前的会话标识）。
	s.limiter.RecordSuccess(key)
	sess := s.sessions.Create(userID, username, roles)
	return &LoginResult{
		SessionID: sess.ID,
		UserID:    sess.UserID,
		Username:  sess.Username,
		Roles:     append([]string(nil), sess.Roles...),
		CSRFToken: s.csrf.Issue(sess.ID),
	}, nil
}

// Logout 立即撤销会话，撤销后任何请求都不能再使用它。
func (s *Service) Logout(sessionID string) {
	s.sessions.Revoke(sessionID)
}

// IssueCSRF 在客户端丢失令牌时为当前会话补发绑定令牌。
func (s *Service) IssueCSRF(sessionID string) (string, error) {
	sess, ok := s.sessions.Get(sessionID)
	if !ok {
		return "", authError(ErrSessionInvalid, "session not found, expired or revoked")
	}
	return s.csrf.Issue(sess.ID), nil
}

// AuthorizeRequest 鉴权一次请求：
//   - Touch 完成滑动续期并同时判定会话有效性（过期/撤销立即拒绝）；
//   - 对敏感（状态变更）操作强制校验绑定会话的 CSRF 令牌；
//   - 最后做基于角色 × 资源 × 动作的 RBAC 校验，默认拒绝。
//
// 任一步失败都返回对应 ErrorCode，便于解释与观测。
func (s *Service) AuthorizeRequest(sessionID, csrfToken, resource string, action rbac.Action, requireCSRF bool) (*session.Session, error) {
	sess, ok := s.sessions.Touch(sessionID)
	if !ok {
		return nil, authError(ErrSessionInvalid, "session not found, expired or revoked")
	}
	if requireCSRF && !s.csrf.Validate(sess.ID, csrfToken) {
		return nil, authError(ErrCSRFInvalid, "missing or invalid CSRF token")
	}
	if !s.authz.CanAny(sess.Roles, resource, action) {
		return nil, authError(ErrForbidden, "role not permitted for this resource")
	}
	return sess, nil
}
