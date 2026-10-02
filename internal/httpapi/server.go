package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/feng111627/auth-session-hardening-go/internal/auth"
	"github.com/feng111627/auth-session-hardening-go/internal/csrf"
	"github.com/feng111627/auth-session-hardening-go/internal/ratelimit"
	"github.com/feng111627/auth-session-hardening-go/internal/rbac"
	"github.com/feng111627/auth-session-hardening-go/internal/session"
)

const (
	sessionCookieName = "sid"
	preloginCookie    = "csrf_pre" // 登录前匿名票据：用于把登录请求与令牌绑定
	csrfHeader        = "X-CSRF-Token"
	authzCookie       = "authz_csrf" // 登录后 CSRF 令牌双提交 Cookie
)

// Server 持有 HTTP 层依赖。
type Server struct {
	authSvc  *auth.Service
	sessions *session.Manager
	csrf     *csrf.Protector
	authz    *rbac.Authorizer
	secure   bool // 生产环境应置 true（仅 HTTPS 发送 Cookie）
}

func New(authSvc *auth.Service, sessions *session.Manager, protector *csrf.Protector,
	authz *rbac.Authorizer, secure bool) *Server {
	return &Server{authSvc: authSvc, sessions: sessions, csrf: protector, authz: authz, secure: secure}
}

// Handler 注册全部路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csrf", s.handleIssuePreloginCSRF)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/profile", s.handleProfileRead)
	mux.HandleFunc("POST /api/profile", s.handleProfileWrite)
	mux.HandleFunc("GET /api/orders", s.handleOrdersRead)
	mux.HandleFunc("POST /api/admin/action", s.handleAdminAction)
	return mux
}

// clientIP 提取来源标识，用于限流维度。
func clientIP(r *http.Request) string {
	// 不信任 X-Forwarded-For（可伪造）；经反向代理部署时应在代理层处理。
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorBody 是统一错误响应。message 面向调用方，不区分账号是否存在；
// code 仅在非账号枚举场景下用于区分拒绝原因（CSRF/限流/会话/越权）。
func errorBody(code, message string) map[string]string {
	return map[string]string{"error": message, "code": code}
}

// writeAuthError 把 auth.Error 映射为可解释但不泄露账号信息的 HTTP 响应。
func (s *Server) writeAuthError(w http.ResponseWriter, err *auth.Error) {
	switch err.Code {
	case auth.ErrRateLimited:
		writeJSON(w, http.StatusTooManyRequests, errorBody("rate_limited", "请求过于频繁，请稍后再试"))
	case auth.ErrCSRFInvalid:
		writeJSON(w, http.StatusForbidden, errorBody("csrf_invalid", "安全校验失败，请刷新页面后重试"))
	case auth.ErrSessionInvalid:
		writeJSON(w, http.StatusUnauthorized, errorBody("unauthorized", "登录已失效，请重新登录"))
	case auth.ErrForbidden:
		writeJSON(w, http.StatusForbidden, errorBody("forbidden", "无权访问该资源"))
	default:
		// ErrInvalidCredentials：固定文案，账号不存在与密码错误完全一致。
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid_credentials", "用户名或密码错误"))
	}
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// handleIssuePreloginCSRF 返回当前调用方可用的 CSRF 令牌：
//   - 已登录：补发绑定当前会话的令牌（不改变会话本身）；
//   - 未登录：建立匿名票据并下发绑定该票据的登录前令牌。
func (s *Server) handleIssuePreloginCSRF(w http.ResponseWriter, r *http.Request) {
	if sid, err := r.Cookie(sessionCookieName); err == nil && sid.Value != "" {
		if sess, ok := s.sessions.Get(sid.Value); ok {
			token := s.csrf.Issue(sess.ID)
			s.setCookie(w, r, authzCookie, token, false)
			writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
			return
		}
		// 会话无效：清除可能残留的 Cookie，走匿名票据流程。
		s.clearCookie(w, sessionCookieName)
	}
	pre, err := r.Cookie(preloginCookie)
	if err != nil || pre.Value == "" {
		pre = &http.Cookie{Value: newRandomToken()}
		s.setCookie(w, r, preloginCookie, pre.Value, false)
	}
	token := s.csrf.Issue(pre.Value)
	s.setCookie(w, r, authzCookie, token, false)
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	pre, err := r.Cookie(preloginCookie)
	binding := ""
	if err == nil {
		binding = pre.Value
	}
	token := r.Header.Get(csrfHeader)

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad_request", "请求格式错误"))
		return
	}

	res, err2 := s.authSvc.Login(clientIP(r), req.Username, req.Password, binding, token)
	if err2 != nil {
		if ae, ok := err2.(*auth.Error); ok {
			s.writeAuthError(w, ae)
		} else {
			writeJSON(w, http.StatusInternalServerError, errorBody("internal", "服务暂时不可用"))
		}
		return
	}

	// 登录成功：旧匿名票据作废，下发全新会话 ID 与绑定新会话的 CSRF 令牌。
	s.clearCookie(w, preloginCookie)
	s.setCookie(w, r, sessionCookieName, res.SessionID, true)
	s.setCookie(w, r, authzCookie, res.CSRFToken, false)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   res.Username,
		"roles":      res.Roles,
		"csrf_token": res.CSRFToken,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.authSvc.Logout(sid.Value)
	}
	s.clearCookie(w, sessionCookieName)
	s.clearCookie(w, authzCookie)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// guard 是鉴权类端点的统一前置：取会话 Cookie -> 服务层鉴权。
func (s *Server) guard(w http.ResponseWriter, r *http.Request, resource string, action rbac.Action, requireCSRF bool) (*session.Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		writeJSON(w, http.StatusUnauthorized, errorBody("unauthorized", "登录已失效，请重新登录"))
		return nil, false
	}
	// 双重提交：只接受请求头中的令牌。
	// 不能仅凭 authz_csrf Cookie 通过——跨站请求会自动携带 Cookie，
	// 而攻击者受同源策略限制无法读取 Cookie 值并写入请求头。
	token := r.Header.Get(csrfHeader)
	sess, aerr := s.authSvc.AuthorizeRequest(c.Value, token, resource, action, requireCSRF)
	if aerr != nil {
		s.writeAuthError(w, aerr.(*auth.Error))
		return nil, false
	}
	return sess, true
}

func (s *Server) handleProfileRead(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.guard(w, r, rbac.ResourceProfile, rbac.ActionRead, false)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": sess.UserID, "username": sess.Username})
}

func (s *Server) handleProfileWrite(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.guard(w, r, rbac.ResourceProfile, rbac.ActionWrite, true)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "by": sess.Username})
}

func (s *Server) handleOrdersRead(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.guard(w, r, rbac.ResourceOrders, rbac.ActionRead, false)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": []string{}, "user_id": sess.UserID})
}

func (s *Server) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.guard(w, r, rbac.ResourceAdmin, rbac.ActionAdmin, true)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "by": sess.Username})
}

// 确保未使用的包被引用（ratelimit 仅在服务层使用，这里保留导入检查）。
var _ = ratelimit.Key
