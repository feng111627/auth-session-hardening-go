package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

// User 是内存用户记录。
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         Role
}

// Server 组合会话、限流、CSRF 与鉴权，提供 HTTP 处理器。
type Server struct {
	sessions *Store
	limiter  *Limiter
	csrf     *CSRF
	users    map[string]User // key: username
	mu       sync.RWMutex
	mux      *http.ServeMux
}

const sessionCookie = "session_id"

type ctxKey int

const ctxSession ctxKey = iota

// NewServer 装配各组件并注册路由。
func NewServer(sessionTTL time.Duration, csrfSecret []byte, limiter *Limiter) *Server {
	s := &Server{
		sessions: NewStore(sessionTTL),
		limiter:  limiter,
		csrf:     NewCSRF(csrfSecret),
		users:    make(map[string]User),
		mux:      http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("POST /logout", s.withSession(s.handleLogout))
	s.mux.HandleFunc("GET /profile", s.withSession(s.handleProfile))
	s.mux.HandleFunc("POST /sensitive", s.withSession(s.withCSRF(s.handleSensitive)))
	s.mux.HandleFunc("GET /documents", s.withSession(s.requirePerm("document", "read", s.handleDocuments)))
	s.mux.HandleFunc("POST /documents", s.withSession(s.withCSRF(s.requirePerm("document", "write", s.handleDocuments))))
	s.mux.HandleFunc("DELETE /documents", s.withSession(s.withCSRF(s.requirePerm("document", "delete", s.handleDocuments))))
	s.mux.HandleFunc("GET /admin", s.withSession(s.requirePerm("admin-panel", "read", s.handleAdmin)))
	return s
}

// AddUser 注册用户（口令明文传入，内部哈希存储）。
func (s *Server) AddUser(username, password string, role Role) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = User{
		ID:           "u-" + username,
		Username:     username,
		PasswordHash: hash,
		Role:         role,
	}
	return nil
}

func (s *Server) Handler() http.Handler { return s.mux }

// Sessions 暴露会话存储，供测试与运维诊断。
func (s *Server) Sessions() *Store { return s.sessions }

// ---- 中间件 ----

// withSession 校验会话并滑动续期；失败按内部原因拒绝。
func (s *Server) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required", ReasonSessionUnknown)
			return
		}
		sess, err := s.sessions.Touch(c.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required", ReasonOf(err))
			return
		}
		next(w, contextWithSession(r, sess))
	}
}

// withCSRF 校验变更类请求的 CSRF 令牌；失败以 403 拒绝并给出可区分原因。
func (s *Server) withCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFromContext(r)
		if err := s.csrf.Verify(sess.ID, r.Header.Get("X-CSRF-Token")); err != nil {
			writeError(w, http.StatusForbidden, "csrf validation failed", ReasonOf(err))
			return
		}
		next(w, r)
	}
}

// requirePerm 基于角色与资源做访问控制；越权一律 403。
func (s *Server) requirePerm(resource, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFromContext(r)
		if !Can(sess.Role, resource, action) {
			writeError(w, http.StatusForbidden, "permission denied", ReasonForbidden)
			return
		}
		next(w, r)
	}
}

// ---- 处理器 ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}
	source := clientIP(r)

	// 限流按 (来源, 账号) 维度，无论账号是否存在都同样计数，
	// 因此限流响应不会泄露账号是否存在。
	if !s.limiter.Allow(source, req.Username) {
		writeError(w, http.StatusTooManyRequests, "too many attempts, try again later", ReasonRateLimited)
		return
	}

	s.mu.RLock()
	user, ok := s.users[req.Username]
	s.mu.RUnlock()
	// 账号不存在时也执行一次口令校验，抹平时间侧信道；
	// 对外统一返回 invalid credentials，不区分账号不存在与口令错误。
	if !ok || !VerifyPassword(req.Password, user.PasswordHash) {
		s.limiter.RecordFailure(source, req.Username)
		writeError(w, http.StatusUnauthorized, "invalid credentials", ReasonBadCredentials)
		return
	}
	s.limiter.RecordSuccess(source, req.Username)

	// 会话固定防护：登录成功即作废旧会话、签发全新会话 ID。
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.sessions.Revoke(c.Value)
	}
	sess, err := s.sessions.Create(user.ID, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error", "")
		return
	}
	token, err := s.csrf.Issue(sess.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error", "")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   user.Username,
		"role":       user.Role,
		"csrf_token": token,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.sessions.Revoke(sess.ID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"status": "logged out"})
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    sess.UserID,
		"role":       sess.Role,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleSensitive(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	writeJSON(w, http.StatusOK, map[string]any{"status": "sensitive op done", "user_id": sess.UserID})
}

func (s *Server) handleDocuments(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "method": r.Method, "role": sess.Role})
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "resource": "admin-panel"})
}

// ---- 工具 ----

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func contextWithSession(r *http.Request, sess *Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxSession, sess))
}

func sessionFromContext(r *http.Request) *Session {
	sess, _ := r.Context().Value(ctxSession).(*Session)
	return sess
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 对外返回通用文案与可区分原因码；
// 文案本身不泄露账号是否存在等敏感信息。
func writeError(w http.ResponseWriter, code int, msg string, reason Reason) {
	body := map[string]any{"error": msg}
	if reason != "" {
		body["reason"] = reason
	}
	writeJSON(w, code, body)
}
