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

// ServerConfig 配置会话生命周期与多设备策略。
type ServerConfig struct {
	// IdleTTL 普通会话滑动空闲时长。
	IdleTTL time.Duration
	// PersistentIdleTTL “保持长时间登录”会话的空闲时长（<=0 回退 IdleTTL）。
	PersistentIdleTTL time.Duration
	// AbsoluteTTL 所有会话统一的最长存活时长（<=0 表示不限制）。
	AbsoluteTTL time.Duration
	// MaxSessionsPerUser 每账号活跃会话上限（<=0 表示不限制）。
	MaxSessionsPerUser int
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

// NewServer 装配各组件并注册路由（旧签名，保持旧语义：
// 仅滑动空闲续期，不启用最长存活上限、长登录放宽与每账号会话上限）。
func NewServer(sessionTTL time.Duration, csrfSecret []byte, limiter *Limiter) *Server {
	return newServerRaw(ServerConfig{IdleTTL: sessionTTL}, csrfSecret, limiter)
}

// NewServerWithConfig 按完整配置装配各组件并注册路由；
// 未设置的时长字段归一化为合理默认，保证零值配置也可直接使用。
func NewServerWithConfig(cfg ServerConfig, csrfSecret []byte, limiter *Limiter) *Server {
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 30 * time.Minute
	}
	if cfg.PersistentIdleTTL <= 0 {
		cfg.PersistentIdleTTL = 7 * 24 * time.Hour
	}
	if cfg.AbsoluteTTL <= 0 {
		cfg.AbsoluteTTL = 12 * time.Hour
	}
	return newServerRaw(cfg, csrfSecret, limiter)
}

// newServerRaw 按给定配置原样装配；零值时长按 Store 的“不限制”语义处理。
func newServerRaw(cfg ServerConfig, csrfSecret []byte, limiter *Limiter) *Server {
	s := &Server{
		sessions: NewStoreWithConfig(StoreConfig{
			IdleTTL:            cfg.IdleTTL,
			PersistentIdleTTL:  cfg.PersistentIdleTTL,
			AbsoluteTTL:        cfg.AbsoluteTTL,
			MaxSessionsPerUser: cfg.MaxSessionsPerUser,
		}),
		limiter: limiter,
		csrf:    NewCSRF(csrfSecret),
		users:   make(map[string]User),
		mux:     http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("POST /logout", s.withSession(s.handleLogout))
	s.mux.HandleFunc("GET /profile", s.withSession(s.handleProfile))
	s.mux.HandleFunc("POST /sensitive", s.withSession(s.withCSRF(s.handleSensitive)))
	s.mux.HandleFunc("GET /documents", s.withSession(s.requirePerm("document", "read", s.handleDocuments)))
	s.mux.HandleFunc("POST /documents", s.withSession(s.withCSRF(s.requirePerm("document", "write", s.handleDocuments))))
	s.mux.HandleFunc("DELETE /documents", s.withSession(s.withCSRF(s.requirePerm("document", "delete", s.handleDocuments))))
	s.mux.HandleFunc("GET /admin", s.withSession(s.requirePerm("admin-panel", "read", s.handleAdmin)))
	// 多设备会话管理。
	s.mux.HandleFunc("GET /sessions", s.withSession(s.handleListSessions))
	s.mux.HandleFunc("DELETE /sessions/{id}", s.withSession(s.withCSRF(s.handleRevokeSession)))
	s.mux.HandleFunc("POST /sessions/revoke-all", s.withSession(s.withCSRF(s.handleRevokeAllSessions)))
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
		// Persistent 为可选的“保持长时间登录”：缺省（老客户端不带）按普通会话处理。
		Persistent bool `json:"persistent"`
		// DeviceLabel 为客户端可自报的设备名，仅用于多设备会话展示，可缺省。
		DeviceLabel string `json:"device_label"`
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
	// 设备信息：IP/User-Agent 由服务端采集，标签由客户端自报；
	// 老客户端不带任何新字段时 ClientInfo 为零值，会话照常建立。
	client := ClientInfo{
		UserAgent: r.UserAgent(),
		IP:        source,
		Label:     req.DeviceLabel,
	}
	sess, err := s.sessions.CreateWithClient(user.ID, user.Role, client, req.Persistent)
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
		"username":            user.Username,
		"role":                user.Role,
		"csrf_token":          token,
		"persistent":          sess.Persistent,
		"absolute_expires_at": rfc3339(sess.AbsoluteExpiresAt),
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
		"user_id":             sess.UserID,
		"role":                sess.Role,
		"persistent":          sess.Persistent,
		"expires_at":          rfc3339(sess.ExpiresAt),
		"absolute_expires_at": rfc3339(sess.AbsoluteExpiresAt),
		"last_active_at":      rfc3339(sess.LastActiveAt),
	})
}

// sessionView 是多设备会话列表对外暴露的单条视图。
type sessionView struct {
	ID           string `json:"id"`
	DeviceLabel  string `json:"device_label"`
	UserAgent    string `json:"user_agent"`
	IP           string `json:"ip"`
	LoginAt      string `json:"login_at"`
	LastActiveAt string `json:"last_active_at"`
	ExpiresAt    string `json:"expires_at"`
	Current      bool   `json:"current"`
}

// handleListSessions 列出当前账号全部活跃会话（多设备）。
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	cur := sessionFromContext(r)
	active := s.sessions.ListActive(cur.UserID)
	views := make([]sessionView, 0, len(active))
	for _, sess := range active {
		views = append(views, sessionView{
			ID:           sess.ID,
			DeviceLabel:  sess.Client.Label,
			UserAgent:    sess.Client.UserAgent,
			IP:           sess.Client.IP,
			LoginAt:      rfc3339(sess.CreatedAt),
			LastActiveAt: rfc3339(sess.LastActiveAt),
			ExpiresAt:    rfc3339(sess.ExpiresAt),
			Current:      sess.ID == cur.ID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// handleRevokeSession 结束指定的单条会话；仅允许结束本账号会话。
// 目标不存在、属于他人或已失效时返回统一 404，不泄露会话归属。
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	cur := sessionFromContext(r)
	targetID := r.PathValue("id")
	target, ok := s.sessions.Get(targetID)
	if !ok || target.UserID != cur.UserID {
		writeError(w, http.StatusNotFound, "session not found", ReasonSessionUnknown)
		return
	}
	if !target.Revoked && !target.Evicted {
		s.sessions.Revoke(targetID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "session ended"})
}

// handleRevokeAllSessions 一次结束当前账号在所有设备上的会话，
// 包括发起请求的当前会话；其它账号不受影响。
func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	cur := sessionFromContext(r)
	n := s.sessions.RevokeUser(cur.UserID, "")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"status": "all sessions ended", "ended": n})
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

// rfc3339 统一时间输出；零值时间输出空串（表示该到期线未启用）。
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
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
