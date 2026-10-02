package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
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

// serverConfig 为不改变 NewServer 基本签名而引入的可选配置，
// 全部通过 ServerOption 提供；零值时使用合理默认。
type serverConfig struct {
	maxLifetime        time.Duration
	persistentIdleTTL  time.Duration
	maxSessionsPerUser int
}

// ServerOption 以可选项方式扩展 NewServer，老调用方无需任何改动。
type ServerOption func(*serverConfig)

// WithMaxLifetime 设置会话最长存活时长：从建立起算，无论多活跃到期一律失效。
func WithMaxLifetime(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.maxLifetime = d }
}

// WithPersistentIdleTTL 设置“保持长时间登录”会话的空闲时长。
func WithPersistentIdleTTL(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.persistentIdleTTL = d }
}

// WithMaxSessionsPerUser 设置同一账号的活跃会话数量上限（<=0 表示不限制）。
func WithMaxSessionsPerUser(n int) ServerOption {
	return func(c *serverConfig) { c.maxSessionsPerUser = n }
}

// NewServer 装配各组件并注册路由。
// sessionTTL 为普通会话的空闲到期时长；新生命周期规则通过可变参数配置，
// 缺省提供合理默认：最长存活 24 小时、保持登录空闲 7 天、不限制会话数量。
func NewServer(sessionTTL time.Duration, csrfSecret []byte, limiter *Limiter, opts ...ServerOption) *Server {
	cfg := serverConfig{
		maxLifetime:       24 * time.Hour,
		persistentIdleTTL: 7 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	storeCfg := StoreConfig{
		IdleTTL:            sessionTTL,
		PersistentIdleTTL:  cfg.persistentIdleTTL,
		MaxLifetime:        cfg.maxLifetime,
		MaxSessionsPerUser: cfg.maxSessionsPerUser,
	}
	s := &Server{
		sessions: NewStoreWithConfig(storeCfg),
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
	// 多设备会话管理：查看当前账号的活跃会话、单独结束、一次全部结束。
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
		// Persistent 为可选的“保持长时间登录”；老客户端不带该字段时按普通会话处理。
		Persistent bool `json:"remember_me"`
		// DeviceLabel 为客户端自报的设备/客户端名；缺省时由 User-Agent 推导。
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
	sess, err := s.sessions.CreateSession(CreateMeta{
		UserID:     user.ID,
		Role:       user.Role,
		Persistent: req.Persistent,
		Device:     buildClientInfo(req.DeviceLabel, r, source),
	})
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

// handleListSessions 返回当前账号在所有设备上的活跃会话。
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	list := s.sessions.List(sess.UserID, sess.ID)
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

// handleRevokeSession 结束当前账号在某一台设备上的单条会话。
// 只能结束自己账号下的会话；找不到或不属于本账号时统一 404，
// 不泄露该会话是否存在、属于谁。
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	targetID := r.PathValue("id")
	if target, ok := s.sessions.Get(targetID); !ok || target.UserID != sess.UserID {
		writeError(w, http.StatusNotFound, "session not found", ReasonSessionUnknown)
		return
	}
	s.sessions.Revoke(targetID)
	// 结束的是当前会话时，同步清除浏览器 Cookie。
	if targetID == sess.ID {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "session revoked", "id": targetID})
}

// handleRevokeAllSessions 一次结束当前账号在所有设备上的会话（含当前会话）。
func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	n := s.sessions.RevokeUser(sess.UserID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"status": "all sessions revoked", "revoked": n})
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	resp := map[string]any{
		"user_id":             sess.UserID,
		"role":                sess.Role,
		"persistent":          sess.Persistent,
		"expires_at":          sess.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"absolute_expires_at": nil,
	}
	if !sess.AbsoluteExpiresAt.IsZero() {
		resp["absolute_expires_at"] = sess.AbsoluteExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, resp)
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

// buildClientInfo 从客户端自报名称、User-Agent 与来源 IP 推导设备信息。
// 老客户端不带 device_label、甚至不带 User-Agent 时也给出合理默认，保持可用。
func buildClientInfo(label string, r *http.Request, ip string) ClientInfo {
	ua := r.Header.Get("User-Agent")
	if label == "" {
		label = deviceLabelFromUA(ua)
	}
	return ClientInfo{Label: label, UserAgent: ua, IP: ip}
}

// deviceLabelFromUA 粗略地从 User-Agent 提取 “浏览器 @ 操作系统” 形式的标签。
func deviceLabelFromUA(ua string) string {
	if ua == "" {
		return "未知设备"
	}
	browser := "未知浏览器"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"), strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	osName := "未知系统"
	switch {
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iOS"):
		osName = "iOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		osName = "Linux"
	}
	return browser + " @ " + osName
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
