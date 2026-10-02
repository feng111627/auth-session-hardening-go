package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newCapTestServer(t *testing.T, maxPerUser int) *Server {
	t.Helper()
	limiter := NewLimiter(100, time.Minute, time.Millisecond)
	var opts []ServerOption
	if maxPerUser > 0 {
		opts = append(opts, WithMaxSessionsPerUser(maxPerUser))
	}
	srv := NewServer(time.Hour, []byte("test-secret"), limiter, opts...)
	if err := srv.AddUser("alice", "alice-pass", RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddUser("bob", "bob-pass", RoleGuest); err != nil {
		t.Fatal(err)
	}
	return srv
}

func (c *authClient) rawDo(method, path string, withCSRF bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if c.sessionID != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.sessionID})
	}
	if withCSRF {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	return rec
}

func decodeSessions(t *testing.T, rec *httptest.ResponseRecorder) []SessionInfo {
	t.Helper()
	var resp struct {
		Sessions []SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode sessions: %v body=%s", err, rec.Body)
	}
	return resp.Sessions
}

// 业务（HTTP）：多设备登录后可查看各活跃会话的设备与时间
func TestHTTPListSessionsAcrossDevices(t *testing.T) {
	srv := newCapTestServer(t, 0)
	phone := &authClient{t: t, handler: srv.Handler(), ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile/15E148 Safari/604.1"}
	laptop := &authClient{t: t, handler: srv.Handler(), ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}
	phone.login("alice", "alice-pass")
	laptop.login("alice", "alice-pass")

	rec := laptop.rawDo("GET", "/sessions", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("list sessions: got %d body %s", rec.Code, rec.Body)
	}
	list := decodeSessions(t, rec)
	if len(list) != 2 {
		t.Fatalf("应有 2 条活跃会话, got %d", len(list))
	}
	labels := map[string]string{}
	currents := 0
	for _, s := range list {
		labels[s.ID] = s.Device.Label
		if s.Current {
			currents++
		}
		if s.CreatedAt.IsZero() || s.LastActivityAt.IsZero() {
			t.Fatal("每条会话都应包含登录时间与最近活动时间")
		}
	}
	if currents != 1 {
		t.Fatalf("current 会话必须恰好 1 条, got %d", currents)
	}
	if labels[laptop.sessionID] != "Chrome @ Linux" {
		t.Fatalf("笔记本设备标签推导错误: %q", labels[laptop.sessionID])
	}
	if labels[phone.sessionID] != "Safari @ iOS" {
		t.Fatalf("手机设备标签推导错误: %q", labels[phone.sessionID])
	}
	t.Log("用例通过: GET /sessions 返回两条设备会话（Safari @ iOS / Chrome @ Linux），各带登录与最近活动时间，current 唯一")
}

// 业务（HTTP）：老客户端不带任何新字段时按默认继续可用
func TestHTTPOldClientDefaultDeviceAndTTL(t *testing.T) {
	srv := newCapTestServer(t, 0)
	c := &authClient{t: t, handler: srv.Handler()}
	c.login("alice", "alice-pass") // 不带 remember_me、不带 User-Agent

	rec := c.rawDo("GET", "/sessions", false)
	list := decodeSessions(t, rec)
	if len(list) != 1 {
		t.Fatalf("应有 1 条会话, got %d", len(list))
	}
	if list[0].Device.Label != "未知设备" {
		t.Fatalf("缺省设备标签应为 未知设备, got %q", list[0].Device.Label)
	}
	if rec := c.rawDo("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("老客户端应可继续访问, got %d", rec.Code)
	}
	t.Log("用例通过: 老客户端不带 remember_me / User-Agent 也能登录使用，设备标签回退为“未知设备”")
}

// 业务（HTTP）：单独结束一台设备的会话，立即失效，其它设备继续使用
func TestHTTPRevokeSingleSession(t *testing.T) {
	srv := newCapTestServer(t, 0)
	phone := &authClient{t: t, handler: srv.Handler()}
	laptop := &authClient{t: t, handler: srv.Handler()}
	phone.login("alice", "alice-pass")
	laptop.login("alice", "alice-pass")

	// 笔记本结束手机上的会话（需要 CSRF 令牌）。
	rec := laptop.rawDo("DELETE", "/sessions/"+phone.sessionID, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke single: got %d body %s", rec.Code, rec.Body)
	}
	if rec := phone.rawDo("GET", "/profile", false); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionRevoked)) {
		t.Fatalf("被结束的手机会话应 401 session_revoked, got %d body %s", rec.Code, rec.Body)
	}
	if rec := laptop.rawDo("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("笔记本会话不应受影响, got %d", rec.Code)
	}
	t.Log("用例通过: DELETE /sessions/{id} 立即结束手机会话，笔记本继续使用")

	// 不能结束不属于自己账号的会话：统一 404，不泄露会话归属。
	bob := &authClient{t: t, handler: srv.Handler()}
	bob.login("bob", "bob-pass")
	rec = bob.rawDo("DELETE", "/sessions/"+laptop.sessionID, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("结束他人会话应 404, got %d", rec.Code)
	}
	if rec := laptop.rawDo("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("他人尝试结束不应影响会话, got %d", rec.Code)
	}
	t.Log("用例通过: 结束其它账号的会话返回 404 且不泄露归属，目标会话不受影响")

	// 结束操作同样受 CSRF 防护。
	rec = laptop.rawDo("DELETE", "/sessions/"+laptop.sessionID, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("结束会话缺 CSRF 应 403, got %d", rec.Code)
	}
	t.Log("用例通过: 结束会话接口受 CSRF 保护，缺令牌 403")
}

// 业务（HTTP）：一次结束所有设备会话，当前与其它设备全部立即失效
func TestHTTPRevokeAllSessions(t *testing.T) {
	srv := newCapTestServer(t, 0)
	devs := []*authClient{
		{t: t, handler: srv.Handler()},
		{t: t, handler: srv.Handler()},
		{t: t, handler: srv.Handler()},
	}
	for _, d := range devs {
		d.login("alice", "alice-pass")
	}
	bob := &authClient{t: t, handler: srv.Handler()}
	bob.login("bob", "bob-pass")

	rec := devs[0].rawDo("POST", "/sessions/revoke-all", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke-all: got %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Revoked int `json:"revoked"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Revoked != 3 {
		t.Fatalf("应报告结束 3 条, got %d", resp.Revoked)
	}
	for i, d := range devs {
		if rec := d.rawDo("GET", "/profile", false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("设备 %d 应已失效, got %d", i, rec.Code)
		}
	}
	if rec := bob.rawDo("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("其它账号不应受影响, got %d", rec.Code)
	}
	t.Log("用例通过: POST /sessions/revoke-all 结束本账号全部 3 条会话且立即失效，bob 的会话不受影响")
}

// 业务（HTTP）：会话上限在登录接口生效，最久未活动设备被挤下线
func TestHTTPSessionCapOnLogin(t *testing.T) {
	srv := newCapTestServer(t, 2)
	d1 := &authClient{t: t, handler: srv.Handler()}
	d2 := &authClient{t: t, handler: srv.Handler()}
	d1.login("alice", "alice-pass")
	time.Sleep(2 * time.Millisecond) // 确保 d1 的最近活动时间早于 d2
	d2.login("alice", "alice-pass")
	time.Sleep(2 * time.Millisecond)
	d3 := &authClient{t: t, handler: srv.Handler()}
	d3.login("alice", "alice-pass") // 上限 2，d1 应让位

	if rec := d1.rawDo("GET", "/profile", false); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionEvicted)) {
		t.Fatalf("被挤下线的 d1 应 401 session_evicted, got %d body %s", rec.Code, rec.Body)
	}
	for i, d := range []*authClient{d2, d3} {
		if rec := d.rawDo("GET", "/profile", false); rec.Code != http.StatusOK {
			t.Fatalf("d%d 应继续可用, got %d", i+2, rec.Code)
		}
	}
	list := decodeSessions(t, d3.rawDo("GET", "/sessions", false))
	if len(list) != 2 {
		t.Fatalf("活跃会话应保持上限 2, got %d", len(list))
	}
	t.Log("用例通过: 上限 2 时第 3 台设备登录，最久未活动的 d1 被挤下线(session_evicted)，d2/d3 正常")
}

// 业务（HTTP）：remember_me 登录后会话被标记为保持登录，且携带自报设备名
func TestHTTPRememberMe(t *testing.T) {
	limiter := NewLimiter(100, time.Minute, time.Millisecond)
	srv := NewServer(time.Hour, []byte("test-secret"), limiter,
		WithPersistentIdleTTL(8*time.Hour), WithMaxLifetime(24*time.Hour))
	if err := srv.AddUser("alice", "alice-pass", RoleMember); err != nil {
		t.Fatal(err)
	}
	c := &authClient{t: t, handler: srv.Handler()}
	rec := c.loginBody(`{"username":"alice","password":"alice-pass","remember_me":true,"device_label":"我的手机"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("remember_me login: got %d body %s", rec.Code, rec.Body)
	}
	sess, ok := srv.Sessions().Get(c.sessionID)
	if !ok {
		t.Fatal("会话应存在")
	}
	if !sess.Persistent {
		t.Fatal("remember_me=true 的会话应标记 Persistent")
	}
	if sess.Device.Label != "我的手机" {
		t.Fatalf("自报设备名应透传, got %q", sess.Device.Label)
	}
	if !sess.AbsoluteExpiresAt.Equal(sess.CreatedAt.Add(24 * time.Hour)) {
		t.Fatalf("最长存活时间应为建立 +24h, created=%v abs=%v", sess.CreatedAt, sess.AbsoluteExpiresAt)
	}
	if !sess.ExpiresAt.Equal(sess.CreatedAt.Add(8 * time.Hour)) {
		t.Fatalf("空闲到期应放宽到 8h, got %v", sess.ExpiresAt)
	}
	rec = c.rawDo("GET", "/profile", false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"persistent":true`) {
		t.Fatalf("profile 应反映 persistent=true, got %d body %s", rec.Code, rec.Body)
	}
	t.Log("用例通过: remember_me 会话标记 Persistent、空闲时长放宽到 8h、最长存活仍固定 24h、设备名透传")
}
