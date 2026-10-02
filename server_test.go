package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	limiter := NewLimiter(3, time.Minute, 50*time.Millisecond)
	srv := NewServer(time.Minute, []byte("test-secret"), limiter)
	if err := srv.AddUser("admin", "admin-pass", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddUser("alice", "alice-pass", RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddUser("bob", "bob-pass", RoleGuest); err != nil {
		t.Fatal(err)
	}
	return srv
}

type authClient struct {
	t         *testing.T
	handler   http.Handler
	sessionID string
	csrfToken string
	device    string
	ua        string
}

func (c *authClient) login(username, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	return c.loginBody(body)
}

// loginBody 发送自定义 JSON 登录体（可携带 remember_me / device_label）。
func (c *authClient) loginBody(body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	if c.sessionID != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.sessionID})
	}
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == sessionCookie {
				c.sessionID = ck.Value
			}
		}
		var resp struct {
			CSRFToken string `json:"csrf_token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		c.csrfToken = resp.CSRFToken
	}
	return rec
}

func (c *authClient) do(method, path string, withCSRF bool) *httptest.ResponseRecorder {
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

// 业务：登录 + 会话访问
func TestServerLoginAndProfile(t *testing.T) {
	srv := newTestServer(t)
	c := &authClient{t: t, handler: srv.Handler()}

	rec := c.login("alice", "alice-pass")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d body %s", rec.Code, rec.Body)
	}
	if c.sessionID == "" || c.csrfToken == "" {
		t.Fatal("login must return session cookie and csrf token")
	}
	t.Log("用例通过: 登录成功，签发会话 Cookie 与 CSRF 令牌")

	rec = c.do("GET", "/profile", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile: got %d", rec.Code)
	}
	t.Log("用例通过: 携带会话访问 /profile 成功（同时完成滑动续期）")
}

// 业务：登录失败不泄露账号是否存在
func TestServerLoginNoAccountEnumeration(t *testing.T) {
	srv := newTestServer(t)
	c := &authClient{t: t, handler: srv.Handler()}

	rec1 := c.login("alice", "wrong-pass")
	rec2 := c.login("no-such-user", "wrong-pass")
	if rec1.Code != http.StatusUnauthorized || rec2.Code != http.StatusUnauthorized {
		t.Fatalf("both must be 401, got %d / %d", rec1.Code, rec2.Code)
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Fatalf("response bodies must be identical to avoid account enumeration:\n%s\n%s",
			rec1.Body, rec2.Body)
	}
	t.Log("用例通过: 口令错误与账号不存在返回完全一致的 401 响应，不泄露账号信息")
}

// 业务：登录限流 —— 触发后稳定拒绝，恢复后放行
func TestServerLoginRateLimit(t *testing.T) {
	srv := newTestServer(t)
	c := &authClient{t: t, handler: srv.Handler()}

	for i := 0; i < 3; i++ {
		if rec := c.login("alice", "wrong-pass"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: want 401, got %d", i+1, rec.Code)
		}
	}
	rec := c.login("alice", "alice-pass") // 即使口令正确也被限流
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d body %s", rec.Code, rec.Body)
	}
	t.Log("用例通过: 达到失败阈值后返回 429，稳定拒绝")

	time.Sleep(60 * time.Millisecond) // 等待锁定期满
	if rec := c.login("alice", "alice-pass"); rec.Code != http.StatusOK {
		t.Fatalf("after lockout: want 200, got %d", rec.Code)
	}
	t.Log("用例通过: 锁定期满后正常口令可登录")
}

// 业务：CSRF 防护 —— 敏感操作缺令牌拒绝，原因可区分
func TestServerCSRFRequired(t *testing.T) {
	srv := newTestServer(t)
	c := &authClient{t: t, handler: srv.Handler()}
	c.login("alice", "alice-pass")

	rec := c.do("POST", "/sensitive", false)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), string(ReasonCSRFInvalid)) {
		t.Fatalf("want 403 csrf_invalid, got %d body %s", rec.Code, rec.Body)
	}
	t.Log("用例通过: 缺少 CSRF 令牌的敏感操作被拒，原因 csrf_invalid")

	rec = c.do("POST", "/sensitive", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("with valid token: want 200, got %d", rec.Code)
	}
	t.Log("用例通过: 携带合法 CSRF 令牌的敏感操作放行")
}

// 业务：会话固定防护 —— 登录轮换会话 ID，旧会话立即失效
func TestServerSessionFixation(t *testing.T) {
	srv := newTestServer(t)
	attacker := &authClient{t: t, handler: srv.Handler()}
	attacker.login("bob", "bob-pass")
	oldID := attacker.sessionID

	// 受害者带着攻击者预置的会话登录：登录后必须换成新会话。
	victim := &authClient{t: t, handler: srv.Handler(), sessionID: oldID}
	victim.login("alice", "alice-pass")
	if victim.sessionID == oldID {
		t.Fatal("session id must rotate on login")
	}
	if _, err := srv.Sessions().Touch(oldID); ReasonOf(err) != ReasonSessionRevoked {
		t.Fatalf("old session must be revoked, got %v", err)
	}
	t.Log("用例通过: 登录后会话 ID 轮换，预置旧会话被撤销")
}

// 业务：RBAC 越权访问 —— 一律 403
func TestServerRBAC(t *testing.T) {
	srv := newTestServer(t)

	guest := &authClient{t: t, handler: srv.Handler()}
	guest.login("bob", "bob-pass")
	if rec := guest.do("POST", "/documents", true); rec.Code != http.StatusForbidden {
		t.Fatalf("guest write: want 403, got %d", rec.Code)
	}
	if rec := guest.do("GET", "/documents", false); rec.Code != http.StatusOK {
		t.Fatalf("guest read: want 200, got %d", rec.Code)
	}
	t.Log("用例通过: guest 可读文档、写文档被拒")

	member := &authClient{t: t, handler: srv.Handler()}
	member.login("alice", "alice-pass")
	if rec := member.do("GET", "/admin", false); rec.Code != http.StatusForbidden {
		t.Fatalf("member admin access: want 403, got %d", rec.Code)
	}
	if rec := member.do("DELETE", "/documents", true); rec.Code != http.StatusForbidden {
		t.Fatalf("member delete: want 403, got %d", rec.Code)
	}
	t.Log("用例通过: member 访问管理面板与删除文档均被拒")

	admin := &authClient{t: t, handler: srv.Handler()}
	admin.login("admin", "admin-pass")
	if rec := admin.do("GET", "/admin", false); rec.Code != http.StatusOK {
		t.Fatalf("admin access: want 200, got %d", rec.Code)
	}
	if rec := admin.do("DELETE", "/documents", true); rec.Code != http.StatusOK {
		t.Fatalf("admin delete: want 200, got %d", rec.Code)
	}
	t.Log("用例通过: admin 可访问管理面板并删除文档")
}

// 业务：会话并发续期（HTTP 层）—— 全部成功、无互挤
func TestServerConcurrentRenewal(t *testing.T) {
	srv := newTestServer(t)
	c := &authClient{t: t, handler: srv.Handler()}
	c.login("alice", "alice-pass")

	const workers = 64
	var wg sync.WaitGroup
	codes := make(chan int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- c.do("GET", "/profile", false).Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("concurrent renewal: want 200, got %d", code)
		}
	}
	t.Logf("用例通过: %d 个并发请求共用同一会话全部续期成功", workers)
}

// 业务：登出撤销 —— 会话立即失效
func TestServerLogoutRevokes(t *testing.T) {
	srv := newTestServer(t)
	c := &authClient{t: t, handler: srv.Handler()}
	c.login("alice", "alice-pass")

	if rec := c.do("POST", "/logout", false); rec.Code != http.StatusOK {
		t.Fatalf("logout: got %d", rec.Code)
	}
	rec := c.do("GET", "/profile", false)
	if rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionRevoked)) {
		t.Fatalf("after logout: want 401 session_revoked, got %d body %s", rec.Code, rec.Body)
	}
	t.Log("用例通过: 登出后旧会话立即失效，原因 session_revoked")
}
