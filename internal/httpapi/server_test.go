package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/feng111627/auth-session-hardening-go/internal/auth"
	"github.com/feng111627/auth-session-hardening-go/internal/csrf"
	"github.com/feng111627/auth-session-hardening-go/internal/ratelimit"
	"github.com/feng111627/auth-session-hardening-go/internal/rbac"
	"github.com/feng111627/auth-session-hardening-go/internal/session"
)

type env struct {
	ts       *httptest.Server
	sessions *session.Manager
	limiter  *ratelimit.Limiter
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := auth.NewMemoryDirectory()
	dir.Add("u1", "alice", "alice-pass", []string{rbac.RoleMember})
	dir.Add("u2", "root", "root-pass", []string{rbac.RoleAdmin})

	sessions := session.NewManager(15*time.Minute, 8*time.Hour)
	limiter := ratelimit.NewLimiter(3, 10*time.Minute, 15*time.Minute)
	protector := csrf.NewProtector()
	authz := rbac.NewAuthorizer()
	authz.Grant(rbac.RoleMember, rbac.ResourceProfile, rbac.ActionRead, rbac.ActionWrite)
	authz.Grant(rbac.RoleMember, rbac.ResourceOrders, rbac.ActionRead)
	authz.Grant(rbac.RoleAdmin, rbac.ResourceAdmin, rbac.ActionAdmin)

	svc := auth.NewService(dir, sessions, limiter, protector, authz)
	srv := New(svc, sessions, protector, authz, false)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{ts: ts, sessions: sessions, limiter: limiter}
}

// browser 是带 CookieJar 的测试客户端，并记住最近一次 CSRF 令牌。
type browser struct {
	c    *http.Client
	csrf string
}

func newBrowser(e *env) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{c: &http.Client{Jar: jar}}
}

func (b *browser) do(t *testing.T, e *env, method, path string, body any, withCSRF bool) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF && b.csrf != "" {
		req.Header.Set(csrfHeader, b.csrf)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	// 登录响应中包含 csrf_token 时记住它。
	if v, ok := out["csrf_token"].(string); ok && v != "" {
		b.csrf = v
	}
	return resp.StatusCode, out
}

func (b *browser) fetchCSRF(t *testing.T, e *env) {
	t.Helper()
	status, out := b.do(t, e, http.MethodGet, "/api/csrf", nil, false)
	if status != http.StatusOK {
		t.Fatalf("获取 CSRF 令牌失败: %d %v", status, out)
	}
	b.csrf, _ = out["csrf_token"].(string)
	if b.csrf == "" {
		t.Fatal("未拿到 csrf_token")
	}
}

func TestHTTPEndToEndLoginAndAccess(t *testing.T) {
	t.Log("业务=端到端登录与访问 预登录CSRF->登录->只读/敏感写->登出失效")
	e := newEnv(t)
	b := newBrowser(e)

	// 未登录访问受保护资源
	status, body := b.do(t, e, http.MethodGet, "/api/profile", nil, false)
	if status != http.StatusUnauthorized || body["code"] != "unauthorized" {
		t.Fatalf("用例[未登录拒绝] FAIL: %d %v", status, body)
	}
	t.Logf("用例[未登录访问 401 unauthorized] PASS")

	// 不带 CSRF 登录必须被拒
	status, body = b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, false)
	if status != http.StatusForbidden || body["code"] != "csrf_invalid" {
		t.Fatalf("用例[登录缺CSRF拒绝] FAIL: %d %v", status, body)
	}
	t.Logf("用例[POST /api/login 缺 CSRF -> 403 csrf_invalid] PASS")

	// 正常流程
	b.fetchCSRF(t, e)
	status, body = b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, true)
	if status != http.StatusOK {
		t.Fatalf("用例[正常登录200] FAIL: %d %v", status, body)
	}
	t.Logf("用例[携带CSRF登录成功 user=%v roles=%v] PASS", body["username"], body["roles"])

	// 只读放行
	status, body = b.do(t, e, http.MethodGet, "/api/profile", nil, false)
	if status != http.StatusOK {
		t.Fatalf("用例[读profile放行] FAIL: %d %v", status, body)
	}
	t.Log("用例[GET /api/profile 200] PASS")

	// 敏感写：无 CSRF 拒绝
	status, body = b.do(t, e, http.MethodPost, "/api/profile", map[string]string{}, false)
	if status != http.StatusForbidden || body["code"] != "csrf_invalid" {
		t.Fatalf("用例[敏感写缺CSRF拒绝] FAIL: %d %v", status, body)
	}
	t.Log("用例[POST /api/profile 缺 CSRF -> 403] PASS")

	// 敏感写：带 CSRF 放行
	status, _ = b.do(t, e, http.MethodPost, "/api/profile", map[string]string{}, true)
	if status != http.StatusOK {
		t.Fatalf("用例[敏感写带CSRF放行] FAIL: %d", status)
	}
	t.Log("用例[POST /api/profile 带 CSRF -> 200] PASS")

	// 登出后旧会话立即失效
	status, _ = b.do(t, e, http.MethodPost, "/api/logout", nil, true)
	if status != http.StatusOK {
		t.Fatalf("登出失败: %d", status)
	}
	status, body = b.do(t, e, http.MethodGet, "/api/profile", nil, false)
	if status != http.StatusUnauthorized {
		t.Fatalf("用例[登出后旧Cookie立即失效] FAIL: %d %v", status, body)
	}
	t.Log("用例[登出后旧会话 Cookie -> 401] PASS")
}

func TestHTTPForbiddenAndEnumeration(t *testing.T) {
	t.Log("业务=端到端越权与账号枚举 member不得访问admin资源；登录失败统一文案")
	e := newEnv(t)

	// 越权
	b := newBrowser(e)
	b.fetchCSRF(t, e)
	status, _ := b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, true)
	if status != 200 {
		t.Fatal("登录失败")
	}
	status, body := b.do(t, e, http.MethodPost, "/api/admin/action", map[string]string{}, true)
	if status != http.StatusForbidden || body["code"] != "forbidden" {
		t.Fatalf("用例[member越权admin -> 403 forbidden] FAIL: %d %v", status, body)
	}
	t.Log("用例[member POST /api/admin/action -> 403 forbidden] PASS")

	// admin 可以访问
	b2 := newBrowser(e)
	b2.fetchCSRF(t, e)
	status, _ = b2.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "root", "password": "root-pass"}, true)
	if status != 200 {
		t.Fatal("admin 登录失败")
	}
	status, body = b2.do(t, e, http.MethodPost, "/api/admin/action", map[string]string{}, true)
	if status != http.StatusOK {
		t.Fatalf("用例[admin访问admin资源200] FAIL: %d %v", status, body)
	}
	t.Log("用例[admin POST /api/admin/action -> 200] PASS")

	// 账号枚举：错误密码 vs 不存在账号，状态码与 error 文案一致
	b3 := newBrowser(e)
	b3.fetchCSRF(t, e)
	s1, r1 := b3.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "wrong"}, true)
	b4 := newBrowser(e)
	b4.fetchCSRF(t, e)
	s2, r2 := b4.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "ghost", "password": "wrong"}, true)
	if s1 != s2 || r1["error"] != r2["error"] {
		t.Fatalf("用例[对外不区分账号是否存在] FAIL: %d%v vs %d%v", s1, r1, s2, r2)
	}
	t.Logf("用例[两种失败均 %d 且文案=%q] PASS", s1, r1["error"])
}

func TestHTTPRateLimitTriggerAndRecover(t *testing.T) {
	t.Log("业务=端到端限流触发与恢复 连续失败后429，解除后可登录")
	e := newEnv(t)
	b := newBrowser(e)
	b.fetchCSRF(t, e)

	var lastStatus int
	for i := 0; i < 3; i++ {
		lastStatus, _ = b.do(t, e, http.MethodPost, "/api/login",
			map[string]string{"username": "alice", "password": "bad"}, true)
	}
	if lastStatus != http.StatusUnauthorized {
		t.Fatalf("用例[前3次失败返回401] FAIL: %d", lastStatus)
	}
	t.Log("用例[前 3 次错误密码 -> 401 invalid_credentials] PASS")

	status, body := b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, true)
	if status != http.StatusTooManyRequests || body["code"] != "rate_limited" {
		t.Fatalf("用例[第4次被限流429] FAIL: %d %v", status, body)
	}
	t.Logf("用例[达到阈值 -> 429 rate_limited，正确密码同样被拒] PASS")

	// 模拟封禁到期：重置后立即恢复
	e.limiter.Reset(ratelimit.Key("127.0.0.1", "alice"))
	status, body = b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, true)
	if status != http.StatusOK {
		t.Fatalf("用例[封禁解除恢复登录] FAIL: %d %v", status, body)
	}
	t.Log("用例[封禁解除后 -> 200 登录成功] PASS")
}

func TestHTTPConcurrentRenewal(t *testing.T) {
	t.Log("业务=端到端并发续期 已登录客户端大量并发请求全部成功，登出后全部401")
	e := newEnv(t)
	b := newBrowser(e)
	b.fetchCSRF(t, e)
	status, _ := b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, true)
	if status != 200 {
		t.Fatal("登录失败")
	}

	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	non200 := 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			// 每个 goroutine 独立 client 但共享 Jar：httptest + cookiejar 并发安全。
			req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/profile", nil)
			for _, ck := range b.c.Jar.Cookies(mustURL(e.ts.URL)) {
				if ck.Name == sessionCookieName {
					req.AddCookie(ck)
				}
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				mu.Lock()
				non200++
				mu.Unlock()
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				mu.Lock()
				non200++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if non200 != 0 {
		t.Fatalf("用例[50并发请求全部200，无误判未登录] FAIL 非200数量=%d", non200)
	}
	t.Logf("用例[50 并发 GET /api/profile 全部 200] PASS")

	// 服务端撤销会话后，携带旧 Cookie 的并发请求必须全部 401。
	var sid string
	for _, ck := range b.c.Jar.Cookies(mustURL(e.ts.URL)) {
		if ck.Name == sessionCookieName {
			sid = ck.Value
		}
	}
	if sid == "" {
		t.Fatal("未找到会话 Cookie")
	}
	if _, ok := e.sessions.Get(sid); !ok {
		t.Fatal("会话应仍存在")
	}
	e.sessions.Revoke(sid)
	wg.Add(n)
	revived := 0
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/profile", nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					mu.Lock()
					revived++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if revived != 0 {
		t.Fatalf("用例[撤销后50并发请求全部401] FAIL 仍有 %d 个 200", revived)
	}
	t.Log("用例[服务端撤销后 50 并发请求全部 401，立即失效] PASS")
}

// 确保 time 包被引用（未来时间相关扩展预留）。
var _ = time.Second

func TestHTTPPostLoginCSRFReissue(t *testing.T) {
	t.Log("业务=令牌补发 已登录后请求CSRF端点应补发绑定会话的令牌，不得降级为匿名票据")
	e := newEnv(t)
	b := newBrowser(e)
	b.fetchCSRF(t, e)
	status, _ := b.do(t, e, http.MethodPost, "/api/login",
		map[string]string{"username": "alice", "password": "alice-pass"}, true)
	if status != 200 {
		t.Fatal("登录失败")
	}
	// 记录当前会话与令牌，重新获取后新令牌必须能通过敏感操作。
	var sid string
	for _, ck := range b.c.Jar.Cookies(mustURL(e.ts.URL)) {
		if ck.Name == sessionCookieName {
			sid = ck.Value
		}
	}
	b.fetchCSRF(t, e)
	status, body := b.do(t, e, http.MethodPost, "/api/profile", map[string]string{}, true)
	if status != http.StatusOK {
		t.Fatalf("用例[补发令牌可用于敏感写] FAIL: %d %v", status, body)
	}
	if _, ok := e.sessions.Get(sid); !ok {
		t.Fatal("用例[补发不改变会话] FAIL 会话被替换")
	}
	t.Log("用例[已登录补发令牌绑定原会话且敏感写通过] PASS")

	// 匿名票据 Cookie 不应在登录后被重新写入。
	for _, ck := range b.c.Jar.Cookies(mustURL(e.ts.URL)) {
		if ck.Name == preloginCookie {
			t.Fatal("用例[登录后无匿名票据] FAIL csrf_pre 被重新写入")
		}
	}
	t.Log("用例[登录后不再下发匿名票据] PASS")
}
