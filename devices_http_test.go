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

// newFeatureServer 装配启用完整会话生命周期与设备上限的测试服务。
func newFeatureServer(t *testing.T, maxPerUser int) *Server {
	t.Helper()
	limiter := NewLimiter(5, time.Minute, 50*time.Millisecond)
	srv := NewServerWithConfig(ServerConfig{
		IdleTTL:            time.Minute,
		PersistentIdleTTL:  10 * time.Minute,
		AbsoluteTTL:        30 * time.Minute,
		MaxSessionsPerUser: maxPerUser,
	}, []byte("test-secret"), limiter)
	if err := srv.AddUser("alice", "alice-pass", RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddUser("bob", "bob-pass", RoleGuest); err != nil {
		t.Fatal(err)
	}
	return srv
}

// loginRaw 以自定义 JSON 体与 User-Agent 登录（用于新字段/老客户端对比）。
func (c *authClient) loginRaw(t *testing.T, body, ua string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.RequestURI = "/login"
	if c.sessionID != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.sessionID})
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
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

func (c *authClient) loginAsDevice(t *testing.T, user, pass, label string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q,"device_label":%q}`, user, pass, label)
	return c.loginRaw(t, body, "UA-"+label)
}

type sessionItem struct {
	ID           string `json:"id"`
	DeviceLabel  string `json:"device_label"`
	UserAgent    string `json:"user_agent"`
	IP           string `json:"ip"`
	LoginAt      string `json:"login_at"`
	LastActiveAt string `json:"last_active_at"`
	Current      bool   `json:"current"`
}

func listSessions(t *testing.T, c *authClient) []sessionItem {
	t.Helper()
	rec := c.do("GET", "/sessions", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sessions: got %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Sessions []sessionItem `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode sessions: %v body %s", err, rec.Body)
	}
	return resp.Sessions
}

// 业务：多设备会话（HTTP）—— 查看当前所有活跃会话，区分设备与时间
func TestServerListDevices(t *testing.T) {
	srv := newFeatureServer(t, 0)
	phone := &authClient{t: t, handler: srv.Handler()}
	phone.loginAsDevice(t, "alice", "alice-pass", "alice-iPhone")
	laptop := &authClient{t: t, handler: srv.Handler()}
	laptop.loginAsDevice(t, "alice", "alice-pass", "alice-MacBook")

	items := listSessions(t, phone)
	if len(items) != 2 {
		t.Fatalf("alice 应有 2 条活跃会话，实际 %d", len(items))
	}
	labels := map[string]bool{}
	currentN := 0
	for _, it := range items {
		labels[it.DeviceLabel] = true
		if it.DeviceLabel == "alice-iPhone" && it.UserAgent != "UA-alice-iPhone" {
			t.Fatalf("应记录设备 User-Agent: %+v", it)
		}
		if it.LoginAt == "" || it.LastActiveAt == "" {
			t.Fatalf("登录时间与最近活动时间必须给出: %+v", it)
		}
		if it.Current {
			currentN++
		}
	}
	if !labels["alice-iPhone"] || !labels["alice-MacBook"] {
		t.Fatalf("会话列表必须区分设备，实际 %v", labels)
	}
	if currentN != 1 {
		t.Fatalf("列表中应有且仅有一条 current=true，实际 %d", currentN)
	}
	t.Log("用例通过: 可查看两台设备的活跃会话，设备、登录/活动时间与当前会话标记正确")
}

// 业务：多设备会话（HTTP）—— 单独结束另一台设备，本机继续可用
func TestServerRevokeOneDevice(t *testing.T) {
	srv := newFeatureServer(t, 0)
	phone := &authClient{t: t, handler: srv.Handler()}
	phone.loginAsDevice(t, "alice", "alice-pass", "手机")
	laptop := &authClient{t: t, handler: srv.Handler()}
	laptop.loginAsDevice(t, "alice", "alice-pass", "笔记本")

	items := listSessions(t, phone)
	var laptopID string
	for _, it := range items {
		if it.DeviceLabel == "笔记本" {
			laptopID = it.ID
		}
	}
	if laptopID == "" {
		t.Fatal("未找到笔记本会话")
	}

	// 结束另一台设备：DELETE 需要 CSRF。
	rec := phone.do("DELETE", "/sessions/"+laptopID, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE 缺 CSRF 应 403，实际 %d", rec.Code)
	}
	rec = phone.do("DELETE", "/sessions/"+laptopID, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("结束指定会话应 200，实际 %d body %s", rec.Code, rec.Body)
	}
	if rec := laptop.do("GET", "/profile", false); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionRevoked)) {
		t.Fatalf("被结束设备应立即 401 session_revoked，实际 %d body %s", rec.Code, rec.Body)
	}
	if rec := phone.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("发起结束的本机不应受影响，实际 %d", rec.Code)
	}
	if got := len(listSessions(t, phone)); got != 1 {
		t.Fatalf("结束一台后应剩 1 条，实际 %d", got)
	}
	t.Log("用例通过: 单独结束笔记本后其立即失效，手机继续可用，列表仅剩 1 条")
}

// 业务：多设备会话（HTTP）—— 一次结束全部设备，含当前会话，他人不受影响
func TestServerRevokeAllDevices(t *testing.T) {
	srv := newFeatureServer(t, 0)
	a1 := &authClient{t: t, handler: srv.Handler()}
	a1.loginAsDevice(t, "alice", "alice-pass", "alice-1")
	a2 := &authClient{t: t, handler: srv.Handler()}
	a2.loginAsDevice(t, "alice", "alice-pass", "alice-2")
	b1 := &authClient{t: t, handler: srv.Handler()}
	b1.loginAsDevice(t, "bob", "bob-pass", "bob-1")

	rec := a1.do("POST", "/sessions/revoke-all", true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ended":2`) {
		t.Fatalf("全部结束应 200 且 ended=2，实际 %d body %s", rec.Code, rec.Body)
	}
	for i, c := range []*authClient{a1, a2} {
		if rec := c.do("GET", "/profile", false); rec.Code != http.StatusUnauthorized ||
			!strings.Contains(rec.Body.String(), string(ReasonSessionRevoked)) {
			t.Fatalf("alice 设备 %d 应立即失效，实际 %d body %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := b1.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("bob 的会话不应受影响，实际 %d", rec.Code)
	}
	t.Log("用例通过: 一键结束 alice 全部 2 台设备（含当前），bob 不受影响")
}

// 业务：会话归属（HTTP）—— 不能结束他人会话，统一 404 不泄露归属
func TestServerCannotRevokeOthersSession(t *testing.T) {
	srv := newFeatureServer(t, 0)
	alice := &authClient{t: t, handler: srv.Handler()}
	alice.loginAsDevice(t, "alice", "alice-pass", "alice-x")
	bob := &authClient{t: t, handler: srv.Handler()}
	bob.loginAsDevice(t, "bob", "bob-pass", "bob-x")

	bobItems := listSessions(t, bob)
	if len(bobItems) != 1 {
		t.Fatalf("bob 应只见自己的 1 条会话，实际 %d", len(bobItems))
	}
	// alice 尝试结束 bob 的会话：404 且文案与不存在完全一致。
	recForeign := alice.do("DELETE", "/sessions/"+bobItems[0].ID, true)
	recMissing := alice.do("DELETE", "/sessions/no-such-id", true)
	if recForeign.Code != http.StatusNotFound || recMissing.Code != http.StatusNotFound {
		t.Fatalf("他人会话与不存在会话均应 404，实际 %d / %d", recForeign.Code, recMissing.Code)
	}
	if recForeign.Body.String() != recMissing.Body.String() {
		t.Fatalf("两种 404 响应必须一致以免泄露会话归属:\n%s\n%s", recForeign.Body, recMissing.Body)
	}
	if rec := bob.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("bob 会话不应被他人结束，实际 %d", rec.Code)
	}
	t.Log("用例通过: 结束他人会话返回与不存在一致的 404，不泄露归属")
}

// newClockServer 装配“长空闲、可控时钟”的测试服务，用于到期线类用例，
// 避免推进时钟时空闲线意外先到而掩盖要验证的行为。
func newClockServer(t *testing.T, idle, persistent, absolute time.Duration, maxPerUser int) *Server {
	t.Helper()
	limiter := NewLimiter(5, time.Minute, 50*time.Millisecond)
	srv := NewServerWithConfig(ServerConfig{
		IdleTTL:            idle,
		PersistentIdleTTL:  persistent,
		AbsoluteTTL:        absolute,
		MaxSessionsPerUser: maxPerUser,
	}, []byte("test-secret"), limiter)
	if err := srv.AddUser("alice", "alice-pass", RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddUser("bob", "bob-pass", RoleGuest); err != nil {
		t.Fatal(err)
	}
	return srv
}

// 业务：会话上限（HTTP）—— 第 N+1 台登录挤掉最久未活动设备，新设备立即可用
func TestServerDeviceCapEviction(t *testing.T) {
	// 空闲 TTL 远大于测试推进时间，保证让位原因是“超上限”而非空闲到期。
	srv := newClockServer(t, time.Hour, time.Hour, time.Hour, 2)
	store := srv.Sessions()
	now := time.Now()
	store.now = func() time.Time { return now }

	d1 := &authClient{t: t, handler: srv.Handler()}
	d1.loginAsDevice(t, "alice", "alice-pass", "设备1")
	now = now.Add(time.Minute)
	d2 := &authClient{t: t, handler: srv.Handler()}
	d2.loginAsDevice(t, "alice", "alice-pass", "设备2")
	now = now.Add(time.Minute)
	d3 := &authClient{t: t, handler: srv.Handler()}
	rec := d3.loginAsDevice(t, "alice", "alice-pass", "设备3")
	if rec.Code != http.StatusOK {
		t.Fatalf("新设备登录应成功，实际 %d body %s", rec.Code, rec.Body)
	}

	// 最久未活动的设备1被让位并立即失效。
	if rec := d1.do("GET", "/profile", false); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionEvicted)) {
		t.Fatalf("设备1应被淘汰(session_evicted)，实际 %d body %s", rec.Code, rec.Body)
	}
	// 设备2、设备3继续可用。
	if rec := d2.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("设备2不应受影响，实际 %d", rec.Code)
	}
	if rec := d3.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("刚登录的设备3必须立即可用，实际 %d", rec.Code)
	}
	if got := len(listSessions(t, d3)); got != 2 {
		t.Fatalf("活跃会话不得突破上限 2，实际 %d", got)
	}
	t.Log("用例通过: 第 3 台登录挤掉最久未活动的设备1，设备2/3 正常使用")
}

// 业务：会话上限（HTTP）—— 并发登录不突破上限
func TestServerDeviceCapConcurrent(t *testing.T) {
	srv := newFeatureServer(t, 3)
	const n = 20
	var wg sync.WaitGroup
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := &authClient{t: t, handler: srv.Handler()}
			rec := c.loginAsDevice(t, "alice", "alice-pass",
				fmt.Sprintf("并发-%d", i))
			codes <- rec.Code
		}(i)
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("所有登录请求本身都应成功（淘汰旧会话），实际 %d", code)
		}
	}
	probe := &authClient{t: t, handler: srv.Handler()}
	probe.loginAsDevice(t, "alice", "alice-pass", "探针")
	items := listSessions(t, probe)
	if len(items) != 3 {
		t.Fatalf("并发登录后活跃数应恰好为上限 3，实际 %d", len(items))
	}
	t.Logf("用例通过: %d 台并发登录全部成功，活跃会话稳定为上限 3", n)
}

// 业务：老客户端兼容（HTTP）—— 不带 persistent/设备字段时按默认继续可用
func TestServerLegacyClientDefaults(t *testing.T) {
	srv := newFeatureServer(t, 0)
	c := &authClient{t: t, handler: srv.Handler()}
	// 旧登录体：仅 username/password，且无 User-Agent。
	rec := c.loginRaw(t, `{"username":"alice","password":"alice-pass"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("老客户端登录应成功，实际 %d body %s", rec.Code, rec.Body)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["persistent"] != false {
		t.Fatalf("缺省 persistent 必须为 false，实际 %v", resp["persistent"])
	}
	if rec := c.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("老客户端登录后应能正常访问，实际 %d", rec.Code)
	}
	items := listSessions(t, c)
	if len(items) != 1 || items[0].DeviceLabel != "" || items[0].UserAgent != "" {
		t.Fatalf("老客户端会话设备信息应为空值: %+v", items)
	}
	t.Log("用例通过: 老客户端不带新字段时按普通会话默认值继续可用")
}

// 业务：长登录（HTTP）—— 登录时选择“保持长时间登录”，空闲放宽生效
func TestServerPersistentLoginRelaxesIdle(t *testing.T) {
	srv := newFeatureServer(t, 0)
	store := srv.Sessions()
	now := time.Now()
	store.now = func() time.Time { return now }

	persist := &authClient{t: t, handler: srv.Handler()}
	body := `{"username":"alice","password":"alice-pass","persistent":true,"device_label":"长登录设备"}`
	if rec := persist.loginRaw(t, body, "UA-persist"); rec.Code != http.StatusOK {
		t.Fatalf("长登录应成功: %d body %s", rec.Code, rec.Body)
	}
	normal := &authClient{t: t, handler: srv.Handler()}
	normal.loginRaw(t, `{"username":"bob","password":"bob-pass"}`, "")

	// 普通空闲 1min、长登录 10min：5 分钟不活动后，普通失效、长登录可用。
	now = now.Add(5 * time.Minute)
	if rec := normal.do("GET", "/profile", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("普通会话应已空闲失效，实际 %d", rec.Code)
	}
	if rec := persist.do("GET", "/profile", false); rec.Code != http.StatusOK {
		t.Fatalf("长登录会话空闲放宽后应仍有效，实际 %d body %s", rec.Code, rec.Body)
	}
	t.Log("用例通过: 选择保持登录后空闲 5 分钟仍可用，普通会话同条件已失效")
}

// 业务：双到期线（HTTP）—— 空闲到期与最长存活到期对外均为统一 401 文案
func TestServerExpiryLinesHTTP(t *testing.T) {
	// 空闲线先到：401 + 统一文案 authentication required。
	srv := newClockServer(t, time.Minute, 10*time.Minute, 30*time.Minute, 0)
	store := srv.Sessions()
	now := time.Now()
	store.now = func() time.Time { return now }

	idle := &authClient{t: t, handler: srv.Handler()}
	idle.loginRaw(t, `{"username":"alice","password":"alice-pass"}`, "")
	now = now.Add(2 * time.Minute) // 空闲 1min 已过，绝对 30min 未到
	rec := idle.do("GET", "/profile", false)
	if rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), "authentication required") ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionExpired)) {
		t.Fatalf("空闲到期应 401 统一文案+内部原因，实际 %d body %s", rec.Code, rec.Body)
	}

	// 绝对线先到：持续活跃，30min 后同样 401 统一文案，但内部原因为绝对到期。
	srv = newClockServer(t, 10*time.Minute, 10*time.Minute, 30*time.Minute, 0)
	store = srv.Sessions()
	now = time.Now()
	store.now = func() time.Time { return now }

	abs := &authClient{t: t, handler: srv.Handler()}
	abs.loginRaw(t, `{"username":"alice","password":"alice-pass"}`, "")
	for m := 0; m < 29; m++ {
		now = now.Add(time.Minute)
		if r := abs.do("GET", "/profile", false); r.Code != http.StatusOK {
			t.Fatalf("第 %d 分钟活跃会话应有效: %d", m+1, r.Code)
		}
	}
	now = now.Add(time.Minute)
	rec = abs.do("GET", "/profile", false)
	if rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), "authentication required") ||
		!strings.Contains(rec.Body.String(), string(ReasonSessionAbsoluteExpired)) {
		t.Fatalf("绝对到期应 401 统一文案+绝对到期原因，实际 %d body %s", rec.Code, rec.Body)
	}
	t.Log("用例通过: 两种到期对外都是统一 401 文案，内部原因分别可辨")
}
