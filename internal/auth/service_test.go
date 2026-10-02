package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/feng111627/auth-session-hardening-go/internal/csrf"
	"github.com/feng111627/auth-session-hardening-go/internal/ratelimit"
	"github.com/feng111627/auth-session-hardening-go/internal/rbac"
	"github.com/feng111627/auth-session-hardening-go/internal/session"
)

type fixture struct {
	svc       *Service
	sessions  *session.Manager
	limiter   *ratelimit.Limiter
	protector *csrf.Protector
	authz     *rbac.Authorizer
	dir       *MemoryDirectory
	clock     func() time.Time
	setClock  func(func() time.Time)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := NewMemoryDirectory()
	dir.Add("u1", "alice", "correct-pass", []string{rbac.RoleMember})
	dir.Add("u2", "root", "root-pass", []string{rbac.RoleAdmin})

	sessions := session.NewManager(time.Minute, time.Hour)
	limiter := ratelimit.NewLimiter(3, 10*time.Minute, 15*time.Minute)
	protector := csrf.NewProtector()
	authz := rbac.NewAuthorizer()
	authz.Grant(rbac.RoleMember, rbac.ResourceProfile, rbac.ActionRead, rbac.ActionWrite)
	authz.Grant(rbac.RoleAdmin, rbac.ResourceAdmin, rbac.ActionAdmin)
	svc := NewService(dir, sessions, limiter, protector, authz)
	return &fixture{svc: svc, sessions: sessions, limiter: limiter, protector: protector, authz: authz, dir: dir}
}

func expectCode(t *testing.T, err error, want ErrorCode, caseName string) {
	t.Helper()
	if CodeOf(err) != want {
		t.Fatalf("用例[%s] FAIL 期望错误码=%s 实际=%v", caseName, want, err)
	}
	t.Logf("用例[%s] PASS (code=%s)", caseName, want)
}

func TestLoginSuccessRotatesSession(t *testing.T) {
	t.Log("业务=登录与会话固定防护 成功登录后会话ID与CSRF全部换新并绑定新会话")
	f := newFixture(t)
	binding := "prelogin-ticket"
	tok := f.protector.Issue(binding)

	res, err := f.svc.Login("1.1.1.1", "alice", "correct-pass", binding, tok)
	if err != nil {
		t.Fatalf("正常登录失败: %v", err)
	}
	if res.SessionID == "" || res.CSRFToken == "" {
		t.Fatal("用例[登录返回会话与CSRF] FAIL")
	}
	// 旧绑定票据签发的 token 不得在登录后通过（新令牌绑定的是新会话 ID）。
	if f.protector.Validate(res.SessionID, tok) {
		t.Fatal("用例[旧预登录令牌不可用于新会话] FAIL 存在会话固定风险")
	}
	if !f.protector.Validate(res.SessionID, res.CSRFToken) {
		t.Fatal("用例[新CSRF绑定新会话] FAIL")
	}
	// 再次登录产生不同会话 ID（永不复用固定 ID）。
	res2, err := f.svc.Login("1.1.1.1", "alice", "correct-pass", binding, tok)
	if err != nil {
		t.Fatalf("第二次登录失败: %v", err)
	}
	if res2.SessionID == res.SessionID {
		t.Fatal("用例[每次登录轮换全新会话ID] FAIL")
	}
	t.Log("用例[会话ID轮换、CSRF重新绑定新会话、旧令牌失效] PASS")
}

func TestLoginCSRFRejection(t *testing.T) {
	t.Log("业务=登录CSRF防护 缺失/错误/绑定不符的令牌必须拒绝且原因可区分")
	f := newFixture(t)

	_, err := f.svc.Login("1.1.1.1", "alice", "correct-pass", "b", "")
	expectCode(t, err, ErrCSRFInvalid, "无令牌拒绝")

	bad := f.protector.Issue("other-binding")
	_, err = f.svc.Login("1.1.1.1", "alice", "correct-pass", "b", bad)
	expectCode(t, err, ErrCSRFInvalid, "绑定不符拒绝")

	_, err = f.svc.Login("1.1.1.1", "alice", "correct-pass", "b", "tampered.token")
	expectCode(t, err, ErrCSRFInvalid, "伪造令牌拒绝")
}

func TestLoginAccountEnumeration(t *testing.T) {
	t.Log("业务=账号枚举防护 账号不存在与密码错误返回相同错误码与文案")
	f := newFixture(t)
	binding := "b"
	tok := f.protector.Issue(binding)

	_, err1 := f.svc.Login("1.1.1.1", "ghost", "whatever", binding, tok)
	_, err2 := f.svc.Login("1.1.1.1", "alice", "wrong-pass", binding, tok)
	if CodeOf(err1) != ErrInvalidCredentials || CodeOf(err2) != ErrInvalidCredentials {
		t.Fatalf("用例[错误码一致] FAIL: %v vs %v", err1, err2)
	}
	if err1.Error() == "" || err1.Error() != err2.Error() {
		t.Fatalf("用例[错误文案一致] FAIL: %q vs %q", err1.Error(), err2.Error())
	}
	t.Logf("用例[不存在账号与密码错误完全同码同文案] PASS (%s)", err1.Error())
}

func TestLoginRateLimit(t *testing.T) {
	t.Log("业务=登录失败限流 阈值后稳定拒绝(rate_limited)，成功/恢复后放行")
	f := newFixture(t)
	binding := "b"
	tok := f.protector.Issue(binding)

	for i := 0; i < 3; i++ {
		_, err := f.svc.Login("1.1.1.1", "alice", "bad", binding, tok)
		expectCode(t, err, ErrInvalidCredentials, "失败计数")
	}
	// 即便密码正确，封禁期内也必须稳定拒绝。
	_, err := f.svc.Login("1.1.1.1", "alice", "correct-pass", binding, tok)
	expectCode(t, err, ErrRateLimited, "封禁期正确密码也拒绝")

	// 其它来源不受影响。
	_, err = f.svc.Login("2.2.2.2", "alice", "correct-pass", binding, tok)
	if err != nil {
		t.Fatalf("用例[其他来源正常放行] FAIL: %v", err)
	}
	t.Log("用例[来源维度隔离：其他IP可正常登录] PASS")

	// 封禁解除后恢复（手动重置模拟到期）。
	f.limiter.Reset(ratelimit.Key("1.1.1.1", "alice"))
	res, err := f.svc.Login("1.1.1.1", "alice", "correct-pass", binding, tok)
	if err != nil {
		t.Fatalf("用例[恢复后放行] FAIL: %v", err)
	}
	t.Logf("用例[封禁解除后登录成功 user=%s] PASS", res.Username)
}

func TestLoginConcurrentFailuresNoLostCount(t *testing.T) {
	t.Log("业务=并发登录失败计数 并发失败不得丢计数导致提前放行")
	f := newFixture(t)
	binding := "b"
	tok := f.protector.Issue(binding)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.svc.Login("9.9.9.9", "alice", "bad", binding, tok)
		}()
	}
	wg.Wait()
	_, err := f.svc.Login("9.9.9.9", "alice", "correct-pass", binding, tok)
	expectCode(t, err, ErrRateLimited, "50并发失败后正确密码也被限流")
}

func TestAuthorizeRequest(t *testing.T) {
	t.Log("业务=请求鉴权 会话/CSRF/RBAC三道关，失败原因各自可区分")
	f := newFixture(t)
	binding := "b"
	tok := f.protector.Issue(binding)
	res, err := f.svc.Login("1.1.1.1", "alice", "correct-pass", binding, tok)
	if err != nil {
		t.Fatal(err)
	}

	// 无效会话
	_, err = f.svc.AuthorizeRequest("no-such-session", "", rbac.ResourceProfile, rbac.ActionRead, false)
	expectCode(t, err, ErrSessionInvalid, "不存在的会话拒绝")

	// 正常只读
	sess, err := f.svc.AuthorizeRequest(res.SessionID, "", rbac.ResourceProfile, rbac.ActionRead, false)
	if err != nil {
		t.Fatalf("用例[合法只读放行] FAIL: %v", err)
	}
	if sess.Username != "alice" {
		t.Fatal("用例[鉴权返回会话主体] FAIL")
	}
	t.Log("用例[合法只读请求放行] PASS")

	// 写操作缺 CSRF
	_, err = f.svc.AuthorizeRequest(res.SessionID, "", rbac.ResourceProfile, rbac.ActionWrite, true)
	expectCode(t, err, ErrCSRFInvalid, "敏感操作缺CSRF拒绝")

	// 写操作携带正确 CSRF
	_, err = f.svc.AuthorizeRequest(res.SessionID, res.CSRFToken, rbac.ResourceProfile, rbac.ActionWrite, true)
	if err != nil {
		t.Fatalf("用例[敏感操作携带CSRF放行] FAIL: %v", err)
	}
	t.Log("用例[敏感操作携带正确CSRF放行] PASS")

	// 越权：member 访问 admin 资源
	_, err = f.svc.AuthorizeRequest(res.SessionID, res.CSRFToken, rbac.ResourceAdmin, rbac.ActionAdmin, true)
	expectCode(t, err, ErrForbidden, "member越权admin资源拒绝")

	// 撤销后立即失效
	f.svc.Logout(res.SessionID)
	_, err = f.svc.AuthorizeRequest(res.SessionID, res.CSRFToken, rbac.ResourceProfile, rbac.ActionRead, false)
	expectCode(t, err, ErrSessionInvalid, "登出后会话立即失效")
}
