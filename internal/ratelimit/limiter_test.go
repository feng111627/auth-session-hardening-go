package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
}
func (c *fakeClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTestLimiter(t *testing.T) (*Limiter, *fakeClock) {
	t.Helper()
	c := newFakeClock()
	// 窗口 10 分钟，最多 5 次失败，封禁 15 分钟。
	l := NewLimiter(5, 10*time.Minute, 15*time.Minute)
	l.SetClock(c.now)
	return l, c
}

func TestRateLimitTrigger(t *testing.T) {
	t.Log("业务=登录失败限流 达到阈值前放行，达到阈值瞬间封禁")
	l, _ := newTestLimiter(t)
	k := Key("1.2.3.4", "alice")
	for i := 1; i <= 4; i++ {
		l.RecordFailure(k)
		if !l.Allow(k) {
			t.Fatalf("用例[第%d次失败后仍放行] FAIL", i)
		}
	}
	t.Log("用例[前4次失败后仍放行] PASS")

	l.RecordFailure(k)
	if l.Allow(k) {
		t.Fatal("用例[第5次失败后立即封禁] FAIL 仍放行")
	}
	if !l.blocked(k) {
		t.Fatal("用例[状态机进入封禁态] FAIL")
	}
	if l.RetryAfter(k) <= 0 {
		t.Fatal("用例[RetryAfter返回剩余封禁时间] FAIL")
	}
	t.Log("用例[第5次失败触发封禁并稳定拒绝] PASS")
}

func TestRateLimitBlockThenRecover(t *testing.T) {
	t.Log("业务=限流恢复 封禁期内稳定拒绝，到期后自动清零放行")
	l, c := newTestLimiter(t)
	k := Key("1.2.3.4", "alice")
	for i := 0; i < 5; i++ {
		l.RecordFailure(k)
	}
	if l.Allow(k) {
		t.Fatal("期望封禁中")
	}

	c.advance(14 * time.Minute)
	if l.Allow(k) {
		t.Fatal("用例[封禁第14分钟仍拒绝] FAIL 提前放行")
	}
	t.Log("用例[封禁期间持续拒绝，不提前放行] PASS")

	c.advance(time.Minute + time.Second) // 15 分钟过后
	if !l.Allow(k) {
		t.Fatal("用例[封禁到期恢复放行] FAIL")
	}
	t.Log("用例[封禁到期自动恢复放行] PASS")

	// 恢复后计数已清零：再失败 4 次不应封禁。
	for i := 0; i < 4; i++ {
		l.RecordFailure(k)
	}
	if !l.Allow(k) {
		t.Fatal("用例[恢复后计数已清零] FAIL 旧失败仍被计入")
	}
	t.Log("用例[恢复后计数清零，重新计数] PASS")
}

func TestRateLimitSlidingWindow(t *testing.T) {
	t.Log("业务=滑动窗口 窗口外的旧失败不再计入，达到阈值不封禁")
	l, c := newTestLimiter(t)
	k := Key("1.2.3.4", "alice")
	for i := 0; i < 4; i++ {
		l.RecordFailure(k)
	}
	c.advance(10*time.Minute + time.Second)
	l.RecordFailure(k) // 第 5 次发生在旧记录滑出窗口后
	if !l.Allow(k) {
		t.Fatal("用例[旧失败滑出窗口后不触发封禁] FAIL")
	}
	t.Log("用例[仅统计窗口内失败] PASS")
}

func TestRateLimitSuccessResets(t *testing.T) {
	t.Log("业务=成功登录清除计数 正常用户不受历史失败影响")
	l, _ := newTestLimiter(t)
	k := Key("1.2.3.4", "alice")
	for i := 0; i < 4; i++ {
		l.RecordFailure(k)
	}
	l.RecordSuccess(k)
	for i := 0; i < 4; i++ {
		l.RecordFailure(k)
	}
	if !l.Allow(k) {
		t.Fatal("用例[成功后历史失败被清空] FAIL")
	}
	t.Log("用例[RecordSuccess 清空计数] PASS")
}

func TestRateLimitDimensions(t *testing.T) {
	t.Log("业务=限流维度隔离 不同来源/账号独立计数")
	l, _ := newTestLimiter(t)
	k1 := Key("1.2.3.4", "alice")
	k2 := Key("1.2.3.4", "bob")
	k3 := Key("5.6.7.8", "alice")
	for i := 0; i < 5; i++ {
		l.RecordFailure(k1)
	}
	if l.Allow(k1) {
		t.Fatal("alice@来源1 应被封禁")
	}
	if !l.Allow(k2) || !l.Allow(k3) {
		t.Fatal("用例[其他账号/来源不受牵连] FAIL")
	}
	t.Log("用例[来源×账号维度互相隔离] PASS")
}

func TestRateLimitConcurrentFailures(t *testing.T) {
	t.Log("业务=限流并发计数 大量并发失败一次性达到阈值后必须稳定拒绝，不丢计数、不提前放行")
	l, _ := newTestLimiter(t)
	k := Key("1.2.3.4", "alice")

	const n = 200
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() { defer wg.Done(); l.RecordFailure(k) }()
	}
	wg.Wait()

	if l.Allow(k) {
		t.Fatal("用例[200 并发失败后必封禁] FAIL 计数丢失导致提前放行")
	}
	if !l.blocked(k) {
		t.Fatal("用例[并发后进入封禁态] FAIL")
	}
	t.Log("用例[200 协程并发 RecordFailure 无丢失，阈值后稳定封禁] PASS")

	// 封禁期间并发 Allow 必须全部拒绝。
	var wg2 sync.WaitGroup
	released := make(chan struct{}, n)
	wg2.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg2.Done()
			if l.Allow(k) {
				released <- struct{}{}
			}
		}()
	}
	wg2.Wait()
	close(released)
	if len(released) != 0 {
		t.Fatalf("用例[封禁期并发Allow全部拒绝] FAIL 有 %d 次被放行", len(released))
	}
	t.Log("用例[封禁期 200 协程并发 Allow 零放行] PASS")
}
