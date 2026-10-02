package auth

import (
	"sync"
	"testing"
	"time"
)

// 业务：登录限流 —— 达到阈值稳定拒绝，锁定期满自动恢复
func TestRateLimitTriggerAndRecover(t *testing.T) {
	now := time.Now()
	l := NewLimiter(3, time.Minute, 30*time.Second)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		l.RecordFailure("1.1.1.1", "alice")
		if !l.Allow("1.1.1.1", "alice") {
			t.Fatalf("failure %d: should still be allowed", i+1)
		}
	}
	l.RecordFailure("1.1.1.1", "alice") // 第 3 次，触发锁定
	if l.Allow("1.1.1.1", "alice") {
		t.Fatal("threshold reached: should be locked")
	}
	t.Log("用例通过: 3 次失败触发锁定，稳定拒绝")

	now = now.Add(31 * time.Second) // 锁定期满
	if !l.Allow("1.1.1.1", "alice") {
		t.Fatal("lockout elapsed: should be allowed again")
	}
	t.Log("用例通过: 锁定期满后自动恢复放行")
}

// 业务：登录限流 —— 并发下计数不丢失、不提前放行
func TestRateLimitConcurrentCounting(t *testing.T) {
	l := NewLimiter(100, time.Minute, time.Minute)

	const workers = 100
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.RecordFailure("2.2.2.2", "bob")
		}()
	}
	wg.Wait()

	if l.Allow("2.2.2.2", "bob") {
		t.Fatal("100 concurrent failures must trigger lockout (计数丢失)")
	}
	t.Logf("用例通过: %d 个并发失败全部计入，达到阈值后锁定", workers)
}

// 业务：登录限流 —— 维度隔离与成功清零
func TestRateLimitDimensions(t *testing.T) {
	l := NewLimiter(2, time.Minute, time.Minute)

	l.RecordFailure("3.3.3.3", "carol")
	l.RecordFailure("3.3.3.3", "carol")
	if l.Allow("3.3.3.3", "carol") {
		t.Fatal("same source+account should be locked")
	}
	if !l.Allow("9.9.9.9", "carol") {
		t.Fatal("different source must not be affected")
	}
	if !l.Allow("3.3.3.3", "dave") {
		t.Fatal("different account must not be affected")
	}
	t.Log("用例通过: 限流按 (来源, 账号) 维度隔离")

	l2 := NewLimiter(2, time.Minute, time.Minute)
	l2.RecordFailure("3.3.3.3", "carol")
	l2.RecordSuccess("3.3.3.3", "carol")
	l2.RecordFailure("3.3.3.3", "carol")
	if !l2.Allow("3.3.3.3", "carol") {
		t.Fatal("success should reset failure count")
	}
	t.Log("用例通过: 登录成功后失败计数清零")
}
