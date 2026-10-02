package auth

import (
	"sync"
	"time"
)

// Limiter 按 (来源, 账号) 维度统计登录失败并限流。
// 窗口内失败达到 maxFails 次即锁定 lockout 时长；
// 所有计数在同一把锁内完成，并发下不丢失、不提前放行。
type Limiter struct {
	mu       sync.Mutex
	failures map[string]*limitEntry
	maxFails int
	window   time.Duration
	lockout  time.Duration
	now      func() time.Time
}

type limitEntry struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// NewLimiter maxFails 次失败（window 内）触发 lockout 时长的锁定。
func NewLimiter(maxFails int, window, lockout time.Duration) *Limiter {
	return &Limiter{
		failures: make(map[string]*limitEntry),
		maxFails: maxFails,
		window:   window,
		lockout:  lockout,
		now:      time.Now,
	}
}

func limitKey(source, account string) string { return source + "\x00" + account }

// Allow 在尝试登录前调用；处于锁定期内返回 false。
// 锁定期一过即自动恢复放行，无需额外操作。
func (l *Limiter) Allow(source, account string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[limitKey(source, account)]
	if !ok {
		return true
	}
	// 锁定期内（now < lockedUntil）拒绝；锁定期一过即放行。
	return !l.now().Before(e.lockedUntil)
}

// RecordFailure 记录一次失败，达到阈值即进入锁定。
// 窗口过期后计数归零重新统计。
func (l *Limiter) RecordFailure(source, account string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := limitKey(source, account)
	e, ok := l.failures[key]
	if !ok || now.Sub(e.windowStart) >= l.window {
		e = &limitEntry{windowStart: now}
		l.failures[key] = e
	}
	e.count++
	if e.count >= l.maxFails {
		e.lockedUntil = now.Add(l.lockout)
		e.count = 0
		e.windowStart = now
	}
}

// RecordSuccess 登录成功后清除该维度计数。
func (l *Limiter) RecordSuccess(source, account string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, limitKey(source, account))
}
