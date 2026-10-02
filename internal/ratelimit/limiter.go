package ratelimit

import (
	"sync"
	"time"
)

// Key 组合限流维度：来源（IP/设备标识）与账号。
// 登录失败按“来源 + 账号”聚合，既防止针对单一账号的撞库，
// 也避免同一来源换账号爆破。
func Key(source, username string) string {
	return source + "|" + username
}

// state 是单个 key 的计数状态。
type state struct {
	failures     []time.Time // 窗口内的失败时间戳
	blockedUntil time.Time   // 封禁截止时间；零值表示未封禁
}

// Limiter 按 key 统计失败次数：
//   - 任意滑动窗口 window 内失败达到 maxAttempts 次，立即进入封禁；
//   - 封禁期间 Allow 稳定返回 false（不会因并发抖动提前放行）；
//   - 封禁持续 blockDuration，到期后计数清零并恢复放行，行为可预期；
//   - 一次成功（RecordSuccess）立即清空计数，使正常用户不受历史失败影响。
//
// 全部读写由同一把互斥锁保护，并发下计数不会丢失。
type Limiter struct {
	mu            sync.Mutex
	entries       map[string]*state
	maxAttempts   int
	window        time.Duration
	blockDuration time.Duration
	now           func() time.Time
}

func NewLimiter(maxAttempts int, window, blockDuration time.Duration) *Limiter {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	return &Limiter{
		entries:       make(map[string]*state),
		maxAttempts:   maxAttempts,
		window:        window,
		blockDuration: blockDuration,
		now:           time.Now,
	}
}

// prune 清理窗口外的失败记录。调用方必须持锁。
func (l *Limiter) prune(st *state, now time.Time) {
	cutoff := now.Add(-l.window)
	kept := st.failures[:0]
	for _, t := range st.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.failures = kept
}

// Allow 判断 key 当前是否可放行。封禁到期时在此原子地完成“解封 + 清零”，
// 因此恢复后的第一批并发请求看到的是一致的已清零状态。
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.entries[key]
	if !ok {
		return true
	}
	if now.Before(st.blockedUntil) {
		return false
	}
	if !st.blockedUntil.IsZero() {
		// 封禁刚到期：恢复放行并重置计数。
		st.blockedUntil = time.Time{}
		st.failures = nil
		return true
	}
	l.prune(st, now)
	if len(st.failures) >= l.maxAttempts {
		// 理论上记录失败时已立即封禁；此处兜底，保证绝不提前放行。
		st.blockedUntil = now.Add(l.blockDuration)
		return false
	}
	return true
}

// RecordFailure 原子地记录一次失败；达到阈值立即进入封禁。
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.entries[key]
	if !ok {
		st = &state{}
		l.entries[key] = st
	}
	if !st.blockedUntil.IsZero() && now.Before(st.blockedUntil) {
		// 封禁期间的尝试不延长计数，行为保持“固定时长惩罚”。
		return
	}
	l.prune(st, now)
	st.failures = append(st.failures, now)
	if len(st.failures) >= l.maxAttempts {
		st.blockedUntil = now.Add(l.blockDuration)
	}
}

// RecordSuccess 在登录成功时调用，清空该 key 的历史失败与封禁状态。
func (l *Limiter) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Reset 手动清除某 key 的状态（测试/运维使用）。
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// RetryAfter 返回距离解封还剩多久；未封禁返回 0。
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.entries[key]
	if !ok {
		return 0
	}
	if d := st.blockedUntil.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}
