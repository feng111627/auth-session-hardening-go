package ratelimit

import "time"

func (l *Limiter) SetClock(f func() time.Time) {
	l.mu.Lock()
	l.now = f
	l.mu.Unlock()
}

// blocked 供测试查询某 key 当前是否处于封禁态。
func (l *Limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.entries[key]
	return ok && l.now().Before(st.blockedUntil)
}
