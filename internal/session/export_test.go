package session

import "time"

// SetClock 注入自定义时钟，仅用于测试过期/续期时序。
func (m *Manager) SetClock(f func() time.Time) {
	m.mu.Lock()
	m.now = f
	m.mu.Unlock()
}

// Len 返回当前存活会话数量，供测试断言。
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.store)
}
