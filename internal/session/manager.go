package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session 描述一个已登录会话。
//
// 会话同时受两个超时约束：
//   - 空闲超时（IdleExpires）：每次请求成功续期后向后滑动；
//   - 绝对超时（AbsoluteExpires）：自会话创建起固定不变，防止会话无限续命。
//
// 被撤销或任一超时到期的会话在下次访问时立即失效。
type Session struct {
	ID              string
	UserID          string
	Username        string
	Roles           []string
	CreatedAt       time.Time
	LastAccessAt    time.Time
	AbsoluteExpires time.Time
	IdleExpires     time.Time
}

// expiredAt 判断会话在给定时刻是否已过期（不涉及锁，供内部使用）。
func (s *Session) expiredAt(now time.Time) bool {
	return now.After(s.AbsoluteExpires) || now.After(s.IdleExpires)
}

// snapshot 返回会话的一份拷贝，避免调用方在锁外修改内部状态。
func (s *Session) snapshot() *Session {
	cp := *s
	cp.Roles = append([]string(nil), s.Roles...)
	return &cp
}

// Manager 负责会话的创建、滑动续期、查询与撤销。
// 所有方法均通过互斥锁串行化，保证并发下不会出现：
//   - 请求看到半更新状态而被误判为未登录；
//   - 多个续期互相覆盖、把彼此“挤掉”。
type Manager struct {
	mu              sync.Mutex
	store           map[string]*Session
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	now             func() time.Time
}

func NewManager(idleTimeout, absoluteTimeout time.Duration) *Manager {
	return &Manager{
		store:           make(map[string]*Session),
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
		now:             time.Now,
	}
}

// newID 生成 256 位随机会话标识。
func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属于环境性致命错误，直接 panic 而非降级使用弱随机。
		panic("session: cannot read crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Create 建立一个全新会话。登录（及权限提升）时必须调用它而不是复用旧 ID，
// 以防止会话固定攻击。
func (m *Manager) Create(userID, username string, roles []string) *Session {
	now := m.now()
	s := &Session{
		ID:              newID(),
		UserID:          userID,
		Username:        username,
		Roles:           append([]string(nil), roles...),
		CreatedAt:       now,
		LastAccessAt:    now,
		AbsoluteExpires: now.Add(m.absoluteTimeout),
		IdleExpires:     now.Add(m.idleTimeout),
	}
	m.mu.Lock()
	m.store[s.ID] = s
	m.mu.Unlock()
	return s.snapshot()
}

// Get 返回会话但不续期；会话不存在或已过期时返回 false，过期项会被立即清除。
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.store[id]
	if !ok {
		return nil, false
	}
	if s.expiredAt(m.now()) {
		delete(m.store, id)
		return nil, false
	}
	return s.snapshot(), true
}

// Touch 在一次已鉴权请求开始时调用，执行滑动续期：
// 只要会话仍然有效，就把空闲截止时间向后推一个 idleTimeout。
// 多个请求并发 Touch 同一会话时，更新在锁内完成：
// 每个请求都基于最新状态判断有效性，不会误判未登录，也不会改变会话 ID。
func (m *Manager) Touch(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.store[id]
	if !ok {
		return nil, false
	}
	now := m.now()
	if s.expiredAt(now) {
		delete(m.store, id)
		return nil, false
	}
	s.LastAccessAt = now
	s.IdleExpires = now.Add(m.idleTimeout)
	return s.snapshot(), true
}

// Revoke 立即撤销会话（登出 / 服务端踢下线）。
// 撤销后任何 Get/Touch 都立即失败。
func (m *Manager) Revoke(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.store[id]; !ok {
		return false
	}
	delete(m.store, id)
	return true
}

// Sweep 清除所有已过期会话，供周期性 GC 或测试使用。
func (m *Manager) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	n := 0
	for id, s := range m.store {
		if s.expiredAt(now) {
			delete(m.store, id)
			n++
		}
	}
	return n
}
