package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session 表示一条登录会话。
type Session struct {
	ID        string
	UserID    string
	Role      Role
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
}

// Store 是并发安全的内存会话存储，支持滑动续期与撤销。
// 所有变更在同一把互斥锁内完成：并发 Touch 要么全部续期成功，
// 要么在撤销/过期后全部失败，不会出现部分请求被误判未登录或互相挤掉。
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
	now      func() time.Time
}

// NewStore 创建会话存储；ttl 为滑动过期时长。
func NewStore(ttl time.Duration) *Store {
	return &Store{sessions: make(map[string]*Session), ttl: ttl, now: time.Now}
}

func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Create 建立新会话。登录成功后调用：每次登录都生成全新会话 ID，
// 并撤销该用户请求中携带的旧会话（由调用方完成），从而防御会话固定攻击。
func (s *Store) Create(userID string, role Role) (*Session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess := &Session{
		ID:        id,
		UserID:    userID,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	cp := *sess
	return &cp, nil
}

// Touch 校验会话有效性并滑动续期。
// 续期在锁内原子完成：同一时刻的多个并发 Touch 各自延长过期时间，
// 最终过期时间为其中最晚的一次，互不覆盖为更早的值。
func (s *Store) Touch(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, reasonErr(ReasonSessionUnknown, "session not found")
	}
	if sess.Revoked {
		return nil, reasonErr(ReasonSessionRevoked, "session revoked")
	}
	now := s.now()
	if !now.Before(sess.ExpiresAt) {
		delete(s.sessions, id)
		return nil, reasonErr(ReasonSessionExpired, "session expired")
	}
	sess.ExpiresAt = now.Add(s.ttl)
	cp := *sess
	return &cp, nil
}

// Revoke 撤销会话，撤销后立即失效（后续 Touch 一律返回已撤销错误）。
func (s *Store) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.Revoked = true
	}
}

// Get 只读查询（不续期），供测试与内部诊断。
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	cp := *sess
	return &cp, true
}
