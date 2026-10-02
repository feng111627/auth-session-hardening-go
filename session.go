package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ClientInfo 描述会话来自哪个客户端/设备，由登录请求与请求头推导。
type ClientInfo struct {
	// Label 是面向用户展示的设备/客户端标识（如 "Chrome on Linux"）。
	Label string
	// UserAgent 为登录请求的 User-Agent 原始值。
	UserAgent string
	// IP 为登录来源 IP。
	IP string
}

// Session 表示一条登录会话。
type Session struct {
	ID string
	// ExpiresAt 为空闲到期时间：超过 LastActivityAt+空闲时长未活动即失效。
	ExpiresAt time.Time
	UserID    string
	Role      Role
	CreatedAt time.Time
	// LastActivityAt 为最近一次活动时间，滑动续期随之更新。
	LastActivityAt time.Time
	// AbsoluteExpiresAt 为最长存活到期时间：从建立起算，无论多活跃一律失效。
	// 零值表示不设最长存活上限（向后兼容仅滑动续期的旧行为）。
	AbsoluteExpiresAt time.Time
	// Persistent 表示用户登录时选择了“保持长时间登录”，空闲时长放宽。
	Persistent bool
	// Device 为该会话的客户端/设备信息。
	Device  ClientInfo
	Revoked bool
	// Evicted 表示因同账号会话数达到上限而被让位淘汰。
	Evicted bool
	// seq 为建立序号（内部使用），活动时间相同时用于稳定淘汰排序。
	seq uint64
}

// SessionInfo 是面向用户的会话视图，不含敏感令牌信息。
type SessionInfo struct {
	ID             string     `json:"id"`
	Device         ClientInfo `json:"device"`
	CreatedAt      time.Time  `json:"created_at"`
	LastActivityAt time.Time  `json:"last_activity_at"`
	Current        bool       `json:"current"`
}

// StoreConfig 配置会话生命周期与每账号会话上限。
// 零值字段在归一化后回退为合理默认，老调用方无需提供任何新增信息。
type StoreConfig struct {
	// IdleTTL 普通会话的空闲到期时长（一段时间不活动即失效）。
	IdleTTL time.Duration
	// PersistentIdleTTL “保持长时间登录”会话的空闲到期时长；
	// <= 0 时回退为 IdleTTL。
	PersistentIdleTTL time.Duration
	// MaxLifetime 最长存活时长（从建立起算，不论多活跃一律失效）；
	// <= 0 表示不设最长存活上限。
	MaxLifetime time.Duration
	// MaxSessionsPerUser 同一账号的活跃会话数量上限；<= 0 表示不限制。
	MaxSessionsPerUser int
}

// Store 是并发安全的内存会话存储，支持空闲+绝对双到期、滑动续期、
// 多设备会话列举/撤销与每账号会话上限淘汰。
// 所有变更在同一把互斥锁内完成：并发 Touch 要么全部续期成功，
// 要么在撤销/过期后全部失败，不会出现部分请求被误判未登录或互相挤掉。
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	cfg      StoreConfig
	now      func() time.Time
	// seq 单调递增序号，用于在活动时间相同时稳定地选出“最久未活动”的会话。
	seq uint64
}

// NewStore 创建会话存储；ttl 为普通会话的滑动（空闲）过期时长。
// 不设置最长存活时长与每账号会话上限，保持与旧版本行为兼容。
func NewStore(ttl time.Duration) *Store {
	return NewStoreWithConfig(StoreConfig{IdleTTL: ttl})
}

// NewStoreWithConfig 使用完整生命周期配置创建会话存储。
func NewStoreWithConfig(cfg StoreConfig) *Store {
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 30 * time.Minute
	}
	if cfg.PersistentIdleTTL <= 0 {
		cfg.PersistentIdleTTL = cfg.IdleTTL
	}
	return &Store{sessions: make(map[string]*Session), cfg: cfg, now: time.Now}
}

func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Create 建立新会话（普通空闲时长、不携带设备信息）。
// 保留以兼容旧调用方；新代码应使用 CreateSession。
func (s *Store) Create(userID string, role Role) (*Session, error) {
	return s.CreateSession(CreateMeta{UserID: userID, Role: role})
}

// CreateMeta 描述一次新会话建立的输入。
type CreateMeta struct {
	UserID     string
	Role       Role
	Persistent bool
	Device     ClientInfo
}

// CreateSession 建立新会话。登录成功后调用：每次登录都生成全新会话 ID，
// 并撤销该用户请求中携带的旧会话（由调用方完成），从而防御会话固定攻击。
//
// 若该账号活跃会话数已达上限，则让“最久没有活动”的会话先让位；
// 新会话在淘汰发生之后才加入，因此并发登录也不会突破上限，
// 且刚建立的会话绝不会被本轮淘汰误伤。
func (s *Store) CreateSession(meta CreateMeta) (*Session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	// 所有时间戳都在持锁临界区内读取，与单调序号同时确定；
	// 否则并发下“锁外读时钟、锁后建会话”可能让后建立的会话拿到更早的时间戳，
	// 进而在淘汰时被误判为最久未活动。
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	idleTTL := s.cfg.IdleTTL
	if meta.Persistent {
		idleTTL = s.cfg.PersistentIdleTTL
	}
	sess := &Session{
		ID:                id,
		UserID:            meta.UserID,
		Role:              meta.Role,
		CreatedAt:         now,
		LastActivityAt:    now,
		ExpiresAt:         now.Add(idleTTL),
		Persistent:        meta.Persistent,
		Device:            meta.Device,
		AbsoluteExpiresAt: time.Time{},
	}
	if s.cfg.MaxLifetime > 0 {
		sess.AbsoluteExpiresAt = now.Add(s.cfg.MaxLifetime)
	}
	// 先按上限淘汰旧会话，再放入新会话：新会话永不参与本轮让位。
	if s.cfg.MaxSessionsPerUser > 0 {
		s.evictIfNeededLocked(meta.UserID)
	}
	s.seq++
	sess.seq = s.seq
	s.sessions[id] = sess
	cp := *sess
	return &cp, nil
}

// activeLocked 判断会话当前是否仍可使用（未撤销/淘汰，且两条到期线均未到）。
func (s *Store) activeLocked(sess *Session, now time.Time) bool {
	if sess.Revoked || sess.Evicted {
		return false
	}
	if !sess.AbsoluteExpiresAt.IsZero() && !now.Before(sess.AbsoluteExpiresAt) {
		return false
	}
	return now.Before(sess.ExpiresAt)
}

// evictIfNeededLocked 在活跃会话数超过上限时，反复淘汰最久未活动的会话，
// 直到为新会话腾出一个位置。计数只针对当前账号，其它账号的会话不占名额。
// 调用方必须持锁。
func (s *Store) evictIfNeededLocked(userID string) {
	now := s.now()
	for {
		count := 0
		var oldest *Session
		for _, sess := range s.sessions {
			if sess.UserID != userID || !s.activeLocked(sess, now) {
				continue
			}
			count++
			if oldest == nil || sessBefore(sess, oldest) {
				oldest = sess
			}
		}
		// 活跃会话数（不含即将加入的新会话）小于上限时无需再淘汰。
		if count < s.cfg.MaxSessionsPerUser {
			return
		}
		if oldest == nil {
			return
		}
		oldest.Evicted = true
	}
}

// sessBefore 判定 a 是否比 b 更久没有活动；活动时间相同则按建立序号，
// 保证并发登录下淘汰顺序确定。
func sessBefore(a, b *Session) bool {
	if !a.LastActivityAt.Equal(b.LastActivityAt) {
		return a.LastActivityAt.Before(b.LastActivityAt)
	}
	return a.seq < b.seq
}

// Touch 校验会话有效性并滑动续期。
// 两条到期线哪条先到按哪条算：内部以不同原因区分空闲到期与最长存活到期，
// 对外由上层统一为相同文案。续期只延长空闲到期线，绝不延长最长存活线。
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
	if sess.Evicted {
		return nil, reasonErr(ReasonSessionEvicted, "session evicted")
	}
	now := s.now()
	// 绝对到期先到则按绝对到期处理（即使此刻空闲线尚未到）。
	if !sess.AbsoluteExpiresAt.IsZero() && !now.Before(sess.AbsoluteExpiresAt) {
		delete(s.sessions, id)
		return nil, reasonErr(ReasonSessionAbsoluteExpired, "session reached max lifetime")
	}
	if !now.Before(sess.ExpiresAt) {
		delete(s.sessions, id)
		return nil, reasonErr(ReasonSessionExpired, "session idle expired")
	}
	idleTTL := s.cfg.IdleTTL
	if sess.Persistent {
		idleTTL = s.cfg.PersistentIdleTTL
	}
	sess.LastActivityAt = now
	sess.ExpiresAt = now.Add(idleTTL)
	// 注意：AbsoluteExpiresAt 不随滑动续期改变。
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

// RevokeUser 结束指定账号在所有设备上的会话（当前会话也包含在内），
// 立即全部失效；其它账号的会话不受影响。返回被结束的会话数。
func (s *Store) RevokeUser(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sess := range s.sessions {
		if sess.UserID == userID && !sess.Revoked && !sess.Evicted {
			sess.Revoked = true
			n++
		}
	}
	return n
}

// List 返回指定账号当前仍活跃的会话，按最近活动时间倒序（最新在前）。
// currentID 非空时把该会话标记为 current（调用方自己的当前会话）。
func (s *Store) List(userID, currentID string) []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]SessionInfo, 0)
	for _, sess := range s.sessions {
		if sess.UserID != userID || !s.activeLocked(sess, now) {
			continue
		}
		out = append(out, SessionInfo{
			ID:             sess.ID,
			Device:         sess.Device,
			CreatedAt:      sess.CreatedAt,
			LastActivityAt: sess.LastActivityAt,
			Current:        sess.ID == currentID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastActivityAt.Equal(out[j].LastActivityAt) {
			return out[i].LastActivityAt.After(out[j].LastActivityAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
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
