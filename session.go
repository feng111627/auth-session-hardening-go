package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ClientInfo 标识一条会话来自哪个客户端/设备，用于多设备会话列表展示。
// 所有字段均为可选：老客户端不带任何信息时为空值，会话照常建立。
type ClientInfo struct {
	// UserAgent 客户端原始 User-Agent。
	UserAgent string
	// IP 登录来源 IP（由服务端记录，不信任客户端自报）。
	IP string
	// Label 客户端可自报的可读设备名（如 "iPhone 15 / Safari"），仅用于展示。
	Label string
}

func (c ClientInfo) isZero() bool {
	return c.UserAgent == "" && c.IP == "" && c.Label == ""
}

// Session 表示一条登录会话。
type Session struct {
	ID     string
	UserID string
	Role   Role
	// Client 建立会话时的客户端/设备信息（老客户端为空）。
	Client       ClientInfo
	CreatedAt    time.Time
	LastActiveAt time.Time
	// ExpiresAt 为滑动空闲到期时间（不活动到期线），每次合法请求顺延，
	// 且不会晚于 AbsoluteExpiresAt；零值表示不设空闲上限。
	ExpiresAt time.Time
	// AbsoluteExpiresAt 为最长存活到期时间：自建立起固定不变，不随活动顺延；
	// 零值表示不设绝对上限（旧配置兼容）。
	AbsoluteExpiresAt time.Time
	// Persistent 表示登录时选择了“保持长时间登录”：空闲时长放宽，
	// 但最长存活时长（AbsoluteExpiresAt）不变。
	Persistent bool
	Revoked    bool
	// Evicted 表示该会话因同账号活跃会话达上限、作为最久未活动会话被让位。
	Evicted bool
	// seq 为建立序号，空闲时间并列时保证新建会话不被误淘汰（不对外暴露）。
	seq uint64
}

// StoreConfig 配置会话生命周期与多设备策略。零值字段在 NewStoreWithConfig 内归一化。
type StoreConfig struct {
	// IdleTTL 普通会话的滑动空闲时长；<=0 表示不限制空闲。
	IdleTTL time.Duration
	// PersistentIdleTTL “保持长时间登录”会话的空闲时长；<=0 时回退 IdleTTL。
	PersistentIdleTTL time.Duration
	// AbsoluteTTL 最长存活时长，对普通与长登录会话相同；<=0 表示不限制。
	AbsoluteTTL time.Duration
	// MaxSessionsPerUser 每账号活跃会话数量上限；<=0 表示不限制。
	MaxSessionsPerUser int
}

// Store 是并发安全的内存会话存储，支持双到期线（空闲/最长存活）、
// 滑动续期、多设备会话列举/撤销与每账号活跃会话上限淘汰。
// 所有变更在同一把互斥锁内完成：并发 Touch 要么全部续期成功，
// 要么在撤销/过期/淘汰后全部失败，不会出现部分请求被误判未登录或互相挤掉。
type Store struct {
	mu             sync.Mutex
	sessions       map[string]*Session
	idleTTL        time.Duration
	persistIdleTTL time.Duration
	absoluteTTL    time.Duration
	maxPerUser     int
	nextSeq        uint64
	now            func() time.Time
}

// NewStore 创建会话存储；ttl 为滑动空闲时长。
// 保持旧签名：不启用最长存活上限、长登录放宽与每账号会话上限，行为与旧版一致。
func NewStore(ttl time.Duration) *Store {
	return NewStoreWithConfig(StoreConfig{IdleTTL: ttl})
}

// NewStoreWithConfig 按完整配置创建会话存储。
func NewStoreWithConfig(cfg StoreConfig) *Store {
	idle := cfg.IdleTTL
	persist := cfg.PersistentIdleTTL
	if persist <= 0 {
		persist = idle
	}
	// 长登录只放宽空闲时间；若配置反而更短，则回退普通空闲时长，绝不收紧。
	if idle > 0 && persist > 0 && persist < idle {
		persist = idle
	}
	return &Store{
		sessions:       make(map[string]*Session),
		idleTTL:        idle,
		persistIdleTTL: persist,
		absoluteTTL:    cfg.AbsoluteTTL,
		maxPerUser:     cfg.MaxSessionsPerUser,
		now:            time.Now,
	}
}

func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Create 建立新会话（无设备信息、非长登录）。兼容旧调用方。
func (s *Store) Create(userID string, role Role) (*Session, error) {
	return s.CreateWithClient(userID, role, ClientInfo{}, false)
}

// CreateWithClient 建立新会话并记录客户端/设备信息。
// 登录成功后调用：每次登录都生成全新会话 ID，
// 并撤销该用户请求中携带的旧会话（由调用方完成），从而防御会话固定攻击。
//
// persistent 为“保持长时间登录”：空闲时长使用放宽值，最长存活时长不变。
// 若同账号活跃会话已达上限，立即让最久未活动的会话失效（新会话不受影响）。
//
// 并发安全要点：建立时间戳在锁内捕获，与淘汰序号同序——并发登录时锁的获取
// 顺序就是时间戳顺序，刚建立的会话 LastActiveAt 绝不早于任何已存在会话，
// 因此绝不会在本次上限处理中被当成“最久未活动”误淘汰（登录成功即可用）。
func (s *Store) CreateWithClient(userID string, role Role, client ClientInfo, persistent bool) (*Session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess := &Session{
		ID:           id,
		UserID:       userID,
		Role:         role,
		Client:       client,
		CreatedAt:    now,
		LastActiveAt: now,
		Persistent:   persistent,
	}
	// 空闲到期线：长登录使用放宽后的空闲时长。
	idle := s.idleTTL
	if persistent {
		idle = s.persistIdleTTL
	}
	if idle > 0 {
		sess.ExpiresAt = now.Add(idle)
	}
	// 最长存活到期线：所有会话一致，不随活动顺延。
	if s.absoluteTTL > 0 {
		sess.AbsoluteExpiresAt = now.Add(s.absoluteTTL)
		// 空闲线不得越过绝对线：哪条先到按哪条算。
		if sess.ExpiresAt.IsZero() || sess.ExpiresAt.After(sess.AbsoluteExpiresAt) {
			sess.ExpiresAt = sess.AbsoluteExpiresAt
		}
	}

	sess.seq = s.nextSeq
	s.nextSeq++
	s.sessions[id] = sess
	s.enforceMaxLocked(userID, now, sess.ID)
	cp := *sess
	return &cp, nil
}

// enforceMaxLocked 在锁内执行每账号活跃会话上限淘汰：
// 超过上限时让“最久未活动”的会话先让位；空闲时间并列时建立更早者让位。
// protectID 为刚建立的会话：双保险，任何情况下都不会被选为让位者，
// 保证“登录成功即可用”。由于建立时间戳与淘汰序号同序（见 CreateWithClient），
// 正常流程下它本就不会是最久未活动者。
func (s *Store) enforceMaxLocked(userID string, now time.Time, protectID string) {
	if s.maxPerUser <= 0 {
		return
	}
	var active []*Session
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.isActiveAt(now) {
			active = append(active, sess)
		}
	}
	for len(active) > s.maxPerUser {
		var victim *Session
		for _, cand := range active {
			if cand.ID == protectID {
				continue
			}
			if victim == nil ||
				cand.LastActiveAt.Before(victim.LastActiveAt) ||
				(cand.LastActiveAt.Equal(victim.LastActiveAt) && cand.seq < victim.seq) {
				victim = cand
			}
		}
		if victim == nil {
			// 仅剩受保护的刚建立会话：不淘汰，直接退出。
			break
		}
		victim.Evicted = true
		next := active[:0]
		for _, sess := range active {
			if sess != victim {
				next = append(next, sess)
			}
		}
		active = next
	}
}

// isActiveAt 判断会话在给定时刻是否仍可用（不含未知判断）。
func (sess *Session) isActiveAt(now time.Time) bool {
	if sess.Revoked || sess.Evicted {
		return false
	}
	if !sess.AbsoluteExpiresAt.IsZero() && !now.Before(sess.AbsoluteExpiresAt) {
		return false
	}
	if !sess.ExpiresAt.IsZero() && !now.Before(sess.ExpiresAt) {
		return false
	}
	return true
}

// Touch 校验会话有效性并滑动续期。
//
// 两条到期线同时生效，哪条先到按哪条算：超过空闲线返回 session_expired，
// 超过最长存活线返回 session_absolute_expired（两条同时到达时归为绝对到期）；
// 到期会话立即失效并从存储删除。续期只顺延空闲线，绝对线永不顺延。
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
	if sess.Evicted {
		return nil, reasonErr(ReasonSessionEvicted, "session evicted by concurrent login")
	}
	now := s.now()

	idleDeadline := sess.ExpiresAt
	absDeadline := sess.AbsoluteExpiresAt
	idleReached := !idleDeadline.IsZero() && !now.Before(idleDeadline)
	absReached := !absDeadline.IsZero() && !now.Before(absDeadline)
	switch {
	case absReached && (!idleReached || !idleDeadline.Before(absDeadline)):
		// 绝对线先到，或两条线同时到达：一律按最长存活到期处理。
		delete(s.sessions, id)
		return nil, reasonErr(ReasonSessionAbsoluteExpired, "session reached maximum lifetime")
	case idleReached:
		// 空闲线先到（绝对线尚未到，或空闲线确实更早）。
		delete(s.sessions, id)
		return nil, reasonErr(ReasonSessionExpired, "session expired due to inactivity")
	case absReached:
		delete(s.sessions, id)
		return nil, reasonErr(ReasonSessionAbsoluteExpired, "session reached maximum lifetime")
	}

	// 滑动续期：仅顺延空闲线，并受绝对线封顶。
	idle := s.idleTTL
	if sess.Persistent {
		idle = s.persistIdleTTL
	}
	if idle > 0 {
		sess.ExpiresAt = now.Add(idle)
	} else {
		sess.ExpiresAt = time.Time{}
	}
	if !sess.AbsoluteExpiresAt.IsZero() &&
		(sess.ExpiresAt.IsZero() || sess.ExpiresAt.After(sess.AbsoluteExpiresAt)) {
		sess.ExpiresAt = sess.AbsoluteExpiresAt
	}
	sess.LastActiveAt = now
	cp := *sess
	return &cp, nil
}

// Revoke 撤销单条会话，撤销后立即失效（后续 Touch 一律返回已撤销错误）。
func (s *Store) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.Revoked = true
	}
}

// RevokeUser 撤销某账号的会话，返回本次新撤销的、此前仍活跃的会话数。
// exceptID 非空时保留该会话（用于“下线其它设备”类场景）；为空则全部撤销，
// 包括调用者自己当前的会话。其它账号的会话不受影响。
func (s *Store) RevokeUser(userID, exceptID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, sess := range s.sessions {
		if sess.UserID != userID || sess.ID == exceptID {
			continue
		}
		// 先按撤销前状态统计此前仍活跃的数量，再置撤销标记。
		if !sess.Revoked && !sess.Evicted && sess.isActiveAt(now) {
			n++
		}
		sess.Revoked = true
	}
	return n
}

// ListActive 列举某账号当前仍活跃的会话（按最近活动时间倒序），
// 供多设备会话管理展示。已撤销、被淘汰、已到期（任一条线）的会话不出现。
func (s *Store) ListActive(userID string) []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []*Session
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.isActiveAt(now) {
			cp := *sess
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastActiveAt.Equal(out[j].LastActiveAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].LastActiveAt.After(out[j].LastActiveAt)
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
