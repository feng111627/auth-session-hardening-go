package auth

import (
	"testing"
	"time"
)

// 业务：双到期线 —— 空闲到期先到，按空闲到期失效（即使持续活跃不到最长存活）
func TestLifecycleIdleExpiryFirst(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:     10 * time.Minute,
		MaxLifetime: time.Hour,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.CreateSession(CreateMeta{UserID: "u1", Role: RoleMember})

	// 持续活动 40 分钟（每 5 分钟一次）：空闲线一直被滑动，最长存活线（60 分钟）尚未到。
	for i := 0; i < 8; i++ {
		now = now.Add(5 * time.Minute)
		if _, err := store.Touch(sess.ID); err != nil {
			t.Fatalf("active touch %d should succeed: %v", i, err)
		}
	}
	// 之后停止活动 11 分钟：t=51，空闲到期（50）先到，最长存活（60）未到。
	now = now.Add(11 * time.Minute)
	_, err := store.Touch(sess.ID)
	if ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("空闲到期先到应返回 %q, got %v", ReasonSessionExpired, err)
	}
	t.Log("用例通过: 持续活跃不触达最长存活；一旦停止活动超过空闲时长，立即按 session_expired 失效")
}

// 业务：双到期线 —— 最长存活先到，再活跃也立即失效
func TestLifecycleAbsoluteExpiryFirst(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:     10 * time.Minute,
		MaxLifetime: time.Hour,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.CreateSession(CreateMeta{UserID: "u1", Role: RoleMember})

	// 每 5 分钟活动一次，始终远在空闲线之内；走到第 60 分钟那一刻：
	// 最长存活已到，哪怕刚刚还活跃也必须立即失效，且会话被清除。
	for i := 1; i <= 12; i++ {
		now = now.Add(5 * time.Minute)
		_, err := store.Touch(sess.ID)
		if i < 12 {
			if err != nil {
				t.Fatalf("touch at %dm before max lifetime should succeed: %v", i*5, err)
			}
			continue
		}
		if ReasonOf(err) != ReasonSessionAbsoluteExpired {
			t.Fatalf("达到最长存活应返回 %q, got %v", ReasonSessionAbsoluteExpired, err)
		}
	}
	if _, ok := store.Get(sess.ID); ok {
		t.Fatal("最长存活到期后会话应被清除")
	}
	t.Log("用例通过: 达到最长存活时长（60 分钟）时立即失效，原因 session_absolute_expired；滑动续期未能延长绝对到期线")
}

// 业务：保持长时间登录 —— 空闲时长放宽，但最长存活不变
func TestLifecyclePersistentRelaxedIdleButFixedMaxLifetime(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:           10 * time.Minute,
		PersistentIdleTTL: time.Hour,
		MaxLifetime:       3 * time.Hour,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	persistent, _ := store.CreateSession(CreateMeta{UserID: "u1", Role: RoleMember, Persistent: true})
	normal, _ := store.CreateSession(CreateMeta{UserID: "u2", Role: RoleMember})

	// 30 分钟不活动：普通会话空闲已过期，保持登录会话仍有效。
	now = now.Add(30 * time.Minute)
	if _, err := store.Touch(normal.ID); ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("普通会话 30 分钟不活动应空闲过期, got %v", err)
	}
	if _, err := store.Touch(persistent.ID); err != nil {
		t.Fatalf("保持登录会话 30 分钟不活动仍应有效, got %v", err)
	}
	t.Log("用例通过: 30 分钟不活动，普通会话失效而保持登录会话仍可用（空闲线放宽到 1 小时）")

	// 保持登录会话继续活跃到超过最长存活 3 小时，仍一律失效。
	steps := 0
	for {
		now = now.Add(30 * time.Minute)
		_, err := store.Touch(persistent.ID)
		if err != nil {
			if ReasonOf(err) != ReasonSessionAbsoluteExpired {
				t.Fatalf("保持登录会话达到最长存活应返回 %q, got %v", ReasonSessionAbsoluteExpired, err)
			}
			break
		}
		steps++
		if steps > 20 {
			t.Fatal("保持登录会话未在最长存活处失效")
		}
	}
	t.Log("用例通过: 保持登录不改变最长存活时长（3 小时），到期立即按 session_absolute_expired 失效")
}

// 业务：到期检查的边界 —— 恰好在到期时刻不可用
func TestLifecycleExactBoundary(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{IdleTTL: 10 * time.Minute, MaxLifetime: time.Hour})
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.CreateSession(CreateMeta{UserID: "u1", Role: RoleMember})
	created := sess.CreatedAt

	now = created.Add(10 * time.Minute) // 恰好等于空闲到期时刻
	if _, err := store.Touch(sess.ID); ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("空闲到期时刻应失效, got %v", err)
	}
	t.Log("用例通过: 恰好在空闲到期时刻（now == expiresAt）即不可用")
}
