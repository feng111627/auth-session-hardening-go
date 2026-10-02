package auth

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// 业务：会话上限 —— 超过上限时最久未活动的会话先让位
func TestCapEvictsOldestIdle(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Hour,
		MaxSessionsPerUser: 3,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	s1 := createDeviceSession(t, store, "u1", "dev-1")
	now = now.Add(time.Minute)
	s2 := createDeviceSession(t, store, "u1", "dev-2")
	now = now.Add(time.Minute)
	s3 := createDeviceSession(t, store, "u1", "dev-3")
	// 让 s2 成为最近有活动的会话，s1 最久未活动。
	now = now.Add(time.Minute)
	if _, err := store.Touch(s2.ID); err != nil {
		t.Fatalf("touch s2: %v", err)
	}
	now = now.Add(time.Minute)
	s4 := createDeviceSession(t, store, "u1", "dev-4") // 触发淘汰

	// 最久未活动的 s1 让位。
	if _, err := store.Touch(s1.ID); ReasonOf(err) != ReasonSessionEvicted {
		t.Fatalf("最久未活动的 s1 应被让位(%s), got %v", ReasonSessionEvicted, err)
	}
	for _, id := range []string{s2.ID, s3.ID, s4.ID} {
		if _, err := store.Touch(id); err != nil {
			t.Fatalf("其余会话应继续可用, %s: %v", id, err)
		}
	}
	if list := store.List("u1", ""); len(list) != 3 {
		t.Fatalf("淘汰后活跃会话数应维持上限 3, got %d", len(list))
	}
	t.Log("用例通过: 上限 3，第 4 条登录时最久未活动的 s1 立即失效(session_evicted)，其余 3 条继续可用")
}

// 业务：会话上限 —— 淘汰只作用于同账号，不波及其它账号
func TestCapIsolatedPerUser(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Hour,
		MaxSessionsPerUser: 2,
	})
	a1 := createDeviceSession(t, store, "u1", "a-1")
	a2 := createDeviceSession(t, store, "u1", "a-2")
	b1 := createDeviceSession(t, store, "u2", "b-1")
	b2 := createDeviceSession(t, store, "u2", "b-2")
	createDeviceSession(t, store, "u1", "a-3") // 仅淘汰 u1 的一条

	if _, err := store.Touch(a1.ID); ReasonOf(err) != ReasonSessionEvicted {
		t.Fatalf("a1 应被同账号新会话挤掉, got %v", err)
	}
	if _, err := store.Touch(a2.ID); err != nil {
		t.Fatalf("a2 应继续可用: %v", err)
	}
	for _, id := range []string{b1.ID, b2.ID} {
		if _, err := store.Touch(id); err != nil {
			t.Fatalf("u2 会话不应受 u1 淘汰影响: %v", err)
		}
	}
	t.Log("用例通过: 上限按账号独立计算，u1 的让位不影响 u2 的会话")
}

// 业务：会话上限 —— 已失效/已撤销的会话不计入名额
func TestCapExcludesInactive(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Hour,
		MaxSessionsPerUser: 2,
	})
	s1 := createDeviceSession(t, store, "u1", "dev-1")
	s2 := createDeviceSession(t, store, "u1", "dev-2")
	store.Revoke(s1.ID) // 主动登出，腾出名额

	s3 := createDeviceSession(t, store, "u1", "dev-3")
	if _, err := store.Touch(s2.ID); err != nil {
		t.Fatalf("s2 不应被淘汰（s1 已撤销不应占名额）: %v", err)
	}
	if _, err := store.Touch(s3.ID); err != nil {
		t.Fatalf("新会话 s3 应可用: %v", err)
	}
	t.Log("用例通过: 已撤销会话不占用上限名额，新登录不再误淘汰活跃会话")
}

// 业务：会话上限 —— 并发登录不突破上限，也不误伤刚建立的会话
func TestCapConcurrentLogins(t *testing.T) {
	const limit = 5
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Hour,
		MaxSessionsPerUser: limit,
	})

	const n = 40
	var wg sync.WaitGroup
	created := make(chan *Session, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := store.CreateSession(CreateMeta{UserID: "u1", Role: RoleMember})
			if err != nil {
				t.Errorf("create session: %v", err)
				return
			}
			created <- sess
		}()
	}
	wg.Wait()
	close(created)

	all := make([]*Session, 0, n)
	for sess := range created {
		all = append(all, sess)
	}
	list := store.List("u1", "")
	if len(list) != limit {
		t.Fatalf("并发登录后活跃会话数必须恰好为上限 %d, got %d", limit, len(list))
	}

	// 存活集合必须恰好等于“最后建立的 limit 条”：以存储内单调序号判定真实建立顺序，
	// 新会话永不被自己这轮淘汰误伤，被淘汰的只能是更早建立的会话。
	sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
	alive := map[string]bool{}
	for _, info := range list {
		alive[info.ID] = true
	}
	survivors := all[len(all)-limit:]
	for _, sess := range survivors {
		if !alive[sess.ID] {
			t.Fatalf("后建立的会话（seq=%d）不应被淘汰（不能误伤刚建立的会话）", sess.seq)
		}
	}
	// 每个新建立的会话在建立当刻都必须是可成功建立的；最终状态要么存活，
	// 要么以 session_evicted 让位（不是 unknown——说明它曾真实存在过）。
	evicted := 0
	for _, sess := range all {
		_, err := store.Touch(sess.ID)
		switch ReasonOf(err) {
		case "":
		case ReasonSessionEvicted:
			evicted++
		default:
			t.Fatalf("会话 seq=%d 的非预期状态: %v", sess.seq, err)
		}
	}
	if evicted != n-limit {
		t.Fatalf("应有 %d 条被让位, got %d", n-limit, evicted)
	}
	t.Logf("用例通过: %d 个并发登录后活跃会话恰好 %d 条（不突破上限），后建立的 %d 条全部存活（不误伤新会话），其余 %d 条以 session_evicted 立即失效",
		n, limit, limit, n-limit)
}
