package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 业务：会话双到期线 —— 空闲线先到，按空闲到期处理
func TestLifecycleIdleExpiryFirst(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:     30 * time.Second,
		AbsoluteTTL: 10 * time.Minute,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, err := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "手机"}, false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// 空闲 30s，最长存活 10min；不活动 31s：空闲线先到。
	now = now.Add(31 * time.Second)
	_, err = store.Touch(sess.ID)
	if ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("空闲线先到应返回 session_expired，实际 %v", err)
	}
	t.Log("用例通过: 不活动超过空闲时长立即失效，原因 session_expired；绝对线尚未到")
}

// 业务：会话双到期线 —— 绝对线先到（持续活跃也不能续命超过最长存活）
func TestLifecycleAbsoluteExpiryFirst(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:     5 * time.Minute,
		AbsoluteTTL: 2 * time.Minute,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "PC"}, false)
	// 每分钟活跃一次：空闲线（5min）永远不会先到，但到第 2 分钟必须按最长存活失效。
	now = now.Add(1 * time.Minute)
	if _, err := store.Touch(sess.ID); err != nil {
		t.Fatalf("第 1 分钟仍活跃应可续期: %v", err)
	}
	now = now.Add(1 * time.Minute)
	_, err := store.Touch(sess.ID)
	if ReasonOf(err) != ReasonSessionAbsoluteExpired {
		t.Fatalf("到达最长存活应返回 session_absolute_expired，实际 %v", err)
	}
	t.Log("用例通过: 持续活跃下到达最长存活时长仍立即失效，原因 session_absolute_expired")
}

// 业务：会话双到期线 —— 两条线同时到达时归为绝对到期，且不再可用
func TestLifecycleBothDeadlinesTogether(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:     2 * time.Minute,
		AbsoluteTTL: 2 * time.Minute,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.Create("u1", RoleMember)
	now = now.Add(2 * time.Minute)
	_, err := store.Touch(sess.ID)
	if ReasonOf(err) != ReasonSessionAbsoluteExpired {
		t.Fatalf("双线同时到期应归为 session_absolute_expired，实际 %v", err)
	}
	if _, ok := store.Get(sess.ID); ok {
		t.Fatal("到期会话应立即从存储删除")
	}
	t.Log("用例通过: 两条到期线同时到达，按绝对到期处理并立即删除")
}

// 业务：长登录会话 —— 空闲放宽但最长存活不变
func TestLifecyclePersistentRelaxesIdleOnly(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:           1 * time.Minute,
		PersistentIdleTTL: 10 * time.Minute,
		AbsoluteTTL:       30 * time.Minute,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	persistent, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "个人手机"}, true)
	normal, _ := store.CreateWithClient("u2", RoleMember, ClientInfo{Label: "网吧电脑"}, false)

	// 2 分钟不活动：普通会话已因空闲失效，长登录会话仍可用。
	now = now.Add(2 * time.Minute)
	if _, err := store.Touch(normal.ID); ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("普通会话应空闲到期，实际 %v", err)
	}
	if _, err := store.Touch(persistent.ID); err != nil {
		t.Fatalf("长登录会话空闲放宽后 2 分钟应仍有效: %v", err)
	}
	t.Log("用例通过: 不活动 2 分钟时普通会话失效、长登录会话仍可用")

	// 长登录不能突破最长存活：持续活跃使空闲线不断顺延，
	// 但到第 30 分钟仍必须按最长存活一律失效。
	for i := 0; i < 27; i++ {
		now = now.Add(time.Minute)
		if _, err := store.Touch(persistent.ID); err != nil {
			t.Fatalf("长登录持续活跃第 %d 分钟应仍有效: %v", i+2, err)
		}
	}
	now = now.Add(time.Minute) // 第 30 分钟
	_, err := store.Touch(persistent.ID)
	if ReasonOf(err) != ReasonSessionAbsoluteExpired {
		t.Fatalf("长登录到达最长存活也应失效，实际 %v", err)
	}
	t.Log("用例通过: 长登录会话空闲虽放宽，最长存活 30 分钟一到仍立即失效")
}

// 业务：长登录缺省 —— 老客户端不带 persistent 时按普通会话处理
func TestLifecyclePersistentDefaultsFalse(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:           1 * time.Minute,
		PersistentIdleTTL: 10 * time.Minute,
		AbsoluteTTL:       time.Hour,
	})
	sess, _ := store.Create("u1", RoleMember) // 旧入口：非长登录、无设备信息
	if sess.Persistent || !sess.Client.isZero() {
		t.Fatal("旧 Create 入口必须等价于非长登录、零设备信息")
	}
	if !sess.AbsoluteExpiresAt.Equal(sess.CreatedAt.Add(time.Hour)) {
		t.Fatal("最长存活时间应自建立起固定")
	}
	t.Log("用例通过: 老客户端缺省按普通会话处理，最长存活仍生效")
}

// 业务：多设备会话 —— 列举区分设备、展示登录与最近活动时间、按活动倒序
func TestDevicesListSessions(t *testing.T) {
	store := NewStore(30 * time.Minute)
	now := time.Now()
	store.now = func() time.Time { return now }

	s1, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "iPhone", UserAgent: "iOS Safari", IP: "1.1.1.1"}, false)
	now = now.Add(time.Minute)
	s2, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "MacBook", UserAgent: "macOS Chrome", IP: "2.2.2.2"}, false)
	now = now.Add(time.Minute)
	s3, _ := store.CreateWithClient("u2", RoleMember, ClientInfo{Label: "另一账号设备"}, false)

	list := store.ListActive("u1")
	if len(list) != 2 {
		t.Fatalf("u1 应有 2 条活跃会话，实际 %d", len(list))
	}
	// 最近活动倒序：s2 新于 s1。
	if list[0].ID != s2.ID || list[1].ID != s1.ID {
		t.Fatal("会话列表应按最近活动时间倒序")
	}
	if list[0].Client.Label != "MacBook" || list[0].Client.IP != "2.2.2.2" {
		t.Fatalf("设备信息应可区分: %+v", list[0].Client)
	}
	if !list[1].LastActiveAt.Equal(s1.CreatedAt) {
		t.Fatalf("最近活动时间应等于建立时间（未活动过）: login=%s last=%s",
			s1.CreatedAt, list[1].LastActiveAt)
	}
	// s1 活跃一次后应排到最前。
	now = now.Add(time.Minute)
	if _, err := store.Touch(s1.ID); err != nil {
		t.Fatalf("touch s1: %v", err)
	}
	list = store.ListActive("u1")
	if list[0].ID != s1.ID {
		t.Fatal("s1 活动后应排到列表最前")
	}
	// 其它账号会话绝不出现在列表里。
	for _, sess := range list {
		if sess.ID == s3.ID {
			t.Fatal("列表不得包含其它账号的会话")
		}
	}
	t.Log("用例通过: 多设备会话可区分设备与时间，按最近活动倒序，且账号间隔离")
}

// 业务：多设备会话 —— 单条结束立即失效，其余设备不受影响
func TestDevicesRevokeSingle(t *testing.T) {
	store := NewStore(30 * time.Minute)
	s1, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "设备A"}, false)
	s2, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "设备B"}, false)
	s3, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "设备C"}, false)

	store.Revoke(s2.ID)
	if _, err := store.Touch(s2.ID); ReasonOf(err) != ReasonSessionRevoked {
		t.Fatalf("被结束的会话应立即失效: %v", err)
	}
	if _, err := store.Touch(s1.ID); err != nil {
		t.Fatalf("设备A 不应受影响: %v", err)
	}
	if _, err := store.Touch(s3.ID); err != nil {
		t.Fatalf("设备C 不应受影响: %v", err)
	}
	if got := len(store.ListActive("u1")); got != 2 {
		t.Fatalf("结束一条后应剩 2 条活跃，实际 %d", got)
	}
	t.Log("用例通过: 单独结束设备B后其立即失效，设备A/C 继续可用")
}

// 业务：多设备会话 —— 一次结束全部，当前会话也失效，其它账号不受影响
func TestDevicesRevokeAll(t *testing.T) {
	store := NewStore(30 * time.Minute)
	a1, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "u1-1"}, false)
	a2, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "u1-2"}, false)
	b1, _ := store.CreateWithClient("u2", RoleMember, ClientInfo{Label: "u2-1"}, false)

	n := store.RevokeUser("u1", "")
	if n != 2 {
		t.Fatalf("应结束 u1 的 2 条会话，实际 %d", n)
	}
	for _, sess := range []*Session{a1, a2} {
		if _, err := store.Touch(sess.ID); ReasonOf(err) != ReasonSessionRevoked {
			t.Fatalf("u1 会话应全部撤销，实际 %v", err)
		}
	}
	if _, err := store.Touch(b1.ID); err != nil {
		t.Fatalf("其它账号会话不应受影响: %v", err)
	}
	t.Log("用例通过: 结束全部时 u1 两条会话立即失效，u2 会话不受影响")
}

// 业务：多设备会话 —— “下线其它设备”保留指定会话
func TestDevicesRevokeOthersExceptCurrent(t *testing.T) {
	store := NewStore(30 * time.Minute)
	cur, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "当前设备"}, false)
	other, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "其它设备"}, false)

	if n := store.RevokeUser("u1", cur.ID); n != 1 {
		t.Fatalf("应仅结束 1 条其它会话，实际 %d", n)
	}
	if _, err := store.Touch(cur.ID); err != nil {
		t.Fatalf("当前会话应保留: %v", err)
	}
	if _, err := store.Touch(other.ID); ReasonOf(err) != ReasonSessionRevoked {
		t.Fatalf("其它设备应被结束: %v", err)
	}
	t.Log("用例通过: 可保留下令者当前会话、仅结束其它设备")
}

// 业务：会话上限 —— 超过上限时最久未活动者让位，新会话不受影响
func TestCapEvictsLeastRecentlyActive(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Hour,
		MaxSessionsPerUser: 2,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	s1, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "最早"}, false)
	now = now.Add(time.Minute)
	s2, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "其次"}, false)
	now = now.Add(time.Minute)
	s1t, _ := store.Touch(s1.ID) // s1 变为最近活跃
	_ = s1t
	now = now.Add(time.Minute)
	s3, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "新设备"}, false)

	if _, err := store.Touch(s2.ID); ReasonOf(err) != ReasonSessionEvicted {
		t.Fatalf("最久未活动的 s2 应被让位: %v", err)
	}
	if _, err := store.Touch(s1.ID); err != nil {
		t.Fatalf("刚活跃过的 s1 不应被淘汰: %v", err)
	}
	if _, err := store.Touch(s3.ID); err != nil {
		t.Fatalf("刚建立的 s3 绝不应被误伤: %v", err)
	}
	if got := len(store.ListActive("u1")); got != 2 {
		t.Fatalf("活跃会话数不得突破上限，实际 %d", got)
	}
	t.Log("用例通过: 超上限时淘汰最久未活动会话，新会话与刚活跃会话均保留")
}

// 业务：会话上限 —— 淘汰立即生效、账号间互不影响、过期会话不占名额
func TestCapIsolationAndExpiredDoNotCount(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Minute,
		MaxSessionsPerUser: 2,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	old, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "u1-old"}, false)
	now = now.Add(2 * time.Minute) // old 已空闲到期，不再占名额
	s1, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "u1-a"}, false)
	s2, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "u1-b"}, false)
	if _, err := store.Touch(old.ID); ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("已过期会话应报过期: %v", err)
	}
	if got := len(store.ListActive("u1")); got != 2 {
		t.Fatalf("过期会话不应占名额，u1 活跃数应为 2，实际 %d", got)
	}
	if _, err := store.Touch(s1.ID); err != nil {
		t.Fatalf("u1-a 不应被过期会话挤掉: %v", err)
	}
	if _, err := store.Touch(s2.ID); err != nil {
		t.Fatalf("u1-b 不应被过期会话挤掉: %v", err)
	}

	// u2 拥有独立名额：u1 达上限不影响 u2 建立同数会话。
	v1, _ := store.CreateWithClient("u2", RoleMember, ClientInfo{Label: "u2-a"}, false)
	v2, _ := store.CreateWithClient("u2", RoleMember, ClientInfo{Label: "u2-b"}, false)
	if _, err := store.Touch(v1.ID); err != nil {
		t.Fatalf("u2-a 应不受 u1 上限影响: %v", err)
	}
	if _, err := store.Touch(v2.ID); err != nil {
		t.Fatalf("u2-b 应不受 u1 上限影响: %v", err)
	}
	t.Log("用例通过: 过期会话不占上限名额，淘汰仅作用于同账号")
}

// 业务：会话上限 —— 并发登录不突破上限、不误伤刚建立的会话
func TestCapConcurrentLogins(t *testing.T) {
	const max = 3
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Hour,
		MaxSessionsPerUser: max,
	})

	const n = 30
	var wg sync.WaitGroup
	created := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess, err := store.CreateWithClient(
				"u1", RoleMember,
				ClientInfo{Label: fmt.Sprintf("并发设备-%d", i)}, false)
			if err != nil {
				t.Errorf("create %d: %v", i, err)
				return
			}
			created <- sess.ID
		}(i)
	}
	wg.Wait()
	close(created)

	active := store.ListActive("u1")
	if len(active) != max {
		t.Fatalf("并发登录后活跃会话必须恰好为上限 %d，实际 %d", max, len(active))
	}
	// 最后完成建立的若干新会话：取一个仍在活跃集合中的新会话做 Touch，必须可用。
	if _, err := store.Touch(active[0].ID); err != nil {
		t.Fatalf("幸存的新会话应立即可用，实际 %v", err)
	}
	// 所有被淘汰的会话立即失效，且不影响幸存会话。
	activeSet := map[string]bool{}
	for _, sess := range active {
		activeSet[sess.ID] = true
	}
	for id := range created {
		if activeSet[id] {
			continue
		}
		if _, err := store.Touch(id); ReasonOf(err) != ReasonSessionEvicted {
			t.Fatalf("被让位会话应返回 session_evicted，实际 %v", err)
		}
	}
	if got := len(store.ListActive("u1")); got != max {
		t.Fatalf("淘汰后再校验活跃数仍应为 %d，实际 %d", max, got)
	}
	t.Logf("用例通过: %d 个并发登录后活跃数恰好 %d，被让位者立即失效、新会话不受误伤", n, max)
}
