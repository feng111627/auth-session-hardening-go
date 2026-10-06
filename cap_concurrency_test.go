package auth

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// 业务：会话上限（并发登录回归）—— 登录成功的会话绝不立即掉线，
// 最终存活的稳定为“最近建立”的那几条，被让位者立即失效。
//
// 回归背景：曾存在“刚登录成功马上就掉线”的偶发问题——并发登录把活跃会话
// 顶到上限时，新会话的建立时间戳在锁外捕获，与锁内淘汰序不一致，导致刚建立
// 的会话被当成“最久未活动”误淘汰。本用例以高并发、多轮运行稳定复现该场景。
func TestCapConcurrentLoginSurvivorsAreNewest(t *testing.T) {
	const (
		max    = 3  // 每账号活跃会话上限
		burst  = 16 // 每轮并发登录数，远超上限
		rounds = 40 // 多轮运行，覆盖不同的调度交错
	)
	for r := 0; r < rounds; r++ {
		store := NewStoreWithConfig(StoreConfig{
			IdleTTL:            time.Hour,
			MaxSessionsPerUser: max,
		})
		start := make(chan struct{}) // 发令枪：让所有 goroutine 同时涌入
		var wg sync.WaitGroup
		created := make(chan *Session, burst)
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				sess, err := store.CreateWithClient(
					"u1", RoleMember,
					ClientInfo{Label: fmt.Sprintf("第%d轮-设备%d", r, i)}, false)
				if err != nil {
					t.Errorf("第 %d 轮: 登录 %d 应成功: %v", r, i, err)
					return
				}
				created <- sess
			}(i)
		}
		close(start)
		wg.Wait()
		close(created)

		var all []*Session
		for sess := range created {
			all = append(all, sess)
		}
		if len(all) != burst {
			t.Fatalf("第 %d 轮: %d 个登录应全部成功，实际 %d", r, burst, len(all))
		}
		// 建立顺序以锁内淘汰序为准：最近建立的 max 条必须全部存活。
		sort.Slice(all, func(i, j int) bool { return all[i].seq > all[j].seq })
		wantAlive := map[string]bool{}
		for _, sess := range all[:max] {
			wantAlive[sess.ID] = true
		}

		active := store.ListActive("u1")
		if len(active) != max {
			t.Fatalf("第 %d 轮: 并发登录后活跃数必须恰好为上限 %d，实际 %d", r, max, len(active))
		}
		for _, sess := range active {
			if !wantAlive[sess.ID] {
				t.Fatalf("第 %d 轮: 更早建立的会话不应挤掉更晚建立的会话而存活: %+v", r, sess)
			}
		}
		// 最近建立的 max 条：登录成功后立即可用，绝不会被这次上限处理顶掉。
		for _, sess := range all[:max] {
			if _, err := store.Touch(sess.ID); err != nil {
				t.Fatalf("第 %d 轮: 刚登录成功的会话必须立即可用，实际 %v", r, err)
			}
		}
		// 其余会话：作为更久未活动者被让位，立即失效且原因可区分。
		for _, sess := range all[max:] {
			if _, err := store.Touch(sess.ID); ReasonOf(err) != ReasonSessionEvicted {
				t.Fatalf("第 %d 轮: 被让位会话应立即失效(session_evicted)，实际 %v", r, err)
			}
		}
	}
	t.Logf("用例通过: %d 轮 × %d 并发登录，每轮活跃数稳定为上限 %d，"+
		"最近建立的 %d 条全部存活且立即可用，被让位者立即失效",
		rounds, burst, max, max)
}

// 业务：会话上限（长登录会话）—— “保持长时间登录”只放宽空闲时间，
// 上限与淘汰规则不变：长登录会话作为最久未活动者一样让位。
func TestCapPersistentSessionStillEvicted(t *testing.T) {
	store := NewStoreWithConfig(StoreConfig{
		IdleTTL:            time.Minute,
		PersistentIdleTTL:  time.Hour,
		MaxSessionsPerUser: 2,
	})
	now := time.Now()
	store.now = func() time.Time { return now }

	old, err := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "长登录-旧"}, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !old.Persistent {
		t.Fatal("应为长登录会话")
	}
	// 间隔小于普通空闲时长，保证三条会话都活跃；长登录会话的空闲线远在 1 小时后，
	// 若它被让位，原因只能是“超上限按 LRU 淘汰”，与空闲到期无关。
	now = now.Add(30 * time.Second)
	s1, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "普通-1"}, false)
	now = now.Add(30 * time.Second)
	s2, _ := store.CreateWithClient("u1", RoleMember, ClientInfo{Label: "普通-2"}, false)

	// 长登录会话虽空闲放宽，但作为最久未活动者必须让位。
	if _, err := store.Touch(old.ID); ReasonOf(err) != ReasonSessionEvicted {
		t.Fatalf("长登录会话达上限时一样按 LRU 让位，实际 %v", err)
	}
	if _, err := store.Touch(s1.ID); err != nil {
		t.Fatalf("普通会话 s1 不应受影响: %v", err)
	}
	if _, err := store.Touch(s2.ID); err != nil {
		t.Fatalf("普通会话 s2 不应受影响: %v", err)
	}
	if got := len(store.ListActive("u1")); got != 2 {
		t.Fatalf("活跃数不得突破上限 2，实际 %d", got)
	}
	t.Log("用例通过: 长登录只放宽空闲时间，上限与 LRU 淘汰规则不变")
}
