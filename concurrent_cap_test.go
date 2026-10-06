package auth

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sortSessionsBySeqDesc(in []*Session) {
	sort.Slice(in, func(i, j int) bool { return in[i].seq > in[j].seq })
}

// burstClock 在登录潮期间每次调用都严格推进时钟，压出
// “锁外取样、锁内建会话”的时间戳错序窗口；freeze 后冻结在结尾时刻，
// 使登录潮结束后的 Touch 不再改变淘汰次序，只反映最终结果。
func burstClock(base time.Time) (clock func() time.Time, freeze func()) {
	var ticks atomic.Int64
	var frozen atomic.Bool
	var end atomic.Value
	clock = func() time.Time {
		if frozen.Load() {
			return end.Load().(time.Time)
		}
		return base.Add(time.Duration(ticks.Add(1)) * time.Nanosecond)
	}
	freeze = func() {
		end.Store(base.Add(time.Duration(ticks.Load()+1) * time.Nanosecond))
		frozen.Store(true)
	}
	return clock, freeze
}

// 并发登录结果：按 goroutine 发起顺序记录返回的会话。
type burstResult struct {
	sess *Session
	err  error
}

func runBurst(t *testing.T, store *Store, userID string, n int, persistent bool, label string) []burstResult {
	t.Helper()
	results := make([]burstResult, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			sess, err := store.CreateWithClient(
				userID, RoleMember,
				ClientInfo{Label: fmt.Sprintf("%s-%d", label, i)}, persistent)
			results[i] = burstResult{sess: sess, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	return results
}

// 业务：并发登录下的会话上限与淘汰
//
// 覆盖用例：
//  1. 上限严格生效：高并发多轮后活跃数恒等于上限；
//  2. 登录成功即立即可用：刚建立的会话不会被自己这次上限处理顶掉；
//  3. 最终存活稳定为最近建立的若干条；
//  4. 被让位会话立即返回 session_evicted，不影响其它会话；
//  5. 长登录会话同样受上限与 LRU 约束（放宽的只是空闲时间）。
func TestConcurrentCapBurst(t *testing.T) {
	const max, n, rounds = 3, 64, 10

	t.Run("普通会话-活跃数恒等于上限且幸存集合稳定为最近建立", func(t *testing.T) {
		for r := 0; r < rounds; r++ {
			store := NewStoreWithConfig(StoreConfig{
				IdleTTL:            time.Hour,
				MaxSessionsPerUser: max,
			})
			clock, freeze := burstClock(time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC))
			store.now = clock

			results := runBurst(t, store, "u1", n, false, "设备")
			for _, res := range results {
				if res.err != nil {
					t.Fatalf("第 %d 轮登录不应失败: %v", r+1, res.err)
				}
			}
			freeze()

			active := store.ListActive("u1")
			if len(active) != max {
				t.Fatalf("第 %d 轮活跃数应为上限 %d，实际 %d", r+1, max, len(active))
			}
			survivors := map[string]bool{}
			for _, sess := range active {
				survivors[sess.ID] = true
			}

			// 最近建立（seq 最大）的 max 条必须全部存活，且可立即使用。
			created := make([]*Session, 0, n)
			for _, res := range results {
				created = append(created, res.sess)
			}
			sortSessionsBySeqDesc(created)
			for _, sess := range created[:max] {
				if !survivors[sess.ID] {
					t.Fatalf("第 %d 轮：最近建立的会话(序号=%d)应存活，实际被淘汰",
						r+1, sess.seq)
				}
				if _, err := store.Touch(sess.ID); err != nil {
					t.Fatalf("第 %d 轮：幸存会话(序号=%d)应立即可用，实际 %v",
						r+1, sess.seq, err)
				}
			}

			// 其余会话一律立即 session_evicted；幸存会话不受牵连。
			evicted := 0
			for _, sess := range created[max:] {
				if _, err := store.Touch(sess.ID); ReasonOf(err) != ReasonSessionEvicted {
					t.Fatalf("第 %d 轮：被让位会话(序号=%d)应返回 session_evicted，实际 %v",
						r+1, sess.seq, err)
				}
				evicted++
			}
			if got := len(store.ListActive("u1")); got != max {
				t.Fatalf("第 %d 轮校验后活跃数仍应为 %d，实际 %d", r+1, max, got)
			}
			if r == 0 {
				t.Logf("用例进展: 第 1 轮 %d 并发登录，%d 条让位、%d 条存活且立即可用",
					n, evicted, max)
			}
		}
		t.Logf("用例通过: %d 轮 x %d 并发登录，活跃数恒为 %d，幸存集合稳定为最后建立的 %d 条",
			rounds, n, max, max)
	})

	t.Run("长登录会话-放宽空闲但不改变上限与淘汰规则", func(t *testing.T) {
		for r := 0; r < rounds; r++ {
			store := NewStoreWithConfig(StoreConfig{
				IdleTTL:            time.Minute,
				PersistentIdleTTL:  30 * time.Minute,
				AbsoluteTTL:        time.Hour,
				MaxSessionsPerUser: max,
			})
			clock, freeze := burstClock(time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC))
			store.now = clock

			results := runBurst(t, store, "u1", n, true, "长登录设备")
			freeze()

			active := store.ListActive("u1")
			if len(active) != max {
				t.Fatalf("第 %d 轮长登录活跃数应为 %d，实际 %d", r+1, max, len(active))
			}
			created := make([]*Session, 0, n)
			for _, res := range results {
				if !res.sess.Persistent {
					t.Fatal("长登录标记必须保留")
				}
				created = append(created, res.sess)
			}
			sortSessionsBySeqDesc(created)
			survivors := map[string]bool{}
			for _, sess := range active {
				survivors[sess.ID] = true
			}
			for _, sess := range created[:max] {
				if !survivors[sess.ID] {
					t.Fatalf("第 %d 轮：最近建立的长登录会话(序号=%d)应存活", r+1, sess.seq)
				}
				got, err := store.Touch(sess.ID)
				if err != nil {
					t.Fatalf("第 %d 轮：幸存长登录会话应立即可用: %v", r+1, err)
				}
				// 空闲线应按放宽时长计算。
				if !got.ExpiresAt.Equal(got.LastActiveAt.Add(30 * time.Minute)) {
					t.Fatalf("长登录空闲线应放宽至 30min，实际 expires=%s active=%s",
						got.ExpiresAt, got.LastActiveAt)
				}
			}
			for _, sess := range created[max:] {
				if _, err := store.Touch(sess.ID); ReasonOf(err) != ReasonSessionEvicted {
					t.Fatalf("第 %d 轮：被让位长登录会话应 session_evicted，实际 %v", r+1, err)
				}
			}
		}
		t.Logf("用例通过: %d 轮 x %d 并发长登录，上限仍是 %d、淘汰仍是最久未活动，空闲放宽至 30min",
			rounds, n, max)
	})

	t.Run("已有活跃会话被登录潮顶掉-最久未活动者让位、新会话全部存活", func(t *testing.T) {
		// 预置 max 条同刻会话（模拟顶满上限），随后并发涌入更多登录。
		for r := 0; r < rounds; r++ {
			store := NewStoreWithConfig(StoreConfig{
				IdleTTL:            time.Hour,
				MaxSessionsPerUser: max,
			})
			base := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
			var now atomic.Value
			now.Store(base)
			store.now = func() time.Time { return now.Load().(time.Time) }

			old := make([]*Session, max)
			for i := range old {
				old[i], _ = store.CreateWithClient("u1", RoleMember,
					ClientInfo{Label: fmt.Sprintf("既有-%d", i)}, false)
			}

			// 登录潮：时钟推进，每条新会话比既有会话更新。
			clock, freeze := burstClock(base.Add(time.Minute))
			store.now = clock
			results := runBurst(t, store, "u1", n, false, "新设备")
			freeze()

			for i, sess := range old {
				if _, err := store.Touch(sess.ID); ReasonOf(err) != ReasonSessionEvicted {
					t.Fatalf("第 %d 轮：既有会话 %d 应让位(session_evicted)，实际 %v",
						r+1, i, err)
				}
			}
			created := make([]*Session, 0, n)
			for _, res := range results {
				created = append(created, res.sess)
			}
			sortSessionsBySeqDesc(created)
			active := store.ListActive("u1")
			if len(active) != max {
				t.Fatalf("第 %d 轮活跃数应为 %d，实际 %d", r+1, max, len(active))
			}
			survivors := map[string]bool{}
			for _, sess := range active {
				survivors[sess.ID] = true
			}
			for _, sess := range created[:max] {
				if !survivors[sess.ID] {
					t.Fatalf("第 %d 轮：最近建立的新会话(序号=%d)应存活", r+1, sess.seq)
				}
				if _, err := store.Touch(sess.ID); err != nil {
					t.Fatalf("第 %d 轮：幸存新会话应立即可用: %v", r+1, err)
				}
			}
		}
		t.Logf("用例通过: %d 轮预置 %d 条既有会话后涌入 %d 登录，既有全部让位、最后建立的 %d 条存活",
			rounds, max, n, max)
	})

	t.Run("账号隔离-一个账号的登录潮不淘汰其它账号会话", func(t *testing.T) {
		store := NewStoreWithConfig(StoreConfig{
			IdleTTL:            time.Hour,
			MaxSessionsPerUser: max,
		})
		clock, freeze := burstClock(time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC))
		store.now = clock

		bobSessions := runBurst(t, store, "u2", max, false, "bob")
		_ = runBurst(t, store, "u1", n, false, "alice")
		freeze()

		if got := len(store.ListActive("u2")); got != max {
			t.Fatalf("u2 活跃数不应受 u1 登录潮影响，应为 %d，实际 %d", max, got)
		}
		for _, res := range bobSessions {
			if _, err := store.Touch(res.sess.ID); err != nil {
				t.Fatalf("u2 会话应继续正常使用: %v", err)
			}
		}
		t.Logf("用例通过: u1 的 %d 并发登录未影响 u2 的 %d 条会话，淘汰严格按账号隔离", n, max)
	})
}

// 业务：并发登录 HTTP 端到端 —— 登录成功拿到的凭据立即可用
//
// 登录潮结束后，最终幸存的客户端拿着登录响应中的 Cookie 访问受保护接口，
// 必须全部 200；被让位的客户端得到统一 401 文案（不泄露账号信息）。
func TestConcurrentCapHTTPLoginImmediatelyUsable(t *testing.T) {
	const max, n, rounds = 3, 24, 5
	for r := 0; r < rounds; r++ {
		srv := newFeatureServer(t, max)
		store := srv.Sessions()
		base := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
		var now atomic.Value
		now.Store(base)
		store.now = func() time.Time { return now.Load().(time.Time) }

		clients := make([]*authClient, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		var okCount atomic.Int64
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c := &authClient{t: t, handler: srv.Handler()}
				<-start
				rec := c.loginRaw(t,
					fmt.Sprintf(`{"username":"alice","password":"alice-pass","device_label":%q}`,
						fmt.Sprintf("并发-%d", i)),
					fmt.Sprintf("UA-%d", i))
				if rec.Code == 200 {
					okCount.Add(1)
				}
				clients[i] = c
			}(i)
		}
		close(start)
		wg.Wait()
		if okCount.Load() != n {
			t.Fatalf("第 %d 轮所有登录请求都应返回成功，实际成功 %d/%d", r+1, okCount.Load(), n)
		}

		// 以服务端最终活跃集合为准，逐个客户端用“登录响应里的 Cookie”访问。
		// 注意 AddUser 的内部账号 ID 为 "u-<username>"。
		activeIDs := map[string]bool{}
		for _, sess := range store.ListActive("u-alice") {
			activeIDs[sess.ID] = true
		}
		if len(activeIDs) != max {
			t.Fatalf("第 %d 轮活跃数应为 %d，实际 %d", r+1, max, len(activeIDs))
		}
		survivors, evicted := 0, 0
		for _, c := range clients {
			rec := c.do("GET", "/profile", false)
			switch {
			case activeIDs[c.sessionID] && rec.Code != 200:
				t.Fatalf("第 %d 轮：幸存客户端登录后必须立即可用，实际 %d body=%s",
					r+1, rec.Code, rec.Body)
			case activeIDs[c.sessionID]:
				survivors++
			case rec.Code != 401 ||
				!strings.Contains(rec.Body.String(), "authentication required") ||
				!strings.Contains(rec.Body.String(), string(ReasonSessionEvicted)):
				t.Fatalf("第 %d 轮：被让位客户端应统一 401 文案+session_evicted，实际 %d body=%s",
					r+1, rec.Code, rec.Body)
			default:
				evicted++
			}
		}
		if survivors != max || evicted != n-max {
			t.Fatalf("第 %d 轮存活/让位数量应为 %d/%d，实际 %d/%d",
				r+1, max, n-max, survivors, evicted)
		}
	}
	t.Logf("用例通过: %d 轮 x %d 并发 HTTP 登录，%d 个登录凭据立即可用、%d 个统一 401 重登录，无账号信息泄露",
		rounds, n, max, n-max)
}
