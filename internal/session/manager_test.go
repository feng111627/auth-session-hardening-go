package session

import (
	"sync"
	"testing"
	"time"
)

// fakeClock 是并发安全的测试时钟。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestManager(t *testing.T) (*Manager, *fakeClock) {
	t.Helper()
	c := newFakeClock()
	m := NewManager(5*time.Minute, 30*time.Minute)
	m.SetClock(c.now)
	return m, c
}

func TestSessionCreateAndGet(t *testing.T) {
	t.Log("业务=会话 创建后可查询，且返回的是拷贝，外部修改不影响内部状态")
	m, _ := newTestManager(t)
	s := m.Create("u1", "alice", []string{"member"})
	if s == nil || s.ID == "" {
		t.Fatalf("创建会话失败: %+v", s)
	}
	got, ok := m.Get(s.ID)
	if !ok {
		t.Fatal("用例[创建后可查询] 期望 ok=true")
	}
	if got.UserID != "u1" {
		t.Fatalf("用例[创建后可查询] UserID 不符: %s", got.UserID)
	}
	t.Logf("用例[创建后可查询] PASS id=%s user=%s roles=%v", got.ID, got.Username, got.Roles)

	got.Roles[0] = "hacked"
	again, _ := m.Get(s.ID)
	if again.Roles[0] != "member" {
		t.Fatal("用例[快照隔离] FAIL 内部角色被外部修改污染")
	}
	t.Log("用例[快照隔离] PASS")
}

func TestSessionSlidingRenewal(t *testing.T) {
	t.Log("业务=会话滑动续期 空闲超时随访问后移，但绝对超时不变")
	m, c := newTestManager(t)
	s := m.Create("u1", "alice", nil)
	initialIdle := s.IdleExpires

	c.advance(4 * time.Minute) // 仍在 5 分钟空闲窗口内
	if _, ok := m.Touch(s.ID); !ok {
		t.Fatal("用例[窗口内续期] FAIL 有效会话被误判失效")
	}
	got, _ := m.Get(s.ID)
	if !got.IdleExpires.After(initialIdle) {
		t.Fatal("用例[空闲截止后移] FAIL IdleExpires 未滑动")
	}
	if !got.AbsoluteExpires.Equal(s.AbsoluteExpires) {
		t.Fatal("用例[绝对截止不变] FAIL AbsoluteExpires 被改变")
	}
	t.Log("用例[窗口内续期+滑动+绝对上限固定] PASS")

	c.advance(4 * time.Minute) // 距上次访问 4 分钟，仍有效
	if _, ok := m.Touch(s.ID); !ok {
		t.Fatal("用例[连续滑动续期] FAIL")
	}
	t.Log("用例[连续滑动续期] PASS")
}

func TestSessionExpiry(t *testing.T) {
	t.Log("业务=会话过期 空闲超时与绝对超时任一到达即立即失效")
	m, c := newTestManager(t)

	// 空闲过期
	s1 := m.Create("u1", "alice", nil)
	c.advance(5*time.Minute + time.Second)
	if _, ok := m.Get(s1.ID); ok {
		t.Fatal("用例[空闲过期立即失效] FAIL 仍能取到会话")
	}
	if m.Len() != 0 {
		t.Fatal("用例[空闲过期被清理] FAIL 存储仍保留过期会话")
	}
	t.Log("用例[空闲过期立即失效并清除] PASS")

	// 绝对过期：持续 Touch 使空闲不超时，但绝对上限到达后必须失效
	s2 := m.Create("u2", "bob", nil)
	for i := 0; i < 6; i++ {
		c.advance(4 * time.Minute) // 共 24 分钟 < 30 分钟绝对上限
		if _, ok := m.Touch(s2.ID); !ok {
			t.Fatalf("用例[绝对上限内反复续期] FAIL 第 %d 次 Touch", i+1)
		}
	}
	c.advance(7 * time.Minute) // 总时长 31 分钟 > 30 分钟绝对上限
	if _, ok := m.Touch(s2.ID); ok {
		t.Fatal("用例[达到绝对上限立即失效] FAIL 绝对过期会话仍被续期")
	}
	t.Log("用例[绝对上限到达立即失效，无法靠续期续命] PASS")
}

func TestSessionRevoke(t *testing.T) {
	t.Log("业务=会话撤销 Revoke 后所有访问立即失败")
	m, _ := newTestManager(t)
	s := m.Create("u1", "alice", nil)
	if !m.Revoke(s.ID) {
		t.Fatal("用例[撤销存在的会话返回true] FAIL")
	}
	if _, ok := m.Get(s.ID); ok {
		t.Fatal("用例[撤销后Get失败] FAIL")
	}
	if _, ok := m.Touch(s.ID); ok {
		t.Fatal("用例[撤销后Touch失败] FAIL")
	}
	if m.Revoke(s.ID) {
		t.Fatal("用例[重复撤销返回false] FAIL")
	}
	t.Log("用例[撤销立即生效且不可恢复] PASS")
}

func TestSessionConcurrentTouch(t *testing.T) {
	t.Log("业务=会话并发续期 同一会话大量并发请求不得误判未登录、不得互相挤掉")
	m, c := newTestManager(t)
	s := m.Create("u1", "alice", []string{"member"})

	const goroutines = 64
	const rounds = 20
	var wg sync.WaitGroup
	var failMu sync.Mutex
	failures := 0

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				got, ok := m.Touch(s.ID)
				if !ok {
					failMu.Lock()
					failures++
					failMu.Unlock()
					return
				}
				if got.ID != s.ID || got.UserID != "u1" {
					t.Errorf("用例[续期不换ID/不串号] FAIL got id=%s user=%s", got.ID, got.UserID)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()

	if failures != 0 {
		t.Fatalf("用例[并发Touch全部成功] FAIL 有 %d 次被误判为未登录", failures)
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("用例[并发后续话仍存活] FAIL")
	}
	t.Logf("用例[%d 协程 × %d 轮并发 Touch 零误判、零挤掉] PASS", goroutines, rounds)

	// 并发撤销 + Touch：撤销完成后不得再出现成功
	if !m.Revoke(s.ID) {
		t.Fatal("撤销失败")
	}
	c.advance(0)
	for i := 0; i < 100; i++ {
		if _, ok := m.Touch(s.ID); ok {
			t.Fatal("用例[撤销后并发Touch全部拒绝] FAIL")
		}
	}
	t.Log("用例[撤销后 100 次 Touch 全部拒绝] PASS")
}
