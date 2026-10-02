package auth

import (
	"sync"
	"testing"
	"time"
)

// 业务：会话滑动续期 —— 并发续期不误判、不互挤
func TestSessionConcurrentTouch(t *testing.T) {
	store := NewStore(time.Minute)
	sess, err := store.Create("u1", RoleMember)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	const workers = 64
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := store.Touch(sess.ID)
			if err != nil {
				errs <- err
				return
			}
			if got.UserID != "u1" {
				t.Errorf("unexpected user %q", got.UserID)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent touch failed (误判未登录或互挤): %v", err)
	}
	t.Logf("用例通过: %d 个并发续期全部成功，无误判未登录、无互挤", workers)
}

// 业务：会话过期 —— 到期后立即失效
func TestSessionExpiry(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.Create("u1", RoleMember)
	if _, err := store.Touch(sess.ID); err != nil {
		t.Fatalf("touch before expiry should succeed: %v", err)
	}

	now = now.Add(2 * time.Minute)
	_, err := store.Touch(sess.ID)
	if ReasonOf(err) != ReasonSessionExpired {
		t.Fatalf("want reason %q, got %v", ReasonSessionExpired, err)
	}
	t.Log("用例通过: 过期会话立即失效，原因可区分为 session_expired")
}

// 业务：会话滑动续期 —— 活跃访问推迟过期
func TestSessionSlidingRenewal(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Now()
	store.now = func() time.Time { return now }

	sess, _ := store.Create("u1", RoleMember)
	// 每 30 秒访问一次，共 3 分钟；若没有滑动续期早已过期。
	for i := 0; i < 6; i++ {
		now = now.Add(30 * time.Second)
		if _, err := store.Touch(sess.ID); err != nil {
			t.Fatalf("touch %d should succeed under sliding renewal: %v", i, err)
		}
	}
	t.Log("用例通过: 持续活跃下会话滑动续期，3 分钟内保持有效")
}

// 业务：会话撤销 —— 撤销后立即失效，并发访问也一律拒绝
func TestSessionRevoke(t *testing.T) {
	store := NewStore(time.Minute)
	sess, _ := store.Create("u1", RoleMember)
	store.Revoke(sess.ID)

	const workers = 32
	var wg sync.WaitGroup
	reasons := make(chan Reason, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Touch(sess.ID)
			reasons <- ReasonOf(err)
		}()
	}
	wg.Wait()
	close(reasons)
	for r := range reasons {
		if r != ReasonSessionRevoked {
			t.Fatalf("want reason %q, got %q", ReasonSessionRevoked, r)
		}
	}
	t.Logf("用例通过: 撤销后 %d 个并发请求全部被拒，原因均为 session_revoked", workers)
}

// 业务：未知会话 —— 未登录请求被明确区分
func TestSessionUnknown(t *testing.T) {
	store := NewStore(time.Minute)
	_, err := store.Touch("no-such-session")
	if ReasonOf(err) != ReasonSessionUnknown {
		t.Fatalf("want reason %q, got %v", ReasonSessionUnknown, err)
	}
	t.Log("用例通过: 未知会话拒绝，原因 session_unknown")
}
