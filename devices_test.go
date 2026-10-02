package auth

import (
	"testing"
	"time"
)

func createDeviceSession(t *testing.T, store *Store, userID string, label string) *Session {
	t.Helper()
	sess, err := store.CreateSession(CreateMeta{
		UserID: userID,
		Role:   RoleMember,
		Device: ClientInfo{Label: label, IP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("create session for %s/%s: %v", userID, label, err)
	}
	return sess
}

// 业务：多设备会话 —— 查看当前账号的活跃会话，含设备标识与时间信息
func TestDevicesListSessions(t *testing.T) {
	store := NewStore(time.Hour)
	now := time.Now()
	store.now = func() time.Time { return now }

	phone := createDeviceSession(t, store, "u1", "iPhone")
	now = now.Add(2 * time.Minute)
	laptop := createDeviceSession(t, store, "u1", "MacBook")
	now = now.Add(2 * time.Minute)
	tablet := createDeviceSession(t, store, "u1", "iPad")
	// 另一个账号的会话不应出现在列表中。
	other := createDeviceSession(t, store, "u2", "Windows PC")

	list := store.List("u1", laptop.ID)
	if len(list) != 3 {
		t.Fatalf("u1 应有 3 条活跃会话, got %d", len(list))
	}
	// 最近活动在前：tablet（最新）、laptop、phone。
	wantOrder := []string{tablet.ID, laptop.ID, phone.ID}
	for i, want := range wantOrder {
		if list[i].ID != want {
			t.Fatalf("位置 %d 应按最近活动倒序为 %s, got %s", i, want, list[i].ID)
		}
	}
	found := map[string]SessionInfo{}
	for _, info := range list {
		found[info.ID] = info
	}
	if found[phone.ID].Device.Label != "iPhone" {
		t.Fatalf("设备标识应为 iPhone, got %q", found[phone.ID].Device.Label)
	}
	if found[phone.ID].CreatedAt.IsZero() || found[phone.ID].LastActivityAt.IsZero() {
		t.Fatal("会话必须带登录时间与最近活动时间")
	}
	if !found[laptop.ID].Current {
		t.Fatal("当前会话应被标记为 current")
	}
	if found[phone.ID].Current || found[tablet.ID].Current {
		t.Fatal("只有当前会话可标记为 current")
	}
	if _, err := store.Touch(other.ID); err != nil {
		t.Fatalf("其它账号会话不应受列表查询影响: %v", err)
	}
	t.Log("用例通过: 列表仅含本账号 3 条活跃会话，设备标识/登录时间/最近活动时间齐全，按最近活动倒序，current 标记唯一")
}

// 业务：多设备会话 —— 单独结束其中一条，立即失效，其余不受影响
func TestDevicesRevokeOne(t *testing.T) {
	store := NewStore(time.Minute)
	phone := createDeviceSession(t, store, "u1", "iPhone")
	laptop := createDeviceSession(t, store, "u1", "MacBook")
	other := createDeviceSession(t, store, "u2", "Windows PC")

	store.Revoke(phone.ID)

	if _, err := store.Touch(phone.ID); ReasonOf(err) != ReasonSessionRevoked {
		t.Fatalf("被结束的会话应立即失效(%s), got %v", ReasonSessionRevoked, err)
	}
	if _, err := store.Touch(laptop.ID); err != nil {
		t.Fatalf("同账号其它设备会话不应受影响, got %v", err)
	}
	if _, err := store.Touch(other.ID); err != nil {
		t.Fatalf("其它账号会话不应受影响, got %v", err)
	}
	if list := store.List("u1", ""); len(list) != 1 || list[0].ID != laptop.ID {
		t.Fatalf("结束一条后应只剩笔记本会话, got %+v", list)
	}
	t.Log("用例通过: 手机端会话被单独结束后立即 401(session_revoked)，笔记本与其它账号会话照常可用")
}

// 业务：多设备会话 —— 一次结束该账号在所有设备上的会话，其它账号不受影响
func TestDevicesRevokeAll(t *testing.T) {
	store := NewStore(time.Minute)
	s1 := createDeviceSession(t, store, "u1", "device-1")
	s2 := createDeviceSession(t, store, "u1", "device-2")
	s3 := createDeviceSession(t, store, "u1", "device-3")
	other1 := createDeviceSession(t, store, "u2", "other-1")
	other2 := createDeviceSession(t, store, "u3", "other-2")

	n := store.RevokeUser("u1")
	if n != 3 {
		t.Fatalf("应结束 3 条会话, got %d", n)
	}
	for _, id := range []string{s1.ID, s2.ID, s3.ID} {
		if _, err := store.Touch(id); ReasonOf(err) != ReasonSessionRevoked {
			t.Fatalf("u1 会话 %s 应已撤销, got %v", id, err)
		}
	}
	if len(store.List("u1", "")) != 0 {
		t.Fatal("全量结束后不应再有活跃会话")
	}
	for _, id := range []string{other1.ID, other2.ID} {
		if _, err := store.Touch(id); err != nil {
			t.Fatalf("其它账号会话不应受影响: %v", err)
		}
	}
	// 已撤销后再次全量结束不重复计数。
	if n := store.RevokeUser("u1"); n != 0 {
		t.Fatalf("重复全量结束应返回 0, got %d", n)
	}
	t.Log("用例通过: 一次结束 u1 全部 3 条设备会话且立即失效，u2/u3 会话不受影响")
}
