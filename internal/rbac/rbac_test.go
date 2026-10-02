package rbac

import "testing"

func TestRBACDefaultDeny(t *testing.T) {
	t.Log("业务=RBAC默认拒绝 未显式授权一律拒绝")
	a := NewAuthorizer()
	if a.Can(RoleMember, ResourceAdmin, ActionAdmin) {
		t.Fatal("用例[未授权角色拒绝] FAIL")
	}
	if a.Can("unknown-role", ResourceProfile, ActionRead) {
		t.Fatal("用例[未知角色拒绝] FAIL")
	}
	if a.CanAny(nil, ResourceProfile, ActionRead) {
		t.Fatal("用例[空角色列表拒绝] FAIL")
	}
	t.Log("用例[默认拒绝：未授权/未知角色/空角色] PASS")
}

func TestRBACGrants(t *testing.T) {
	t.Log("业务=RBAC授权矩阵 按角色×资源×动作精确放行")
	a := NewAuthorizer()
	a.Grant(RoleMember, ResourceProfile, ActionRead, ActionWrite)
	a.Grant(RoleMember, ResourceOrders, ActionRead)
	a.Grant(RoleAdmin, ResourceAdmin, ActionAdmin)

	if !a.Can(RoleMember, ResourceProfile, ActionRead) ||
		!a.Can(RoleMember, ResourceProfile, ActionWrite) {
		t.Fatal("用例[member可读写profile] FAIL")
	}
	if a.Can(RoleMember, ResourceProfile, ActionAdmin) {
		t.Fatal("用例[member不得admin profile] FAIL")
	}
	if a.Can(RoleMember, ResourceAdmin, ActionAdmin) {
		t.Fatal("用例[越权:member访问admin资源必须拒绝] FAIL")
	}
	if !a.Can(RoleAdmin, ResourceAdmin, ActionAdmin) {
		t.Fatal("用例[admin可执行admin动作] FAIL")
	}
	if !a.CanAny([]string{RoleGuest, RoleMember}, ResourceOrders, ActionRead) {
		t.Fatal("用例[多角色任一命中即放行] FAIL")
	}
	if a.CanAny([]string{RoleGuest, RoleMember}, ResourceAdmin, ActionAdmin) {
		t.Fatal("用例[多角色均无权时拒绝] FAIL")
	}
	t.Log("用例[最小权限放行、越权拒绝、多角色并集] PASS")
}
