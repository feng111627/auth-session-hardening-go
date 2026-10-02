package auth

import "testing"

// 业务：基于角色与资源的访问控制 —— 越权一律拒绝
func TestRBAC(t *testing.T) {
	cases := []struct {
		role          Role
		resource, act string
		want          bool
	}{
		{RoleAdmin, "document", "read", true},
		{RoleAdmin, "document", "write", true},
		{RoleAdmin, "document", "delete", true},
		{RoleAdmin, "admin-panel", "read", true},
		{RoleMember, "document", "read", true},
		{RoleMember, "document", "write", true},
		{RoleMember, "document", "delete", false},
		{RoleMember, "admin-panel", "read", false},
		{RoleGuest, "document", "read", true},
		{RoleGuest, "document", "write", false},
		{RoleGuest, "admin-panel", "read", false},
		{Role("unknown"), "document", "read", false},
	}
	for _, tc := range cases {
		got := Can(tc.role, tc.resource, tc.act)
		if got != tc.want {
			t.Errorf("Can(%s, %s, %s) = %v, want %v", tc.role, tc.resource, tc.act, got, tc.want)
		}
	}
	t.Logf("用例通过: %d 条角色-资源-操作判定全部符合访问控制表", len(cases))
}
