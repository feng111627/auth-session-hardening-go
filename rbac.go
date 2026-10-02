package auth

// Role 表示用户角色。
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleGuest  Role = "guest"
)

// Permission 表示对某资源的某类操作。
type Permission struct {
	Resource string
	Action   string
}

// rolePermissions 是基于角色与资源的访问控制表。
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {
		{Resource: "document", Action: "read"},
		{Resource: "document", Action: "write"},
		{Resource: "document", Action: "delete"},
		{Resource: "admin-panel", Action: "read"},
	},
	RoleMember: {
		{Resource: "document", Action: "read"},
		{Resource: "document", Action: "write"},
	},
	RoleGuest: {
		{Resource: "document", Action: "read"},
	},
}

// Can 判断角色是否允许对 resource 执行 action；未授权一律拒绝。
func Can(role Role, resource, action string) bool {
	for _, p := range rolePermissions[role] {
		if p.Resource == resource && p.Action == action {
			return true
		}
	}
	return false
}
