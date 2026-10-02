package rbac

import "sync"

// Action 是对资源的操作类别。
type Action string

const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
	ActionAdmin Action = "admin"
)

// 资源名称常量，供策略配置与处理器共用，避免拼写漂移。
const (
	ResourceProfile = "profile"
	ResourceOrders  = "orders"
	ResourceAdmin   = "admin"
)

// 内置角色常量。
const (
	RoleGuest  = "guest"
	RoleMember = "member"
	RoleStaff  = "staff"
	RoleAdmin  = "admin"
)

type rule struct {
	resource string
	action   Action
}

// Authorizer 实现基于“角色 × 资源 × 动作”的访问控制（RBAC）。
// 默认拒绝：未显式授权的任何组合一律拒绝，保证越权请求被挡下。
type Authorizer struct {
	mu    sync.RWMutex
	rules map[string]map[rule]struct{} // role -> set(rule)
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{rules: make(map[string]map[rule]struct{})}
}

// Grant 授予某角色对某资源的若干动作权限。
func (a *Authorizer) Grant(role, resource string, actions ...Action) {
	a.mu.Lock()
	defer a.mu.Unlock()
	set, ok := a.rules[role]
	if !ok {
		set = make(map[rule]struct{})
		a.rules[role] = set
	}
	for _, act := range actions {
		set[rule{resource: resource, action: act}] = struct{}{}
	}
}

// Can 判断单个角色是否被授权。
func (a *Authorizer) Can(role, resource string, action Action) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	set, ok := a.rules[role]
	if !ok {
		return false
	}
	_, ok = set[rule{resource: resource, action: action}]
	return ok
}

// CanAny 判断一组角色中是否任一被授权（多角色取并集）。
// 角色列表为空时拒绝（默认拒绝原则）。
func (a *Authorizer) CanAny(roles []string, resource string, action Action) bool {
	for _, r := range roles {
		if a.Can(r, resource, action) {
			return true
		}
	}
	return false
}
