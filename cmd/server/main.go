package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/feng111627/auth-session-hardening-go/internal/auth"
	"github.com/feng111627/auth-session-hardening-go/internal/csrf"
	"github.com/feng111627/auth-session-hardening-go/internal/httpapi"
	"github.com/feng111627/auth-session-hardening-go/internal/ratelimit"
	"github.com/feng111627/auth-session-hardening-go/internal/rbac"
	"github.com/feng111627/auth-session-hardening-go/internal/session"
)

func main() {
	// 会话：空闲 15 分钟滑动续期，绝对上限 8 小时。
	sessions := session.NewManager(15*time.Minute, 8*time.Hour)
	// 限流：同一“来源+账号”10 分钟窗口内失败 5 次即封禁 15 分钟。
	limiter := ratelimit.NewLimiter(5, 10*time.Minute, 15*time.Minute)
	protector := csrf.NewProtector()
	authz := rbac.NewAuthorizer()

	// 角色-资源策略（默认拒绝，仅显式授权可访问）。
	authz.Grant(rbac.RoleMember, rbac.ResourceProfile, rbac.ActionRead, rbac.ActionWrite)
	authz.Grant(rbac.RoleMember, rbac.ResourceOrders, rbac.ActionRead)
	authz.Grant(rbac.RoleStaff, rbac.ResourceProfile, rbac.ActionRead)
	authz.Grant(rbac.RoleStaff, rbac.ResourceOrders, rbac.ActionRead)
	authz.Grant(rbac.RoleAdmin, rbac.ResourceProfile, rbac.ActionRead, rbac.ActionWrite)
	authz.Grant(rbac.RoleAdmin, rbac.ResourceOrders, rbac.ActionRead)
	authz.Grant(rbac.RoleAdmin, rbac.ResourceAdmin, rbac.ActionAdmin)

	dir := auth.NewMemoryDirectory()
	dir.Add("u-001", "alice", "alice-pass", []string{rbac.RoleMember})
	dir.Add("u-002", "bob", "bob-pass", []string{rbac.RoleStaff})
	dir.Add("u-003", "root", "root-pass", []string{rbac.RoleAdmin})

	svc := auth.NewService(dir, sessions, limiter, protector, authz)
	srv := httpapi.New(svc, sessions, protector, authz, false)

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("auth demo server listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
