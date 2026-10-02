package main

import (
	"crypto/rand"
	"log"
	"net/http"
	"time"

	auth "github.com/feng111627/auth-session-hardening-go"
)

func main() {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("generate csrf secret: %v", err)
	}
	// 5 分钟内同一 (来源, 账号) 失败 5 次，锁定 1 分钟。
	limiter := auth.NewLimiter(5, 5*time.Minute, time.Minute)
	// 会话生命周期：空闲 30 分钟失效；选择“保持长时间登录”时间放宽到 7 天；
	// 无论多活跃，最长存活 30 天一律失效；同一账号最多 5 条活跃会话，
	// 超出时最久未活动的会话让位。
	srv := auth.NewServer(
		30*time.Minute,
		secret,
		limiter,
		auth.WithPersistentIdleTTL(7*24*time.Hour),
		auth.WithMaxLifetime(30*24*time.Hour),
		auth.WithMaxSessionsPerUser(5),
	)

	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	must(srv.AddUser("admin", "admin-secret", auth.RoleAdmin))
	must(srv.AddUser("alice", "alice-secret", auth.RoleMember))
	must(srv.AddUser("bob", "bob-secret", auth.RoleGuest))

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, srv.Handler()))
}
