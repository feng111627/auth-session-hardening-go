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
	srv := auth.NewServer(30*time.Minute, secret, limiter)

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
