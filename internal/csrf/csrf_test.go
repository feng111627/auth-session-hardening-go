package csrf

import (
	"strings"
	"testing"
)

func TestCSRFIssueAndValidate(t *testing.T) {
	t.Log("业务=CSRF令牌 签发后可校验，篡改/跨绑定/空值一律拒绝")
	p := NewProtector()
	tok := p.Issue("session-123")
	if tok == "" || !strings.Contains(tok, ".") {
		t.Fatal("用例[令牌格式] FAIL")
	}
	if !p.Validate("session-123", tok) {
		t.Fatal("用例[同绑定校验通过] FAIL")
	}
	if p.Validate("session-999", tok) {
		t.Fatal("用例[跨会话绑定必须拒绝] FAIL")
	}
	if p.Validate("session-123", tok+"x") {
		t.Fatal("用例[篡改令牌必须拒绝] FAIL")
	}
	if p.Validate("session-123", "deadbeef."+strings.Split(tok, ".")[1]) {
		t.Fatal("用例[替换nonce必须拒绝] FAIL")
	}
	if p.Validate("", tok) || p.Validate("session-123", "") {
		t.Fatal("用例[空绑定或空令牌拒绝] FAIL")
	}
	if p.Validate("session-123", "garbage") {
		t.Fatal("用例[畸形令牌拒绝] FAIL")
	}
	t.Log("用例[合法通过；跨会话/篡改/重放nonce/空值/畸形全部拒绝] PASS")

	// 同一绑定两次签发应不同（nonce 随机），但都有效。
	tok2 := p.Issue("session-123")
	if tok == tok2 {
		t.Fatal("用例[令牌nonce随机化] FAIL 两次签发相同")
	}
	if !p.Validate("session-123", tok2) {
		t.Fatal("用例[新令牌有效] FAIL")
	}
	t.Log("用例[每次签发唯一且均可校验] PASS")
}

func TestCSRFKeyIsolation(t *testing.T) {
	t.Log("业务=CSRF密钥隔离 不同密钥签发的令牌互不认")
	p1, _ := NewProtectorWithKey(bytes(1))
	p2, _ := NewProtectorWithKey(bytes(2))
	tok := p1.Issue("s1")
	if p2.Validate("s1", tok) {
		t.Fatal("用例[跨密钥令牌拒绝] FAIL")
	}
	if _, err := NewProtectorWithKey([]byte("short")); err == nil {
		t.Fatal("用例[弱密钥被拒绝] FAIL")
	}
	t.Log("用例[密钥不同则互不认，弱密钥构造报错] PASS")
}

func bytes(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed
	}
	return b
}
