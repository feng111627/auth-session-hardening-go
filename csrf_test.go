package auth

import (
	"strings"
	"testing"
)

// 业务：CSRF 防护 —— 合法令牌放行，伪造/跨会话令牌拒绝
func TestCSRFVerify(t *testing.T) {
	c := NewCSRF([]byte("test-secret"))

	token, err := c.Issue("sess-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := c.Verify("sess-1", token); err != nil {
		t.Fatalf("valid token should pass: %v", err)
	}
	t.Log("用例通过: 合法令牌校验通过")

	if err := c.Verify("sess-2", token); ReasonOf(err) != ReasonCSRFInvalid {
		t.Fatalf("token bound to another session must fail, got %v", err)
	}
	t.Log("用例通过: 令牌绑定会话，跨会话重放被拒")

	parts := strings.Split(token, ".")
	forged := parts[0] + "." + strings.Repeat("A", len(parts[1]))
	if err := c.Verify("sess-1", forged); ReasonOf(err) != ReasonCSRFInvalid {
		t.Fatalf("forged token must fail, got %v", err)
	}
	if err := c.Verify("sess-1", "garbage"); ReasonOf(err) != ReasonCSRFInvalid {
		t.Fatalf("malformed token must fail, got %v", err)
	}
	t.Log("用例通过: 伪造与畸形令牌均被拒，原因 csrf_invalid")
}

// 业务：会话固定防护 —— 会话轮换后旧 CSRF 令牌失效
func TestCSRFInvalidAfterRotation(t *testing.T) {
	c := NewCSRF([]byte("test-secret"))
	oldToken, _ := c.Issue("old-session")
	if err := c.Verify("new-session", oldToken); ReasonOf(err) != ReasonCSRFInvalid {
		t.Fatalf("token from rotated session must fail, got %v", err)
	}
	t.Log("用例通过: 会话轮换后旧令牌自动失效")
}
