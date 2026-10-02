package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

// CSRF 负责签发与校验绑定会话的 CSRF 令牌。
// 令牌格式：<nonce_b64>.<hmac_b64>，其中 HMAC 覆盖 nonce 与 sessionID，
// 因此令牌无法被移植到其他会话，会话轮换后旧令牌自动失效。
type CSRF struct {
	secret []byte
}

func NewCSRF(secret []byte) *CSRF { return &CSRF{secret: secret} }

func (c *CSRF) mac(nonce, sessionID string) []byte {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(nonce))
	h.Write([]byte{0})
	h.Write([]byte(sessionID))
	return h.Sum(nil)
}

// Issue 为指定会话签发令牌。
func (c *CSRF) Issue(sessionID string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate csrf nonce: %w", err)
	}
	enc := base64.RawURLEncoding
	ns := enc.EncodeToString(nonce[:])
	return ns + "." + enc.EncodeToString(c.mac(ns, sessionID)), nil
}

// Verify 校验令牌是否有效且绑定到该会话；失败返回可区分的内部原因。
func (c *CSRF) Verify(sessionID, token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return reasonErr(ReasonCSRFInvalid, "malformed csrf token")
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return reasonErr(ReasonCSRFInvalid, "malformed csrf token")
	}
	want := c.mac(parts[0], sessionID)
	if subtle.ConstantTimeCompare(mac, want) != 1 {
		return reasonErr(ReasonCSRFInvalid, "csrf token mismatch")
	}
	return nil
}
