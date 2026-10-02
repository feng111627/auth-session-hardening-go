package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

// Protector 生成并校验与“绑定值”关联的 CSRF 令牌。
//
// 令牌结构：hex(nonce) + "." + hex(mac)，其中
//
//	mac = HMAC-SHA256(serverKey, binding + "|" + nonce)
//
// 登录前 binding 使用匿名票据（写入 Cookie），登录后 binding 改用会话 ID：
// 令牌因此无法跨会话重用，配合每次登录重新发令牌与轮换会话 ID，
// 可抵御会话固定与跨站请求伪造。
// 服务端密钥在进程启动时随机生成，令牌无需在服务端保存。
type Protector struct {
	key []byte
}

// NewProtector 使用随机密钥构造保护器。
func NewProtector() *Protector {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("csrf: cannot read crypto/rand: " + err.Error())
	}
	return &Protector{key: key}
}

// NewProtectorWithKey 使用指定密钥构造（用于多实例共享密钥的场景/测试）。
func NewProtectorWithKey(key []byte) (*Protector, error) {
	if len(key) < 16 {
		return nil, errors.New("csrf: key must be at least 16 bytes")
	}
	cp := append([]byte(nil), key...)
	return &Protector{key: cp}, nil
}

func (p *Protector) sign(binding, nonce string) []byte {
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte(binding))
	m.Write([]byte{'|'})
	m.Write([]byte(nonce))
	return m.Sum(nil)
}

// Issue 生成与 binding 绑定的令牌。
func (p *Protector) Issue(binding string) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic("csrf: cannot read crypto/rand: " + err.Error())
	}
	n := hex.EncodeToString(nonce)
	return n + "." + hex.EncodeToString(p.sign(binding, n))
}

// Validate 恒定时间校验：格式、签名与绑定值必须全部匹配。
// 空 binding 或空令牌一律拒绝。
func (p *Protector) Validate(binding, token string) bool {
	if binding == "" || token == "" {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	n, macHex := parts[0], parts[1]
	if len(n) != 32 || len(macHex) != 64 {
		return false
	}
	want := p.sign(binding, n)
	got, err := hex.DecodeString(macHex)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}
