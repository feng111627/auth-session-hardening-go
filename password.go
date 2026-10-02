package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Iter   = 210_000
	pbkdf2KeyLen = 32
	saltLen      = 16
)

// HashPassword 使用 PBKDF2-SHA256 派生口令摘要，
// 输出格式：pbkdf2$sha256$<iter>$<salt_b64>$<hash_b64>，自描述可升级。
func HashPassword(password string) (string, error) {
	var salt [saltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt[:], pbkdf2Iter, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	enc := base64.RawStdEncoding
	return "pbkdf2$sha256$" + strconv.Itoa(pbkdf2Iter) + "$" +
		enc.EncodeToString(salt[:]) + "$" + enc.EncodeToString(key), nil
}

// VerifyPassword 以恒定时间比较校验口令；格式非法时返回 false。
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[2])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
