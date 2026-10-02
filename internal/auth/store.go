package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
)

// MemoryUser 是内存目录中的一条用户记录。passwordHash 为 SHA-256 摘要。
// 真实系统应使用 bcrypt/argon2，这里为零依赖示例保持简单但仍做恒定时间比较。
type MemoryUser struct {
	ID           string
	Username     string
	PasswordHash [32]byte
	Roles        []string
}

// MemoryDirectory 是并发安全的内存用户目录，可用于演示与测试。
type MemoryDirectory struct {
	mu    sync.RWMutex
	users map[string]MemoryUser // username(lower) -> user
}

func NewMemoryDirectory() *MemoryDirectory {
	return &MemoryDirectory{users: make(map[string]MemoryUser)}
}

// Add 注册用户（明文密码在写入时摘要化）。
func (d *MemoryDirectory) Add(id, username, password string, roles []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[username] = MemoryUser{
		ID:           id,
		Username:     username,
		PasswordHash: sha256.Sum256([]byte(password)),
		Roles:        append([]string(nil), roles...),
	}
}

func (d *MemoryDirectory) Authenticate(username, password string) (string, []string, bool, error) {
	d.mu.RLock()
	u, ok := d.users[username]
	d.mu.RUnlock()
	if !ok {
		// 即使账号不存在也执行一次比较以减少时序侧信道，
		// 真正的账号枚举防护仍以统一响应文案为准。
		dummy := sha256.Sum256([]byte(password))
		subtle.ConstantTimeCompare(dummy[:], make([]byte, 32))
		return "", nil, false, nil
	}
	got := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(got[:], u.PasswordHash[:]) != 1 {
		return "", nil, true, nil
	}
	return u.ID, append([]string(nil), u.Roles...), true, nil
}
