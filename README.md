# auth-session-hardening-go

对登录与访问控制的安全加固示例：会话滑动续期、防 CSRF / 会话固定、
基于角色与资源的访问控制（RBAC）、按 (来源, 账号) 维度的登录限流。
仅依赖 Go 标准库。

## 会话与鉴权规则

### 会话（session.go）
- 登录成功即签发**全新会话 ID**（32 字节随机数），并撤销请求中携带的旧会话，
  防御会话固定攻击。
- 会话采用**滑动续期**：每次携带会话的合法请求都会把过期时间顺延一个 TTL。
- 所有会话变更在同一把互斥锁内原子完成：同一会话的多个并发续期**全部成功、
  互不挤掉**，不会出现部分请求被误判为未登录。
- 被撤销（登出/轮换）或已过期的会话**立即失效**，后续请求一律 401。
- 失败原因内部可区分（`session_unknown` / `session_expired` / `session_revoked`），
  对外文案统一为 `authentication required`，不泄露额外信息。

### CSRF（csrf.go）
- 登录响应下发 CSRF 令牌：`<nonce>.<HMAC(nonce|sessionID)>`。
- 所有变更类请求（`POST /sensitive`、`POST/DELETE /documents`）必须携带
  `X-CSRF-Token` 头；校验失败返回 403，原因 `csrf_invalid`。
- 令牌绑定会话 ID：会话轮换后旧令牌自动失效，无法跨会话重放。

### 口令（password.go）
- PBKDF2-SHA256（210k 迭代）加盐哈希存储，恒定时间比较。
- 账号不存在时也执行一次校验以抹平时间侧信道；
  口令错误与账号不存在返回**完全一致的 401 响应**，不泄露账号是否存在。

### RBAC（rbac.go）
- 访问控制表按 角色 × 资源 × 操作 判定，未授权一律 403：

| 角色   | 允许的操作                                            |
|--------|-------------------------------------------------------|
| admin  | document: read/write/delete，admin-panel: read        |
| member | document: read/write                                  |
| guest  | document: read                                        |

## 限流策略（ratelimit.go）
- 维度：`(来源 IP, 登录账号)`，账号是否存在都同样计数，不泄露账号信息。
- 规则：窗口内失败达到阈值即锁定一段时间（`cmd/server` 默认 5 分钟窗口内
  失败 5 次，锁定 1 分钟）。
- 锁定期间登录请求一律 429（即使口令正确）；锁定期满自动恢复放行。
- 计数在同一把锁内完成，并发下不丢失、不提前放行；登录成功即清零该维度计数。

## 本地验证

```bash
# 全部测试（-v 可看到每个业务用例的覆盖说明与结果）
go test -v ./...

# 并发安全验证
go test -race ./...

# 启动服务（内置 admin/alice/bob 三个账号，口令均为 <用户名>-secret 变体，见 cmd/server/main.go）
go run ./cmd/server
```

手工验证示例：

```bash
# 登录，保存 Cookie 与 CSRF 令牌
curl -i -c jar -X POST localhost:8080/login \
  -d '{"username":"alice","password":"alice-secret"}'

# 携带会话访问（触发滑动续期）
curl -b jar localhost:8080/profile

# 缺少 CSRF 令牌的敏感操作 → 403 csrf_invalid
curl -b jar -X POST localhost:8080/sensitive

# 连续输错口令触发限流 → 429
for i in 1 2 3 4 5 6; do
  curl -X POST localhost:8080/login \
    -d '{"username":"alice","password":"wrong"}'; echo
done
```

## 测试覆盖一览

| 业务           | 用例                                                        |
|----------------|-------------------------------------------------------------|
| 会话并发续期   | `TestSessionConcurrentTouch`、`TestServerConcurrentRenewal` |
| 滑动续期       | `TestSessionSlidingRenewal`                                 |
| 过期/撤销      | `TestSessionExpiry`、`TestSessionRevoke`、`TestServerLogoutRevokes` |
| 会话固定防护   | `TestServerSessionFixation`、`TestCSRFInvalidAfterRotation` |
| CSRF           | `TestCSRFVerify`、`TestServerCSRFRequired`                  |
| 防账号枚举     | `TestServerLoginNoAccountEnumeration`                       |
| 越权访问       | `TestRBAC`、`TestServerRBAC`                                |
| 限流触发/恢复  | `TestRateLimitTriggerAndRecover`、`TestServerLoginRateLimit` |
| 限流并发计数   | `TestRateLimitConcurrentCounting`                           |
| 限流维度隔离   | `TestRateLimitDimensions`                                   |
