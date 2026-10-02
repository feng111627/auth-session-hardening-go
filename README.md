# auth-session-hardening-go

对登录与访问控制的安全加固示例：会话双到期线（空闲超时 + 最长存活）、
滑动续期与“保持长时间登录”、多设备会话管理与每账号会话上限淘汰、
防 CSRF / 会话固定、基于角色与资源的访问控制（RBAC）、
按 (来源, 账号) 维度的登录限流。仅依赖 Go 标准库。

## 会话与鉴权规则

### 会话生命周期（session.go）
- 登录成功即签发**全新会话 ID**（32 字节随机数），并撤销请求中携带的旧会话，
  防御会话固定攻击。
- **双到期线同时生效，哪条先到按哪条算，到期后立即不可用：**
  - **空闲到期线**：一段时间不活动即失效。每次携带会话的合法请求都会把
    空闲到期时间顺延一个空闲 TTL（滑动续期）。
  - **最长存活到期线**：自会话建立起固定不变，滑动续期**不会**顺延它；
    无论期间多活跃，超过最长存活时长一律失效。
  - 两条线同时到达时归为“最长存活到期”。
- 登录时可选择**“保持长时间登录”**（请求体 `"persistent": true`）：
  仅放宽空闲时长（示例为 7 天），**最长存活时长不变**。
- 内部原因码可分辨两种到期：`session_expired`（空闲到期）与
  `session_absolute_expired`（最长存活到期）；被账号上限让位为
  `session_evicted`，登出/轮换撤销为 `session_revoked`，未知会话为
  `session_unknown`。对外响应文案统一为 `authentication required`，
  不泄露账号与会话归属信息。
- 所有会话变更在同一把互斥锁内原子完成：同一会话的多个并发续期**全部成功、
  互不挤掉**，不会出现部分请求被误判为未登录。

默认生命周期参数（`NewServerWithConfig` 可整体配置；旧入口 `NewServer`
保持旧语义，仅滑动空闲、不启用绝对上限与会话上限）：

| 参数 | 示例默认值 | 说明 |
|------|-----------|------|
| `IdleTTL` | 30 分钟 | 普通会话滑动空闲时长 |
| `PersistentIdleTTL` | 7 天 | “保持长时间登录”会话的空闲时长 |
| `AbsoluteTTL` | 12 小时 | 最长存活时长，对所有会话一致 |
| `MaxSessionsPerUser` | 5 | 每账号活跃会话数量上限 |

### 多设备会话管理（server.go）
- 同一账号可同时在多台设备登录；会话记录登录时的设备信息
  （IP、User-Agent 由服务端采集，客户端可自报 `device_label` 仅用于展示）。
- `GET /sessions`：列出当前账号全部**活跃**会话，每条给出设备标识、
  登录时间、最近活动时间，并用 `current` 标出当前会话；按最近活动倒序，
  且只返回本账号会话。
- `DELETE /sessions/{id}`：单独结束指定会话（需 CSRF 令牌）。
  目标立即失效，同账号其它会话不受影响；目标属于他人或不存在时
  **返回完全一致的 404**，不泄露会话归属。
- `POST /sessions/revoke-all`：一次结束该账号在所有设备上的会话，
  包括发起请求的当前会话（需 CSRF 令牌），其它账号不受影响。

### 每账号会话上限与淘汰
- 活跃会话数有每账号上限（`MaxSessionsPerUser`，可配置，`<=0` 表示不限制）。
  新登录导致超过上限时，**最久未活动（LRU）的会话先让位**；空闲时间并列时
  建立更早者让位，因此刚建立的新会话绝不会被误伤。
- 并发登录在同一把锁内串行完成检查与淘汰：上限**绝不被突破**，
  被让位会话立即失效（`session_evicted`），该账号其余会话继续可用，
  不同账号名额相互独立。已撤销/已到期（任一条线）的会话不占用名额。

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

# “保持长时间登录”（空闲放宽至 7 天，最长存活仍为 12 小时）并自报设备名
curl -i -c jar2 -X POST localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-secret","persistent":true,"device_label":"我的手机"}'

# 查看当前账号的所有活跃会话（多设备）
curl -b jar localhost:8080/sessions

# 单独结束某台设备（id 取自 /sessions，变更类请求需 CSRF 令牌）
curl -b jar -X DELETE localhost:8080/sessions/<session-id> \
  -H "X-CSRF-Token: $TOKEN"

# 一次结束该账号在所有设备上的会话（含当前会话）
curl -b jar -X POST localhost:8080/sessions/revoke-all \
  -H "X-CSRF-Token: $TOKEN"
```

老客户端兼容：登录请求体仍只接受 `username`/`password`，缺省
`persistent=false`、设备信息留空，按普通会话默认策略继续可用；
旧构造入口 `NewServer(ttl, secret, limiter)` 的签名与语义保持不变。

## 测试覆盖一览

| 业务                 | 用例                                                        |
|----------------------|-------------------------------------------------------------|
| 双到期线（存储层）   | `TestLifecycleIdleExpiryFirst`、`TestLifecycleAbsoluteExpiryFirst`、`TestLifecycleBothDeadlinesTogether` |
| 双到期线（HTTP 层）  | `TestServerExpiryLinesHTTP`                                 |
| 保持长时间登录       | `TestLifecyclePersistentRelaxesIdleOnly`、`TestServerPersistentLoginRelaxesIdle` |
| 老客户端缺省兼容     | `TestLifecyclePersistentDefaultsFalse`、`TestServerLegacyClientDefaults` |
| 多设备会话查看       | `TestDevicesListSessions`、`TestServerListDevices`          |
| 多设备单独/全部结束  | `TestDevicesRevokeSingle`、`TestDevicesRevokeAll`、`TestDevicesRevokeOthersExceptCurrent`、`TestServerRevokeOneDevice`、`TestServerRevokeAllDevices`、`TestServerCannotRevokeOthersSession` |
| 会话上限与 LRU 淘汰  | `TestCapEvictsLeastRecentlyActive`、`TestCapIsolationAndExpiredDoNotCount`、`TestServerDeviceCapEviction` |
| 并发登录上限         | `TestCapConcurrentLogins`、`TestServerDeviceCapConcurrent`  |
| 会话并发续期         | `TestSessionConcurrentTouch`、`TestServerConcurrentRenewal` |
| 滑动续期             | `TestSessionSlidingRenewal`                                 |
| 过期/撤销            | `TestSessionExpiry`、`TestSessionRevoke`、`TestServerLogoutRevokes` |
| 会话固定防护         | `TestServerSessionFixation`、`TestCSRFInvalidAfterRotation` |
| CSRF                 | `TestCSRFVerify`、`TestServerCSRFRequired`                  |
| 防账号枚举           | `TestServerLoginNoAccountEnumeration`                       |
| 越权访问             | `TestRBAC`、`TestServerRBAC`                                |
| 限流触发/恢复        | `TestRateLimitTriggerAndRecover`、`TestServerLoginRateLimit` |
| 限流并发计数         | `TestRateLimitConcurrentCounting`                           |
| 限流维度隔离         | `TestRateLimitDimensions`                                   |
