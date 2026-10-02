# auth-session-hardening-go

对登录与访问控制的安全加固示例：会话滑动续期、防 CSRF / 会话固定、
基于角色与资源的访问控制（RBAC）、按 (来源, 账号) 维度的登录限流。
仅依赖 Go 标准库。

## 会话与鉴权规则

### 会话（session.go）
- 登录成功即签发**全新会话 ID**（32 字节随机数），并撤销请求中携带的旧会话，
  防御会话固定攻击。
- **双到期线并行生效，哪条先到按哪条算，到期立即不可用**：
  - **空闲到期（idle TTL）**：采用滑动续期，每次携带会话的合法请求把空闲线顺延一个 TTL；
    一段时间不活动即失效，内部原因为 `session_expired`。
  - **最长存活（max lifetime）**：从会话建立时刻起算的绝对截止线，**滑动续期不会延长它**；
    无论期间多活跃，到点一律失效，内部原因为 `session_absolute_expired`。
  - 两条线在同一临界区内判定；对外统一返回 `authentication required` 的 401 文案，
    只有内部 `reason` 可区分，不向外部泄露账号相关信息。
- **“保持长时间登录”（`remember_me`）**：登录请求可选携带 `"remember_me": true`，
  此类会话只放宽**空闲时长**，**最长存活时长不变**。老客户端不带该字段时按普通会话处理。
- **多设备会话管理**：同一账号可同时在多台设备登录，每条会话记录设备/客户端标识、
  User-Agent、来源 IP、登录时间与最近活动时间；可查看全部活跃会话、单独结束任一条、
  一次结束全部。被结束的会话**立即失效**，同账号其它设备及其它账号的会话不受影响。
- **每账号会话数量上限（可配置）**：超过上限时让**最久没有活动**的会话先让位
  （内部原因 `session_evicted`，立即失效）。淘汰只针对同一账号；并发登录下：
  名额统计与淘汰、新会话加入在同一把锁内完成，活跃会话数绝不突破上限，
  且新会话在淘汰完成后才入库——**刚建立的会话不会被自己这轮淘汰误伤**。
  已撤销/已过期/已淘汰的会话不占名额。上限按配置项设置，未配置时不限制（兼容旧行为）。
- 所有会话变更在同一把互斥锁内原子完成：同一会话的多个并发续期**全部成功、
  互不挤掉**，不会出现部分请求被误判为未登录。
- 失败原因内部可区分（`session_unknown` / `session_expired` /
  `session_absolute_expired` / `session_evicted` / `session_revoked`），
  对外文案统一为 `authentication required`，不泄露额外信息。

#### 多设备会话接口

| 方法与路径 | 说明 |
|---|---|
| `GET /sessions` | 查看当前账号的全部活跃会话（设备、登录时间、最近活动时间，当前会话 `current:true`） |
| `DELETE /sessions/{id}` | 单独结束一条会话（需 CSRF 令牌）；只能结束本账号会话，不存在或非本人统一 404，不泄露归属 |
| `POST /sessions/revoke-all` | 一次结束本账号全部设备会话（需 CSRF 令牌），响应给出 `revoked` 数量 |

登录请求可选字段（缺省均有合理默认，老客户端无需改造）：

```json
{ "username": "alice", "password": "...", "remember_me": true, "device_label": "我的主力机" }
```

- `device_label` 缺省时由 `User-Agent` 推导（如 `Chrome @ Linux`、`Safari @ iOS`），
  连 UA 也没有时显示“未知设备”。
- `GET /profile` 的响应新增 `persistent` 与 `absolute_expires_at` 字段。

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

# 并发安全验证（会话上限淘汰、并发续期均在锁内原子完成）
go test -race ./...

# 启动服务（默认：空闲 30 分钟、保持登录 7 天、最长存活 30 天、每账号最多 5 条会话；
# 内置 admin/alice/bob 三个账号，口令均为 <用户名>-secret 变体，见 cmd/server/main.go）
go run ./cmd/server
```

手工验证示例：

```bash
# 登录，保存 Cookie 与 CSRF 令牌（可选 remember_me / device_label）
curl -i -c jar -X POST localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-secret","remember_me":true,"device_label":"主力机"}'

# 携带会话访问（触发滑动续期）
curl -b jar localhost:8080/profile

# 查看当前账号在所有设备上的活跃会话
curl -b jar localhost:8080/sessions

# 单独结束某台设备上的会话（变更类操作需 CSRF 令牌）
TOK=<登录响应中的 csrf_token>
curl -b jar -X DELETE localhost:8080/sessions/<会话ID> -H "X-CSRF-Token: $TOK"

# 一次结束该账号在所有设备上的会话
curl -b jar -X POST localhost:8080/sessions/revoke-all -H "X-CSRF-Token: $TOK"

# 缺少 CSRF 令牌的敏感操作 → 403 csrf_invalid
curl -b jar -X POST localhost:8080/sensitive

# 连续输错口令触发限流 → 429
for i in 1 2 3 4 5 6; do
  curl -X POST localhost:8080/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"wrong"}'; echo
done
```

### 服务端配置方式

`NewServer` 通过可选项配置新策略，不传任何选项时使用安全默认
（空闲 30m 语义来自第一个参数；最长存活默认 24h、保持登录默认 7d、不限制会话数量），
老调用方与老客户端均无需改动：

```go
srv := auth.NewServer(30*time.Minute, secret, limiter,
    auth.WithPersistentIdleTTL(7*24*time.Hour), // “保持长时间登录”的空闲时长
    auth.WithMaxLifetime(30*24*time.Hour),      // 最长存活时长（不论活跃度）
    auth.WithMaxSessionsPerUser(5),             // 每账号活跃会话上限，<=0 不限制
)
```

存储层也可直接使用 `NewStoreWithConfig(StoreConfig{...})`；
旧的 `NewStore(ttl)` 与 `Store.Create(...)` 签名保持不变。

## 测试覆盖一览

| 业务               | 用例                                                        |
|--------------------|-------------------------------------------------------------|
| 双到期线           | `TestLifecycleIdleExpiryFirst`、`TestLifecycleAbsoluteExpiryFirst`、`TestLifecycleExactBoundary` |
| 保持长时间登录     | `TestLifecyclePersistentRelaxedIdleButFixedMaxLifetime`、`TestHTTPRememberMe` |
| 多设备查看/结束    | `TestDevicesListSessions`、`TestDevicesRevokeOne`、`TestDevicesRevokeAll`、`TestHTTPListSessionsAcrossDevices`、`TestHTTPRevokeSingleSession`、`TestHTTPRevokeAllSessions` |
| 会话上限与淘汰     | `TestCapEvictsOldestIdle`、`TestCapIsolatedPerUser`、`TestCapExcludesInactive`、`TestCapConcurrentLogins`、`TestHTTPSessionCapOnLogin` |
| 老客户端兼容       | `TestHTTPOldClientDefaultDeviceAndTTL`                      |
| 会话并发续期       | `TestSessionConcurrentTouch`、`TestServerConcurrentRenewal` |
| 滑动续期           | `TestSessionSlidingRenewal`                                 |
| 过期/撤销          | `TestSessionExpiry`、`TestSessionRevoke`、`TestServerLogoutRevokes` |
| 会话固定防护       | `TestServerSessionFixation`、`TestCSRFInvalidAfterRotation` |
| CSRF               | `TestCSRFVerify`、`TestServerCSRFRequired`                  |
| 防账号枚举         | `TestServerLoginNoAccountEnumeration`                       |
| 越权访问           | `TestRBAC`、`TestServerRBAC`                                |
| 限流触发/恢复      | `TestRateLimitTriggerAndRecover`、`TestServerLoginRateLimit` |
| 限流并发计数       | `TestRateLimitConcurrentCounting`                           |
| 限流维度隔离       | `TestRateLimitDimensions`                                   |
