# 登录与访问控制加固（Go）

在最小可运行的 HTTP 服务上，对**会话、鉴权、限流**做一轮并发与异常情况下的加固：
所有决策都有明确的成功/失败语义，失败原因内部可区分、对外不泄露敏感信息，
核心状态在并发下由互斥锁保护并通过 `-race` 验证。

## 目录结构

| 包 | 职责 |
| --- | --- |
| `internal/session` | 会话创建、滑动续期、过期与撤销（并发安全） |
| `internal/ratelimit` | 按「来源 + 账号」维度的登录失败限流 |
| `internal/rbac` | 角色 × 资源 × 动作的访问控制，默认拒绝 |
| `internal/csrf` | 与绑定值关联的 HMAC 签名 CSRF 令牌 |
| `internal/auth` | 组合上述组件：登录、登出、请求鉴权、内存用户目录 |
| `internal/httpapi` | Cookie / 双重提交令牌 / 统一错误响应 / 路由 |
| `cmd/server` | 本地演示服务装配与启动 |

## 会话规则

- **标识**：登录成功生成 256 位随机会话 ID（`sid`，HttpOnly、`SameSite=Strict`，
  生产环境应启用 Secure/HTTPS）。
- **滑动续期（空闲超时）**：每次已鉴权请求通过 `Touch` 把空闲截止时间向后滑动 15 分钟。
- **绝对超时**：会话自创建起最多存活 8 小时，到期立即失效，不能靠持续访问无限续命。
- **并发安全**：所有会话读写在同一把互斥锁内完成。多个请求并发续期同一会话时，
  每个请求都基于最新状态判断有效性——不会误判未登录、不会改变或互相挤掉会话 ID。
- **立即失效**：登出或服务端撤销（`Revoke`）后，会话从存储删除，后续任何请求
  （含在途并发请求）立即得到 401；过期会话在下次访问时同步清除，另提供 `Sweep` 做周期 GC。
- **防会话固定**：登录**绝不复用**登录前的标识，总是创建全新会话 ID；
  CSRF 令牌同时重新签发并绑定到新会话 ID，旧令牌在登录后失效。

## 鉴权与 CSRF 规则

鉴权管线（`Service.AuthorizeRequest`）顺序固定，任一环节失败即拒绝，错误码可区分：

| 错误码 | HTTP 状态 | 对外文案 | 触发场景 |
| --- | --- | --- | --- |
| `csrf_invalid` | 403 | 安全校验失败，请刷新页面后重试 | CSRF 令牌缺失/伪造/绑定不匹配 |
| `unauthorized` | 401 | 登录已失效，请重新登录 | 会话不存在/已过期/已撤销 |
| `forbidden` | 403 | 无权访问该资源 | 角色未被授予该资源的动作（越权） |
| `invalid_credentials` | 401 | 用户名或密码错误 | 账号不存在与密码错误**完全同码同文案** |
| `rate_limited` | 429 | 请求过于频繁，请稍后再试 | 命中失败限流 |

- **CSRF（双重提交 + HMAC 绑定）**：令牌为 `nonce.HMAC-SHA256(key, binding|nonce)`。
  登录前 `binding` 是匿名票据 Cookie（`csrf_pre`），登录后改为会话 ID，令牌无法跨会话重用。
  敏感操作（POST）必须通过 `X-CSRF-Token` 请求头提交；**只凭 Cookie 不放行**
  （跨站请求会自动带 Cookie，但读不到 Cookie 值、无法构造请求头）。校验使用恒定时间比较。
- **RBAC**：策略为「角色 × 资源 × 动作」三元组，**默认拒绝**；多角色取并集。
  示例策略：member 可读写个人资料、读订单；admin 额外可访问 admin 资源。
- **不泄露账号是否存在**：账号不存在与密码错误返回相同状态码与文案；
  账号不存在时也执行一次哈希比较以减小时序侧信道。

## 限流策略

- 维度：`来源IP + 用户名`（`ratelimit.Key`），换 IP 或换账号各自独立计数。
- 规则：10 分钟**滑动窗口**内失败 **5** 次（演示配置；测试中为 3 次），立即封禁 **15** 分钟。
- 封禁期间 `Allow` 稳定返回 false——**即使密码正确也拒绝**，并发下不会提前放行。
- 封禁到期后原子地「解封 + 计数清零」，恢复正常即可登录；登录成功立即清空历史失败。
- 全部计数在互斥锁内更新，并发失败不会丢计数（见 `TestRateLimitConcurrentFailures`，
  200 协程并发计数后必然进入封禁）。

## 本地验证

要求 Go 1.25+，无第三方依赖。

```bash
# 构建
go build ./...

# 运行全部测试（输出中以“业务=…/用例[…]”标注覆盖的业务场景与结果）
go test ./... -v

# 并发正确性验证（竞态检测）
go test -race -count=1 ./...
```

启动演示服务（`alice/alice-pass`=member，`root/root-pass`=admin）：

```bash
go run ./cmd/server          # 默认监听 :8080
ADDR=:18080 go run ./cmd/server   # 端口被占用时可用 ADDR 指定
```

用 curl 走一遍完整流程（Cookie 保存在 /tmp/cj）：

```bash
# 1) 取预登录票据与 CSRF 令牌
curl -s -c /tmp/cj http://localhost:8080/api/csrf
TOKEN=$(awk '/authz_csrf/{print $7}' /tmp/cj)

# 2) 不带 CSRF 登录 -> 403 csrf_invalid
curl -s -b /tmp/cj -X POST http://localhost:8080/api/login \
  -d '{"username":"alice","password":"alice-pass"}'

# 3) 带 CSRF 正常登录
curl -s -c /tmp/cj -b /tmp/cj -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $TOKEN" \
  -d '{"username":"alice","password":"alice-pass"}'
# 响应里的 csrf_token 是登录后令牌（绑定新会话），后续敏感操作使用它
TOKEN=$(curl -s -b /tmp/cj http://localhost:8080/api/csrf >/dev/null; awk '/authz_csrf/{print $7}' /tmp/cj)

# 4) 读资源
curl -s -b /tmp/cj http://localhost:8080/api/profile

# 5) 敏感写：缺令牌 403；带令牌 200
curl -s -b /tmp/cj -X POST http://localhost:8080/api/profile -d '{}'
curl -s -b /tmp/cj -X POST http://localhost:8080/api/profile -H "X-CSRF-Token: $TOKEN" -d '{}'

# 6) member 越权访问 admin 资源 -> 403 forbidden
curl -s -b /tmp/cj -X POST http://localhost:8080/api/admin/action -H "X-CSRF-Token: $TOKEN"

# 7) 登出后旧会话立即失效 -> 401
curl -s -b /tmp/cj -X POST http://localhost:8080/api/logout -H "X-CSRF-Token: $TOKEN"
curl -s -b /tmp/cj http://localhost:8080/api/profile
```

## 测试覆盖一览

| 测试 | 覆盖业务 |
| --- | --- |
| `session.TestSessionConcurrentTouch` | 64 协程 × 20 轮并发滑动续期零误判/零挤掉；撤销后 100 次访问全拒绝 |
| `session.TestSessionExpiry` | 空闲过期立即清除；绝对上限到达后无法靠续期续命 |
| `session.TestSessionRevoke` | 撤销立即生效、不可恢复 |
| `ratelimit.TestRateLimitTrigger` | 阈值前放行、达阈值瞬间封禁 |
| `ratelimit.TestRateLimitBlockThenRecover` | 封禁期不提前放行、到期清零恢复 |
| `ratelimit.TestRateLimitConcurrentFailures` | 200 并发失败无丢计数；封禁期 200 并发 Allow 零放行 |
| `ratelimit.TestRateLimitSlidingWindow` / `...Dimensions` / `...SuccessResets` | 滑窗、维度隔离、成功清计数 |
| `rbac.TestRBACDefaultDeny` / `TestRBACGrants` | 默认拒绝、精确授权、越权拒绝 |
| `csrf.TestCSRFIssueAndValidate` / `...KeyIsolation` | 篡改/跨会话重放/空值拒绝、密钥隔离 |
| `auth.TestLogin*` | 会话固定防护、CSRF 拒绝原因、账号枚举同码同文案、限流触发/恢复、并发计数 |
| `auth.TestAuthorizeRequest` | 会话/CSRF/RBAC 三道关与登出立即失效 |
| `httpapi.TestHTTP*` | 端到端：登录全链路、越权、枚举、429 触发与恢复、50 并发续期与撤销 |
