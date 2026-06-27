# API-Key 绑定页面 — 增量需求

## Context

`/bind-key` 页面已上线（commit `70fce23c`），用户可粘贴 key 抢占池子里的可用 key 并绑定到自己账户。前一轮已实现"月度限制 + 资格预检 + 响应式宽度"三项（见下文 §A）。本轮新增**两处线上 Bug 修复**（§B）：

**A. 已落地：**
1. **每月一次限制**：同一用户每自然月只能成功绑定 1 次 key；下月 1 日 0 点（服务器本地时区）自然恢复资格。
2. **资格预检 UI**：进入页面就要识别用户是否有资格，没有资格时友好提示，并隐藏粘贴框/按钮区域，避免用户输入完才被拒。
3. **响应式宽度**：当前 `<div class="mx-auto max-w-2xl ...">` 把整个页面卡死在 ~672px，桌面浏览器看起来像在手机上；改成自适应、桌面下用更宽的栅格。

**B. 本轮新增（线上反馈）：**
4. **绑定后用户余额仍为 0**：池 key 绑定到用户账户后，[api_key_auth.go:205](backend/internal/server/middleware/api_key_auth.go#L205) 的 `apiKey.User.Balance <= 0` 门禁拦截；用户拿到 key 却用不了。需要绑定时**赠送 = key 剩余额度（quota - quota_used）**的 USD 余额到用户账户。
5. **绑定后 key 没有分组**：[service.go:274](backend/internal/keybind/service.go#L274) 在转移所有权时调用了 `.ClearGroupID()`，把池 key 上配置好的 group_id 清掉了，结果绑定后的 key 在密钥列表里显示无分组。需要把 group_id 一起转移过来（运营保证池 key 不放在 is_exclusive 的排他分组，所以无需额外白名单处理）。

**约束保持不变**：所有改动尽量集中在 `backend/internal/keybind/` 与 `frontend/src/views/BindKeyView.vue` 内部，不动主干文件、不改 ent schema、不加 DB 迁移。本轮 Bug 修复**唯一的主干扰动**：[backend/internal/server/router.go:123](backend/internal/server/router.go#L123) 那一行多传一个已经在闭包内的 `apiKeyService` 形参（用于失效认证缓存）；不改 `http.go` / `wire_gen.go` 签名。

---

# A. 已落地的改动（前一轮）

## 后端改动

### 1. 月度参与名单：纯文件持久化

**位置**：`<DATA_DIR>/keybind/<YYYYMM>.bind-keys.users`，每行一个 user_id（十进制字符串）。

- 上月文件无需清理：服务自然只读"当月"的文件名，往月文件留作审计/手动备份。
- 跨进程并发：用 `flock(LOCK_EX)` 包住"读 → 判存在 → 追加"，单机够用。本项目没有水平扩展场景（Redis 是缓存，不是分布式锁中心），用 fcntl 即可。Linux/macOS 走 `syscall.Flock`，Windows 用 build tag 隔离一个 stub（生产是 Linux）。
- 文件大小：一万人写入 ≈ 80KB，无需切片。
- 时区：用 `time.Now()`（服务器本地时区）格式化 `200601`，保持与运维直觉一致。

### 2. 新文件 [backend/internal/keybind/participation.go](backend/internal/keybind/participation.go)

```go
type ParticipationStore struct {
    dir string
    mu  sync.Mutex // 进程内串行化，避免短时间多次 fopen+flock 的开销
}

func NewParticipationStore(dataDir string) *ParticipationStore {
    return &ParticipationStore{dir: filepath.Join(dataDir, "keybind")}
}

// HasParticipated 当月是否已绑定过。
func (p *ParticipationStore) HasParticipated(ctx context.Context, userID int64) (bool, error)

// MarkParticipated 把 userID 追加到当月文件；幂等——若已存在直接返回 nil。
func (p *ParticipationStore) MarkParticipated(ctx context.Context, userID int64) error

// CurrentMonthKey 返回 "200601"——便于前端 "下次重置时间" 渲染。
func (p *ParticipationStore) CurrentMonthKey() string

// NextResetUnixMs 返回下个自然月 1 日 0 点的 epoch 毫秒（用于前端展示）。
func (p *ParticipationStore) NextResetUnixMs() int64
```

实现要点：
- `MarkParticipated` 内部调用 `HasParticipated` 后才追加，保持幂等；写入用 `O_APPEND|O_CREATE|O_WRONLY 0644`，写完 `Sync()` 一次。
- `flock`：Linux/WSL 用 `syscall.Flock(fd, LOCK_EX)`；Windows 用 build tag stub（仅靠 `sync.Mutex`，可接受，因为生产是 Linux）。
- 失败处理：文件 IO 错误 → 返回 `infraerrors.InternalServer("BIND_KEY_PARTICIPATION_IO", ...)`，handler 层转 500。

### 3. 修改 [backend/internal/keybind/service.go](backend/internal/keybind/service.go)

- `Service` 结构体加 `participation *ParticipationStore` 字段。
- `NewService` 新增 `dataDir string` 参数，构造 `ParticipationStore`。
- 新增 `ErrAlreadyParticipated = infraerrors.Forbidden("BIND_KEY_ALREADY_PARTICIPATED", "you have already bound a key this month")`。
- 新增公开方法：

  ```go
  type EligibilityResult struct {
      Eligible            bool   `json:"eligible"`
      AlreadyParticipated bool   `json:"already_participated"`
      NextResetUnixMs     int64  `json:"next_reset_unix_ms"`
      Reason              string `json:"reason,omitempty"` // 可选：feature_disabled
  }

  func (s *Service) CheckEligibility(ctx context.Context, userID int64) (*EligibilityResult, error)
  ```

  - `!s.Enabled()` → `Eligible: false, Reason: "feature_disabled"`。
  - `userID <= 0`（匿名）→ 视为有资格，由 `Commit` 兜底。
  - 已登录 → 调 `participation.HasParticipated`；命中则 `AlreadyParticipated: true, NextResetUnixMs: ...`。

- **`Commit` 关键改动**（防绕过）：在执行 `client.APIKey.Update()` **之前**先调 `participation.HasParticipated(userID)`；命中直接返回 `ErrAlreadyParticipated`，同时 `DEL` reservation 防止他人再 commit（`lock` key 留下让 TTL 自然过期）。
  - 顺序：`HasParticipated` → `client.APIKey.Update`（含 TOCTOU where）→ 成功后 `MarkParticipated` → `DEL reservation`。
  - `MarkParticipated` 失败：key 已转移成功，仅 `log.Printf` 记错，不回滚 DB（避免"拿到 key 却被告知失败"的更糟体验）。

### 4. 修改 [backend/internal/keybind/handler.go](backend/internal/keybind/handler.go)

新增 `Eligibility` handler（GET，需 JWT）：

```go
func (h *Handler) Eligibility(c *gin.Context) {
    subject, ok := servermiddleware.GetAuthSubjectFromContext(c)
    if !ok { response.Unauthorized(c, "user not authenticated"); return }
    res, err := h.svc.CheckEligibility(c.Request.Context(), subject.UserID)
    if err != nil { response.ErrorFrom(c, err); return }
    response.Success(c, res)
}
```

### 5. 修改 [backend/internal/keybind/routes.go](backend/internal/keybind/routes.go)

- `RegisterRoutes` 增加 `dataDir string` 参数（来自 `cfg.Pricing.DataDir`，复用项目已有约定）。
- `NewService(ctx, client, redisClient, poolEmail, dataDir)` 调用同步更新。
- 新路由：

  ```go
  g.GET("/eligibility", gin.HandlerFunc(jwtAuth), h.Eligibility) // 需 JWT
  ```

  公开 `/reserve` 不做月度检查（匿名用户身份未知）；月度限制由 `Commit` 强制。

### 6. 修改 [backend/internal/server/router.go](backend/internal/server/router.go)（仅 1 行）

[backend/internal/server/router.go:123](backend/internal/server/router.go#L123) 这一行从

```go
keybind.RegisterRoutes(v1, entClient, redisClient, jwtAuth)
```

改为

```go
keybind.RegisterRoutes(v1, entClient, redisClient, jwtAuth, cfg.Pricing.DataDir)
```

`cfg` 已在闭包内可用（[router.go:103](backend/internal/server/router.go#L103)），无需改函数签名，**不动** `http.go` / `wire_gen.go`。

---

## 前端改动（仅 [frontend/src/views/BindKeyView.vue](frontend/src/views/BindKeyView.vue)）

### 1. 资格预检

- 新增 state：`eligibility = ref<EligibilityResult | null>(null)`、`loadingEligibility = ref(true)`。
- `onMounted`：在 storage 检测之后、auto-commit 之前，若 `isAuthenticated.value === true` → `apiClient.get('/bind-key/eligibility')`，写入 `eligibility.value`。
- 渲染分支（在 storage OK 的 `<template v-else>` 内）：
  1. `loadingEligibility` → 显示骨架/转圈卡片。
  2. `eligibility?.already_participated === true` → 渲染"已参与"卡片（紫色/info 风格），展示倒计时（用 `next_reset_unix_ms - Date.now()` 计算"X 天 Y 小时"），**不渲染**粘贴框/绑定按钮/pending 区。
  3. `eligibility?.eligible === false && reason === 'feature_disabled'` → 渲染"功能未开启"提示。
  4. 其它（已登录且合规 / 匿名）→ 走原有粘贴流程。
- `commitReservation` 失败时若 `reason === 'BIND_KEY_ALREADY_PARTICIPATED'` → 把 `eligibility.value.already_participated` 置 true，触发上面分支，并 `clearPending()`。

### 2. 双语文案补充（追加到 `en` / `zh` 两个常量对象）

- `monthlyLimitTitle` / `monthlyLimitBody`（"本月已参与，下月 1 日重置"）
- `nextResetLabel`（"下次重置"）
- `featureDisabledTitle` / `featureDisabledBody`（"该功能当前未启用"）
- `eligibilityChecking`（"正在检查参与资格…"）

### 3. 响应式宽度

- 根容器从 `<div class="mx-auto max-w-2xl space-y-6 p-4">` 改为 `<div class="mx-auto w-full max-w-2xl md:max-w-3xl xl:max-w-5xl space-y-6 p-4 md:p-6">`。
- 在 `xl` 断点用 `xl:grid xl:grid-cols-3 xl:gap-6` 把"粘贴框 + 状态"放左 2 栏、"工作原理"放右 1 栏；移动端仍单列。
- 卡片内边距 `p-6 md:p-8`。
- **不改** [AppLayout.vue](frontend/src/components/layout/AppLayout.vue) / [AuthLayout.vue](frontend/src/components/layout/AuthLayout.vue)：`AppLayout` 主区已 `p-4 md:p-6 lg:p-8` 自适应；`AuthLayout` 内部强制 `max-w-md` 是登录卡片设计意图，匿名状态下页面窄合理（与 `/login` 一致）。只在已登录走 `AppLayout` 时受益于宽屏。

---

## 关键文件汇总

| 角色 | 路径 | 类型 |
|------|------|------|
| 月度参与存储 | [backend/internal/keybind/participation.go](backend/internal/keybind/participation.go) | 新文件 |
| 后端服务（追加方法 + Commit 加月度门禁） | [backend/internal/keybind/service.go](backend/internal/keybind/service.go) | 修改 |
| 后端 handler（追加 `Eligibility`） | [backend/internal/keybind/handler.go](backend/internal/keybind/handler.go) | 修改 |
| 后端路由（追加 `/eligibility` + dataDir 参数） | [backend/internal/keybind/routes.go](backend/internal/keybind/routes.go) | 修改 |
| 主干钩子（仅 1 行参数变化） | [backend/internal/server/router.go:123](backend/internal/server/router.go#L123) | 修改 1 行 |
| 前端页面（资格预检 + 响应式宽度 + 文案） | [frontend/src/views/BindKeyView.vue](frontend/src/views/BindKeyView.vue) | 修改 |

完全不动：`http.go` / `wire_gen.go` / `frontend/src/router/index.ts` / 任何 ent schema / config 结构。

---

## 验证方案

### 后端编译/测试
```bash
cd backend && GOPROXY=https://goproxy.cn,direct go build ./...
cd backend && GOPROXY=https://goproxy.cn,direct go test -race ./internal/keybind/...
```

测试覆盖：
- `MarkParticipated` 幂等：同 user_id 调两次，文件只追加一行。
- 并发安全：`-race` + 10 goroutine 同 user_id 并发 commit，仅 1 成功。
- `Eligibility` 三种分支（disabled / 已参与 / 未参与）。

### 手动 E2E
```bash
cd backend && BIND_KEY_POOL_USER_EMAIL=keypool@atai8.cc go run ./cmd/server/
cd frontend && pnpm dev
```

- **场景 A（首次访问）**：登录后访问 `/bind-key` → 完整粘贴 UI；粘贴有效 key → 绑定成功 → 检查 `data/keybind/202605.bind-keys.users` 出现 user_id。
- **场景 B（重复参与拦截）**：同账户刷新 `/bind-key` → 显示"本月已参与，下月 X 日重置"，看不到粘贴框；用 curl 直接打 `POST /api/v1/bind-key/commit` 模拟绕过 → 后端 403 `BIND_KEY_ALREADY_PARTICIPATED`。
- **场景 C（跨月恢复）**：`mv 202605.bind-keys.users 202504.bind-keys.users` → 刷新 → 资格恢复。
- **场景 D（响应式）**：1920×1080 桌面 → 内容占合理宽度（含右侧"工作原理"栏）；768px → 单列；375px 移动 → 单列正常。
- **场景 E（功能未启用）**：不设环境变量且 DB 也无 keypool 用户 → 已登录访问 `/bind-key` → 显示"功能未启用"。
- **场景 F（并发同账户两 tab）**：两 tab 同时 commit → 仅一个成功。

### 主干合并演练
```bash
git fetch upstream && git merge upstream/main --no-commit --no-ff
```
预期：仅 `router.go` 出现 1 行 contextual diff，新文件无冲突。

---

## 风险与备注

- **跨时区**：本期采用服务器本地时间（国内运维常驻 UTC+8）。如未来跨多地区再引入 tz 配置。
- **文件清理**：旧月文件不自动清理，作为审计留存；按 ≤100KB/月增长可忽略。
- **`MarkParticipated` 失败但 key 已转移**：宽松失败、仅日志告警，不回滚 DB。
- **匿名 commit 路径**：必须 JWT，所以一旦 user_id 拿到，月度检查就生效。匿名 reserve 不做月度检查合理——攻击者消费 reservation 必须登录某个账号，那时就会被拦。
- **回滚**：仅 keybind 包 + 前端 view，`git revert` 单 commit 即可；无 DB 迁移。

---

# B. 本轮新增改动（Bug 1 余额未赠送 / Bug 2 分组被清）

## 设计要点（已与用户确认）

- **赠送金额**：`max(0, apikey.Quota - apikey.QuotaUsed)`。这与 `Reserve` 阶段返回的 `RemainingQuota` 同源，最贴合"用户接管这个 key 还能用多少"的直觉。`quota == 0`（无限额度）时不赠送（赠送 0），由后续配额改造再覆盖。
- **分组保留**：直接保留池 key 上的 group_id，无白名单处理。运营约定：放进池子的 key 永远不属于 `is_exclusive=true` 的分组。
- **缓存一致性**：余额改了之后，必须**同步**清掉 auth 缓存（防止 [api_key_auth_cache.go](backend/internal/service/api_key_auth_cache.go) 缓存住旧的 `user.balance=0`）和 billing 缓存里的余额条目（防止扣费链路读到旧值）。失效粒度：`InvalidateAuthCacheByUserID(userID)` + `InvalidateUserBalance(userID)`。

## 后端改动

### 1. 修改 [backend/internal/keybind/service.go](backend/internal/keybind/service.go)

#### 1.1 注入依赖

`Service` 结构体新增两个**可选**字段：

```go
type Service struct {
    // ... 已有字段 ...

    // 可选依赖：用于绑定成功后赠送余额并失效相关缓存。
    // 为 nil 时降级为"不赠送"，但仍正常转移 key 所有权（保持向后兼容）。
    userBalanceUpdater UserBalanceUpdater          // 可选
    authCacheInval     APIKeyAuthCacheInvalidator // 可选
    billingCacheInval  BillingBalanceInvalidator  // 可选
}

// UserBalanceUpdater 仅依赖 *ent.Client 的最小接口，避免引入 repository 包。
// 由 keybind 包内自己实现一个适配器（直接 client.User.UpdateOneID().AddBalance(...).AddTotalRecharged(...)）。
type UserBalanceUpdater interface {
    AddBalanceAndTotalRecharged(ctx context.Context, userID int64, amount float64) error
}

// APIKeyAuthCacheInvalidator 与 service.APIKeyAuthCacheInvalidator 接口一致。
// 这里只声明 keybind 包真正用到的方法，便于后续 mock。
type APIKeyAuthCacheInvalidator interface {
    InvalidateAuthCacheByUserID(ctx context.Context, userID int64)
}

type BillingBalanceInvalidator interface {
    InvalidateUserBalance(ctx context.Context, userID int64) error
}
```

> **类型选择理由**：keybind 包要避免直接 `import "internal/service"` 形成循环依赖（`service` 包也间接依赖 `ent`）。在 keybind 内部声明结构等价的接口，让 router 注入时由 Go 的 structural typing 自动满足，零代码改动到 `service` 侧。

#### 1.2 `NewService` 签名扩展

新增**变参 functional options** 风格，避免再次撑爆参数列表：

```go
type Option func(*Service)

func WithBalanceGift(updater UserBalanceUpdater, authCache APIKeyAuthCacheInvalidator, billing BillingBalanceInvalidator) Option {
    return func(s *Service) {
        s.userBalanceUpdater = updater
        s.authCacheInval = authCache
        s.billingCacheInval = billing
    }
}

func NewService(ctx context.Context, client *ent.Client, redisClient *redis.Client, poolUserEmail string, dataDir string, opts ...Option) *Service {
    // ... 已有逻辑 ...
    for _, opt := range opts {
        opt(svc)
    }
    return svc
}
```

#### 1.3 keybind 内置的 `entUserBalanceUpdater`（避免引入 repository）

新文件 [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go)：

```go
package keybind

import (
    "context"

    "github.com/Wei-Shaw/sub2api/ent"
    dbuser "github.com/Wei-Shaw/sub2api/ent/user"
)

type entUserBalanceUpdater struct {
    client *ent.Client
}

func NewEntUserBalanceUpdater(client *ent.Client) UserBalanceUpdater {
    return &entUserBalanceUpdater{client: client}
}

func (u *entUserBalanceUpdater) AddBalanceAndTotalRecharged(ctx context.Context, userID int64, amount float64) error {
    if amount <= 0 {
        return nil
    }
    _, err := u.client.User.Update().
        Where(dbuser.IDEQ(userID)).
        AddBalance(amount).
        AddTotalRecharged(amount).
        Save(ctx)
    return err
}
```

#### 1.4 `Commit()` 关键修改

去掉 `.ClearGroupID()`（**Bug 2 fix**），并在 key 转移成功后赠送余额并失效缓存（**Bug 1 fix**）：

```go
// 1. 先查池 key 当前状态，拿到 quota / quota_used / group_id 用于后续逻辑
poolKey, err := s.client.APIKey.Query().
    Where(
        apikey.IDEQ(keyID),
        apikey.UserIDEQ(s.poolUserID),
        apikey.StatusEQ(domain.StatusActive),
        apikey.DeletedAtIsNil(),
    ).
    Only(ctx)
if err != nil {
    if ent.IsNotFound(err) {
        _ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
        return nil, ErrPoolKeyAlreadyClaimed
    }
    return nil, fmt.Errorf("query pool key: %w", err)
}

giftAmount := poolKey.Quota - poolKey.QuotaUsed
if poolKey.Quota <= 0 || giftAmount < 0 {
    giftAmount = 0
}

// 2. TOCTOU guard 转移所有权——保留 group_id（去掉 ClearGroupID）
affected, err := s.client.APIKey.Update().
    Where(
        apikey.IDEQ(keyID),
        apikey.UserIDEQ(s.poolUserID),
        apikey.StatusEQ(domain.StatusActive),
        apikey.DeletedAtIsNil(),
    ).
    SetUserID(userID).
    Save(ctx)
// （不再调用 ClearGroupID；group_id 自然随 key 一起转移）
```

紧接 `affected == 0` 处理之后、`MarkParticipated` 之前，插入"赠送余额 + 失效缓存"块：

```go
// 3. 赠送余额（Bug 1 修复）。失败仅记日志、不回滚——key 已转移，
//    用户可联系运营手工补；比"绑定失败但 key 没了"体验好。
if giftAmount > 0 && s.userBalanceUpdater != nil {
    if err := s.userBalanceUpdater.AddBalanceAndTotalRecharged(ctx, userID, giftAmount); err != nil {
        log.Printf("[keybind] grant balance %.4f to user %d failed: %v", giftAmount, userID, err)
    } else {
        // 余额改了，必须失效缓存，否则中间件读到旧 balance=0 仍然 403。
        if s.authCacheInval != nil {
            s.authCacheInval.InvalidateAuthCacheByUserID(ctx, userID)
        }
        if s.billingCacheInval != nil {
            cacheCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
            _ = s.billingCacheInval.InvalidateUserBalance(cacheCtx, userID)
            cancel()
        }
        log.Printf("[keybind] granted %.4f USD to user %d (key %d remaining quota)", giftAmount, userID, keyID)
    }
}

// 4. （已有）MarkParticipated → 反正是宽松失败
```

> **顺序选择理由**：`MarkParticipated` 必须在余额赠送**之后**调用——若颠倒，余额赠送崩了但月度名单已记，用户本月失去重试机会。当前顺序：`UpdateAPIKey` → 赠送余额（lenient）→ `MarkParticipated`（lenient），三者都失败时最差是"key 转移成功 + 没赠送 + 没记月度"，运营可手工修。

#### 1.5 已落地的 `.ClearGroupID()` 是哪行？

[backend/internal/keybind/service.go:274](backend/internal/keybind/service.go#L274) 删除该行即可。**无任何上游用到 group_id 被清的语义**——前端 [BindKeyView.vue](frontend/src/views/BindKeyView.vue) 不读 group，admin 列表也无差别。

### 2. 修改 [backend/internal/keybind/routes.go](backend/internal/keybind/routes.go)

`RegisterRoutes` 增加可选参数 `apiKeyService`（用作 auth + billing 缓存失效器）：

```go
func RegisterRoutes(
    v1 *gin.RouterGroup,
    client *ent.Client,
    redisClient *redis.Client,
    jwtAuth servermiddleware.JWTAuthMiddleware,
    dataDir string,
    apiKeyService APIKeyAuthCacheInvalidator,    // 新增；nil 时降级为不失效缓存（仍能赠送余额，但用户首次请求需等 60s 缓存自然过期）
    billingCache BillingBalanceInvalidator,      // 新增；nil 时同上
) {
    // ... 已有逻辑 ...
    opts := []Option{}
    updater := NewEntUserBalanceUpdater(client)
    opts = append(opts, WithBalanceGift(updater, apiKeyService, billingCache))

    svc := NewService(context.Background(), client, redisClient, poolEmail, dataDir, opts...)
    // ...
}
```

### 3. 修改 [backend/internal/server/router.go](backend/internal/server/router.go)（仍 1 行 contextual diff）

[backend/internal/server/router.go:123](backend/internal/server/router.go#L123) 这一行从

```go
keybind.RegisterRoutes(v1, entClient, redisClient, jwtAuth, cfg.Pricing.DataDir)
```

改为

```go
keybind.RegisterRoutes(v1, entClient, redisClient, jwtAuth, cfg.Pricing.DataDir, apiKeyService, apiKeyService.BillingCacheService())
```

> **替代方案**：如果 `APIKeyService` 没有 `BillingCacheService()` getter（看代码似乎是私有字段），就让 `registerRoutes` 多接一个形参 `billingCacheService *service.BillingCacheService`，从外层 `SetupRouter` 透传——但 [server/http.go:31](backend/internal/server/http.go#L31) `ProvideRouter` 的签名也得加一个参数，违反"不动 http.go"约束。
>
> **最优解**：在 keybind 包内不要求传 `BillingCacheService`，改为直接接 `*BillingCacheService` 指针通过最简注入。具体做法：让 `apiKeyService` 自身**已经**在余额变动时失效 billing 缓存（看 redeem_service 是上层显式失效）。本期采用如下折中：
>
> - **router.go 改成 2 行参数**：`registerRoutes` 函数现有 13 个参数已经很长，再加 1 个 `billingCacheService` 走主干闭包注入。这与"不改 http.go 签名"冲突——需要 `ProvideRouter` 也加 `billingCacheService *service.BillingCacheService` 参数。
>
> **复盘后最终决定**：放弃精确失效 billing 缓存，仅失效 auth 缓存（这是真正阻塞中间件读的那一层）。billing 缓存的余额条目 TTL 自然过期即可（项目默认 ≤ 数十秒，对一次性绑定操作可接受）。这样 router.go 仍只改 1 行：

router.go 最终改法（**保留单行扰动**）：

```go
keybind.RegisterRoutes(v1, entClient, redisClient, jwtAuth, cfg.Pricing.DataDir, apiKeyService)
```

`RegisterRoutes` 签名相应去掉 `billingCache BillingBalanceInvalidator` 参数；`Service` 内 `billingCacheInval` 字段保留为 nil，不调用。代价：**用户绑定后 ~10s 内**，billing 缓存中的旧 balance=0 仍可能被某些链路读到（导致请求被拒）；考虑到 auth 缓存失效后中间件会重新查 DB 拿到新 balance（[api_key_auth.go:69 GetByKey](backend/internal/server/middleware/api_key_auth.go#L69)），实际影响可忽略。

### 4. **不修改** [backend/internal/keybind/handler.go](backend/internal/keybind/handler.go)

handler 层不需要任何修改：`Commit` handler 已经把 `userID` 透传给 `svc.Commit`，新逻辑全在 service 内部。

### 5. **不修改** [backend/internal/keybind/participation.go](backend/internal/keybind/participation.go)

月度限制逻辑不变。本轮新逻辑插在"已 transfer key"和"MarkParticipated"之间，不影响幂等性。

## 前端改动

**无前端改动**。`/bind-key` 页面仅展示 key 信息和绑定状态；用户余额由顶栏 [AppLayout.vue](frontend/src/components/layout/AppLayout.vue) 自己查询。绑定成功跳转后顶栏自然刷新即可。

如果想做更精细的用户体验：可以在 `commitReservation` 成功后调用 `userStore.refresh()`（已有方法）触发余额刷新。这是优化项，**本期不做**——刷新页面或下次请求都能看到新余额。

## 关键文件汇总（本轮）

| 角色 | 路径 | 类型 |
|------|------|------|
| 余额赠送适配器 | [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go) | 新文件 |
| 后端服务（Commit 加赠送余额 + 不再 ClearGroupID） | [backend/internal/keybind/service.go](backend/internal/keybind/service.go) | 修改 |
| 后端路由（增 1 个 cache 失效器形参） | [backend/internal/keybind/routes.go](backend/internal/keybind/routes.go) | 修改 |
| 主干钩子（仅 1 行参数变化） | [backend/internal/server/router.go:123](backend/internal/server/router.go#L123) | 修改 1 行 |

完全不动：`http.go` / `wire_gen.go` / `frontend/**` / 任何 ent schema / config 结构。

## 验证方案（本轮）

### 后端编译/测试
```bash
cd backend && GOPROXY=https://goproxy.cn,direct go build ./...
cd backend && GOPROXY=https://goproxy.cn,direct go test -race ./internal/keybind/...
```

新测试覆盖（追加到既有 `service_test.go` / 新建 `balance_test.go`）：
- `Commit` 成功后：用户 `balance` 增加了 `quota - quota_used`，`total_recharged` 同步增加。
- `Commit` 成功后：`api_keys.group_id` **未被清零**（与池 key 入站时一致）。
- `Commit` 当 `quota == 0`（无限额度）时：不赠送余额（balance 不变），key 仍正常转移。
- `Commit` 当 `userBalanceUpdater == nil`（未注入）时：不 panic、不赠送、key 仍正常转移（向后兼容）。
- 余额赠送失败（mock updater 返 err）：日志告警、`MarkParticipated` 仍执行、用户得到 key、月度名单已写入。

### 手动 E2E
```bash
cd backend && BIND_KEY_POOL_USER_EMAIL=keypool@atai8.cc go run ./cmd/server/
cd frontend && pnpm dev
```

- **场景 G（Bug 1 修复）**：注册新账户（balance=0）→ 绑定一个 quota=10、quota_used=2 的池 key → 检查 `users.balance` ≈ 8、`total_recharged` ≈ 8 → 用绑定的 key 调 `/v1/messages` → 正常返回（不再被 INSUFFICIENT_BALANCE 拦截）。
- **场景 H（Bug 2 修复）**：池 key 在分组 X（standard，非 is_exclusive）→ 绑定 → 在 `/keys` 页面看到该 key `group_id` 仍是 X，UI 显示分组 X 的名字。
- **场景 I（缓存一致性）**：绑定后**立即**用新 key 调 `/v1/messages`（不等任何 TTL）→ 第一秒就成功，证明 auth 缓存被失效。
- **场景 J（无限额度）**：池 key quota=0 → 绑定 → 用户 balance 不增（仍是 0）→ 但 key 转移成功；用 key 调用——这一步**已知会失败**（需要 balance > 0），属于运营配置问题，超出本期 Bug 修复范围。
- **场景 K（与已有月度限制叠加）**：同一账户当月已绑过 → 再次绑定 → `BIND_KEY_ALREADY_PARTICIPATED` 403，余额无变化。

### 主干合并演练（不变）
```bash
git fetch upstream && git merge upstream/main --no-commit --no-ff
```
预期：`router.go` 仍只 1 行 contextual diff（参数列表 +1）；新文件 `balance.go` 无冲突；`service.go` 的两处修改是函数体内的，不会与 upstream 冲突除非他们也改 keybind（不会）。

## 风险与备注（本轮）

- **赠送余额"挪用"风险**：用户在多账户互踢时（虽然有月度限制）可累计赠送。月度限制 + key 唯一性已经在 §A 收紧，攻击面极小。
- **billing 缓存延迟**：决定不显式失效 billing 缓存（见上文路由章节 §3）。最坏情况：绑定后 ~10s 内某些扣费链路仍读到旧 balance=0；但 auth 中间件会从 DB 重新读到新 balance，主路径正常。如运营反馈不可接受再扩成 2 行参数透传 `BillingCacheService`。
- **giftAmount 为负**：`quota_used > quota` 这种异常状态被夹到 0；不退还旧用量。
- **回滚**：`git revert` 单 commit；无 DB 迁移，已赠送的 balance 不会回退（属于已发生的运营动作，符合预期）。
