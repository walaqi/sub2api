# BindKey 成功页 — 赠金详情透出

## Context

Phase 3 赠金子系统（commit `0c962baf`）已让运营可以**按池 key 配置**赠金的 `deduction_mode` / `ratio_recharge` / `expires_after_days`（表 A：`bind_key_gift_settings`）。但用户在 `/bind-key` 页面绑定成功后，前端只看到一行 "Key sk-***xxxx 已成功绑定到你的账户"，**完全感知不到**：

1. 这次拿到了多少赠金（USD 金额）
2. 赠金有没有过期日期，需要在多久之内用完
3. 赠金的扣费规则（priority 优先扣 / ratio 按比例与充值同扣，且每元扣费分别从两池消耗多少）

用户提出的诉求（原话）：

> 在用户成功绑定并领取定金后，下方的信息提示栏需要给出
> "领取赠金 \$xx
> 使用规则：有效期。请在有效期之前使用完毕
> 扣费比例：优先扣除 | 按比例扣除（扣除金额 1 元 = 充值余额 xx + 赠金 xx）"

需要把 Phase 3 已经存在但被丢弃的赠金参数透传到前端，渲染到现有成功卡片里。

约束（继承）：仅改 `backend/internal/keybind/` + `frontend/src/views/BindKeyView.vue`；不动 `gift` 包 / `http.go` / `wire_gen.go` / ent schema / DB 迁移 / `router.go`。

---

## 改动概览

| # | 文件 | 类型 | 说明 |
|---|------|------|------|
| 1 | [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go) | 修改 | `UserBalanceUpdater` 接口返回值 + `giftEngineUpdater` 实现 |
| 2 | [backend/internal/keybind/service.go](backend/internal/keybind/service.go) | 修改 | `CommitResult` 加 `Gift *GrantedGift`；`Commit` 把 grant 出参回穿 |
| 3 | [frontend/src/views/BindKeyView.vue](frontend/src/views/BindKeyView.vue) | 修改 | 成功卡片插入赠金详情块 + i18n + 计算属性 |

完全不动：`gift/*`（已经返回 `*UserGift`，无需改）/ `keybind/handler.go` / `keybind/routes.go` / `server/router.go` / `server/http.go` / `cmd/server/wire_gen.go` / 任何 ent schema。

---

## 后端改动

### 1. [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go)

#### 1.1 `UserBalanceUpdater` 接口签名升级

返回 `*GrantedGift` 而不仅是 `error`，让 service 层能拿到 `engine.Grant` 已经返回的 `*UserGift` 详情。

```go
// GrantedGift 是 Commit 回应里"刚发出的赠金"快照，足够前端渲染：
//   - 金额（display "$xx"）
//   - 扣费模式 + ratio_recharge（priority 不需 ratio；ratio 必带）
//   - 过期时间（nil 表示永不过期）
type GrantedGift struct {
    Amount          float64               `json:"amount"`
    DeductionMode   gift.DeductionMode    `json:"deduction_mode"`           // "priority" | "ratio"
    RatioRecharge   *float64              `json:"ratio_recharge,omitempty"` // 仅 ratio 模式有值
    ExpiresAtUnixMs *int64                `json:"expires_at_unix_ms,omitempty"` // 永不过期 → 省略
}

type UserBalanceUpdater interface {
    // 返回 (*GrantedGift, nil) 表示成功；amount<=0 或 engine 为 nil 时 (nil, nil)。
    GrantForBindKey(ctx context.Context, userID int64, amount float64, apiKeyID int64) (*GrantedGift, error)
}
```

#### 1.2 `giftEngineUpdater.GrantForBindKey` 实现

把现有 `_, err := u.engine.Grant(ctx, input)` 改成接住 `*gift.UserGift` 并投影：

```go
func (u *giftEngineUpdater) GrantForBindKey(ctx context.Context, userID int64, amount float64, apiKeyID int64) (*GrantedGift, error) {
    if amount <= 0 {
        return nil, nil
    }
    if u == nil || u.engine == nil {
        return nil, errors.New("giftEngineUpdater: engine is nil")
    }

    input := gift.GrantInput{ /* ... 不变 ... */ }
    if ref := apiKeyRef(apiKeyID); ref != "" { input.SourceRef = &ref }
    if u.resolver != nil && apiKeyID > 0 {
        // ... 原有 resolver 覆盖逻辑不变 ...
    }

    granted, err := u.engine.Grant(ctx, input)
    if err != nil { return nil, err }
    if granted == nil { return nil, nil }

    out := &GrantedGift{
        Amount:        granted.Amount,
        DeductionMode: granted.Mode,
        RatioRecharge: granted.RatioRecharge,
    }
    if granted.ExpiresAt != nil {
        ms := granted.ExpiresAt.UnixMilli()
        out.ExpiresAtUnixMs = &ms
    }
    return out, nil
}
```

> **理由**：`gift.UserGift` 已是包外 DTO（[gift/types.go:50-63](backend/internal/gift/types.go#L50-L63)），但直接把 `*gift.UserGift` 序列化会暴露内部 ID/Status/CreatedAt 等无关字段；定义一个 keybind 自己的 `GrantedGift` 更紧凑也更稳定。

#### 1.3 `NewEntUserBalanceUpdater`（已废弃）

已经返回 `nil`，签名虽然变了但没有调用方。直接改成新签名即可：

```go
// Deprecated: use NewGiftEngineUpdater(engine, resolver).
func NewEntUserBalanceUpdater(_ *ent.Client) UserBalanceUpdater { return nil }
```

不需要再动。

### 2. [backend/internal/keybind/service.go](backend/internal/keybind/service.go)

#### 2.1 `CommitResult` 加字段

```go
type CommitResult struct {
    APIKeyID  int64        `json:"api_key_id"`
    MaskedKey string       `json:"masked_key"`
    Gift      *GrantedGift `json:"gift,omitempty"` // 没赠送 / updater 关闭 / 失败 → nil
}
```

`omitempty` 是关键：旧前端读不到 `gift` 时行为不变（向后兼容）。

#### 2.2 `Commit()` 接住 grant 出参

`service.go:331-346` 当前调用 `s.userBalanceUpdater.GrantForBindKey(ctx, userID, giftAmount, keyID)` 只拿 `error`，改为：

```go
var grantedGift *GrantedGift
if giftAmount > 0 && s.userBalanceUpdater != nil {
    g, err := s.userBalanceUpdater.GrantForBindKey(ctx, userID, giftAmount, keyID)
    if err != nil {
        log.Printf("[keybind] grant balance %.4f to user %d failed: %v", giftAmount, userID, err)
    } else {
        grantedGift = g
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
```

两处 `return` 都把 `grantedGift` 带上：

- 降级路径（`row, err := s.client.APIKey.Get(...)` 失败，[service.go:360](backend/internal/keybind/service.go#L360)）：
  ```go
  return &CommitResult{APIKeyID: keyID, MaskedKey: "", Gift: grantedGift}, nil
  ```
- 正常路径（[service.go:366](backend/internal/keybind/service.go#L366)）：
  ```go
  return &CommitResult{APIKeyID: row.ID, MaskedKey: maskKey(row.Key), Gift: grantedGift}, nil
  ```

handler 层 `Commit` 直接 `response.Success(c, res)`，无需改动。

---

## 前端改动（仅 [frontend/src/views/BindKeyView.vue](frontend/src/views/BindKeyView.vue)）

### 3.1 类型与 state

在 `<script setup>` 顶部 imports 后追加：

```ts
interface GrantedGiftPayload {
  amount: number
  deduction_mode: 'priority' | 'ratio'
  ratio_recharge?: number | null
  expires_at_unix_ms?: number | null
}

const grantedGift = ref<GrantedGiftPayload | null>(null)
```

### 3.2 `commitReservation` 解析新字段

把现有的 `ApiEnvelope<{ masked_key: string }>` 类型扩展，并在成功分支保存赠金：

```ts
const result = await apiClient.post<ApiEnvelope<{
  masked_key: string
  api_key_id: number
  gift?: GrantedGiftPayload | null
}>>(...)

// 成功分支：
grantedGift.value = result?.data?.gift ?? null
```

跳转/导航前**不**清掉 `grantedGift`（成功卡片要继续渲染）；只有 `clearPending()` / 切换 reservation 时才一起 reset。

### 3.3 计算属性

```ts
const giftAmountText = computed(() => {
  const g = grantedGift.value
  if (!g || g.amount <= 0) return ''
  // 至少 2 位小数；< 0.01 显示 < $0.01，避免 "$0.00"
  if (g.amount < 0.01) return '< $0.01'
  return `$${g.amount.toFixed(2)}`
})

const giftExpiryText = computed(() => {
  const g = grantedGift.value
  if (!g) return ''
  if (g.expires_at_unix_ms == null) return tr.value.giftExpiryNever
  const d = new Date(g.expires_at_unix_ms)
  // 用本地时区渲染 YYYY-MM-DD
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return tr.value.giftExpiryUntil.replace('{date}', `${yyyy}-${mm}-${dd}`)
})

const giftDeductionText = computed(() => {
  const g = grantedGift.value
  if (!g) return ''
  if (g.deduction_mode === 'priority') return tr.value.giftDeductionPriority
  // ratio：每扣 1 单位时 recharge_part = 1/(1+r), gift_part = r/(1+r)
  const r = Number(g.ratio_recharge ?? 0)
  if (!Number.isFinite(r) || r <= 0) return tr.value.giftDeductionPriority // 容错
  const recharge = (1 / (1 + r)).toFixed(2)
  const gift = (r / (1 + r)).toFixed(2)
  return tr.value.giftDeductionRatio
    .replace('{recharge}', recharge)
    .replace('{gift}', gift)
})
```

### 3.4 模板：成功卡片下方新增 3 行赠金块

定位到现有 success 区（包含 `tr.value.successBound` 的那段卡片），在 `<p>{{ successMessage }}</p>` 之后追加：

```vue
<div
  v-if="grantedGift && grantedGift.amount > 0"
  class="mt-4 space-y-2 rounded-lg border border-emerald-200 bg-emerald-50/60 p-4 text-sm dark:border-emerald-900/40 dark:bg-emerald-900/20"
>
  <div class="flex items-baseline justify-between gap-3">
    <span class="text-muted-foreground">{{ tr.giftReceivedLabel }}</span>
    <span class="font-mono font-semibold text-emerald-700 dark:text-emerald-300">{{ giftAmountText }}</span>
  </div>
  <div class="flex items-baseline justify-between gap-3">
    <span class="text-muted-foreground">{{ tr.giftExpiryLabel }}</span>
    <span>{{ giftExpiryText }}</span>
  </div>
  <div class="flex items-baseline justify-between gap-3">
    <span class="text-muted-foreground">{{ tr.giftDeductionLabel }}</span>
    <span class="text-right">{{ giftDeductionText }}</span>
  </div>
</div>
```

样式说明：复用项目已有的 emerald/dark 配色，与 success 卡片整体保持一致；`text-right` 让 ratio 比较长的文案在右栏右对齐。

### 3.5 i18n（追加到 `en` / `zh` 两个常量对象）

```ts
// en
giftReceivedLabel: 'Gift balance received',
giftExpiryLabel: 'Validity',
giftExpiryNever: 'No expiration. You can use it anytime.',
giftExpiryUntil: 'Use before {date}. Please consume the gift balance before this date.',
giftDeductionLabel: 'Deduction rule',
giftDeductionPriority: 'Priority — gift balance is consumed before your top-up balance.',
giftDeductionRatio: 'Ratio — each $1 of usage deducts ${recharge} from top-up + ${gift} from gift balance.',

// zh
giftReceivedLabel: '本次领取赠金',
giftExpiryLabel: '使用规则',
giftExpiryNever: '永久有效，无需担心过期',
giftExpiryUntil: '请在 {date} 前使用完毕',
giftDeductionLabel: '扣费规则',
giftDeductionPriority: '优先扣除：赠金会先于充值余额被消耗',
giftDeductionRatio: '按比例扣除：每消耗 1 美元 = 充值余额 ${recharge} + 赠金 ${gift}',
```

> 中文 `{date}` 占位符与 `giftExpiryUntil` 模板一致；前端渲染替换。

---

## 验证方案

### 后端

```bash
cd backend && GOPROXY=https://goproxy.cn,direct go build ./...
cd backend && GOPROXY=https://goproxy.cn,direct go test -race ./internal/keybind/...
```

`service_test.go` 追加 / 调整：

- `Commit` 成功且配置了 priority 模式 → `result.Gift.DeductionMode == "priority"`、`Gift.RatioRecharge == nil`、`Gift.Amount` 等于 `quota - quota_used`、`Gift.ExpiresAtUnixMs` 与 resolver 配置一致。
- `Commit` 成功且配置了 ratio 模式（`ratio_recharge=2.0`、`expires_after_days=7`）→ `Gift.RatioRecharge == 2.0`、`Gift.ExpiresAtUnixMs ≈ now + 7d`。
- `Commit` 成功但 `userBalanceUpdater == nil`（feature off）→ `result.Gift == nil`、key 仍转移。
- `GrantForBindKey` 失败（mock 返 error）→ `result.Gift == nil`、log 有告警、`MarkParticipated` 仍执行。
- `quota == 0`（无限额度）→ `giftAmount == 0`，不进 grant 分支，`result.Gift == nil`。

### 前端

```bash
cd frontend && pnpm typecheck && pnpm lint
```

### 手动 E2E

```bash
cd backend && BIND_KEY_POOL_USER_EMAIL=keypool@atai8.cc go run ./cmd/server/
cd frontend && pnpm dev
```

5 个场景，逐个验证成功卡片下方赠金块文案：

1. **priority 永不过期**：池 key `quota=10, quota_used=2`，表 A 配 `mode=priority, expires_after_days=NULL` → 赠金块显示「\$8.00 / 永久有效，无需担心过期 / 优先扣除：……」。
2. **priority 7 天过期**：表 A 配 `mode=priority, expires_after_days=7` → 显示「请在 2026-06-04 前使用完毕」（基于今天 2026-05-28）。
3. **ratio=2.0**：表 A 配 `mode=ratio, ratio_recharge=2.0, expires_after_days=30` → 显示「按比例扣除：每消耗 1 美元 = 充值余额 \$0.33 + 赠金 \$0.67」+ 30 天后过期。
4. **未配置赠金 / quota=0**：池 key `quota=0` → 成功卡片**不**渲染赠金块（`v-if` 拦截），不影响 success 文本。
5. **EN/ZH 切换**：切换语言后整个赠金块文案随 `tr.value` 切换。

---

## 风险与备注

- **JSON 兼容性**：`gift` 字段加 `omitempty`，旧前端构建（不读这个字段）行为不变；仅当用户主动刷新前端才看到新 UI。
- **`UserBalanceUpdater` 是破坏性签名变更**：当前只有 `giftEngineUpdater` 一个实现 + `NewEntUserBalanceUpdater`（已 deprecated 返 nil），生产无外部实现，安全。
- **小金额显示**：`amount < 0.01` 不显示 `$0.00`，改用 `< $0.01`，符合 `gift` 包内部金额精度（4 位小数存储）。
- **过期日期时区**：用浏览器本地时区渲染（`new Date(unixMs).getFullYear()/...`），与现有 BindKey 月度倒计时一致。
- **回滚**：单 commit `git revert`。后端只动 keybind 包内 2 个文件，前端 1 个文件；无 DB 迁移、无主干改动。
