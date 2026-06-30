# 赠金子系统设计方案 v2（吸收第一轮评审）

## Context

当前 `users.balance` 单字段把"真实充值"与"赠金"混在一起，最近一次绑 key 改造（commit `32df9534`）甚至把赠金也累加进 `total_recharged`。本方案引入独立的 `user_gifts` 子账本，每笔赠金支持有效期与扣除模式（priority / ratio）。

设计原则：
- 不动 `users` 表（包括 `balance` 字段语义、`total_recharged` 字段、所有现有 ent 生成代码的字段读写）
- `users.balance` 不变量从"含赠金的总余额"明确化为：`balance = recharge_pool + Σ(active gifts.remaining)`
- 与 upstream `walaqi/sub2api` 合并尽量零冲突：仅在 `users.Edges()` 末尾追加一行 `edge.To("gifts", UserGift.Type)`
- 赠金算法跑在异步 worker 池中，主路径事务正确性优先于"零延迟"
- 退款与"账号 quota / API key quota / 限速"维度按既有口径推进，赠金不参与

---

## 术语表（贯穿全文）

| 术语 | 定义 |
|------|------|
| `total_balance` | 用户总余额，等于 [users.balance](backend/ent/schema/user.go#L49)。**字段语义不变**，由"充值池 + 赠金池"两部分构成 |
| `recharge_pool` | 真实充值余额（含管理员手动充值、退款回滚、redeem code、affiliate 联盟分润）。**没有独立字段**，等于 `total_balance - Σ(active gifts.remaining)` |
| `gift_pool` | 所有 active 且未过期的赠金 remaining 之和：`Σ(user_gifts.remaining WHERE status='active' AND (expires_at IS NULL OR expires_at > now()))` |
| `priority gift` | `deduction_mode='priority'` 的赠金，扣费时优先于 `recharge_pool` 消耗 |
| `ratio gift` | `deduction_mode='ratio'` 的赠金，每扣 1 单位 `recharge_pool` 同步扣 `ratio_recharge` 单位赠金 |
| `ratio_recharge` | `ratio gift` 的扣费比例（赠金:充值），值越小赠金消耗越快。值 = "赠金消耗量 / 充值消耗量" |
| 不变量 | `total_balance ≡ recharge_pool + Σ(active gifts.remaining)`，每次扣费/发放/作废后必须守恒 |

---

## 现有扣费架构 · 异步路径与 sync 降级（修订 P0-1）

实测路径（[gateway_handler.go:511-537](backend/internal/handler/gateway_handler.go#L511-L537)）：

1. handler 调用 `submitUsageRecordTask`（**响应是否已 flush 视乎流式/非流式**）
2. [usage_record_worker_pool.go:145-184](backend/internal/service/usage_record_worker_pool.go#L145-L184) `Submit()` 按 OverflowPolicy 决定：
   - `enqueued`：进 pond 队列，worker goroutine 跑 → 用户响应零延迟
   - `sync`：**当前 goroutine 直接执行** → 算法在请求 goroutine 上跑
   - `drop` / `sample drop`：扣费被丢弃（已知设计权衡）
3. worker 调 [gateway_service.go:8146](backend/internal/service/gateway_service.go#L8146) `applyUsageBilling → repo.Apply`，事务内执行 [usage_billing_repo.go:108-146](backend/internal/repository/usage_billing_repo.go#L108-L146) 的 5 维度更新

**对赠金引擎的影响**：

- 算法本质 O(N)，N = 用户活跃 gift 数（产品上限定为 50；超出告警，不影响执行）
- 单事务内 N 次 `UPDATE user_gifts` + 1 次 `UPDATE users` + 可能 1 次"作废全部 ratio"
- `enqueued` 模式：用户感知零延迟
- `sync` 降级：算法跑在请求 goroutine，但 **用户响应是否已 flush 取决于流式/非流式**：
  - **流式 SSE**：响应主体已通过上游 copy 写出，handler 只剩 trailer，影响极小
  - **非流式**：响应可能尚未 flush，会让用户多等 N 次 UPDATE 的事务时间（PG 本地实测 < 5ms）
- 不依赖"响应已发出"前提；`sync` 降级时把延迟控制在 N 上限即可

---

## `users.balance` 写入点全表（修订 P0-2）

逐个核实仓库内所有 balance 写入点，标注是否走赠金引擎：

| # | 文件:行 | 调用 | 走赠金引擎? | 备注 |
|---|---------|------|------------|------|
| 1 | [usage_billing_repo.go:176-192](backend/internal/repository/usage_billing_repo.go#L176-L192) `deductUsageBillingBalance` | `UPDATE users SET balance = balance - $1` | **是** · 改造为调用 `giftEngine.AllocateAndDeduct` | 生产主路径，worker 池内 |
| 2 | [gateway_service.go:8014](backend/internal/service/gateway_service.go#L8014) `postUsageBilling` 兜底 | `userRepo.DeductBalance` | **是** · 同样改造 | 注释标注为 legacy fallback；为一致性同步改造 |
| 3 | [user_repo.go:694](backend/internal/repository/user_repo.go#L694) `UpdateBalance` | `AddBalance + AddTotalRecharged` | 否（保留） | 管理员手动充值入口，按用户决策保持现状 |
| 4 | [user_repo.go:714](backend/internal/repository/user_repo.go#L714) `DeductBalance` | `AddBalance(-amount)` | 否（保留） | 仅退款使用；**改造**：见 #5 |
| 5 | [payment_refund.go:272-295](backend/internal/service/payment_refund.go#L272-L295) `BalanceToDeduct` | `min(refund, u.Balance)` → `userRepo.DeductBalance` | 否，但**口径改造** | 改 `min(refund, recharge_pool)`，赠金不动 |
| 6 | [payment_refund.go:415](backend/internal/service/payment_refund.go#L415) `RollbackRefund` | `userRepo.UpdateBalance` | 否（保留） | 退款失败回滚到 recharge_pool |
| 7 | [keybind/balance.go:54-64](backend/internal/keybind/balance.go#L54-L64) `AddBalanceAndTotalRecharged` | `AddBalance + AddTotalRecharged` | **是** · 改造为 `giftEngine.Grant(priority)` | **同时移除 `AddTotalRecharged`，修复 32df9534 污染** |
| 8 | [auth_oauth_first_bind.go:81](backend/internal/service/auth_oauth_first_bind.go#L81) | `UpdateOneID().AddBalance()` | **是** · 改造为 `giftEngine.Grant(priority)` | OAuth 首登赠送 |
| 9 | [promo_service.go:127](backend/internal/service/promo_service.go#L127) | `userRepo.UpdateBalance` | **是** · 改造为 `giftEngine.Grant(priority)` | 优惠码注册赠送 |
| 10 | [redeem_service.go:448](backend/internal/service/redeem_service.go#L448) | `userRepo.UpdateBalance` | 否（保留） | 用户决策：兑换码统一仍走充值口径，本次不区分赠金型 |
| 11 | [affiliate_repo.go:291-292](backend/internal/repository/affiliate_repo.go#L291-L292) | `AddBalance + AddTotalRecharged` | 否（保留） | 用户决策：联盟分润保持现状 |
| 12 | [usage_service.go:125](backend/internal/service/usage_service.go#L125) | `userRepo.UpdateBalance(-cost)` | 否（不改） | 实测无生产路由调用 `UsageService.Create`，仅测试夹具 |
| 13 | [billing_cache_service.go:357](backend/internal/service/billing_cache_service.go#L357) `QueueDeductBalance` | Redis 缓存层扣减 | 否（不动） | 仅缓存层；DB SoT 由 #1 接管，缓存层"用户总余额"语义不变 |

**结论**：本次改造的"扣费引擎接入点"是 #1（生产主路径）+ #2（legacy fallback，一致性同步），"发放接入点"是 #7、#8、#9。其余维持现状。

### 与订阅 / API key quota / 账号 quota 维度的关系（修订 P0-3）

[usage_billing_repo.go:108-146](backend/internal/repository/usage_billing_repo.go#L108-L146) 的 5 个维度按用户决策处理：

| 维度 | 字段 | 赠金消费时是否推进? |
|------|------|---------------------|
| `cmd.SubscriptionCost` | `user_subscriptions.{daily,weekly,monthly}_usage_usd` | **不涉及**：订阅是用户付钱买的，单 key 二选一（订阅 OR 按量），赠金只针对按量路径，订阅路径走不到赠金引擎 |
| `cmd.BalanceCost` | `users.balance` | **接管**：经赠金引擎分摊；`UPDATE users SET balance` 仍是单条，但前面多了 N 行 `UPDATE user_gifts` |
| `cmd.APIKeyQuotaCost` | `api_keys.quota_used` | 照常推进：用户自购 key 的限速保护，与资金来源无关 |
| `cmd.APIKeyRateLimitCost` | `api_keys.usage_5h/1d/7d` | 照常推进：限速窗口 |
| `cmd.AccountQuotaCost` | `accounts.extra.quota_*` | 照常推进：上游渠道账号供给侧成本控制（按 `TotalCost * AccountRateMultiplier`），与用户付费形态完全无关 |

**简化版结论**：赠金接管 `cmd.BalanceCost` 一个维度，其余 4 个维度的现有 SQL 不变。

---

## 数据模型

### 新增表 `user_gifts`（迁移 `142_user_gifts.sql`）

```sql
CREATE TABLE user_gifts (
  id              BIGSERIAL    PRIMARY KEY,
  user_id         BIGINT       NOT NULL REFERENCES users(id),
  amount          DECIMAL(20,8) NOT NULL CHECK (amount > 0),
  remaining       DECIMAL(20,8) NOT NULL CHECK (remaining >= 0),
  deduction_mode  VARCHAR(16)  NOT NULL CHECK (deduction_mode IN ('priority','ratio')),
  ratio_recharge  DECIMAL(20,8) NULL,  -- ratio 模式必填(>0)，priority 模式必为 NULL
  expires_at      TIMESTAMPTZ  NULL,
  source          VARCHAR(32)  NOT NULL,
  source_ref      VARCHAR(128) NULL,
  status          VARCHAR(16)  NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','exhausted','expired','revoked')),
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  CHECK ((deduction_mode = 'ratio' AND ratio_recharge IS NOT NULL AND ratio_recharge > 0)
      OR (deduction_mode = 'priority' AND ratio_recharge IS NULL))
);
CREATE INDEX idx_user_gifts_user_active
  ON user_gifts (user_id, status, expires_at)
  WHERE status = 'active';
CREATE INDEX idx_user_gifts_expiry_sweep
  ON user_gifts (expires_at)
  WHERE status = 'active' AND expires_at IS NOT NULL;
```

字段说明：

- `source`：枚举 `keybind` / `oauth_first_bind` / `promo_code` /（保留）`manual` / `redeem` 等
- `source_ref`：业务侧关联 ID（如 promo_code_usage_id），便于追溯
- `status` 状态机：
  - `active` → `exhausted`（remaining = 0 自然耗尽）
  - `active` → `expired`（过期清理任务）
  - `active` → `revoked`（充值池触底，所有 ratio gift 联动作废）

### ent schema 改造

新增 [backend/ent/schema/user_gift.go](backend/ent/schema/user_gift.go)：

- `field.Float("amount").SchemaType(decimal(20,8))`
- `field.Float("remaining").SchemaType(decimal(20,8))`
- `field.Float("ratio_recharge").Optional().Nillable().SchemaType(decimal(20,8))`
- `field.Time("expires_at").Optional().Nillable()`
- 其余字段按表定义

ent 端类型仍是 `float64`（与 `users.balance` 保持一致），**计算层用 `shopspring/decimal`**（详见下节"精度策略"）。

[backend/ent/schema/user.go](backend/ent/schema/user.go) 的 `Edges()` **末尾追加一行**：
```go
edge.To("gifts", UserGift.Type),
```
不动现有任何字段、索引、edges。改完跑 `go generate ./...`，提交所有生成代码 diff（与 upstream 合并时按"重生成 + 验证"流程处理）。

### 精度策略（修订 P0-4）

事实：[ent/user.go:33](backend/ent/user.go#L33) `User.Balance` 是 `float64`，PG 列是 `decimal(20,8)`；现有 [usage_billing_repo.go:178](backend/internal/repository/usage_billing_repo.go#L178) 的 `UPDATE balance = balance - $1` 已经是 float64 走传参 → PG decimal 列做减法。

策略：

1. **DB 列**全部 `decimal(20,8)`（`users.balance`、`user_gifts.amount/remaining/ratio_recharge`）
2. **Go 计算层**全程使用 `shopspring/decimal`（项目已依赖，见 [payment_amounts.go](backend/internal/service/payment_amounts.go)、[payment/fee.go](backend/internal/payment/fee.go)）
3. **跨进程边界**（ent CRUD、SQL 参数）走 `float64`，但分摊算法的累加/相减永远在 `decimal.Decimal` 域里跑
4. **舍入约定**：`Round(8, decimal.RoundHalfUp)` 把每行 `remaining` 减量与 `recharge_pool` 减量都对齐到 8 位小数；最后一笔（链尾）吸收所有舍入误差，确保 `Σ(gift 减量) + recharge_pool 减量 ≡ totalCost` 精确相等
5. **断言**：单测对 round-trip 严格相等做 `decimal.Equal` 断言（不用 `InEpsilon`）

---

## 计费引擎 · 不变量 + 算法（修订 P0-5）

### 全局不变量（每次 Apply 完成后必须成立）

```
total_balance ≡ recharge_pool + Σ(active gifts.remaining)
recharge_pool ≥ 0   (扣到底则触发 ratio gift 联动作废)
priority gift remaining ≥ 0
ratio gift remaining ≥ 0
```

### 发放（`Grant`）— 修复 32df9534 污染

```
Grant(ctx, GrantInput) -> (*UserGift, error):
  if input.Amount <= 0:
    return nil, nil    # 早返回，不写 user_gifts、不动 balance
  事务内（外部 tx 复用 / 内部短事务）：
    INSERT user_gifts (user_id, amount, remaining=amount, mode, ratio_recharge, expires_at, source, source_ref, status='active')
    UPDATE users SET balance = balance + amount  -- 不动 total_recharged
```
关键：**所有走 Grant 的入口都不再 +total_recharged**，从源头修复污染。

**事务参数语义**（修订 P1-N1）：

`Grant` 走 `*ent.Tx`（不是 `*sql.Tx`），与项目 ent 事务模式一致：
- 调用方已开 ent 事务：通过 [dbent.TxFromContext(ctx)](backend/internal/service/auth_oauth_first_bind.go#L56) 在 ctx 上识别 tx，发放与上下文同事务
- 调用方未持事务：内部 `entClient.Tx(ctx)` 开短事务，函数返回前 commit
- 模式与 [promo_service.go:104](backend/internal/service/promo_service.go#L104) `dbent.NewTxContext(ctx, tx)`、[auth_oauth_first_bind.go:55-58](backend/internal/service/auth_oauth_first_bind.go#L55-L58) `tx := dbent.TxFromContext(ctx)` 一致

`amount = 0` 是合法输入：OAuth 首登的 `providerDefaults.Balance` 可能为 0（管理员只配置订阅/并发），现有 [keybind/balance.go:55](backend/internal/keybind/balance.go#L55) 也是这个语义。Engine 在最外层早返回，不写 `user_gifts` 行、不动 `users.balance`。单测必须覆盖 `amount=0` 路径。

### 扣费（`AllocateAndDeduct`）— 三阶段算法

输入：`userID`, `totalCost`（decimal）；前置条件：调用方持有事务 `tx`。

**Step 0 · 加锁读取（防 P0-6 超扣）**

```sql
-- 1. 锁 users 行（防止与 Grant / refund 并发覆盖）
SELECT id, balance FROM users WHERE id = $userID FOR UPDATE;

-- 2. 锁 user_gifts active 行，按 id ASC 顺序（防死锁）
SELECT id, remaining, deduction_mode, ratio_recharge, expires_at
FROM user_gifts
WHERE user_id = $userID AND status = 'active'
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY id ASC
FOR UPDATE;
```
所有路径（AllocateAndDeduct、过期清理、对账）必须**先 users 后 user_gifts**、user_gifts 内**按 id ASC**加锁，杜绝循环依赖。

**Step 1 · 计算分摊（纯函数，全程 decimal）**

```
remaining_to_charge = totalCost
gift_deltas = {}                # gift_id → 减量

# 第一阶段：priority 类（按 expires_at ASC, id ASC 排序）
for g in priority_gifts:
    take = min(g.remaining, remaining_to_charge)
    gift_deltas[g.id] = take
    remaining_to_charge -= take
    if remaining_to_charge == 0: break

# 第二阶段：ratio 类（按 ratio_recharge ASC, expires_at ASC, id ASC）
# ratio_recharge 越小赠金消耗越快 → 用户更划算 → 优先扣完
recharge_pool_avail = total_balance - Σ(priority remaining 扣后) - Σ(ratio remaining)
for g in ratio_gifts:
    if remaining_to_charge == 0: break
    # 这一段用 g 时：每扣 1 单位 recharge → 同步扣 g.ratio_recharge 单位 g
    # 设这段总扣 T，分摊：recharge_part = T/(1+r), gift_part = T*r/(1+r)
    cap_by_gift = g.remaining * (1 + g.ratio_recharge) / g.ratio_recharge
    cap_by_recharge = recharge_pool_avail * (1 + g.ratio_recharge)
    T = min(remaining_to_charge, cap_by_gift, cap_by_recharge)
    gift_part = T * g.ratio_recharge / (1 + g.ratio_recharge)
    recharge_part = T - gift_part
    gift_deltas[g.id] = gift_part
    recharge_pool_avail -= recharge_part
    remaining_to_charge -= T

# 第三阶段：剩余 → recharge_pool
recharge_extra = remaining_to_charge   # 可能为 0
remaining_to_charge = 0

# 舍入收口：把所有 gift_deltas 与 recharge_part 累加，与 totalCost 比对
# 误差归到链尾最后一项
```

**Step 2 · 执行更新（事务内）**

```sql
-- 1. 多行 UPDATE user_gifts，每行 remaining -= delta，归零时改 status='exhausted'
UPDATE user_gifts SET
  remaining = remaining - $delta,
  status = CASE WHEN remaining - $delta <= 0 THEN 'exhausted' ELSE status END,
  updated_at = NOW()
WHERE id = $gift_id;

-- 2. 一次 UPDATE users，只对总余额做 totalCost 一次扣减（保持现有 SQL 形态不变）
UPDATE users SET balance = balance - $totalCost, updated_at = NOW()
WHERE id = $userID AND deleted_at IS NULL
RETURNING balance;
```

**Step 3 · ratio gift 联动作废检查**

`recharge_pool` 触底（≤ 0）时，把所有仍 active 的 ratio gift 一起作废：

```sql
-- 1. 锁定要作废的行并取出原 remaining
WITH to_revoke AS (
  SELECT id, remaining
  FROM user_gifts
  WHERE user_id = $userID AND status = 'active' AND deduction_mode = 'ratio'
  FOR UPDATE
),
-- 2. 作废赠金
upd AS (
  UPDATE user_gifts SET remaining = 0, status = 'revoked', updated_at = NOW()
  WHERE id IN (SELECT id FROM to_revoke)
)
-- 3. 同步从 users.balance 扣掉赠金那部分（对应"残留 remaining"在 balance 里的份额）
UPDATE users SET balance = balance - (SELECT COALESCE(SUM(remaining),0) FROM to_revoke), updated_at = NOW()
WHERE id = $userID;
```
只在 Step 2 后实测 `recharge_pool ≤ 0` 时才走这一步；正常路径跳过。

**不变量逐步验证**：
- Step 2 的 `Σ(gift 减量) + recharge_extra = totalCost` → `total_balance` 减 totalCost 后仍 ≡ `recharge_pool + Σ(remaining)`
- Step 3 把"残留 ratio gift remaining"从 balance 一次性扣掉 + remaining → 0，仍守恒

### 算法走查例（写入计划稿便于评审/测试对照）

初始：`total_balance = 100`，含 `priority gift A=20`、`ratio gift B=30 (ratio_recharge=2.0)`、`recharge_pool=50`。
扣费 `totalCost = 60`：

| 步骤 | A.remaining | B.remaining | recharge_pool | total_balance | 说明 |
|------|------------:|------------:|--------------:|--------------:|------|
| 初始 | 20 | 30 | 50 | 100 | — |
| Step1 priority | 0 | 30 | 50 | 80 | A 吃 20，剩余待扣 40 |
| Step2 ratio B | 0 | 30 - 40·2/3 = 30 - 26.67 = 3.33 | 50 - 40·1/3 = 50 - 13.33 = 36.67 | 40 | B 是 2:1 比例，每扣 1 充值同步扣 2 赠金；T=40 分摊：gift_part=26.67, recharge_part=13.33 |
| 不变量 | — | — | — | 36.67+3.33=40 | ✓ 等于 total_balance |

再扣 `totalCost = 50`：

| 步骤 | B.remaining | recharge_pool | total_balance | 说明 |
|------|------------:|--------------:|--------------:|------|
| 初始 | 3.33 | 36.67 | 40 | — |
| Step2 cap_by_gift | 3.33·3/2=5.0 | — | — | B 最多承担总扣 5（包含赠金 3.33 + 充值 1.67）|
| Step2 应用 | 0 | 36.67-1.67=35 | 35 | B 用尽 |
| Step3 第三阶段 | 0 | 35-45=-10 | — | 剩 45 全压 recharge_pool，触底 |
| Step3 联动作废 | — | — | — | 没有其他 ratio gift，跳过 |
| 收尾 | 0 | -10 | -10 | recharge_pool 透支 → 见下节"透支策略" |

> 走查例为可读性截到 2 位小数；实际算法在 `decimal.Decimal` 域里保留 8 位（`Round(8, RoundHalfUp)`），舍入误差归到链尾最后一项的减量上，确保 `Σ(gift 减量) + recharge 减量 ≡ totalCost` 严格相等（修订 P2-N1）。

### 透支策略（与现有口径一致）

[user_repo.go:714 DeductBalance](backend/internal/repository/user_repo.go#L714) 当前允许 balance 扣到负值（[user_repo_integration_test.go:391 TestDeductBalance_AllowsOverdraft](backend/internal/repository/user_repo_integration_test.go#L391)）。赠金引擎保持这一现状：`recharge_pool` 可以透支，触底之后才作废 ratio gift；不在引擎层引入"扣不动就拒绝"的新行为，避免改变现有计费失败语义。

---

## 接入点改造清单

### 扣费侧

#### 主路径（生产）
[backend/internal/repository/usage_billing_repo.go:108-146](backend/internal/repository/usage_billing_repo.go#L108-L146)：

```go
// 改后
if cmd.BalanceCost > 0 {
    newBalance, err := r.giftEngine.AllocateAndDeduct(ctx, tx, cmd.UserID, cmd.BalanceCost)
    if err != nil {
        return err
    }
    result.NewBalance = &newBalance
}
```
`giftEngine` 注入到 `usageBillingRepository`，签名见下"模块结构"。其余 4 个维度（subscription / api_key quota / rate limit / account quota）保持不变。

#### Legacy fallback（一致性同步改造）
[backend/internal/service/gateway_service.go:8014](backend/internal/service/gateway_service.go#L8014) 的 `postUsageBilling`：
```go
// 改后：替换 deps.userRepo.DeductBalance
if err := deps.giftEngine.AllocateAndDeductSimple(billingCtx, p.User.ID, cost.ActualCost); err != nil {
    slog.Error("deduct balance failed", ...)
}
```
（`AllocateAndDeductSimple` 内部自己开一个独立短事务，不依赖外部 tx，因为这条路径没有 `usage_billing_dedup` 保护）

#### 退款（修订 P1-4 + P1-N2 · 透支保护与并发竞态）
[backend/internal/service/payment_refund.go:272](backend/internal/service/payment_refund.go#L272) `evaluateBalanceDeduction` 与 [行 288 ExecuteRefund](backend/internal/service/payment_refund.go#L288) 改为两阶段防御：

阶段 A（评估，[行 272](backend/internal/service/payment_refund.go#L272)）：
```go
// 改前
p.BalanceToDeduct = math.Min(p.RefundAmount, u.Balance)

// 改后
rechargePool, _ := giftEngine.GetRechargePool(ctx, u.ID)  // u.Balance - Σ(active gifts.remaining)
p.BalanceToDeduct = math.Min(p.RefundAmount, rechargePool)
```

阶段 B（执行，[行 288](backend/internal/service/payment_refund.go#L288)）—— **新增**，杜绝评估-执行间的并发扣费消耗充值池：
```go
// 改前
if err := s.userRepo.DeductBalance(ctx, p.Order.UserID, p.BalanceToDeduct); err != nil { ... }

// 改后：开短事务，事务内 FOR UPDATE 重新读 recharge_pool 并取 min
actualDeducted, err := giftEngine.DeductFromRechargePool(ctx, p.Order.UserID, p.BalanceToDeduct)
if err != nil { ... }
p.BalanceToDeduct = actualDeducted   // 真实扣减额回写，审计日志使用
```
`DeductFromRechargePool` 在事务内：
1. `SELECT id FROM users WHERE id=$1 FOR UPDATE`
2. `SELECT remaining FROM user_gifts WHERE user_id=$1 AND status='active' ... ORDER BY id ASC FOR UPDATE`
3. 计算 `cap = balance - Σ(remaining)`，返回 `cap` 与传入额度的较小值
4. `UPDATE users SET balance = balance - <actual>`，赠金行不动

**不变量保持**：退款最多扣 `recharge_pool`，赠金始终 ≥ 0；并发场景下事务 + FOR UPDATE 串行化，不会透支赠金。审计日志记录 `actualDeducted`，与 `RefundAmount` 的差额由 `force` 决定后续行为（既有逻辑不变）。

### 发放侧

| 入口 | 文件:行 | 改造 | 默认参数 |
|------|---------|------|---------|
| 绑 key | [keybind/balance.go:54](backend/internal/keybind/balance.go#L54) `entUserBalanceUpdater.AddBalanceAndTotalRecharged` | 重命名为 `GrantBindKeyGift` 调 `giftEngine.Grant`；移除 `AddTotalRecharged` | `mode=priority`, `expires_at=NULL`, `source='keybind'` |
| OAuth 首登 | [auth_oauth_first_bind.go:81](backend/internal/service/auth_oauth_first_bind.go#L81) | 用 `giftEngine.Grant` 替换 `UpdateOneID().AddBalance()` | `mode=priority`, `expires_at=NULL`（可后续配置）, `source='oauth_first_bind'` |
| 优惠码 | [promo_service.go:127](backend/internal/service/promo_service.go#L127) | 用 `giftEngine.Grant` 替换 `userRepo.UpdateBalance` | `mode=priority`, 沿用 promo_code 自身的 `expires_at`（如有）, `source='promo_code'`, `source_ref=promo_code_usage_id` |
| 兑换码 | [redeem_service.go:448](backend/internal/service/redeem_service.go#L448) | **不改** | 用户决策：本次不区分赠金型 |
| affiliate | [affiliate_repo.go:291](backend/internal/repository/affiliate_repo.go#L291) | **不改** | 用户决策：保持现状 |
| 管理员后台 | [user_repo.go:694](backend/internal/repository/user_repo.go#L694) | **不改** | 充值/补偿路径，按既有 `+balance + total_recharged` |

### 模块结构

新增包 `backend/internal/gift/`：

- [backend/internal/gift/engine.go](backend/internal/gift/engine.go)：核心 `Engine` 类型
  - `Grant(ctx, GrantInput) (*UserGift, error)` — 自动识别 `dbent.TxFromContext(ctx)`，nil 时内部开短事务；`amount<=0` 早返回
  - `AllocateAndDeduct(ctx, tx *sql.Tx, userID int64, totalCost float64) (newBalance float64, err error)` — 必须传 raw tx（usage_billing_repo 主路径与原有 `*sql.Tx` 一致）
  - `AllocateAndDeductSimple(ctx, userID, totalCost float64) error` — 内部开短事务（legacy fallback）
  - `DeductFromRechargePool(ctx, userID int64, requestedAmount float64) (actualDeducted float64, err error)` — 退款专用，事务内 FOR UPDATE 重校验充值池上限
  - `GetRechargePool(ctx, userID) (float64, error)` — 评估阶段查询接口（无锁）
  - `GetGiftBalance(ctx, userID) (float64, error)` — Profile API 用
- [backend/internal/gift/allocator.go](backend/internal/gift/allocator.go)：纯函数 `Allocate(input AllocateInput) AllocateResult`，不碰 IO，便于单测
- [backend/internal/gift/repository.go](backend/internal/gift/repository.go)：薄包装 `*ent.Client` + raw `*sql.DB`（与 usage_billing_repo 同样混用模式）
- [backend/internal/gift/expirer.go](backend/internal/gift/expirer.go)：过期清理服务，模仿 [subscription_expiry_service.go:49](backend/internal/service/subscription_expiry_service.go#L49) 的 ticker goroutine
- [backend/internal/gift/types.go](backend/internal/gift/types.go)：DTO（`GrantInput`、`UserGift`、`AllocateInput/Result`）

`Engine` 通过 wire 注入到：
- `usageBillingRepository`（主扣费路径）
- `keybind.Service`（绑 key 发放）
- `AuthService`（OAuth 首登）
- `PromoService`（优惠码）
- `PaymentService`（退款查询 recharge_pool）
- `UserHandler`（Profile API 查询 gift_balance）

---

## 展示 / 缓存 / 过期清理

### Profile API
[backend/internal/handler/dto/types.go](backend/internal/handler/dto/types.go) 的 `UserResponse` 增加两个字段（叠加返回，不破坏老前端）：

```go
type UserResponse struct {
    // 现有字段保持不变
    Balance         float64 `json:"balance"`           // = total_balance
    GiftBalance     float64 `json:"gift_balance"`      // 新增：Σ active gifts.remaining
    RechargeBalance float64 `json:"recharge_balance"`  // 新增：balance - gift_balance
    // ...
}
```
[backend/internal/handler/user_handler.go](backend/internal/handler/user_handler.go) `GetProfile` 用 `giftEngine.GetGiftBalance(userID)` 计算。前端 Type [frontend/src/types/index.ts:88](frontend/src/types/index.ts#L88) 的 `User.balance` 注释更新为"= recharge_balance + gift_balance"。

### 缓存层（修订 P1-7）
[billing_cache_service.go:357 QueueDeductBalance](backend/internal/service/billing_cache_service.go#L357) 仍按现有"用户总余额"语义工作，**不需要感知 gift/recharge 拆分**——它的单字段缓存对应 `users.balance`，与 SoT 一致。Profile API 的 `gift_balance` / `recharge_balance` 走"DB 直查"（`SELECT SUM(remaining) FROM user_gifts WHERE ... AND status='active'`），不进 cache，避免引入新缓存一致性问题。

### 过期清理任务（修订 P1-6）
新增 [backend/internal/gift/expirer.go](backend/internal/gift/expirer.go)，模仿 [account_expiry_service.go:34](backend/internal/service/account_expiry_service.go#L34)、[subscription_expiry_service.go:49](backend/internal/service/subscription_expiry_service.go#L49) 的实现：

- 启动一个 goroutine，`time.NewTicker(10 * time.Minute)` 触发
- 每次扫描 `expires_at < NOW() AND status = 'active'`（用 `idx_user_gifts_expiry_sweep` 部分索引）
- 按 `user_id` 分批处理；单个用户事务内：
  ```sql
  WITH to_expire AS (
    SELECT id, remaining FROM user_gifts
    WHERE user_id = $1 AND expires_at < NOW() AND status = 'active'
    FOR UPDATE
  ),
  upd AS (
    UPDATE user_gifts SET remaining = 0, status = 'expired', updated_at = NOW()
    WHERE id IN (SELECT id FROM to_expire)
  )
  UPDATE users SET balance = balance - (SELECT COALESCE(SUM(remaining),0) FROM to_expire)
  WHERE id = $1;
  ```
- 加锁顺序与 AllocateAndDeduct 一致（先 users 后 user_gifts）
- 失败重试：sleep + 下个 tick 自然重试，不引入额外重试机制

### 灰度策略（修订 P2-3）
项目无 feature flag 框架。**采用硬切换**：上线时所有发放路径改为 Grant，回滚靠 git revert。理由：双路径会让"扣费一致性"窗口扩大（旧 +balance 路径与新 Grant 路径写入语义不同），引入更难诊断的 bug。一次性上线 + 严密 e2e 测试更稳。

---

## 修复历史污染（独立 PR · 修订 P2-4）

绑 key 改造之前的 commit `32df9534` 已经把绑 key 赠金累加进 `total_recharged`。修复脚本作为**独立 plan/PR** 处理，不混在本次：

- 新建 [docs/pending-plans/total-recharged-cleanup.md](docs/pending-plans/total-recharged-cleanup.md)
- 反查窗口：从 commit `32df9534` 部署日期开始，扫 `user_keybind_logs` 反推赠金额
- 一次性 SQL：`UPDATE users SET total_recharged = total_recharged - <赠金额> WHERE id = ?`
- 不影响本计划落地

---

## 验证方案

### 单元测试 [backend/internal/gift/allocator_test.go](backend/internal/gift/allocator_test.go)

纯函数 `Allocate` 的表驱动测试覆盖：
- 纯 priority：1 笔 priority + 充值 → 先吃赠金
- 纯 ratio：1 笔 `ratio_recharge=2.0` + 充值 → 比例分摊正确
- 多笔 ratio：低比例（消耗快）先于高比例耗尽
- 充值耗尽：ratio gift 联动作废 + balance 同步扣
- priority + ratio + recharge 混合：阶段顺序正确
- 过期 gift 不参与分摊
- 极小值（0.00000001）`decimal.Equal` 严格断言
- 多笔同 expires_at 的 priority：按 id ASC tie-break，无 flake
- 扣费 = 0：no-op
- ratio_recharge 边界（极大、极小）

### 集成测试（跑真 PG）

[backend/internal/gift/engine_integration_test.go](backend/internal/gift/engine_integration_test.go)：
- 100 个并发 goroutine 扣同一用户：验证 `Σ(扣减) ≡ totalCost · 100`，无超扣
- Grant + AllocateAndDeduct + 查 profile：`gift_balance` 正确
- 模拟过期清理任务与扣费并发：不死锁、不丢账
- 退款：充值后 + Grant 赠金 + 退款 → `recharge_pool` 减少，赠金不变

### 端到端冒烟

1. 启动后端 → 注册新用户 → 绑 key
2. 调一次 API → 查 `/user/profile`：`gift_balance`、`recharge_balance` 拆分正确
3. DB 直查 `user_gifts` 行的 `remaining`、`status`
4. 触发 ratio gift 联动作废（构造小 recharge_pool + 大 ratio gift）

### upstream 合并演练

- 跑 `git merge upstream/main` 模拟拉取 upstream 修改 `users` 表的某个无关字段（如新增 timezone 列），确认仅 `ent/*.go` 生成代码冲突，schema 文件本身零冲突
- 把"重生成 + 验证"步骤写入 [docs/upstream-merge-runbook.md](docs/upstream-merge-runbook.md)（与本计划同 PR）

### 对账任务（修订 P2-7）

新增每日任务（复用过期清理同款 ticker，单独函数）：
- 扫描所有用户：`SUM(active gifts.remaining)` vs `users.balance` 减实际"充值池"是否一致
- 不一致时打 warning + 写 metrics（`gift_invariant_mismatch_total`），**不自动修复**

### Prometheus 指标（修订 P2-N3）

赠金涉及钱，需可观测性。在 `gift.Engine` 关键路径埋点：
- `gift_grant_total{source}` — Grant 计数（按 source 分维度）
- `gift_consumed_total{deduction_mode}` — AllocateAndDeduct 中按模式累计的扣费
- `gift_expired_total` — 过期清理任务作废条数
- `gift_revoked_total` — ratio 联动作废条数
- `gift_invariant_mismatch_total` — 对账任务发现的不一致用户数
- `gift_engine_duration_seconds{op}` — 关键操作耗时直方图（`grant`/`allocate_deduct`/`expire_sweep`）

---

## 关键文件清单

新增：
- [backend/ent/schema/user_gift.go](backend/ent/schema/user_gift.go) — ent schema
- [backend/migrations/142_user_gifts.sql](backend/migrations/142_user_gifts.sql) — 建表 + 部分索引
- [backend/internal/gift/types.go](backend/internal/gift/types.go) — DTO
- [backend/internal/gift/allocator.go](backend/internal/gift/allocator.go) — 纯函数分摊算法
- [backend/internal/gift/allocator_test.go](backend/internal/gift/allocator_test.go) — 单元测试
- [backend/internal/gift/engine.go](backend/internal/gift/engine.go) — Engine（IO 层）
- [backend/internal/gift/repository.go](backend/internal/gift/repository.go) — ent + raw SQL 包装
- [backend/internal/gift/expirer.go](backend/internal/gift/expirer.go) — 过期清理 ticker
- [backend/internal/gift/engine_integration_test.go](backend/internal/gift/engine_integration_test.go) — 集成测试
- [docs/upstream-merge-runbook.md](docs/upstream-merge-runbook.md) — upstream 合并操作手册

修改（最小化）：
- [backend/ent/schema/user.go](backend/ent/schema/user.go) — `Edges()` 末尾追加一行
- [backend/internal/repository/usage_billing_repo.go](backend/internal/repository/usage_billing_repo.go) — `applyUsageBillingEffects` 调赠金引擎
- [backend/internal/service/gateway_service.go](backend/internal/service/gateway_service.go) — `postUsageBilling` 兜底改造
- [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go) — `entUserBalanceUpdater` 改 `Grant`
- [backend/internal/service/auth_oauth_first_bind.go](backend/internal/service/auth_oauth_first_bind.go) — OAuth 首登改 `Grant`
- [backend/internal/service/promo_service.go](backend/internal/service/promo_service.go) — 优惠码改 `Grant`
- [backend/internal/service/payment_refund.go](backend/internal/service/payment_refund.go) — `evaluateBalanceDeduction` 用 `recharge_pool` 而非 `u.Balance`
- [backend/internal/handler/dto/types.go](backend/internal/handler/dto/types.go) — `UserResponse` 增 `gift_balance` / `recharge_balance`
- [backend/internal/handler/user_handler.go](backend/internal/handler/user_handler.go) — `GetProfile` 计算返回
- [backend/cmd/server/wire.go](backend/cmd/server/wire.go) + 重新生成的 [wire_gen.go](backend/cmd/server/wire_gen.go) — 注入 `gift.Engine`
- [frontend/src/types/index.ts](frontend/src/types/index.ts) — `User.balance` 注释 + `gift_balance` / `recharge_balance` 类型

---

## 复杂度与风险

| 维度 | 评分 | 说明 |
|------|------|------|
| 代码量 | 中 | 新增约 800 行（含测试），改动散落 9 个文件，每处 < 10 行 |
| 算法复杂度 | 中-高 | 三阶段 + ratio 比例分摊 + 联动作废；用 `decimal.Decimal` 严控精度 |
| 响应延迟 | 极小 | 异步 worker 池主路径；`sync` 降级时算法跑在请求 goroutine，但流式响应主体已写出，影响不超过 5ms |
| 并发风险 | 中 | 加锁顺序：先 users 后 user_gifts(id ASC)，杜绝死锁；`usage_billing_dedup` 已防 request_id 级重复 |
| 数据迁移风险 | 低 | 仅新增表与索引，不动 users；硬切换上线 |
| upstream 合并 | 高 | users schema 零改动；`Edges()` 仅追加一行；冲突面可控 |
| 测试投入 | 中 | 算法单测 ~20 case + 集成测试 + e2e 冒烟 |
| 前端改动 | 极小 | DTO 字段叠加返回；老前端零改动 |
| 回滚成本 | 低 | git revert 即可；DROP TABLE user_gifts 清理 |

**预估实现时间**（独立工作，含测试和验证）：
- Phase 1（核心引擎 + 异步扣费接入 + 绑 key 改造）：1.5~2 天
- Phase 2（其他发放点 + profile API + 退款语义修订 + 过期清理 + 对账任务）：1~1.5 天
- Phase 3（前端展示分离 + upstream merge runbook）：0.5 天
- 合计：**3~4 工作日**

### 风险一览

| # | 风险 | 缓解 |
|---|------|------|
| R1 | 算法 bug 导致超扣/漏扣 | 纯函数分摊 + 表驱动测试 + decimal 严格断言 |
| R2 | 并发扣同一用户 | 事务内 `SELECT ... FOR UPDATE`，加锁顺序固定 |
| R3 | `users.balance` ↔ `Σ gifts.remaining` 失配 | 每日对账任务 + metrics 告警，不自动修复 |
| R4 | upstream 改 `users.balance` 字段类型 | 我们只读不改，影响小；如真改单独处理 |
| R5 | decimal/float 边界舍入 | 链尾吸收舍入误差 + decimal.Equal 严格断言 |
| R6 | 退款透支：充值后未消费即退款，赠金保留 | 已知设计选择（用户决策），文档明示 |
| R7 | sync 降级时非流式响应延迟 | N 上限 50；产品监控告警 |
| R8 | redeem code / affiliate / 管理员路径未走赠金 | 用户决策保持现状，本次不动 |

---

# Phase 3：可配置发放 + 运维 API + 使用记录拆分 + Profile UI

## Context（Phase 3 增量）

Phase 1+2 已上线，所有发放路径硬编码 `priority` mode。当前需求扩展四块能力：

1. **绑 key 赠金参数可配置**：每条池 key 可独立配置 `deduction_mode / ratio_recharge / expires_after_days`，不修改 `api_keys` schema，附加表 A
2. **运维 API**：外部独立服务（`/home/chris/projects/sub2api-ops/`）通过 admin JWT 调用，覆盖"配置表 A / 任意发放赠金 / 列表查询 / 撤销 / 给 user 直接增额"
3. **使用记录区分**：`usage_logs` 新增 `gift_cost` + `recharge_cost`（decimal(20,10)），前端列表 + hover 浮窗显示赠金扣减
4. **Profile 页展示赠金**：`/api/v1/user/profile` 已返回 `gift_balance` / `recharge_balance`，前端在余额下方加一行不同颜色的赠金数字

不需要前端管理界面（运维侧自建）；**鉴权复用 admin JWT**（用户决策）；表 A **不设外键**（绑定后所有权转移，配置生命周期由运维清理）。

### 扣费时赠金过期行为澄清

**当前实现是"每次扣费实时查 DB，无缓存"**：
- [gift/repository.go:111-122 lockedSnapshot](backend/internal/gift/repository.go#L111-L122) 的 `WHERE expires_at IS NULL OR expires_at > NOW()` 在每次扣费时实时过滤
- ticker（[expirer.go:14 默认 10 分钟](backend/internal/gift/expirer.go#L14)）只负责把过期赠金的 status 置 expired 并扣回 users.balance；**不影响扣费正确性**
- 过期"瞬间"的并发：扣费会忽略已过期的赠金（按充值池扣），ticker 跑过后 balance 同步减回；不变量 `balance ≡ recharge_pool + Σ active remaining` 在两个时间点都成立
- 性能：每次扣费 ~1ms（FOR UPDATE 走 [`idx_user_gifts_user_active` 部分索引](backend/migrations/142_user_gifts.sql#L29-L31)）；单用户活跃 gift < 50 时延迟可忽略
- **不引入缓存层**：扣费跑在异步 worker pool，对延迟不敏感；缓存与 FOR UPDATE 协调成本不划算

Phase 3 不改这一行为。

---

## 1 · 绑 key 赠金配置表（表 A）

### Schema [backend/ent/schema/bind_key_gift_setting.go](backend/ent/schema/bind_key_gift_setting.go)

新增表 `bind_key_gift_settings`：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | bigserial PK | |
| `api_key_id` | int8 NOT NULL UNIQUE | 关联 `api_keys.id`；**不设外键**，由运维清理 |
| `deduction_mode` | varchar(16) NOT NULL CHECK IN ('priority','ratio') | |
| `ratio_recharge` | decimal(20,8) NULL | priority 必为 NULL；ratio 必 > 0，组合 CHECK |
| `expires_after_days` | int NULL | NULL=永不过期；正数=赠金 expires_at = grant_time + N 天 |
| `created_at` / `updated_at` | timestamptz | |

迁移：[backend/migrations/143_bind_key_gift_settings.sql](backend/migrations/143_bind_key_gift_settings.sql)，建表 + `UNIQUE(api_key_id)` + 索引（api_key_id 因 unique 自带）。

### ent edges
不在 `User.Edges()` 或 `APIKey.Edges()` 加 edge —— 表 A 与 api_keys 解耦，仅用 raw SQL 或独立 `BindKeyGiftSetting` 实体查询。

### 默认值约定
- 表 A 中**没有**该 api_key_id 的行 → 沿用现有硬编码：`priority`，无过期
- 有行 → 严格按行内配置发放

## 2 · keybind 发放路径改造

### 改动点 [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go)

`giftEngineUpdater` 现在持有 `*gift.Engine` + 一个 `BindKeyGiftSettingResolver`（新增接口）：

```go
type BindKeyGiftSettingResolver interface {
    // Resolve 按 api_key_id 查表 A，返回 nil 表示"无配置，走默认 priority"
    Resolve(ctx context.Context, apiKeyID int64) (*BindKeyGiftSetting, error)
}

type BindKeyGiftSetting struct {
    DeductionMode    gift.DeductionMode
    RatioRecharge    *float64
    ExpiresAfterDays *int
}
```

### 改动点 [backend/internal/keybind/service.go:330-345](backend/internal/keybind/service.go#L330-L345)

`Commit` 流程在调 `userBalanceUpdater` 前先 resolve：

```go
// 改前：
if giftAmount > 0 && s.userBalanceUpdater != nil {
    s.userBalanceUpdater.AddBalanceAndTotalRecharged(ctx, userID, giftAmount)
}

// 改后：把 apiKeyID 一起传下去（接口签名扩展）
if giftAmount > 0 && s.userBalanceUpdater != nil {
    s.userBalanceUpdater.GrantForBindKey(ctx, userID, giftAmount, apiKeyID)
}
```

`GrantForBindKey` 内部：

1. `resolver.Resolve(ctx, apiKeyID)` 取配置（nil → priority 默认）
2. 计算 `expires_at = now + days`（若配置）
3. 调 `engine.Grant(ctx, GrantInput{Mode, RatioRecharge, ExpiresAt, Source: SourceKeybind, SourceRef: "api_key:<id>"})`

`UserBalanceUpdater` 接口废弃旧的 `AddBalanceAndTotalRecharged`，改为新方法 `GrantForBindKey(ctx, userID, amount, apiKeyID)`。同步改 [keybind/service.go:331](backend/internal/keybind/service.go#L331) 的调用。

### 实现 [backend/internal/keybind/gift_settings_repo.go](backend/internal/keybind/gift_settings_repo.go)

`Resolver` 的 raw SQL 实现：`SELECT deduction_mode, ratio_recharge, expires_after_days FROM bind_key_gift_settings WHERE api_key_id = $1`。

---

## 3 · usage_logs 区分 gift_cost / recharge_cost

### Schema 扩展 [backend/ent/schema/usage_log.go](backend/ent/schema/usage_log.go)

新增字段：

```go
field.Float("gift_cost").
    SchemaType(map[string]string{dialect.Postgres: "decimal(20,10)"}).
    Default(0),
field.Float("recharge_cost").
    SchemaType(map[string]string{dialect.Postgres: "decimal(20,10)"}).
    Default(0),
```

迁移 [backend/migrations/144_usage_log_gift_breakdown.sql](backend/migrations/144_usage_log_gift_breakdown.sql)：`ALTER TABLE usage_logs ADD COLUMN gift_cost / recharge_cost ... DEFAULT 0`。历史行 `gift_cost = 0, recharge_cost = actual_cost` 由 DEFAULT 自然填充。

**不变量**：`gift_cost + recharge_cost = actual_cost`（订阅扣费路径下两者均为 0）。

### 引擎接口扩展 [backend/internal/gift/engine.go](backend/internal/gift/engine.go)

`AllocateAndDeduct` 当前只返 `newBalance`。新增：

```go
type AllocateBreakdown struct {
    GiftCost     float64  // Σ(gift deltas) + revoked remaining (作废的也算"消耗给用户的"赠金)
    RechargeCost float64  // recharge pool 减量
}

func (e *Engine) AllocateAndDeductWithBreakdown(
    ctx context.Context, tx *sql.Tx, userID int64, totalCost float64,
) (newBalance float64, breakdown AllocateBreakdown, err error)
```

旧 `AllocateAndDeduct` 保留为简单封装（丢弃 breakdown），调用方按需选用。

**关键决策**：ratio 联动作废的 `RevokedRemaining` **不算**进 `gift_cost`，因为它不是"用户消费"而是"作废"——usage_log 应只反映本次请求实际消耗的赠金。`RevokedRemaining` 走单独的 metrics（`gift_revoked_total`，已在计划里）。

### 落到 usage_log

1. `UsageBillingApplyResult` 增加 `GiftCost *float64` + `RechargeCost *float64`
2. [usage_billing_repo.go:108-146](backend/internal/repository/usage_billing_repo.go#L108-L146) `applyUsageBillingEffects` 调用新接口，把 breakdown 写进 result
3. [gateway_service.go:8523 applyUsageBilling](backend/internal/service/gateway_service.go#L8523) 调用方拿到 result 后，赋值到 `usageLog.GiftCost / RechargeCost`
4. `writeUsageLogBestEffort` (line 8542) 落库

[backend/internal/handler/dto/types.go UsageLog](backend/internal/handler/dto/types.go) DTO 增加 `gift_cost`/`recharge_cost` 字段透传。

### 前端展示 [frontend/src/views/user/UsageView.vue:439-493](frontend/src/views/user/UsageView.vue#L439-L493)

- **列表"费用"列**：当 `gift_cost > 0` 时，主数字仍显示 `actual_cost`，**下方加一个小字赠金扣减**（不同颜色），如 `$0.05 / 赠金 $0.03`
- **hover 浮窗**：在"实际扣除 $X"那一行下方加"其中赠金 $Y / 充值 $Z"两行，颜色区分

具体实现按附图截图风格调整；TS 类型 [frontend/src/types/index.ts:88](frontend/src/types/index.ts#L88) 同步加 `gift_cost?: number` / `recharge_cost?: number`。

---

## 4 · Profile 页展示赠金

### 后端补充：即将过期赠金额

[backend/internal/gift/engine.go](backend/internal/gift/engine.go) 新增方法：

```go
// GetGiftBalanceBreakdown 返回 (gift_balance, expiring_soon)
// expiring_soon = Σ(active gifts.remaining WHERE expires_at IS NOT NULL AND expires_at < NOW() + 120h)
// 不变量：expiring_soon ≤ gift_balance
func (e *Engine) GetGiftBalanceBreakdown(ctx context.Context, userID int64) (giftBalance, expiringSoon float64, err error)
```

实现：单条 SQL 同时算两个值，避免两次往返：
```sql
SELECT
  COALESCE(SUM(remaining), 0) AS gift_balance,
  COALESCE(SUM(CASE WHEN expires_at IS NOT NULL
                     AND expires_at < NOW() + INTERVAL '120 hours'
                    THEN remaining END), 0) AS expiring_soon
FROM user_gifts
WHERE user_id = $1 AND status = 'active'
  AND (expires_at IS NULL OR expires_at > NOW())
```

阈值 120 小时（5 天）目前**硬编码常量 `GiftExpiringSoonThreshold = 120 * time.Hour`** 在 `gift` 包里，便于将来需要时改成可配。

### Profile API 扩展

[backend/internal/handler/dto/types.go User](backend/internal/handler/dto/types.go) 增加字段：

```go
type User struct {
    Balance              float64 `json:"balance"`
    GiftBalance          float64 `json:"gift_balance"`
    GiftExpiringSoon     float64 `json:"gift_expiring_soon"`  // 新增：120h 内即将过期的赠金额
    RechargeBalance      float64 `json:"recharge_balance"`
    // ...
}
```

[backend/internal/handler/user_handler.go buildUserProfileResponse](backend/internal/handler/user_handler.go) 改为调 `GetGiftBalanceBreakdown` 一次拿两个值，分别赋值到 `GiftBalance` 与 `GiftExpiringSoon`。

### 前端

- [frontend/src/types/index.ts:88](frontend/src/types/index.ts#L88) `User` 类型加 `gift_balance?: number` / `gift_expiring_soon?: number` / `recharge_balance?: number`（Phase 2 后端已返回前两者，本次再加 expiring_soon）
- [frontend/src/components/user/profile/ProfileInfoCard.vue:61-95](frontend/src/components/user/profile/ProfileInfoCard.vue#L61-L95) 在"账户余额"主数字下方追加：
  - 一行赠金 `赠金 $X.XX`（金色 / 浅紫，与 balance 主色区分）
  - **当 `gift_expiring_soon > 0` 时**，赠金数字后追加一个橙色/红色小字提示 `(其中 $Y.YY 即将过期)`
  - 当 `gift_balance == 0` 时整行隐藏

后端不返回过期阈值（`120h`）的具体数字给前端；前端只显示金额，文案"即将过期"语义由产品决定（5 天内）。如以后阈值改成可配，前端可加 `gift_expiring_soon_hours` 字段同步 tooltip 文案。

---

## 5 · 运维 API

### 鉴权
**复用现有 admin JWT 中间件**（用户决策）。所有 ops API 挂在 `/api/v1/admin/ops/gifts/*`，由 [admin_auth.go](backend/internal/server/middleware/admin_auth.go) 把关。运维系统（`/home/chris/projects/sub2api-ops/`）拿管理员账号通过 `/api/v1/auth/login` 获 JWT，存本地反复使用并按 JWT TTL 自动刷新。

### Endpoint 列表

#### A. 表 A 配置管理（绑 key 赠金参数）

| Method | Path | Body / Query | 说明 |
|--------|------|------|------|
| POST | `/api/v1/admin/ops/bind-key-gifts` | `{api_key_id, deduction_mode, ratio_recharge?, expires_after_days?}` | 创建/upsert 配置（同 api_key_id 已存在则更新） |
| GET | `/api/v1/admin/ops/bind-key-gifts/:api_key_id` | — | 查单条 |
| GET | `/api/v1/admin/ops/bind-key-gifts?page=1&page_size=50` | — | 列表（分页） |
| DELETE | `/api/v1/admin/ops/bind-key-gifts/:api_key_id` | — | 删除（绑 key 后可清理） |

#### B. 赠金账本运维

| Method | Path | Body | 说明 |
|--------|------|------|------|
| POST | `/api/v1/admin/ops/gifts/grant` | `{user_id, amount, deduction_mode, ratio_recharge?, expires_at?, source, source_ref?}` | **任意 mode 给指定用户发赠金**；source 通常是 `manual` 或自定义 |
| GET | `/api/v1/admin/ops/gifts?user_id=X&status=&page=&page_size=` | — | 列出某用户/某状态的赠金记录 |
| GET | `/api/v1/admin/ops/gifts/:gift_id` | — | 查单笔 |
| POST | `/api/v1/admin/ops/gifts/:gift_id/revoke` | `{reason?}` | 撤销：status=revoked, remaining=0, 同步扣 users.balance |
| POST | `/api/v1/admin/ops/gifts/users/:user_id/recharge` | `{amount}` | **给充值池增额**（amount > 0：+balance + total_recharged；amount < 0：-balance，不动 total_recharged，运维负责合理性） |

#### C. 运维查询

| Method | Path | 说明 |
|--------|------|------|
| GET | `/api/v1/admin/ops/users/:user_id/balance` | 返回 `{total_balance, gift_balance, recharge_balance, gifts: [...]}` |

### 实现

- [backend/internal/handler/admin/gift_ops_handler.go](backend/internal/handler/admin/gift_ops_handler.go)：所有上面的 handler，注入 `*gift.Engine` + `*service.UserService`
- [backend/internal/service/gift_ops_service.go](backend/internal/service/gift_ops_service.go)（可选）：把"撤销 + 同步扣 balance"包装成事务方法 `RevokeGift(ctx, giftID, reason)`；引擎也可直接暴露
- 路由注册 [backend/internal/server/routes/admin.go](backend/internal/server/routes/admin.go) 新增 `registerGiftOpsRoutes(admin, h)`，与 `registerOpsRoutes` 同级

### 输入校验
- `amount > 0` 严格校验
- `deduction_mode` 枚举校验
- `ratio_recharge` 仅 ratio 模式必填且 > 0
- `expires_at` 必须是未来时间
- `revoke` 时校验 gift 当前 status='active'，否则返回 409

### 引擎方法补全 [backend/internal/gift/engine.go](backend/internal/gift/engine.go)

新增 ops 路径需要的方法：

```go
// RevokeGift 把指定 gift 置 revoked，同步扣 users.balance
// 失败返回；事务内处理；不允许撤销已 exhausted/expired/revoked 的赠金
func (e *Engine) RevokeGift(ctx context.Context, giftID int64, reason string) error

// ListGiftsByUser 列出某用户的赠金（分页）
func (e *Engine) ListGiftsByUser(ctx context.Context, userID int64, status Status, page, pageSize int) ([]UserGift, int64, error)

// GetGiftByID 查单笔
func (e *Engine) GetGiftByID(ctx context.Context, giftID int64) (*UserGift, error)
```

### 充值增额（给 recharge_pool 加钱）
**沿用现有 [user_repo.go:694 UpdateBalance](backend/internal/repository/user_repo.go#L694)**：`AddBalance + AddTotalRecharged`。这条路径已经是"真实充值"语义，复用即可，handler 仅做包装。

---

## 6 · 文件清单

新增：
- [backend/migrations/143_bind_key_gift_settings.sql](backend/migrations/143_bind_key_gift_settings.sql)
- [backend/migrations/144_usage_log_gift_breakdown.sql](backend/migrations/144_usage_log_gift_breakdown.sql)
- [backend/ent/schema/bind_key_gift_setting.go](backend/ent/schema/bind_key_gift_setting.go)
- [backend/internal/keybind/gift_settings_repo.go](backend/internal/keybind/gift_settings_repo.go)
- [backend/internal/handler/admin/gift_ops_handler.go](backend/internal/handler/admin/gift_ops_handler.go)
- [docs/pending-plans/赠金子系统/ops-api.md](docs/pending-plans/赠金子系统/ops-api.md) — 详细 API 列表（请求/响应示例），交付给运维系统作集成文档

修改：
- [backend/ent/schema/usage_log.go](backend/ent/schema/usage_log.go) — 加 gift_cost/recharge_cost 字段
- [backend/ent/schema/user.go](backend/ent/schema/user.go) — 不动；表 A 不挂 edge
- [backend/internal/keybind/balance.go](backend/internal/keybind/balance.go) — `UserBalanceUpdater` 接口改 `GrantForBindKey(ctx, userID, amount, apiKeyID)`
- [backend/internal/keybind/service.go](backend/internal/keybind/service.go) — Commit 调用传 apiKeyID
- [backend/internal/keybind/routes.go](backend/internal/keybind/routes.go) — 注入 resolver
- [backend/internal/gift/engine.go](backend/internal/gift/engine.go) — 加 `AllocateAndDeductWithBreakdown` / `RevokeGift` / `ListGiftsByUser` / `GetGiftByID`
- [backend/internal/repository/usage_billing_repo.go](backend/internal/repository/usage_billing_repo.go) — 改用 `WithBreakdown` 版本，`UsageBillingApplyResult` 加 `GiftCost`/`RechargeCost`
- [backend/internal/service/gateway_service.go](backend/internal/service/gateway_service.go) — `applyUsageBilling` 把 breakdown 写到 usageLog
- [backend/internal/handler/dto/types.go](backend/internal/handler/dto/types.go) — `UsageLog` DTO 加 `gift_cost`/`recharge_cost` 字段
- [backend/internal/server/routes/admin.go](backend/internal/server/routes/admin.go) — 注册 `registerGiftOpsRoutes`
- [frontend/src/types/index.ts](frontend/src/types/index.ts) — `User` 加 gift_balance/recharge_balance；`UsageLog` 加 gift_cost/recharge_cost
- [frontend/src/components/user/profile/ProfileInfoCard.vue](frontend/src/components/user/profile/ProfileInfoCard.vue) — 余额下方加一行赠金
- [frontend/src/views/user/UsageView.vue](frontend/src/views/user/UsageView.vue) — 列表费用列 + hover 浮窗加赠金行

---

## 7 · 验证

### 单元测试
- `bind_key_gift_settings` Repository 增删改查 + UNIQUE 约束行为
- `AllocateAndDeductWithBreakdown` 表驱动：纯 priority、纯 ratio、混合、ratio 联动作废 → 各自的 GiftCost/RechargeCost 计算正确
- `Engine.RevokeGift`：active 可撤销并扣 balance；非 active 报错；不变量保持

### 集成测试
- 运维 API：admin JWT 调用全 7 个端点，鉴权失败 401；表 A upsert 行为；revoke 后用户 balance 同步减
- 端到端：建表 A 配置 `ratio_recharge=2.0` → 绑 key → 检查 user_gifts 行 mode='ratio' + ratio_recharge=2.0
- usage_log 拆分：用户跑一次 API → `usage_logs` 行 `gift_cost + recharge_cost = actual_cost`

### 前端验证
- Profile 页：构造 gift_balance > 0 用户，刷新页面看到金色赠金行；gift_balance=0 时该行隐藏
- 使用记录：构造一笔 gift_cost > 0 的请求记录，列表费用列与 hover 浮窗显示赠金扣减

### 上线后烟雾
- 表 A 写入一行 → 绑 key → user_gifts 行 mode 正确
- 运维 API `revoke` → user_gifts.status='revoked' + users.balance 同步减
- 跑一次 API → usage_logs.gift_cost 非零（赠金用户）/ 全 recharge_cost（无赠金用户）

---

## 8 · 复杂度评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 代码量 | 中 | 后端约 600 行（含 ops handler + 引擎扩展 + 测试），前端约 80 行 |
| 算法复杂度 | 低 | breakdown 是 allocator 已有 GiftDeltas/RechargeDelta 的简单聚合 |
| 数据迁移 | 低 | 仅新增 1 表 + 2 列；历史 usage_logs 默认 0 自然兼容 |
| 接口变更 | 中 | `UserBalanceUpdater` 改签名（同包内仅 1 处调用），`UsageBillingApplyResult` 加字段（向后兼容） |
| 鉴权风险 | 低 | 复用 admin JWT，无新引入 |
| 前端改动 | 低 | 2 个文件改动 ≤ 80 行 |
| **预计工作量** | **2~2.5 天** | Phase 3.1 表 A + keybind 1d、Phase 3.2 usage_log breakdown 0.5d、Phase 3.3 ops API 1d、Phase 3.4 前端 0.5d |

风险：
- R3-1：运维 ops API `/users/:user_id/recharge` 接受负数 amount → 风控由运维侧负责，handler 不做业务限制
- R3-2：表 A 删除 api_keys 时不联动 → 数据老化由运维清理（用户决策）
- R3-3：`UserBalanceUpdater` 接口改名是 breaking change，需要确保 `keybind/service.go` 内部唯一调用点同步






