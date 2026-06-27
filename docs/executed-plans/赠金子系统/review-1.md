# 赠金子系统设计方案 · 第一轮评审

被评审计划：[/home/chris/.claude/plans/wobbly-herding-waffle.md](/home/chris/.claude/plans/wobbly-herding-waffle.md)
评审范围：与现有代码事实核对、设计自洽性、边界与遗漏

---

## 总评

方向合理：**新增 `user_gifts` 表 + 不动 `users.balance` SoT** 的策略，确实是当前最 upstream-merge 友好的做法；扣费走异步 worker 池的判断也成立。但计划稿存在多处与代码不符、边界不明、接入点遗漏的问题，**直接按现有版本落地会出错**。下面分项列出阻塞性问题（P0）、需要修订的问题（P1）和补充建议（P2）。

---

## P0 · 阻塞性问题（必须先修订计划再开工）

### P0-1 「响应已发出之后才扣费」的前提不成立

计划稿在 [行 124](/home/chris/.claude/plans/wobbly-herding-waffle.md#L124)、[行 128](/home/chris/.claude/plans/wobbly-herding-waffle.md#L128) 反复声称：
> `submitUsageRecordTask` 在 handler 写完 response 后才调用，所以仍然不影响客户端感知延迟

**与代码不符。** 实际位置 [backend/internal/handler/gateway_handler.go:511-537](backend/internal/handler/gateway_handler.go#L511-L537)：

```go
// 行 511：submitUsageRecordTask 在 SSE 响应仍在写出途中、handler return 之前就提交
h.submitUsageRecordTask(func(ctx context.Context) {
    if err := h.gatewayService.RecordUsage(ctx, ...) { ... }
})
return
```

`submitUsageRecordTask` 只是把任务投递到 pond worker 池，**响应是否已经写完**取决于：
- 流式响应：实际 SSE 帧由 `Forward`/upstream copy 阶段已经在写
- 非流式：到此处响应可能尚未 flush

更要命的是 **OverflowStrategy=`sync`** 的降级路径（[usage_record_worker_pool.go:25-27、429-432](backend/internal/service/usage_record_worker_pool.go)）会把整个 `RecordUsage` 跑在请求 goroutine 上。计划稿"sync 降级时仍然零延迟"的论断**没有代码依据**。

**整改建议**：

1. 把"零延迟"改为"绝大多数情况下异步、`sync` 降级时占用请求 goroutine 数毫秒"，**别再说"响应已发出"**。
2. 提供降级后的 SLA 估算：active gifts 数量上限（例如规定单用户活跃 gifts ≤ 50，否则告警），算法 O(N)，PG 单事务 N 次 UPDATE 的延迟上限。
3. 如果项目确实关心 `sync` 模式的扣费延迟，建议把"赠金分摊+多行 UPDATE"放到一个**独立 outbox**（参考项目已有 [scheduler_outbox](/home/chris/projects/sub2api/backend/internal/service/scheduler_outbox.go) 机制），与 `usage_billing_dedup` 解耦——但这会让"扣费一致性"模型变复杂，需要另一轮设计。

---

### P0-2 双重扣费路径的处理是模糊的

计划稿 [行 28](/home/chris/.claude/plans/wobbly-herding-waffle.md#L28) 说 `usage_service.go:125` "并非 gateway worker 主路径"，又在 [行 133](/home/chris/.claude/plans/wobbly-herding-waffle.md#L133) 说"如果该路径已经死代码可不改，需现场确认"——**这是重大不确定性**。

事实：
- [backend/internal/service/usage_service.go:122-129](backend/internal/service/usage_service.go#L122-L129) 确实存在 `userRepo.UpdateBalance(txCtx, req.UserID, -req.ActualCost)`，且写入了独立事务（line 131-135）
- 探索 agent 没找到直接调用 `UsageService.Create` 的入口，但**不能据此就断言它是死代码**

**整改建议**：

1. **开工前必须先 grep 全仓 + 测试代码**确认 `UsageService.Create` 是否仍被路由调用，结论写入计划。
2. 还有 [backend/internal/service/gateway_service.go:8014](backend/internal/service/gateway_service.go#L8014) 的 `userRepo.DeductBalance(billingCtx, p.User.ID, cost.ActualCost)` 和 [gateway_service.go:8176](backend/internal/service/gateway_service.go#L8176) 的 `billingCacheService.QueueDeductBalance` 计划稿**完全没列出**——这是计划稿"扣费唯一接入点"前提的重大缺口。请在计划里把整张「balance 扣减点全表」列清楚，每一处都写明是否要走赠金引擎。
3. 计划稿里"现有 11+ 处读写点不需要改写"的论断只对**只读**成立；**写入点必须逐个排查**，不能含糊。探索 agent 已列出 11 处主要写入点，应作为附录纳入计划。

---

### P0-3 「赠金不影响订阅/quota」的论断不成立

计划稿暗含一个假设：**只要 `users.balance` 扣得对，其他维度（订阅 daily/weekly/monthly_usage_usd、API key quota_used、account quota）就不需要动**。

事实（[usage_billing_repo.go:108-146](backend/internal/repository/usage_billing_repo.go#L108-L146)）：

```go
func (r *usageBillingRepository) applyUsageBillingEffects(...) error {
    if cmd.SubscriptionCost > 0 && cmd.SubscriptionID != nil { ... }   // 订阅维度
    if cmd.BalanceCost > 0 { ... }                                      // 余额维度
    if cmd.APIKeyQuotaCost > 0 { ... }                                  // API key 配额
    if cmd.APIKeyRateLimitCost > 0 { ... }                              // API key 限流
    if cmd.AccountQuotaCost > 0 { ... }                                 // 账号配额
}
```

需要计划明确的语义问题：

- 若用户有"赠金 + 订阅"组合：用赠金扣的部分**算不算订阅 daily/weekly/monthly_usage_usd**？
  - 算：用户用赠金跑完免费配额会推进订阅用量统计
  - 不算：需要在 cost 拆分阶段就把赠金消耗的那部分从 `SubscriptionCost` 里剔除
- 若 `BalanceCost > 0` 且 `APIKeyQuotaCost > 0` 同时发生：赠金扣的部分**是否计入 API key quota_used**？

这是产品决策，不是技术决策。**第一轮请补全产品规则。**

---

### P0-4 `users.balance` 是 `float64`，不是 `decimal`

计划稿 [行 93](/home/chris/.claude/plans/wobbly-herding-waffle.md#L93)：
> 全程使用 shopspring/decimal 或 math/big.Rat 计算，最后再转 float 落库（项目其他金额已是 decimal(20,8)）

事实（[backend/ent/schema/user.go:49-50](backend/ent/schema/user.go#L49-L50)）：
```go
field.Float("balance").SchemaType(map[string]string{dialect.Postgres: "decimal(20,8)"})
```

ent 的 Go 端类型是 `float64`，PG 列是 `decimal(20,8)`。这意味着：

1. 现有 `deductUsageBillingBalance` 走 `tx.QueryRowContext(... amount float64 ...)` ——**已经在 Go 端用 float 计算扣减**，引入精度污染
2. 比例分摊算法 `T / (1 + ratio)` 在 float 下不可避免有舍入误差，多次扣费后累计误差会让 `SUM(remaining) > users.balance` 或反之
3. 计划稿"先 decimal 算，最后转 float"的方案**会让赠金引擎与现有扣减口径冲突**

**整改建议**：

1. `user_gifts.remaining` 字段必须存为 `decimal(20,8)`，且 ent schema 用 `field.Other(...)` 或 `decimal.Decimal` 类型（参考已使用 `shopspring/decimal` 的 [payment_amounts.go](/home/chris/projects/sub2api/backend/internal/service/payment_amounts.go)）。
2. 算法层全程 `decimal.Decimal`，**最后 UPDATE `users.balance` 时确保「赠金各行 remaining 减量之和 + 充值池减量 = totalCost」精确相等**——给出舍入策略（例如把舍入误差全部归到充值池）。
3. 单测必须包含极小值与多笔扣费累计误差用例（计划已提到，但要明确 round-trip 严格相等的断言）。

---

### P0-5 「比例赠金作废」的语义有内部矛盾

计划稿 [行 91](/home/chris/.claude/plans/wobbly-herding-waffle.md#L91)：

> 每次扣费后，若充值池（= `users.balance - SUM(priority remaining) - SUM(ratio remaining)`）≤ 0，则把所有 `ratio` 类 active 赠金状态置 `expired`，对应 remaining 归 0，并从 `users.balance` 中扣掉这部分

矛盾点：

1. 充值池公式假设 `users.balance = 充值 + Σpriority remaining + Σratio remaining`，但发放时计划稿要求**只 +balance 不改 total_recharged**（[行 75](/home/chris/.claude/plans/wobbly-herding-waffle.md#L75) `Grant` 描述）——意味着**`users.balance` 的语义被偷偷扩展为"充值 + 赠金"**，这与计划稿声称的"`users.balance` 语义保持不变"自相矛盾（[行 14](/home/chris/.claude/plans/wobbly-herding-waffle.md#L14)）。
2. 步骤 5 又要"一次性 `users.balance -= totalCost`"，但比例阶段的扣减分摊本来就已经包含赠金部分 → 这一步会把赠金那一份**从 users.balance 重复扣一次**。
3. 比例赠金作废时再"从 `users.balance` 扣掉这部分" → 同上，赠金部分本来就包含在 balance 里，作废时应该是"把对应 remaining 直接清零并把这一份从 balance 减掉"——但计划稿没说清楚是"用户已实际消费的部分"还是"剩余未用的部分"。

**整改建议**：

把"`users.balance` = 真实充值池 + Σ active gifts remaining"的不变量**写在计划首段**，并：

1. 明确 `Grant` 语义：插入 `user_gifts(remaining=amount)` 同时 `users.balance += amount`（与现状一致），且 **`total_recharged` 绝不动**（修复 32df9534 的污染）。
2. 明确 `AllocateAndDeduct` 语义：本次扣 `T`，分摊到 priority/ratio/充值池后，**只对 `users.balance` 做一次 `-= T` UPDATE**，对 `user_gifts.remaining` 做多行 UPDATE，二者之和守恒。
3. 比例赠金作废 = "把 `remaining` 清零 + 同步 `users.balance -= 清零部分` + 状态置 expired"，**这是一次单独的额外 UPDATE**，不与本次扣费混在一起。

把上述不变量改成一个**贯穿全文的伪代码块**，比现在分散的描述清晰得多。

---

### P0-6 缺并发控制的具体方案

计划稿 [行 116](/home/chris/.claude/plans/wobbly-herding-waffle.md#L116) 说算法第一步是 `SELECT user_gifts WHERE user_id=? AND status='active' FOR UPDATE`。但事实是：

- 现有 `deductUsageBillingBalance` 用 `UPDATE ... RETURNING balance` 拿到新值，**没有先 `SELECT FOR UPDATE`**（[行 178-184](/home/chris/projects/sub2api/backend/internal/repository/usage_billing_repo.go#L178-L184)）。两个并发请求各自的 `UPDATE balance = balance - $1` 通过行锁串行化，结果正确。
- 引入赠金后，分摊算法**必须先读多行 user_gifts，再 update**——两个并发事务可能基于同一份 remaining 快照算出冲突的减量，最后 commit 都成功，导致**超扣**。

**整改建议**：

1. 在 `AllocateAndDeduct` 起手用 `SELECT id, remaining ... FROM user_gifts WHERE user_id = $1 AND status = 'active' ORDER BY id FOR UPDATE`，并对 `users` 也加 `SELECT id FROM users WHERE id=$1 FOR UPDATE`（避免 priority/ratio 排序读到与 `users.balance` UPDATE 顺序不一致的快照）。
2. 注意 PG 默认 `READ COMMITTED` 隔离级别下 `FOR UPDATE` 行锁的死锁风险——所有路径必须**按 `gift.id ASC` 顺序加锁**。
3. 性能：`usage_billing_dedup` 已经保证 request_id 级幂等，正常路径不会触发并发，但管理后台批量充值/退款仍可能并发。要在测试里覆盖。

---

## P1 · 必须修订的问题

### P1-1 ent schema 改动不止「Edges 加一行」

计划稿 [行 61](/home/chris/.claude/plans/wobbly-herding-waffle.md#L61) 称对 `users` schema "仅追加，不删/不改现有字段"。实际：

- [backend/ent/](backend/ent/) 下有 177 个生成代码文件，所有都已提交
- 加 edge 后必须跑 `go generate ./...` —— 会修改大量 `backend/ent/*.go`、`backend/ent/migrate/*.go`、`backend/ent/runtime/*.go` 生成文件

合并 upstream 时这些**生成代码 diff 也是合并冲突源**。计划应增加：

- 步骤："新增 `UserGift` 实体后跑 `go generate ./...`，提交所有生成文件 diff"
- 风险条目：upstream 也对 `users` edges 增减时，生成代码会冲突；需要一段固定的"重生成 + 验证"操作手册

### P1-2 迁移文件编号与项目惯例对齐

计划稿建议 `142_user_gifts.sql`（[行 62](/home/chris/.claude/plans/wobbly-herding-waffle.md#L62)）。事实：当前 [backend/migrations/](backend/migrations/) 最大编号是 `141_subscription_expiry_notify_enabled.sql`，**手写 SQL，不用 ent migrate**。所以编号 142 正确。但计划应额外明确：

- 是否需要为 `gift_balance / recharge_balance` 视图建索引？至少 `(user_id, status, expires_at)` 复合索引必备
- 过期清理任务对 `expires_at` 的扫描索引：`(status, expires_at)` 部分索引 `WHERE status = 'active'`
- DOWN migration（如果项目有 down 惯例）

### P1-3 兑换码区分「赠金型」缺设计

计划稿 [行 142](/home/chris/.claude/plans/wobbly-herding-waffle.md#L142) 说"仅当兑换码标记为'赠金型'时走 Grant"，但现有 [backend/ent/schema/redeem_code.go](backend/ent/schema/redeem_code.go) 的 `Type` 字段只有 `RedeemTypeBalance/Concurrency/Subscription/Invitation`（[redeem_service.go:208/252/442](backend/internal/service/redeem_service.go)），**没有"赠金型"**。

要新增这个区分，需要：

1. ent schema 加字段（例如 `is_gift bool` 或新增 `RedeemTypeGift` 枚举值）
2. 管理后台兑换码创建表单加字段（前端改动）
3. 迁移脚本

**这一项被严重低估**。计划稿"现场确认"的态度不够，应在第一版就给出方案 A/B 让用户选。

### P1-4 退款回滚的语义需要决断

计划稿 [行 132](/home/chris/.claude/plans/wobbly-herding-waffle.md#L132) 说退款"保持简化决策，可由用户后续确认"。这等于把核心一致性问题推到后面。

事实场景：
- 用户充值 $100 → 触发"充值赠 10% 赠金"促销 → `users.balance += $110`，`user_gifts(amount=10, remaining=10)`
- 用户消费 $50（吃赠金 $10 + 充值 $40）→ `remaining` 归 0，状态 exhausted；`users.balance = $60`
- 用户申请退款 $100 → [payment_refund.go:288](backend/internal/service/payment_refund.go#L288) 直接 `DeductBalance($100)` → `users.balance = -40`（透支）

**这个 bug 已经潜伏在现状里**（promo 赠金 + 退款），计划稿不解决但也没标注为"已知问题"——必须列入风险。

**整改建议**：第一版至少**显式标注"退款不联动赠金、可能透支"**，并在风险段加一条"促销+退款的透支风险"。

### P1-5 affiliate 联盟转账被遗漏

[backend/internal/repository/affiliate_repo.go:291-292](backend/internal/repository/affiliate_repo.go#L291-L292) 的 `AddBalance + AddTotalRecharged` 是**第 6 个发放点**，计划稿没列。是否要走赠金？产品语义未知（联盟分润算"真实充值"还是"赠金"？），计划应在第一版就让用户决定。

### P1-6 cron 注册机制的依赖错位

计划稿 [行 155](/home/chris/.claude/plans/wobbly-herding-waffle.md#L155) "复用项目现有 cron 注册机制"。事实：项目**没有传统 cron**，只有 [scheduler_outbox](/home/chris/projects/sub2api/backend/internal/service/scheduler_outbox.go) 这种基于 outbox 的调度。过期清理走它需要进一步设计：

- outbox 是单次调度还是支持周期？
- 失败重试的语义？

请在计划里写清楚要么"沿用 outbox + 注册一个周期任务"，要么"新增简单的 ticker goroutine"，**不要含糊一句『复用现有机制』**。

### P1-7 `BillingCacheService` 与赠金的同步

[gateway_service.go:8176](backend/internal/service/gateway_service.go#L8176) 的 `billingCacheService.QueueDeductBalance` 是**异步队列扣费**，与 `usageBillingRepository.Apply` 是不同路径。计划稿对这条路径**完全没提**，需要：

1. 列出该路径的触发条件（什么时候走它？为什么有两条）
2. 决定是否走赠金引擎
3. 缓存层是否需要感知赠金（比如缓存 `gift_balance`？）

---

## P2 · 改进建议

### P2-1 计划首页加「术语表」

`recharge_balance`、`gift_balance`、`充值池`、`priority`、`ratio_recharge` 这些术语在计划稿里出现位置分散，定义偶尔不一致（"充值池"在分摊阶段和作废阶段的算式不同）。建议第一段就把术语表列出，每个术语定一个 SQL/数学表达式锚定。

### P2-2 用 ASCII 表把扣费阶段画出来

P0-5 的不变量 + 三阶段算法用文字描述太散。建议给一个具体例子（用户余额 100，含 priority gift 20 + ratio 30(ratio_recharge=2.0) + 充值 50；扣 60）的逐步分解表格，写在计划里——单测和评审都能照着抄。

### P2-3 灰度策略具体化

计划稿提到"feature flag 关闭时所有发放走旧路径"，但项目**没有 feature flag 框架**（探索 agent 已确认）。要么：

- 用 ENV 变量 `GIFT_SYSTEM_ENABLED=true/false` 在 `Engine` 入口分流
- 或硬切换（一次性上线，回滚靠 git）

需要在计划里明确选哪种。我倾向**硬切换 + 严密 e2e 测试**，因为带 flag 的双路径会让事务一致性窗口变大。

### P2-4 历史 `total_recharged` 修复脚本应分独立 PR

计划稿 [行 157](/home/chris/.claude/plans/wobbly-herding-waffle.md#L157) "可选第二阶段"提到反查脚本。建议：

- 先把它写成单独的 plan（`docs/pending-plans/total-recharged-cleanup.md`）
- 不要与本次赠金子系统改造合在一个 PR，否则审查面太宽
- 反查窗口建议明确是"32df9534 之后"还是"全量回溯"，影响 SQL 复杂度

### P2-5 Profile 接口字段命名

计划稿提议 `gift_balance` / `recharge_balance`。建议：

- 对前端 [frontend/src/types/index.ts:88](frontend/src/types/index.ts#L88) 的 `User.balance` 类型补充注释 "= recharge_balance + gift_balance"
- 在 [frontend/src/views/KeyUsageView.vue](frontend/src/views/KeyUsageView.vue) 加一个 Tooltip 说明二者之和等于显示值，避免用户困惑
- 后端 DTO 字段考虑 `total_balance / gift_balance / recharge_balance`，让 `total_balance` 与 `balance` 别名，方便未来废弃

### P2-6 单元测试要测的极端场景

计划稿测试列表（[行 182-189](/home/chris/.claude/plans/wobbly-herding-waffle.md#L182-L189)）漏了：

- **同时有 priority 和 ratio 但 priority remaining > 总充值**：扣费应优先吃 priority，不会触发 ratio 作废
- **ratio_recharge = 0** 的边界（等价于 priority？还是不允许？）
- **多笔同 expires_at 的 priority 赠金**：先后顺序未定义会引入测试 flake
- **扣费金额 = 0**（应该 no-op，不写 user_gifts UPDATE）
- **gift expires_at 刚好在 now + ε 之间**：与过期清理任务的并发

### P2-7 metrics 与 audit log

赠金系统涉及钱，必须有可观测性。建议增加：

- Prometheus 指标：`gift_grant_total{source}`、`gift_consumed_total{deduction_mode}`、`gift_expired_total`
- 审计日志：`audit_logs` 表（如果项目已有）记录每一笔 grant / 自动作废
- 一次性对账任务（计划已提到，[行 228](/home/chris/.claude/plans/wobbly-herding-waffle.md#L228)）应该同时输出 metrics

---

## 第一轮结论

**不批准当前版本。** 核心阻塞：

- P0-1 误判异步时机
- P0-2 `users.balance` 写入点未列全（漏 gateway_service.go:8014/8176、affiliate_repo.go）
- P0-3 赠金与订阅/quota 维度的语义未定义
- P0-4 float vs decimal 精度策略不一致
- P0-5 `users.balance` 不变量与三阶段算法自相矛盾
- P0-6 并发控制只一句话带过

**下一步**：请按 P0 各条逐项修订计划稿，把：

1. 「balance 扣减点全表」（11+ 处，逐一标注是否走赠金引擎）
2. 「不变量 + 三阶段算法 + 比例作废」的伪代码（贯穿一致的符号）
3. 「赠金 vs 订阅/quota」的产品规则
4. 「兑换码赠金型」的 schema 增量

这四块补全后，再来第二轮。
