# 赠金子系统设计方案 v2 · 第二轮评审

被评审计划：[/home/chris/.claude/plans/wobbly-herding-waffle.md](/home/chris/.claude/plans/wobbly-herding-waffle.md)（v2，吸收第一轮评审）
对照：[review-1.md](/home/chris/projects/sub2api/docs/pending-plans/赠金子系统/review-1.md)
评审范围：v2 修订是否解决第一轮 P0/P1，是否引入新缺陷

---

## 总评

v2 把第一轮 6 项 P0 全部按事实修订，4 项 P1 落地，整体可读性和可执行性显著提升。术语表、不变量、加锁顺序、分摊算法走查例都补齐，**可以进入实现阶段**。

仍有 2 处技术细节需要在落地前修订（P1 级别），3 处建议级别的小事可以并行处理或留作后续 PR。

---

## 第一轮 P0 落实情况

| 项 | v2 处理 | 结论 |
|----|---------|------|
| P0-1 异步时机误判 | [行 30-49](/home/chris/.claude/plans/wobbly-herding-waffle.md#L30-L49) 改为"`enqueued` 零延迟，`sync` 降级时区分流式/非流式" + N 上限 50 + 实测 < 5ms | ✅ 已落实，论断与 [gateway_handler.go:511-537](backend/internal/handler/gateway_handler.go#L511-L537)、[usage_record_worker_pool.go:145-184](backend/internal/service/usage_record_worker_pool.go#L145-L184) 一致 |
| P0-2 写入点未列全 | [行 56-73](/home/chris/.claude/plans/wobbly-herding-waffle.md#L56-L73) 列出 13 处（含 [gateway_service.go:8014](backend/internal/service/gateway_service.go#L8014)、[gateway_service.go:8176](backend/internal/service/gateway_service.go#L8176)、[affiliate_repo.go:291](backend/internal/repository/affiliate_repo.go#L291)、[usage_service.go:125](backend/internal/service/usage_service.go#L125)、[billing_cache_service.go:357](backend/internal/service/billing_cache_service.go#L357)）逐一标注 | ✅ 已覆盖第一轮列举的 11+ 写入点；现场 grep 复核仍准确（见下文 P1-N1） |
| P0-3 赠金 vs 订阅/quota | [行 76-87](/home/chris/.claude/plans/wobbly-herding-waffle.md#L76-L87) 表格化 5 维度处理：赠金只接管 `BalanceCost`；订阅/quota/限速保持现状 | ✅ 与 [gateway_service.go:8111-8116](backend/internal/service/gateway_service.go#L8111-L8116) 一致 ——`SubscriptionCost` 和 `BalanceCost` 互斥（订阅/按量二选一），赠金不与订阅冲突，逻辑成立 |
| P0-4 float vs decimal | [行 149-159](/home/chris/.claude/plans/wobbly-herding-waffle.md#L149-L159) 5 条策略：DB decimal、Go 端 `shopspring/decimal`、跨边界 float、链尾吸收舍入、`decimal.Equal` 严格断言 | ✅ 策略明确；唯一的小遗憾是 ent schema 仍用 `field.Float`（ent 端类型保持 float64），与现有 `users.balance` 一致，可接受 |
| P0-5 不变量自相矛盾 | [行 162-282](/home/chris/.claude/plans/wobbly-herding-waffle.md#L162-L282) 重写：明确不变量 `total_balance ≡ recharge_pool + Σ(active gifts.remaining)`，三阶段算法逐步守恒，含走查例 | ✅ 矛盾消除；走查例（priority A=20 + ratio B=30/r=2.0 + recharge=50，扣 60）数学正确 |
| P0-6 并发控制缺失 | [行 188-201](/home/chris/.claude/plans/wobbly-herding-waffle.md#L188-L201) Step 0 加锁：先 `users FOR UPDATE`、再 `user_gifts ORDER BY id ASC FOR UPDATE` | ✅ 加锁顺序固定，死锁风险已控；过期清理任务也按同顺序（[行 414-425](/home/chris/.claude/plans/wobbly-herding-waffle.md#L414-L425)） |

**P0 全部解决。**

---

## 第一轮 P1 落实情况

| 项 | v2 处理 | 结论 |
|----|---------|------|
| P1-1 ent 生成代码 diff | [行 146](/home/chris/.claude/plans/wobbly-herding-waffle.md#L146) 明示"跑 `go generate ./...`，提交所有生成代码 diff" + [行 477-480](/home/chris/.claude/plans/wobbly-herding-waffle.md#L477-L480) upstream merge runbook | ✅ 风险面已明示 |
| P1-2 迁移文件索引 | [行 113-118](/home/chris/.claude/plans/wobbly-herding-waffle.md#L113-L118) 包含 `idx_user_gifts_user_active`（部分索引）+ `idx_user_gifts_expiry_sweep`（部分索引） | ✅ 索引设计合理 |
| P1-3 兑换码区分赠金型 | [行 68](/home/chris/.claude/plans/wobbly-herding-waffle.md#L68)、[行 360](/home/chris/.claude/plans/wobbly-herding-waffle.md#L360) **用户决策：本次不区分**，redeem code 仍走充值口径 | ✅ 一刀切决策清晰，避免设计膨胀；redeem code 不动 |
| P1-4 退款透支 | [行 341-351](/home/chris/.claude/plans/wobbly-herding-waffle.md#L341-L351) `evaluateBalanceDeduction` 改用 `recharge_pool` 而非 `u.Balance` | ✅ 解决"促销 + 退款" bug；详见下方 P1-N2 一处遗漏 |
| P1-5 affiliate | [行 69](/home/chris/.claude/plans/wobbly-herding-waffle.md#L69)、[行 361](/home/chris/.claude/plans/wobbly-herding-waffle.md#L361) **用户决策：保持现状**，不走赠金 | ✅ 显式标注 |
| P1-6 cron 机制 | [行 408-428](/home/chris/.claude/plans/wobbly-herding-waffle.md#L408-L428) 选"独立 ticker goroutine"，模仿 `account_expiry_service.go` / `subscription_expiry_service.go` | ✅ 与既有惯例一致，不引入对 outbox 的依赖 |
| P1-7 BillingCacheService 路径 | [行 71](/home/chris/.claude/plans/wobbly-herding-waffle.md#L71)、[行 405-406](/home/chris/.claude/plans/wobbly-herding-waffle.md#L405-L406) 明确：缓存层只感知"用户总余额"，DB SoT 由赠金引擎接管，`gift_balance` / `recharge_balance` 走 DB 直查 | ✅ 设计自洽 |

**P1 全部解决。**

---

## P1 · 本轮新发现的阻塞性问题

### P1-N1 [auth_oauth_first_bind.go:81](backend/internal/service/auth_oauth_first_bind.go#L81) 的发放上下文与 v2 的简化模型不符

v2 [行 358](/home/chris/.claude/plans/wobbly-herding-waffle.md#L358) 计划用 `giftEngine.Grant` 替换 `client.User.UpdateOneID(userID).AddBalance(providerDefaults.Balance)`。但**实际 OAuth 首登发放是按 provider 维度的**——同一个 provider 类型的用户只赠送一次（[auth_oauth_first_bind.go:60-78](backend/internal/service/auth_oauth_first_bind.go#L60-L78) 通过 `user_provider_default_grants` 表 + `ON CONFLICT DO NOTHING` 保证幂等），并且**同一个事务里还会发放 concurrency 与 subscription**（[auth_oauth_first_bind.go:85-100](backend/internal/service/auth_oauth_first_bind.go#L85-L100)）。

潜在问题：

1. `providerDefaults.Balance` 可能为 0（管理员只配置了订阅/并发），按 [keybind/balance.go:55](backend/internal/keybind/balance.go#L55) 的现有"amount <= 0 直接 return nil"模式，`giftEngine.Grant` 必须显式处理"amount = 0 跳过"。v2 在 [行 178](/home/chris/.claude/plans/wobbly-herding-waffle.md#L178) 的 `Grant` 伪代码没写。
2. `Grant` 写入需要走与 OAuth 首登事务相同的 ent 事务（已在 line 59-70 用 `client.Driver().Exec` 跑 raw SQL）。v2 [行 369](/home/chris/.claude/plans/wobbly-herding-waffle.md#L369) `Grant(ctx, tx?, GrantInput)` 接受 tx 参数即可，但这里 OAuth 首登是 `*ent.Client` 的子事务模式（用 `client.Tx(ctx)` 嵌套），需要写明 `Grant` 在已有 ent tx 下如何工作。

**整改建议**：
- 在 v2 [行 369-373](/home/chris/.claude/plans/wobbly-herding-waffle.md#L369-L373) 的 Engine 接口签名补一段："`Grant` 接受 `*ent.Tx`（不是 `*sql.Tx`），在 OAuth 首登/promo 这两条 ent 事务路径上复用"。
- `Grant` 入口加 `if input.Amount <= 0 return nil, nil` 早返回。
- 单测覆盖 amount=0 不写 `user_gifts` 行的场景。

**严重程度**：P1（影响接口设计；不影响算法本身）。

### P1-N2 [payment_refund.go:288 ExecuteRefund](backend/internal/service/payment_refund.go#L288) 的 `DeductBalance` 仍透支充值池

v2 [行 64](/home/chris/.claude/plans/wobbly-herding-waffle.md#L64) 把 [payment_refund.go:415 RollbackRefund](backend/internal/service/payment_refund.go#L415) 的 `UpdateBalance` 标"保留（退款失败回滚到 recharge_pool）"——这没问题；但 v2 只改 [行 272 evaluateBalanceDeduction](backend/internal/service/payment_refund.go#L272) 把 `BalanceToDeduct = min(refund, recharge_pool)`（计划阶段算 cap），**`ExecuteRefund` 行 288 的实际写入仍是 `userRepo.DeductBalance(ctx, p.Order.UserID, p.BalanceToDeduct)`**（[user_repo.go:714](backend/internal/repository/user_repo.go#L714)，允许透支到负值）。

风险路径：
1. `evaluateBalanceDeduction` 计算时 `recharge_pool=$50`，`BalanceToDeduct=$50`
2. 进入 `ExecuteRefund` 之前用户被另一并发扣费消耗了 `recharge_pool` 到 `$10`
3. `ExecuteRefund` line 288 直接 `DeductBalance($50)` → `users.balance -= 50` → `recharge_pool` 变 `-40`，**透支了赠金池在 `users.balance` 里的份额**
4. 不变量 `recharge_pool ≥ 0` 在退款路径下被破坏，赠金部分被退款"借走"

**整改建议**：
- v2 [行 348](/home/chris/.claude/plans/wobbly-herding-waffle.md#L348) 描述里加一行："`evaluateBalanceDeduction` 在 `ExecuteRefund` 入口**也**重新拿一次 `recharge_pool` 并取 `min(p.BalanceToDeduct, recharge_pool)`（同事务下 `FOR UPDATE`），杜绝评估-执行间的并发竞态。"
- 或者更彻底：把 `DeductBalance` 改为 `giftEngine.DeductFromRechargePool(ctx, tx, userID, amount) (actualDeducted, err)`，由引擎事务内重新校验上限并返回实际扣减量。
- 选哪种由用户决定；目前 v2 没覆盖。

**严重程度**：P1（与第一轮 P1-4 同源，v2 只解决了"评估值正确"但没解决"评估到执行的窗口"）。

---

## P2 · 改进建议

### P2-N1 走查例的舍入说明

v2 [行 286-294](/home/chris/.claude/plans/wobbly-herding-waffle.md#L286-L294) 走查例算到 `26.67`、`13.33` 这种 2 位小数，但 [行 157](/home/chris/.claude/plans/wobbly-herding-waffle.md#L157) 约定 `Round(8, decimal.RoundHalfUp)`。读者可能疑惑"为什么例子不是 8 位"。建议在走查例下方加一句"实际 decimal 计算保留 8 位，本表为可读性截到 2 位；舍入误差归到链尾最后一项"。

### P2-N2 `total_recharged` 修复的反查窗口

v2 [行 437-442](/home/chris/.claude/plans/wobbly-herding-waffle.md#L437-L442) 把修复脚本拆出独立 PR 的决策正确，但反查窗口写得偏简化："从 `32df9534` 部署日期开始"。建议明确：
- "部署日期"是 `git log --format='%ci' 32df9534` 的日期还是实际生产部署日期？
- `user_keybind_logs` 表是否真的能反推出每条赠金额？（需要在 cleanup plan 里先验证表结构）
- 这些细节挪到 [docs/pending-plans/total-recharged-cleanup.md](docs/pending-plans/total-recharged-cleanup.md) 即可，不阻塞本计划。

### P2-N3 metrics 一并落地

v2 没在主要修改文件清单里列 metrics（参考第一轮 P2-7）。建议至少在"对账任务"段补一句："对账任务 + 关键路径都打 Prometheus 指标 `gift_grant_total{source}`、`gift_consumed_total{deduction_mode}`、`gift_expired_total`、`gift_invariant_mismatch_total`，便于上线后监控"。

[行 482-487](/home/chris/.claude/plans/wobbly-herding-waffle.md#L482-L487) 已经提到 `gift_invariant_mismatch_total`，把另外三条补上即可。

---

## 现场代码核对（v2 论断 vs 实测）

| v2 论断 | 实测结果 | 结论 |
|---------|---------|------|
| [行 39](/home/chris/.claude/plans/wobbly-herding-waffle.md#L39) `submitUsageRecordTask` 通过 pond pool | [usage_record_worker_pool.go:155](backend/internal/service/usage_record_worker_pool.go#L155) `p.pool.TrySubmit` | ✅ |
| [行 70](/home/chris/.claude/plans/wobbly-herding-waffle.md#L70) `usage_service.go:125` "实测无生产路由调用 `UsageService.Create`" | grep 全仓：`UsageService` 仅在 [wire.go:452](backend/internal/service/wire.go#L452) 注入；handler 调用全是 `List*/Get*/GetStats*` 等读侧接口；**没有任何生产代码调用 `Create`** | ✅ 论断准确 |
| [行 81-82](/home/chris/.claude/plans/wobbly-herding-waffle.md#L81-L82) "订阅是用户付钱买的，单 key 二选一（订阅 OR 按量）" | [gateway_service.go:8111-8116](backend/internal/service/gateway_service.go#L8111-L8116) `if IsSubscriptionBill { SubscriptionCost = ActualCost } else { BalanceCost = ActualCost }` | ✅ 互斥关系成立 |
| [行 78-87](/home/chris/.claude/plans/wobbly-herding-waffle.md#L78-L87) "5 维度仅 `BalanceCost` 接管赠金" | [usage_billing_repo.go:108-146](backend/internal/repository/usage_billing_repo.go#L108-L146) `applyUsageBillingEffects` 5 个独立 if 分支 | ✅ |
| [行 412](/home/chris/.claude/plans/wobbly-herding-waffle.md#L412) "模仿 `subscription_expiry_service.go` 的 ticker" | 该文件存在（grep 命中 [行 49](backend/internal/service/subscription_expiry_service.go#L49)） | ✅ 可参照 |
| [行 71](/home/chris/.claude/plans/wobbly-herding-waffle.md#L71) `billing_cache_service.go:357 QueueDeductBalance` | [billing_cache_service.go:356-357](backend/internal/service/billing_cache_service.go#L356-L357) 与 [billing_cache_service.go:376-381 InvalidateUserBalance](backend/internal/service/billing_cache_service.go#L376-L381) 都存在 | ✅ |
| [行 80-81](/home/chris/.claude/plans/wobbly-herding-waffle.md#L80-L81) `cmd.SubscriptionCost` 字段名 | [usage_billing.go:37-38](backend/internal/service/usage_billing.go#L37-L38) `BalanceCost` 与 `SubscriptionCost` 字段确实存在 | ✅ |

---

## 第二轮结论

**有条件批准。** v2 的 P0/P1 修订完整准确，整体设计自洽。剩余两个 P1 是接口/事务边界的细节：

- **P1-N1**：补 `Grant(*ent.Tx)` 接口签名 + amount=0 早返回 + 对应单测
- **P1-N2**：补"`ExecuteRefund` 内重新校验 `recharge_pool` 上限，杜绝评估-执行间并发"

**下一步**：
1. 把上述两点写进 v2，做最后定稿
2. 第三轮评审仅核对这两处即可（半页 review-3.md），通过后即可开工
3. P2 三项可以并行落地或留作后续 PR，不阻塞主任务
