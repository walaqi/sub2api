# PR Review Checklist · 赠金子系统

实现期落地前必须勾选的检查项。来源：[review-3.md](review-3.md) "开工前的最后检查项"，对照 [计划稿](/home/chris/.claude/plans/wobbly-herding-waffle.md)。

---

## C1 · tx 类型割裂的 wire 注入正确性

**背景**：项目"扣费走 raw SQL、CRUD 走 ent"是既有架构割裂，不是缺陷。

- `AllocateAndDeduct(ctx, tx *sql.Tx, ...)` 走 raw `*sql.Tx`，与 [usage_billing_repo.go](../../backend/internal/repository/usage_billing_repo.go) 一致
- `Grant(ctx, GrantInput)` 走 `*ent.Tx`，通过 `dbent.TxFromContext(ctx)` 自动识别外部事务

**Checklist**：

- [ ] `gift.Engine` 构造函数同时注入 `*ent.Client` 与 `*sql.DB`，二者持有同一 PG 连接池
- [ ] wire.go 同时把上述两个依赖传给 `gift.NewEngine`
- [ ] `Engine` 内部 raw SQL 路径与 ent 路径不互相调用（避免事务嵌套混乱）
- [ ] 单测分别覆盖：仅传 `*sql.Tx`、仅传 `ctx with ent tx`、仅传裸 ctx 三种场景

---

## C2 · `DeductFromRechargePool` 与 hasAuditLog 重试路径适配

**背景**：[payment_refund.go:286-295](../../backend/internal/service/payment_refund.go#L286-L295) 的 retry 跳过逻辑依赖 `p.BalanceToDeduct` 与 `REFUND_ROLLBACK_FAILED` 审计日志的组合状态。引入 `DeductFromRechargePool` 后，`actualDeducted` 可能与原始 `BalanceToDeduct` 不同，retry 路径必须读取实际扣减额，避免二次扣减或漏退。

**Checklist**：

- [ ] `DeductFromRechargePool` 返回的 `actualDeducted` 在 ExecuteRefund 内回写到 `p.BalanceToDeduct`
- [ ] [REFUND_SUCCESS 审计日志](../../backend/internal/service/payment_refund.go#L409) 的 `balanceDeducted` 字段记录 `actualDeducted` 而非"评估值"
- [ ] retry 场景集成测试：第一次退款失败留下 `REFUND_ROLLBACK_FAILED`，第二次重试不会再扣 `recharge_pool`
- [ ] retry 场景的 `actualDeducted` 从审计日志或订单字段反查，而非重新评估

---

## C3 · 并发集成测试矩阵

**背景**：单纯 "100 并发扣同一用户" 不够，需覆盖跨操作的并发组合。

**Checklist**：

- [ ] **场景 A**：N 个 goroutine 并发 `AllocateAndDeduct` × M 次 + 1 个 goroutine `DeductFromRechargePool`（退款），断言：
  - 无死锁
  - `Σ(扣减) = 预期总扣 + 退款额`
  - 退款不影响赠金 remaining
- [ ] **场景 B**：N 个 goroutine 并发 `Grant`（不同 source）+ M 个 goroutine 并发 `AllocateAndDeduct`，断言不变量 `total_balance ≡ recharge_pool + Σ(active gifts.remaining)` 始终成立
- [ ] **场景 C**：过期清理 ticker 在扣费高峰期触发，断言不死锁、不丢账
- [ ] **场景 D**：ratio gift 联动作废与并发 `Grant priority gift` 同时发生，断言新发放的 priority gift 不会被错误地 revoke

---

## 通用项

- [ ] `users.balance` 字段语义文档（[user.go:49](../../backend/ent/schema/user.go#L49) 注释）更新为"= recharge_pool + Σ(active gifts.remaining)"
- [ ] 单测对 `decimal.Decimal` 边界用 `decimal.Equal`，不用 `InEpsilon`
- [ ] 加锁顺序在所有路径都是"先 users 后 user_gifts(id ASC)"——code review 时逐处对照
- [ ] `go generate ./...` 后所有 ent 生成文件 diff 与 schema 修改在同一 commit
- [ ] 上线前对账任务跑通至少 24h，`gift_invariant_mismatch_total` 始终为 0
