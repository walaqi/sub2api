# 赠金子系统设计方案 v2 · 第三轮评审

被评审计划：[/home/chris/.claude/plans/wobbly-herding-waffle.md](/home/chris/.claude/plans/wobbly-herding-waffle.md)
对照：[review-2.md](/home/chris/projects/sub2api/docs/pending-plans/赠金子系统/review-2.md)

---

## 结论：**GO ✅**

第二轮遗留的两项 P1 与三项 P2 全部按事实落地，可进入实现阶段。

| 第二轮遗留 | v2 当前位置 | 验证 |
|----|----|----|
| **P1-N1** `Grant` 接口签名（ent.Tx + amount=0 早返回） | [行 176-192](/home/chris/.claude/plans/wobbly-herding-waffle.md#L176-L192) | ✅ 显式 `if input.Amount <= 0 return nil, nil`；走 `dbent.TxFromContext(ctx)` 与 [auth_oauth_first_bind.go:55-58](backend/internal/service/auth_oauth_first_bind.go#L55-L58)、[promo_service.go:104](backend/internal/service/promo_service.go#L104) 既有 ent 事务模式一致；要求单测覆盖 amount=0 |
| **P1-N2** 退款评估-执行竞态 | [行 354-383](/home/chris/.claude/plans/wobbly-herding-waffle.md#L354-L383) | ✅ 两阶段防御：阶段 A 无锁评估（`GetRechargePool`），阶段 B `DeductFromRechargePool` 事务内 `FOR UPDATE` 重校验 cap，返回 `actualDeducted`；`Engine` 接口签名 [行 404](/home/chris/.claude/plans/wobbly-herding-waffle.md#L404) 已补 |
| P2-N1 走查例舍入说明 | [行 317](/home/chris/.claude/plans/wobbly-herding-waffle.md#L317) | ✅ |
| P2-N3 Prometheus 指标 | [行 521-529](/home/chris/.claude/plans/wobbly-herding-waffle.md#L521-L529) | ✅ 6 条指标 + `gift_engine_duration_seconds` 直方图 |
| P2-N2 `total_recharged` cleanup PR | [行 468-475](/home/chris/.claude/plans/wobbly-herding-waffle.md#L468-L475) | ✅ 已声明独立 PR，反查窗口细节留待 cleanup plan 内部完善，不阻塞主任务 |

---

## 开工前的最后检查项（实现期落地，非阻塞）

1. **`AllocateAndDeduct` 与 `Grant` 的 tx 类型不一致**：前者 `*sql.Tx`（[行 402](/home/chris/.claude/plans/wobbly-herding-waffle.md#L402) 沿用 [usage_billing_repo.go](backend/internal/repository/usage_billing_repo.go) 的 raw SQL 模式），后者 `*ent.Tx`（[行 187](/home/chris/.claude/plans/wobbly-herding-waffle.md#L187)）。这是项目"扣费走 raw SQL、CRUD 走 ent"的既有割裂，不是缺陷；但 `Engine` 内部需要确保两条路径分别拿到对应类型的 tx，wire 注入 [行 412-418](/home/chris/.claude/plans/wobbly-herding-waffle.md#L412-L418) 时记得同时注入 `*ent.Client` 与 `*sql.DB`。
2. **`DeductFromRechargePool` 在 `ExecuteRefund` 落地时**：注意 [行 286-295 hasAuditLog 重试跳过逻辑](backend/internal/service/payment_refund.go#L286-L295) 也要适配新返回的 `actualDeducted`——retry 路径下 `BalanceToDeduct` 已被改写为前次实际扣减额，避免二次扣减。
3. **集成测试 [行 498](/home/chris/.claude/plans/wobbly-herding-waffle.md#L498) "100 并发扣同一用户"** 建议显式覆盖：(a) AllocateAndDeduct × N + 同时一个 Refund DeductFromRechargePool 的死锁/超扣；(b) Grant 与 AllocateAndDeduct 并发时不变量保持。

以上三点写入实现期 PR 的 review checklist 即可。

---

**Verdict: GO. 可以开工。**
