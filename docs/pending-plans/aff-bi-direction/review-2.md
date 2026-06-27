# 第二轮评审意见

评审对象：`plan.md`

上一轮评审回顾：第一轮提出的核心问题包括充值折扣订单级幂等、消费事件幂等、注册入口覆盖、裂变折扣数据模型不匹配、金额单位、i18n 路径、公告 targeting 前端支持、系统设置和测试缺口。当前计划已吸收大部分关键建议：新增 `user_recharge_discounts`、`recharge_discount_applications`、`referral_spend_events`，明确 USD、decimal、折扣有效天数、多折扣选择规则、中心化 affiliate 绑定触发、公告 targeting 前端类型/UI、`/referral` 页面状态和 `GET /api/referral/status`。

结论：相比第一轮明显收敛，但仍有阻塞级问题。当前不建议进入实现。

## 阻塞问题

1. 充值折扣钩子位置写错，可能永远不会执行。

   计划写“在 `PaymentService.markCompleted()` 之后、与 `applyAffiliateRebateForOrder` 同级位置调用”，但当前 `doBalance()` 是先 redeem、再 `applyAffiliateRebateForOrder()`、最后 `markCompleted()`；`markCompleted()` 只更新 `RECHARGING -> COMPLETED` 并发通知。如果严格按“markCompleted 之后”实现，`doBalance()` 已 return，且重试时 `ExecuteBalanceFulfillment()` 看到 `COMPLETED` 会直接返回，不会再补发折扣。

   建议改为：在 `doBalance()` 中 redeem 成功后、`markCompleted()` 前调用 `applyRechargeDiscountForOrder()`，位置与 `applyAffiliateRebateForOrder()` 并列，且其自身用 `recharge_discount_applications(payment_order_id)` 做幂等。

2. 折扣 bonus 的 fail-open 语义和 `recharge_discount_applications` 表状态不匹配。

   计划写同一事务内更新折扣、`gift.Engine.Grant`、插入 application，但又写“失败记日志，不回滚订单完成状态（fail-open）”。当前 application 表没有 `status/error/retry_count`，如果 gift 发放失败且事务回滚，订单完成后不会再自动进入折扣逻辑；如果先写 application 再 gift 失败，会形成“已处理但未到账”的坏记录。

   建议二选一：
   - 强一致：折扣发放失败则 fulfillment 返回错误，订单保持可重试状态，由幂等逻辑保证重试安全。
   - 真正 fail-open：application 表增加 `status=pending/applied/failed`、`error`、`retry_after`，订单完成后由补偿任务重试，不可只记日志。

3. 邀请消费达标挂在 usage log ID 上不可靠。

   计划使用 `eventID = "usage_log:{id}"`，并说在 `recordUsageLog` 成功后触发。但当前 gateway 写 usage log 走 `writeUsageLogBestEffort()`，优先 `CreateBestEffort()` batch 路径，调用点不一定拿得到数据库自增 `usage_logs.id`；同步 fallback 也没有明确把 ID 回写为稳定契约。更重要的是，usage log 是 best-effort，而消费达标奖励依赖的是“计费已成功扣费”，不应依赖日志是否成功落库。

   建议使用 billing 层已确认应用的幂等键：`event_id = "billing:{request_id}:{api_key_id}"`，触发点放在 `applyUsageBilling()` 返回 `result.Applied=true` 后，金额使用 `cmd.BalanceCost` / `usageLog.ActualCost`。这样与 `usage_billing_dedup` 的成功扣费语义一致，不依赖 usage log 表。

4. `ReferralRewardService` 异步使用请求 `ctx` 有取消风险。

   计划在 `BindInviterByCode` 和 gateway 中 `go s.referralReward... (ctx, ...)`。注册/网关请求结束后 `ctx` 可能被取消，异步任务会随机失败。风险与计划中“异步不阻断注册/请求”目标冲突。

   建议所有异步调用使用 `context.WithTimeout(context.Background(), 3*time.Second)`，并显式传入必要字段，不捕获 gin/request context。

5. `AffiliateService.BindInviterByCode` 回调设计未解决依赖方向和测试注入。

   计划让 `AffiliateService` 绑定成功后回调 `ReferralRewardService`，但 `ReferralRewardService` 又需要查询 affiliate/tracker/gift/settings。需要明确 interface，而不是让 `AffiliateService` 直接依赖具体 service，避免 wire 循环和单测 stub 大面积破坏。

   建议定义小接口，例如：
   `type InviterBoundHook interface { OnInviterBound(ctx context.Context, inviterID, inviteeID int64) }`，由 `AffiliateService` 可选注入。`BindInviterByCode` 需要拿到 `bound` 和 `inviterID` 后触发 hook。

6. 计划残留旧表名/旧字段，实施顺序和测试计划会误导开发。

   数据层已改为 `user_recharge_discounts`，但实现顺序和测试计划仍写：
   - `migration: bind_key_discount_usage 表`
   - `TestCommit_WritesDiscountUsage...`
   - `valid_until=now+expires_after_days`
   - `referral_reward_tracker 表（含折扣传播字段）`

   这些与新设计冲突。实施前必须统一为 `user_recharge_discounts`、`valid_days`、`referral_spend_events`，并删除“tracker 含折扣传播字段”的旧描述。

## 重要问题

7. `user_recharge_discounts` 约束不完整。

   计划写了业务校验，但 migration 没有 DB-level `CHECK`，未来直接 SQL 或 bug 写入可产生负数/非法 rate。建议增加：
   - `CHECK (discount_rate > 0 AND discount_rate <= 1)`
   - `CHECK (max_discountable_amount > 0)`
   - `CHECK (total_discounted >= 0 AND total_discounted <= max_discountable_amount)`
   - `CHECK (source IN ('bind_key','referral_inherit'))`

8. `recharge_discount_applications` 的唯一键按订单全局唯一会阻止未来多折扣组合。

   当前计划定义“多折扣只选一条”，所以 `payment_order_id UNIQUE` 可行。但若未来允许拆分多个折扣，表结构要改。建议在计划中明确这是有意约束，并在应用记录保存 `discount_rate/max_discountable_amount` 快照，便于审计。

9. `/api/referral/status` 影响范围未列完整。

   计划定义了 API，但没有列 handler、route、DTO、service、wire/provider 变更。需要补充：
   - `backend/internal/handler/user_handler.go` 或新 `ReferralHandler`
   - `backend/internal/server/routes/user.go`
   - `backend/internal/service/wire.go` / wire 生成
   - 前端 `api/referral.ts` 和 view 调用

10. “无资格用户隐藏 aff_code/link”与 affiliate 系统并存语义冲突。

   当前 `/affiliate` 页面仍可能展示 aff_code，且 `EnsureUserAffiliate` 会给用户生成 aff_code。`/referral/status` 在 `eligible=false` 时不返回 aff_code 只是隐藏超级邀请入口，不是真正禁止普通 affiliate 邀请。计划需要明确：无超级邀请资格是否仍允许普通 affiliate 邀请。如果允许，文案不能暗示“没有邀请资格”；如果不允许，需要修改 affiliate 绑定/注册逻辑，而这会影响现有系统。

11. `feature_enabled=false` 时 API 字段语义不清。

   `GET /api/referral/status` 返回 `feature_enabled=false` 时，是否还返回 discount、invitee_count、历史奖励统计没有定义。建议定义稳定响应结构，避免前端分支和后端 DTO 不一致。

12. `referral_reward_tracker` 创建时机还不够明确。

   `GrantInviteeReward` 依赖 tracker 行并锁行；`TrackSpend...` 也依赖 tracker 行。计划需要明确 tracker 在 `OnInviterBound` 中先 `INSERT ... ON CONFLICT DO NOTHING`，即使 `referral_reward_enabled=false` 时是否创建也要定义。否则后续开关打开后历史 invitee 消费是否追踪会出现歧义。

13. 异步失败“下次消费事件会重新触发追踪”的说法不完全成立。

   如果某次消费事件扣费成功，但异步 reward 任务失败且没有写入 `referral_spend_events`，后续消费会继续累计后续金额，但丢失这一次金额，可能导致邀请人迟迟不到账。若这是可接受的 best-effort，需要产品确认；若不可接受，需要 outbox/pending queue。

14. `gift.Engine.Grant` 在同一事务内可以工作，但计划需明确用 `dbent.NewTxContext`。

   现有 gift 引擎会识别 `dbent.TxFromContext(ctx)`。计划多处写“同一事务内 gift.Engine.Grant”，但没有明确将 tx 注入 context。建议在伪代码/实现说明中写清楚使用 `txCtx := dbent.NewTxContext(ctx, tx)`。

15. 公告 targeting 的 `MarkRead` 说明可能过度扩大范围。

   当前是否需要在 `MarkRead` 里重新做 targeting 取决于现有 service 实现。计划写“ListForUser / MarkRead 两处”但未贴现有逻辑依据。建议实现前确认 `MarkRead` 是否只按公告 ID 写 read，若要防止非目标用户标记，需要明确这是新增行为并加测试。

## 上一轮问题状态

- 已解决：概述功能数量错误、金额单位混乱、i18n 文件路径、折扣金额语义、裂变无 api_key_id 的模型问题、多折扣选择规则、注册入口覆盖方向、公告 targeting 前端类型/UI、系统设置同步范围、主要测试矩阵。
- 部分解决：充值折扣幂等和并发安全已有表和锁设计，但 fail-open/补偿语义仍阻塞。
- 部分解决：消费事件幂等已有 `referral_spend_events`，但事件源选错，应从 billing dedup 成功应用处取键，而不是 usage log id。
- 未完全解决：实施顺序和测试计划仍残留旧设计，必须清理。

## Go / No-Go

**No-Go。**

不建议按当前计划直接实施。核心原因是：折扣发放的执行位置和失败语义会造成漏发；邀请消费达标依赖 best-effort usage log ID 不可靠；计划文档仍有旧表名/旧字段残留，实施时容易写错 schema 和测试。

达到 Go 的最低条件：

1. 把充值折扣调用点改到 `doBalance()` 中 `markCompleted()` 前，并明确强一致或补偿式 fail-open。
2. 将 referral spend event 源改为 billing 成功应用事件，使用 `request_id + api_key_id` 幂等键。
3. 清理所有旧表名/旧字段残留，统一为 `user_recharge_discounts`、`valid_days`、`referral_spend_events`。
4. 明确 async context、hook interface、`/api/referral/status` 后端影响范围。
