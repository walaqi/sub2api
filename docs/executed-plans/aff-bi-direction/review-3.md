# 第三轮评审意见

评审对象：`plan.md`

本轮重点回顾 `review-2.md` 的 No-Go 条件，并核对用户列出的 15 项修正是否已进入计划。结论是：核心阻塞项已被吸收，计划可以进入实现，但仍有几个实现前应清理的文档一致性和落点细节。

## Review-2 条件回归

1. 折扣钩子位置：已修正。

   计划已改为在 `PaymentService.doBalance()` 中、`applyAffiliateRebateForOrder` 并列、`markCompleted()` 前调用 `applyRechargeDiscountForOrder()`。这解决了“订单 completed 后不再补发”的问题。

2. 折扣失败语义：已修正。

   计划已明确强一致：折扣发放失败则 `doBalance()` 返回错误，订单保持 `RECHARGING` 可重试，不再使用不完整的 fail-open 语义。

3. 消费事件源：已修正。

   计划已从 `usage_log:{id}` 改为 `billing:{request_id}:{api_key_id}`，并把触发点移到 `applyUsageBilling()` 成功且 `result.Applied == true` 后。这个事件源与 `usage_billing_dedup` 的扣费成功语义一致。

4. 异步 context：已修正。

   计划已明确使用 `context.WithTimeout(context.Background(), ...)`，不捕获 request context。

5. Hook interface：已修正。

   计划新增 `InviterBoundHook` 小接口，由 `AffiliateService` 可选注入，避免直接依赖具体 `ReferralRewardService`。

6. 旧表名清理：基本修正。

   实现顺序和测试计划已改为 `user_recharge_discounts`、`ValidDays`、`referral_spend_events`，并删除了 tracker 承载折扣传播字段的旧设计。

7. 其他 review-2 重要项：基本修正。

   DB CHECK、`discount_rate_snapshot`、`/api/referral/status` 影响范围、eligible 语义、稳定 API 响应、tracker 创建时机、best-effort 取舍、`dbent.NewTxContext`、`MarkRead` targeting 影响都已进入计划。

## 仍需修正

1. `recharge_discount_applications` 表定义重复且不一致。

   前面第一次建表没有 `discount_rate_snapshot`，后面又重新给出一份包含 `discount_rate_snapshot` 的建表语句。实现时容易按第一份写 migration，遗漏审计快照。

   建议只保留一份最终 DDL，并包含 `discount_rate_snapshot`。如果需要，也可以增加 `max_discountable_amount_snapshot`，但这不是当前 Go 条件。

2. 顶部改动范围仍写 `zh.json` / `en.json`。

   后续 i18n 章节已改为 `zh.ts` / `en.ts`，但功能 1 的表格仍是旧路径。建议同步为 `frontend/src/i18n/locales/zh.ts` / `en.ts`，避免开发按旧路径新增文件。

3. `applyUsageBilling()` 示例使用 `s.referralReward`，但当前函数是 package-level helper。

   现有 `applyUsageBilling(ctx, requestID, usageLog, p, deps, repo)` 不是 `GatewayService` 方法，函数体里没有 `s`。实现时应把 referral reward 依赖放入 `billingDeps`，例如 `referralReward *ReferralRewardService` 或小接口，然后在 helper 内通过 `deps.referralReward` 触发；或者把触发逻辑放在调用 `applyUsageBilling()` 的 service 方法返回后。

4. `referral_spend_events` 注释仍提到 usage log。

   DDL 注释写“防止 usage log 重放/重试”，字段注释写“usage_logs.id 或 request_id”。新方案已经确定使用 billing dedup 事件，应改成“防止 billing 事件重放/重试”，唯一来源写 `billing:{request_id}:{api_key_id}`。

5. `gift.SourceRechargeDiscount` 的新增位置不够显式。

   实现顺序提到新增 `recharge_discount` source，测试也覆盖了，但“新增 gift Source”小节只列了 `SourceReferralInvitee` / `SourceReferralInviter`。建议在那里一并列出：
   `SourceRechargeDiscount Source = "recharge_discount"`。

## 实现注意

1. 折扣应用事务必须用 `dbent.NewTxContext(ctx, tx)` 调 `gift.Engine.Grant`，否则 gift 发放和应用记录不在同一事务内。

2. `TrackSpendAndMaybeGrantInviterReward` 的 best-effort 丢事件是产品已接受的取舍，但日志必须足够可排查，至少包含 `event_id`、`invitee_id`、`amount`、错误。

3. `feature_enabled=false` 时前端隐藏超级邀请入口，但已获得折扣继续展示和生效；实现时不要把折扣应用逻辑错误绑定到 `referral_reward_enabled`。

4. `eligible=false` 只影响 `/referral` 页面是否展示超级邀请链接，不影响 `/affiliate` 普通邀请。文案需要避免写成“无邀请资格”。

## Go / No-Go

**Go。**

可以开始实现。上述 5 个“仍需修正”属于文档一致性和实现落点细节，不再阻塞总体方案；但建议在正式编码前先整理 `plan.md`，尤其是重复 DDL 和 `applyUsageBilling` 依赖注入方式，避免开发时产生迁移或编译错误。
