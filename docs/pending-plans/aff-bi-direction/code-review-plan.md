# Code Review 计划

评审对象：`plan.md` 对应实现，以及实施团队后续提交的 diff。

目标：优先发现会导致重复发奖、漏发奖、余额不一致、订单无法重试、migration 错误、编译失败和前后端语义不一致的问题。

## 项目上下文

已读取 Claude 项目记忆，review 时需要遵守以下项目事实：

- 本地运行不用 Docker，后端 `go run` + 前端 `pnpm`；migration 启动时自动跑。
- Gift 子系统核心不变量：`users.balance = recharge_pool + sum(active gifts.remaining)`。
- 余额扣费主路径：`gateway_service.go` -> `usage_billing_repo.go` -> `gift.Engine.AllocateAndDeductWithBreakdown`。
- `gift.Engine.Grant` 会复用 `dbent.TxFromContext(ctx)`；事务内发赠金必须使用 `dbent.NewTxContext(ctx, tx)`。
- bind-key 只依赖 pool user ID 和 API key 自身状态；禁用 pool user 不会停发。
- 订阅扣费与 gift 扣费互斥，订阅路径 `gift_cost/recharge_cost` 恒为 0。
- 触及 billing/auth/gift 时必须重点跑 gift 子系统回归测试。

## Review 分阶段

### 1. 变更范围盘点

- 对比 `plan.md`、`review-1.md`、`review-2.md`、`review-3.md` 和实际 diff。
- 按 Phase 1/2/3/4 分类文件，确认没有跨阶段半成品混入。
- 检查是否误改用户已有变更或无关文件。
- 检查 migration 编号、命名、是否包含必要 CHECK/UNIQUE/INDEX。

### 2. Phase 1：前端快捷入口

- `Icon.vue` 图标 registry 命名一致，无重复 key。
- `UserDashboardQuickActions.vue` 的 `/bind-key`、`/referral` 路由跳转正确。
- 样式、暗色模式、移动端布局符合现有 Dashboard 模式。
- i18n 只改 `frontend/src/i18n/locales/zh.ts` / `en.ts`，没有新增旧的 `json` 文件。
- 无资格用户的文案不能暗示普通 affiliate 邀请资格被禁用。

### 3. Phase 2：BindKey 充值折扣

- `user_recharge_discounts` DDL 使用 decimal 金额字段，包含 source CHECK、rate/max/total CHECK、幂等索引和有效折扣查询索引。
- `recharge_discount_applications` DDL 只有一份最终定义，包含 `discount_rate_snapshot`，`payment_order_id` 唯一。
- `domain.BindKeyConfig` / resolver / 管理端 API 正确读写 `config.recharge_discount`。
- `keybind.Service.Commit()` 中 key 转移和折扣记录创建在同一 DB 事务内完成。
- bind-key 原赠金发放仍按计划 best-effort，不错误回滚 key 转移和折扣记录。
- `PaymentService.doBalance()` 在 `markCompleted()` 前调用 `applyRechargeDiscountForOrder()`。
- 折扣应用失败时 `doBalance()` 返回错误，订单保持 `RECHARGING` 可重试。
- 折扣应用事务中使用 `FOR UPDATE` 锁折扣行，更新 `total_discounted`、`gift.Engine.Grant`、插入 application 在同一事务内。
- `gift.Engine.Grant` 通过 `dbent.NewTxContext(ctx, tx)` 进入同一事务。
- 多折扣选择严格实现：折扣率高优先；折扣率相同，到期时间最近优先。
- decimal 精度按 8 位处理，避免 float 累计突破上限。

### 4. Phase 3：双向奖励与裂变

- `InviterBoundHook` 是小接口，`AffiliateService` 不直接依赖具体 `ReferralRewardService`。
- wire 注入不形成循环依赖，stub/mock 能编译。
- `BindInviterByCode` 绑定成功后触发 hook，能拿到 `inviterID` 和 `inviteeID`。
- 所有异步任务使用 `context.WithTimeout(context.Background(), ...)`，不捕获 request ctx。
- `OnInviterBound` 无条件 `INSERT ... ON CONFLICT DO NOTHING` 创建 tracker；开关只控制发放/继承。
- `GrantInviteeReward` 锁 tracker 行，gift 发放和 tracker 更新同事务。
- 消费事件源来自 billing 成功应用：`result.Applied == true` 且 `cmd.BalanceCost > 0`。
- 事件 ID 使用 `billing:{request_id}:{api_key_id}`，不依赖 best-effort usage log ID。
- `applyUsageBilling()` 是 package-level helper，不能直接使用 `s.referralReward`；需要通过 `billingDeps` 或调用方传递依赖。
- `referral_spend_events` unique index 防重复累计。
- `TrackSpendAndMaybeGrantInviterReward` 锁 tracker 行，并发跨阈值只发一次邀请人奖励。
- best-effort 丢事件是产品接受的取舍，但日志必须包含 `event_id`、`invitee_id`、`amount`、error。
- 裂变继承查询邀请人当前最优有效折扣，写入 `user_recharge_discounts`，不依赖 `api_key_id`。
- `feature_enabled=false` 不影响已获得折扣继续生效。

### 5. `/api/referral/status` 与前端页面

- 后端 handler、route、DTO、service、wire/provider 变更完整。
- 路由路径与项目惯例一致，计划中为 `GET /api/v1/referral/status`。
- `feature_enabled=false` 时仍返回稳定结构。
- `eligible=false` 只影响 `/referral` 页面是否展示超级邀请链接，不影响 `/affiliate` 普通邀请。
- `aff_code` / `invite_link` 是否返回与计划一致，前端仅按 `eligible` 控制展示。
- `discount` 的 `remaining_eligible`、`total_discounted`、`valid_until` 计算正确。
- 被邀请人列表复用 affiliate 接口时保持既有脱敏和权限。

### 6. Phase 4：公告 Targeting

- `AnnouncementTargeting.Matches` 改签名后所有调用点和测试同步。
- `ListForUser` 和 `MarkRead` 构建同一 `UserTargetingContext`。
- `MarkRead` 现有可见性校验不能被绕过。
- `referral_value` validate/normalize 覆盖 `has_inviter`、`is_inviter`、`no_inviter`。
- affiliate 状态查询失败降级为 false，不阻断公告。
- 前端 `types/index.ts` 和 `AnnouncementTargetingEditor.vue` 支持 referral 条件，保存和回显不丢字段。

## 测试审查

测试本身作为一等 review 对象，不能只检查“有没有测试”。

### 覆盖率是否覆盖真实风险

- 充值折扣：订单重试幂等、并发充值锁行、部分额度、过期/未生效、多折扣排序、`gift.Grant` 失败后订单保持可重试。
- 双向奖励：重复 billing event 不累计、并发跨阈值只发一次、feature off 仍创建 tracker、OAuth/email 注册都触发 hook。
- 裂变：继承最优折扣、过期不继承、三级链路、`eligible=false` 不影响普通 affiliate。
- 公告：`ListForUser` 和 `MarkRead` 都按新 targeting 判断。

### 断言是否足够具体

- 不只断言无 error，还要查 DB 行、金额、source/source_ref、gift_id、状态位、`total_discounted`、`invitee_spend_tracked`。
- 金额断言使用 decimal 或明确容差。
- 幂等测试必须验证重复调用后 DB 只有一条 application/event/gift。

### 单测与集成测试边界

- 单测覆盖纯计算、分支、接口调用、错误处理。
- 集成测试覆盖事务、唯一索引、`FOR UPDATE`、migration DDL、真实 gift balance 更新。
- 并发安全不能只靠 mock 单测，至少要有真实 DB 集成测试。

### 防止假阳性

- Mock 不应替代 DB unique constraint 和事务锁关键行为。
- 异步逻辑测试要有同步 hook 或 wait helper，不能靠固定 sleep。
- billing event 测试必须覆盖 `result.Applied=false` 不触发、`Applied=true` 才触发。

### 是否和最终计划一致

- 测试名、表名、字段名必须使用最终设计：`user_recharge_discounts`、`recharge_discount_applications`、`referral_spend_events`、`billing:{request_id}:{api_key_id}`。
- 不应残留 `bind_key_discount_usage`、`usage_log:{id}`、`expires_after_days` 作为折扣有效期。

## 验证命令

实际命令以项目当前脚本为准，review 时先读取 `Makefile`、`backend/Makefile`、`package.json`。

- 后端相关单测：gift、keybind、payment discount、referral reward、announcement targeting。
- migration/schema 测试：触及 DDL 时必须跑。
- 前端：typecheck/build 或项目现有等价命令。
- 如命令因已有已知失败阻断，需要标明是否属于项目记忆中的已知 setting guard 问题，不能混同为本次回归。

## 输出标准

- 阻塞：会导致重复发奖、漏发、余额不一致、订单无法重试、migration 错误、编译失败。
- 重要：接口语义不一致、文案误导、测试缺关键路径、性能或降级策略不完整。
- 次要：命名、注释、UI 细节、可维护性改进。

每次 review 需要单独给出“测试覆盖与正确性”结论：

- `充分`：关键风险路径均有可信测试覆盖。
- `有缺口`：核心实现可接受，但需要补指定测试。
- `不可信`：测试大量依赖 mock 或断言过弱，不能证明实现正确。
