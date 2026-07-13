# 第一轮评审意见

评审对象：`plan.md`

结论：当前方案方向可行，但存在若干会导致重复发放、漏发放、无法落库或前后端不可配置的问题。建议先补齐幂等、事务边界、注册入口覆盖、数据模型表达能力，再进入实现。

## 阻塞问题

1. 充值折扣发放缺少订单级幂等与并发锁设计。

   计划在 `ExecuteBalanceFulfillment` / `markCompleted` 附近发放折扣赠金，但当前充值链路允许在 `RECHARGING` 状态失败后重试，且 affiliate 返利已经专门用 `payment_audit_logs` 做了 claim 去重。充值折扣如果只查 `bind_key_discount_usage` 并更新 `total_discounted`，会在 `markCompleted` 失败重试、进程重启、手动重放时重复发放 bonus，或者并发充值时突破 `max_amount`。

   建议明确：
   - 增加 `bind_key_discount_applications` 或复用 `payment_audit_logs`，以 `order_id` 做唯一幂等键。
   - 对命中的 `bind_key_discount_usage` 行使用事务和 `FOR UPDATE`，在同一事务内计算 `eligible_amount`、发放赠金、更新 `total_discounted`、写入应用记录。
   - 明确折扣发放失败时订单是否可完成。若允许 fail-open，需要有可补偿的 pending/failed application 记录，否则用户会丢奖励。

2. 邀请人消费达标奖励缺少消费事件幂等来源。

   计划写“在计费链路异步触发即可”，但 gateway 计费有请求级去重表 `usage_billing_dedup`，usage log 写入也可能失败或重放。若 `TrackSpendAndMaybeGrantInviterReward(inviteeID, spendAmount)` 没有事件唯一键，重试会重复累计 `invitee_spend_tracked`，提前触发邀请人奖励。

   建议明确：
   - 用已确认扣费成功且去重后的事件作为唯一来源，例如 `usage_billing_dedup(request_id, api_key_id)` 或成功插入的 `usage_logs.id`。
   - 新增消费明细表或在 tracker 内记录 last/event id 不够，推荐 `referral_reward_spend_events(event_id UNIQUE, invitee_id, amount)`。
   - “消费包含赠金和充值余额”应使用本次实际扣费总额 `BalanceCost` / `ActualCost`，不是 `RechargeCost`。当前系统已有 `GiftCost` / `RechargeCost` breakdown，计划需明确采用 `GiftCost + RechargeCost`。

3. 注册奖励触发点覆盖不完整。

   计划只写 `AuthService.RegisterWithVerification()` 中 affiliate 绑定成功后调用 `GrantInviteeReward`，但当前代码还有 OAuth 注册绑定路径 `bindOAuthAffiliate()`，被 email OAuth、LinuxDo、微信、OIDC、钉钉等路径复用。只改 email 注册会导致 OAuth 新用户通过 aff 注册时不发双向注册赠金、不传播折扣。

   建议把触发点下沉到 affiliate 绑定成功的中心位置，而不是分散在注册入口。当前 `AffiliateService.BindInviterByCode` 只返回 `error`，不返回 `inviterID/bound`，计划中的 `GrantInviteeReward(ctx, inviterID, inviteeID)` 需要改接口或绑定后重新查询 `user_affiliates.inviter_id`。

4. 裂变折扣继承与 `bind_key_discount_usage` 模型不匹配。

   `bind_key_discount_usage.api_key_id BIGINT NOT NULL` 且唯一索引是 `(user_id, api_key_id)`，但通过邀请传播获得折扣的用户不一定绑定过任何池 key。计划又要求“为被邀请人创建等同的折扣记录（bind_key_discount_usage）”，这会缺少合法 `api_key_id`，并且无法表达来源是 referral propagation。

   建议改模型：
   - 将 `api_key_id` 改为 nullable `origin_api_key_id`，增加 `source/source_ref`，或单独建 `user_recharge_discounts` 表。
   - 唯一约束从 `(user_id, api_key_id)` 调整为能表达活动来源的幂等键，例如 `(user_id, source, source_ref)`。
   - 明确用户存在多个有效折扣时的选择规则：最高折扣、最早到期、按创建时间，还是叠加。当前计划只写“若存在有效折扣”，实现会不确定。

## 重要问题

5. “bind-key 过期时间”来源不清晰。

   计划多处写折扣从领取时间到 bind-key 过期时间，但现有 bind-key 配置里可见的是 `bind_key_gift_settings.expires_after_days`，这是赠金过期配置，不等同于池 key 自身过期。若要复用该字段，需要明确语义变更；若不是，需要新增 `recharge_discount.valid_days` 或读取 API key 的真实过期字段。

6. BindKey Commit 的事务边界需要重新设计。

   当前 `keybind.Service.Commit()` 先转移 API key，再 best-effort 发放赠金，失败不回滚。计划要求成功后创建折扣记录，但未说明该记录失败时如何处理。这样会出现“key 已领取但无折扣记录”的不可见漏发。

   建议明确折扣记录创建是强一致还是可补偿：
   - 强一致：key 转移和折扣记录在一个 DB 事务内，赠金可继续 best-effort。
   - 可补偿：写失败记录/audit，提供后台补偿任务或运维查询。

7. `referral_reward_tracker` 发奖也需要并发安全。

   `TrackSpendAndMaybeGrantInviterReward` 需要在同一事务内锁定 tracker 行，累加消费，判断阈值，发放邀请人赠金，设置 `inviter_reward_granted=true`。否则同一 invitee 的并发请求同时跨过阈值时会给邀请人发多笔 ¥10。

8. 奖励金额币种和显示单位不一致。

   计划中使用 `¥10`，现有充值/余额代码和 bind-key 示例多处用 `$` / USD 语义，例如 `GrantedGift` 注释和充值折扣文案。需要确定系统内部金额单位是 USD、CNY 还是站内余额单位，避免 UI 写人民币但余额按美元扣减。

9. 赠金发放的 `SourceRef` 不足以幂等。

   `SourceRef: inviter:%d` / `invitee:%d` 便于审计，但 `user_gifts` 当前没有 `(user_id, source, source_ref)` 唯一约束。仅靠 `referral_reward_tracker` 布尔字段可以幂等，但必须先锁 tracker 再发 gift，并在同一事务内更新 gift id。计划需要写明这一点。

10. 公告 targeting 后端扩展遗漏前端编辑器和 TS 类型。

   计划只描述后端 `referral` 条件，但实际前端有 `AnnouncementTargetingEditor.vue` 和 `frontend/src/types/index.ts`，当前 condition type 只有 `subscription | balance`。如果不改前端，管理员无法配置 referral targeting，或者保存时类型/表单丢字段。

11. i18n 文件路径写错。

   计划写 `frontend/src/i18n/locales/zh.json` / `en.json`，实际项目使用 `zh.ts` / `en.ts`。实施计划应修正路径，避免开发时新增错文件。

12. 系统设置只列 key，未覆盖持久化、DTO、管理端表单。

   新增 referral reward 设置需要同步：
   - `domain_constants.go` / `setting_service.go` 默认值、解析和保存。
   - `handler/dto/settings.go`、管理员 settings handler 请求/响应。
   - 前端管理设置页展示和保存。

## 设计缺口

13. BindKey 折扣配置没有管理 API/UI 方案。

   计划在 `BindKeyConfig` 增加 `RechargeDiscount`，但现有 ops API 只列出 bind-key gift setting 和 registration window。需要补齐如何配置、校验、显示折扣率/上限/有效天数，否则功能只能靠直接写 JSONB。

14. 折扣配置校验缺失。

   需要明确 `DiscountRate` 范围、`MaxAmount` 是否必须大于 0、精度和舍入策略。建议后端校验 `0 < rate <= 合理上限`，`max_amount > 0`，所有金额按 decimal 计算，避免 float 累计误差影响额度上限。

15. `discount_max_amount` 语义需要明确是“可参与折扣的充值本金上限”还是“最多赠送的 bonus 上限”。

   计划写“最大可享受折扣的充值总额”，公式也是按本金上限计算；前端文案“最高 $Y”容易被理解为最高额外获得 $Y。建议文案和字段名统一，例如 `max_discountable_recharge_amount`，或改成 `max_bonus_amount` 并调整公式。

16. `/api/referral/status` 返回结构不足。

   页面需要展示折扣状态、规则、邀请链接、开关状态、奖励进度摘要。计划只说返回“双向奖励开关状态和摘要”，需要定义字段，尤其是：
   - 当前用户有效折扣：rate、remaining eligible amount、valid_until。
   - 当前用户自己的 aff_code/link。
   - 是否已有 inviter、是否已拿 invitee reward。
   - 邀请人奖励统计可以显示聚合，不暴露单个 invitee 消费进度。

17. “被邀请人获得与邀请人完全相同资格”与系统开关关系不清晰。

   如果 `referral_reward_enabled=false` 或 `affiliate_enabled=false`，裂变传播、注册赠金、邀请人达标赠金、充值折扣继承分别是否停用需要明确。尤其现有 affiliate 总开关关闭会让 `AccrueInviteRebateForOrder` 停止，但是否仍允许绑定关系和双向赠金需要独立定义。

18. 公告 targeting 的查询成本和接口变更需补充。

   `AnnouncementTargeting.Matches` 改签名会影响现有单测和调用点。`ListForUser` 每次查询公告时额外查 affiliate 状态，可以接受，但应封装为 repository 方法并有降级策略。前端 targeting editor 也需要新增 `referral_value` 的展示、校验和 i18n。

## 测试建议

19. 充值折扣测试：
   - 同一订单 fulfillment 重试只发一次折扣赠金。
   - 两笔并发充值不会超过 `max_amount`。
   - 订单金额超过剩余额度时只按剩余额度计算 bonus。
   - 折扣过期、无效配置、多折扣并存的选择规则。

20. 双向奖励测试：
   - email 注册和 OAuth 注册均绑定 inviter 后发 invitee reward。
   - affiliate 绑定失败、自邀请、重复绑定不发奖励。
   - 同一 invitee 多个并发消费请求跨阈值只给 inviter 发一次。
   - 消费金额包含 gift/recharge 两部分，失败请求和重复请求不累计。

21. 裂变传播测试：
   - A 有 bind-key 折扣，B 通过 A 注册后获得继承折扣，C 通过 B 注册继续继承。
   - B 无折扣或折扣过期时是否传播，按明确规则验证。
   - inherited discount 不依赖 `api_key_id` 非空。

22. 公告 targeting 测试：
   - `has_inviter`、`is_inviter`、`no_inviter` 的后端匹配和 validate。
   - 原有 subscription/balance targeting 向后兼容。
   - 管理端创建/编辑 referral 条件后能完整保存和回显。

## 建议调整优先级

建议先把功能拆成三个可独立上线的阶段：

1. 先做 BindKey 充值折扣，补齐数据模型、幂等和支付链路。
2. 再做双向奖励，先不做无限裂变，确保注册入口和消费达标幂等可靠。
3. 最后做裂变传播和公告 targeting。裂变传播依赖折扣模型泛化，公告 targeting 是相对独立的管理能力，不应和返利核心链路耦合上线。
