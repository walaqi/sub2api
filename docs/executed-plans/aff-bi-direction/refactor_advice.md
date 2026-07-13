Findings

  1. High: Change request 和前文资格定义冲突，必须先统一。
     docs/pending-plans/aff-bi-direction/plan.md:474 仍写 eligible = valid_until >= now AND total_discounted < max_discountable_amount，但 docs/pending-plans/aff-bi-direction/plan.md:1081
     又改成“仅由时间窗口决定”。这会导致 /referral/status、前端入口展示、inviter_eligible_at_bind、折扣继承四套口径不一致。建议把第 474 行和页面状态文案一起改掉：超级邀请资格只看 valid_from
     <= now AND (valid_until IS NULL OR valid_until >= now)。

  2. High: inviter_eligible_at_bind DEFAULT TRUE 对存量数据向后兼容可以，但对“异步 hook 丢失后 lazy 补建 tracker”有误判风险。
     当前 TrackSpendAndMaybeGrantInviterReward 会在无 tracker 时从 user_affiliates 补建 tracker，实际代码见 backend/internal/service/referral_reward_service.go:124。方案说补建时“判定当前邀
     请人是否有资格”，见 docs/pending-plans/aff-bi-direction/plan.md:1220。这不是绑定时资格，可能把绑定时有资格、消费时已过期的 invitee 错误标成 false。建议：OnInviterBound 必须成为资格快
     照的权威路径；lazy 补建只能用于 race fallback，最好在计划里明确该路径的保守策略和可接受误差，或从 user_affiliates 增加/使用绑定时间来按 bind time 查询资格。

  3. High: QueryDiscountsForInheritance 只改查询条件还不够，相关索引仍按“未耗尽额度”过滤。
     当前迁移索引 backend/migrations/165_user_recharge_discounts.sql:21 是：
     WHERE total_discounted < max_discountable_amount。
     新查询去掉额度条件后，这个索引对耗尽额度的折扣不可用。数据量大时 /register/hook 路径会退化。建议新增独立索引，例如 (user_id, valid_until) 或 (user_id, valid_from, valid_until)，不带
     total_discounted partial 条件。

  4. Medium: “仅由时间窗口决定”还需要明确 valid_from 和 valid_until IS NULL 语义。
     方案正文多处说只看 valid_until >= NOW()，但实现 SQL 包含 valid_from <= NOW() 和 valid_until IS NULL OR valid_until >= NOW()，见 docs/pending-plans/aff-bi-direction/plan.md:1247。实际
     表允许 valid_until 为 NULL，见 backend/migrations/165_user_recharge_discounts.sql:12。建议文案统一成：资格看“当前处于有效时间窗口”，即 valid_from <= now AND (valid_until IS NULL OR
     valid_until >= now)。

  5. Medium: Gap 3 的设置改动文件清单不完整，容易漏掉 admin 读写链路。
     现有配置不只在 GetReferralRewardConfig 读，还在 settings view 聚合、admin update DTO、change log、前端 settings API/type/form 中各维护一份，相关现状见 backend/internal/service/
     setting_service.go:3609、backend/internal/handler/admin/setting_handler.go:668、frontend/src/views/admin/SettingsView.vue:5750。方案第 1336 行只笼统写 UI，建议清单明确补齐：
     domain_constants.go、SettingService.GetSettings/UpdateSettings、admin request/response DTO、change list、frontend/src/api/admin/settings.ts、SettingsView.vue 默认值/submit payload。

  6. Medium: RechargeDiscountRepo 接口扩展会影响 handler 依赖，不只是 test stubs。
     RechargeDiscountHandler 也直接依赖 service.RechargeDiscountRepo，见 backend/internal/handler/recharge_discount_handler.go:13。虽然真实 adapter 会实现新方法，但所有测试 mock/stub、编译
     期 fake 都要更新。方案写“所有 stub/mock”，方向对，但建议执行前用 rg "RechargeDiscountRepo|QueryActiveDiscountsReadOnly" 明确列出影响面。

  Summary
  方案的大方向是正确的：用 tracker 快照字段解决邀请人达标赠金资格，用新的 inheritance query 解耦额度耗尽，用配置扩展邀请人赠金扣除模式。

  但我建议先改 plan 本身再实施：统一 eligible 定义、明确 lazy 补建的绑定时资格语义、补索引、补完整配置链路和测试清单。否则实现出来很可能后端发奖正确了，但 /referral/status 和前端展示仍按旧
  口径。

  还有, 方案是不是在单点解决问题, 没有通盘考虑,整体规划
• 是的，我认为这个方案明显偏“单点补洞”，还没有通盘设计完整。

  它现在是在三个症状上分别补：

  - 邀请人过期后仍拿达标赠金 → tracker 加 inviter_eligible_at_bind
  - 额度耗尽后不能传播折扣 → 新增 QueryDiscountsForInheritance
  - 邀请人赠金 mode 不可配 → 加 setting

  这些点本身都合理，但缺少一个统一的“超级邀请状态机/资格模型”。所以容易继续出现口径漂移，比如：

  - /referral/status 的 eligible 到底是“页面展示资格”、“传播资格”、“自己充值折扣可用资格”，还是“邀请人达标赠金资格”？
  - 折扣 active、继承 eligible、邀请人 reward eligible、普通 aff invite 可用，是不是同一个概念？
  - total_discounted >= max 对哪些能力失效？只影响自己充值折扣，还是影响页面入口？
  - referral_reward_enabled=false 时，绑定、tracker、被邀请人赠金、邀请人赠金、折扣继承分别是什么行为？
  - lazy 补建 tracker 时没有绑定时快照，应该如何处理？
  - 存量 tracker 默认 TRUE 是产品决策，还是技术兼容？是否需要审计/回填策略？
  - 前端显示“超级邀请资格”时，用户看到的是传播能力，还是可用折扣额度？

  我建议先把模型重写成四个独立能力，而不是继续叫一个模糊的 eligible：

  1. invite_link_usable
     普通邀请码是否可用于注册绑定。按你现在语义，应始终可用，不因超级邀请资格失效而禁用。

  2. invitee_signup_reward_enabled
     被邀请人注册是否拿赠金。由全局 referral_reward_enabled 和注册绑定成功决定，不依赖邀请人资格。

  3. discount_inheritance_eligible
     被邀请人是否继承折扣。看邀请人在绑定时是否有处于时间窗口内的折扣，不看额度是否耗尽。

  4. inviter_reward_eligible_for_this_invitee
     邀请人是否能因这个 invitee 后续达标拿赠金。必须在绑定时快照记录，后续消费达标只读这个快照。

  然后数据模型也围绕这个规划：

  referral_reward_tracker
    inviter_id
    invitee_id
    inviter_eligible_at_bind -- 更准确可命名为 inviter_reward_eligible_at_bind
    discount_inherited_at
    invitee_reward_granted
    inviter_reward_granted
    spend_threshold
    invitee_spend_tracked

  我会倾向把字段命名得更具体：inviter_reward_eligible_at_bind，不要叫泛泛的 inviter_eligible_at_bind。因为邀请人资格失去后，邀请码仍可用，被邀请人仍拿赠金，所以“inviter eligible”这个名字本
  身就容易再次误解。

  结论：这个 change request 方向没错，但应先升级成整体规则重构。否则现在修完三个 gap，后面大概率还会在 status API、前端文案、lazy tracker、开关语义、测试断言上继续补洞。


  不一定大，取决于做到什么程度。

  我建议不要做“大重构”，而是做一个小型规则收敛，工作量可控：

  1. 先改 plan 里的概念
     把一个模糊的 eligible 拆成 3-4 个明确能力。这个主要是文档工作，成本低，但能防止后面继续误实现。

  2. 代码只做最小必要改动
     不需要重写 referral 系统。核心还是：
      - tracker 加 inviter_reward_eligible_at_bind
      - 折扣继承查询改成只看时间窗口
      - TrackSpend... 发邀请人赠金前检查快照字段
      - /referral/status 的 eligible 口径同步

  3. 暂时不扩展复杂状态机
     不需要新增多张表，也不需要把所有状态都做成 API 字段。只要内部命名和文档说清楚即可。

  4. 测试补关键路径
     加 3-5 个测试就够：
      - 邀请人折扣过期后注册：invitee 拿赠金、不继承折扣、inviter 后续不拿达标赠金
      - 邀请人折扣额度耗尽但未过期：invitee 继承折扣、inviter 后续可拿达标赠金
      - 存量 tracker 默认 true 行为不变
      - ratio mode 配置能正确传给 gift engine
      - /referral/status eligible 按新口径返回

  所以实际工作量我估计是中小型，不是大工程。

  比较合理的拆法：

  - Phase 1：规则收敛 + Gap 1/2
    这是必须做的，后端为主，风险可控。

  - Phase 2：Gap 3 邀请人赠金 mode 配置
    这是产品增强，不是资格语义 bug，可以单独做，避免把一次变更搞得太大。

  我的建议：现在不要把 Gap 3 混进同一个 change request。先把“资格语义”修干净，工作量会小很多，也更容易 review。