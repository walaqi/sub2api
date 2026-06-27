# 超级邀请返利 + BindKey 充值折扣 实现计划

## 概述

本计划包含五个子功能：
1. Dashboard 快捷操作区增加"绑定赠金"和"超级邀请"入口
2. BindKey 充值折扣属性（i18n 显示名：中文"超级邀请返利" / 英文 "Super Referral Bonus"）
3. 充值时自动应用折扣（含幂等和并发安全）
4. "超级邀请"双向奖励系统 + 裂变传播
5. 公告 Targeting 扩展（被邀请人弹窗通知）

**金额单位约定：系统内部统一使用 USD（美元），与现有 balance/gift/affiliate 一致。前端展示时按 locale 格式化为 $ 符号。计划中标注的"$10"均为 10 USD。**

---

## 功能 1：Dashboard 快捷操作 — 绑定赠金

### 改动范围

| 文件 | 改动 |
|------|------|
| `frontend/src/components/user/dashboard/UserDashboardQuickActions.vue` | 新增按钮 |
| `frontend/src/components/icons/Icon.vue` (或 svg 目录) | 新增 gift-key 图标 |
| `frontend/src/i18n/locales/zh.ts` / `en.ts` | 新增 i18n key |

### 实现细节

在现有三个按钮（API Keys / Usage / Redeem Code）之后新增：

```html
<!-- 绑定赠金 -->
<button @click="router.push('/bind-key')" class="group flex w-full ...">
  <div class="... bg-violet-100 dark:bg-violet-900/30">
    <Icon name="giftKey" size="lg" class="text-violet-600 dark:text-violet-400" />
  </div>
  <div>
    <p>{{ t('dashboard.bindGiftKey') }}</p>
    <p>{{ t('dashboard.bindGiftKeyDesc') }}</p>
  </div>
</button>
```

图标选用：一个 key + gift 组合的 SVG（参考现有 Icon 组件 registry，新增 `giftKey` 名称）。

---

## 功能 2 + 3：BindKey 充值折扣

### 概念设计

BindKey（池 key）新增可选属性"充值折扣"：
- `discount_rate`：折扣比例（如 0.1 表示充值额外获得 10% 余额）
- `max_discountable_amount`：有效期内最大可参与折扣的**充值本金**总额（非 bonus 上限）
- `valid_days`：折扣有效天数（从领取时刻起算，独立于赠金过期时间）
- 折扣从 bind-key **领取时间**开始算，持续 `valid_days` 天
- 如果 bind-key 没有配置额度（gift_settings 无行或 amount 相关字段无值），则跳过赠金绑定步骤

**语义明确：`max_discountable_amount` 是可参与折扣的充值本金上限。bonus = 本金 × rate。前端文案应显示"有效期内充值前 $X 可额外获得 Y%"。**

### 数据层改动

#### 扩展 `domain.BindKeyConfig`

```go
// backend/internal/domain/bind_key.go
type BindKeyConfig struct {
    Unlimit            *bool                       `json:"unlimit,omitempty"`
    RegistrationWindow *BindKeyRegistrationWindow  `json:"registration_window,omitempty"`
    // NEW: 充值折扣配置
    RechargeDiscount   *BindKeyRechargeDiscount    `json:"recharge_discount,omitempty"`
}

type BindKeyRechargeDiscount struct {
    Enabled              bool    `json:"enabled"`
    DiscountRate         float64 `json:"discount_rate"`          // 0.1 = 额外 10%
    MaxDiscountableAmount float64 `json:"max_discountable_amount"` // 可参与折扣的充值本金上限
    ValidDays            int     `json:"valid_days"`             // 折扣有效天数（独立于赠金过期）
}
```

**校验规则（后端 + 管理端表单）：**
- `0 < DiscountRate <= 1.0`（100% 为上限）
- `MaxDiscountableAmount > 0`
- `ValidDays >= 1`
- 所有金额计算使用 `shopspring/decimal`，避免 float 累计误差

优点：利用现有 `bind_key_gift_settings.config` JSONB 列，无需改 schema。

#### 新增用户充值折扣表（泛化为支持多来源）

```sql
-- migration: xxx_user_recharge_discounts.sql
CREATE TABLE IF NOT EXISTS user_recharge_discounts (
    id                    BIGSERIAL PRIMARY KEY,
    user_id               BIGINT NOT NULL,
    source                VARCHAR(32) NOT NULL,       -- 'bind_key' | 'referral_inherit'
    source_ref            VARCHAR(128),               -- bind_key: 'api_key:{id}', referral: 'inviter:{user_id}'
    origin_api_key_id     BIGINT,                     -- bind_key 来源时非 null；裂变继承时 null
    total_discounted      DECIMAL(20,8) NOT NULL DEFAULT 0,  -- 已参与折扣的充值本金累计
    discount_rate         DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_discountable_amount DECIMAL(20,8) NOT NULL DEFAULT 0,
    valid_from            TIMESTAMPTZ NOT NULL,
    valid_until           TIMESTAMPTZ,                -- null = 永不过期
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- DB-level 防御性约束
    CONSTRAINT chk_urd_rate CHECK (discount_rate > 0 AND discount_rate <= 1),
    CONSTRAINT chk_urd_max CHECK (max_discountable_amount > 0),
    CONSTRAINT chk_urd_total CHECK (total_discounted >= 0 AND total_discounted <= max_discountable_amount),
    CONSTRAINT chk_urd_source CHECK (source IN ('bind_key', 'referral_inherit'))
);
-- 幂等键：同一来源对同一用户不重复创建
CREATE UNIQUE INDEX idx_urd_user_source_ref ON user_recharge_discounts(user_id, source, source_ref);
CREATE INDEX idx_urd_user_valid ON user_recharge_discounts(user_id, valid_until)
    WHERE total_discounted < max_discountable_amount;
```

**与 review 对应：**
- `origin_api_key_id` nullable → 解决裂变继承无 key 的问题
- `source` + `source_ref` → 区分直接绑定 vs 裂变继承
- unique index `(user_id, source, source_ref)` → 幂等创建

#### 新增折扣发放去重表

```sql
-- 防止 fulfillment 重试导致重复发放（有意设计：payment_order_id 全局唯一，当前不允许一笔订单拆多折扣）
CREATE TABLE IF NOT EXISTS recharge_discount_applications (
    id                    BIGSERIAL PRIMARY KEY,
    user_id               BIGINT NOT NULL,
    discount_id           BIGINT NOT NULL REFERENCES user_recharge_discounts(id),
    payment_order_id      BIGINT NOT NULL,
    applied_amount        DECIMAL(20,8) NOT NULL,     -- 本次参与折扣的充值本金
    bonus_amount          DECIMAL(20,8) NOT NULL,     -- 本次发放的 bonus
    discount_rate_snapshot DOUBLE PRECISION NOT NULL,  -- 发放时的折扣率快照（审计用）
    gift_id               BIGINT,                     -- 发放的 user_gifts.id
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_rda_order ON recharge_discount_applications(payment_order_id);
```

**多条有效折扣的选取规则：折扣率最高者优先；折扣率相同时取到期时间最近的（鼓励用户先消费即将过期的）。**

#### BindKey Commit 时写入折扣记录

在 `keybind.Service.Commit()` 中，key 转移与折扣记录创建在**同一 DB 事务**内完成：

1. 读取 key 的 config（已在 Commit 流程中通过 resolver 获取）
2. 若 `config.RechargeDiscount != nil && config.RechargeDiscount.Enabled`：
   - 在同一事务中 INSERT `user_recharge_discounts`
   - `source = 'bind_key'`, `source_ref = 'api_key:{keyID}'`
   - `valid_from = now()`, `valid_until = now() + valid_days * 24h`
3. 赠金发放继续 best-effort（失败不回滚折扣记录）

**事务边界：** key 转移 + 折扣记录 = 强一致（一个事务）。赠金 = best-effort（失败记日志，不影响折扣）。

### 充值时应用折扣（幂等 + 并发安全）

在 `PaymentService.doBalance()` 中，**与 `applyAffiliateRebateForOrder` 并列、`markCompleted()` 之前**调用：

```go
// doBalance() 流程（修改后）：
// 1. redeem
// 2. applyAffiliateRebateForOrder(ctx, o)
// 3. applyRechargeDiscountForOrder(ctx, o)  ← 新增，在 markCompleted 前
// 4. markCompleted(ctx, o, "RECHARGE_SUCCESS")
```

**语义选择：强一致。** 折扣发放失败则 `doBalance()` 返回错误，订单保持 RECHARGING 状态可重试。`recharge_discount_applications(payment_order_id)` 唯一索引确保重试不会重复发放。

```go
func (s *PaymentService) applyRechargeDiscountForOrder(ctx context.Context, order *ent.PaymentOrder) error {
    // 1. 幂等检查：查 recharge_discount_applications 是否已有该 order_id
    if exists := checkDiscountApplicationExists(ctx, order.ID); exists {
        return nil // 已处理过，幂等跳过
    }

    // 2. 查询用户最优有效折扣（FOR UPDATE 锁行防并发）
    discount := queryBestActiveDiscount(ctx, order.UserID) // SELECT ... FOR UPDATE
    if discount == nil {
        return nil
    }

    // 3. 计算 eligible amount
    remaining := discount.MaxDiscountableAmount - discount.TotalDiscounted
    if remaining <= 0 {
        return nil
    }
    appliedAmount := min(order.Amount, remaining) // order.Amount 是充值本金
    bonus := decimal(appliedAmount) * decimal(discount.DiscountRate)

    // 4. 同一事务内（使用 txCtx := dbent.NewTxContext(ctx, tx)）：
    //    a) 更新 discount.total_discounted += appliedAmount
    //    b) gift.Engine.Grant(txCtx, bonus, priority, expires=discount.valid_until)
    //    c) INSERT recharge_discount_applications(order_id, discount_id, applied_amount, bonus, gift_id)
    // 5. 事务提交失败 → doBalance 返回 error → 订单保持 RECHARGING 可重试
}
```

**并发安全：** `FOR UPDATE` 锁住选中的 `user_recharge_discounts` 行，两笔并发充值不会超 `max_discountable_amount`。

**幂等安全：** `recharge_discount_applications` 的 unique index `(payment_order_id)` 确保重试/重放不会重复发放。

**管理端 API：** 扩展现有 `gift_ops_handler.go` 的 PATCH/PUT bind_key_gift_settings 接口，支持 `config.recharge_discount` 字段的读写。

**管理端 UI：** 在 bind-key gift settings 编辑表单中新增"充值折扣"配置区：
- 开关：是否启用充值折扣
- 折扣率：输入框 + 校验 (0, 1.0]
- 充值本金上限：输入框 + 校验 > 0
- 有效天数：输入框 + 校验 >= 1

### 前端改动

BindKey 绑定成功后的反馈中，如果返回了折扣信息，显示折扣卡片：
- "恭喜获得充值折扣：有效期 X 天内，前 $Y 充值可额外获得 Z% 余额"

---

## 功能 4：邀请用户获额度（双向奖励）

### 与现有 Affiliate 系统的关系

现有 affiliate 系统是**百分比返利**模型（邀请人获得被邀请人充值额的 N%，转入 aff_quota 后手动提现）。

新的双向奖励是**定额赠金**模型：
- 被邀请人注册即得赠金
- 邀请人在被邀请人消费达标后获得赠金

**决策：复用现有 affiliate 绑定关系，新增独立的双向赠金逻辑。** 两套奖励完全并行、互不干扰：
- 现有 affiliate 返利系统保持不变：被邀请人充值 → 邀请人获得充值额 N% 的返利（进 aff_quota，需手动提现）
- 新增双向赠金系统：被邀请人注册 → 被邀请人立即获赠金；被邀请人消费达标 → 邀请人获赠金

**关键不变量：被邀请人完整参与现有 affiliate 返利序列。** 即：被邀请人注册时绑定 inviter_id → 之后被邀请人每次充值 → `AccrueInviteRebateForOrder` 正常触发 → 邀请人正常获得百分比返利。新增的双向赠金奖励是附加层，不替代、不阻断、不影响原返利链路。

**功能开关独立性：** `referral_reward_enabled` 是独立开关，与 `affiliate_enabled` 不联动。关闭 affiliate 总开关会停止百分比返利，但不影响双向赠金。关闭 `referral_reward_enabled` 只停止新的赠金发放和折扣继承，不影响 affiliate 返利。

### 奖励规则

| 角色 | 触发条件 | 奖励 | 过期 |
|------|----------|------|------|
| 被邀请人 | 注册成功并绑定邀请关系 | $10 优先扣除赠金 | 2 天（自获得之日起） |
| 邀请人 | 被邀请人累计消费达 $10 | $10 优先扣除赠金 | 30 天（自获得之日起） |

- "消费"= 实际扣费总额（`GiftCost + RechargeCost`，即 usage log 的 balance_cost），不含未扣费的失败请求
- 每个被邀请人只能触发一次邀请人奖励
- 金额单位：USD（系统内部统一单位）

### 数据层

#### 新增追踪表

```sql
-- migration: xxx_referral_reward_tracker.sql
CREATE TABLE IF NOT EXISTS referral_reward_tracker (
    id              BIGSERIAL PRIMARY KEY,
    inviter_id      BIGINT NOT NULL,
    invitee_id      BIGINT NOT NULL,
    -- 被邀请人奖励
    invitee_reward_granted  BOOLEAN NOT NULL DEFAULT FALSE,
    invitee_reward_gift_id  BIGINT,
    invitee_reward_at       TIMESTAMPTZ,
    -- 邀请人奖励
    inviter_reward_granted  BOOLEAN NOT NULL DEFAULT FALSE,
    inviter_reward_gift_id  BIGINT,
    inviter_reward_at       TIMESTAMPTZ,
    -- 追踪被邀请人消费进度
    invitee_spend_tracked   DECIMAL(20,8) NOT NULL DEFAULT 0,
    spend_threshold         DECIMAL(20,8) NOT NULL DEFAULT 10,  -- $10
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_rrt_inviter_invitee ON referral_reward_tracker(inviter_id, invitee_id);
CREATE INDEX idx_rrt_invitee ON referral_reward_tracker(invitee_id);
CREATE INDEX idx_rrt_pending_inviter ON referral_reward_tracker(inviter_reward_granted, invitee_id)
    WHERE inviter_reward_granted = FALSE;
```

#### 新增消费事件去重表

```sql
-- 防止 billing 事件重放/重试导致 spend_tracked 重复累加
CREATE TABLE IF NOT EXISTS referral_spend_events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        VARCHAR(128) NOT NULL,  -- 唯一来源：billing:{request_id}:{api_key_id}
    invitee_id      BIGINT NOT NULL,
    amount          DECIMAL(20,8) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_rse_event ON referral_spend_events(event_id);
```

#### 新增 gift Source

```go
SourceReferralInvitee  Source = "referral_invitee"   // 被邀请人注册奖励
SourceReferralInviter  Source = "referral_inviter"   // 邀请人消费达标奖励
SourceRechargeDiscount Source = "recharge_discount"  // 充值折扣 bonus
```

### 后端服务层

新增 `backend/internal/service/referral_reward_service.go`：

```go
type ReferralRewardService struct {
    entClient       *ent.Client
    giftEngine      *gift.Engine
    settingService  *SettingService
    authCacheInval  APIKeyAuthCacheInvalidator
    billingCache    *BillingCacheService
}

// GrantInviteeReward 被邀请人注册时调用
func (s *ReferralRewardService) GrantInviteeReward(ctx context.Context, inviterID, inviteeID int64) error

// TrackSpendAndMaybeGrantInviterReward 每次计费成功后调用
func (s *ReferralRewardService) TrackSpendAndMaybeGrantInviterReward(ctx context.Context, inviteeID int64, eventID string, spendAmount float64) error

// InheritDiscountFromInviter 注册时继承邀请人的折扣
func (s *ReferralRewardService) InheritDiscountFromInviter(ctx context.Context, inviterID, inviteeID int64) error
```

#### 触发点

1. **被邀请人奖励 + 折扣继承触发：**

   **不在各注册入口分散调用，而是在 affiliate 绑定成功的中心位置触发。**

   定义小接口避免循环依赖：
   ```go
   // backend/internal/service/affiliate_hooks.go
   type InviterBoundHook interface {
       OnInviterBound(ctx context.Context, inviterID, inviteeID int64)
   }
   ```

   `AffiliateService` 可选注入该 hook（wire 注入时由 `ReferralRewardService` 实现）：
   ```go
   type AffiliateService struct {
       // ...existing fields...
       inviterBoundHook InviterBoundHook // 可选，nil 时不触发
   }
   ```

   `BindInviterByCode` 绑定成功后触发：
   ```go
   if bound {
       if s.inviterBoundHook != nil {
           // 使用 detached context，不捕获 gin/request context
           hookCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
           go func() {
               defer cancel()
               s.inviterBoundHook.OnInviterBound(hookCtx, inviterID, userID)
           }()
       }
   }
   ```

   **异步 context 安全：** 所有异步调用使用 `context.WithTimeout(context.Background(), ...)` 而非请求 ctx。避免 HTTP 请求结束后 ctx 被取消导致异步任务失败。

   **覆盖所有注册入口：** email 注册、OAuth 注册（LinuxDo/微信/OIDC/钉钉）均通过 `BindInviterByCode` 绑定邀请关系，因此中心触发点自动覆盖全部入口。

   **`OnInviterBound` 实现（`ReferralRewardService`）：**
   - 创建 `referral_reward_tracker` 行（`INSERT ... ON CONFLICT DO NOTHING`，开关关闭时也创建，确保后续开启时历史 invitee 能被追踪）
   - 若 `referral_reward_enabled`：调用 `GrantInviteeReward` + `InheritDiscountFromInviter`
   - 若功能关闭：只创建 tracker，不发放

2. **邀请人奖励触发：**

   **事件源：billing 成功应用事件。** 不依赖 best-effort 的 usage log ID。

   触发位置：`gateway_service.go` 中调用 `applyUsageBilling()` 的 service 方法内，在该 helper 返回 `result.Applied == true` 后触发。

   **注意：** `applyUsageBilling` 是 package-level helper（不是 `GatewayService` 方法），无法直接访问 `s`。实现方式有两种：
   - 方案 A（推荐）：在调用 `applyUsageBilling()` 的 service 方法（如 `postStreamBilling` / `postNonStreamBilling`）返回后，根据 result 触发
   - 方案 B：将 referral hook 作为小接口注入 `billingDeps`，由 helper 内部回调

   示例（方案 A，在 service 方法内）：
   ```go
   // gateway_service.go 的 service 方法中，applyUsageBilling 返回后：
   if result != nil && result.Applied && cmd.BalanceCost > 0 {
       eventID := fmt.Sprintf("billing:%s:%d", cmd.RequestID, cmd.APIKeyID)
       hookCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
       go func() {
           defer cancel()
           s.referralReward.TrackSpendAndMaybeGrantInviterReward(hookCtx, userID, eventID, cmd.BalanceCost)
       }()
   }
   ```

   **为什么用 billing 而非 usage log：**
   - `applyUsageBilling → repo.Apply` 有 `usage_billing_dedup` 做去重，`result.Applied=true` 代表扣费确认成功
   - usage log 是 best-effort（`writeUsageLogBestEffort`），可能批量异步写入，拿不到稳定的 DB ID
   - `cmd.BalanceCost` = `GiftCost + RechargeCost`，精确等于本次实际扣费

   **消费事件幂等：** `eventID = "billing:{request_id}:{api_key_id}"` 写入 `referral_spend_events` 的 unique index，与 `usage_billing_dedup` 的成功扣费语义一致。重放不累加。

   **异步失败行为：** 若异步任务失败且未写入 `referral_spend_events`，该笔消费金额会"丢失"（不累计到 tracked）。这是 best-effort 策略，与现有 affiliate rebate 一致。后续消费事件会继续累计后续金额。产品可接受——最坏情况是邀请人稍晚才达标，不会多发。

#### 并发安全

`TrackSpendAndMaybeGrantInviterReward` 在同一事务内：
1. 检查 `referral_spend_events` 是否已有该 eventID → 有则跳过
2. INSERT 到 `referral_spend_events`
3. `SELECT ... FROM referral_reward_tracker WHERE invitee_id = ? FOR UPDATE`
4. 累加 `invitee_spend_tracked += amount`
5. 若 `invitee_spend_tracked >= spend_threshold && !inviter_reward_granted`：
   - `gift.Engine.Grant(inviterID, ...)`
   - 更新 `inviter_reward_granted = true, inviter_reward_gift_id = giftID`
6. COMMIT

`FOR UPDATE` 确保同一 invitee 的并发消费事件串行处理，不会给邀请人重复发放。

#### Gift 发放参数

```go
// 被邀请人
gift.GrantInput{
    UserID:    inviteeID,
    Amount:    10.0,  // USD
    Mode:      gift.DeductionModePriority,
    ExpiresAt: now.Add(2 * 24 * time.Hour),
    Source:    gift.SourceReferralInvitee,
    SourceRef: fmt.Sprintf("inviter:%d", inviterID),
}

// 邀请人
gift.GrantInput{
    UserID:    inviterID,
    Amount:    10.0,  // USD
    Mode:      gift.DeductionModePriority,
    ExpiresAt: now.Add(30 * 24 * time.Hour),
    Source:    gift.SourceReferralInviter,
    SourceRef: fmt.Sprintf("invitee:%d", inviteeID),
}
```

`SourceRef` 确保管理员在"用户管理 → 用户充值和并发变动记录"对话框中可以看到赠金来源。

**幂等保证：** `GrantInviteeReward` 在发放前先锁 tracker 行检查 `invitee_reward_granted`，若已 true 则跳过。Gift 发放和 tracker 更新在同一事务内。

#### 系统设置

在 `SettingService` 中新增开关（同步更新 `domain_constants.go` 默认值、`setting_service.go` 解析保存、`handler/dto/settings.go` DTO、管理端表单）：

```go
SettingKeyReferralRewardEnabled        = "referral_reward_enabled"          // 默认 false
SettingKeyReferralInviteeAmount        = "referral_invitee_amount"          // 默认 10 (USD)
SettingKeyReferralInviteeExpiryDays    = "referral_invitee_expiry_days"     // 默认 2
SettingKeyReferralInviterAmount        = "referral_inviter_amount"          // 默认 10 (USD)
SettingKeyReferralInviterExpiryDays    = "referral_inviter_expiry_days"     // 默认 30
SettingKeyReferralSpendThreshold       = "referral_spend_threshold"         // 默认 10 (USD)
SettingKeyReferralDiscountValidDays    = "referral_discount_valid_days"     // 默认 30（裂变折扣有效天数）
```

**设置变更对已创建记录的影响：** threshold 等值在 tracker 创建时快照写入 `spend_threshold` 字段，后续修改不影响已存在的 tracker 行。

### 前端 — 新增超级邀请页面

#### 路由与页面定位

`/referral` → `frontend/src/views/user/ReferralView.vue`

**与现有 `/affiliate` 的关系：两页并存。**
- `/referral`（超级邀请）：面向普通用户，展示规则、邀请链接、折扣状态、被邀请人列表。Dashboard 快捷入口指向此页。
- `/affiliate`（邀请返利）：面向重度用户，展示返利比例、aff_quota 余额、冻结/历史、手动提现。侧栏保留链接。
- 两页共用同一个 `aff_code`/邀请链接，只是展示角度不同。

页面标题 i18n：
- 中文：`超级邀请`
- 英文：`Super Referral`

#### 页面结构

**超级邀请资格判定：** 用户拥有有效的充值折扣记录（`user_recharge_discounts` 中有 `valid_until >= now` 且 `total_discounted < max_discountable_amount` 的行）即视为"有超级邀请资格"。API `GET /api/referral/status` 返回的 `eligible` 字段标识此状态。

**页面分两种状态渲染：**

**状态 A：有超级邀请资格（eligible=true）— 完整页面**

```
┌──────────────────────────────────────────────────┐
│  超级邀请 / Super Referral                        │
│  ──────────────────────────────────────────       │
│  [规则说明卡片]                                   │
│  ┌────────────────────────────────────────────┐   │
│  │ 🎁 你邀请的好友立刻获得 $10 赠金（2天有效）│   │
│  │ 💰 好友消费满 $10 后，你也获得 $10 赠金    │   │
│  │    （30天有效，优先扣除）                   │   │
│  │ 🔥 好友同时获得充值折扣和邀请资格，         │   │
│  │    可继续邀请更多人，无限裂变！             │   │
│  │ ℹ️ 每位好友仅触发一次邀请人奖励             │   │
│  └────────────────────────────────────────────┘   │
│                                                   │
│  [充值折扣状态卡片]                               │
│  ┌────────────────────────────────────────────┐   │
│  │ 你当前的超级邀请返利：                      │   │
│  │ 充值额外获得 10% 余额 | 剩余额度 $80/$100  │   │
│  │ 有效期至 2026-07-15                        │   │
│  └────────────────────────────────────────────┘   │
│                                                   │
│  [邀请链接区域]  ← 仅有资格时显示               │
│  ┌────────────────────────────────────────────┐   │
│  │ 你的邀请链接：                              │   │
│  │ https://xxx.com/register?aff=XXXXXX [复制]  │   │
│  └────────────────────────────────────────────┘   │
│                                                   │
│  [被邀请人列表]                                   │
│  ┌────────────────────────────────────────────┐   │
│  │ 邮箱(脱敏) │ 注册时间 │ 状态              │   │
│  │ t***@g.com │ 06-25   │ ✅ 已注册          │   │
│  │ a***@q.com │ 06-26   │ ✅ 已注册          │   │
│  └────────────────────────────────────────────┘   │
│  (消费进度不显示，保护隐私)                       │
└──────────────────────────────────────────────────┘
```

**状态 B：无超级邀请资格（eligible=false）— 受限页面**

```
┌──────────────────────────────────────────────────┐
│  超级邀请 / Super Referral                        │
│  ──────────────────────────────────────────       │
│  [无资格提示卡片]                                 │
│  ┌────────────────────────────────────────────┐   │
│  │ ⚠️ 你暂未获得超级邀请资格                   │   │
│  │                                            │   │
│  │ 获得方式：                                  │   │
│  │ • 通过绑定赠金 Key 获得充值折扣后自动激活   │   │
│  │ • 通过其他用户的超级邀请链接注册后自动获得   │   │
│  └────────────────────────────────────────────┘   │
│                                                   │
│  [邀请链接区域 — 不显示，整块隐藏]                │
│                                                   │
│  [被邀请人列表]  ← 仍然显示（历史记录）           │
│  ┌────────────────────────────────────────────┐   │
│  │ 邮箱(脱敏) │ 注册时间 │ 状态              │   │
│  │ (暂无邀请记录)                             │   │
│  └────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
```

**Dashboard 快捷入口行为：**
- 有资格：显示"超级邀请"按钮，点击跳转 `/referral`
- 无资格：按钮仍然显示（让用户知道有这个功能），但 subtitle 改为"了解超级邀请"。跳转后看到状态 B 页面的引导提示。

#### 复用现有 affiliate 接口

- 邀请链接直接用现有 aff_code：`/register?aff={aff_code}`
- 被邀请人列表复用 `/api/affiliate` 接口中的 `invitees` 字段（已有脱敏）

#### 新增 API：`GET /api/referral/status`

**语义澄清：** `eligible=false` 仅控制"超级邀请"页面的邀请链接是否展示，**不影响** `/affiliate` 页面的普通邀请功能。用户在 `/affiliate` 始终可以看到自己的 aff_code 并邀请他人进入普通返利体系。"无超级邀请资格"仅代表该用户邀请的下线不会继承充值折扣。

**稳定响应结构（feature_enabled 无论 true/false 均返回全部字段）：**

```json
{
  "code": 0,
  "data": {
    "feature_enabled": true,
    "eligible": true,
    "aff_code": "ABCD1234",
    "invite_link": "https://xxx.com/register?aff=ABCD1234",
    "has_inviter": true,
    "invitee_reward_received": true,
    "discount": {
      "discount_rate": 0.1,
      "max_discountable_amount": 100,
      "total_discounted": 20,
      "remaining_eligible": 80,
      "valid_until": "2026-07-15T00:00:00Z"
    },
    "invitee_count": 3,
    "inviter_rewards_earned": 1
  }
}
```

字段说明：
- `feature_enabled`：系统开关。false 时前端隐藏整个超级邀请入口（但已获得的折扣仍继续生效）
- `eligible`：是否有超级邀请资格。前端据此决定是否显示邀请链接区域
- `aff_code` / `invite_link`：始终返回（用户始终有 aff_code），前端根据 `eligible` 决定是否渲染邀请链接区域
- `discount`：null 表示无有效折扣。`feature_enabled=false` 时仍返回已有折扣信息（用户有权看到）
- `invitee_count` / `inviter_rewards_earned`：始终返回（0 如果无记录）

**后端影响范围：**

| 文件 | 改动 |
|------|------|
| `backend/internal/handler/referral_handler.go` | 新增 handler（或挂到现有 user_handler） |
| `backend/internal/server/routes/user.go` | 注册 GET `/api/v1/referral/status` |
| `backend/internal/service/referral_reward_service.go` | `GetReferralStatus(ctx, userID)` 方法 |
| `backend/internal/handler/dto/referral.go` | 新增 DTO struct |
| `cmd/server/wire.go` | 注入 ReferralRewardService 到 handler |
| `frontend/src/api/referral.ts` | 新增 API wrapper |
| `frontend/src/views/user/ReferralView.vue` | 调用 API 渲染页面 |

### Dashboard 快捷操作 — 邀请用户获额度

与功能 1 同位置，新增第 5 个按钮：

```html
<!-- 超级邀请 -->
<button @click="router.push('/referral')" class="group flex w-full ...">
  <div class="... bg-indigo-100 dark:bg-indigo-900/30">
    <Icon name="userPlus" size="lg" class="text-indigo-600 dark:text-indigo-400" />
  </div>
  <div>
    <p>{{ t('dashboard.superReferral') }}</p>
    <p>{{ t('dashboard.superReferralDesc') }}</p>
  </div>
</button>
```

### i18n

```ts
// frontend/src/i18n/locales/zh.ts
"dashboard.superReferral": "超级邀请",
"dashboard.superReferralDesc": "超级邀请双向返利",
"dashboard.bindGiftKey": "绑定赠金",
"dashboard.bindGiftKeyDesc": "领取专属 Key 获得赠金",
"rechargeDiscount.title": "超级邀请返利",
"rechargeDiscount.hint": "有效期内充值前 ${max} 可额外获得 {rate}% 余额",

// frontend/src/i18n/locales/en.ts
"dashboard.superReferral": "Super Referral",
"dashboard.superReferralDesc": "Dual-reward referral bonus",
"dashboard.bindGiftKey": "Bind Gift Key",
"dashboard.bindGiftKeyDesc": "Claim a key and receive bonus credits",
"rechargeDiscount.title": "Super Referral Bonus",
"rechargeDiscount.hint": "Get extra {rate}% on your first ${max} recharge",
```

### 裂变传播机制

**核心规则：被邀请人获得与邀请人完全相同的超级邀请资格。**

当用户 A 通过超级邀请链接注册后，A 自动获得：
1. $10 注册赠金（2 天有效）
2. 充值折扣（折扣率、额度上限与邀请人一致）
3. 自己的超级邀请链接，可以继续邀请用户 B
4. 用户 B 同样获得上述全部资格，以此类推

**裂变链路图：**
```
原始邀请人(管理员配置 bind-key) 
  → 被邀请人 A（注册获赠金 + 充值折扣 + 自己的邀请资格）
    → 被邀请人 B（同上）
      → 被邀请人 C（同上）
        → ...无限裂变
```

**裂变传播条件：查询邀请人"当前有效"的折扣记录。**
- 邀请人折扣过期 → 被邀请人不继承折扣（但仍获注册赠金和邀请资格）
- 邀请人折扣仍有效 → 被邀请人继承等同折扣
- 被邀请人的折扣有效期独立计算（从自己注册时刻 + referral_discount_valid_days）

**实现方式（使用 `user_recharge_discounts` 表）：**

注册链路 `InheritDiscountFromInviter` 逻辑：
1. 被邀请人注册绑定 inviter 后（`OnInviterBound` 回调内）
2. 查询邀请人的 `user_recharge_discounts` 中当前有效的记录（`valid_from <= now AND (valid_until IS NULL OR valid_until >= now) AND total_discounted < max_discountable_amount`）
3. 若邀请人有有效折扣，为被邀请人 INSERT `user_recharge_discounts`：
   - `source = 'referral_inherit'`
   - `source_ref = 'inviter:{inviterID}'`
   - `origin_api_key_id = NULL`
   - `discount_rate` / `max_discountable_amount` 直接继承邀请人的值
   - `valid_from = now()`, `valid_until = now() + referral_discount_valid_days`
4. 被邀请人的 affiliate profile 自动生成（现有 `EnsureUserAffiliate` 逻辑），立即具备邀请他人的能力

**裂变折扣继承规则：**
- 折扣率：直接继承邀请人当前最优折扣的 `discount_rate`
- 最大额度：直接继承邀请人当前最优折扣的 `max_discountable_amount`
- 有效期：使用系统设置 `referral_discount_valid_days`（从被邀请人注册时刻起算）
- 无递减、无层级限制（所有被邀请人享受完全相同的折扣）
- 幂等：unique index `(user_id, source, source_ref)` 防止重复创建

---

## 功能 5：公告 Targeting 扩展 — 被邀请人弹窗通知

### 现状分析

当前 `AnnouncementTargeting` 系统（`backend/internal/domain/announcement.go`）支持两种条件类型：
- `subscription`：按用户订阅分组筛选（operator: `in`, `group_ids`）
- `balance`：按用户余额比较（operators: `gt/gte/lt/lte/eq`）

`Matches` 函数签名：
```go
func (t AnnouncementTargeting) Matches(balance float64, activeSubscriptionGroupIDs map[int64]struct{}) bool
```

**限制：无法按"是否为被邀请人"或任何用户属性筛选。**

### 扩展方案

新增条件类型 `referral`，支持筛选被邀请人/邀请人身份：

#### 后端改动

**1. 新增条件类型常量**

```go
// backend/internal/domain/announcement.go
const (
    AnnouncementConditionTypeSubscription = "subscription"
    AnnouncementConditionTypeBalance      = "balance"
    AnnouncementConditionTypeReferral     = "referral"  // NEW
)
```

**2. 扩展 AnnouncementCondition**

```go
type AnnouncementCondition struct {
    Type     string  `json:"type"`
    Operator string  `json:"operator"`
    GroupIDs []int64 `json:"group_ids,omitempty"`
    Value    float64 `json:"value,omitempty"`
    // NEW: referral 条件的属性值
    // operator: "eq"
    // value 字段复用为枚举语义：
    //   referral_value: "has_inviter" | "is_inviter" | "no_inviter"
    ReferralValue string `json:"referral_value,omitempty"`
}
```

**3. 扩展 Matches 签名**

```go
// UserTargetingContext 聚合用户所有可用于 targeting 的属性
type UserTargetingContext struct {
    Balance                    float64
    ActiveSubscriptionGroupIDs map[int64]struct{}
    HasInviter                 bool  // user_affiliates.inviter_id IS NOT NULL
    IsInviter                  bool  // user_affiliates.aff_count > 0
}

func (t AnnouncementTargeting) Matches(ctx UserTargetingContext) bool
```

原有的 `Matches(balance, groupIDs)` 签名改为接收 `UserTargetingContext`。**注意：这是编译级 breaking change（源码不兼容），但 API 层面和数据层面向后兼容。** 需同步更新全部调用点：
- `announcement_service.go` — `ListForUser` 和 `MarkRead` 两处
- `announcement_targeting_test.go` — 所有现有测试用例的 Matches 调用
- 前端无影响（HTTP API 不变）

**4. referral 条件匹配逻辑**

```go
case AnnouncementConditionTypeReferral:
    if c.Operator != AnnouncementOperatorEQ {
        return false
    }
    switch c.ReferralValue {
    case "has_inviter":
        return ctx.HasInviter
    case "is_inviter":
        return ctx.IsInviter
    case "no_inviter":
        return !ctx.HasInviter
    default:
        return false
    }
```

**5. ListForUser 构建 context**

在 `AnnouncementService.ListForUser()` 中：

```go
// 查询用户的 affiliate 状态
hasInviter := false
isInviter := false
if s.entClient != nil {
    row, err := queryUserAffiliateStatus(ctx, s.entClient, userID)
    if err == nil && row != nil {
        hasInviter = row.InviterID != nil
        isInviter = row.AffCount > 0
    }
}

targetCtx := domain.UserTargetingContext{
    Balance:                    user.Balance,
    ActiveSubscriptionGroupIDs: activeGroupIDs,
    HasInviter:                 hasInviter,
    IsInviter:                  isInviter,
}
```

**6. validate 扩展**

```go
case AnnouncementConditionTypeReferral:
    if c.Operator != AnnouncementOperatorEQ {
        return ErrAnnouncementInvalidTarget
    }
    switch c.ReferralValue {
    case "has_inviter", "is_inviter", "no_inviter":
        return nil
    default:
        return ErrAnnouncementInvalidTarget
    }
```

### 管理员使用方式

管理员在后台创建公告时：
1. 设置 notify_mode = `popup`
2. 设置 targeting:
```json
{
  "any_of": [{
    "all_of": [{
      "type": "referral",
      "operator": "eq",
      "referral_value": "has_inviter"
    }]
  }]
}
```
3. 公告内容写明超级邀请的权益：充值折扣、邀请资格等
4. 被邀请人登录后自动看到弹窗

### 前端管理端改动

公告编辑表单的 targeting 配置 UI 需新增"邀请状态"条件选项：

```
条件类型：[订阅分组 ▼] [余额 ▼] [邀请状态 ▼]  ← 新增

选择"邀请状态"后：
  匹配值：[是被邀请人 ▼] [是邀请人 ▼] [无邀请关系 ▼]
```

### 影响范围

| 文件 | 改动 |
|------|------|
| `backend/internal/domain/announcement.go` | 新增 type/struct/Matches 改签名 |
| `backend/internal/service/announcement_service.go` | ListForUser / MarkRead 构建 ctx，新增 queryUserAffiliateStatus |
| `backend/internal/service/announcement_targeting_test.go` | 新增 referral 条件测试 + 改写现有 Matches 调用 |
| `frontend/src/types/index.ts` | AnnouncementCondition 类型增加 `referral_value` 字段 |
| `frontend/src/components/admin/announcements/` | targeting 编辑 UI 支持 referral 条件 |

**降级策略：** `queryUserAffiliateStatus` 查询失败时降级为 `HasInviter=false, IsInviter=false`（不崩溃，不阻断公告展示），可封装为 repository 方法并加 Redis 短缓存（TTL 5min，affiliate 状态几乎不变）。

---

## 实现顺序

```
Phase 1 — Dashboard 快捷入口 (0.5d)
  ├── 新增 giftKey / userPlus SVG 图标
  ├── UserDashboardQuickActions.vue 加两个按钮
  └── i18n 补 key（zh.ts / en.ts）

Phase 2 — BindKey 充值折扣 (2-3d)
  ├── domain.BindKeyConfig 扩展 RechargeDiscount（含 ValidDays）
  ├── migration: user_recharge_discounts 表 + recharge_discount_applications 表
  ├── keybind.Commit 同事务写入折扣记录
  ├── PaymentService.doBalance() 折扣钩子（markCompleted 前，强一致）
  ├── 管理端 API/UI：配置 RechargeDiscount（gift_ops_handler 扩展）
  ├── 前端：绑定成功卡片展示折扣信息
  ├── 前端：充值页提示"当前有充值折扣 X%"
  └── 单元测试 + 集成测试

Phase 3 — 双向邀请奖励 + 裂变 (3-4d)
  ├── migration: referral_reward_tracker 表 + referral_spend_events 表
  ├── gift.Source 新增 referral_invitee / referral_inviter / recharge_discount
  ├── InviterBoundHook interface + ReferralRewardService 实现
  ├── AffiliateService 注入 hook，BindInviterByCode 绑定后触发
  ├── 注册链路集成：GrantInviteeReward + InheritDiscountFromInviter
  ├── billing 链路集成：applyUsageBilling 成功后 TrackSpend（detached ctx）
  ├── 系统设置 keys（domain_constants + setting_service + dto + 管理端 UI）
  ├── GET /api/referral/status（handler + route + dto + wire）
  ├── 前端：ReferralView.vue 超级邀请页（eligible 双状态）
  ├── 前端：/referral 路由 + api/referral.ts
  └── 单元测试 + 集成测试

Phase 4 — 公告 Targeting 扩展 (1-1.5d)
  ├── domain: UserTargetingContext struct + AnnouncementCondition 增 referral_value
  ├── Matches 改签名 → 所有调用点（ListForUser / MarkRead / tests）同步更新
  ├── queryUserAffiliateStatus + Redis 短缓存降级
  ├── validate 扩展 + 单测
  ├── 前端：types/index.ts + admin targeting 编辑 UI 支持"邀请状态"
  └── 管理员配置 popup 公告：targeting=has_inviter
```

---

## 测试计划

### Phase 2 测试：BindKey 充值折扣

#### 单元测试 (`backend/internal/keybind/`)

| 测试文件 | 测试用例 | 验证点 |
|----------|----------|--------|
| `discount_config_test.go` | TestRechargeDiscount_ParseFromJSON | config JSONB 正确反序列化 RechargeDiscount 字段 |
| | TestRechargeDiscount_NilWhenMissing | config 无 recharge_discount 键时解析为 nil |
| | TestRechargeDiscount_DisabledWhenFalse | Enabled=false 时不触发折扣写入 |
| `service_discount_test.go` | TestCommit_WritesDiscount_WhenEnabled | Commit 成功 + key 有 RechargeDiscount → 写入 user_recharge_discounts |
| | TestCommit_SkipsDiscount_WhenDisabled | Commit 成功 + Enabled=false → 不写入 |
| | TestCommit_SkipsDiscount_WhenNoConfig | key 无 gift_settings 行 → 不写入 |
| | TestCommit_Discount_ValidFrom_ValidUntil | valid_from=now, valid_until=now+ValidDays |

#### 单元测试 (`backend/internal/service/`)

| 测试文件 | 测试用例 | 验证点 |
|----------|----------|--------|
| `payment_discount_test.go` | TestApplyRechargeDiscount_HappyPath | 有效折扣 → bonus = amount × rate，gift.Grant 被调用 |
| | TestApplyRechargeDiscount_PartialRemaining | total_discounted + amount > max_amount → 只折扣剩余部分 |
| | TestApplyRechargeDiscount_ExactlyMaxAmount | total_discounted == max_amount → 不发放 |
| | TestApplyRechargeDiscount_Expired | valid_until < now → 跳过 |
| | TestApplyRechargeDiscount_NotYetValid | valid_from > now → 跳过 |
| | TestApplyRechargeDiscount_NoRecord | 用户无折扣记录 → 跳过 |
| | TestApplyRechargeDiscount_MultipleRecords | 多条折扣记录只用第一条有效的 |
| | TestApplyRechargeDiscount_UpdatesTotalDiscounted | 发放后 total_discounted 正确累加 |
| | TestApplyRechargeDiscount_GiftSourceAndRef | gift.Source == recharge_discount, SourceRef 含 key ID |
| | TestApplyRechargeDiscount_DecimalPrecision | 折扣金额精度对齐 8 位小数 |

#### 集成测试 (`backend/internal/keybind/` 或 `backend/internal/service/`)

| 测试文件 | 测试用例 | 验证点 |
|----------|----------|--------|
| `discount_integration_test.go` | TestEndToEnd_BindKey_ThenRecharge_GetsDiscount | 完整流程：配置 key → reserve → commit → 充值 → 折扣赠金到账 |
| | TestEndToEnd_BindKey_NoDiscount_NoBonus | key 无折扣配置 → 充值无额外赠金 |
| | TestEndToEnd_Discount_ExhaustsMaxAmount | 多次充值累计超过 max_amount → 后续充值无折扣 |
| | TestEndToEnd_Discount_ExpiresAfterValidUntil | 过期后充值 → 无折扣 |

---

### Phase 3 测试：双向邀请奖励 + 裂变

#### 单元测试 (`backend/internal/service/referral_reward_service_test.go`)

**被邀请人奖励 (GrantInviteeReward)**

| 测试用例 | 验证点 |
|----------|--------|
| TestGrantInviteeReward_HappyPath | 功能开启 + 首次绑定 → 被邀请人获赠金，tracker 记录 invitee_reward_granted=true |
| TestGrantInviteeReward_FeatureDisabled | 功能关闭 → 不发放，不报错（静默） |
| TestGrantInviteeReward_AlreadyGranted | tracker 已有 invitee_reward_granted=true → 幂等跳过 |
| TestGrantInviteeReward_GiftParams | 金额=设置值，Mode=priority，ExpiresAt=now+设置天数 |
| TestGrantInviteeReward_SourceRefContainsInviterID | source_ref 格式 "inviter:{id}" 确保管理员可追溯 |
| TestGrantInviteeReward_InvalidatesCache | 发放后调用 authCacheInval + billingCache |

**邀请人奖励 (TrackSpendAndMaybeGrantInviterReward)**

| 测试用例 | 验证点 |
|----------|--------|
| TestTrackSpend_BelowThreshold | 消费 5 < 阈值 10 → 仅更新 tracked，不发放 |
| TestTrackSpend_ExactlyThreshold | 累计消费 == 10 → 触发发放 |
| TestTrackSpend_AboveThreshold | 单次消费 15 > 阈值 → 触发发放（只发一次） |
| TestTrackSpend_IncrementalAccumulation | 3+4+5=12 → 第三次触发 |
| TestTrackSpend_AlreadyGranted | inviter_reward_granted=true → 幂等跳过，不重复发放 |
| TestTrackSpend_NoInviter | 用户无 inviter → 无 tracker 行 → 静默返回 |
| TestTrackSpend_FeatureDisabled | 功能关闭 → 不追踪不发放 |
| TestTrackSpend_InviterGiftParams | 金额=设置值，过期=30天，source=referral_inviter |
| TestTrackSpend_ZeroAmount | spendAmount=0 → 不更新 |
| TestTrackSpend_NegativeAmount | spendAmount<0 → 不更新 |
| TestTrackSpend_ConcurrentSafe | 并发调用不重复发放（依赖 DB 行锁 + granted 前置检查） |

**裂变折扣继承**

| 测试用例 | 验证点 |
|----------|--------|
| TestInheritDiscount_InviterHasActiveDiscount | 邀请人有有效折扣 → 被邀请人获得等同折扣记录 |
| TestInheritDiscount_InviterDiscountExpired | 邀请人折扣已过期 → 被邀请人不继承 |
| TestInheritDiscount_InviterNoDiscount | 邀请人无折扣 → 被邀请人无折扣 |
| TestInheritDiscount_RateAndMaxCopied | 继承的 rate 和 max_amount 与邀请人一致 |
| TestInheritDiscount_ValidDaysFromSetting | valid_until = now + referral_discount_valid_days |
| TestInheritDiscount_ChainedViral | A→B→C 三级裂变：C 继承 B 的折扣（B 继承自 A） |

#### 集成测试 (`backend/internal/service/`)

| 测试文件 | 测试用例 | 验证点 |
|----------|----------|--------|
| `referral_reward_integration_test.go` | TestE2E_Register_WithAff_GetsInviteeReward | 注册带 aff 码 → 被邀请人 gift 表有 source=referral_invitee |
| | TestE2E_InviteeSpend_TriggersInviterReward | 被邀请人消费累计达标 → 邀请人 gift 表有 source=referral_inviter |
| | TestE2E_BothRewards_CoexistWithAffiliate | 被邀请人充值 → 邀请人同时获得 aff_quota 返利 + 消费达标赠金 |
| | TestE2E_ViralChain_ThreeLevels | A 绑 key 获折扣 → 邀请 B → B 获折扣 → B 邀请 C → C 获折扣 |
| | TestE2E_InviteeReward_VisibleInAdminGiftOps | 管理员查看用户赠金记录能看到 referral 来源 |
| | TestE2E_DisableFeature_StopsNewRewards | 关闭开关后新注册不发放，已发放不回收 |

---

### Phase 4 测试：公告 Targeting 扩展

#### 单元测试 (`backend/internal/service/announcement_targeting_test.go`)

| 测试用例 | 验证点 |
|----------|--------|
| TestReferralCondition_HasInviter_MatchesTrue | HasInviter=true → 命中 |
| TestReferralCondition_HasInviter_MatchesFalse | HasInviter=false → 不命中 |
| TestReferralCondition_IsInviter_MatchesTrue | IsInviter=true → 命中 |
| TestReferralCondition_IsInviter_MatchesFalse | IsInviter=false → 不命中 |
| TestReferralCondition_NoInviter_MatchesTrue | HasInviter=false → 命中 |
| TestReferralCondition_NoInviter_MatchesFalse | HasInviter=true → 不命中 |
| TestReferralCondition_InvalidOperator | operator != "eq" → 不命中 |
| TestReferralCondition_InvalidValue | referral_value="garbage" → 不命中 |
| TestReferralCondition_CombinedWithBalance | referral + balance AND 组合：两者都满足才命中 |
| TestReferralCondition_OrGroup | 多组 OR：referral 不满足但 balance 满足 → 命中 |
| TestNormalizeAndValidate_RejectsInvalidReferralOperator | operator != "eq" → ErrAnnouncementInvalidTarget |
| TestNormalizeAndValidate_RejectsInvalidReferralValue | referral_value="" → ErrAnnouncementInvalidTarget |
| TestNormalizeAndValidate_AcceptsValidReferral | 三种合法值均通过校验 |
| TestMatches_BackwardCompatible_NoReferralFields | ctx 的 HasInviter/IsInviter 默认 false 时，原有 subscription/balance 条件行为不变 |

#### 单元测试 (`backend/internal/service/announcement_service_test.go`)

| 测试用例 | 验证点 |
|----------|--------|
| TestListForUser_ReferralTargeting_HasInviter | 用户有 inviter → 命中 referral=has_inviter 公告 |
| TestListForUser_ReferralTargeting_NoInviter | 用户无 inviter → 不命中 |
| TestListForUser_ReferralTargeting_QueryFailure | affiliate 查询失败 → 降级为 HasInviter=false（不崩溃） |
| TestMarkRead_ReferralTargeting_Eligible | 被邀请人标记已读 → 成功 |
| TestMarkRead_ReferralTargeting_NotEligible | 非被邀请人标记已读 → ErrAnnouncementNotFound |

#### 集成测试

| 测试文件 | 测试用例 | 验证点 |
|----------|----------|--------|
| `announcement_referral_integration_test.go` | TestE2E_PopupShownToInvitee | 创建 popup 公告 + referral targeting → 被邀请人 ListForUser 返回该公告 |
| | TestE2E_PopupNotShownToNonInvitee | 同一公告 → 非被邀请人看不到 |
| | TestE2E_MarkRead_PersistsAndHides | 被邀请人标记已读 → unreadOnly 不再返回 |

---

### 通用测试约束

1. **单元测试 tag**：所有单元测试使用 `//go:build unit`，可通过 `go test -tags=unit ./...` 单独运行。
2. **集成测试 tag**：所有集成测试使用 `//go:build integration`，需要真实 PostgreSQL + Redis。
3. **Mock/Stub 更新**：新增的 interface 方法（如 `ReferralRewardService` 依赖的 gift.Engine stub）必须同步更新所有 `*Stub`/`*Mock` 结构体。
4. **测试数据隔离**：集成测试使用事务回滚或独立 schema，不污染其他测试。
5. **覆盖率目标**：新增代码行覆盖率 ≥ 80%，核心金额计算路径 100% 覆盖。
6. **边界条件必测**：
   - 金额：0、负数、极小值（0.00000001）、极大值
   - 时间：刚好过期、刚好生效、null 过期时间
   - 并发：同一用户同时触发（依赖 unique index 防重复）
   - 功能开关：开启/关闭/中途切换

---

---

## 风险与注意事项

1. **计费链路性能**：`TrackSpendAndMaybeGrantInviterReward` 必须异步/旁路执行（goroutine + context.WithTimeout(3s)），不能阻塞 gateway 请求。失败仅记日志，下次消费事件会重新触发追踪。

2. **幂等性**：三层幂等保护：
   - `referral_reward_tracker` unique index + `FOR UPDATE` + granted 布尔前置检查 → 不重复发放赠金
   - `referral_spend_events` unique index (event_id) → 不重复累加消费
   - `recharge_discount_applications` unique index (payment_order_id) → 不重复发放折扣 bonus

3. **与现有 affiliate 共存**：两套系统独立运作。用户既能获得双向赠金奖励，也能获得充值百分比返利（进 aff_quota）。`/referral` 和 `/affiliate` 两页并存，规则文案在前端向用户解释清楚。

4. **折扣计算精度**：使用 `shopspring/decimal` 保持与现有 gift 系统一致的 8 位精度。

5. **bind-key 无额度配置时跳过赠金**：Commit 流程中若 key 对应的 gift_settings 无行（resolver 返回 nil），则 giftAmount=0，自然跳过赠金发放。充值折扣同理：config.RechargeDiscount 为 nil 或 Enabled=false 时不写入折扣记录。

6. **管理员可见性**：gift 表的 `source` 和 `source_ref` 字段确保管理员在用户详情的"充值和变动记录"中可以看到赠金来源（`referral_invitee` / `referral_inviter` / `recharge_discount` + 对方 user_id 或 key_id）。现有的 admin gift ops 展示逻辑已能显示这些字段。

7. **bind-key 撤销/删除后折扣处理**：折扣独立于 key 状态——一旦发放就按 `valid_until` 自然到期，不回收。与现有赠金逻辑一致（key 转移后赠金不回收）。

8. **邀请人被封禁/删除**：被邀请人注册时若邀请人已被封禁，仍发放被邀请人注册赠金（因为赠金是给被邀请人的）。折扣继承查的是邀请人的折扣记录是否有效（valid_until 未过期），不检查邀请人账号状态。

9. **Wire DI 扩展**：`ReferralRewardService` 需要注入到 `AffiliateService` 和 gateway service。修改 `cmd/server/wire.go` 后需 `go generate ./cmd/server` 重新生成。
