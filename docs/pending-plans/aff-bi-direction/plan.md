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

**超级邀请资格判定：** 用户拥有处于有效时间窗口内的充值折扣记录（`user_recharge_discounts` 中有 `valid_from <= now AND (valid_until IS NULL OR valid_until >= now)` 的行）即视为"有超级邀请资格"。额度是否耗尽（`total_discounted >= max_discountable_amount`）仅影响用户自身充值时能否享受折扣，不影响超级邀请资格。API `GET /api/referral/status` 返回的 `eligible` 字段标识此状态。

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

---

## Change Request: 超级邀请资格语义收敛 (2026-06-27)

### 背景

代码审查发现三个 gap + reviewer 指出实现方案偏"单点补洞"，需要先统一概念模型再实施。

### 能力模型（取代模糊的单一 "eligible"）

超级邀请系统拆为四个独立能力，各自有明确的判定条件：

| # | 能力 | 含义 | 判定条件 |
|---|------|------|----------|
| 1 | `invite_link_usable` | 邀请码是否可用于新用户注册绑定 | 始终可用（有 aff_code 即可），不因超级邀请资格失效而禁用 |
| 2 | `invitee_signup_reward_enabled` | 被邀请人注册是否拿赠金 | 全局 `referral_reward_enabled=true` + 绑定成功 + **邀请人绑定时有超级邀请资格**（`inviter_reward_eligible_at_bind=true`，与能力 #3 同一时间窗口判定）。**〔2026-07-06 修订〕** 早期设计为"不依赖邀请人资格"，因无资格邀请人用普通返利链接拉人时会被误发被邀请人赠金（同一 `aff_code`、同一 `/register?aff=` 链接，超级邀请开关全局生效），故收敛为"绑定照常，仅当邀请人有资格才发被邀请人赠金" |
| 3 | `discount_inheritance_eligible` | 被邀请人是否继承折扣 | 邀请人**绑定时**有处于时间窗口内的折扣：`valid_from <= bind_time AND (valid_until IS NULL OR valid_until >= bind_time)`。**不看额度是否耗尽** |
| 4 | `inviter_reward_eligible_for_this_invitee` | 邀请人是否能因该 invitee 达标拿赠金 | 绑定时快照记录（`inviter_reward_eligible_at_bind`），后续消费达标只读此快照 |

**"超级邀请资格"在前端页面的含义：** 用户自己是否有处于有效时间窗口内的折扣。决定 `/referral` 页面展示完整邀请区域（eligible=true）还是受限区域（eligible=false）。判定 SQL：`valid_from <= NOW() AND (valid_until IS NULL OR valid_until >= NOW())`。额度耗尽不影响此判定。

**额度耗尽的唯一影响：** 用户自身充值时不再享受折扣 bonus。不影响页面展示、裂变传播、邀请人达标赠金任何一个。

**`referral_reward_enabled=false` 时各环节行为：**
- tracker 行照建（确保后续开启时能追踪）
- 被邀请人赠金不发
- 邀请人达标赠金不发
- 折扣继承不执行（`inheritDiscountFromInviter` 在 `OnInviterBound` 中与赠金同受开关控制）

**〔2026-07-06 修订〕`referral_reward_enabled=true` 但邀请人绑定时无超级邀请资格（`inviter_reward_eligible_at_bind=false`）时的行为：**
- tracker 行照建（快照记为 false）
- 邀请关系正常绑定（普通邀请返利照常生效，`aff_count`/返利额度不受影响）
- 被邀请人赠金**不发**（新增 gate）
- 折扣继承**不执行**
- 邀请人达标赠金**不发**（`TrackSpend` 读快照 false 时跳过，原有行为）
- gate 位置：`OnInviterBound` 入口统一判定 `rewardEligible`（与折扣继承 #3 同一 `queryInviterDiscountsForReferralGrant(boundAt)` 判定源），不再深入 `grantInviteeReward` 内部单独检查

### Gap 1：邀请人资格过期后，被邀请人达标仍发放邀请人赠金

**位置：** `referral_reward_service.go` → `TrackSpendAndMaybeGrantInviterReward`

**现状：** 被邀请人消费达标时，只检查全局开关 `referral_reward_enabled` + threshold 达标即发放邀请人赠金。不检查邀请人在被邀请人注册时是否仍有超级邀请资格。

**正确行为：** 邀请人赠金仅在"被邀请人注册时邀请人有资格"（能力 #4: `inviter_reward_eligible_for_this_invitee`）的前提下发放。资格过期后注册的被邀请人，即使后续消费达标，邀请人也不应获得赠金。

### Gap 2：折扣继承判定错误地将额度耗尽视为无资格

**位置：** `referral_reward_service.go` → `inheritDiscountFromInviter` → 调用 `QueryActiveDiscountsReadOnly`

**现状：** `QueryActiveDiscountsReadOnly` 的 SQL 条件包含 `total_discounted < max_discountable_amount`。邀请人额度用完后，新被邀请人注册时查不到 active discount → 不继承折扣。

**正确行为：** 裂变继承（能力 #3: `discount_inheritance_eligible`）只看时间窗口，不看额度消耗。邀请人把自己的折扣额度充值用完了，不影响其邀请新人的能力。

### Gap 3：邀请人达标赠金的扣除模式不可配置（Phase 2 单独实施）

**位置：** `referral_reward_service.go` → `TrackSpendAndMaybeGrantInviterReward` → `giftEngine.Grant`

**现状：** 邀请人因被邀请人消费达标获得的赠金硬编码为 `DeductionModePriority`（优先扣除）。无管理后台配置项。

**正确行为：** 管理员可选择邀请人达标赠金的扣除模式：`priority`（优先扣除）或 `ratio`（比例扣除）。被邀请人注册赠金保持 `priority` 不变。

**注意：** 此 gap 为产品增强而非资格语义 bug，与 Gap 1/2 解耦，Phase 2 单独 PR 实施。

---

## 实现方案

### 分 Phase 实施

- **Phase 1（本次 PR）：** 资格语义收敛 + Gap 1 + Gap 2 + 补索引 + 测试
- **Phase 2（下个 PR）：** Gap 3 邀请人赠金 mode 配置（产品增强，独立实施）

---

### Phase 1: Gap 1 实现

**方案：tracker 表加字段 `inviter_reward_eligible_at_bind`**

字段命名用 `inviter_reward_eligible_at_bind` 而非泛泛的 `inviter_eligible_at_bind`，因为邀请人资格失去后邀请码仍可用、普通 affiliate 绑定/返利不受影响；快照本身直接决定"邀请人达标赠金"能力。**〔2026-07-06 修订〕** 被邀请人注册赠金、折扣继承、邀请人达标赠金三者均受绑定时超级邀请资格约束（`OnInviterBound` 入口统一 gate），不再是"被邀请人仍拿赠金"。

#### 1.1 Migration

新增 `migrations/168_tracker_inviter_reward_eligible.sql`：

```sql
-- 168_tracker_inviter_reward_eligible.sql
-- Gap 1: 记录绑定时邀请人是否有超级邀请资格（决定能否因该 invitee 达标获赠金）

ALTER TABLE referral_reward_tracker
    ADD COLUMN IF NOT EXISTS inviter_reward_eligible_at_bind BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN referral_reward_tracker.inviter_reward_eligible_at_bind IS
    '绑定时邀请人是否有 discount_inheritance_eligible（时间窗口内有折扣）。FALSE 时邀请人不因该 invitee 达标获赠金。存量默认 TRUE（向后兼容）。';
```

默认 `TRUE`：存量 tracker 行保持原有行为，无需回填。这是产品决策（存量用户已按旧规则建立预期），不是技术妥协。

#### 1.2 资格判定辅助方法

`referral_reward_service.go` 新增：

```go
// hasInviterRewardEligibility 判断邀请人是否有超级邀请资格（仅看时间窗口，不看额度）。
// 用于 OnInviterBound 时快照记录，决定该 invitee 后续达标时邀请人是否获赠金。
func (s *ReferralRewardService) hasInviterRewardEligibility(ctx context.Context, inviterID int64) bool {
    if s.discountRepo == nil {
        return false
    }
    discounts, err := s.discountRepo.QueryDiscountsForInheritance(ctx, inviterID)
    return err == nil && len(discounts) > 0
}
```

#### 1.3 修改 `ensureTracker`

增加 `rewardEligible` 参数：

```go
func (s *ReferralRewardService) ensureTracker(ctx context.Context, inviterID, inviteeID int64, threshold float64, rewardEligible bool) error {
    execer := s.execer(ctx)
    _, err := execer.ExecContext(ctx,
        `INSERT INTO referral_reward_tracker (inviter_id, invitee_id, spend_threshold, inviter_reward_eligible_at_bind)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (inviter_id, invitee_id) DO NOTHING`,
        inviterID, inviteeID, threshold, rewardEligible)
    if err != nil {
        return fmt.Errorf("ensure tracker: %w", err)
    }
    return nil
}
```

#### 1.4 修改 `OnInviterBound` 调用处

```go
rewardEligible := s.hasInviterRewardEligibility(ctx, inviterID)
if err := s.ensureTracker(ctx, inviterID, inviteeID, cfg.SpendThreshold, rewardEligible); err != nil {
    ...
}
```

`OnInviterBound` 是资格快照的**权威路径**。

#### 1.5 修改 `TrackSpendAndMaybeGrantInviterReward`

tracker SELECT 增加字段：

```go
type trackerRow struct {
    id                    int64
    inviterID             int64
    spendTracked          float64
    threshold             float64
    inviterGranted        bool
    rewardEligibleAtBind  bool  // 新增
}
```

发放前检查：

```go
if !tracker.inviterGranted && newTracked >= tracker.threshold {
    if !tracker.rewardEligibleAtBind {
        // 邀请人在该被邀请人注册时已无资格，跳过发放
        return tx.Commit()
    }
    // ... 原发放逻辑
}
```

#### 1.6 Lazy 补建 tracker 的资格判定（竞态 fallback 路径）

`TrackSpendAndMaybeGrantInviterReward` 中 `lookupInviterID` 补建 tracker 时的策略：

**问题：** lazy 补建发生在消费时（可能远晚于绑定时），此时查邀请人资格可能已过期，造成误判。

**解法：** 从 `user_affiliates.created_at` 获取绑定时间（`bind_time`），用历史时间点查资格：

```go
// lazy 补建时，用绑定时间查历史资格
bindTime := inviteeAffiliate.CreatedAt
rewardEligible := s.hasInviterRewardEligibilityAtTime(ctx, inviterID, bindTime)
```

新增辅助方法：

```go
// hasInviterRewardEligibilityAtTime 查询邀请人在指定时间点是否有资格。
// 用于 lazy 补建 tracker 时还原绑定时快照。
func (s *ReferralRewardService) hasInviterRewardEligibilityAtTime(ctx context.Context, inviterID int64, atTime time.Time) bool {
    if s.discountRepo == nil {
        return false
    }
    discounts, err := s.discountRepo.QueryDiscountsForInheritanceAtTime(ctx, inviterID, atTime)
    return err == nil && len(discounts) > 0
}
```

对应 repo 方法 SQL：
```sql
SELECT id FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= $2
  AND (valid_until IS NULL OR valid_until >= $2)
LIMIT 1
```

**可接受误差：** 如果折扣行已被手动删除（极罕见运维操作），查询返回空 → `rewardEligibleAtBind=false` → 保守拒绝。这是可接受的，因为：
1. 正常流程 `OnInviterBound` 会先于 `TrackSpend` 执行，lazy 补建本就是 race fallback
2. 遇到此情况可通过 SQL 手动将 tracker 行的 `inviter_reward_eligible_at_bind` 修正为 TRUE

---

### Phase 1: Gap 2 实现

#### 2.1 接口扩展

`payment_recharge_discount.go` 的 `RechargeDiscountRepo` 接口新增两个方法：

```go
// QueryDiscountsForInheritance 查询用于裂变继承的折扣（仅看时间窗口，不看额度）。
QueryDiscountsForInheritance(ctx context.Context, userID int64) ([]RechargeDiscountSummary, error)

// QueryDiscountsForInheritanceAtTime 查询指定时间点的继承资格（用于 lazy 补建还原绑定时快照）。
QueryDiscountsForInheritanceAtTime(ctx context.Context, userID int64, atTime time.Time) ([]RechargeDiscountSummary, error)
```

#### 2.2 实现

`recharge_discount_repo_impl.go` 新增：

```go
func (r *rechargeDiscountRepoImpl) QueryDiscountsForInheritance(ctx context.Context, userID int64) ([]RechargeDiscountSummary, error) {
    rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, source, source_ref, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_from, valid_until
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= NOW()
  AND (valid_until IS NULL OR valid_until >= NOW())
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST`, userID)
    // ... 同 QueryActiveDiscountsReadOnly 的 scan 逻辑
}

func (r *rechargeDiscountRepoImpl) QueryDiscountsForInheritanceAtTime(ctx context.Context, userID int64, atTime time.Time) ([]RechargeDiscountSummary, error) {
    rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, source, source_ref, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_from, valid_until
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= $2
  AND (valid_until IS NULL OR valid_until >= $2)
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST`, userID, atTime)
    // ... 同上 scan 逻辑
}
```

与 `QueryActiveDiscountsReadOnly` 的区别：去掉 `AND total_discounted < max_discountable_amount`。

#### 2.3 补索引

现有 `165_user_recharge_discounts.sql` 的 partial index 带 `WHERE total_discounted < max_discountable_amount`，新查询去掉该条件后走不上索引。在同一 migration 文件中补：

`migrations/168_tracker_inviter_reward_eligible.sql` 追加：

```sql
-- Gap 2: 继承查询专用索引（不含额度条件，仅按时间窗口过滤）
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_urd_inheritance_lookup
    ON user_recharge_discounts (user_id, valid_from, valid_until);
```

#### 2.4 调用处修改

`inheritDiscountFromInviter` 改调新方法：

```go
discounts, err := s.discountRepo.QueryDiscountsForInheritance(ctx, inviterID)
```

#### 2.5 更新 test stubs 和 mocks

影响面（执行前用 `grep -r "RechargeDiscountRepo" backend/` 确认）：
- `internal/service/referral_reward_service_test.go` — stub
- `internal/service/payment_recharge_discount_integration_test.go` — 可能有 mock
- `internal/handler/recharge_discount_handler.go` — 依赖该接口但真实 adapter 自动满足
- 所有实现 `RechargeDiscountRepo` 的 stub/mock 需新增两个方法（返回 nil, nil 即可）

---

### Phase 2: Gap 3 实现（单独 PR）

#### 3.1 新增 setting keys

`setting_service.go` 常量区：

```go
SettingKeyReferralInviterGiftMode           = "referral_inviter_gift_mode"            // "priority" | "ratio"
SettingKeyReferralInviterGiftRatioRecharge   = "referral_inviter_gift_ratio_recharge"  // float, 如 0.5
```

#### 3.2 扩展 `ReferralRewardConfig`

```go
type ReferralRewardConfig struct {
    // ... 现有字段 ...
    InviterGiftMode        string  // "priority" | "ratio"，默认 "priority"
    InviterGiftRatio       float64 // ratio 模式下的比例值，默认 0.5
}
```

#### 3.3 `GetReferralRewardConfig` 读取

```go
cfg.InviterGiftMode = "priority"
cfg.InviterGiftRatio = 0.5
if v, err := s.settingRepo.GetValue(ctx, SettingKeyReferralInviterGiftMode); err == nil {
    if v == "ratio" {
        cfg.InviterGiftMode = "ratio"
    }
}
if v, err := s.settingRepo.GetValue(ctx, SettingKeyReferralInviterGiftRatioRecharge); err == nil {
    if f, e := strconv.ParseFloat(v, 64); e == nil && f > 0 && f <= 10 {
        cfg.InviterGiftRatio = f
    }
}
```

#### 3.4 `TrackSpendAndMaybeGrantInviterReward` 发放时使用

```go
mode := gift.DeductionModePriority
var ratioRecharge *float64
if cfg.InviterGiftMode == "ratio" {
    mode = gift.DeductionModeRatio
    r := cfg.InviterGiftRatio
    ratioRecharge = &r
}

grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
    UserID:        tracker.inviterID,
    Amount:        cfg.InviterAmount,
    Mode:          mode,
    RatioRecharge: ratioRecharge,
    ExpiresAt:     &expiresAt,
    Source:        gift.SourceReferralInviter,
    SourceRef:     referralPtrStr(fmt.Sprintf("invitee:%d", inviteeID)),
})
```

#### 3.5 完整配置链路清单

| 层 | 文件 | 改动 |
|----|------|------|
| 常量 | `internal/service/domain_constants.go` | 新增 setting key 常量 |
| 读取 | `internal/service/setting_service.go` → `GetReferralRewardConfig` | 解析新字段 |
| 聚合 | `internal/service/settings_view.go` → `GetSettings` | 返回给前端 |
| 写入 | `internal/service/setting_service.go` → `UpdateReferralRewardSettings` | 持久化 |
| admin DTO | `internal/handler/dto/settings.go` | 请求/响应 DTO |
| admin handler | `internal/handler/admin/setting_handler.go` | 读写端点 |
| 前端 API | `frontend/src/api/admin/settings.ts` | type + 调用 |
| 前端 UI | `frontend/src/views/admin/SettingsView.vue` | 下拉 + 条件输入 |
| change log | `internal/service/setting_service.go` audit 段 | 记录变更 |

---

### Phase 1 改动文件清单

| 文件 | Gap | 改动 |
|------|-----|------|
| `migrations/168_tracker_inviter_reward_eligible.sql` | 1+2 | 新建：ALTER TABLE + 补索引 |
| `internal/service/referral_reward_service.go` | 1+2 | 主体逻辑：快照判定 + 继承改调 |
| `internal/service/payment_recharge_discount.go` | 2 | 接口新增 2 个方法 |
| `internal/service/recharge_discount_repo_impl.go` | 2 | 实现新方法 |
| test stubs（`grep -r "RechargeDiscountRepo" backend/internal/`） | 2 | 新增方法 stub |
| `internal/service/referral_reward_service_test.go` | 1+2 | 新增 5 个单测 |

### Phase 1 测试覆盖

| 测试 | 验证点 |
|------|--------|
| TestInviterRewardSkipped_WhenEligibleAtBindFalse | 邀请人折扣过期后注册的 invitee 达标 → 不发放邀请人赠金 |
| TestInviterRewardGranted_WhenEligibleAtBindTrue | 邀请人有资格时注册的 invitee 达标 → 正常发放 |
| TestDiscountInherited_WhenQuotaExhaustedButTimeValid | 邀请人额度耗尽但时间未到期 → 被邀请人仍继承折扣 |
| TestDiscountNotInherited_WhenTimeExpired | 邀请人时间过期 → 被邀请人不继承（即使额度未用完） |
| TestLazyTrackerBuild_UsesBindTimeForEligibility | lazy 补建 tracker 时用 user_affiliates.created_at 而非 NOW() 判定资格 |

### 向后兼容

- Migration 默认 `TRUE` → 存量 tracker 不受影响，邀请人照常获赠金
- `QueryDiscountsForInheritance` 宽松化条件 → 之前因额度耗尽"误拒"的继承在下次注册时自动恢复
- 新索引 `CONCURRENTLY` 创建，不阻塞线上读写

---

## Change Request: 充值折扣赠金可配置扣除模式 (2026-06-27)

### 背景

当前充值折扣产生的赠金（`SourceRechargeDiscount`）在 `payment_recharge_discount.go:193`
**硬编码** `Mode: gift.DeductionModePriority`，只能优先扣除。运营希望能像邀请人达标赠金
一样，按 key 配置选择 `priority`（优先扣除）或 `ratio`（按比例与充值余额同步消耗）。

赠金引擎（`gift.Engine`）、`user_gifts` 表（`deduction_mode` + `ratio_recharge`）、扣费逻辑
都已支持两种模式，缺的只是把扣除策略从「发放时硬编码」改为「随 discount 行固化并透传」。

### 核心设计原则：策略固化在 discount 行，发放时不回查

扣除模式不是发放赠金时刻才决定的全局策略，而是**创建 discount 行时就固化的属性**。

- 充值发放赠金（`payment_recharge_discount.go`）→ 读 discount 行上的 mode/ratio
- 邀请继承（`inheritDiscountFromInviter`）→ 直接复制邀请人 **best discount** 行的 mode/ratio
  给被邀请人，被邀请人后续充值时同样读自己行上的值

**绝不在充值发放时反向查询邀请人的当前 key 配置。** 否则邀请人事后改 key 配置、折扣过期、
或多条折扣并存时，被邀请人的历史权益会变得不稳定。现有代码 `inheritDiscountFromInviter`
已经是快照复制 rate/maxAmount 的模式，本 CR 只是把 mode/ratio 一起复制，保持一致。

`best discount` 的选择沿用现有排序 `discount_rate DESC, valid_until ASC NULLS LAST`，
即被邀请人继承的是「最高折扣率那条」的扣除策略——与「同用户多条 discount 行各自独立」一致。

### 全景数据流

```
BindKeyRechargeDiscount (key 配置, admin 设定 mode/ratio)
        │
        ↓ CreateBindKeyDiscount(写入 mode/ratio)
user_recharge_discounts 行  ← mode/ratio 固化在此行
        │
        ├─→ 用户充值 → payment_recharge_discount → Grant(读本行 mode/ratio)
        │
        └─→ 邀请继承 → inheritDiscountFromInviter → 复制 best 行(含 mode/ratio)
                              → 被邀请人 user_recharge_discounts 行 → 被邀请人充值时读本行
```

### 字段设计（与 user_gifts 对齐，避免精度/语义漂移）

`user_recharge_discounts` 新增两列，约束照搬 `migrations/142_user_gifts.sql`：

```sql
gift_deduction_mode VARCHAR(16) NOT NULL DEFAULT 'priority',
gift_ratio_recharge DECIMAL(20,8) NULL,
CONSTRAINT chk_urd_gift_mode_ratio CHECK (
    (gift_deduction_mode = 'priority' AND gift_ratio_recharge IS NULL)
    OR
    (gift_deduction_mode = 'ratio' AND gift_ratio_recharge IS NOT NULL AND gift_ratio_recharge > 0)
)
```

- 类型 `DECIMAL(20,8)` 与 `user_gifts.ratio_recharge` 一致（继承复制时无精度损失）
- 默认 `priority` + ratio NULL → 存量行行为不变
- check 约束在 DB 层兜底，与代码层归一化双重保障

### 防御性归一化（reviewer 第 3、8 点）

不信任 JSON / 不信任 DB，在两个写入/读取边界都做归一化：

**写入边界（admin handler + resolveRechargeDiscountConfig）：**
- `gift_deduction_mode` 空值/未知值 → 归一为 `priority`
- `priority` → 强制 `gift_ratio_recharge = nil`
- `ratio` → `gift_ratio_recharge` 必须 `> 0`，且沿用折扣率上限语义限制 `(0, 10]`；非法则拒绝

**发放边界（payment_recharge_discount，即使 DB 有 check 也兜底）：**
- mode 不是 `ratio` → 一律按 `priority` 发放（`RatioRecharge = nil`）
- mode 是 `ratio` 但 ratio 为 nil 或 `<= 0` → **返回 error**，订单保持可重试，
  避免静默发错模式（数据不合法应暴露而非降级）

### CreateDiscount 签名重构（reviewer 第 6 点：还签名债）

当前 `CreateDiscount(ctx, userID, source, sourceRef, originAPIKeyID, rate, maxAmount, validFrom, validUntil)`
已经很长，再加 mode/ratio 更糟。本 CR 引入入参 struct：

```go
type CreateRechargeDiscountInput struct {
    UserID            int64
    Source            string
    SourceRef         string
    OriginAPIKeyID    *int64
    Rate              float64
    MaxAmount         float64
    ValidFrom         time.Time
    ValidUntil        *time.Time
    GiftDeductionMode string   // "priority" | "ratio"，空 → priority
    GiftRatioRecharge *float64 // 仅 ratio 模式非 nil
}
CreateDiscount(ctx context.Context, in CreateRechargeDiscountInput) (int64, error)
```

`CreateBindKeyDiscount`（keybind 包内独立接口）同理加 mode/ratio 参数。

### 改动清单（按数据流顺序）

| # | 文件 | 改动 |
|---|------|------|
| 1 | `migrations/170_urd_gift_deduction_mode.sql` | 新建：ALTER TABLE 加两列 + check 约束 |
| 2 | `internal/domain/bind_key.go` | `BindKeyRechargeDiscount` 加 `GiftDeductionMode string` + `GiftRatioRecharge *float64` |
| 3 | `internal/handler/admin/gift_ops_handler.go` | `RechargeDiscountPayload` 加两字段；`SetBindKeyRechargeDiscount` 校验+归一化；写入 `domain.BindKeyRechargeDiscount` |
| 4 | `internal/keybind/service.go` | `resolveRechargeDiscountConfig` 归一化 mode/ratio；调用 `CreateBindKeyDiscount` 透传；`GrantedDiscount` DTO 加两字段（reviewer 第 4 点） |
| 5 | `internal/keybind/balance.go` | `RechargeDiscountCreator.CreateBindKeyDiscount` 接口签名加 mode/ratio |
| 6 | `internal/keybind/discount_creator.go` | INSERT 写入 mode/ratio + 入参校验归一化 |
| 7 | `internal/service/payment_recharge_discount.go` | `RechargeDiscountRecord` + `RechargeDiscountSummary` 加两字段；接口 `CreateDiscount` 改 struct 入参；发放处读 `discountLocked` mode/ratio + 防御性归一化（mode=ratio&&ratio<=0 → error） |
| 8 | `internal/service/recharge_discount_repo_impl.go` | 所有 SELECT 补两列（`QueryBestActiveDiscountForUpdate`/`QueryActiveDiscountsReadOnly`/`QueryDiscountsForInheritance`/`AtTime`）；scan 补字段；`CreateDiscount` 改 struct 入参 + INSERT 写两列 |
| 9 | `internal/service/referral_reward_service.go` | `inheritDiscountFromInviter` 复制 `best.GiftDeductionMode/GiftRatioRecharge` 透传 `CreateDiscount` |
| 10 | `internal/handler/recharge_discount_handler.go` | 用户侧 `/user/recharge-discount` 响应 DTO 补两字段（reviewer 第 5 点，API 层同步） |
| 11 | 前端 admin 配置表单 | **UI deferred**：现有代码无 per-key 充值折扣配置的前端调用方（`/admin/ops/bind-key-gifts/:id/recharge-discount` 是纯后端 endpoint）。后端已支持 mode/ratio 并做了归一化校验，将来加 UI 时直接传两字段即可。本次不实现表单 |
| 12 | 前端 `/user/recharge-discount` type | 补两字段（展示与否另说，type 同步） |
| 13 | 测试 stub 同步 | `discountRepoForReferralStub`、`payment_recharge_discount_test`、`recharge_discount_handler_test`、`discount_creator_integration_test`：接口签名变动牵连，全部更新 |

### 影响接口 / Stub（CLAUDE.md gotcha）

两个接口签名变动，必须同步所有 stub/mock：

- `service.RechargeDiscountRepo.CreateDiscount`（struct 入参）→
  `discountRepoForReferralStub`、`payment_recharge_discount_test.go` 内的 stub
- `keybind.RechargeDiscountCreator.CreateBindKeyDiscount`（加 mode/ratio）→
  `discount_creator_integration_test.go`

### 测试覆盖

| 测试 | 验证点 |
|------|--------|
| TestCreateDiscount_Priority_RatioNil | priority 模式 INSERT 时 ratio 落 NULL |
| TestCreateDiscount_Ratio_PersistsRatio | ratio 模式持久化 ratio 值 |
| TestResolveRechargeDiscountConfig_NormalizesMode | 空/未知 mode → priority；priority 清空 ratio；ratio 非法 → 拒绝 |
| TestPaymentGrant_ReadsDiscountMode_Priority | discount=priority → Grant 用 priority |
| TestPaymentGrant_ReadsDiscountMode_Ratio | discount=ratio → Grant 用 ratio + 正确 ratio 值 |
| TestPaymentGrant_RatioModeButRatioNil_ReturnsError | mode=ratio 但 ratio<=0 → 返回 error，不发放 |
| TestInheritDiscount_CopiesMode_Priority | 邀请人 best=priority → 被邀请人继承 priority |
| TestInheritDiscount_CopiesMode_Ratio | 邀请人 best=ratio → 被邀请人继承 ratio + ratio 值 |

### 向后兼容

- Migration 默认 `priority` + ratio NULL → 存量行为不变
- `CreateDiscount` 改 struct 入参是编译期强制，无运行时风险
- 前端旧表单不传 mode → 后端归一化为 priority
- check 约束允许存量行（mode=priority, ratio=NULL 天然满足）

## Change Request: 充值折扣赠金有效期与折扣有效期解耦 (2026-06-29)

### 背景

当前充值折扣产生的赠金（`SourceRechargeDiscount`）在 `payment_recharge_discount.go`
发放时直接把 `user_recharge_discounts.valid_until` 作为 `user_gifts.expires_at`：

```go
if discountLocked.ValidUntil != nil {
    t := *discountLocked.ValidUntil
    expiresAt = &t
}
```

这把三个本应独立的概念绑在了一起：

- 充值优惠可使用时间：`user_recharge_discounts.valid_until`
- 超级邀请资格时间窗口：同样基于 discount 行的时间窗口判断
- 充值优惠产生的赠金有效期：当前也被迫等于 `valid_until`

因此无法表达「充值优惠/超级邀请资格有效 15 天，但充值优惠产生的赠金永久有效」这类配置。

### 核心设计原则：赠金有效期策略也固化在 discount 行

沿用上一 CR 的建模：**充值折扣权益本身携带它产生赠金的全部策略**。

发放赠金时只读取被使用的 `user_recharge_discounts` 行，不回查 key 配置或邀请人当前状态。邀请继承时复制邀请人 best discount 的有效期策略，让被邀请人的历史权益保持稳定快照。

```text
BindKeyRechargeDiscount (key 配置：折扣有效期 + 赠金扣除模式 + 赠金有效期策略)
        │
        ↓ CreateBindKeyDiscount(写入 discount 行)
user_recharge_discounts 行
        ├─ valid_until                      → 充值优惠/超级邀请资格有效期
        ├─ gift_deduction_mode/ratio         → 该折扣产生赠金的扣除方式
        └─ gift_expiry_mode/expires_after    → 该折扣产生赠金的有效期策略
        │
        ├─ 用户充值 → payment_recharge_discount → Grant(按本行策略计算 ExpiresAt)
        └─ 邀请继承 → inheritDiscountFromInviter → 复制 best 行全部赠金策略
```

### 字段设计

在 `user_recharge_discounts` 新增两列：

```sql
gift_expiry_mode VARCHAR(24) NOT NULL DEFAULT 'discount_valid_until',
gift_expires_after_days INT NULL,
CONSTRAINT chk_urd_gift_expiry CHECK (
    (gift_expiry_mode = 'discount_valid_until' AND gift_expires_after_days IS NULL)
    OR
    (gift_expiry_mode = 'never' AND gift_expires_after_days IS NULL)
    OR
    (gift_expiry_mode = 'after_days' AND gift_expires_after_days IS NOT NULL AND gift_expires_after_days > 0)
)
```

语义：

- `discount_valid_until`：当前行为，赠金过期时间等于 discount 的 `valid_until`
- `never`：赠金永久有效，`user_gifts.expires_at = NULL`
- `after_days`：赠金从发放时起 N 天后过期，读取 `gift_expires_after_days`

默认 `discount_valid_until` 保持存量行为不变。

### 配置源头

`bind_key_gift_settings.config.recharge_discount` 增加：

```json
{
  "gift_expiry_mode": "never",
  "gift_expires_after_days": null
}
```

归一化规则：

- 空值/未知 `gift_expiry_mode` → `discount_valid_until`
- `discount_valid_until` / `never` → `gift_expires_after_days = nil`
- `after_days` → `gift_expires_after_days > 0`，否则拒绝

### 发放边界

`payment_recharge_discount.go` 不再直接把 `discountLocked.ValidUntil` 作为赠金过期时间，而是统一调用 helper：

```go
resolveDiscountGiftExpiresAt(mode string, days *int, discountValidUntil *time.Time, now time.Time)
```

输出：

- `discount_valid_until` → `discountValidUntil`
- `never` → `nil`
- `after_days` → `now + days * 24h`
- `after_days` 但 days nil/<=0 → error，订单保持可重试

### 改动清单

| # | 文件 | 改动 |
|---|------|------|
| 1 | `migrations/171_urd_gift_expiry_mode.sql` | 新增 `gift_expiry_mode` + `gift_expires_after_days` + check 约束 |
| 2 | `internal/domain/bind_key.go` | `BindKeyRechargeDiscount` 加赠金有效期字段；新增 `NormalizeGiftExpiry` |
| 3 | `internal/handler/admin/gift_ops_handler.go` | `RechargeDiscountPayload` 加两字段；写入前归一化校验 |
| 4 | `internal/keybind/balance.go` / `discount_creator.go` / `service.go` | `CreateBindKeyDiscount` 透传有效期策略；resolver 归一化；`GrantedDiscount` DTO 补字段 |
| 5 | `internal/service/payment_recharge_discount.go` | `CreateRechargeDiscountInput` / `RechargeDiscountRecord` 补字段；发放时按策略计算 `ExpiresAt` |
| 6 | `internal/service/recharge_discount_repo_impl.go` | 所有 SELECT/scan/INSERT 补字段，写入边界归一化 |
| 7 | `internal/service/referral_reward_service.go` | 继承 best discount 时复制赠金有效期策略 |
| 8 | `internal/handler/recharge_discount_handler.go` + `frontend/src/api/user.ts` | 用户侧当前折扣 API/type 补字段 |
| 9 | 测试 | 覆盖 `never`、`discount_valid_until`、`after_days`、非法 `after_days` 以及继承复制 |

### 向后兼容

- 存量 discount 行默认 `gift_expiry_mode='discount_valid_until'`，行为与当前完全一致
- 旧 admin 调用不传新字段时归一为 `discount_valid_until`
- 继承/发放都只读 discount 行快照，不会受后续 key 配置变更影响

## Change Request: 超级邀请资格获得方式全局开关 (2026-06-29)

### 背景

当前超级邀请资格由 `ReferralRewardService.hasInviterRewardEligibility*` 判定，本质是：

```text
邀请人存在处于有效时间窗口内的 user_recharge_discounts 行
```

而 bind-key 领取成功时会立即创建 `user_recharge_discounts`，所以现有行为等价于「领取带充值折扣的 key 后立即获得超级邀请资格」。运营需要可配置为另一种模式：「领取 key 后还不获得资格，必须完成充值后才开启」。

同时，充值后开启资格需要一个可选充值金额门槛：当门槛为 `0` 时不限制金额，只要发生过符合条件的充值即可；当门槛大于 `0` 时，累计符合条件的充值本金达到该金额后才开启资格。

### 产品语义

新增两个全局配置：

```text
referral_eligibility_grant_mode:
  bind_key_claim  领取带充值折扣 key 后立即获得超级邀请资格
  recharge        领取带充值折扣 key 后，完成符合门槛的充值后获得超级邀请资格

referral_eligibility_recharge_min_amount:
  0      不限制充值金额；只要有一次折扣实际应用记录即可
  > 0    需要累计符合条件的折扣应用本金 >= 该金额
```

默认值：

```text
referral_eligibility_grant_mode = bind_key_claim
referral_eligibility_recharge_min_amount = 0
```

这样保持存量行为不变。

本开关控制同一套「超级邀请资格」闸门：

- `/api/v1/user/referral/status` 的 `eligible`
- `referral_reward_tracker.inviter_reward_eligible_at_bind`
- 邀请人赠金是否可发放
- 被邀请人是否可继承邀请人的充值折扣

本开关不控制：

- 被邀请人绑定成功时自己的注册赠金
- 普通 affiliate 邀请码是否可绑定
- 普通 affiliate 返利是否可累计

### 与「超级邀请资格语义收敛」CR 对齐

前序「超级邀请资格语义收敛」CR 定义：

```text
eligible = 用户有处于有效时间窗口内的折扣
```

且额度耗尽不影响资格。该定义在 `bind_key_claim` 模式下继续成立。

本 CR 在 `recharge` 模式下显式 supersede 上述定义：`eligible = 用户有处于有效时间窗口内的折扣 + 该折扣已有符合门槛的 application 累计本金`。额度耗尽仍不影响资格，但充值门槛成为新增维度。

为了避免资格闸门只拦住赠金、不拦住折扣继承，`recharge` 模式下折扣继承也必须走同一资格查询；未达门槛的邀请人既不会获得邀请人赠金资格快照，也不会让 invitee 继承自己的充值折扣。

### 关键口径

`recharge` 模式下的「充值金额」指 `recharge_discount_applications.applied_amount` 的累计值，也就是实际参与该超级邀请/充值折扣权益的充值本金，不是：

- 订单支付金额的 bonus 后余额
- 折扣赠金金额 `bonus_amount`
- 普通无折扣充值金额
- 普通 affiliate 返利金额

资格只与超级邀请/充值折扣权益链路绑定，避免用户通过任意普通充值绕过领取 key 流程。

金额门槛按单个 `user_recharge_discounts` 行累计，不跨多个折扣行拼凑。这样可以避免多个过期/继承折扣分别不足额但合计达标而误开资格。

### 行为矩阵

| 模式 | 用户状态 | `eligible` | invitee 是否继承折扣 | 后续 invitee 达标是否给邀请人赠金 |
|------|----------|------------|----------------------|----------------------------------|
| `bind_key_claim` | 有有效 discount 行 | true | 是 | 绑定时快照 true |
| `bind_key_claim` | 无有效 discount 行或已过期 | false | 否 | 绑定时快照 false |
| `recharge`, min=0 | 有有效 discount 行，但没有 application | false | 否 | 绑定时快照 false |
| `recharge`, min=0 | 有有效 discount 行，至少 1 条 application | true | 是 | 绑定时快照 true |
| `recharge`, min>0 | 有效 discount 的 application 累计 `applied_amount < min` | false | 否 | 绑定时快照 false |
| `recharge`, min>0 | 有效 discount 的 application 累计 `applied_amount >= min` | true | 是 | 绑定时快照 true |

### 时间点语义

`referral_reward_tracker.inviter_reward_eligible_at_bind` 仍然是绑定时快照。`recharge` 模式下资格依赖 application 截止时间，因此所有创建 tracker 的路径必须使用同一个绑定时间基准，不能一条路径用 `NOW()`、另一条路径用历史时间。

新增稳定绑定时间字段：

```sql
ALTER TABLE user_affiliates
  ADD COLUMN IF NOT EXISTS inviter_bound_at TIMESTAMPTZ NULL;

UPDATE user_affiliates
SET inviter_bound_at = updated_at
WHERE inviter_id IS NOT NULL AND inviter_bound_at IS NULL;
```

后续 `BindInviter` 首次写入 `inviter_id` 时同时写入 `inviter_bound_at = NOW()`。`updated_at` 不再作为新数据的绑定时间语义来源；历史数据仅用迁移回填的 `updated_at` 作为 best-effort 近似。

实现要求：

- `AffiliateRepository.BindInviter` 返回绑定时间，或新增等价方法让 `AffiliateService.BindInviterByCode` 在 hook 前拿到同一事务写入的 `inviter_bound_at`。
- `InviterBoundHook.OnInviterBound` 签名改为接收 `boundAt time.Time`。
- `OnInviterBound` 创建 tracker 时调用 at-time 资格查询，时间点为 `boundAt`，不能使用当前时间。
- lazy 补建 tracker 时从 `user_affiliates.inviter_bound_at` 读取绑定时间；兼容旧数据可使用 `COALESCE(inviter_bound_at, updated_at)`。
- `recharge` 模式下，历史时间判断要求：在 `boundAt`，邀请人已有有效 discount，且截至该时间点 `recharge_discount_applications.created_at <= boundAt` 的累计 `applied_amount` 达到门槛。

### 后端设计

#### 1. Setting key 与配置读取

`internal/service/domain_constants.go` 新增：

```go
SettingKeyReferralEligibilityGrantMode = "referral_eligibility_grant_mode"
SettingKeyReferralEligibilityRechargeMinAmount = "referral_eligibility_recharge_min_amount"
```

`ReferralRewardConfig` 新增：

```go
EligibilityGrantMode         string  // "bind_key_claim" | "recharge"
EligibilityRechargeMinAmount float64 // >= 0
```

归一化：

- 空值/未知 mode -> `bind_key_claim`
- min amount 解析失败或 `< 0` -> `0`
- 保存入口拒绝 `< 0`

#### 2. 绑定时间迁移与 affiliate 绑定链路

新增迁移 `backend/migrations/172_user_affiliates_inviter_bound_at.sql`：

- `user_affiliates.inviter_bound_at TIMESTAMPTZ NULL`
- 实际 SQL 使用 `ADD COLUMN IF NOT EXISTS`，保持迁移重放/手动应用时幂等
- 对已有 `inviter_id IS NOT NULL` 的行回填 `updated_at`
- 可加普通索引或不加；当前查询按 invitee `user_id` 定位，不需要新索引

`internal/repository/affiliate_repo.go`：

- `BindInviter` 更新 `inviter_id` 时同时写入 `inviter_bound_at = NOW()`
- 返回 `boundAt`，或提供 bind 后读取同一行绑定时间的接口
- 测试覆盖二次绑定不会覆盖 `inviter_bound_at`

`internal/service/affiliate_hooks.go` / `internal/service/affiliate_service.go`：

- `InviterBoundHook.OnInviterBound(ctx, inviterID, inviteeID, boundAt)` 接收绑定时间
- `BindInviterByCode` 将 repo 返回的 `boundAt` 传给异步 hook

#### 3. RechargeDiscountRepo 扩展

`payment_recharge_discount.go` 的 `RechargeDiscountRepo` 新增查询方法：

```go
QueryDiscountsForEligibilityAfterRecharge(ctx context.Context, userID int64, minAppliedAmount float64) ([]RechargeDiscountSummary, error)
QueryDiscountsForEligibilityAfterRechargeAtTime(ctx context.Context, userID int64, atTime time.Time, minAppliedAmount float64) ([]RechargeDiscountSummary, error)
```

查询语义：

- 只看 `user_recharge_discounts` 时间窗口有效的行。
- `minAppliedAmount == 0`：该 discount 至少存在一条 `recharge_discount_applications`。
- `minAppliedAmount > 0`：该 discount 的 applications 累计 `SUM(applied_amount) >= minAppliedAmount`。
- AtTime 版本额外要求 `recharge_discount_applications.created_at <= atTime`，用于绑定时快照。

`minAppliedAmount == 0` 建议用 `EXISTS`，避免 `HAVING SUM >= 0` 与 `COUNT > 0` 的冗余表达：

```sql
SELECT d.*
FROM user_recharge_discounts d
WHERE d.user_id = $1
  AND d.valid_from <= $time
  AND (d.valid_until IS NULL OR d.valid_until >= $time)
  AND EXISTS (
    SELECT 1
    FROM recharge_discount_applications a
    WHERE a.discount_id = d.id
      AND a.created_at <= $time
  )
ORDER BY d.discount_rate DESC, d.valid_until ASC NULLS LAST
```

`minAppliedAmount > 0` 使用单个 discount 粒度聚合：

```sql
SELECT d.*
FROM user_recharge_discounts d
JOIN recharge_discount_applications a ON a.discount_id = d.id
WHERE d.user_id = $1
  AND d.valid_from <= $time
  AND (d.valid_until IS NULL OR d.valid_until >= $time)
  AND a.created_at <= $time
GROUP BY d.id
HAVING SUM(a.applied_amount) >= $min
ORDER BY d.discount_rate DESC, d.valid_until ASC NULLS LAST
```

当前时间版本可以复用同一实现并传 `time.Now()`，或保留无 at-time SQL，但语义必须一致。

#### 4. 资格判断与折扣继承分支

`ReferralRewardService` 内部新增统一 helper：

```go
queryInviterDiscountsForReferralGrant(ctx, inviterID int64, atTime *time.Time) ([]RechargeDiscountSummary, error)
hasInviterRewardEligibilityByConfig(ctx, inviterID int64, atTime *time.Time) bool
```

分支：

- `bind_key_claim`：沿用 `QueryDiscountsForInheritance*`。
- `recharge`：调用新增 `QueryDiscountsForEligibilityAfterRecharge*`。

调用点：

- `OnInviterBound` 创建 tracker 时的 `rewardEligible`，传入 `boundAt`
- `TrackSpendAndMaybeGrantInviterReward` lazy 补建 tracker 时的 `rewardEligible`，传入 `inviter_bound_at`
- `GetReferralStatus` 的 `status.Eligible`，使用当前时间
- `inheritDiscountFromInviter`，使用同一 helper 的返回结果选择可继承折扣

这样 #3 `discount_inheritance_eligible` 与 #4 `inviter_reward_eligible_at_bind` 在 `recharge` 模式下不会分裂。

#### 5. API / DTO / 前端设置

管理端 settings DTO 新增：

```json
{
  "referral_eligibility_grant_mode": "bind_key_claim",
  "referral_eligibility_recharge_min_amount": 0
}
```

用户侧 `ReferralStatus` 与 `backend/internal/handler/referral_handler.go` 序列化结果新增：

```json
{
  "eligibility_grant_mode": "recharge",
  "eligibility_recharge_min_amount": 10
}
```

前端设置页在超级邀请配置区增加：

- 单选/分段控件：资格获得方式
  - 领取 Key 后立即获得
  - 充值后获得
- 当选择「充值后获得」时显示数值输入：
  - 标签：最低充值本金
  - 提示：`0` 表示不限制金额
  - 校验：`>= 0`

前端 `/referral` 页面据此展示更准确的未开启原因：

- `bind_key_claim`：提示领取带超级邀请返利的 Key。
- `recharge` 且 min=0：提示完成一次充值后开启。
- `recharge` 且 min>0：提示累计充值本金达到指定金额后开启。

### 改动清单

| # | 文件 | 改动 |
|---|------|------|
| 1 | `backend/migrations/172_user_affiliates_inviter_bound_at.sql` | 新增稳定绑定时间列并回填历史绑定 |
| 2 | `internal/service/domain_constants.go` | 新增两个 setting key |
| 3 | `internal/service/setting_service.go` | `ReferralRewardConfig` 新增字段；读取/保存/默认值/校验 |
| 4 | `internal/service/settings_view.go` | settings 聚合响应补字段 |
| 5 | `internal/handler/dto/settings.go` | admin settings 请求/响应 DTO 补字段 |
| 6 | `internal/handler/admin/setting_handler.go` | 读写与 audit changed list 补字段 |
| 7 | `internal/repository/affiliate_repo.go` | `BindInviter` 写入并返回/暴露 `inviter_bound_at` |
| 8 | `internal/service/affiliate_hooks.go` | hook 签名新增 `boundAt time.Time` |
| 9 | `internal/service/affiliate_service.go` | 绑定成功后把 `boundAt` 传给 `OnInviterBound` |
| 10 | `internal/service/payment_recharge_discount.go` | `RechargeDiscountRepo` 接口新增两个 eligibility 查询 |
| 11 | `internal/service/recharge_discount_repo_impl.go` | 实现充值后资格查询与 at-time 查询 |
| 12 | `internal/service/referral_reward_service.go` | 资格判断按配置分支；`OnInviterBound`/lazy 使用同一绑定时间；折扣继承也走闸门；status 返回 mode/min |
| 13 | `internal/handler/referral_handler.go` | 用户侧 referral status 响应包含 mode/min |
| 14 | `frontend/src/api/admin/settings.ts` | type 与 payload 补字段 |
| 15 | `frontend/src/views/admin/SettingsView.vue` | 超级邀请配置区新增控件与校验 |
| 16 | `frontend/src/views/user/ReferralView.vue` / `frontend/src/types/index.ts` | status 类型补 `eligibility_grant_mode` 与 min amount；未开启提示按模式显示 |
| 17 | 测试 stub/调用点同步 | `discountRepoForReferralStub`、`rechargeDiscountRepoStub`、`queryErrorRepoStub`、`discountRepoStub` 全部补新接口方法；`oauthEmailAffiliateRepoStub` 与 `affiliate_repo_integration_test.go:144` 同步 `BindInviter` 签名 |
| 18 | 测试 | 覆盖配置、资格判断、继承 gate、status、tracker 快照与绑定时间 |

### 测试覆盖

| 测试 | 验证点 |
|------|--------|
| `TestGetReferralRewardConfig_EligibilityDefaults` | 缺省 mode=`bind_key_claim`，min=0 |
| `TestGetReferralRewardConfig_EligibilityRechargeMode` | 合法 mode/min 正确读取 |
| `TestGetReferralRewardConfig_EligibilityInvalidFallback` | 非法 mode 回退，负数 min 回退/保存拒绝 |
| `TestReferralEligibility_BindKeyClaimMode` | 有有效 discount 即 eligible |
| `TestReferralEligibility_RechargeMode_MinZero_NoApplicationFalse` | min=0 但未充值 false |
| `TestReferralEligibility_RechargeMode_MinZero_WithApplicationTrue` | min=0 且有 application true |
| `TestReferralEligibility_RechargeMode_MinAmountBelowFalse` | 累计 applied_amount 不足 false |
| `TestReferralEligibility_RechargeMode_MinAmountReachedTrue` | 累计 applied_amount 达标 true |
| `TestOnInviterBound_UsesBoundAtNotNow_RechargeMode` | 绑定后才发生的充值不会让绑定时快照变 true |
| `TestLazyTrackerEligibility_UsesInviterBoundAt` | lazy 补建按稳定绑定时间点统计 applications |
| `TestRechargeMode_DiscountInheritanceRequiresEligibility` | recharge 模式下未达充值门槛不继承折扣 |
| `TestBindInviter_WritesInviterBoundAtOnce` | 首次绑定写入 `inviter_bound_at`，重复绑定不覆盖 |
| `TestReferralStatus_ReturnsEligibilityModeAndMinAmount` | status 响应包含 mode/min |

### 向后兼容

- 默认 `bind_key_claim`，现有实例行为不变。
- 新增 `user_affiliates.inviter_bound_at`，历史绑定用 `updated_at` 回填作为 best-effort；未来绑定使用稳定字段。
- 普通 affiliate 邀请码仍可用；该开关只影响超级邀请资格、被邀请人注册赠金、折扣继承和邀请人达标赠金资格快照。
- 已存在的 `referral_reward_tracker.inviter_reward_eligible_at_bind` 不回填；新开关只影响后续绑定/懒补建。

### Open Questions

无。已决策：

- 金额门槛按单个 discount 行累计。
- 切换开关前已经创建的 tracker 不重算。
- `recharge` 模式下折扣继承与邀请人赠金资格共用同一闸门。

---

## Change Request: 邀请人达标奖励发放次数配额 + 配额耗尽登录弹窗 (2026-07-07)

> 详细实施方案与两轮 cx-s2 审阅记录见同目录 `inviter-reward-quota-plan.md`（已 approved）。本节为并入主计划的摘要。

### 背景

当前"邀请人达标奖励"（被邀请人累计非订阅消费达 `SpendThreshold` → 给邀请人发赠金）**无发放次数上限**：只要被邀请人达标、绑定时快照 `inviter_reward_eligible_at_bind=true` 且全局开关开着，每个 (inviter,invitee) 配对都发一次，配对数量无上限。

新增限制：**邀请人每充值 50 USD 获得 10 次**"领取达标奖励"的机会；机会用尽后被邀请人达标也不再给邀请人发奖。并在邀请人因配额用尽卡住 pending 奖励时，登录弹窗告知（走公告板块）。

### 决策（需求方确认）

- 充值口径 = **支付充值 + 兑换码**（`RedeemTypeBalance && Value>0`，含支付订单与直接兑换码；不含订阅/并发/负数退款）。
- 配额总开关**默认关闭**：关=完全直通（既不赚也不花），行为 == 现在的无限发放。
- 存量历史邀请人初始配额：新列默认 0，**不自动折算历史充值**；由需求方拿 SQL 手动 UPDATE。
- 弹窗命中语义：**仅"有被 quota=0 卡住的 pending 达标奖励"** 的邀请人（不打扰从未获得机会的新邀请人）。

### 数据模型（migration 175）

- `user_affiliates` 加列：`inviter_reward_quota INT DEFAULT 0`（剩余机会）、`inviter_reward_recharge_carry DECIMAL(20,8) DEFAULT 0`（未凑满一档的充值余额，跨次累积）、`inviter_reward_quota_consumed_total INT DEFAULT 0`（审计/展示）。
- `referral_reward_tracker` 加列：`inviter_reward_blocked_by_quota BOOLEAN NOT NULL DEFAULT FALSE`（弹窗事实源，pair 级）。
- 新表 `referral_recharge_quota_grants(id, user_id, source_type, source_id, order_amount, batches_granted, created_at)`，`UNIQUE(source_type,source_id)`，`source_id` 用数字主键（`payment_orders.id`/`redeem_codes.id`）。
- CHECK：quota/carry/consumed_total >= 0、batches_granted >= 0、order_amount > 0。
- partial index（`_notx`）：`referral_reward_tracker(inviter_id) WHERE inviter_reward_granted=false AND inviter_reward_blocked_by_quota=true`。

### 赚机会（充值入账时）

- 订单级 `applyReferralQuotaForOrder`：`doBalance` 里 `Redeem` 后、`markCompleted` 前。抢去重 slot → `FOR UPDATE` 锁 affiliate 行 → `carry+=amount; batches=floor(carry/step); quota+=batches*perBatch; carry-=batches*step`。**best-effort**：失败只记审计 `REFERRAL_QUOTA_ACCRUE_FAILED` 并 `return nil`，绝不阻断充值主链路（与 affiliate/discount 的失败阻断语义刻意不同）。
- 兑换级 `tryAccrueReferralQuotaForRedeem`：`Redeem` 后 best-effort；支付订单触发的 Redeem 用**新增独立** `ContextSkipRedeemReferralQuota` 抑制（不复用 `ContextSkipRedeemAffiliate`），去重表 UNIQUE 作第二重保险。
- 充值者无 affiliate 行时先 `EnsureUserAffiliate` 再更新。

### 花机会（达标发奖时）

`referral_reward_service.go` 现有 grant 事务内、`giftEngine.Grant` 前：`SELECT inviter_reward_quota ... FOR UPDATE`。
- `quota<=0`：跳过发放、不置 granted（保留 pending，语义同"全局开关关闭"），并置 `inviter_reward_blocked_by_quota=true`。
- `quota>0`：`quota-=1; consumed_total+=1`，置 granted 并清 blocked flag，同事务原子。
- 锁序：先 tracker(invitee) 后 affiliate(inviter)，赚机会只锁 affiliate → 无死锁。
- pending 可能**无限挂起**：只有被邀请人新消费才重试，补配额/事件重放都不主动补发。

### 配置（3 新 setting）

`referral_inviter_reward_quota_enabled`（默认 false）、`referral_inviter_reward_quota_recharge_step`（默认 50）、`referral_inviter_reward_quota_per_batch`（默认 10）。

### 配额耗尽登录弹窗（公告 Targeting 扩展）

复用公告 `notify_mode=popup`，新增 referral 投放取值 `inviter_reward_blocked`。`UserTargetingContext` 加 `InviterRewardBlocked`；`fillReferralTargeting` 补 `EXISTS(SELECT 1 FROM referral_reward_tracker WHERE inviter_id=$1 AND inviter_reward_granted=false AND inviter_reward_blocked_by_quota=true)`，沿用 `ReferralKnown` fail-closed。domain `Matches`/`validate` + DTO + 前端 `AnnouncementTargetingEditor.vue` + `types/index.ts` + i18n 各加一分支。查询**不 gate** 配额总开关（关关后历史 pending 仍可弹，符合"充值即可解锁"语义）。

### 充值后立即补发（第三轮追加，需求方决策）

原"不主动补发"被推翻：邀请人充值补足配额后 pending 奖励**立即到账**。唯一发奖逻辑抽成内层 `grantInviterRewardLocked`（**不自开事务、不重锁 tracker**，前置=调用方已在打开事务里且已 `FOR UPDATE` 锁该 invitee tracker，内层仅在配额开关开时再锁 affiliate，锁序恒 `tracker→affiliate`）。两个入口：① `TrackSpend` 在其现有事务内累加 spend 后直接调（Option A，复用已持锁）；② `backfillPendingInviterRewards` 在"加 quota"事务提交后，对每个被卡 invitee 新开独立事务锁 tracker 再调同一内层，quota 耗尽自然停发。补发 best-effort（失败记 `REFERRAL_QUOTA_BACKFILL_FAILED`，不阻断充值），剩余 pending 由下次消费兜底。

### 展示

`ReferralStatus` 加 `InviterRewardQuota`；`InviteeProgress` 加 `BlockedByQuota`。前端 `/referral` 状态徽章由三态扩**四态**（未达标/已发/无资格/**配额用尽待充值解锁**）。登录弹窗（公告 popup）**只做定性告知不带数字**（公告为全体共享静态文本，无模板变量），具体"哪些被邀请人卡住"由 `/referral` 四态徽章展示。

### 影响面

migration×1（`user_affiliates` 3 列 + `referral_reward_tracker` 1 列 + 新表 + partial index）；改 `domain_constants.go`、`setting_service.go`、`dto/settings.go`、`setting_handler.go`、`payment_fulfillment.go`(+新文件 `payment_referral_quota.go`)、`redeem_service.go`、`referral_reward_service.go`、repo 层、`domain/announcement.go`、`announcement_service.go`、`handler/dto/announcement.go`、前端 `AnnouncementTargetingEditor.vue`/`types/index.ts`/ReferralView/i18n、单测。**不动**绑定/继承/被邀请人赠金/折扣逻辑。

### 审阅状态

cx-s2 三轮审阅全部 approved：
- 第一轮（配额主体）：7 点意见全采纳——best-effort 失败不阻断、独立 skip key、pending 语义与前端三态、CHECK 约束、source_id 数字主键、锁序无环、carry 跨次累积。
- 第二轮（弹窗追加）：4 点认可——flag 放 tracker 为 pair 级事实源、置/清路径无 stale、投放解耦配额开关、fail-closed；采纳 partial index 非阻塞建议。
- 第三轮（充值立即补发 + 四态 + 弹窗定性）：#8 死锁规避确认（先提交加 quota 再逐笔补发，环消除）、#10 四态徽章+弹窗定性分工认可；#9 事务边界原有"同一/独立事务"歧义按 cx-s2 意见收紧为 Option A（内层不自开事务不重锁 tracker）后通过。
