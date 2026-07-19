# 超级邀请运营指南

> 面向运营/管理员。讲清超级邀请体系下**每一种权益从何而来、到何时为止**，特别是各类资格与奖励的**终止条件**。
>
> 适用版本：分支 `feat/super-referral-plan`（2026-06-30）。代码以 `backend/internal/service/referral_reward_service.go`、`payment_recharge_discount.go`、`internal/gift/` 为准。

---

## 1. 先理清两套独立的体系

超级邀请相关的"赠金"其实来自**两套互相独立**的机制，搞混它们是所有困惑的根源：

| | Phase 2 — 充值折扣 | Phase 3 — 超级邀请双向奖励 |
|---|---|---|
| 是什么 | 用户充值时，按折扣率额外赠送一笔赠金 | 邀请注册 / 邀请人消费达标，发放的奖励赠金 |
| 载体表 | `user_recharge_discounts`（折扣行）→ 充值时发 `user_gifts` | `referral_reward_tracker`（进度）→ 达标/注册时发 `user_gifts` |
| 触发时机 | 每次充值订单完成 | 被邀请人绑定那一刻、被邀请人每次消费 |
| **受全局开关影响？** | **否，完全独立** | **是** |

**全局开关 = 后台「超级邀请」总开关（`referral_reward_enabled`）。它只管 Phase 3，不管 Phase 2。**

---

## 2. 全局开关到底关掉了什么

后台关闭超级邀请总开关后，代码里只有三处行为改变（均在 `referral_reward_service.go`）：

1. **被邀请人绑定时**：注册赠金 + 折扣继承**直接跳过**。
2. **被邀请人消费时**：邀请人达标奖**不发放**；但消费额**照常累加**进进度表。
3. **前端 `/referral` 页面**：整页显示「超级邀请未开启」，用户看不到邀请链接和进度。

**关闭期间不受影响的**：

- 任何已经存在于 `user_recharge_discounts` 表中、仍在有效期内的充值折扣，**充值照样发赠金**（无论持有者是邀请人还是被邀请人）。
- 已经发放到账的赠金（无论哪种来源），**照常可以消费**，直到它们各自的过期/耗尽条件触发。

> 一句话：**关闭全局开关 = 停止"超级邀请奖励的新发放"，而不是"销毁已有权益"。** 充值折扣是另一套体系，完全不受它影响。

---

## 3. 各类权益的终止条件（核心）

下面逐一说明每种权益"什么时候不再有效"。

### 3.1 邀请人的充值折扣终止

**这是什么**：邀请人通过领取带权益的 Key 获得的 `user_recharge_discounts` 折扣行，充值时按折扣率送赠金。

**终止条件（满足任一即不再生效）**：

1. **到期**：`valid_until < 当前时间`。
2. **额度用尽**：累计已折扣金额 `total_discounted ≥ max_discountable_amount`（折扣有总额度上限）。
3. **尚未生效**：`valid_from > 当前时间`（生效窗口还没到，少见）。

**机制说明**：
- `user_recharge_discounts` **没有"状态"列、也没有定时作废任务**。所谓"终止"完全是**查询时按条件过滤**——下次充值时，`QueryBestActiveDiscountForUpdate` 查不到这条行，就不再发赠金。
- 若 `valid_until` 为 NULL，表示**永不过期**，只会因额度用尽而终止。
- 与全局开关**无关**，关闭期间充值仍正常发。

### 3.2 邀请人获得奖励的终止（消费达标奖）

**这是什么**：被邀请人累计消费达到门槛（`SpendThreshold`，默认 10）后，给**邀请人**发的一笔奖励赠金（`InviterAmount`，默认 10；有效期 `InviterExpiryDays`，默认 30 天）。

**终止条件**：

1. **已发放**：每个"邀请人↔被邀请人"配对只发一次。`referral_reward_tracker.inviter_reward_granted=true` 后永不再发。
2. **绑定时无资格（快照）**：被邀请人绑定那一刻，系统给邀请人拍快照存进 `inviter_reward_eligible_at_bind`。若当时邀请人**没有有效折扣资格**，此值为 `false` → 即使被邀请人后来消费达标，**也永不发放**（达标只读快照，不回查邀请人当前状态）。
3. **全局开关关闭**：关闭期间达标也不发。但消费额会继续累加，**重新开启后该被邀请人的下一笔消费会触发补发**（前提是快照 eligible=true）。
4. **赠金本身过期**：奖励一旦发放成功，它就是一笔普通赠金，到 `expires_at` 后由定时任务（GiftExpirer）置为 `expired` 并扣回余额。

> ⚠️ 不会主动补发存量：关闭期间已达标但没发的，重开后**不会被定时扫描补发**，必须靠"被邀请人再产生一笔消费"来触发。若该被邀请人再无消费，这笔奖励就一直挂着。

### 3.3 被邀请人获得奖励的终止（通过邀请注册获得的赠金）

**这是什么**：被邀请人成功绑定邀请关系时，发给**被邀请人**的注册赠金（`InviteeAmount`，默认 10；有效期 `InviteeExpiryDays`，默认 **2 天**，比较短）。扣除模式为 priority（优先扣）。

**终止条件**：

1. **已发放**：每个被邀请人只发一次，`invitee_reward_granted=true` 后不再发。
2. **过期**：发放后 `InviteeExpiryDays`（默认 2 天）到期，GiftExpirer 置 `expired`，剩余额度扣回。**这是被邀请人注册赠金最常见的终止原因——窗口很短。**
3. **用尽**：消费扣减到 `remaining ≤ 0` 时置 `exhausted`。
4. **绑定时全局开关关闭**：注册赠金根本不发（`OnInviterBound` 直接 return），**且无补发**——这批被邀请人永久错过。
5. **〔2026-07-06 新增〕绑定时邀请人无超级邀请资格**：邀请人绑定那一刻若没有有效折扣资格（`inviter_reward_eligible_at_bind=false`），注册赠金**不发**、折扣也不继承（`OnInviterBound` 在开关检查后统一 gate）。邀请关系仍正常绑定、普通邀请返利照常。**背景**：邀请返利与超级邀请共用同一个 `aff_code` 和 `/register?aff=` 链接，早期逻辑只要超级邀请全局开关开着就无条件发被邀请人赠金，导致无资格邀请人用普通返利链接拉的人也被批量发 10 元赠金。

### 3.4 被邀请人的充值折扣终止（继承自邀请人）

**这是什么**：被邀请人绑定时，系统把邀请人**当前最佳折扣**复制一份成被邀请人**自己的独立折扣行**（`source='referral_inherit'`）。有效期 = 绑定时刻 + `DiscountValidDays`（默认 30 天），折扣率/额度/赠金策略都拷贝邀请人那条。

**终止条件**：

1. **到期**：`valid_until < 当前时间`（= 绑定时刻 + DiscountValidDays）。
2. **额度用尽**：`total_discounted ≥ max_discountable_amount`。
3. （与 3.1 相同的机制：无状态列、无 expirer，查询时过滤。）

**关键点**：
- 一旦继承成功，这条折扣行就**完全独立**，与邀请人后续状态、与全局开关都**无关**。邀请人的折扣后来过期了，不影响被邀请人这条；全局开关关了，被邀请人充值照样享受。
- **唯一例外**：如果被邀请人是在**全局开关关闭期间**绑定的，则继承动作从未执行——他名下根本没有这条折扣行。这不是"失效"，是"从未获得"。

### 3.5 超级邀请资格（Eligibility）终止

**这是什么**：判断一个用户"是否拥有超级邀请资格"（前端 `/referral` 页是否显示邀请链接、能否作为有效邀请人）。

**判定逻辑**：`hasInviterRewardEligibility` 按后台「资格获得方式」分两种模式，二者互斥、判定数据源不同：

- `bind_key_claim`（默认）：看用户名下**是否存在一条时间窗内的充值折扣行**（`valid_from<=NOW() AND (valid_until IS NULL OR valid_until>=NOW())`），即领取带权益 Key 后立即有资格（依赖领券）。此模式下资格**没有独立的"资格有效期"字段**，它的有效期就等于底层那条折扣的 `valid_until`。
- `recharge`：只看邀请人**累计充值额 `users.total_recharged` 是否达到 `EligibilityRechargeMinAmount`**，与是否领券、有无折扣行**完全无关**。门槛为 0 时只要有过任意充值即算资格。此模式下资格不随折扣存亡变化，只随累计充值单调增长（`total_recharged` 是单调累加计数器，退款不减）。

> **重要**：`recharge` 模式是「与赠金领券彻底解耦」的选项——邀请人无需领券、只要累计充值达标即成为超级邀请人。若要让超级邀请完全独立于领券活动，选此模式。

**终止条件分两种情形：**

#### 情形 A：全局开关**开启**时

资格终止条件**按模式不同**：

`bind_key_claim` 模式——资格随**底层折扣的存亡**而定：
- 名下**所有**折扣行都过期或额度用尽 → 查不到有效折扣 → **资格终止**，前端不再显示邀请链接和进度。
- 只要还有**任意一条**时间窗内的折扣 → 资格保持。
- 若有 `valid_until=NULL` 的永久折扣 → 资格永不因时间终止。

`recharge` 模式——资格随**累计充值额**而定：
- 只看 `users.total_recharged` 是否达到门槛，与折扣存亡无关。
- `total_recharged` 单调递增（退款不减），因此**一旦达标即永久保持资格**，不会因折扣过期而终止。

#### 情形 B：全局开关**关闭**时

- 前端 `status.enabled=false`，`/referral` 整页显示「未开启」，**所有人**（邀请人和被邀请人）都看不到邀请链接、进度、奖励——从用户视角看，相当于资格被整体收起。
- 但后端的资格判定值（`eligible`）**并不会被开关改写**——它仍按当前模式计算（`bind_key_claim` 看折扣、`recharge` 看累计充值），只是被 `enabled=false` 罩住不展示。
- 重新开启后，资格立即按当时的折扣状态恢复显示，**无需任何迁移或补建**。

> 总结资格终止：
> - **开启时**：资格 = 有没有有效折扣，折扣全没了资格才终止。
> - **关闭时**：不管邀请人/被邀请人、不管被邀请人何时注册，全员的超级邀请入口**统一不可见**（暂停，非销毁）；重开即恢复。

---

## 4. 一个高频混淆点：达标统计与订阅消费

被邀请人若使用**订阅套餐**消费，这部分消费**不计入**邀请人达标统计（`invitee_spend_tracked`）。

- 代码：计费回调触发达标追踪的条件是 `!isSubscriptionBilling && cost.ActualCost > 0`。
- 含义：订阅用户全程用订阅额度消费的话，`invitee_spend_tracked` 永远是 0，邀请人达标奖永远不触发。只有走**余额/赠金计费**（非订阅）的消费才累加。

如果运营上希望订阅消费也算达标，需要改代码（当前不计入）。

---

## 5. 默认参数一览（后台「超级邀请」设置）

| 设置项 | 字段 | 默认值 | 说明 |
|---|---|---|---|
| 被邀请人注册赠金额 | InviteeAmount | 10 | 绑定即发给被邀请人 |
| 被邀请人赠金有效期 | InviteeExpiryDays | **2 天** | 窗口短，易过期 |
| 邀请人达标奖励额 | InviterAmount | 10 | 被邀请人达标后发给邀请人 |
| 邀请人赠金有效期 | InviterExpiryDays | 30 天 | |
| 达标消费门槛 | SpendThreshold | 10 | 被邀请人累计非订阅消费 |
| 继承折扣有效期 | DiscountValidDays | 30 天 | 被邀请人继承折扣的窗口 |
| 资格获得方式 | EligibilityGrantMode | bind_key_claim | bind_key_claim（看折扣/依赖领券）/ recharge（看累计充值/与领券无关） |
| 充值资格门槛 | EligibilityRechargeMinAmount | 0 | recharge 模式下 `users.total_recharged` 门槛；0=有过任意充值即可 |

---

## 6. 运营操作建议

- **想暂停整个超级邀请活动**：关后台总开关即可。已发赠金、已有充值折扣不受影响照常用；新邀请的注册赠金/折扣继承/达标奖暂停。**注意：暂停期间绑定的新被邀请人，其注册赠金和折扣继承会永久错过，重开不补发**——若活动只是短暂维护，建议避免在关闭期推广邀请链接。
- **想彻底停止某人的折扣**：因为折扣无状态列、无法"撤销"，只能等其 `valid_until` 自然到期或额度用尽。若需立即停止，须在数据库层手动调整该折扣行的 `valid_until`（属高风险数据操作，需谨慎并备份）。
- **被邀请人反馈"注册赠金不见了"**：大概率是 2 天有效期已过（默认很短），属正常过期，可查 `user_gifts` 中该用户 `source='referral_invitee'` 行的 `status`/`expires_at` 确认。
- **邀请人反馈"被邀请人消费了却没拿到奖励"**：依次排查 ① 被邀请人是否走订阅消费（不计达标）② 绑定时快照 `inviter_reward_eligible_at_bind` 是否为 false ③ 是否累计未达门槛 ④ 全局开关在达标时是否关闭。
- **想让超级邀请与「赠金领券」活动彻底解耦（领券活动结束后也能长期运行）**：把「资格获得方式」切到 `recharge`，门槛按需填 `EligibilityRechargeMinAmount`。切换后资格改看邀请人累计充值额、不再依赖领券。**注意切换影响存量**：① 判定即时生效，此前靠领券拿资格但累计充值未达门槛的邀请人会**失去**资格（后续绑定不发奖，但已发的历史奖励不回收）；反之累计充值已达标的邀请人即便没券也**获得**资格。② 折扣继承始终以邀请人名下的有效折扣券为准，与模式无关——纯充值达标（无券）的邀请人，其被邀请人继承不到折扣，只拿注册赠金。③ 快照字段 `inviter_reward_eligible_at_bind` 只在绑定/懒补建那一刻按当时模式计算，不会追溯改写已有 tracker。

---

## 附：相关代码位置

```
backend/internal/service/
  referral_reward_service.go     — OnInviterBound / TrackSpendAndMaybeGrantInviterReward
                                   / grantInviteeReward / inheritDiscountFromInviter
                                   / hasInviterRewardEligibility / GetReferralStatus
  payment_recharge_discount.go   — applyRechargeDiscountForOrder（充值折扣兑现，独立于全局开关）
  recharge_discount_repo_impl.go — QueryBestActiveDiscountForUpdate（折扣时间窗+额度过滤）
  setting_service.go             — ReferralRewardConfig 各项默认值与归一化
backend/internal/gift/
  expirer.go                     — GiftExpirer：expires_at<NOW 置 expired 并扣回余额
  repository.go                  — remaining-x<=0 时置 exhausted
数据库表：user_recharge_discounts / referral_reward_tracker / user_gifts / user_affiliates
```
