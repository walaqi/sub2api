# 超级邀请「邀请人达标奖励」发放次数配额 — 实施方案（待审阅）

## 背景与目标

当前超级邀请中，"邀请人达标奖励"（被邀请人累计非订阅消费达 `SpendThreshold`（默认 10 USD）→ 给**邀请人**发一笔赠金）是**无发放次数上限**的：只要被邀请人达标、邀请人绑定时快照 `inviter_reward_eligible_at_bind=true` 且全局开关开着，每个 (inviter,invitee) 配对都发一次，配对数量无上限。

新增限制：**邀请人每充值 50 USD 获得 10 次**"领取达标奖励"的机会。机会用尽后，即使被邀请人达标也不再给该邀请人发奖励。

## 已核实的现状（代码）

- 发放点：`internal/service/referral_reward_service.go` 的 `TrackSpendAndMaybeGrantInviterReward`（约 194 行）——事务内 `FOR UPDATE` 锁 tracker 行，`newTracked >= threshold && !inviterGranted`，再过 `rewardEligible`（快照）+ 全局开关两道 gate 后 `giftEngine.Grant`，然后置 `inviter_reward_granted=true`。每个 (inviter,invitee) 最多发一次。
- 充值入账点：`internal/service/payment_fulfillment.go` 的 `doBalance`：建兑换码 → `redeemService.Redeem`（`UpdateBalance` 加余额+`total_recharged`）→ `applyAffiliateRebateForOrder` → `applyRechargeDiscountForOrder` → `markCompleted`。**支付充值订单本质是"建 balance 兑换码再 Redeem"**，所以两种入账都汇入 `RedeemService.Redeem`。
- `RedeemService.Redeem`（`internal/service/redeem_service.go:379`）：`RedeemTypeBalance && Value>0` 覆盖「支付充值」与「直接兑换码」两种来源；订阅码/并发码/负数退款码天然不在内。已有 `ContextSkipRedeemAffiliate` 语义用于抑制"支付订单触发的 Redeem"在兑换级重复计返利。
- 邀请人账户表 `user_affiliates`（migration 130）：`user_id PK`、`aff_code NOT NULL UNIQUE`、`inviter_id`、`aff_count`、`aff_quota`、`aff_history_quota`。每个能发起邀请的用户一行。
- 既有先例：**affiliate 返利**就是"充值时累积到 user_affiliates"，采用订单级+兑换级双钩子 + 幂等去重 + ContextSkip 抑制双计。本方案照抄此经过验证的模式。

## 决策（已与需求方确认）

1. 充值口径 = **支付充值 + 兑换码**（即 `RedeemTypeBalance && Value>0`，含支付订单与直接兑换码；不含订阅/并发/负数退款）。
2. 配额总开关**默认关闭**：关=完全直通（既不赚也不花），行为 == 现在的无限发放。
3. 存量历史邀请人的初始配额：新列默认 0，**不自动折算历史充值**；由需求方拿 SQL 手动 UPDATE。

## 数据模型（migration 175）

`user_affiliates` 加列：
- `inviter_reward_quota INT NOT NULL DEFAULT 0` — 剩余机会
- `inviter_reward_recharge_carry DECIMAL(20,8) NOT NULL DEFAULT 0` — 未凑满一档的充值余额，跨次累积（充 70 → +10 机会、carry=20；再充 30 → carry=50 → 再 +10 机会、carry=0）
- `inviter_reward_quota_consumed_total INT NOT NULL DEFAULT 0` — 审计/展示

新去重表 `referral_recharge_quota_grants`：
- `id BIGSERIAL PK, user_id BIGINT, source_type VARCHAR(20), source_id BIGINT, order_amount DECIMAL(20,8), batches_granted INT, created_at TIMESTAMPTZ`
- `UNIQUE(source_type, source_id)`，`source_type ∈ {payment_order, redeem_code}`
- **`source_id` 一律用数字主键**：`payment_order` → `payment_orders.id`，`redeem_code` → `redeem_codes.id`；不用 code 字符串。（review #5）
- **CHECK 约束**（review #4）：`user_affiliates`：`inviter_reward_quota >= 0`、`inviter_reward_recharge_carry >= 0`、`inviter_reward_quota_consumed_total >= 0`；`referral_recharge_quota_grants`：`batches_granted >= 0`、`order_amount > 0`。`carry < step` 因 step 可配置不入 DB check，由代码保证。

## 赚机会（充值入账时）

- 订单级 `applyReferralQuotaForOrder(ctx, o)`：`doBalance` 里 `Redeem` 之后、`markCompleted` 前调用（紧挨 `applyRechargeDiscountForOrder`）。事务内 `INSERT referral_recharge_quota_grants ... ON CONFLICT (source_type,source_id) DO NOTHING` 抢 slot → 命中则 `FOR UPDATE` 锁 `user_affiliates[o.UserID]` → `carry+=amount; batches=floor(carry/step); quota+=batches*perBatch; carry-=batches*step`，回写 `batches_granted` → commit。
- **[review #1 — High] 失败不阻断充值主链路**：配额是旁路权益，`applyReferralQuotaForOrder` 内部 **best-effort**——任何错误（配额表故障、EnsureUserAffiliate 失败、设置读取失败）只记审计日志（`REFERRAL_QUOTA_ACCRUE_FAILED`）并 `return nil`，**不向 `doBalance` 冒泡**，避免像 affiliate/recharge-discount 那样把已入账订单 `markFailed`。幂等去重表保证若日后补跑不重复赚。（与现有 affiliate/discount 的"失败阻断+重试"语义**刻意不同**，因为配额丢失可容忍、支付主链路不可牺牲。）
- 兑换级 `tryAccrueReferralQuotaForRedeem(...)`：`Redeem` 提交后 best-effort（仅 `RedeemTypeBalance && Value>0`）。
- **[review #2 — Medium] 不复用 affiliate 的 skip key**：支付订单触发的 Redeem 需抑制兑换级配额累积（否则与订单级双计），但**不复用 `ContextSkipRedeemAffiliate`**（其语义专指"跳过兑换级返利"，复用会把返利与配额耦合，无法表达"跳返利不跳配额"）。新增独立 `ContextSkipRedeemReferralQuota`，在 `doBalance` 调 `Redeem` 时与 affiliate skip 一并设置。去重表 `UNIQUE(source_type,source_id)` 作为第二重保险保留。
- 充值者若无 `user_affiliates` 行，先 `EnsureUserAffiliate`（aff_code 是 NOT NULL UNIQUE，不能裸插）再更新。

## 花机会（达标发奖时）

**[cx-s2 review #9 — 事务边界写死，采用 Option A]** 唯一发奖逻辑抽成**内层函数**，它 **不自开事务、不重锁 tracker**——由调用方保证"已在一个打开的事务里、且该 invitee 的 tracker 行已被本事务 `FOR UPDATE` 锁住"：

```
// 前置条件：txCtx 是已打开的事务；tracker 行已在本事务内 FOR UPDATE 锁定。
// 内部只在需要时再锁 affiliate（tracker→affiliate 序），绝不新开事务、绝不重锁 tracker。
grantInviterRewardLocked(txCtx, tracker *lockedTracker) error
```

内层逻辑：
1. gate：`!tracker.granted && tracker.spendTracked>=tracker.threshold && tracker.rewardEligible && 全局开关开`。任一不满足 → 直接返回（不发、不改 flag）。
2. **配额开关关**（`quota_enabled=false`）：直接发（== 现在的无限行为），置 granted、清 blocked flag。
3. **配额开关开**：`SELECT inviter_reward_quota FROM user_affiliates WHERE user_id=tracker.inviterID FOR UPDATE`（第二把锁，顺序恒 tracker 后 affiliate）：
   - `quota<=0`：不发、不置 granted，**置 `inviter_reward_blocked_by_quota=true`**。
   - `quota>0`：`quota-=1; consumed_total+=1`，`giftEngine.Grant`，置 `granted=true`、清 blocked flag，全部在同一 txCtx 内原子完成。

两个入口（事务边界不同，内层实现同一个）：
- **入口 1 — `TrackSpend`（Option A，无新事务）**：`TrackSpend` 现有事务里本就已 `FOR UPDATE` 锁 tracker 并累加 `spend_tracked`；累加后 `newTracked>=threshold` 时**在同一事务内直接调 `grantInviterRewardLocked`**（复用已持有的 tracker 锁，不新开事务、不重锁）。达标累加与发奖同一事务提交，保持现有原子语义，无自锁、无展示滞后。
- **入口 2 — `backfillPendingInviterRewards` wrapper**：对每个待补发 invitee **新开一个独立事务** → `SELECT ... FROM referral_reward_tracker WHERE invitee_id=$1 FOR UPDATE`（此处才锁 tracker）→ 调同一个 `grantInviterRewardLocked` → 提交。逐笔独立事务，锁序同样 tracker→affiliate。

gift grant 与 granted 标记同事务，回滚避免"扣了机会没发奖"。

**pending 语义（修订：充值后立即补发，不再无限 pending）**：达标那一刻 `quota=0` 则 spend event 已记录、`spend_tracked` 越过 threshold，但奖未发、`granted=false`、`blocked_by_quota=true`。此 pending 有**两条**兑现途径：
- ① 被邀请人后续再产生非订阅消费 → `TrackSpend` 再次调共享函数（原有兜底）。
- ② **邀请人充值补足配额 → 充值路径立即扫描补发**（见下节，新增）。

因此 `InviteeProgress` 需表达**四态**：①未达标 ②已达标已发 ③已达标但绑定时邀请人无资格（`reward_eligible=false`，现有）④**已达标但邀请人配额用尽被卡（`blocked_by_quota=true`，新增）**。

## 充值后立即补发 pending 奖励（新增，需求方决策）

需求方要求：邀请人充值补足配额后，被卡的 pending 奖励**立即到账**（而非仅等被邀请人下次消费）。

- **位置**：`applyReferralQuotaForOrder` 加完 quota、**提交那笔"加 quota"事务之后**，追加 `backfillPendingInviterRewards(ctx, inviterID)`。
- **逻辑**：`SELECT invitee_id FROM referral_reward_tracker WHERE inviter_id=$1 AND inviter_reward_granted=false AND inviter_reward_blocked_by_quota=true ORDER BY created_at`（命中 partial index）→ 对每个 invitee 走**入口 2**：新开独立事务 → 锁该 invitee 的 tracker → 调**同一个内层** `grantInviterRewardLocked`。每笔各自独立事务、锁序 `tracker→affiliate`，quota 耗尽后内层自然停发（`quota<=0` 分支，剩余保持 blocked）。
- **死锁规避**：补发**不**在"加 quota"事务里持 affiliate 锁去锁 tracker（那会造成 affiliate→tracker 反序）。而是先提交加 quota，再逐笔走共享函数（tracker→affiliate 序）。全局锁序统一，无环。
- **best-effort**：补发整体包在 recover/error-swallow 里，任何失败只记审计 `REFERRAL_QUOTA_BACKFILL_FAILED`，不阻断充值主链路；未发的 pending 仍由"被邀请人下次消费"兜底。
- **兑换级**同样在 `tryAccrueReferralQuotaForRedeem` 加完 quota 后调 `backfillPendingInviterRewards`。

**并发正确性**：补发（入口 2）与"被邀请人正好此刻消费"（入口 1）可能同时尝试发同一笔——两者都在各自事务内先对 tracker 行 `FOR UPDATE`，谁先拿到锁谁发，另一方阻塞到前者提交后读到 `granted=true`，内层 gate 直接空转。保证只发一次。

## 配置（3 新 setting + DTO + 默认 + 校验）

- `referral_inviter_reward_quota_enabled`（bool，默认 false）
- `referral_inviter_reward_quota_recharge_step`（默认 50）
- `referral_inviter_reward_quota_per_batch`（默认 10）

## 展示

`ReferralStatus` 加 `InviterRewardQuota int`（剩余机会）；`InviteeProgress` 加 `BlockedByQuota bool`，读自 `referral_reward_tracker.inviter_reward_blocked_by_quota`。前端 `/referral`（`ReferralView.vue`）：
- 开关开时显示剩余机会数。
- 每个被邀请人的状态徽章从现有三态扩到**四态**：现有逻辑 `granted?已发 : reward_eligible===false?无资格 : pending`，在中间插入 `blocked_by_quota?已达标待充值解锁`（新增红/橙色徽章 + i18n `referral.statusBlockedByQuota`）。这是弹窗告知后用户点进来看到"具体哪些被邀请人卡住、需充值"的落点。
- i18n zh/en。

## 配额耗尽登录弹窗（走公告板块，新增投放条件）

需求：邀请人因配额用尽导致"被邀请人已达标却发不出奖"时，登录时弹窗告知（充值即可解锁）。**复用现有公告系统**——无需新弹窗机制：管理员建一条 `notify_mode=popup` 公告，挂上下面这个新投放条件即可。弹窗展示、已读记录、频控全部走公告既有链路。

### 精确命中语义（需求方选定：仅"有被卡住的待发奖励"）

只命中"名下存在**因 quota=0 被卡的 pending 达标奖励**"的邀请人——不打扰从未获得过机会的新邀请人，也不与"全局开关关闭"或"eligible_at_bind=false"混淆。纯 SQL 查 `quota<=0` 无法区分这三种阻断原因，故用**显式标志位**。

### 标志位（并入 migration 175）

`referral_reward_tracker` 加列 `inviter_reward_blocked_by_quota BOOLEAN NOT NULL DEFAULT FALSE`：
- **置 true**：花机会路径中，`newTracked>=threshold && !granted && rewardEligible && 全局开关开` 但 `quota<=0` 时（即"本该发、只差机会"）。仅此一条分支置 true，精确排除 switch-off / eligible=false。
- **清 false**：同路径后续 `quota>0` 成功发奖、置 `inviter_reward_granted=true` 时一并清（granted=true 后 EXISTS 自然不再命中，清 flag 只为语义干净）。
- 放 tracker（per 邀请人↔被邀请人对）而非 `user_affiliates`：blocked 是"某个具体被邀请人的奖励卡住"，天然是 pair 级；避免在 affiliate 行维护计数器的增减一致性难题。
- **partial index（cx-s2 review 非阻塞建议，采纳）**：`CREATE INDEX ... ON referral_reward_tracker(inviter_id) WHERE inviter_reward_granted=false AND inviter_reward_blocked_by_quota=true`（`_notx` 迁移）。避免大邀请人登录时 `fillReferralTargeting` 的 EXISTS 扫过多 pair 行。

### 投放条件扩展

- domain：新增 referral 条件取值 `inviter_reward_blocked`（`AnnouncementCondition.ReferralValue`）。`Matches`/`validate` 各加一分支。
- context：`UserTargetingContext` 加 `InviterRewardBlocked bool`；在 `announcement_service.go` 的 `fillReferralTargeting` 里，与现有 affiliate 查询同一处补一条 `EXISTS(SELECT 1 FROM referral_reward_tracker WHERE inviter_id=$1 AND inviter_reward_granted=false AND inviter_reward_blocked_by_quota=true)`（沿用 `ReferralKnown` fail-closed：查询失败则不命中，不误投）。
- DTO/前端：`AnnouncementReferralValue` 加 `'inviter_reward_blocked'`；`AnnouncementTargetingEditor.vue` 的 referral 下拉加一项；i18n zh/en 加文案（如"邀请达标奖励机会已用尽"）。

### 边界

此条件只依赖 tracker flag，与配额总开关**解耦**读取：即使管理员事后关掉配额开关，历史被卡的 pending 仍会命中（合理——奖励确实还没发）。若不希望关关后仍弹，可在公告文案侧说明，或后续按需在 `fillReferralTargeting` 加开关 gate（本期不做，保持最小改动）。

## 测试（go test -tags=unit）

carry 跨次累积、幂等重试不重复赚、两被邀请人并发达标只扣一次机会、quota=0 时跳过且不置 granted 且置 blocked flag、开关关闭时行为完全不变、订单级+兑换级不双计（支付订单 Redeem 被 `ContextSkipRedeemReferralQuota` 抑制）、**赚配额步骤失败不阻断充值订单完成（best-effort，仅记审计）**。**充值立即补发**：充值补足配额后 backfill 立即发出被卡 pending（无需被邀请人再消费）、补发按 quota 数量逐笔发完即止、quota 不足时部分补发剩余仍 blocked、backfill 失败不阻断充值且 pending 仍可被后续消费兜底、补发与被邀请人同时消费只发一次（共享函数 tracker FOR UPDATE + !granted gate）、共享函数被 TrackSpend 与 backfill 调用行为一致。**弹窗条件**：`blocked_by_quota` 仅在 quota=0 阻断分支置 true（switch-off/eligible=false 不置）、补发/消费发奖后 flag 清且 EXISTS 不再命中、`fillReferralTargeting` 的 EXISTS 命中/不命中/DB 失败 fail-closed、domain `Matches`/`validate` 新取值。**前端**：四态徽章渲染（未达标/已发/无资格/blocked）。

## 影响面

migration×1（`user_affiliates` 加 3 列 + `referral_reward_tracker` 加 1 列 blocked flag）、新表×1（`referral_recharge_quota_grants`）；改 `domain_constants.go`、`setting_service.go`、`dto/settings.go`、`setting_handler.go`、`payment_fulfillment.go`(+新文件 `payment_referral_quota.go`)、`redeem_service.go`、`referral_reward_service.go`、repo 层、`domain/announcement.go`（新 referral 取值 + context 字段）、`announcement_service.go`（fillReferralTargeting 补 EXISTS）、`handler/dto/announcement.go` 及前端 `AnnouncementTargetingEditor.vue`、`types/index.ts`、前端 ReferralView+i18n、单测。**不动**绑定/继承/被邀请人赠金/折扣逻辑。

## 需重点评审的语义点

1. ~~`quota=0` 的达标 pending 不主动补发~~ —— **已被第三轮"充值立即补发"推翻**，见第 8-10 点。
2. 订单级+兑换级双钩子去重是否严密（ContextSkip 抑制 + 去重表双保险）。
3. carry 跨次累积语义（而非每单独立 floor）是否符合"每充值 50 得 10"的直觉。

## 【第三轮追加待评审】充值立即补发 + 四态展示（需求方新决策）

需求方追加两点：① 邀请人充值补足配额后 pending 奖励**立即到账**（不再仅等被邀请人下次消费）；② 登录弹窗**只做定性告知不带数字**，具体"哪些被邀请人卡住"由 `/referral` 四态徽章展示。请重点评审：

8. **[High] 死锁规避**：新增"充值补发"是第二条发奖路径。花机会路径锁序 `tracker→affiliate`；若补发在"加 quota"事务内持 affiliate 锁再去锁 tracker 就成反序 → 死锁。方案的解法：**先提交"加 quota"事务，再逐笔走共享函数 `tryGrantInviterRewardWithQuota`**（内部锁序恒 `tracker→affiliate`）。请确认此拆分确实消除环、且"加 quota 已提交但补发中途失败"时状态一致（quota 已加、部分 pending 已发、剩余仍 blocked，下次消费兜底——可接受）。
9. **[Medium — 已按 cx-s2 意见收紧，采用 Option A]** 事务边界原文"同一事务或紧随其后的独立事务"有自锁歧义（`TrackSpend` 已持 tracker `FOR UPDATE`，若内层再自开事务重锁同行 → 自锁/超时）。已改为：唯一发奖逻辑是**内层 `grantInviterRewardLocked`，不自开事务、不重锁 tracker**，要求调用方已在打开的事务里且已锁 tracker。入口 1（`TrackSpend`）在其现有事务内直接调（复用已持锁，Option A，最接近现有原子语义）；入口 2（backfill）每笔新开独立事务、锁 tracker 后再调。请确认此边界无自锁、无双发/漏发。
10. **[Low] 四态徽章**：`InviteeProgress` 加 `BlockedByQuota`，前端 `/referral` 徽章由三态扩四态（插在 pending 前）。弹窗（公告 popup）不注入数字，仅定性文案 + 引导去 `/referral`。是否认可这个"弹窗定性 + referral 详情"的分工。

## 【第二轮追加待评审】配额耗尽登录弹窗

在已 approved 的配额方案上新增：邀请人因配额用尽卡住 pending 奖励时，登录弹窗告知（走公告 popup + 新投放条件）。请重点评审：

4. **标志位放 tracker 而非 user_affiliates**：`referral_reward_tracker.inviter_reward_blocked_by_quota`，仅在"该发但 quota=0"分支置 true、发奖成功清除。是否比在 affiliate 行维护计数器更可靠（避免增减一致性）。
5. **flag 的置/清是否覆盖全部路径**：置 true 仅限 `>=threshold && !granted && rewardEligible && 开关开 && quota<=0`；switch-off / eligible_at_bind=false 分支**不置**。清除随成功发奖。有无遗漏路径导致 flag 与实际 pending 状态不一致（stale true / 漏置）。
6. **投放查询解耦配额开关**：`fillReferralTargeting` 用 `EXISTS(... granted=false AND blocked_by_quota=true)` 命中，不 gate 配额总开关。即管理员事后关掉配额开关，历史卡住的 pending 仍会弹。是否可接受，还是应加开关 gate。
7. **fail-closed**：沿用现有 `ReferralKnown` 语义，EXISTS 查询失败则条件不命中（不误投）。
