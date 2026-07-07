-- 175_inviter_reward_quota.sql
-- 超级邀请「邀请人达标奖励」发放次数配额。
-- 邀请人每充值 recharge_step USD 获得 per_batch 次"领取被邀请人达标奖励"的机会。
-- 机会用尽后被邀请人达标也不再给邀请人发奖，直到邀请人再充值补足配额。
--
-- 设计要点（详见 docs/pending-plans/aff-bi-direction/inviter-reward-quota-plan.md）：
--   - 配额计数器随邀请人挂在 user_affiliates 行（每邀请人一行）。
--   - carry 跨次累积未凑满一档的充值余额。
--   - referral_reward_tracker 加 blocked_by_quota 标志位（pair 级事实源），
--     供"配额耗尽登录弹窗"公告投放 + /referral 四态展示。
--   - referral_recharge_quota_grants 是充值赚配额的幂等去重表（每笔充值只赚一次）。

-- 1. 邀请人配额计数器（挂在 user_affiliates）
ALTER TABLE user_affiliates
    ADD COLUMN IF NOT EXISTS inviter_reward_quota INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS inviter_reward_recharge_carry DECIMAL(20,8) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS inviter_reward_quota_consumed_total INT NOT NULL DEFAULT 0;

ALTER TABLE user_affiliates
    DROP CONSTRAINT IF EXISTS chk_ua_inviter_reward_quota_non_negative;
ALTER TABLE user_affiliates
    ADD CONSTRAINT chk_ua_inviter_reward_quota_non_negative
        CHECK (inviter_reward_quota >= 0);

ALTER TABLE user_affiliates
    DROP CONSTRAINT IF EXISTS chk_ua_inviter_reward_carry_non_negative;
ALTER TABLE user_affiliates
    ADD CONSTRAINT chk_ua_inviter_reward_carry_non_negative
        CHECK (inviter_reward_recharge_carry >= 0);

ALTER TABLE user_affiliates
    DROP CONSTRAINT IF EXISTS chk_ua_inviter_reward_consumed_non_negative;
ALTER TABLE user_affiliates
    ADD CONSTRAINT chk_ua_inviter_reward_consumed_non_negative
        CHECK (inviter_reward_quota_consumed_total >= 0);

COMMENT ON COLUMN user_affiliates.inviter_reward_quota IS
    'Remaining number of inviter-reward grants this inviter may still receive. Earned by recharging; consumed when an invitee reward is granted.';
COMMENT ON COLUMN user_affiliates.inviter_reward_recharge_carry IS
    'Recharge amount not yet forming a full batch, carried across recharges. batches = floor((carry+amount)/step).';
COMMENT ON COLUMN user_affiliates.inviter_reward_quota_consumed_total IS
    'Cumulative number of inviter-reward grants consumed. Audit/display only.';

-- 2. tracker 上的"因配额用尽被卡"标志位（pair 级事实源）
ALTER TABLE referral_reward_tracker
    ADD COLUMN IF NOT EXISTS inviter_reward_blocked_by_quota BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN referral_reward_tracker.inviter_reward_blocked_by_quota IS
    'TRUE means the invitee met the threshold but the inviter reward was NOT granted purely because the inviter had no quota. Set only in the quota<=0 branch; cleared when the reward is finally granted. Drives the "quota exhausted" login popup and /referral display.';

-- 3. 充值赚配额的幂等去重表（每笔充值只赚一次）
CREATE TABLE IF NOT EXISTS referral_recharge_quota_grants (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL,
    source_type     VARCHAR(20) NOT NULL,
    source_id       BIGINT NOT NULL,
    order_amount    DECIMAL(20,8) NOT NULL,
    batches_granted INT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_rrqg_source_type CHECK (source_type IN ('payment_order', 'redeem_code')),
    CONSTRAINT chk_rrqg_order_amount_positive CHECK (order_amount > 0),
    CONSTRAINT chk_rrqg_batches_non_negative CHECK (batches_granted >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rrqg_source ON referral_recharge_quota_grants(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_rrqg_user ON referral_recharge_quota_grants(user_id);
