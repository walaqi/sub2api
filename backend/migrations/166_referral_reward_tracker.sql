-- 166_referral_reward_tracker.sql
-- 双向邀请奖励追踪表 + 消费事件去重表

CREATE TABLE IF NOT EXISTS referral_reward_tracker (
    id                      BIGSERIAL PRIMARY KEY,
    inviter_id              BIGINT NOT NULL,
    invitee_id              BIGINT NOT NULL,
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
    spend_threshold         DECIMAL(20,8) NOT NULL DEFAULT 10,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rrt_inviter_invitee ON referral_reward_tracker(inviter_id, invitee_id);
CREATE INDEX IF NOT EXISTS idx_rrt_invitee ON referral_reward_tracker(invitee_id);
CREATE INDEX IF NOT EXISTS idx_rrt_pending_inviter ON referral_reward_tracker(inviter_reward_granted, invitee_id)
    WHERE inviter_reward_granted = FALSE;

-- 消费事件去重表：防止 billing 事件重放导致 spend_tracked 重复累加
CREATE TABLE IF NOT EXISTS referral_spend_events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        VARCHAR(128) NOT NULL,
    invitee_id      BIGINT NOT NULL,
    amount          DECIMAL(20,8) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rse_event ON referral_spend_events(event_id);
