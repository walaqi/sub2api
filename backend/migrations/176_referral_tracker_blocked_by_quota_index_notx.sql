-- 176_referral_tracker_blocked_by_quota_index_notx.sql
-- Partial index for the "quota exhausted" login popup targeting.
-- fillReferralTargeting runs EXISTS(... inviter_id=$1 AND inviter_reward_granted=false
-- AND inviter_reward_blocked_by_quota=true) this narrow partial index keeps that
-- probe cheap even for inviters with many invitee tracker rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rrt_inviter_blocked_pending
    ON referral_reward_tracker (inviter_id)
    WHERE inviter_reward_granted = FALSE AND inviter_reward_blocked_by_quota = TRUE;
