-- Gap 1: snapshot whether this invitee can produce an inviter reward.

ALTER TABLE referral_reward_tracker
    ADD COLUMN IF NOT EXISTS inviter_reward_eligible_at_bind BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN referral_reward_tracker.inviter_reward_eligible_at_bind IS
    'Whether the inviter had super-referral reward eligibility when this invitee was bound. FALSE means this invitee cannot trigger an inviter reward.';
