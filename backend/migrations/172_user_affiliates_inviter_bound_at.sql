-- Store a stable timestamp for when a user first binds an inviter.
-- updated_at can change later for unrelated affiliate profile updates, so it
-- cannot be used as a historical referral eligibility snapshot time.

ALTER TABLE user_affiliates
    ADD COLUMN IF NOT EXISTS inviter_bound_at TIMESTAMPTZ NULL;

UPDATE user_affiliates
SET inviter_bound_at = updated_at
WHERE inviter_id IS NOT NULL
  AND inviter_bound_at IS NULL;

COMMENT ON COLUMN user_affiliates.inviter_bound_at IS
    'Timestamp when inviter_id was first bound. Used for super-referral eligibility snapshots.';
