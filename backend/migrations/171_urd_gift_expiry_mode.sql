-- Recharge-discount gifts: decouple gift expiry from discount validity.
-- The discount valid_until still controls recharge-discount availability and
-- super-referral eligibility. These fields control only the gift granted when
-- the discount is consumed.

ALTER TABLE user_recharge_discounts
    ADD COLUMN IF NOT EXISTS gift_expiry_mode VARCHAR(24) NOT NULL DEFAULT 'discount_valid_until',
    ADD COLUMN IF NOT EXISTS gift_expires_after_days INT NULL;

ALTER TABLE user_recharge_discounts
    DROP CONSTRAINT IF EXISTS chk_urd_gift_expiry;

ALTER TABLE user_recharge_discounts
    ADD CONSTRAINT chk_urd_gift_expiry CHECK (
        (gift_expiry_mode = 'discount_valid_until' AND gift_expires_after_days IS NULL)
        OR
        (gift_expiry_mode = 'never' AND gift_expires_after_days IS NULL)
        OR
        (gift_expiry_mode = 'after_days' AND gift_expires_after_days IS NOT NULL AND gift_expires_after_days > 0)
    );

COMMENT ON COLUMN user_recharge_discounts.gift_expiry_mode IS
    'Expiry mode for gifts granted by this discount: discount_valid_until|never|after_days. Fixed at discount creation and copied on referral inheritance.';
COMMENT ON COLUMN user_recharge_discounts.gift_expires_after_days IS
    'Number of days after grant for after_days mode; NULL for discount_valid_until and never.';
