-- Recharge-discount gifts: configurable deduction mode (priority|ratio).
-- Mirrors user_gifts (migrations/142) deduction_mode + ratio_recharge semantics.
-- The mode is fixed on the discount row at creation time and read at grant time;
-- inheritance copies the row's mode/ratio so invitees keep a stable snapshot.

ALTER TABLE user_recharge_discounts
    ADD COLUMN IF NOT EXISTS gift_deduction_mode VARCHAR(16) NOT NULL DEFAULT 'priority',
    ADD COLUMN IF NOT EXISTS gift_ratio_recharge DECIMAL(20,8) NULL;

ALTER TABLE user_recharge_discounts
    ADD CONSTRAINT chk_urd_gift_mode_ratio CHECK (
        (gift_deduction_mode = 'priority' AND gift_ratio_recharge IS NULL)
        OR
        (gift_deduction_mode = 'ratio' AND gift_ratio_recharge IS NOT NULL AND gift_ratio_recharge > 0)
    );

COMMENT ON COLUMN user_recharge_discounts.gift_deduction_mode IS
    'Deduction mode for the gift granted by this discount: priority|ratio. Fixed at creation, read at grant time, copied on referral inheritance.';
COMMENT ON COLUMN user_recharge_discounts.gift_ratio_recharge IS
    'Ratio value for ratio mode (NULL for priority). Consumed alongside recharge balance at this ratio.';
