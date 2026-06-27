-- 167_alter_discount_rate_limit.sql
-- 放开 discount_rate 上限: 1 → 10（支持充值倍率奖励）

ALTER TABLE user_recharge_discounts
    DROP CONSTRAINT IF EXISTS chk_urd_rate,
    ADD CONSTRAINT chk_urd_rate CHECK (discount_rate > 0 AND discount_rate <= 10);
