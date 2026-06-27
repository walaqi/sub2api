-- 用户充值折扣表（支持 bind_key 直接绑定和 referral 裂变继承两种来源）
CREATE TABLE IF NOT EXISTS user_recharge_discounts (
    id                      BIGSERIAL PRIMARY KEY,
    user_id                 BIGINT NOT NULL,
    source                  VARCHAR(32) NOT NULL,
    source_ref              VARCHAR(128),
    origin_api_key_id       BIGINT,
    total_discounted        DECIMAL(20,8) NOT NULL DEFAULT 0,
    discount_rate           DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_discountable_amount DECIMAL(20,8) NOT NULL DEFAULT 0,
    valid_from              TIMESTAMPTZ NOT NULL,
    valid_until             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_urd_rate CHECK (discount_rate > 0 AND discount_rate <= 1),
    CONSTRAINT chk_urd_max CHECK (max_discountable_amount > 0),
    CONSTRAINT chk_urd_total CHECK (total_discounted >= 0 AND total_discounted <= max_discountable_amount),
    CONSTRAINT chk_urd_source CHECK (source IN ('bind_key', 'referral_inherit'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_urd_user_source_ref ON user_recharge_discounts(user_id, source, source_ref);
CREATE INDEX IF NOT EXISTS idx_urd_user_valid ON user_recharge_discounts(user_id, valid_until)
    WHERE total_discounted < max_discountable_amount;

-- 充值折扣发放去重表（每订单只发一次，防 fulfillment 重试重复发放）
CREATE TABLE IF NOT EXISTS recharge_discount_applications (
    id                      BIGSERIAL PRIMARY KEY,
    user_id                 BIGINT NOT NULL,
    discount_id             BIGINT NOT NULL REFERENCES user_recharge_discounts(id),
    payment_order_id        BIGINT NOT NULL,
    applied_amount          DECIMAL(20,8) NOT NULL,
    bonus_amount            DECIMAL(20,8) NOT NULL,
    discount_rate_snapshot  DOUBLE PRECISION NOT NULL,
    gift_id                 BIGINT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rda_order ON recharge_discount_applications(payment_order_id);
