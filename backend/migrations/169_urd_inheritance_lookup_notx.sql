-- Gap 2: inheritance eligibility looks only at the discount time window, not quota exhaustion.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_urd_inheritance_lookup
    ON user_recharge_discounts (user_id, valid_from, valid_until);
