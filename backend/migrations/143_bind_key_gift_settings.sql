-- 143_bind_key_gift_settings.sql
-- 绑 key 赠金参数表（表 A）：每条池 key 可配置发放时的赠金 mode/ratio_recharge/expires_after_days。
-- 与 api_keys 解耦（不设外键），由运维清理；绑定后所有权转移给用户，配置可独立删除。
-- 详见 /home/chris/.claude/plans/wobbly-herding-waffle.md Phase 3 §1。

CREATE TABLE IF NOT EXISTS bind_key_gift_settings (
    id                  BIGSERIAL    PRIMARY KEY,
    api_key_id          BIGINT       NOT NULL UNIQUE,
    deduction_mode      VARCHAR(16)  NOT NULL CHECK (deduction_mode IN ('priority','ratio')),
    ratio_recharge      DECIMAL(20,8) NULL,
    expires_after_days  INTEGER      NULL CHECK (expires_after_days IS NULL OR expires_after_days > 0),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT bind_key_gift_settings_mode_ratio_check CHECK (
        (deduction_mode = 'ratio' AND ratio_recharge IS NOT NULL AND ratio_recharge > 0)
        OR (deduction_mode = 'priority' AND ratio_recharge IS NULL)
    )
);
