-- 142_user_gifts.sql
-- 赠金子系统：每笔赠金独立记账。
-- users.balance 保持"含赠金的总余额"语义，通过子账本拆分 gift_pool 与 recharge_pool。
-- 详见 /home/chris/.claude/plans/wobbly-herding-waffle.md。

CREATE TABLE IF NOT EXISTS user_gifts (
    id              BIGSERIAL    PRIMARY KEY,
    user_id         BIGINT       NOT NULL,
    amount          DECIMAL(20,8) NOT NULL CHECK (amount > 0),
    remaining       DECIMAL(20,8) NOT NULL CHECK (remaining >= 0),
    deduction_mode  VARCHAR(16)  NOT NULL CHECK (deduction_mode IN ('priority','ratio')),
    ratio_recharge  DECIMAL(20,8) NULL,
    expires_at      TIMESTAMPTZ  NULL,
    source          VARCHAR(32)  NOT NULL,
    source_ref      VARCHAR(128) NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','exhausted','expired','revoked')),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT user_gifts_mode_ratio_check CHECK (
        (deduction_mode = 'ratio' AND ratio_recharge IS NOT NULL AND ratio_recharge > 0)
        OR (deduction_mode = 'priority' AND ratio_recharge IS NULL)
    ),
    CONSTRAINT user_gifts_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 扣费路径主查询：用户的 active 赠金按 id ASC 加锁
CREATE INDEX IF NOT EXISTS idx_user_gifts_user_active
    ON user_gifts (user_id, status, expires_at)
    WHERE status = 'active';

-- 过期清理任务扫描：仅扫有 expires_at 且 active 的赠金
CREATE INDEX IF NOT EXISTS idx_user_gifts_expiry_sweep
    ON user_gifts (expires_at)
    WHERE status = 'active' AND expires_at IS NOT NULL;
