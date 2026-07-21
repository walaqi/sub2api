-- 分组级「按模型的 5 小时 USD 限额」功能。
--
-- 1) groups.model_5h_limits：分组上按精确模型名配置的 5h USD 上限。
--    形如 {"claude-opus-4-8": 3.5, "gpt-5.3-codex": 2}；空对象 = 该分组不设任何 5h 限额。
--    key 为精确模型名（不支持通配），value 为该模型在单个 5h 固定窗口内的 USD 上限。
--
-- 2) user_group_model_quota_5h：每个用户在 (分组, 模型) 维度上的 5h 用量计数（USD）。
--    Redis 为实时 enforcement 权威，本表为持久化镜像（重启后回填、审计对账）。
--    window_start 记录当前 5h 固定窗口起点；跨窗口时由累加逻辑重置 usage 并推进 window_start。

ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS model_5h_limits JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS user_group_model_quota_5h (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    model_name VARCHAR(200) NOT NULL,
    usage_usd DECIMAL(20,10) NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, group_id, model_name)
);

CREATE INDEX IF NOT EXISTS idx_ugmq5h_user
    ON user_group_model_quota_5h (user_id);
