-- 177_user_gifts_group_scope_and_pin.sql
-- 赠金绑定分组 + 置顶功能。
-- 详见 docs/pendding-plans/赠金子系统-固定key分组/plan.md。
--
-- 设计要点：
--   - group_id 可空：NULL = 全局通用（任意分组可花）；非 NULL = 仅限该分组消费。
--     领取带分组的池 key 时固化为该组；分组被删除时置回 NULL（转全局，见 §3.5）。
--   - pinned：用户置顶的赠金，至多一条（部分唯一索引强约束），
--     allocator Stage 0 最先消费（绝对第一，见 §3.10）。
--   - 不加外键：分组软删走应用层置 NULL，外键对软删无意义、且避免级联耦合。
--   - 存量零回归：所有历史赠金 group_id 默认 NULL、pinned 默认 false。

-- 1. 新增列
ALTER TABLE user_gifts
    ADD COLUMN IF NOT EXISTS group_id BIGINT NULL,
    ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN user_gifts.group_id IS
    'Optional group this gift is restricted to. NULL = usable in any group. Set at claim time from the pool key group; reset to NULL when the group is deleted.';
COMMENT ON COLUMN user_gifts.pinned IS
    'Whether the user pinned this gift to be consumed first (allocator Stage 0). At most one pinned gift per user (enforced by partial unique index).';

-- 2. 扣费快照按 (user_id, group_id) 过滤
CREATE INDEX IF NOT EXISTS user_gifts_user_id_group_id
    ON user_gifts (user_id, group_id);

-- 3. 分组删除按 group_id 清扫；单列偏索引仅覆盖有分组的赠金，
--    (user_id, group_id) 复合索引无法高效服务 WHERE group_id = $1。
CREATE INDEX IF NOT EXISTS user_gifts_group_id
    ON user_gifts (group_id)
    WHERE group_id IS NOT NULL;

-- 4. 一人至多一条置顶：部分唯一索引在 DB 层强约束
CREATE UNIQUE INDEX IF NOT EXISTS user_gifts_one_pin_per_user
    ON user_gifts (user_id)
    WHERE pinned;

-- 5. 计费幂等指纹版本列（两阶段发布，见 plan.md §3.6）。
--    存量行 DEFAULT 1（V1 公式，不含 group_id）；新写入按 config 开关决定写 1 还是 2。
--    dedup 比对时按存储版本选公式重算，避免滚动部署期混版误判冲突。
--    归档搬运器（dashboard_aggregation_repo.CleanupUsageBillingDedup）会带上该列。
ALTER TABLE usage_billing_dedup
    ADD COLUMN IF NOT EXISTS fingerprint_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE usage_billing_dedup_archive
    ADD COLUMN IF NOT EXISTS fingerprint_version SMALLINT NOT NULL DEFAULT 1;

COMMENT ON COLUMN usage_billing_dedup.fingerprint_version IS
    'Fingerprint formula version for request_fingerprint. 1 = legacy (no group_id); 2 = includes group_id. Compared version-aware to stay compatible across rolling deploys.';
COMMENT ON COLUMN usage_billing_dedup_archive.fingerprint_version IS
    'Fingerprint formula version, copied from usage_billing_dedup on archival.';
