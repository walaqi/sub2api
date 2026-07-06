-- 174_bind_key_gift_settings_activity_id.sql
-- 给表 A bind_key_gift_settings 增加 nullable 列 activity_id。
-- 用途：把一条池 key 关联到某个活动（activity_events.id）。
-- NULL = 该 key 不隶属任何活动（普通推广 key，仅走 /bind-key 手动领取）。
-- 活动报名时按 activity_id 查出该活动下、仍属池用户（未被领走）的 key。
-- 建独立索引列（而非塞进 config JSONB），以支持高效过滤"某活动的所有 key"。
-- 不加外键约束：activity_events 属独立活动子系统（裸 SQL 管理），
-- 且 key 配置行由运维独立清理，避免跨子系统级联删除耦合。

ALTER TABLE bind_key_gift_settings
    ADD COLUMN IF NOT EXISTS activity_id BIGINT NULL;

CREATE INDEX IF NOT EXISTS bindkeygiftsetting_activity_id
    ON bind_key_gift_settings (activity_id);

COMMENT ON COLUMN bind_key_gift_settings.activity_id IS
    'Optional activity_events.id this pool key belongs to. NULL = not tied to any activity.';
