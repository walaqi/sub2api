-- 151_bind_key_gift_settings_config.sql
-- 给表 A bind_key_gift_settings 增加可扩展 JSONB 配置列 `config`。
-- 用途：承载 per-key 的扩展配置（首个使用方：注册时间窗口 registration_window）。
-- 设计：以后 bind-key 的其它 per-key 选项继续往同一个 JSON 里加，避免反复迁移 schema。
-- NULL = 无扩展配置（含无注册窗口），与历史行为一致。
-- 配置随 api_key_id 落本表，key 删除时由运维清理本表即一并清除，不产生孤儿。

ALTER TABLE bind_key_gift_settings
    ADD COLUMN IF NOT EXISTS config JSONB;
