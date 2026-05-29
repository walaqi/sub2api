-- 145_payment_provider_instance_metadata.sql
-- payment_provider_instances 增加 metadata text 列：存储自由形式 JSON 元数据，
-- 用于易支付「自定通道」的 label / icon_url / 余额倍率 / 商品名前后缀覆盖。
-- 默认空字符串与 ent schema (Default("")) 一致。

ALTER TABLE payment_provider_instances
    ADD COLUMN IF NOT EXISTS metadata TEXT NOT NULL DEFAULT '';
