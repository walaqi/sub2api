-- 144_usage_log_gift_breakdown.sql
-- usage_logs 增加赠金 / 充值池扣减拆分字段。
-- 不变量：gift_cost + recharge_cost = actual_cost（订阅扣费路径下两者均为 0）。
-- 历史行 DEFAULT 0 自然兼容；写入端由 gift.Engine.AllocateAndDeductWithBreakdown 提供。

ALTER TABLE usage_logs
    ADD COLUMN IF NOT EXISTS gift_cost     DECIMAL(20,10) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS recharge_cost DECIMAL(20,10) NOT NULL DEFAULT 0;
