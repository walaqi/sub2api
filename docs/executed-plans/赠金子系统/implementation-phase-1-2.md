实施完成总结
按计划稿 Phase 1 + Phase 2 全部落地，41 个测试包全部通过，0 failure。

Phase 1（核心引擎 + 主扣费路径 + 绑 key）：

backend/migrations/142_user_gifts.sql — 建表 + 部分索引
backend/ent/schema/user_gift.go + 重生成 ent 代码
backend/internal/gift/ 新包：types / allocator（纯函数 + 10 个表驱动单测全过）/ repository / engine
backend/internal/repository/usage_billing_repo.go — 主扣费路径接入 giftEngine.AllocateAndDeduct
backend/internal/keybind/balance.go — 绑 key 改走 gift.SourceKeybind priority，修复 total_recharged 污染
Phase 2（其他发放点 + 退款 + Profile + 过期清理）：

backend/internal/service/auth_oauth_first_bind.go — OAuth 首登 priority gift（amount=0 早返回；amount<0 退化到旧路径）
backend/internal/service/promo_service.go — 优惠码 priority gift（沿用 promo_code.expires_at + source_ref）
backend/internal/service/payment_refund.go — 退款两阶段防御：评估查 recharge_pool + ExecuteRefund 内 DeductFromRechargePool 重校验 + actualDeducted 回写
backend/internal/handler/dto/types.go + user_handler.go — Profile API 拆分 gift_balance / recharge_balance
backend/internal/gift/expirer.go + wire — 过期清理 ticker（10 min 周期，wire 注入 + cleanup 注册）
兑换码 / affiliate / 管理员路径按用户决策保持现状
gateway_service.go postUsageBilling legacy fallback 加 TODO 注释
未做（按 review-3 checklist 留作后续）：Phase 3 前端展示拆分、独立的 total_recharged cleanup PR、Prometheus metrics 落地、并发集成测试矩阵。