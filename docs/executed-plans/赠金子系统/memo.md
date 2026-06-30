## 赠金过期不可恢复

当手动设置过期时间, 让赠金过期, 然后重新设置过期时间, 让赠金重新生效, 但是赠金看起来再也回不来了. 原因是什么?\*\*只调研不改代码文档\*\*

原因如下：

**核心机制**：`expirer.go` 的过期处理是**破坏性副作用**，不是软过期，不可通过修改 `expires_at` 单字段还原。

**ticker 处理过期赠金时做了三件事**（一个事务内）：

1.  `user_gifts.status` 从 `active` → `expired`
2.  `user_gifts.remaining` 置为 0
3.  `users.balance` 扣减原 remaining 数额（维持不变量 `balance ≡ recharge_pool + Σ(active gifts.remaining)`）

**`GetGiftBalanceBreakdown` 的查询条件**：

```sql
WHERE status = 'active' AND (expires_at IS NULL OR expires_at > NOW())
SUM(remaining)
```

**所以仅把 `expires_at` 改回未来，三个失败点同时存在**：

| 字段 | 当前状态 | 是否被 query 命中 |
| --- | --- | --- |
| `status` | `expired` | ❌ 被 `status='active'` 过滤掉 |
| `remaining` | `0` | 即使 status 改回 active，SUM 也是 0 |
| `users.balance` | 已扣 | 即使前两项修好，余额已经少了一份 |

**要"复活"这个赠金，需要在一个事务里同时**：

```sql
BEGIN;
UPDATE user_gifts SET 
  status = 'active',
  remaining = <原 remaining 数额>,  -- 通常等于 amount，但若曾被部分消费要看历史
  expires_at = <未来时间>
WHERE id = <gift_id>;

UPDATE users SET 
  balance = balance + <恢复的 remaining>
WHERE id = <user_id>;
COMMIT;
```

**设计意图**：过期是终态。这个状态机故意不可逆——一旦进了 `expired`，业务语义就是"这笔赠金作废了"，再也不参与计算。如果产品要支持"延期"，正确做法是在过期**之前**修改 `expires_at`（`active` 状态下 ticker 不会动它），或走运维 API 发一笔新赠金，而不是事后救活旧记录。

**`RevokeGift` 的状态机也印证了这点**：`engine.go` 里 `RevokeGift` 显式检查 `status == 'active'` 才允许操作，否则返回 `ErrGiftNotRevocable`。expired 同样属于"已终结"分支，不再可逆。