# 赠金子系统 · 手动测试执行计划

针对 [wobbly-herding-waffle.md](/home/chris/.claude/plans/wobbly-herding-waffle.md) Phase 1 + Phase 2 已落地代码的端到端验证。

测试目标：

- 验证不变量 `users.balance ≡ recharge_pool + Σ(active gifts.remaining)` 在所有路径下守恒
- 验证 commit `32df9534` 引入的 `total_recharged` 污染已修复
- 验证三阶段算法（priority → ratio → recharge）落库行为与单测一致
- 验证退款只扣 `recharge_pool`，赠金不联动
- 验证 Profile API `gift_balance` / `recharge_balance` 拆分正确
- 验证过期清理 ticker 不破坏不变量

---

## 0 · 前置准备

### 0.1 环境

- [ ] PostgreSQL 数据库可访问，用户具有 SELECT/UPDATE 权限
- [ ] 后端可启动至 listen 状态（`go run ./cmd/server` 或运行编译产物）
- [ ] 一个 admin 账号 + 一个普通用户账号（普通账号没有未结清订单，避免干扰）
- [ ] Redis 已启动（绑 key 失效缓存依赖）
- [ ] 至少配置一个可用的 API key 池用户（`BIND_KEY_POOL_USER_EMAIL` 或默认 `keypool@atai8.cc`），其下挂未被认领的 key

### 0.2 工具

- 数据库直查工具：`psql` 或 GUI（DBeaver / TablePlus）
- HTTP 客户端：curl 或前端
- 后端日志监控：`tail -f` 或 stderr

### 0.3 测试快查 SQL（贯穿全文反复使用）

把这两条 SQL 收藏到工具里，每个 case 验证完都跑一次。**用前把 `<USER_ID>` 整段替换为测试用户的整数 ID**（例如 `42`）。不要用 `:name` / `:'name'` 这类客户端语法 —— psql 没设 `\set` 时会保留原样、GUI 客户端不解析，结果一律比较失败 → 返回空。

```sql
-- Q1：用户余额拆分快照（即使没赠金记录，也应返回 1 行：gift_balance=0, recharge_pool=balance）
SELECT
    u.id,
    u.balance                                       AS total_balance,
    u.total_recharged,
    COALESCE(SUM(CASE WHEN g.status='active'
                       AND (g.expires_at IS NULL OR g.expires_at > NOW())
                       THEN g.remaining END), 0)   AS gift_balance,
    u.balance
        - COALESCE(SUM(CASE WHEN g.status='active'
                             AND (g.expires_at IS NULL OR g.expires_at > NOW())
                             THEN g.remaining END), 0) AS recharge_pool
FROM users u
LEFT JOIN user_gifts g ON g.user_id = u.id
WHERE u.id = <USER_ID>
GROUP BY u.id;

-- Q2：用户当前所有赠金记录（没赠金时返回 0 行，属于正常情况）
SELECT id, amount, remaining, deduction_mode, ratio_recharge,
       expires_at, source, source_ref, status, created_at, updated_at
FROM user_gifts
WHERE user_id = <USER_ID>
ORDER BY id;
```

**异常情况自查**：

- Q1 返回空 → users 表里没这个 ID（用户没创建/已软删除）；先 `SELECT id, email, deleted_at FROM users WHERE id = <USER_ID>` 确认
- Q1 报 `relation "user_gifts" does not exist` → 迁移 142 没执行；回 §1 检查
- Q2 返回空但 Q1 显示 `gift_balance > 0` → 不可能，说明前面 SQL 替换错了 ID

---

## 1 · 迁移与表结构验证

### TC-1.1 迁移 142 已应用

**前置说明**：项目的迁移 runner（[migrations_runner.go:118 applyMigrationsFS](backend/internal/repository/migrations_runner.go#L118)）成功路径**完全静默**——不会打"applied XXX.sql"这类日志，只在失败时返回 error。这是 by design：成功是常态，没必要刷日志。所以"日志里没看到"不能用来判断迁移有没有跑。

权威来源是 `schema_migrations` 表：runner 在事务内执行 SQL 后会 `INSERT INTO schema_migrations (filename, checksum)` 记录。

**步骤**：

1. 直接查迁移记录表：
   ```sql
   SELECT filename, checksum, applied_at
   FROM schema_migrations
   WHERE filename = '142_user_gifts.sql';
   ```
2. 查表结构是否真存在：
   ```sql
   \d user_gifts
   \d+ user_gifts
   SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'user_gifts';
   ```

**验证**：

- [ ] `schema_migrations` 有 `142_user_gifts.sql` 这一行；`applied_at` 是个合理的过去时间（首次启动后端的时刻）
- [ ] 字段：`id, user_id, amount, remaining, deduction_mode, ratio_recharge, expires_at, source, source_ref, status, created_at, updated_at`
- [ ] CHECK 约束：`amount > 0`、`remaining >= 0`、`deduction_mode IN ('priority','ratio')`、`status IN ('active','exhausted','expired','revoked')`、组合 CHECK（ratio 必须有正比例 / priority 必须无）
- [ ] 外键：`user_id → users(id)`
- [ ] 索引：`idx_user_gifts_user_active`、`idx_user_gifts_expiry_sweep`（均为部分索引，`indexdef` 末尾应有 `WHERE status = 'active'` 之类条件）

**注意**：你提到"SQL 执行成功 user_gifts 确认表存在，键值都正确"——配合 `schema_migrations` 里有 142 这行，就是迁移已成功跑过，状态正常。后端启动早期（在 `InitEnt` → `applyMigrationsFS` 阶段）就会跑迁移，可能在你接到第一个请求前已经悄悄跑完了。

### TC-1.2 迁移幂等

**机制说明**：runner 通过 `schema_migrations.filename` 主键判断已应用；checksum 字段记录文件 SHA256，启动时若文件被改过会**报错拒绝启动**（防篡改），未改则静默跳过。

**步骤**：

1. 重启后端进程
2. 确认 `schema_migrations.142_user_gifts.sql` 行的 `applied_at` **没变**（仍是首次启动那次的时间戳）
3. 后端无 panic、无 `migration ... checksum mismatch` 错误

**验证**：

- [ ] 重启后行为正确：表已存在但不会被重复创建，`applied_at` 时间戳不变
- [ ] **不要修改** `142_user_gifts.sql` 文件内容（哪怕一个空格），否则会触发 checksum mismatch 阻止启动；如需变更建表 schema，按规范新建 `143_xxx.sql`

---

## 2 · 发放路径测试

### TC-2.1 绑 key 赠送（修复 32df9534 污染）

**步骤**：

1. 准备一个普通用户 X，记录初始 `users.balance` 与 `users.total_recharged`（跑 Q1）
2. 在 admin 后台往池用户挂 1 笔可领取 key，配置 `gift_amount > 0`（如 5.00）
3. 用户 X 调 `POST /api/v1/bind-key/reserve` + `POST /api/v1/bind-key/commit` 完成绑定
4. 跑 Q1 + Q2

**验证**：

- [ ] `users.balance = 初始 + 5.00`
- [ ] **`users.total_recharged` 与初始**完全一致**（关键修复点：32df9534 之前会 +5.00，现在不动）
- [ ] `user_gifts` 多了一行：`amount=5, remaining=5, deduction_mode='priority', ratio_recharge=NULL, expires_at=NULL, source='keybind', status='active'`
- [ ] Q1 算式 `recharge_pool = total_balance - gift_balance` 与初始 `recharge_pool` 相等

### TC-2.2 OAuth 首登赠送

**前置**：admin 后台为某 provider（如 linuxdo）配置 `default_grants.balance > 0`，并保证测试账号未在 `user_provider_default_grants` 表里。

**步骤**：

1. 用一个全新邮箱注册 → 接着用同一账号绑 LinuxDo OAuth
2. 跑 Q1 + Q2 + 这条额外 SQL：
   ```sql
   SELECT * FROM user_provider_default_grants WHERE user_id = :user_id AND grant_reason = 'first_bind';
   ```

**验证**：

- [ ] `user_provider_default_grants` 多一行，避免重复发放
- [ ] `user_gifts` 多一行：`source='oauth_first_bind', deduction_mode='priority', remaining=配置值`
- [ ] `users.balance = 初始 + 配置值`，`total_recharged` 不变
- [ ] **再次绑同一 provider** 不应再发放：把 user_provider_default_grants 那行不删，重做 OAuth 绑定，确认 `user_gifts` 数量不变（幂等）

### TC-2.3 OAuth 首登 amount=0 不写记录

**前置**：admin 把某 provider 的 `default_grants.balance` 设为 0。

**步骤**：

1. 新邮箱注册 → 绑该 provider
2. 跑 Q2

**验证**：

- [ ] `user_gifts` **没有新行**（amount=0 在 Engine 入口早返回）
- [ ] `user_provider_default_grants` **仍有 first_bind 行**（grant 记录不影响）

### TC-2.4 优惠码赠送（带 expires_at + source_ref）

**前置**：admin 后台创建一个优惠码 P：`bonus_amount=10, expires_at=NOW()+30 days`。

**步骤**：

1. 用户 X 注册时填入 P，或调 `POST /api/v1/promo/apply` 类路径（具体 API 路径见现有实现）
2. 跑 Q2 + 这条 SQL：
   ```sql
   SELECT id, promo_code_id, user_id, bonus_amount FROM promo_code_usages
   WHERE user_id = :user_id ORDER BY id DESC LIMIT 1;
   ```

**验证**：

- [ ] `user_gifts` 多一行：`source='promo_code', amount=10, remaining=10, expires_at` 与优惠码一致
- [ ] `source_ref = 'promo_code:<promo_code.id>'`
- [ ] `users.balance` 增 10，`total_recharged` 不变
- [ ] **重复使用同一优惠码**应被 `promo_code_usages` 唯一约束拒绝（既有逻辑），`user_gifts` 不再增加

### TC-2.5 兑换码 / Affiliate / 管理员手动充值（保持现状）

按用户决策不走赠金。逐项验证：

- [ ] 兑换码 `type=balance` 兑换：`user_gifts` 不变，`balance + total_recharged` 同步增加
- [ ] Affiliate 联盟分润触发（构造引荐链路）：`user_gifts` 不变，`balance + total_recharged` 同步增加
- [ ] admin 后台 `POST /admin/users/:id/balance` 充值：`user_gifts` 不变，`balance + total_recharged` 同步增加

---

## 3 · 扣费分摊（核心算法）

### TC-3.1 纯 priority 扣费

**构造**：用户 X，初始 `recharge_pool=50`、1 笔 priority gift `remaining=20`，扣费 30。

构造方式（直接 SQL 或经发放路径）：

```sql
-- 假设管理员已充 50（balance=50, total_recharged=50, 无 gift）
-- 通过绑 key 或 promo 给用户增加 priority 20
-- 触发条件：用一个真实模型发起一次 API 请求，使该 key 的 actual_cost=30
```

**验证**（请求完成后跑 Q1 + Q2）：

- [ ] gift A `remaining = 0, status='exhausted'`
- [ ] `users.balance = 70 - 30 = 40`
- [ ] `recharge_pool = 50`（未动）
- [ ] `gift_balance = 0`

### TC-3.2 priority + recharge 联合扣

**构造**：`recharge_pool=50`、priority gift `remaining=20`，扣费 60。

**验证**：

- [ ] gift A `remaining=0, status='exhausted'`
- [ ] `users.balance = 10`
- [ ] `recharge_pool = 10`，`gift_balance = 0`

### TC-3.3 纯 ratio gift（2:1）扣 60

**构造**：`recharge_pool=70`、ratio gift `remaining=30, ratio_recharge=2.0`，扣费 60。

**预期算法**（与 [allocator_test.go:TestAllocate_PureRatio_2to1](backend/internal/gift/allocator_test.go#L66) 一致）：

- 阶段 2：T = min(60, 30·3/2=45, 70·3=210) = 45 → gift_part=30, recharge_part=15
- 阶段 3：剩 15 全压 recharge_pool

**验证**：

- [ ] gift B `remaining=0, status='exhausted'`
- [ ] `users.balance = 100 - 60 = 40`
- [ ] `recharge_pool = 70 - 15 - 15 = 40`
- [ ] `gift_balance = 0`

### TC-3.4 多笔 ratio：低比例先耗尽

**构造**：`recharge_pool=70`、gift A `remaining=10, r=0.5`、gift B `remaining=20, r=2.0`，扣费 30。

**验证**：

- [ ] gift A 全用尽（10 → 0, exhausted）
- [ ] gift B **未动**（20 → 20）
- [ ] `recharge_pool = 50`（70 − 20）
- [ ] 不变量：`balance = 50 + 20 = 70`

### TC-3.5 priority + ratio + recharge 混合（设计稿走查例）

**构造**：priority A=20, ratio B=30 (r=2.0), recharge=50, balance=100。扣 60。

**验证**：

- [ ] A `remaining=0, exhausted`
- [ ] B `remaining ≈ 30 - 26.67 = 3.33`（精确到 8 位小数）
- [ ] `users.balance = 40`
- [ ] 不变量：`balance = recharge_pool + B.remaining`

### TC-3.6 ratio 联动作废（充值池触底）

**构造**：`balance=20`、ratio A `remaining=10, r=2`、ratio B `remaining=5, r=3`。扣费 50。

**预期**（与 [TestAllocate_RatioRevokeWhenRechargeBottoms](backend/internal/gift/allocator_test.go#L143) 一致）：

- A 全扣（gift=10, recharge=5）后 recharge_pool=0
- B 在 stage 2 不能扣（cap_by_recharge=0）
- stage 3 剩 35 全压 → recharge_pool=−35（透支）
- 触底 → B 联动 revoke，`balance` 再扣 5

**验证**：

- [ ] A `status='exhausted', remaining=0`
- [ ] B `status='revoked', remaining=0`
- [ ] `users.balance = 20 - 50 - 5 = -35`（允许透支）
- [ ] 不变量仍守恒：`balance = recharge_pool + 0`，即 recharge_pool = -35

### TC-3.7 过期 gift 不参与扣费

**构造**：`balance=100`，gift A `remaining=20, expires_at=NOW()-1 hour`（过期但 status 仍 active 还没被 ticker 清理），扣费 30。

**验证**：

- [ ] gift A 不参与（lockedSnapshot 的 SQL 已过滤 `expires_at > NOW()`）
- [ ] `users.balance = 70`
- [ ] gift A 仍 active，等 ticker 清理（见 TC-6）

### TC-3.8 扣费 = 0 no-op

让一次请求返回 `actual_cost=0`（如订阅免费分组）。

- [ ] `user_gifts` 不变，`users.balance` 不变

---

## 4 · 退款透支保护（P1-N2 验证点）

### TC-4.1 退款只扣充值池

**构造**：

```
1. 管理员充值 100（balance=100, total_recharged=100, 无 gift）
2. promo 赠送 20（balance=120, gift A remaining=20）
3. 用户消费 5（balance=115，A 仍 20-5=15）
   实际：priority A 先吃 5 → A.remaining=15
4. 退款 100
```

**验证**：

- [ ] `BalanceToDeduct` 计算阶段 cap = 115 - 15 = 100，p.RefundAmount=100 → BalanceToDeduct=100
- [ ] 执行后 `users.balance = 115 - 100 = 15`
- [ ] gift A **不动**：`remaining=15, status='active'`
- [ ] 不变量：balance(15) = recharge_pool(0) + gift_balance(15)
- [ ] 审计日志 `REFUND_SUCCESS` 中 `balanceDeducted=100`（actualDeducted）

### TC-4.2 退款超过充值池：force=false 时实际只扣充值池

**构造**：充值 50，promo 赠 30（balance=80, gift=30, recharge_pool=50），消费 0。退款 80（设 force=true 通过早期校验）。

**验证**：

- [ ] 阶段 A 评估：`min(80, recharge_pool=50)=50` → BalanceToDeduct=50
- [ ] 阶段 B 执行：`DeductFromRechargePool(80)` 内部 cap=50 → actualDeducted=50
- [ ] 执行后 `users.balance = 30`，gift remaining=30 不变，recharge_pool=0
- [ ] 审计日志 `balanceDeducted=50`（不是 80）

### TC-4.3 评估到执行间并发扣费（手动构造）

**步骤**：

1. 充值 100，无 gift
2. 退款流程：第一步 `evaluateBalanceDeduction` 算出 cap=100 →  BalanceToDeduct=100
3. **在 admin 进入 `ExecuteRefund` 之前**，用同一用户跑一次 API 调用，actual_cost=30 → balance=70
4. ExecuteRefund 触发 `DeductFromRechargePool(100)`

**验证**：

- [ ] `DeductFromRechargePool` 内部 FOR UPDATE 重读 cap = 70（含赠金扣减后的真实充值池），返回 actualDeducted=70
- [ ] `users.balance = 0`（不是 -30，避免透支）
- [ ] 审计日志 `balanceDeducted=70`

### TC-4.4 retry 路径（hasAuditLog REFUND_ROLLBACK_FAILED）

**步骤**：

1. 构造一个 `REFUND_ROLLBACK_FAILED` 审计记录（可手动 INSERT 到 `payment_audit_logs`）
2. 重新触发 ExecuteRefund

**验证**：

- [ ] `BalanceToDeduct` 被改写为 0，跳过扣减（不会重复扣 recharge_pool）

---

## 5 · Profile API 拆分

### TC-5.1 GET /api/v1/user/profile 返回 gift / recharge

**构造**：随便造 balance=100, gift_balance=30 的用户。

```bash
curl -H "Authorization: Bearer <jwt>" http://localhost:8080/api/v1/user/profile | jq '{balance, gift_balance, recharge_balance}'
```

**验证**：

- [ ] `balance=100`, `gift_balance=30`, `recharge_balance=70`
- [ ] 老前端忽略新字段不报错（用浏览器实际测一次旧版本前端，或不带新字段的 client）

### TC-5.2 多笔 active gift 求和

**构造**：用户有 priority 5 + ratio 10 (r=1)（共 active 15）+ 1 笔 status='exhausted' 的 30。

**验证**：

- [ ] `gift_balance = 15`（exhausted 不计）
- [ ] `recharge_balance = balance - 15`

### TC-5.3 过期 gift 不计入

**构造**：1 笔 active gift `expires_at = NOW() - 1 day`，`remaining=10`。

**验证**：

- [ ] `gift_balance = 0`（API 用 `expires_at IS NULL OR expires_at > NOW()` 过滤）

### TC-5.4 失败降级

**手动构造**（可选）：把 PG 杀掉模拟引擎调用失败，再请求 profile。

- [ ] 接口仍返回 200（gift_balance/recharge_balance=0），不阻塞 profile 主体

---

## 6 · 过期清理 ticker

### TC-6.1 过期 gift 自动清理

**步骤**：

1. 直接 SQL 插入一笔过期赠金：
   ```sql
   -- 假设当前 user_id=42, balance=100
   INSERT INTO user_gifts (user_id, amount, remaining, deduction_mode, expires_at, source, status)
   VALUES (42, 20, 20, 'priority', NOW() - INTERVAL '1 minute', 'manual', 'active');
   UPDATE users SET balance = balance + 20 WHERE id = 42;
   ```
2. 跑 Q1：`balance=120, gift=20, recharge_pool=100`
3. 等 ≤ 10 分钟（默认 ticker 间隔）或重启后端立刻触发首轮 `runOnce`
4. 跑 Q1 + Q2

**验证**：

- [ ] gift `status='expired', remaining=0`
- [ ] `users.balance = 100`（自动减回 20）
- [ ] 后端日志包含 `[GiftExpirer] processed 1 users with expired gifts`
- [ ] 不变量守恒：balance(100) = recharge_pool(100) + 0

### TC-6.2 ticker 与并发扣费

**步骤**：

1. 构造用户 A 同时有：1 笔过期 gift（remaining=10）+ 1 笔 active priority（remaining=20）
2. ticker 触发的同一时刻发起扣费 5

**验证**：

- [ ] 不死锁（所有路径加锁顺序：先 users 后 user_gifts(id ASC)）
- [ ] 最终不变量守恒；过期那笔 expired，active 那笔被扣

### TC-6.3 没有过期赠金时 noop

- [ ] 等一个 tick 周期，日志不打 "processed N users"（仅在 N>0 时输出）

---

## 7 · 不变量与回归测试

### TC-7.1 不变量校验（每个 case 收尾必跑）

```sql
-- 全局不变量扫描
SELECT u.id, u.balance,
       COALESCE(SUM(CASE WHEN g.status='active'
                          AND (g.expires_at IS NULL OR g.expires_at > NOW())
                          THEN g.remaining END), 0) AS gift_sum
FROM users u
LEFT JOIN user_gifts g ON g.user_id = u.id
GROUP BY u.id
HAVING u.balance < COALESCE(SUM(CASE WHEN g.status='active'
                                      AND (g.expires_at IS NULL OR g.expires_at > NOW())
                                      THEN g.remaining END), 0);
```

- [ ] 上面查询应返回 **0 行**——任何 `balance < gift_sum` 都说明不变量被破坏

### TC-7.2 total_recharged 不再被赠金污染

```sql
-- 取若干测试用户
SELECT id, balance, total_recharged FROM users WHERE id IN (...);
```

- [ ] 验证 `total_recharged` 仅在管理员充值 / 兑换码 / affiliate 路径累加，绑 key / OAuth 首登 / promo 之后**完全不动**

### TC-7.3 既有非赠金路径无回归

- [ ] 普通 API 调用流程：扣费、订阅扣减、quota 推进，行为与本次改造前一致
- [ ] 充值订单完成：`total_recharged` 累加正常
- [ ] 订阅路径（`SubscriptionCost`）扣费：不进赠金引擎，`user_subscriptions.daily/weekly/monthly_usage_usd` 推进正常
- [ ] API key quota / rate limit / 账号 quota：行为与改造前一致

### TC-7.4 wire 注入完整性

- [ ] 启动后端，日志无 panic（`gift.NewEngine: entClient is nil` / `sqlDB is nil` 这类 panic 表示 wire 没注好）
- [ ] `keybind` 模块日志为 `feature enabled` 而不是 disabled

---

## 8 · 上线前的烟雾测试（最小集合）

如果时间紧，至少跑这 5 项：

- [ ] **TC-2.1** 绑 key 赠送 + 不污染 total_recharged
- [ ] **TC-3.5** priority + ratio + recharge 混合扣费
- [ ] **TC-3.6** ratio 联动作废
- [ ] **TC-4.1** 退款只扣充值池
- [ ] **TC-7.1** 不变量全局扫描

---

## 9 · 回滚预案

如果发现严重问题：

1. **关闭新发放路径**：把 [keybind/balance.go:NewGiftEngineUpdater](backend/internal/keybind/balance.go) 改回返回 nil，即"绑 key 不再发赠金"（key 仍能转移）
2. **revert 全部 commits**：本次改造按 phase 分提交，可分阶段回滚
3. **DROP TABLE user_gifts**：仅在彻底放弃时使用；之前 promo / OAuth / 绑 key 已发的赠金会丢失记账，但 `users.balance` 仍正确
4. **数据修复**：用 Q1 找出 `gift_sum > 0` 的用户，把 `users.balance -= gift_sum`，再 DROP 表

---

## 测试结果记录模板

| Case | 执行人 | 时间 | 结果 | 备注 |
|------|--------|------|------|------|
| TC-1.1 | | | | |
| TC-1.2 | | | | |
| TC-2.1 | | | | |
| TC-2.2 | | | | |
| TC-2.3 | | | | |
| TC-2.4 | | | | |
| TC-2.5 | | | | |
| TC-3.1 | | | | |
| TC-3.2 | | | | |
| TC-3.3 | | | | |
| TC-3.4 | | | | |
| TC-3.5 | | | | |
| TC-3.6 | | | | |
| TC-3.7 | | | | |
| TC-3.8 | | | | |
| TC-4.1 | | | | |
| TC-4.2 | | | | |
| TC-4.3 | | | | |
| TC-4.4 | | | | |
| TC-5.1 | | | | |
| TC-5.2 | | | | |
| TC-5.3 | | | | |
| TC-5.4 | | | | |
| TC-6.1 | | | | |
| TC-6.2 | | | | |
| TC-6.3 | | | | |
| TC-7.1 | | | | |
| TC-7.2 | | | | |
| TC-7.3 | | | | |
| TC-7.4 | | | | |
