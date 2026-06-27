# 赠金子系统 Phase 3 测试计划

## 0 · 背景

Phase 3 已实施完毕，覆盖四块能力：

1. **绑 key 赠金参数表 A**（[backend/migrations/143_bind_key_gift_settings.sql](../../backend/migrations/143_bind_key_gift_settings.sql)）
2. **usage_logs 拆分 gift_cost / recharge_cost**（[backend/migrations/144_usage_log_gift_breakdown.sql](../../backend/migrations/144_usage_log_gift_breakdown.sql)）
3. **运维 API**（[backend/internal/handler/admin/gift_ops_handler.go](../../backend/internal/handler/admin/gift_ops_handler.go)）共 9 个端点，挂在 `/api/v1/admin/ops/*`
4. **Profile UI 展示赠金**（[ProfileInfoCard.vue](../../frontend/src/components/user/profile/ProfileInfoCard.vue) + [UsageView.vue](../../frontend/src/views/user/UsageView.vue)）

测试目标：在不上线灰度的硬切换前提下，确保功能正确、契约稳定、不变量守恒。

---

## 1 · 全局不变量（每条都要在测试里断言）

| # | 不变量 | 验证位置 |
|---|--------|----------|
| I1 | `users.balance ≡ recharge_pool + Σ(active gifts.remaining)` | 单元 + 集成 + 对账 |
| I2 | `usage_logs.gift_cost + usage_logs.recharge_cost = usage_logs.actual_cost`（按量路径） | 单元 + E2E |
| I3 | `Σ(GiftDeltas) + RechargeDelta ≡ TotalCost`（联动作废前的算法层） | 单元（已存在 [allocator_test.go:10 assertConservation](../../backend/internal/gift/allocator_test.go#L10)） |
| I4 | `0 ≤ gift_expiring_soon ≤ gift_balance` | 单元 + Profile API 集成 |
| I5 | 表 A 行：`(mode='priority' AND ratio_recharge IS NULL) OR (mode='ratio' AND ratio_recharge > 0)` | 集成（CHECK 约束验证） |
| I6 | `bind_key_gift_settings.api_key_id` 唯一 | 集成（重复 upsert 不报 23505） |
| I7 | `RevokeGift` 仅对 active 生效，其他状态返回 [ErrGiftNotRevocable](../../backend/internal/gift/engine.go#L251) → HTTP 409 | 单元 + handler 测试 |

---

## 2 · 后端单元测试

### 2.1 `gift.Engine.AllocateAndDeductWithBreakdown`

新增 [backend/internal/gift/engine_breakdown_test.go](../../backend/internal/gift/engine_breakdown_test.go)，构造内存 sqlmock 或复用集成测试 fixture（更稳）。验证 `breakdown.GiftCost / RechargeCost` 与 `Allocate` 纯函数一致。

表驱动覆盖（11 个用例）：

| # | 场景 | 期望 GiftCost | 期望 RechargeCost |
|---|------|-------------:|------------------:|
| 1 | totalCost=0 | 0 | 0 |
| 2 | 纯 priority，赠金充裕 | totalCost | 0 |
| 3 | 纯 priority，赠金不足，余款充值池吃 | gift.Remaining | totalCost - gift.Remaining |
| 4 | 纯 ratio (r=2.0)，赠金/充值都充裕 | T·r/(1+r) | T/(1+r) |
| 5 | 纯 ratio，cap_by_gift 触发（赠金不够大） | gift.Remaining | gift.Remaining/r |
| 6 | priority + ratio + recharge 混合（计划稿走查例） | 见 [wobbly-herding-waffle.md:300](wobbly-herding-waffle.md) | 同左 |
| 7 | 多笔 priority（按 id ASC tie-break），逐个吃透 | Σ priority remaining | totalCost - 上 |
| 8 | 多笔 ratio，比例小者先扣 | 按算法 | 按算法 |
| 9 | 联动作废触发：rechargePool ≤ 0 + 仍有 ratio active | breakdown 不含被作废的 RevokedRemaining | 充值池减量 |
| 10 | 极小值 1e-8（精度收口验证 `decimal.Equal`） | 严格相等 | 严格相等 |
| 11 | 过期赠金不参与（lockedSnapshot 已过滤） | 只算 active | 同 |

**关键决策回归**：用例 9 必须断言 `breakdown.GiftCost` 不含 `RevokedRemaining`（[engine.go:75](../../backend/internal/gift/engine.go#L75) 注释明示）。

### 2.2 `gift.Engine` 其他方法

新增 [backend/internal/gift/engine_ops_test.go](../../backend/internal/gift/engine_ops_test.go)：

- `RevokeGift`：active gift 撤销成功 → status=revoked, remaining=0, users.balance 减原 remaining；非 active（exhausted/expired/revoked）返回 `ErrGiftNotRevocable`
- `RevokeGift(giftID=0)` → "must be positive" 错误（[engine.go:222](../../backend/internal/gift/engine.go#L222)）
- `GetGiftBalanceBreakdown`：构造 3 笔 active 赠金，1 笔 < 120h 过期，2 笔无过期或 > 120h；断言 `expiringSoon` 只覆盖第 1 笔
- `GetGiftBalanceBreakdown` 边界：阈值正好等于 120h 的赠金不算入 expiringSoon（SQL 是 `< NOW() + 120h`，[engine.go:213](../../backend/internal/gift/engine.go#L213)）
- `ListGiftsByUser`：page=0/pageSize=0 走默认；pageSize > 200 截到 200（[engine.go:236](../../backend/internal/gift/engine.go#L236)）
- `ListGiftsByUser` 按 status 过滤：`""` 全量，`"active"`/`"revoked"`/`"expired"` 各自命中
- `GetGiftByID(0)` → "must be positive"

### 2.3 `keybind.giftEngineUpdater.GrantForBindKey`

新增 [backend/internal/keybind/balance_test.go](../../backend/internal/keybind/balance_test.go)，用 mock resolver + 真 gift.Engine（连测试 PG）：

| 场景 | resolver 返回 | 期望 user_gifts 行 |
|------|---------------|--------------------|
| amount ≤ 0 | — | 早返回，无写入 |
| resolver=nil | — | priority + 永不过期 + source=keybind + source_ref="api_key:N" |
| resolver 返回 nil（表中无行） | nil, nil | 同上（[balance.go:94](../../backend/internal/keybind/balance.go#L94)） |
| resolver 返回 priority + days=7 | `{Mode:priority, ExpiresAfterDays:7}` | priority, expires_at ≈ now+7d |
| resolver 返回 ratio + ratio_recharge=2.0 | `{Mode:ratio, RatioRecharge:&2.0}` | ratio, ratio_recharge=2.0 |
| resolver 返回错误 | err | 透传 err，不发放 |

### 2.4 `keybind.entBindKeyGiftSettingResolver`

新增 [backend/internal/keybind/gift_settings_repo_test.go](../../backend/internal/keybind/gift_settings_repo_test.go)：

- 表中有匹配行 → 返回完整 `BindKeyGiftSetting`，字段映射正确
- 表中无行 → `(nil, nil)`（[gift_settings_repo.go:49](../../backend/internal/keybind/gift_settings_repo.go#L49)）
- 表中行的 `deduction_mode` 是未知字符串 → 返回 "unknown deduction_mode" 错误（[gift_settings_repo.go:57](../../backend/internal/keybind/gift_settings_repo.go#L57) 防御）
- client=nil → `(nil, nil)`（[gift_settings_repo.go:42](../../backend/internal/keybind/gift_settings_repo.go#L42)）

### 2.5 `admin.GiftOpsHandler` 校验分支（不依赖 DB）

用 `httptest` + gin engine 直挂 handler，跳过 admin 中间件，覆盖 [validateBindKeyGiftPayload](../../backend/internal/handler/admin/gift_ops_handler.go#L388) 与 GrantGift inline 校验：

| 入参 | 期望 |
|------|------|
| `{api_key_id:0}` upsert | 400 "api_key_id must be positive" |
| `{deduction_mode:"foo"}` upsert | 400 "must be priority or ratio" |
| priority + ratio_recharge=非nil | 400 "must not include ratio_recharge" |
| ratio + ratio_recharge=nil | 400 "requires positive ratio_recharge" |
| ratio + ratio_recharge=0 | 400 同上 |
| priority + expires_after_days=0 | 400 "must be positive when provided" |
| GrantGift amount=0 | 400 "amount must be > 0" |
| GrantGift expires_at 在过去 | 400 "expires_at must be in the future" |
| RechargeUser amount=0 | 400 "amount must not be zero" |
| `:gift_id` 非数字 | 400 "invalid gift_id" |
| `:user_id` 非数字 | 400 "invalid user_id" |

---

## 3 · 后端集成测试（真 PG）

### 3.1 表 A 数据库约束

新增 [backend/internal/keybind/gift_settings_integration_test.go](../../backend/internal/keybind/gift_settings_integration_test.go)（或并入 `gift_settings_repo_test.go` 的真 DB 部分）：

- INSERT priority + ratio_recharge=NULL → 成功
- INSERT priority + ratio_recharge=1.0 → 触发 `bind_key_gift_settings_mode_ratio_check`，PG 返回 23514
- INSERT ratio + ratio_recharge=NULL → 同上失败
- INSERT ratio + ratio_recharge=0 → 失败（CHECK > 0）
- INSERT 重复 api_key_id → UNIQUE 约束 23505；upsert handler 走 update 分支不报错
- INSERT expires_after_days=-1 → CHECK 失败（[143.sql:11](../../backend/migrations/143_bind_key_gift_settings.sql#L11)）
- INSERT expires_after_days=0 → 同上失败

### 3.2 运维 API 端到端（gin test server + admin JWT）

新增 [backend/internal/handler/admin/gift_ops_integration_test.go](../../backend/internal/handler/admin/gift_ops_integration_test.go)。复用 [wire_gen_test.go](../../backend/cmd/server/wire_gen_test.go) 注入完整依赖；admin token 通过 `/api/v1/auth/login` 用测试管理员账号取得。

#### A. 表 A 配置端点

- `POST /api/v1/admin/ops/bind-key-gifts` 创建 → 200，DB 行存在
- 同 api_key_id 再次 POST → 200，DB 仍 1 行，字段被覆盖（验证 upsert 走 update 分支）
- `GET /:api_key_id` 命中 → 200 + 字段一致；不命中 → 404
- `GET /` 分页：插 60 行 → `?page=1&page_size=50` 返回 50 + total=60；`page_size=300` 截到 200
- `DELETE /:api_key_id` → 200 `{deleted:1}`；再次 DELETE → 200 `{deleted:0}`

#### B. 赠金账本端点

- `POST /gifts/grant` priority → 200，user_gifts 行 mode='priority', remaining=amount, balance += amount
- `POST /gifts/grant` ratio + ratio_recharge=2.0 → 同上 + ratio_recharge 落库
- `POST /gifts/grant` source 留空 → 默认 "manual"（[gift_ops_handler.go:233](../../backend/internal/handler/admin/gift_ops_handler.go#L233)）
- `POST /gifts/grant` expires_at 未来时间 → 落库；过去时间 → 400
- `GET /gifts?user_id=X` 不带 status → 全量；带 `status=active` → 只返回 active
- `GET /gifts/:gift_id` 命中/不命中 → 200/404
- `POST /gifts/:gift_id/revoke` active 赠金 → 200 + 状态变 revoked + balance 同步减
- 同上对已 revoked 的赠金再调一次 → 409 + `ErrGiftNotRevocable` message
- `POST /gifts/users/:user_id/recharge` amount=10 → balance +10 + total_recharged +10
- `POST /gifts/users/:user_id/recharge` amount=-5 → balance -5 + total_recharged 不变

#### C. 用户余额查询

- `GET /users/:user_id/balance` → 返回 `{total_balance, gift_balance, recharge_balance, gift_expiring_soon, total_recharged}`
- 构造 1 笔 < 120h 到期赠金 + 1 笔无期 + recharge_pool 充值 → 四个字段值与不变量 I1+I4 一致

#### D. 鉴权

- 不带 token 调任意 ops 端点 → 401
- 普通用户 token 调 → 403（admin_auth 中间件，由 [admin.go:18](../../backend/internal/server/routes/admin.go#L18) 全局挂载）

### 3.3 usage_billing_repo → usage_logs 端到端

新增（或扩展）[backend/internal/repository/usage_billing_repo_integration_test.go](../../backend/internal/repository/usage_billing_repo_integration_test.go) 用例：

- 用户有 1 笔 priority gift = $0.05 + recharge_pool = $0.10；扣费 $0.08 → usage_logs 行 `gift_cost=0.05, recharge_cost=0.03, actual_cost=0.08`
- 同上扣费 $0.03 → `gift_cost=0.03, recharge_cost=0`
- 用户无赠金 → `gift_cost=0, recharge_cost=actual_cost`
- 订阅扣费路径（不进 gift engine）→ 历史行为：`gift_cost=0, recharge_cost=0`（DEFAULT 兜底，[144.sql:7](../../backend/migrations/144_usage_log_gift_breakdown.sql#L7)）
- 不变量 I2 在每条用例终点断言

---

## 4 · 前端验证清单（手工 + 可选 component test）

### 4.1 ProfileInfoCard

[frontend/src/components/user/profile/ProfileInfoCard.vue:61-95](../../frontend/src/components/user/profile/ProfileInfoCard.vue#L61-L95) 的三个分支：

| 状态 | 期望 |
|------|------|
| `gift_balance == 0` | 赠金行隐藏（v-if 不渲染 `data-testid="profile-overview-metric-gift-balance"`） |
| `gift_balance > 0, gift_expiring_soon == 0` | 显示金色一行 "赠金 $X.XX"，无橙色尾巴 |
| `gift_balance > 0, gift_expiring_soon > 0` | 显示金色 + 橙色 "(其中 $Y.YY 即将过期)" |

i18n 双语校验：[en.ts:1140-1141](../../frontend/src/i18n/locales/en.ts#L1140-L1141) 与 [zh.ts:1144-1145](../../frontend/src/i18n/locales/zh.ts#L1144-L1145) 文案 key 与组件中的 `t('profile.giftBalance')` / `t('profile.giftExpiringSoonHint')` 对齐，参数 `{amount}` 插值正确。

### 4.2 UsageView 列表 + Tooltip

[frontend/src/views/user/UsageView.vue:305-308](../../frontend/src/views/user/UsageView.vue#L305-L308)（列表行）+ [行 540-552](../../frontend/src/views/user/UsageView.vue#L540) 的 tooltip：

| 数据 | 列表行期望 | tooltip 期望 |
|------|------------|--------------|
| `gift_cost > 0, recharge_cost > 0` | 主数字 actual_cost + 下方小字 "赠金扣减 $X" | 出现两行 "赠金扣减" + "充值扣减" |
| `gift_cost > 0, recharge_cost == 0` | 同上小字 | 同上（recharge_cost 用 `\|\| 0` 兜底） |
| `gift_cost == 0` | 不渲染小字（v-if 守卫） | 不渲染该 section（[UsageView.vue:540 v-if](../../frontend/src/views/user/UsageView.vue#L540)） |
| `gift_cost` 字段缺失（老后端） | 不渲染（`row.gift_cost && row.gift_cost > 0`） | 同上 |

i18n 校验：`usage.giftDeducted` 在 [en.ts:919](../../frontend/src/i18n/locales/en.ts#L919) "Gift used" / [zh.ts:923](../../frontend/src/i18n/locales/zh.ts#L923) "赠金扣减"。

### 4.3 TS 类型回归

[frontend/src/types/index.ts:88](../../frontend/src/types/index.ts#L88) 的 `User` 与 `UsageLog` 类型必须包含可选字段：

- `User.gift_balance?: number`
- `User.recharge_balance?: number`
- `User.gift_expiring_soon?: number`
- `UsageLog.gift_cost?: number`
- `UsageLog.recharge_cost?: number`

跑 `npm run build` 或 `vue-tsc --noEmit`，0 errors。

---

## 5 · 端到端冒烟（上线前必跑一次，上线后再复跑）

> 顺序固定，跑一次约 5 分钟。任一步失败立即阻止上线。

1. **建表 A 配置**
   ```bash
   curl -X POST .../api/v1/admin/ops/bind-key-gifts \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"api_key_id":<test_pool_key_id>,"deduction_mode":"ratio","ratio_recharge":2.0,"expires_after_days":7}'
   ```
   预期：200，DB `bind_key_gift_settings` 1 行。

2. **新用户绑 key**（走 `BindKeyView` 全流程）
   - 登录测试账号 → 输入兑换码 → 提交
   - 后端日志：`giftEngineUpdater.GrantForBindKey` 命中表 A
   - DB `user_gifts` 行：`mode='ratio', ratio_recharge=2.0, expires_at ≈ now+7d, source='keybind', source_ref='api_key:<id>'`

3. **跑一次按量计费 API**
   - 用刚绑的 key 调 `/v1/chat/completions` 一次
   - DB `usage_logs` 行：`gift_cost > 0, recharge_cost > 0, gift_cost + recharge_cost = actual_cost`

4. **Profile API 拆分**
   ```bash
   curl .../api/v1/user/profile -H "Authorization: Bearer $USER_JWT"
   ```
   预期返回包含 `gift_balance`, `recharge_balance`, `gift_expiring_soon`，不变量 I1 / I4 成立。

5. **前端 Profile 页**：刷新页面，赠金行显示金色 "赠金 $X.XX (其中 $Y.YY 即将过期)"。

6. **前端 Usage 页**：本次记录列表显示 actual_cost + 小字赠金扣减；hover tooltip 含 "赠金扣减/充值扣减" 两行。

7. **运维侧撤销**
   ```bash
   curl -X POST .../api/v1/admin/ops/gifts/<gift_id>/revoke \
     -H "Authorization: Bearer $ADMIN_JWT" -d '{"reason":"e2e test"}'
   ```
   预期：200，DB `user_gifts.status='revoked', remaining=0`，`users.balance` 同步减。

8. **联动作废路径**（构造场景）
   - admin 给用户发 1 笔 ratio gift remaining=$10, ratio_recharge=2.0
   - admin 把 recharge_pool 调到刚好 $1
   - 用户跑一次大额 API（`actual_cost=$5`）
   - 结果：recharge_pool 触底 → 该 ratio gift 自动 revoke，剩余 remaining 同步从 balance 扣
   - 注意：`usage_logs.gift_cost` 不含 RevokedRemaining（设计决策）

---

## 6 · 回归保护

### 6.1 不变量对账（每天定时跑一次）

直连 DB 跑：

```sql
-- I1 守恒：所有用户 balance 与 recharge_pool + gift_pool 是否一致
SELECT u.id, u.balance,
       COALESCE(SUM(g.remaining), 0) AS gift_pool,
       u.balance - COALESCE(SUM(g.remaining), 0) AS recharge_pool
FROM users u
LEFT JOIN user_gifts g ON g.user_id = u.id
  AND g.status = 'active'
  AND (g.expires_at IS NULL OR g.expires_at > NOW())
GROUP BY u.id, u.balance
HAVING u.balance < COALESCE(SUM(g.remaining), 0);  -- 这种行说明 recharge_pool 为负到不合理程度
```

```sql
-- I2 守恒：usage_logs 字段守恒（按量路径）
SELECT id, actual_cost, gift_cost, recharge_cost
FROM usage_logs
WHERE billing_type = 0
   AND created_at>='2026-05-28 13:33:11.645531+00'
  AND ABS(actual_cost - gift_cost - recharge_cost) > 0.000001
LIMIT 100;
-- 订阅路径
SELECT id, actual_cost, gift_cost, recharge_cost
FROM usage_logs
WHERE billing_type = 1
   AND created_at>='2026-05-28 13:33:11.645531+00'
  AND ABS(actual_cost - gift_cost - recharge_cost) > 0.000001
LIMIT 100;
```

任一查询返回非空 → 触发告警，由对账任务（[wobbly-herding-waffle.md:516](wobbly-herding-waffle.md) 修订 P2-7）记 metrics `gift_invariant_mismatch_total`。

### 6.2 兼容性

- **老前端（不识别新字段）**：`gift_balance` / `gift_cost` 等是 JSON 叠加字段，`UserResponse.Balance` 语义不变；老前端展示与改造前一致 → 在测试环境部署一份 Phase 2 版本前端 + Phase 3 后端，跑核心路径回归通过
- **历史 usage_logs 行**：`gift_cost / recharge_cost = 0`（DEFAULT 落库）→ 前端 `v-if="row.gift_cost > 0"` 自动跳过，不影响展示

---

## 7 · 优先级与跑测顺序

| 优先级 | 项 | 阻塞上线？ |
|--------|----|------------|
| P0 | 单元 2.1 + 集成 3.3（算法 + 写库守恒） | 是 |
| P0 | 集成 3.2 鉴权 + 撤销/CRUD 主路径 | 是 |
| P0 | 端到端冒烟 §5 全流程 | 是 |
| P1 | 单元 2.2~2.5 其余 case | 否 |
| P1 | 集成 3.1 表 A 约束 | 否 |
| P1 | 前端 §4 三类分支 | 否（但上线前手测一遍） |
| P2 | 不变量对账 §6.1 上线脚本 | 否（上线后 24h 内挂上） |

---

## 8 · 工时估算

| 类别 | 工时 |
|------|------|
| 单元测试 (2.1~2.5) | 0.5 day |
| 集成测试 (3.1~3.3) | 1 day |
| 前端手测 + i18n 校验 | 0.25 day |
| E2E 冒烟脚本（curl + 断言） | 0.25 day |
| 对账 SQL + 接入 metrics | 0.25 day |
| **合计** | **~2.25 day** |
