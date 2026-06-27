# 赠金子系统 · 运维 API

外部独立的运维系统（如 [sub2api-ops](file:///home/chris/projects/sub2api-ops/)）通过这套 API 完成所有赠金账本和绑 key 配置的运营操作。本端不提供管理界面，全部通过 API 暴露能力。

## 1 · 鉴权

**复用现有 admin JWT 中间件**，无新引入鉴权方案。

### 获取 Token

调用现有登录接口：

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "..."
}
```

响应包含 `token`（JWT），运维系统持本地存储，按 TTL 自动刷新（或失效时重新登录）。

### 调用约定

所有运维 API 都挂在 `/api/v1/admin/ops/...`，统一加请求头：

```
Authorization: Bearer <jwt>
```

未授权或非管理员账号 → `401 Unauthorized`。

---

## 2 · 通用响应

### 成功

```json
{ "data": { ... } }
```

或：

```json
{ "data": [ ... ], "total": 123, "page": 1, "page_size": 50 }
```

### 错误

| HTTP | Body | 触发条件 |
|------|------|--------|
| 400 | `{"error": "..."}` | 参数缺失/格式错误/约束校验失败 |
| 401 | `{"error": "..."}` | 未登录 / token 失效 |
| 403 | `{"error": "..."}` | 非管理员 |
| 404 | `{"error": "..."}` | 资源不存在 |
| 409 | `{"error": "..."}` | 状态冲突（如撤销非 active 赠金） |
| 500 | `{"error": "..."}` | 服务端异常 |

---

## 3 · A. 表 A：bind-key 赠金配置

绑 key 时，系统先查 `bind_key_gift_settings` 表（按 `api_key_id`）：

- 命中 → 按行内的 `deduction_mode` / `ratio_recharge` / `expires_after_days` 发放
- 未命中 → 沿用默认（`deduction_mode=priority`、不过期）

⚠️ 表 A 与 `api_keys` **没有外键关联**：绑 key 后所有权转移给用户，配置生命周期由运维独立维护。删除 api_key 不会自动清理对应的 setting，需要运维定期清理。

### 3.1 · 创建 / 更新（Upsert）

```http
POST /api/v1/admin/ops/bind-key-gifts
Content-Type: application/json
Authorization: Bearer <jwt>

{
  "api_key_id":          12345,
  "deduction_mode":      "ratio",      // "priority" 或 "ratio"
  "ratio_recharge":      2.0,           // ratio 模式必填且 > 0；priority 模式必须省略
  "expires_after_days":  30             // 可选；NULL=永不过期，正数=赠金 expires_at = grant_time + N 天
}
```

行为：同 `api_key_id` 已存在 → 全字段覆盖；不存在 → 创建。

**响应**（200 OK）：

```json
{
  "data": {
    "id": 17,
    "api_key_id": 12345,
    "deduction_mode": "ratio",
    "ratio_recharge": 2.0,
    "expires_after_days": 30,
    "created_at": "2026-05-27T10:00:00Z",
    "updated_at": "2026-05-27T10:00:00Z"
  }
}
```

**校验规则**：

- `api_key_id > 0`
- `deduction_mode ∈ {"priority", "ratio"}`
- `ratio` 模式：`ratio_recharge` 必填且 > 0
- `priority` 模式：禁止携带 `ratio_recharge`
- `expires_after_days` 提供时必须 > 0

### 3.2 · 查单条

```http
GET /api/v1/admin/ops/bind-key-gifts/:api_key_id
```

未配置 → `404 Not Found`。

### 3.3 · 列表

```http
GET /api/v1/admin/ops/bind-key-gifts?page=1&page_size=50
```

`page_size` 默认 50，最大 200。按 `id DESC` 排序。

### 3.4 · 删除

```http
DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id
```

**响应**：

```json
{ "deleted": 1 }
```

---

## 4 · B. 赠金账本运维

### 4.1 · 任意 mode 发放赠金

给指定用户发一笔赠金，参数完全自由（`priority` / `ratio` / 任意过期时间）。

```http
POST /api/v1/admin/ops/gifts/grant
Content-Type: application/json

{
  "user_id":          7788,
  "amount":           100.0,
  "deduction_mode":   "priority",         // 或 "ratio"
  "ratio_recharge":   null,               // ratio 模式必填且 > 0
  "expires_at":       "2026-12-31T23:59:59Z",  // 可选；不填即永不过期
  "source":           "manual",           // 可选；缺省 "manual"
  "source_ref":       "ticket-456"        // 可选；用于审计
}
```

**响应**：

```json
{
  "data": {
    "id": 1024,
    "user_id": 7788,
    "amount": 100.0,
    "remaining": 100.0,
    "deduction_mode": "priority",
    "ratio_recharge": null,
    "expires_at": "2026-12-31T23:59:59Z",
    "source": "manual",
    "source_ref": "ticket-456",
    "status": "active",
    "created_at": "2026-05-27T10:00:00Z",
    "updated_at": "2026-05-27T10:00:00Z"
  }
}
```

**校验规则**：

- `amount > 0`
- `deduction_mode ∈ {"priority", "ratio"}`
- `ratio` 模式：`ratio_recharge` 必填且 > 0
- `priority` 模式：禁止携带 `ratio_recharge`
- `expires_at` 提供时必须是未来时间

发放成功后：`user_gifts` 写入新行（`status='active'`），`users.balance` 同步 `+amount`，但 **不动 `total_recharged`**。

### 4.2 · 列出某用户的赠金

```http
GET /api/v1/admin/ops/gifts?user_id=7788&status=active&page=1&page_size=50
```

`status` 取值（可选）：`active` / `exhausted` / `expired` / `revoked`。空字符串=不过滤。

返回结构同发放响应的 `data` 字段，外加分页。

### 4.3 · 查单笔

```http
GET /api/v1/admin/ops/gifts/:gift_id
```

不存在 → `404`。

### 4.4 · 撤销赠金

```http
POST /api/v1/admin/ops/gifts/:gift_id/revoke
Content-Type: application/json

{ "reason": "客户投诉重复发放" }
```

行为：事务内将 `status` 置 `revoked`、`remaining` 归 0，**同步从 `users.balance` 扣回剩余赠金额**。

- 仅 `active` 可撤销
- 非 `active` → `409 Conflict { "error": "gift is not active and cannot be revoked" }`
- `reason` 为可选字段（当前未持久化，预留给未来审计扩展）

**响应**：

```json
{ "revoked_id": 1024 }
```

### 4.5 · 给充值池增额（管理员手动充值）

```http
POST /api/v1/admin/ops/gifts/users/:user_id/recharge
Content-Type: application/json

{
  "amount": 50.0,            // 正数=充值（同步 + total_recharged），负数=扣减（仅扣 balance，不动 total_recharged）
  "notes":  "退款补偿"       // 可选
}
```

⚠️ **该接口直接走 `users.balance` 而非 `user_gifts`**，语义是"管理员真实充值/扣减"。如要发赠金请用 4.1。

**响应**：

```json
{ "user_id": 7788, "delta": 50.0 }
```

**校验**：`amount` 不能为 0。

---

## 5 · C. 用户余额拆分查询

```http
GET /api/v1/admin/ops/users/:user_id/balance
```

**响应**：

```json
{
  "user_id":            7788,
  "total_balance":      237.50,
  "gift_balance":       100.00,
  "recharge_balance":   137.50,
  "gift_expiring_soon": 50.00,
  "total_recharged":    500.00
}
```

字段说明：

- `total_balance` = `users.balance`（含赠金的总余额）
- `gift_balance` = `Σ(active gifts.remaining)`（未过期 active 赠金合计）
- `recharge_balance` = `total_balance - gift_balance`
- `gift_expiring_soon` = `gift_balance` 中 120 小时内即将过期的部分
- `total_recharged` = `users.total_recharged`

---

## 6 · 端点速查表

| Method | Path | 描述 |
|--------|------|------|
| POST | `/api/v1/admin/ops/bind-key-gifts` | 创建/更新表 A 配置 |
| GET | `/api/v1/admin/ops/bind-key-gifts` | 列表表 A |
| GET | `/api/v1/admin/ops/bind-key-gifts/:api_key_id` | 查表 A 单条 |
| DELETE | `/api/v1/admin/ops/bind-key-gifts/:api_key_id` | 删除表 A 单条 |
| POST | `/api/v1/admin/ops/gifts/grant` | 任意 mode 发赠金 |
| GET | `/api/v1/admin/ops/gifts` | 列出用户赠金（query: user_id, status） |
| GET | `/api/v1/admin/ops/gifts/:gift_id` | 查单笔赠金 |
| POST | `/api/v1/admin/ops/gifts/:gift_id/revoke` | 撤销赠金 |
| POST | `/api/v1/admin/ops/gifts/users/:user_id/recharge` | 给充值池增额 |
| GET | `/api/v1/admin/ops/users/:user_id/balance` | 用户余额拆分查询 |

---

## 7 · 集成示例（伪代码）

```python
import requests, time

BASE = "https://api.example.com"
TOKEN = login()  # 缓存 + 自动刷新

def grant_gift(user_id, amount, mode="priority", ratio=None, days=None, source="manual"):
    expires_at = None
    if days:
        expires_at = (time.time() + days*86400)  # 转 RFC3339
    body = {"user_id": user_id, "amount": amount, "deduction_mode": mode, "source": source}
    if ratio is not None:
        body["ratio_recharge"] = ratio
    if expires_at:
        body["expires_at"] = expires_at
    r = requests.post(f"{BASE}/api/v1/admin/ops/gifts/grant",
                      json=body,
                      headers={"Authorization": f"Bearer {TOKEN}"})
    r.raise_for_status()
    return r.json()["data"]
```

---

## 8 · 不变量与审计

- `users.balance ≡ recharge_pool + Σ(active gifts.remaining)` — 引擎保证
- 发放/撤销/扣费均在事务内完成，不会出现中间态
- `gift_expiring_soon` 阈值常量 `GiftExpiringSoonThreshold = 120 * time.Hour` 定义在 [internal/gift/engine.go](backend/internal/gift/engine.go)，如需调整改为可配再说
- ratio gift 联动作废：当 `recharge_pool ≤ 0` 时，所有 active ratio gift 一起置 `revoked`，从 balance 同步扣回剩余 — 这部分 **不算** 用户消费（不写 usage_log）
- 关键操作 metrics（Prometheus）：`gift_grant_total{source}` / `gift_revoked_total` / `gift_expired_total` / `gift_consumed_total{deduction_mode}`
