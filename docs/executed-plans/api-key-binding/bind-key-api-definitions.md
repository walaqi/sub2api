# Bind-Key API 定义（供外部系统参考）

本文件描述 `/bind-key` 功能的全部 HTTP 接口，包括面向终端用户的领取流程接口，以及供外部
运维系统远程调用的管理接口（赠金配置 + 注册时间窗口）。

> 适用版本：包含「注册时间窗口（per-key）」改动的版本。
> 所有路径基于 API 前缀 `/api/v1`。

---

## 0. 通用约定

### 0.1 两套响应信封

本功能涉及两类 handler，**响应信封格式不同**，对接时需区分：

**A. 用户态 keybind 接口**（`reserve` / `commit` / `eligibility`）——统一信封：

成功：
```json
{ "code": 0, "message": "success", "data": { ... } }
```
失败：
```json
{ "code": 403, "message": "you have already bound a key this month",
  "reason": "BIND_KEY_ALREADY_PARTICIPATED", "metadata": { ... } }
```
- `code`：成功固定为 `0`；失败为 HTTP 状态码（如 400/401/403/404/409/503）。
- `reason`：稳定的机器可读错误码（外部系统应据此分支，而非匹配 `message`）。
- `metadata`：可选的结构化补充字段，值均为字符串。

**B. 运维态管理接口**（`admin/ops/bind-key-gifts/*`）——裸 `data` 信封：

成功（读/写）：
```json
{ "data": { ... } }
```
列表：
```json
{ "data": [ ... ], "total": 12, "page": 1, "page_size": 50 }
```
删除：
```json
{ "deleted": 1 }
```
失败（经统一错误信封）：
```json
{ "code": 400, "message": "max_days must be >= min_days", "reason": "" }
```
> 注意：管理接口的**参数校验错误**走 `response.BadRequest`，`reason` 为空字符串，
> 仅 `message` 有内容；对接时以 HTTP 状态码 + `message` 判断。

### 0.2 鉴权

| 接口类别 | 鉴权方式 | Header |
|---|---|---|
| `POST /bind-key/reserve` | 无（公开） | — |
| `POST /bind-key/commit` | 用户 JWT | `Authorization: Bearer <jwt>` |
| `GET /bind-key/eligibility` | 用户 JWT | `Authorization: Bearer <jwt>` |
| `*/admin/ops/bind-key-gifts/*` | 管理员 | `x-api-key: <admin-api-key>` 或 `Authorization: Bearer <admin-jwt>` |

管理接口二选一：
1. **Admin API Key**：`x-api-key: <admin-api-key>`（推荐外部系统使用，长期凭证）。
2. **Admin JWT**：`Authorization: Bearer <jwt>`（需账号为管理员角色）。

鉴权失败统一返回 `401`：
```json
{ "code": 401, "message": "Invalid admin API key", "reason": "INVALID_ADMIN_KEY" }
```

---

## 1. 用户态接口：领取流程

领取分两步：`reserve`（占位锁定一个池 key，公开）→ `commit`（登录后完成所有权转移）。
`eligibility` 用于进入页面时预检资格。

### 1.1 POST /api/v1/bind-key/reserve

从输入的 key 列表中，自上而下选出**第一个**满足条件的池 key 并锁定 5 分钟。无需登录。

条件：属于池用户、`status=active`、未软删除、剩余配额 > 50%、未被其它预留锁定。

**请求体**
```json
{ "keys": ["sk-xxxxxxxxxxxx", "sk-yyyyyyyyyyyy"] }
```
| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `keys` | `string[]` | 是 | 候选 key 明文，单次最多 50 个；自动去重、去空白。 |

**成功响应 `200`**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "reservation_id": "a1b2c3...（48 hex）",
    "masked_key": "sk-************wxyz",
    "remaining_quota": 8.0,
    "quota_limit": 10.0,
    "expires_at_unix_ms": 1717300000000
  }
}
```
| 字段 | 类型 | 说明 |
|---|---|---|
| `reservation_id` | string | 预留 ID，提交时回传。 |
| `masked_key` | string | 脱敏后的 key（保留前缀与末 4 位）。 |
| `remaining_quota` | number | 该 key 剩余配额（USD）。 |
| `quota_limit` | number | 该 key 配额上限（USD），`0` 表示无限。 |
| `expires_at_unix_ms` | number | 预留过期时间（epoch 毫秒），约 5 分钟后。 |

**错误**
| HTTP | reason | 含义 |
|---|---|---|
| 400 | （空 reason，`message`=invalid request…） | 请求体非法 JSON。 |
| 400 | `BIND_KEY_EMPTY` | `keys` 为空。 |
| 400 | `BIND_KEY_TOO_MANY` | `keys` 超过 50 个。 |
| 404 | `BIND_KEY_NO_ELIGIBLE` | 列表中没有可领取的 key。 |
| 503 | `BIND_KEY_DISABLED` | 功能未配置（池用户未设置）。 |

> `reserve` **不做**月度限制与注册窗口校验（匿名阶段无用户身份）；这些在 `commit` 强制。

---

### 1.2 POST /api/v1/bind-key/commit

把预留的 key 所有权转移到当前登录用户，并按 per-key 配置发放赠金。需要 JWT。

**请求头**：`Authorization: Bearer <jwt>`

**请求体**
```json
{ "reservation_id": "a1b2c3..." }
```

**成功响应 `200`**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "api_key_id": 12345,
    "masked_key": "sk-************wxyz",
    "gift": {
      "amount": 8.0,
      "deduction_mode": "priority",
      "ratio_recharge": null,
      "expires_at_unix_ms": 1719892000000
    }
  }
}
```
| 字段 | 类型 | 说明 |
|---|---|---|
| `api_key_id` | number | 绑定后 key 的 ID。 |
| `masked_key` | string | 脱敏 key；降级场景可能为空串。 |
| `gift` | object \| 省略 | 本次发放的赠金详情；未发放（无配置/`quota=0`/失败）时**省略**该字段。 |
| `gift.amount` | number | 赠金金额（USD）。 |
| `gift.deduction_mode` | string | `priority`（优先扣赠金）或 `ratio`（按比例与充值同扣）。 |
| `gift.ratio_recharge` | number \| null | 仅 `ratio` 模式有值；每消耗 1 单位，充值占 `1/(1+r)`、赠金占 `r/(1+r)`。 |
| `gift.expires_at_unix_ms` | number \| 省略 | 赠金过期时间（epoch 毫秒）；永不过期时省略。 |

**错误**
| HTTP | reason | 含义 | metadata |
|---|---|---|---|
| 401 | `BIND_KEY_NO_USER` | 未携带有效 JWT / 用户身份缺失。 | — |
| 404 | `BIND_KEY_RESERVATION_EXPIRED` | 预留不存在或已过期。 | — |
| 409 | `BIND_KEY_RACE` | key 在 reserve 与 commit 之间被他人领走/失效。 | — |
| 403 | `BIND_KEY_ALREADY_PARTICIPATED` | 本自然月已领取过一次。 | — |
| 403 | `BIND_KEY_REGISTRATION_WINDOW` | 账号注册时间不在该 key 允许的窗口内。 | `min_days`, `max_days` |
| 503 | `BIND_KEY_DISABLED` | 功能未配置。 | — |

**`BIND_KEY_REGISTRATION_WINDOW` 错误示例**
```json
{
  "code": 403,
  "message": "your account registration date is outside the allowed window for this key",
  "reason": "BIND_KEY_REGISTRATION_WINDOW",
  "metadata": { "min_days": "0", "max_days": "30" }
}
```
> `metadata.min_days` / `max_days` 为**字符串**形式的整数，前端据此渲染「需注册满 X 天且不超过 Y 天」。

**校验顺序**（commit 内部，自上而下，命中即返回）：
1. JWT / 用户身份 → `BIND_KEY_NO_USER`
2. 预留有效性 → `BIND_KEY_RESERVATION_EXPIRED`
3. 月度限制 → `BIND_KEY_ALREADY_PARTICIPATED`
4. 注册时间窗口（per-key）→ `BIND_KEY_REGISTRATION_WINDOW`
5. key 所有权转移（TOCTOU 守卫）→ 失败则 `BIND_KEY_RACE`
6. 发放赠金（宽松失败，不影响 key 转移）

---

### 1.3 GET /api/v1/bind-key/eligibility

进入页面时预检当前用户**本月**是否还有资格。需要 JWT。

> ⚠ 该接口**不**预检 per-key 注册时间窗口——窗口依赖具体选中的 key，只能在 `commit` 阶段判定。
> 外部系统若需在选 key 前提示窗口，请改用 `GET /admin/ops/bind-key-gifts/:api_key_id` 读取该 key 的窗口配置。

**请求头**：`Authorization: Bearer <jwt>`

**成功响应 `200`**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "eligible": true,
    "already_participated": false,
    "next_reset_unix_ms": 1719792000000,
    "reason": ""
  }
}
```
| 字段 | 类型 | 说明 |
|---|---|---|
| `eligible` | bool | 本月是否可参与。 |
| `already_participated` | bool | 本月是否已领取过。 |
| `next_reset_unix_ms` | number | 下个自然月 1 日 0 点（服务器本地时区）epoch 毫秒，用于倒计时。 |
| `reason` | string \| 省略 | `feature_disabled` 表示功能未启用；正常时省略/空。 |

**错误**
| HTTP | reason | 含义 |
|---|---|---|
| 401 | `UNAUTHORIZED` | 未携带有效 JWT。 |

---

## 2. 运维态接口：表 A 配置（赠金 + 注册时间窗口）

所有接口前缀：`/api/v1/admin/ops/bind-key-gifts`，鉴权见 §0.2。

数据存于表 A `bind_key_gift_settings`，每个 `api_key_id` 一行，包含：
- **赠金字段**：`deduction_mode` / `ratio_recharge` / `expires_after_days`。
- **扩展配置**：`config` (JSONB)，目前承载 `registration_window`。

> **赠金与窗口相互独立**：更新赠金（§2.1）不会清除窗口；设置/删除窗口（§2.5/§2.6）不会动赠金字段。
> 二者写不同的列，互不覆盖。

### 2.0 表 A 行的数据结构（响应 DTO）

`GET`/`PUT`/`POST` 返回的 `data` 对象：
```json
{
  "id": 1,
  "api_key_id": 12345,
  "deduction_mode": "ratio",
  "ratio_recharge": 2.0,
  "expires_after_days": 7,
  "config": {
    "registration_window": { "enabled": true, "min_days": 0, "max_days": 30 }
  },
  "created_at": "2026-06-02T10:00:00+08:00",
  "updated_at": "2026-06-02T11:00:00+08:00"
}
```
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | number | 表 A 行 ID。 |
| `api_key_id` | number | 对应的池 key ID（唯一）。 |
| `deduction_mode` | string | `priority` 或 `ratio`。 |
| `ratio_recharge` | number \| 省略 | 仅 `ratio` 模式有值。 |
| `expires_after_days` | number \| 省略 | 赠金有效天数；省略 = 永不过期。 |
| `config` | object \| 省略 | 扩展配置；无任何扩展时省略。 |
| `config.registration_window` | object \| 省略 | 注册时间窗口；未配置时省略。 |
| `created_at` / `updated_at` | string(RFC3339) | 时间戳。 |

### 2.1 POST /api/v1/admin/ops/bind-key-gifts — upsert 赠金配置

按 `api_key_id` upsert 赠金参数（已存在则覆盖赠金字段，不存在则创建）。**不影响**已有的注册窗口。

**请求体**
```json
{ "api_key_id": 12345, "deduction_mode": "ratio", "ratio_recharge": 2.0, "expires_after_days": 7 }
```
| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `api_key_id` | number | 是 | 池 key ID，> 0。 |
| `deduction_mode` | string | 是 | `priority` 或 `ratio`。 |
| `ratio_recharge` | number | `ratio` 时必填 | > 0；`priority` 时**禁止**出现。 |
| `expires_after_days` | number | 否 | > 0；省略 = 永不过期。 |

**成功 `200`**：返回表 A 行 DTO（§2.0）。
**错误 `400`**：`api_key_id must be positive` / `priority mode must not include ratio_recharge` /
`ratio mode requires positive ratio_recharge` / `deduction_mode must be priority or ratio` /
`expires_after_days must be positive when provided`。

### 2.2 GET /api/v1/admin/ops/bind-key-gifts — 列表

**查询参数**：`page`（默认 1）、`page_size`（默认 50，上限 200）。

**成功 `200`**
```json
{ "data": [ { ...行 DTO... } ], "total": 12, "page": 1, "page_size": 50 }
```

### 2.3 GET /api/v1/admin/ops/bind-key-gifts/:api_key_id — 单条

**成功 `200`**：`{ "data": { ...行 DTO，含 config.registration_window... } }`
**错误 `404`**：`{ "code": 404, "message": "setting not found", "reason": "" }`（无该 key 配置时）。

> 外部系统可用此接口在用户选 key 前读取窗口，提前提示资格。

### 2.4 DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id — 删除整行

删除该 key 的整条表 A 记录（赠金 + 窗口一起删）。

**成功 `200`**：`{ "deleted": 1 }`（无该行时 `{ "deleted": 0 }`）。

### 2.5 PUT /api/v1/admin/ops/bind-key-gifts/:api_key_id/registration-window — 设置注册窗口

为某条池 key 设置「注册时间窗口」。只有注册时长落在 `[min_days, max_days]`（滚动相对当前时间）
的用户才能领取该 key；依旧叠加「每自然月一次」的全局规则。**不影响**该 key 的赠金配置。

- 若表 A 已有该 `api_key_id` 行：仅更新 `config.registration_window`，保留赠金字段。
- 若不存在：创建一条占位行，`deduction_mode` 默认 `priority`（赠金行为等价于「无配置」），
  并写入窗口。

**路径参数**：`api_key_id`（> 0）。

**请求体**
```json
{ "enabled": true, "min_days": 0, "max_days": 30 }
```
| 字段 | 类型 | 必填 | 约束 | 说明 |
|---|---|---|---|---|
| `enabled` | bool | 是 | — | `false` = 保留配置但不生效（等价于不限制）。 |
| `min_days` | number(int) | 是 | `>= 0` | 最小注册时长（天）；`0` = 对下界不设限（含新用户）。 |
| `max_days` | number(int) | 是 | `>= 1` 且 `>= min_days` | 最大注册时长（天）。 |

**判定逻辑**（commit 时）：设用户注册时长 `age = now - user.created_at`，
当 `enabled=true` 且（`age < min_days*24h` 或 `age > max_days*24h`）→ 拒绝（`BIND_KEY_REGISTRATION_WINDOW`）。
时区：服务器本地时间。

**成功 `200`**：返回表 A 行 DTO（§2.0，含写入的 `config.registration_window`）。

**错误 `400`**
| message | 触发 |
|---|---|
| `invalid api_key_id` | 路径参数非正整数。 |
| `min_days must be >= 0` | `min_days < 0`。 |
| `max_days must be >= 1` | `max_days < 1`。 |
| `max_days must be >= min_days` | `max_days < min_days`。 |

**示例**
```bash
curl -X PUT \
  -H "x-api-key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"min_days":0,"max_days":7}' \
  https://your-host/api/v1/admin/ops/bind-key-gifts/12345/registration-window
```

### 2.6 DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id/registration-window — 清除注册窗口

清除该 key 的注册窗口，**保留**其赠金配置（只清 `config.registration_window`）。

**路径参数**：`api_key_id`（> 0）。

**成功 `200`**
- 实际清除：`{ "deleted": 1 }`
- 行不存在或本就无窗口：`{ "deleted": 0 }`（no-op）。

**错误 `400`**：`invalid api_key_id`。

**示例**
```bash
curl -X DELETE \
  -H "x-api-key: $ADMIN_API_KEY" \
  https://your-host/api/v1/admin/ops/bind-key-gifts/12345/registration-window
```

---

## 3. 错误码速查（reason）

| reason | HTTP | 出现接口 | 含义 |
|---|---|---|---|
| `BIND_KEY_EMPTY` | 400 | reserve | `keys` 为空。 |
| `BIND_KEY_TOO_MANY` | 400 | reserve | `keys` > 50。 |
| `BIND_KEY_NO_ELIGIBLE` | 404 | reserve | 无可领取 key。 |
| `BIND_KEY_RESERVATION_EXPIRED` | 404 | commit | 预留过期/不存在。 |
| `BIND_KEY_RACE` | 409 | commit | key 被并发领走。 |
| `BIND_KEY_NO_USER` | 401 | commit | 缺用户身份。 |
| `BIND_KEY_ALREADY_PARTICIPATED` | 403 | commit | 本月已领取。 |
| `BIND_KEY_REGISTRATION_WINDOW` | 403 | commit | 注册时间不在窗口内（带 `min_days`/`max_days` metadata）。 |
| `BIND_KEY_DISABLED` | 503 | reserve / commit | 功能未配置。 |
| `INVALID_ADMIN_KEY` / `UNAUTHORIZED` | 401 | 管理接口 / eligibility | 鉴权失败。 |
| （空 reason） | 400 | 管理接口 | 参数校验失败，详见 `message`。 |

---

## 4. 典型对接流程

**配置某 key 仅限「注册不超过 7 天的新用户」领取：**
```bash
PUT /api/v1/admin/ops/bind-key-gifts/12345/registration-window
{ "enabled": true, "min_days": 0, "max_days": 7 }
```

**用户领取（外部站点代理或前端直连）：**
1. `POST /bind-key/reserve` `{ "keys": ["sk-..."] }` → 拿 `reservation_id`。
2. 用户登录拿 JWT。
3. `POST /bind-key/commit`（带 `Authorization: Bearer <jwt>`）`{ "reservation_id": "..." }`。
   - 成功 → 读 `data.gift` 展示赠金。
   - `403 BIND_KEY_REGISTRATION_WINDOW` → 读 `metadata.min_days`/`max_days` 提示「需注册满 X 天且不超过 Y 天」。
   - `403 BIND_KEY_ALREADY_PARTICIPATED` → 提示本月已领取。

**解除限制：**
```bash
DELETE /api/v1/admin/ops/bind-key-gifts/12345/registration-window
# 或 PUT enabled=false
```

---

## 5. 备注

- 窗口为**滚动相对窗口**，相对当前时间计算，无需周期性改配置。
- 窗口校验只在 `commit`（与月度限制一致）；`reserve` 匿名、不校验。若同一批 paste 列表混入
  不同窗口的 key，可能先 reserve 到不符的 key，再在 commit 被拒。常见「整批同窗口」用法无影响。
- 配置随 `api_key_id` 落表 A；key 删除后由运维清理表 A，配置一并消失，不产生孤儿记录。
- 所有时间窗口边界使用**服务器本地时区**。
