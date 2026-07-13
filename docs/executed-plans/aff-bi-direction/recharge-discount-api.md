# Recharge Discount API Reference

## Admin Ops API（外部 ops 系统调用，需 admin JWT）

### 设置充值折扣

```
PUT /api/v1/admin/ops/bind-key-gifts/:api_key_id/recharge-discount
```

设置指定池 key 的充值折扣配置。绑定该 key 后用户在有效期内充值可额外获得赠金。

**Request Body:**

```json
{
  "enabled": true,
  "discount_rate": 0.1,
  "max_discountable_amount": 500,
  "valid_days": 30
}
```

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| enabled | bool | required | 是否启用 |
| discount_rate | float | (0, 10.0] | 折扣比例，0.1 = 额外 10%，5.0 = 额外 500% |
| max_discountable_amount | float | > 0 | 可参与折扣的充值本金上限 (USD) |
| valid_days | int | >= 1 | 从绑定时刻起算的有效天数 |

**Response 200:**

```json
{
  "data": {
    "id": 1,
    "api_key_id": 42,
    "deduction_mode": "priority",
    "config": {
      "recharge_discount": {
        "enabled": true,
        "discount_rate": 0.1,
        "max_discountable_amount": 500,
        "valid_days": 30
      }
    },
    "created_at": "2026-06-27T10:00:00Z",
    "updated_at": "2026-06-27T10:00:00Z"
  }
}
```

**行为说明：**
- 行不存在时自动创建占位行（deduction_mode=priority）
- 只修改 config.recharge_discount，不影响赠金配置（deduction_mode/ratio_recharge 等）
- 与 registration-window 互不覆盖

---

### 清除充值折扣

```
DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id/recharge-discount
```

清除指定池 key 的充值折扣配置，保留其他配置字段。

**Response 200:**

```json
{ "deleted": 1 }
```

行不存在或无折扣配置时返回 `{ "deleted": 0 }`。

---

## 用户 API（需 JWT 认证）

### 查询活跃充值折扣

```
GET /api/v1/user/recharge-discount
```

返回当前用户的最佳活跃折扣（按 discount_rate DESC 排序）。用于充值页展示折扣提示。

**Response 200（有折扣）：**

```json
{
  "code": 0,
  "data": {
    "id": 5,
    "source": "bind_key",
    "discount_rate": 0.1,
    "max_discountable_amount": 500,
    "total_discounted": 120.5,
    "remaining_quota": 379.5,
    "valid_until_unix_ms": 1722556800000
  }
}
```

**Response 200（无折扣）：**

```json
{
  "code": 0,
  "message": "success"
}
```

注意：无折扣时 `data` 字段被省略（omitempty），前端应以 `data ?? null` 兼容。

| 字段 | 说明 |
|------|------|
| source | 折扣来源：`bind_key` 或 `referral_inherit` |
| discount_rate | 当前折扣比例 |
| max_discountable_amount | 充值本金上限 |
| total_discounted | 已参与折扣的充值本金累计 |
| remaining_quota | 剩余可参与折扣额度 |
| valid_until_unix_ms | 过期时间戳（毫秒），null=永不过期 |

---

## 绑定成功响应扩展

`POST /api/v1/bind-key/commit` 响应新增 `discount` 字段：

```json
{
  "code": 0,
  "data": {
    "api_key_id": 42,
    "masked_key": "sk-****xxxx",
    "gift": { "amount": 5.0, "deduction_mode": "priority", "expires_at_unix_ms": null },
    "discount": {
      "discount_rate": 0.1,
      "max_discountable_amount": 500,
      "valid_days": 30
    }
  }
}
```

`discount` 为 null 时表示该 key 未配置充值折扣。前端据此决定是否显示折扣卡片。
