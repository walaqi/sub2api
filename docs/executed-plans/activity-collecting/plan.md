# 活动报名功能实现计划

## 目标

在用户界面新增活动报名页面：用户进入页面后从下拉列表选择当前进行中的活动，页面展示活动介绍，用户点击报名并填写接收活动邮件地址。

同时新增给外部 ops 系统调用的接口：ops 系统可注册活动并获得活动 ID，活动开始前可按活动 ID 拉取报名用户的用户名和接收活动邮件地址列表。

## 合并冲突控制

- 后端新增独立包 `backend/internal/activity`，不修改现有 `handler.Handlers` 聚合结构。
- 后端主路由仅增加一行 `activity.RegisterRoutes(...)`，参考现有 `keybind.RegisterRoutes(...)` 模式。
- 数据库访问使用本包内 raw SQL，不新增 ent schema，避免大量生成文件和 upstream 合并冲突。
- ops 接口复用现有管理员 JWT 鉴权，不额外引入 activity 专用 secret，减少生产配置成本。
- 前端新增独立 API 文件和独立页面，仅在路由表新增入口。

## 后端接口

### 用户接口

`GET /api/v1/activity/events/active`

- 需要 JWT。
- 返回当前进行中的活动列表。
- 当前进行中定义：`status = 'active'`，且 `starts_at <= now()`，且 `ends_at IS NULL OR ends_at > now()`。

`POST /api/v1/activity/events/:id/signups`

- 需要 JWT。
- 请求体：

```json
{
  "receive_email": "user@example.com"
}
```

- 用户 ID 来自 JWT，不接受前端传入用户 ID。
- 同一用户同一活动只保留一条报名记录，重复提交会更新接收活动邮件地址。

### ops 接口

ops 接口复用现有管理员 JWT 鉴权，不需要 `ACTIVITY_OPS_SECRET` 或额外请求头。

```http
Authorization: Bearer <admin_jwt>
Content-Type: application/json
```

推荐路径挂在现有 admin/ops 命名空间下：

`POST /api/v1/admin/ops/activity/events`

- 注册活动。
- 请求体：

```json
{
  "name": "活动名称",
  "description": "活动简介",
  "starts_at": "2026-07-01T00:00:00Z",
  "ends_at": "2026-07-10T00:00:00Z"
}
```

- `name` 和 `description` 必填。
- `description` 支持 Markdown 原文；数据库仍存原始 Markdown，前端使用 `marked` 转 HTML 后再用 `DOMPurify` 清洗并渲染。
- `starts_at` 可选，默认 `now()`。
- `ends_at` 可选，空值表示不设结束时间。
- 返回标准响应 envelope，`data.id` 是活动 ID：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 123
  }
}
```

curl 示例：

```bash
curl -X POST 'https://sub2api.example.com/api/v1/admin/ops/activity/events' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "活动名称",
    "description": "## 活动简介\n- 支持 Markdown\n- 前端安全渲染",
    "starts_at": "2026-07-01T00:00:00Z",
    "ends_at": "2026-07-10T00:00:00Z"
  }'
```

`GET /api/v1/admin/ops/activity/events/:id/signups`

- 按活动 ID 拉取报名用户列表。
- 返回标准响应 envelope，`data` 是报名列表。
- ops 导出报名名单时取 `username` 和 `receive_email` 两列即可。
- 兼容路径：`/api/v1/activity/ops/events` 和 `/api/v1/activity/ops/events/:id/signups` 暂时保留，但同样要求管理员 JWT。

响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": [
    {
      "id": 1,
      "activity_id": 123,
      "user_id": 456,
      "username": "alice",
      "receive_email": "alice@example.com",
      "created_at": "2026-06-29T10:00:00Z",
      "updated_at": "2026-06-29T10:00:00Z"
    }
  ]
}
```

curl 示例：

```bash
curl 'https://sub2api.example.com/api/v1/admin/ops/activity/events/123/signups' \
  -H 'Authorization: Bearer <admin_jwt>'
```

`PUT /api/v1/admin/ops/activity/events/:id`

- 修改活动名称、简介、状态和报名开放时间窗口。
- 适用于 ops 创建活动后修正文案，或调整活动是否在用户端显示。
- `status` 支持 `active` / `disabled`。
- `ends_at` 传 `null` 表示清除结束时间；不传 `starts_at` / `ends_at` 时保留原值。

请求体示例：

```json
{
  "name": "活动名称",
  "description": "## 修改后的活动简介\n\n- 支持 Markdown",
  "status": "active",
  "starts_at": "2026-06-29T00:00:00Z",
  "ends_at": null
}
```

curl 示例：

```bash
curl -X PUT 'https://sub2api.example.com/api/v1/admin/ops/activity/events/123' \
  -H 'Authorization: Bearer <admin_jwt>' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "活动名称",
    "description": "## 修改后的活动简介\n\n- 支持 Markdown",
    "status": "active",
    "starts_at": "2026-06-29T00:00:00Z",
    "ends_at": null
  }'
```

兼容路径：`PUT /api/v1/activity/ops/events/:id` 暂时保留，但同样要求管理员 JWT。

## 前端页面

- 新增 `frontend/src/api/activity.ts`。
- 新增 `frontend/src/views/user/ActivitySignupView.vue`。
- 新增路由 `/activities`，需要登录。
- 页面流程：
  - 进入页面拉取当前进行中活动。
  - 下拉列表选择活动。
  - 展示活动简介。
  - 用户填写接收活动邮件地址。
  - 提交报名并展示成功或错误状态。

## 数据库 schema

迁移文件：`backend/migrations/173_activity_signup.sql`

```sql
CREATE TABLE IF NOT EXISTS activity_events (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ends_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_events_active_window
    ON activity_events (status, starts_at, ends_at);

CREATE TABLE IF NOT EXISTS activity_signups (
    id BIGSERIAL PRIMARY KEY,
    activity_id BIGINT NOT NULL REFERENCES activity_events(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receive_email VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (activity_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_activity_signups_activity_id
    ON activity_signups (activity_id);

CREATE INDEX IF NOT EXISTS idx_activity_signups_user_id
    ON activity_signups (user_id);
```

### 字段说明

`activity_events`

- `id`：活动 ID，返回给 ops 系统。
- `name`：活动名称。
- `description`：活动简介，前端选择活动后展示。
- `status`：活动状态，当前支持 `active` / `disabled`。
- `starts_at`：活动开始时间，用于判断是否当前进行中。
- `ends_at`：活动结束时间，空值表示不设结束时间。
- `created_at`：创建时间。
- `updated_at`：更新时间。

`activity_signups`

- `id`：报名记录 ID。
- `activity_id`：活动 ID。
- `user_id`：报名用户 ID。
- `receive_email`：用户填写的接收活动邮件地址。
- `created_at`：首次报名时间。
- `updated_at`：报名信息更新时间。
- `UNIQUE(activity_id, user_id)`：保证同一用户同一活动只有一条报名记录。
