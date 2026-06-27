# Bind-Key 增量需求：注册时间窗口限制（per-key，存表 A）

## 需求

在 `/bind-key` 绑定功能上增加一个**可选**限制：某条池 key 可配置"只有注册时长落在
[min_days, max_days] 滚动窗口内的用户"才能领取，依旧叠加"每个自然月只能参与一次"的既有规则。

**remark 1（已采纳）**：这不是必选项。某条 key 不配置窗口时，只走"每月一次"规则，行为同现状。

**remark 2 / 存储模型（已采纳，修正首版错误）**：
- 首版我错误地设计成"全局单条配置存 `settings` 表"——会在共享表里留下与 keybind 解耦哲学
  不符的记录。
- 正确做法：**per-key 配置，复用已有的表 A `bind_key_gift_settings`**（按 `api_key_id` 唯一），
  这样 key 被删除时配置天然一起清理，**不产生孤儿**。
- 为避免将来频繁迁移 schema，给表 A **新增一个可扩展 `config` JSONB 字段**，注册窗口存进
  `config.registration_window`；以后 bind-key 的其它 per-key 选项继续往同一个 JSON 里加，
  不用再改 schema。（这正是你之前要的"config 字段"。）

窗口语义（用户确认）：
- 滚动相对窗口：`MinDays*24h <= (now - user.created_at) <= MaxDays*24h`。
- `MinDays >= 0`（默认 0，0=对下界不设限，含新用户）；`MaxDays >= 1`（默认 30）；要求 `MaxDays >= MinDays`。

配置方式（用户确认）：暴露管理 API（外部站点远程调 → 自建管理 UI），不做本地 UI。

## 现状调研结论

- 表 A `bind_key_gift_settings`（[ent/schema/bind_key_gift_setting.go](../projects/sub2api/backend/ent/schema/bind_key_gift_setting.go)，
  迁移 [143](../projects/sub2api/backend/migrations/143_bind_key_gift_settings.sql)）：
  `api_key_id`(unique) + `deduction_mode`(NOT NULL, priority|ratio) + `ratio_recharge` + `expires_after_days`。
  与 api_keys 解耦、无外键，运维独立清理。
- 表 A 的**读**在 keybind 包（[gift_settings_repo.go](../projects/sub2api/backend/internal/keybind/gift_settings_repo.go)
  的 `BindKeyGiftSettingResolver.Resolve`，按 api_key_id 查）。
- 表 A 的**写/管理 API 已存在**于主 admin handler：
  [gift_ops_handler.go](../projects/sub2api/backend/internal/handler/admin/gift_ops_handler.go) 的
  `UpsertBindKeyGiftSetting / Get / List / Delete`，路由在
  [admin.go:664 registerGiftOpsRoutes](../projects/sub2api/backend/internal/server/routes/admin.go#L664)
  → `/api/v1/admin/ops/bind-key-gifts`，由现有 `adminAuth` 守卫。**已注册，无需改 router.go/http.go/wire_gen.go。**
- 绑定流程：`Reserve`（public，无 JWT，无用户身份）→ `Commit`（JWT，有用户 + reservation→keyID）。
  per-key 窗口需要 `user.created_at`（要登录）**且** keyID（要选中 key）→ 二者同时具备的点是
  **`Commit`**。月度限制也是在 Commit 强制的（[service.go:274](../projects/sub2api/backend/internal/keybind/service.go#L274)），同源。
- ent JSON 字段范式：`field.JSON("targeting", domain.AnnouncementTargeting{})`
  （[announcement.go:48](../projects/sub2api/backend/ent/schema/announcement.go#L48)），类型定义在 `internal/domain`，
  ent schema import domain（无环：domain 不 import ent；keybind 也已 import domain）。
- 迁移是**手写 SQL**（runner `internal/repository/migrations_runner.go`，最新 150），ent 仅生成类型化 client；
  故需"手写迁移 + ent schema 加字段 + 重生成 ent"三者一致。`make generate` = `go generate ./ent`。
- 用户确认过：**为避免未来频繁迁移，这次加一个 config 字段是被授权的**。

## 设计

把**配置存储 + 校验**收敛到 per-key 表 A；**校验执行**在 keybind 的 `Commit`；
**管理 API** 扩展已有的 `gift_ops_handler`（表 A 写操作的既有归属地）。
**不动** router.go / http.go / wire_gen.go（管理路由组 + keybind 注册都已就位）。

### 1. 迁移（新文件，additive）

`backend/migrations/151_bind_key_gift_settings_config.sql`：
```sql
-- 给表 A 增加可扩展 JSONB 配置列；NULL = 无扩展配置（含无注册窗口）。
ALTER TABLE bind_key_gift_settings
    ADD COLUMN IF NOT EXISTS config JSONB;
```
幂等、可重放、向后兼容（旧行 config 为 NULL）。

### 2. domain 新类型（新文件）

`backend/internal/domain/bind_key.go`：
```go
package domain

// BindKeyConfig 是表 A 的可扩展 per-key 配置（存 bind_key_gift_settings.config JSONB）。
// 新增 per-key 选项往这里加字段，避免再迁移 schema。
type BindKeyConfig struct {
    RegistrationWindow *BindKeyRegistrationWindow `json:"registration_window,omitempty"`
}

// BindKeyRegistrationWindow 滚动相对注册窗口（单位：天）。
type BindKeyRegistrationWindow struct {
    Enabled bool `json:"enabled"`
    MinDays int  `json:"min_days"`
    MaxDays int  `json:"max_days"`
}
```
纯数据、零 import，确保无环。

### 3. ent schema + 重新生成

[ent/schema/bind_key_gift_setting.go](../projects/sub2api/backend/ent/schema/bind_key_gift_setting.go) `Fields()` 追加：
```go
field.JSON("config", &domain.BindKeyConfig{}).Optional(),
```
（import `internal/domain`。）然后：
```bash
cd backend && go generate ./ent        # 重生成类型化 client（生成 row.Config / SetConfig）
```
生成物 diff 限于 bindkeygiftsetting 相关文件 + runtime。列名与迁移一致（`config`）。

### 4. keybind 读取扩展（[gift_settings_repo.go](../projects/sub2api/backend/internal/keybind/gift_settings_repo.go)）

`BindKeyGiftSetting`（resolver 返回的解析结构）追加：
```go
RegistrationWindow *domain.BindKeyRegistrationWindow
```
`Resolve` 解析 `row.Config`：
```go
if row.Config != nil && row.Config.RegistrationWindow != nil {
    out.RegistrationWindow = row.Config.RegistrationWindow
}
```
无行 → 返回 nil（同现状），调用方按"无 gift 配置 + 无窗口"处理。

### 5. keybind 校验执行（[service.go](../projects/sub2api/backend/internal/keybind/service.go)）

- `Service` 加字段 `giftSettingResolver BindKeyGiftSettingResolver`，
  `NewService` 里 `giftSettingResolver: NewBindKeyGiftSettingResolver(client)`（client 已有，**不改 NewService 签名**）。
- 新错误：
  ```go
  ErrRegistrationWindow = infraerrors.Forbidden(
      "BIND_KEY_REGISTRATION_WINDOW",
      "your account registration date is outside the allowed window for this key")
  ```
- 新方法：
  ```go
  // 返回 nil 表示通过（含"未配置窗口"）。窗口外返回 ErrRegistrationWindow（附 min/max metadata）。
  func (s *Service) checkRegistrationWindow(ctx, userID, keyID int64) error
  ```
  逻辑：`Resolve(keyID)` → 无 window 或 `!Enabled` → nil；否则查 `user.created_at`
  （`client.User.Query().Where(user.IDEQ(userID)).Select(user.FieldCreatedAt).Only`），
  计算 `age=time.Since(createdAt)`，`age>=Min*24h && age<=Max*24h` → nil，否则
  `ErrRegistrationWindow.WithMetadata({"min_days","max_days"})`（前端可读 metadata 渲染具体天数）。
- 在 `Commit` 中，紧接月度 `HasParticipated` 拒绝块**之后**、`poolKey` 查询之前插入：
  ```go
  if err := s.checkRegistrationWindow(ctx, userID, keyID); err != nil {
      if errors.Is(err, ErrRegistrationWindow) { _ = s.redis.Del(ctx, resKey).Err() } // 释放预留
      return nil, err
  }
  ```
  在 key 转移前拒绝；不记月度名单、不转移、不发赠金。

> Eligibility 端点**不改**：它无 key 上下文，无法预检 per-key 窗口；窗口在 Commit 强制并由前端
> 在 commit 错误分支渲染（与既有 `BIND_KEY_ALREADY_PARTICIPATED` 的 commit 兜底处理对称）。

### 6. 管理 API 扩展（[gift_ops_handler.go](../projects/sub2api/backend/internal/handler/admin/gift_ops_handler.go) + [admin.go](../projects/sub2api/backend/internal/server/routes/admin.go)）

表 A 写操作的既有归属地，新增 per-key 窗口的独立读写（不与 gift 互相覆盖）：

handler 新增：
```go
type RegistrationWindowPayload struct {
    Enabled bool `json:"enabled"`
    MinDays int  `json:"min_days"`
    MaxDays int  `json:"max_days"`
}

// PUT /api/v1/admin/ops/bind-key-gifts/:api_key_id/registration-window
func (h *GiftOpsHandler) SetBindKeyRegistrationWindow(c *gin.Context)
//  - 校验 MinDays>=0, MaxDays>=1, MaxDays>=MinDays
//  - 查 existing row：
//      存在 → existing.Update().SetConfig(把 RegistrationWindow 合并进 config).Save()  // 保留 gift 字段
//      不存在 → Create().SetAPIKeyID(id).SetDeductionMode("priority").SetConfig(...).Save()
//        （priority 默认 = 与"无行"等价的赠金行为，不改变 gift 语义）

// DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id/registration-window
func (h *GiftOpsHandler) DeleteBindKeyRegistrationWindow(c *gin.Context)
//  - 行不存在 → 200 no-op；存在 → 清掉 config.RegistrationWindow 后写回（保留 gift 字段）
```
扩展既有 DTO `BindKeyGiftSettingResponse` 增加 `Config *domain.BindKeyConfig`（或直接 `RegistrationWindow`）
字段（omitempty），让既有 `GET /:api_key_id` 与 `GET（list）` 一并返回窗口配置。

> 既有 `UpsertBindKeyGiftSetting`（gift）只 `Set*` gift 列、不碰 `config`，故 gift 更新天然
> 保留窗口；反之窗口更新只 `SetConfig`、保留 gift 列。二者独立、互不覆盖。

[admin.go registerGiftOpsRoutes](../projects/sub2api/backend/internal/server/routes/admin.go#L664) 的
`bindKeyGifts` 组内追加两行：
```go
bindKeyGifts.PUT("/:api_key_id/registration-window", h.Admin.GiftOps.SetBindKeyRegistrationWindow)
bindKeyGifts.DELETE("/:api_key_id/registration-window", h.Admin.GiftOps.DeleteBindKeyRegistrationWindow)
```

### 7. 前端（仅 [BindKeyView.vue](../projects/sub2api/frontend/src/views/BindKeyView.vue)）

per-key 窗口无法在 eligibility 预检（无 key 上下文），故纯由 commit 错误驱动：
- 新增 `registrationBlocked = ref(false)`、`registrationWindow = ref<{min_days,max_days}|null>(null)`。
- `commitReservation` catch 增加分支：`reason === 'BIND_KEY_REGISTRATION_WINDOW'` →
  `registrationBlocked.value = true`，从 `e.metadata`/`e.response.data.metadata` 取 min/max 存
  `registrationWindow`，`clearPending()` + 清 pending。
- 模板在 monthlyBlocked 卡片旁并列新增"注册时间不符"卡片（橙色 warning 风格），命中时隐藏粘贴框
  （`v-else-if="registrationBlocked"`，置于 monthlyBlocked 分支后）。
- 双语文案（追加到 inline `en`/`zh`，沿用不碰 i18n locale 文件约定）：
  - `regWindowTitle`：「你的账号不符合该 Key 的领取条件」/`Your account isn't eligible for this key`
  - `regWindowBody`：按 min/max 渲染「该 Key 仅限注册时间在特定范围内的账号领取……」
    （若有 metadata：注册满 X 天且不超过 Y 天）。

## 关键文件汇总

| 角色 | 路径 | 类型 |
|------|------|------|
| 迁移：表 A 加 config JSONB | `backend/migrations/151_bind_key_gift_settings_config.sql` | 新文件 |
| domain 配置类型 | `backend/internal/domain/bind_key.go` | 新文件 |
| ent schema 加 config 字段 | `backend/ent/schema/bind_key_gift_setting.go` | 修改 + 重生成 |
| ent 生成物 | `backend/ent/**`（bindkeygiftsetting 相关） | 重生成 |
| 解析 config.registration_window | `backend/internal/keybind/gift_settings_repo.go` | 修改 |
| 服务：Commit 窗口门禁 + 错误 | `backend/internal/keybind/service.go` | 修改 |
| 管理 API：窗口 set/delete + DTO | `backend/internal/handler/admin/gift_ops_handler.go` | 修改 |
| 路由：注册 2 条窗口端点 | `backend/internal/server/routes/admin.go` | 修改（既有组内 +2 行）|
| 前端：commit 错误分支 + 卡片 | `frontend/src/views/BindKeyView.vue` | 修改 |

**完全不动**：`router.go` / `http.go` / `wire_gen.go` / `participation.go` / `routes.go`(keybind) /
`NewService` 签名 / i18n locale 文件。

## 管理 API 契约（供远程站点调用）

鉴权：admin（JWT 或 x-api-key，经 `adminAuth`），与既有 ops API 相同。

- `PUT /api/v1/admin/ops/bind-key-gifts/{api_key_id}/registration-window`
  body `{"enabled":true,"min_days":0,"max_days":30}`
  → `200 {"data":{...含 config.registration_window...}}`；非法 `400`。
- `DELETE /api/v1/admin/ops/bind-key-gifts/{api_key_id}/registration-window` → `200`。
- `GET /api/v1/admin/ops/bind-key-gifts/{api_key_id}`（既有，DTO 扩展）→ 返回 gift + window。
- `GET /api/v1/admin/ops/bind-key-gifts`（既有 list，DTO 扩展）→ 列表含 window。

## 验证方案

### 后端
```bash
cd backend && GOPROXY=https://goproxy.cn,direct go generate ./ent
cd backend && GOPROXY=https://goproxy.cn,direct go build ./...
cd backend && GOPROXY=https://goproxy.cn,direct go test -race ./internal/keybind/... ./internal/handler/admin/...
```
新测试（keybind enttest+sqlite，参照 service 包既有用法）：
- resolver：行有 `config.registration_window` → 解析出窗口；config NULL → nil。
- `checkRegistrationWindow`：无行/`!Enabled` → 通过；`min=0,max=30` 注册10天前→通过、40天前→拒；
  `min=7` 注册3天前→拒。
- `Commit`：窗口外 → `BIND_KEY_REGISTRATION_WINDOW`，未转移 key、未写月度名单、释放预留；
  窗口内 + 本月已参与 → 仍 `BIND_KEY_ALREADY_PARTICIPATED`。
- handler：set/delete 窗口不影响 gift 字段；set gift（既有 upsert）不清窗口；GET 回读含窗口。
- 迁移幂等：重放 151 不报错。

### 前端
```bash
cd frontend && pnpm typecheck && pnpm lint
```

### 手动 E2E
```bash
cd backend && BIND_KEY_POOL_USER_EMAIL=keypool@atai8.cc go run ./cmd/server/
cd frontend && pnpm dev
```
- 远程 `PUT .../{keyID}/registration-window {enabled:true,min_days:0,max_days:7}` → `GET` 回读确认。
- 注册 >7 天账号绑该 key → commit 返 `BIND_KEY_REGISTRATION_WINDOW`，前端显示"注册时间不符"卡片；
  curl 直打 `/commit` 同样 403。
- 注册 <7 天账号 → 正常绑定成功。
- `DELETE .../registration-window` 或 `enabled:false` → 限制解除，仅留月度规则。
- key 删除后表 A 行由运维清理 → 配置随之消失，无孤儿。

## 风险与备注

- **ent 重生成**：标准流程（`make generate`），diff 限于新字段相关生成文件；CI/构建会校验一致性。
- **enforcement 仅在 Commit**：与月度限制一致。Reserve 匿名、无身份，无法预检；同一 paste 列表里
  混入不同窗口的 key 时可能"先 reserve 到不符的 key 再被 commit 拒"——常见用法（整批同窗口）下不影响。
  如需 reserve 期预筛为后续项。
- **window-only 行**：为存窗口而建的行 `deduction_mode='priority'`，赠金行为与"无行"等价，不改变发放语义。
- **时区**：窗口边界用服务器本地时间，与月度逻辑一致。
- **无孤儿**：配置随 api_key_id 落表 A，key 删除时运维清理表 A 即一并清除（与既有 gift 配置同生命周期）。
- **向后兼容**：config NULL → 无窗口；DTO/Eligibility 新字段 omitempty，旧前端忽略。
- **回滚**：`git revert` 单 commit + 可选 `ALTER TABLE ... DROP COLUMN config`（additive 列，留着也无害）。
