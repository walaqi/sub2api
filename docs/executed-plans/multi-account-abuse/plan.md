# 多账户滥用检测 — 管理端 + 临时限流 实施计划

状态：待实施（Phase 3）。Phase 1（device_id 落库）、Phase 2（HTTP 层 client_fingerprint）已完成。

> 修订记录：本版已纳入第一轮评审（[review-1.md](./review-1.md)）的修订要求 —— 阻断项 R1（批量禁用同步失效鉴权缓存）、R2（热路径设置改用缓存范式）已写入设计；R3（三层级联语义）、R4（IP 单维度护栏）、R7（跳过 admin 的实现）已补全；R5（TTL 缩短）、R6（运行间隔入配置）、R8（限流审计列表）已纳入。事实性修正 F1–F3 已就地更正。

## 背景与目标

系统是 sub2api（Go API 网关，代理 Claude/OpenAI/Gemini）。数据中发现真实"农场"：多个平台用户登录共享同一 device_id / client_fingerprint / IP（例如 IP `66.90.98.34` 与 `43.139.65.187` 共享约 40 个账户）。

要做两个使用场景：

1. **管理端界面**：统计与查询为主，提供多选禁用 —— 选中多个高危用户，一键禁用。
2. **临时限流**：作为开关选项，打开后对高危用户临时 RPM 限流。在原有 user+group 限流基础上，对所有相关疑似用户做 50% 限流。

## 关键结论（已厘清）

检测以 `usage_logs.user_id` 聚合，RPM 也按 **user** 执行。所以禁用 / 限流的目标是**平台用户（User，即客户登录账号）**，不是上游 AI 凭证（Account）。一个"农场" = 多个 User 共享同一 device_id / client_fingerprint / IP。

> 注：探索阶段曾有误判为 Account。数据模型（usage_logs 按 user_id 分组）和"在 user+group 限流基础上"的描述都指向 User，以 User 为准。

设计原则（延续 Phase 1/2）：单向判据 —— 一个 device_id / 指纹 / IP 命中**多个**用户 = 强证据；缺失或唯一**不**等于清白。指纹与 device_id 都可伪造，价值在 device_id ∩ IP ∩ client_fingerprint 三向交叉。

## 已确认的产品决策

- **限流名单产生方式：全自动。** 开关打开后，后台按检测规则自动算出疑似集合并限流，无需人工圈选。
- **无限额用户（RPMLimit=0）：设兜底上限。** 被限流但本来无限制的用户，套用一个可配置兜底 RPM（默认 30），否则"50% 的无限制"仍是无限制。
- **限流时长：固定 TTL，可配置（默认 24h）。** 名单条目带 TTL 自动过期，管理员可调时长，也可手动清空。

---

## Part A — 检测统计查询（后端）

新仓库方法 `usage_log_repo.go: FindSuspectedMultiAccountGroups(ctx, params)`，对一个时间窗口做三类聚合：

- `GROUP BY device_id HAVING COUNT(DISTINCT user_id) >= N`
- `GROUP BY client_fingerprint HAVING COUNT(DISTINCT user_id) >= N`
- `GROUP BY ip_address HAVING COUNT(DISTINCT user_id) >= N`

返回每个"团伙"的标识、关联 user_id 列表、各 user 的请求量 / 时间跨度。

**展示 vs 自动限流的范围差异（呼应 R4）：** Part A 这三个维度按**独立 OR**聚合，用于**人工查看**，三个维度（含 IP 单维度）都展示，供管理员判断。但 Part C 的**自动**限流名单**不**直接采纳 IP 单维度命中 —— 见 Part C §2 的交叉护栏。展示层把每条团伙标注命中维度（device / fingerprint / ip / 交叉），让管理员一眼看出哪些是强证据、哪些只是共享出口 IP。

**NULL 语义（已在代码层成立，需在测试里锁住）：** `device_id` 与 `client_fingerprint` 入库经 `optionalTrimmedStringPtr`（[usage_log_helpers.go:5](../../../backend/internal/service/usage_log_helpers.go#L5)），空值落 `NULL` 而非 `""`。聚合查询的 `WHERE device_id IS NOT NULL` / `WHERE client_fingerprint IS NOT NULL` 因此不会把空值塌缩成一个巨型误报团伙。Part A 的测试需构造含空 device_id / fingerprint 的数据集，断言它们不被计入任何团伙（防回归）。

**索引（F2 更正）：** `device_id`、`client_fingerprint` 维度复用已建索引 `usagelog_device_id_user_id`、`usagelog_client_fingerprint_user_id`。IP 维度**已有**单列非分区索引 `idx_usage_logs_ip_address`（[migrations/031_add_ip_address.sql](../../../backend/migrations/031_add_ip_address.sql)），但它不覆盖 `COUNT(DISTINCT user_id)`；按需补一条 `(ip_address, user_id)` 复合分区索引（迁移 150，最高号现为 149）作为**补充**，让 IP 聚合走覆盖索引。

- Service: `AbuseDetectionService.ListSuspectGroups(window, minUsers, dimensions)`
- Handler + route: `GET /api/v1/admin/abuse/suspects`（挂 admin 组，沿用分页 DTO）

参考实现：
- 聚合查询模式 `usage_log_repo.go: GetStatsWithFilters`（约 3534 行）、`GetDailyStatsAggregated`（约 1983 行，`GROUP BY`）
- admin 路由注册 `internal/server/routes/admin.go`（`/api/v1/admin` 前缀，`AdminAuthMiddleware`）

## Part B — 批量禁用用户（后端）

- DTO `BulkUpdateUsersRequest{ UserIDs []int64; Status string }`，复用现有 `UpdateUser` 的 status 校验。
  - **校验分两处（F3）：** handler 层是 binding 标签 `oneof=active disabled`（[user_handler.go:57](../../../backend/internal/handler/admin/user_handler.go#L57)）；service 层另有手写检查 `role=="admin" && status=="disabled"` → 拒绝（[admin_service.go:722](../../../backend/internal/service/admin_service.go#L722)）。批量路径需各自对应。
- Service `BulkUpdateUsers` → repo `UPDATE users SET status=... WHERE id = ANY(...)`，返回 `{success, failed, success_ids, failed_ids, skipped_ids}`（镜像 `BulkUpdateAccountsResult`，`admin_service.go:2592`，额外加 `skipped_ids` 用于 admin 跳过）。
- Route: `POST /api/v1/admin/users/bulk-update`。

### R1（阻断）— 禁用后必须同步失效鉴权缓存

API Key 鉴权路径的用户状态来自 L2 缓存快照（[api_key_auth_cache_impl.go](../../../backend/internal/service/api_key_auth_cache_impl.go)），默认 `l2_ttl_seconds: 300`（[config.go:1712](../../../backend/internal/config/config.go#L1712)）。单用户 `UpdateUser` 改状态后会**显式调用** `s.authCacheInvalidator.InvalidateAuthCacheByUserID(...)`（[admin_service.go:778](../../../backend/internal/service/admin_service.go#L778)）。批量路径若只发一条 UPDATE 就返回，被禁用用户在 API Key 路径上**最长还能正常调用约 5 分钟** —— 对"一键封禁农场"不可接受。

**要求：** `BulkUpdateUsers` 在 UPDATE 成功后，对每个**实际被改动**的 user_id 调用 `InvalidateAuthCacheByUserID`（接口见 [api_key_auth_cache_invalidate.go:15](../../../backend/internal/service/api_key_auth_cache_invalidate.go#L15)，`adminServiceImpl` 已持有 `authCacheInvalidator`）。逐个调用（每个 user 的 key 集合不同），失败仅打 warning 不阻塞。补对应单测：用 mock invalidator 断言每个 user_id 都被调用。

### R7 — 跳过 admin 用户的实现方式

`UPDATE ... WHERE id = ANY($1)` 是盲写，无法同时"跳过 admin"+"报告被跳过的 id"。采用**先查后写**：

1. 按 id 批量查出 `(id, role)`；
2. 过滤出 `role <> 'admin'` 的目标集合，被滤掉的进 `skipped_ids`；
3. 对过滤后的集合执行 UPDATE；
4. UPDATE 成功的进 `success_ids` 并触发 R1 的缓存失效；查询/写入失败的进 `failed_ids`。

（与 `BulkUpdateAccounts` 不是 1:1 —— 账户无 role 概念，故这里多一步 role 预查。）补单测：admin 角色用户被跳过且出现在 `skipped_ids`。

参考实现：
- 现有批量更新 [admin/account_handler.go:1412](../../../backend/internal/handler/admin/account_handler.go#L1412) `BulkUpdate` + `admin_service.go: BulkUpdateAccounts`（约 2592 行）+ `account_repo.go: BulkUpdate`（约 1381 行）
- 单用户更新 `admin_service.go: UpdateUser`（706 行）

## Part C — 临时限流（后端，核心）

### 1. 运行时开关 + 配置

配置结构：

```go
type SuspectThrottleSettings struct {
    Enabled      bool `json:"enabled"`       // 总开关
    RatePercent  int  `json:"rate_percent"`  // 默认 50
    FloorRPM     int  `json:"floor_rpm"`     // 无限额用户兜底，默认 30
    MinUsers     int  `json:"min_users"`     // 触发阈值 N，默认 3
    WindowHours  int  `json:"window_hours"`  // 检测窗口，默认 24
    IntervalMin  int  `json:"interval_min"`  // 后台重跑间隔（分钟），默认 5（R6）
    TTLMinutes   int  `json:"ttl_minutes"`   // 名单条目 TTL（分钟），默认 30（R5，原 24h 改短）
}
```

新增 getter/setter + setting key（`domain_constants.go` 风格，如 `SettingKeySuspectThrottleSettings`）。`DefaultSuspectThrottleSettings()` 返回上述默认值。

**R6 — 运行间隔入配置：** 后台重跑间隔由 `IntervalMin` 提供（默认 5 分钟），不写死。

**R2（阻断）— 热路径 getter 必须走缓存范式：** `checkRPM` 是网关最热路径。**不能**镜像 `GetRateLimit429CooldownSettings`（它每次 `settingRepo.GetValue` 裸打 DB，[setting_service.go:3827](../../../backend/internal/service/setting_service.go#L3827)），否则功能**关闭时也会**每请求多一次 DB 往返，"零开销"前提不成立。

改用项目已有的「内存 `atomic.Value` 快照 + `singleflight` + 60s TTL、命中零锁」范式，参考 `IsBackendModeEnabled`（[setting_service.go:2008](../../../backend/internal/service/setting_service.go#L2008)）与 `getGatewayForwardingSettingsCached`（[setting_service.go:2056](../../../backend/internal/service/setting_service.go#L2056)）。即新增 `getSuspectThrottleSettingsCached(ctx)`，`checkRPM` 用它判断开关。这样「开关关 → 命中内存快照 → 直接返回，连 Redis 都不查」才真正零额外往返。后台服务（§2）也复用同一 getter。

### 2. 全自动名单

新增后台服务 `SuspectThrottleService`，复刻 `IdempotencyCleanupService` 的 ticker 结构（`idempotency_cleanup_service.go`：`Start/Stop/runLoop/startOnce/stopCh`），在 `wire.go` 里 `ProvideSuspectThrottleService(...).Start()`（参照 `wire.go:340 ProvideIdempotencyCleanupService`）。

逻辑：

- 开关开启时，每隔 `IntervalMin` 分钟（R6）跑一次检测。
- 命中的 user_id 写入 Redis，**每个 user_id 独立 TTL**：字符串键 `throttle:suspect:{userID}` + `EXPIRE TTLMinutes*60`（用字符串键而非 Set，TTL 逐条天然过期）。命中即续期，行为停止后很快自然消散。
- 开关关闭则跳过本轮（不主动清，靠 TTL 自然消散；前端另提供"立即清空"按钮）。

**R4（中）— IP 单维度不进自动名单（交叉护栏）：** 设计原则是"device_id ∩ IP ∩ client_fingerprint 三向交叉才是强证据"。但 IP 单维度会被企业 NAT / 运营商 CGNAT / 同住所 / VPN 出口轻易突破 N，全自动限流误伤合法用户的代价高。因此**自动名单的入选规则严于展示**：

- 自动名单只采纳**交叉命中**：同一 user 同时在 `device∩IP` 或 `fingerprint∩IP` 命中（即一个 user 既因 device 进某团伙、又因 IP 进某团伙）。
- **IP 单维度命中仅用于 Part A 展示**，不单独进自动名单。
- device 单维度、fingerprint 单维度（这两者远比 IP 难共享）可保留进自动名单，或同样要求与 IP 交叉 —— 实现时默认"device 或 fingerprint，且与 IP 交叉"，把阈值/维度组合做成可调以便后续收紧。

**R5（中）— TTL 缩短到分钟级：** 检测循环每 `IntervalMin` 分钟重判并自动续期，TTL 不必到 24h。默认 `TTLMinutes=30`（约数个检测周期）。命中则下一轮续期；一旦行为停止或属误判，分钟级自然消散，把误报代价从"一天"降到"分钟级"。

### 3. 限流注入（R3 — 三层级联完整语义）

在 `checkRPM`（[billing_cache_service.go:711](../../../backend/internal/service/billing_cache_service.go#L711)）内计算 effective limit 时按系数缩放。先确认现有级联是**三个输入并行**（非两层）：

1. per-user-group **override**（`override==0` = 该组内豁免，但 user 级仍检查）
2. `group.RPMLimit`（仅当无 override 时生效）
3. `user.RPMLimit`（**全局硬上限**，始终生效，不被前两层覆盖）

注入流程（仅当开关开启）：进 `checkRPM` 先查 `throttleService.IsSuspect(ctx, user.ID)`（一次 Redis GET，fail-open）。未命中 → 现有逻辑零改动。命中则按下面分支缩放各层的**有效阈值**（不新增计数键，复用 `rpm:ug` / `rpm:u`，[user_rpm_cache.go](../../../backend/internal/service/user_rpm_cache.go)）：

```
scale(limit):
    if limit > 0:  return max(1, limit * RatePercent / 100)
    else:          return FloorRPM          # 0 = 无限制 → 套兜底

# 第一层（group 维度，与现有分支一一对应）
if override != nil:
    if *override > 0:
        effGroup = scale(*override)         # 有意限额 → 缩放
        check rpm:ug 是否 > effGroup
    else:  # *override == 0
        # 有意的"组内豁免"，不是无限额误判 → 保持豁免，不套 FloorRPM
        skip group 层检查
elif group.RPMLimit > 0:
    effGroup = scale(group.RPMLimit)
    check rpm:ug 是否 > effGroup
# group.RPMLimit == 0 且无 override → 该组无组级限制，本层不引入兜底
# （兜底只在 user 全局层兜，避免同一用户被两层都套 FloorRPM）

# 第二层（user 全局硬上限，始终）
if user.RPMLimit > 0:
    effUser = scale(user.RPMLimit)
    check rpm:u 是否 > effUser
else:  # user.RPMLimit == 0（全局无限额）
    effUser = FloorRPM                       # 命中"无限额兜底"决策
    check rpm:u 是否 > effUser
```

关键裁定（写清以免歧义）：
- **`override == 0` 不套兜底。** 它是管理员有意的组内豁免，缩放/兜底逻辑不得把它误判成 30rpm。
- **兜底只兜 user 全局层。** 当 group override=1000、user.RPMLimit=0 的疑似用户被限流时：group 层 effective=500（1000×50%），user 层 effective=30（兜底）→ 两者并行，user 层 30 成为实际天花板。FloorRPM 套在 user 层即可，不在 group 层重复套，避免双重兜底。
- 三层 fail-open 行为与现有一致（Redis 故障打 warning、放行）。

### 4. R8 — 自动动作的可观测性

全自动限流会**自动限制付费用户**，目前只在 Redis key 留痕，客服无法解释"我为什么被限速"。`SuspectThrottleService` 维护/暴露一个**当前被限流用户列表**（user_id + 命中维度 + 命中时间 + 剩余 TTL），通过 `GET /api/v1/admin/abuse/throttled` 返回。前端"立即清空"按钮本就需要这个列表视图（Part D）。实现上可在写 `throttle:suspect:{userID}` 时附带维度/时间元信息（值存 JSON 而非空串），列表用 `SCAN throttle:suspect:*` 汇总。

## Part D — 管理端界面（前端，Vue3 + Tailwind）

新页面 `frontend/src/views/admin/AbuseDetectionView.vue` + 路由 `/admin/abuse`（`requiresAdmin: true`，`router/index.ts`）。

- 复用 `DataTable` + 多选 checkbox + 批量操作栏模式（参照 `views/admin/AccountsView.vue`：表头全选 + 行 checkbox + `AccountBulkActionsBar`）。
- 列：团伙维度（device / fingerprint / IP / 交叉）、关联用户数、user 列表（可展开）、请求量、首末时间。IP 单维度团伙标注"仅展示（不自动限流）"以呼应 R4。
- 多选用户 → "一键禁用"（调 Part B）。
- 顶部：`Toggle` 开关临时限流 + 配置项（百分比 / 兜底 / 阈值 / 窗口 / 重跑间隔 / TTL分钟），沿用 `SettingsView` 的保存模式（调 Part C 的 settings API）。
- **被限流用户列表（R8）：** 单独区块展示当前自动限流名单（调 `GET /api/v1/admin/abuse/throttled`，显示 user_id / 命中维度 / 命中时间 / 剩余 TTL），配"立即清空"按钮。
- API client：`frontend/src/api/admin/abuse.ts`（沿用 `api/client.ts` 的 axios + Bearer 拦截器）。
- i18n：`frontend/src/i18n/locales/zh.ts` 与 `en.ts` 同步加 `admin.abuse.*`。

参考实现：
- 表格 + 批量选择 `views/admin/AccountsView.vue`、`components/common/DataTable.vue`
- 开关 `components/common/Toggle.vue`、设置保存 `views/admin/SettingsView.vue`
- 风控页风格 `views/admin/RiskControlView.vue` + `api/admin/riskControl.ts`

---

## 验证

- 后端：
  - repo 用 sqlmock 测聚合查询；
  - **Part A 防回归（R 区 NULL 语义）：** 构造含空 `device_id` / `client_fingerprint` 行的数据集，断言聚合不把它们计入团伙；
  - `checkRPM` 缩放逻辑单测（命中 / 未命中 / 无限额兜底 / `override==0` 不兜底 / fail-open）；
  - **R1：** `BulkUpdateUsers` 成功后对每个受影响 user_id 调用了 `InvalidateAuthCacheByUserID`（mock invalidator 断言调用）；
  - **R7：** admin 角色用户在批量禁用中被跳过、且出现在 `skipped_ids`；
  - **R2：** `SuspectThrottleSettings` getter 命中内存快照时不打 DB（缓存范式断言）；
  - settings getter/setter 测试；
  - 全部 `go test -tags unit`。
- `go build ./...` + `go vet` + 相关包 `go test -tags unit`。
- 迁移 150（若加 IP 复合索引）过 migration runner 校验（参照 147/149 的 `_notx` + `validateMigrationExecutionMode`）。
- 前端：手动验证表格多选 / 禁用 / 开关持久化 / 被限流列表与"立即清空"。

## 落地顺序

A（查询）→ B（批量禁用，含 R1 缓存失效 + R7 admin 跳过）→ C（限流：先 settings **走缓存范式 R2**，再注入 R3 三层缩放，再后台服务含 R4 交叉护栏 / R5 短 TTL / R8 审计列表）→ D（前端）。每步独立可测、可单独提交。

可选裁剪：若本期只想要展示 + 手动禁用，可先做 A + B + D，把 Part C（自动限流）推到下一期。注意：一旦 Part C 上线，R4 的交叉护栏不可省 —— 全自动 + IP 单维度会误伤 CGNAT 合法用户。

## 检测查询参考

> Part A（展示）跑下面三条；Part C（自动限流）只采纳 device/fingerprint **与 IP 的交叉**命中，IP 单维度结果仅用于展示（R4）。

```sql
-- device 维度
SELECT device_id, COUNT(DISTINCT user_id) AS users
FROM usage_logs
WHERE device_id IS NOT NULL AND created_at >= now() - interval '24 hours'
GROUP BY device_id HAVING COUNT(DISTINCT user_id) >= 3;

-- client_fingerprint 维度
SELECT client_fingerprint, COUNT(DISTINCT user_id) AS users
FROM usage_logs
WHERE client_fingerprint IS NOT NULL AND created_at >= now() - interval '24 hours'
GROUP BY client_fingerprint HAVING COUNT(DISTINCT user_id) >= 3;

-- ip 维度
SELECT ip_address, COUNT(DISTINCT user_id) AS users
FROM usage_logs
WHERE created_at >= now() - interval '24 hours'
GROUP BY ip_address HAVING COUNT(DISTINCT user_id) >= 3;
```
