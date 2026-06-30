# 多账户滥用检测实现 — 第二轮评审（代码评审）

评审对象：review-1 的全部修订项 + Phase 3 实现代码（44 改 + 18 新，约 1250 行）。
评审方式：逐文件读源码，比对 [plan.md](./plan.md) 与 [review-1.md](./review-1.md) 的 R1–R8，运行后端 build/vet/单测与前端 typecheck。

结论：**实现质量高，review-1 的两个阻断项（R1/R2）和需补写的设计细节（R3/R4/R7）全部落实，R5/R6 优化项也已采纳。可以放行。** 未发现新的阻断级问题。下面只列核对结果与若干可选改进。

---

## 一、验证结果（全绿）

| 检查 | 结果 |
|------|------|
| `go build ./...` | exit 0 |
| `go vet -tags unit`（service / repository / handler/... / usagestats / migrations） | exit 0 |
| `go test -tags unit`（service / repository / handler / handler/admin / usagestats / migrations / server / routes / middleware） | 全 ok |
| 前端 `npm run typecheck`（vue-tsc --noEmit） | 通过 |

迁移 146–150 经 migration runner 校验（含 147/149/150 的 `_notx` CONCURRENTLY 模式）。

---

## 二、review-1 各条落实核对

### R1（阻断）批量禁用必须失效鉴权缓存 — ✅ 已修

[admin_service.go:916-922](../../../backend/internal/service/admin_service.go#L916) 在 `BatchUpdateStatus` 成功后，对每个 `target` 调 `InvalidateAuthCacheByUserID`。测试 [admin_service_bulk_users_test.go:58](../../../backend/internal/service/admin_service_bulk_users_test.go#L58) `TestAdminService_BulkUpdateUsers_InvalidatesAuthCache` 用 mock invalidator 断言 1/2/3 全部失效。

### R2（高）热路径设置改用缓存范式 — ✅ 已修

[setting_service.go:3893 `GetSuspectThrottleSettingsCached`](../../../backend/internal/service/setting_service.go#L3893) 采用 `atomic.Value` 快照 + `singleflight` + 60s TTL（错误时 5s 短 TTL，`ErrSettingNotFound` 时满 TTL 缓存默认值），与 `IsBackendModeEnabled` 范式一致；`Set` 时 `Forget` + 写穿刷新。`checkRPM` 命中内存快照时零锁零 DB。测试 `ThrottleDisabledSkipsRedis` 断言关闭时不查 Redis、`ThrottleNotSuspectIsZeroOverhead` 断言未命中零改动。

### R3（中）三层级联缩放语义 — ✅ 已补写并实现

[checkRPM](../../../backend/internal/service/billing_cache_service.go#L745) 三层分别处理：override>0 缩放、`override==0` 保持豁免（不缩放不兜底）、group>0 缩放、user 全局层缩放；`user.RPMLimit==0` 且命中名单时在 **user 层**套 `FloorRPM`，组层不重复兜底。六个分支均有专项测试（`ThrottleScalesUserLimit` / `ThrottleFloorForUnlimitedUser` / `ThrottleOverrideZeroStaysExempt` / `ThrottleScalesGroupLimit` / …）。`scaleRPMLimit` 缩放后下限为 1，避免缩成 0（=无限）。

### R4（中）IP 单维度自动限流护栏 — ✅ 已实现

[computeAutoThrottleUsers](../../../backend/internal/service/abuse_detection_service.go#L83)：自动名单只收 `IP ∩ (device ∨ fingerprint)`，IP 单维度仅供展示。展示接口（Part A）仍按 OR 返回全部维度，与「自动严于展示」一致。测试 `IPOnlyIsExcluded` / `DeviceIntersectIP` / `FingerprintIntersectIP` / `DeviceWithoutIPExcluded` / `AllThreeDimensions` 覆盖。

### R5（中）TTL 从 24h 降到几个周期 — ✅ 已采纳

默认 `TTLMinutes=30`、`IntervalMin=5`（[settings_view.go:496](../../../backend/internal/service/settings_view.go#L496)）—— 约 6 个检测周期，命中续期、停止后分钟级消散。误报代价从「一天」降到分钟级。

### R6（低）后台间隔进入配置 — ✅ 已加

`SuspectThrottleSettings.IntervalMin`（[settings_view.go:468](../../../backend/internal/service/settings_view.go#L468)）。`SuspectThrottleService` 固定 30s tick 唤醒、按 `IntervalMin` 判断是否到点，配置变更一个周期内生效。

### R7（低）跳过 admin 的实现方式 — ✅ 已实现（先查 role 再 UPDATE）

[admin_service.go:873-895](../../../backend/internal/service/admin_service.go#L873)：禁用时先 `GetRolesByIDs` 过滤 admin → 进 `SkippedIDs`，不存在的 id → `FailedIDs`，其余才 UPDATE。仅禁用动作启用该保护（启用 admin 无害，与单用户 `UpdateUser` 语义一致）。测试 `SkipsAdminUsers` / `ActivateSkipsRoleGuard` / `UnknownIDsFail` 覆盖。

### R8（低）自动动作可观测性 — ✅ 已实现

`SuspectMeta{Dimensions, MarkedAt}` 随每条名单落 Redis；`GET /admin/abuse/throttled` 列出当前限流用户 + 命中维度 + 剩余 TTL；`DELETE /admin/abuse/throttled` 一键清空。`List`/`Clear` 用 SCAN（200/批）而非 KEYS，避免阻塞。

### F1/F2/F3 事实偏差 — 均已对齐

- F1：handler 在 `handler/admin/` 子目录 —— 新代码即放于此（[abuse_handler.go](../../../backend/internal/handler/admin/abuse_handler.go)）。
- F2：迁移 150 注释明确「complements — does not replace」既有单列索引 `idx_usage_logs_ip_address`，复合索引用于覆盖 `COUNT(DISTINCT user_id)` 的 index-only 聚合。
- F3：handler 层 binding `oneof=active disabled`，service 层 `BulkUpdateUsers` 自带 status 白名单校验 + admin 保护，两层各自对应。

---

## 三、安全与正确性专项

- **SQL 注入**：`findSuspectGroupsForDimension` 用 `fmt.Sprintf` 仅插入**列名**，列名来自内部白名单 [suspectGroupDimensionColumn](../../../backend/internal/repository/usage_log_repo.go#L4528)（device_id/client_fingerprint/ip_address），所有用户值（时间窗、阈值、LIMIT）走 `$1..$4` 占位符。无注入面。
- **NULL 语义**：CTE 带 `WHERE %col IS NOT NULL`，空指纹/设备不会塌缩成巨型误报团伙。测试 `NullSemantics` 锁定。
- **fail-open 一致性**：`IsSuspect` 出错 → 打 warning 不限流（测试 `ThrottleLookupErrorFailOpen`）；RPM 计数 Redis 出错沿用既有 fail-open。功能默认 `Enabled=false`，全新安装零影响。
- **DI 无环**：`BillingCacheService.SetSuspectThrottle` 在 `ProvideSuspectThrottleService` 里后置注入，避免 SettingService/SuspectStore 与 BillingCache 的构造环。wire_gen 已重新生成并构建通过。
- **响应包络**：前端 axios 拦截器解包 `{code,message,data}`，`abuse.ts` 的类型直接对应内层 payload，类型一致。

---

## 四、可选改进（非阻断，可后续处理）

1. **O1（低）限流缺少用户可见反馈**：被 50% 限流后返回的仍是普通 `ErrUserRPMExceeded`（429），用户/客服无法区分「我被反多账户限流了」与「正常超速」。可在错误 metadata 里加一个标记位，或仅在管理端 `throttled` 列表自查。当前 R8 列表已能让管理员解释，够用。
2. **O2（低）`maybeRun` 的 `lastRun` 是单进程内存态**：多副本部署时每个实例各自按 `IntervalMin` 跑检测（互相重复，但 `Mark` 幂等、TTL 续期，无正确性问题，只是重复计算）。若将来要省，可加 Redis 分布式锁（参考已有 `SystemOperationLockService`）。单副本无影响。
3. **O3（低）gofmt — ✅ 评审中已顺手修复**：`abuse_detection_service.go`、`suspect_throttle_service.go`、`billing_cache_service.go` 三处对齐/空格不规范已 `gofmt -w`，包构建通过。
4. **O4（提示）窗口与 TTL 的关系**：`WindowHours` 默认 24h、`IntervalMin` 5min —— 每 5 分钟扫一次过去 24h 的 usage_logs。数据量大时该聚合查询成本值得上线后观察；已有 (dim,user_id) 复合分区索引支撑，预计可控，但建议上线后看一眼慢查询日志。

---

## 五、放行结论

- review-1 的 R1–R8 与 F1–F3 **全部落实**，且每条都有对应单测锁定行为。
- build / vet / 后端单测 / 前端 typecheck 全绿；SQL 无注入面；功能默认关闭、fail-open，上线风险低。
- 可选项 O1–O4 均非阻断，建议 O3 顺手 `gofmt`，其余按需。

**评审通过，可合并 / 进入联调。**
