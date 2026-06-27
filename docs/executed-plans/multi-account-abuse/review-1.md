# 多账户滥用检测计划 — 第一轮评审

评审对象：[plan.md](./plan.md)
评审方式：对计划引用的每一处代码位置（文件/行号/可复用模式）做实地核对，并对四个 Part 的设计正确性做交叉验证。
结论概览：**方向正确、引用基本属实，可进入实现阶段；但有 2 个必须先解决的正确性问题（R1、R2），以及若干需要在动手前明确的设计细节。**

---

## 一、事实性核对结果

计划里引用的文件、行号、可复用模式**绝大多数属实**，下面只列出与计划描述不一致或需要补充的地方。其余（Part A 的 `GetStatsWithFilters@3534`、`GetDailyStatsAggregated@1983`、Part C 的 `RateLimit429CooldownSettings@447`、`IdempotencyCleanupService`、`wire.go@340`、`checkRPM@711`、`user_rpm_cache` 的 `rpm:ug`/`rpm:u`、Part D 全部前端引用）均已核实**与计划一致**。

| # | 计划描述 | 实际情况 | 影响 |
|---|---------|---------|------|
| F1 | Part B 引用 `account_handler.go: BulkUpdate`、`user_handler.go:57` | 实际路径在 **admin 子目录**：[backend/internal/handler/admin/account_handler.go:1412](../../../backend/internal/handler/admin/account_handler.go#L1412)、[backend/internal/handler/admin/user_handler.go:57](../../../backend/internal/handler/admin/user_handler.go#L57) | 仅路径不精确，模式属实 |
| F2 | Part A：「IP 维度按需补一条 `_notx` 索引（迁移 150）」 | 已存在单列非分区索引 `idx_usage_logs_ip_address`（[migrations/031_add_ip_address.sql](../../../backend/migrations/031_add_ip_address.sql)）；最高迁移号确为 149，150 可用 | 新建 `(ip_address, user_id)` 复合分区索引仍有价值（覆盖 `COUNT(DISTINCT user_id)`），但计划应说明它是**补充**已有单列索引，而非「IP 没有索引」 |
| F3 | Part B 状态校验「复用 `UpdateUser` 的 status 校验」 | handler 层是 binding 标签 `oneof=active disabled`（user_handler.go:57）；service 层 `UpdateUser@706` 另有手写检查 `role=="admin" && status=="disabled"` → 拒绝（admin_service.go:722） | 两处校验位置不同，Part B 需各自对应（见 R7） |

**一个正面确认（消除了一个潜在隐患）：** `device_id` 与 `client_fingerprint` 入库时都经过 `optionalTrimmedStringPtr`（[usage_log_helpers.go:5](../../../backend/internal/service/usage_log_helpers.go#L5)），空值落 `NULL` 而非 `""`。因此 Part A 的 `WHERE device_id IS NOT NULL GROUP BY ...` **不会把所有空值塌缩成一个巨型误报团伙** —— 这一点计划没写明，但代码层面已经成立。

---

## 二、必须先解决的正确性问题

### R1（阻断级）批量禁用必须同步失效鉴权缓存，否则禁用不即时生效

计划 Part B 直接镜像 `BulkUpdateAccounts`，但**漏了鉴权缓存失效**这一步。

- API Key 鉴权路径的用户状态来自 L2 缓存快照（[api_key_auth_cache_impl.go](../../../backend/internal/service/api_key_auth_cache_impl.go)），默认 **`l2_ttl_seconds: 300`**（[config.go:1712](../../../backend/internal/config/config.go#L1712)）。
- 现有单用户路径 `UpdateUser` 改完状态后**显式调用** `s.authCacheInvalidator.InvalidateAuthCacheByUserID(...)`（[admin_service.go:778](../../../backend/internal/service/admin_service.go#L778)）。
- 如果 `BulkUpdateUsers` 只发一条 `UPDATE` 就返回，被禁用的用户在 API Key 路径上**最长还能正常调用约 5 分钟**（直到快照过期）。对一个「一键封禁农场」的功能，这个延迟会被滥用者利用。

**要求：** `BulkUpdateUsers` 在 UPDATE 成功后，对每个受影响 user_id 调用 `InvalidateAuthCacheByUserID`（接口见 [api_key_auth_cache_invalidate.go:15](../../../backend/internal/service/api_key_auth_cache_invalidate.go#L15)）。计划需把这一步写进 Part B 的服务层步骤，并补一条对应单测。

### R2（高）Part C「关闭时零开销」的前提不成立，会给最热路径加 DB 往返

计划让 `checkRPM` 每请求先查「限流开关是否开启」，并声称「开关关时连 Redis 都不查、零额外开销」。但计划选的镜像对象 `GetRateLimit429CooldownSettings` **每次都打 DB**（`settingRepo.GetValue`，[setting_service.go:3827](../../../backend/internal/service/setting_service.go#L3827)），没有任何缓存。照此实现，`checkRPM`（网关最热路径）在功能**关闭时也会**每请求多一次 DB 往返。

项目里已有正确的「热路径读设置」范式：内存 `atomic.Value` 快照 + `singleflight` + 60s TTL、命中时零锁。参考 `IsBackendModeEnabled`（[setting_service.go:2007](../../../backend/internal/service/setting_service.go#L2007)）与 `getGatewayForwardingSettingsCached`（[setting_service.go:2056](../../../backend/internal/service/setting_service.go#L2056)）。

**要求：** `SuspectThrottleSettings` 的 getter 必须走带缓存的范式（而不是 `RateLimit429Cooldown` 那套裸 DB 读）。这样「开关关 → 命中内存快照 → 直接返回、不查 Redis」才真正成立。计划的 Part C §1 应把参考对象从 `RateLimit429CooldownSettings` 改成上面两个缓存范式之一。

---

## 三、需要在动手前明确的设计细节

### R3（中）`checkRPM` 是三层级联，计划只描述了两层

计划说「对 group / user 两层 limit 按 RatePercent 缩放」，但实际级联有**三个输入**（[billing_cache_service.go:716-781](../../../backend/internal/service/billing_cache_service.go#L716)）：
1. per-user-group **override**（可为 0 = 该组内豁免）
2. `group.RPMLimit`
3. `user.RPMLimit`（**硬上限**，与前两层叠加，不被覆盖）

需明确：
- override 这一层是否也缩放？
- `override == 0` 当前语义是「该组内豁免」。缩放/兜底逻辑**不能把一个有意的豁免（0）误判成 30rpm 兜底**，除非这正是想要的行为 —— 需要显式说明。
- `user.RPMLimit` 是叠加的硬上限：当 group override=1000、user.RPMLimit=0（无限）的疑似用户被限流时，FloorRPM 到底套在哪一层、最终 effective 取哪个，要写清楚分支。

建议在 Part C §3 用伪代码把三层各分支（override>0 / override==0 / group>0 / 各层==0）逐一列出缩放后的 effective 值。

### R4（中）IP 单维度自动限流的误报风险，与计划自己的设计原则冲突

计划的设计原则写明「真正的力量在 device_id ∩ IP ∩ client_fingerprint **三向交叉**」，但 Part A / Part C 实际把三个维度当成**独立的 OR**（任一维度 `COUNT(DISTINCT user_id) >= N` 即入团伙）。其中 **IP 单维度**最危险：企业 NAT、运营商 CGNAT、同一住所、VPN 出口都会让大量**正常用户**共享一个 IP，轻易突破 N=3。

而 Part C 是**全自动**禁用/限流、无人工复核。IP 单维度直接进自动名单，会误伤合法 CGNAT 用户。

**建议：** 自动限流（Part C）的入选规则应**严于**展示（Part A）。具体可选：
- 自动名单只采纳 `device∩IP` 或 `fingerprint∩IP` 的交叉命中，IP 单维度仅用于**展示**（Part A）供人工判断；
- 或对 IP 维度设更高阈值 / 显式排除已知 NAT 段。

这条同时呼应计划末尾「可选裁剪：先做 A+B+D，把 C 推后」——若 C 要上，交叉护栏不能省。

### R5（中）24h 固定 TTL × 全自动名单，会放大误报的代价

`throttle:suspect:{userID}` 单条 EXPIRE 默认 24h，而后台每 N 分钟重跑检测。对**仍在活动**的农场，重跑会不断刷新 TTL（合理）。但一次误判（见 R4）意味着该用户被**整整限流 24h**、无自动恢复，且无人工在环。

**建议：** 既然检测循环会反复重判，TTL 不必设到 24h —— 设为「几个检测周期」即可（命中则下一轮自动续期，行为停止则很快自然消散）。这样误报的代价从「一天」降到「分钟级」。

### R6（低）后台服务的运行间隔未进入配置

`SuspectThrottleSettings` 有 `MinUsers`、`WindowHours`，但**没有「每隔几分钟跑一次」的间隔字段**，而 Part C §2 又说「每隔 N 分钟跑一次」。需要把间隔加进 settings（或在服务里写死并注明默认值），否则 N 无处配置。

### R7（低）Part B 跳过 admin 用户无法用「一条盲 UPDATE」实现

计划要求「服务层过滤 role=admin 并在结果里标注跳过」。但 `UPDATE users SET status WHERE id = ANY($1)` 是一条盲写，**无法同时**做到「跳过 admin」+「报告被跳过的 id」。需二选一：
- 在 WHERE 加 `AND role <> 'admin'`，再用 `requested - affected` 反推被跳过集合；或
- 先按 id 批量查出 role，过滤后再 UPDATE，结果里明确标注 skipped。

这点与 `BulkUpdateAccounts` 不是 1:1（账户没有 role 概念），计划需单独说明实现方式。

### R8（低）可观测性：自动动作缺审计

Part C 全自动限流，目前只在 Redis key 留痕。对一个会**自动限制付费用户**的功能，建议提供管理员可见的「当前被限流用户列表 + 命中维度 + 命中时间」（前端「立即清空」本就需要一个列表视图）。否则客服无法解释「我为什么被限速」。

---

## 四、测试建议（补充计划已列项）

计划的验证清单已覆盖 repo sqlmock、`checkRPM` 缩放、settings getter/setter。补充三项与上面问题对应的测试：
- **R1 对应：** `BulkUpdateUsers` 成功后对每个 user_id 调用了 `InvalidateAuthCacheByUserID`（用 mock invalidator 断言调用）。
- **R7 对应：** admin 角色用户在批量禁用中被跳过、且出现在 skipped 结果里。
- **Part A 防回归：** 构造含空 `device_id`/`client_fingerprint` 行的数据集，断言聚合查询不会把它们计入团伙（锁住 R 区那条 NULL 语义）。

---

## 五、结论与放行建议

- 计划调研扎实、引用可靠，**目标维度（User 而非 Account）判断正确**，落地顺序（A→B→C→D，C 可裁剪）合理。
- **进入实现前必须修订：R1（鉴权缓存失效）、R2（热路径设置改用缓存范式）** —— 这两条不解决会分别导致「禁用不生效」和「关闭功能仍拖慢全网关」。
- **建议在计划文档里补写清楚：R3（三层级联语义）、R4（IP 单维度自动限流护栏）、R7（跳过 admin 的实现方式）**。
- R5、R6、R8 为优化项，可在实现中一并处理。

修订上述条目后，可进入第二轮评审或直接开工 Part A。
