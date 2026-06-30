# 上游同步合并报告 — merge/sync-1-merge

- 日期：2026-06-05
- 合并分支：`merge/sync-1-merge`（已推送至 origin，commit `fe0a8ecf`）
- 合并方向：`origin/1-merge`（上游，159 提交）→ 本地定制 `main`
- 合并基点（merge-base）：`63b0631a`
- 状态：冲突已全部解决，构建 / vet / 测试 / 前端类型检查全绿。**尚未合入 main，待手动测试后决定。**

---

## 一、合并概览

两分支自 `63b0631a` 分叉：

- `main` 领先 53 提交：本仓库定制功能（赠金系统、绑卡、多账户滥用检测、邮箱白名单、易支付自定通道等）。
- `origin/1-merge` 领先 159 提交：上游批量 PR 同步（OpenAI Codex 桥接重设计、usage 失败请求记录、user×platform 配额、易支付 trade_status 修复、Go 1.26.4 等）。

本质是一次上游同步合并。共 36 个文件冲突。

| 类别 | 数量 | 处理方式 |
|---|---|---|
| ent 自动生成代码 | 16 | `make generate` 从合并后 schema 重建 |
| wire 依赖注入（`wire_gen*`） | 4 | `go generate ./cmd/server` 重建 |
| 测试文件 | 10 | 多为构造函数并列参数 / gofmt 差异，机械合并 |
| 手写核心源码 | 7 | 人工解决，共 12 个冲突块 |

---

## 二、冲突解决要点

### 并列型（保留双方）
main 的 `giftEngine` / `DeviceID` / `ClientFingerprint` 与上游的 `userPlatformQuotaRepo` / `QuotaPlatform` 并存：
- `backend/internal/service/auth_service.go`（结构体字段 + 构造函数）
- `backend/internal/handler/user_handler.go`
- `backend/internal/service/wire.go` / `backend/cmd/server/wire.go`（provider + 后台服务 cleanup step）
- `backend/internal/service/gateway_service.go`（usage input 结构体字段）
- `backend/ent/schema/user.go`（`gifts` edge + `platform_quotas` edge 都保留）

### 三个逻辑冲突
1. **`backend/internal/handler/gateway_handler.go`** — usage 去重指纹的 body 来源：采用上游「用最终上游接受的 body 计算」修复，同时保留 main 的 `clientFingerprint` 埋点。
2. **`backend/internal/handler/openai_gateway_handler.go`** — 上游重构了 WS 账号槽位获取 / sticky 绑定。将 main 的 usage 上报埋点（含 `ClientFingerprint`）重新嫁接到上游新的 `OnComplete` hook（约 1455 行）。**这是本次合并最复杂、最需重点测试的一处。**
3. **`backend/internal/payment/provider/easypay.go`** — 采用上游多字段 `trade_status` 兜底判断（`resp.Status` 从 `int` 改为 `*int`）。将订单状态变量重命名为 `orderStatus`，避开与 main 的 HTTP `status`（来自 `postRaw`）命名冲突；保留 main 的 `postRaw` / `parseEasyPayJSONResponse`（HTML 错误诊断）基础设施。

### device_id 提取重构适配（贯穿改动）
上游为避免异步计费 worker 持有大请求体，从 `RecordUsageInput` 移除了 `ParsedRequest` 字段，导致 main 依赖它提取 device_id 的逻辑失效。

解决方案（符合上游设计意图）：
- 在 `RecordUsageInput` 新增标量字段 `MetadataUserID string`。
- handler 热路径将 `parsedReq.MetadataUserID` 拍成标量传入（Claude 两处 RecordUsage 调用点）。
- `RecordUsage` 内部用 `ParseMetadataUserID(input.MetadataUserID)` 解析出 device_id 再写库。

链路闭环已验证：handler 标量 → `RecordUsage` 解析 → `recordUsageCore` 写库（`gateway_service.go:9164`）。

### 前端
- **`frontend/src/views/user/UsageView.vue`** — 成本列：保留 main 的 `flex-col` 布局 + 赠金扣减行，并采用上游的 `(row.actual_cost ?? 0)` 空值安全修复（上游修过 `actual_cost` 为 null 导致整表空白的 bug）。

---

## 三、生成代码与依赖处理

- ent + wire 全部用 `go generate` 从合并后的 schema 重建。
- 踩坑记录：曾用 `git checkout main -- ent/` 误把上游的 `Group.ModelsListConfig` schema 改动一并回退，已修正为正确的 schema 合并集（上游 `group.go` / `user_platform_quota.go` + main 的 4 个 schema + 手工合并的 `user.go` 双 edge），重新生成后 `ModelsListConfig` 正常。
- 补了 `github.com/google/wire/cmd/wire` 的 go.sum 条目（wire 生成依赖）。
- `go mod tidy` 将 `github.com/aws/smithy-go` 正确归类为 indirect（确认无直接引用）。
- 修了一个冲突清单外的 `NewAuthService` 调用方：`backend/cmd/jwtgen/main.go`（补齐 giftEngine + userPlatformQuotaRepo 两个参数）。

### 数据库迁移：双轨编号（已评估，安全）
合并产生了同号迁移文件（142/143/144/145/147/148 各两个，main 与上游各一）。

迁移器机制：按**文件名**（非编号）排序执行，`filename` 作主键，`checksum` 防篡改，SQL 幂等（`IF NOT EXISTS`）。
- `142_user_gifts.sql` 与 `142_user_platform_quotas.sql` 互不依赖（都只依赖 `users` 表），排序执行安全。
- 编号重复在长期维护上不够干净，但因 `filename` 是迁移主键，**只能重命名尚未在任何环境应用过的文件**，需谨慎。本次未重命名。

---

## 四、自动化验证结果（全绿）

| 检查 | 结果 |
|---|---|
| 后端 `go build ./...` | ✅ |
| 后端 `go vet ./...` | ✅ |
| 后端全量 `go test ./...` | ✅ |
| repository 迁移回归测试 | ✅ |
| 前端 `vue-tsc -b` 类型检查 | ✅ |
| 工作树冲突标记 / 未合并路径 | ✅ 0 |

环境：Go 1.26.4（与上游 go.mod toolchain 一致）。

---

## 五、手动测试计划

自动化测试覆盖不到的部分，集中在「人工嫁接的逻辑点」与「上游 × 本地定制功能交叠区」。

### 🔴 最高优先级 — 人工改写过逻辑的地方

**1. OpenAI WebSocket（Codex）网关 + device_id/fingerprint 埋点**（本次最危险一处）
- [✅] 用 Codex/WS 客户端实跑请求，确认正常拿到响应（sticky 绑定、并发槽位、failover 走通）
- [✅] 查 `usage_logs` 表，确认这次 WS 请求的 `client_fingerprint` 字段**有值**（嫁接点最易漏填）
- [✅] 高并发连续请求同一会话，确认 sticky session 命中，且不会因槽位获取失败而 5xx

**2. 易支付订单状态查询**
- [ ] 走一笔真实订单：下单 → 回调 → 查单全流程，确认状态正确流转为已支付
- [ ] 测 main 的「自定」自由通道，确认没被上游改动覆盖
- [ ] 故意触发查单返回 HTML（非 JSON），确认 main 的错误诊断兜底仍生效

**3. Claude Code 多账户滥用检测（device_id）**
- [✅] 用 Claude Code 客户端发请求，查 `usage_logs.device_id` 字段**有值**
- [✅] 同终端切换多账号发请求，确认滥用检测的扫描/自动限流仍能识别（关联 Phase 3 已上线功能）

### 🟡 次高优先级 — 上游新功能，本地首次引入

**4. 用户×平台配额（user_platform_quota，全新功能）**
- [ ] 确认启动迁移时 `user_platform_quotas` 表成功建立
- [ ] 管理端给某用户某平台（anthropic/openai/gemini/antigravity）设日/周/月 USD 限额，跑到超限，确认被正确拦截
- [ ] 确认后台 `UserPlatformQuotaUsageFlusher` 正常启停，用量能落库

**5. usage 失败请求记录（上游新功能）**
- [ ] 故意制造一次上游失败请求（如无效 model），确认用户端 + 管理端用量明细能看到这条失败记录

**6. 用量明细前端展示**
- [ ] 用量明细页正常加载，有赠金扣减的记录显示「赠金抵扣 $x」行
- [ ] `actual_cost` 为 null 的失败请求记录不会让整表空白

### 🟢 验证性测试

**7. 数据库迁移（双轨编号）**
- [ ] 在**已有数据的预发库**上跑一次启动迁移，确认全部通过、无 checksum 报错（上线前最该验证的一步）

**8. Go 1.26.4 工具链**
- [ ] 确认构建 / CI 环境也是 Go 1.26.4，否则线上构建可能失败

---

## 六、后续动作建议

1. 按上述清单在预发环境完成手动测试。
2. 测试通过后，将 `merge/sync-1-merge` 合入 main 或开 PR。
3. （可选）若希望迁移编号干净，可将上游侧尚未应用的同号迁移文件重命名为后续编号 —— 仅限从未在任何环境应用过的文件。
