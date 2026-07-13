# 赠金子系统 — 赠金权益绑定分组（group-scoped gift）

状态：**已实施并通过 cx-s2 code review（2026-07-13）。分支 feat/group-scoped-gift，PR #56。**
设计评审：基线六轮 APPROVE + 两个新功能 delta 四轮 APPROVE + 实现后 code review（见 §八）。
方向：推翻"锁 key 分组"旧方案，改为把权益约束落在**赠金**上。
日期：2026-07-13

## 〇、方向的纠偏（重要）

最初需求被表述为"领取后固定 key 的分组"，据此设计了 `group_locked` 锁 key 分组方案
（见文末「废弃方案」）。经排查代码，用户与 AI 共同确认该方向是**错的**：

- **请求走哪个分组，唯一由 `apiKey.GroupID` 决定**（已核实：所有 gateway handler
  直接透传 `apiKey.GroupID`，无任何客户端 header/query 可覆盖）。
- **赠金子系统全链路零 group 维度**（已核实：`user_gifts` 表字段无 group；
  `GrantInput`、`allocator.go`、`engine.go`、`repository.go` grep "group" 零命中）。
  赠金一旦发放就是账户余额里一笔**无差别的钱**，在任何分组消费都一样扣。

因此"锁 key 分组"锁住的只是**这一把 key** 的定价通道，拦不住用户**另建一把 key**
去别的分组花**同一笔账户赠金**——它是"凭证隔离"的有漏洞替身，而非"权益隔离"。

**真需求**（用户确认）：**"如果这把 key 带有分组设置，就是希望用户只能在这一个分组里
消费。"** 约束的对象是**赠金（权益）本身**，不是用户对分组的整体访问权。

**正确做法**：给赠金打 group 标签，扣费/preflight 只在"当前请求分组 == 赠金分组
（或赠金无分组）"时才动用该赠金。key 层完全不用管。

## 一、已锁定的产品决策

1. **约束强度**：只约束**赠金**。用户自己的充值余额不受限，去别的（有权限的）分组照常
   花自己的钱。（不做整体 access-control / `user_allowed_groups` 级限制。）
2. **分组删除**：一笔绑定分组 X 的赠金，若 X 之后被管理员删除 → **该赠金转为全局可用**
   （`group_id` 置 NULL）。不作废、不冻结。
3. **兼容存量**：`user_gifts.group_id` 为 nullable，**NULL = 全局通用**（任意分组可花）。
   历史赠金 group_id 默认 NULL，行为不变，零回归，不做 backfill。
4. **扣费顺序**（"每模式内分组专属优先"）：
   `priority-分组专属 > priority-全局 > ratio-分组专属 > ratio-全局`。
5. **充值折扣赠金（SourceRechargeDiscount）分组归属 = 全局（Option B，用户拍板）**：
   绑分组 key 领取后，该用户命中"绑定 key 充值折扣"再发的那笔赠金**不锁分组**，任意组可花。
   理由：折扣赠金是"充值行为"赚来的新钱，不属于 key 本身携带的权益，全局更符合直觉。
   （对应 cx-s2 R4 #3；实现上 `GrantInput.GroupID=nil`，不新增列、不做 claim-time 固化。）

## 二、链路事实（已全部核实）

| 环节 | 位置 | 现状 | 改造 |
|---|---|---|---|
| 请求分组来源 | 所有 gateway handler | 唯一 = `apiKey.GroupID`，不可被客户端覆盖 | 无需改，天然可信；作为唯一 scope 源 |
| 赠金发放 | `keybind.Commit` → `GrantForBindKey`(balance.go:104) → `Engine.Grant`(engine.go:43) | `GrantInput` 无 GroupID；Grant 自持事务 | 加 `GroupID *int64`；锁+落列在 Grant 事务内 |
| 扣费构造 | `gateway_service.go:8959 buildUsageBillingCommand` | 作用域内有 `p.APIKey.GroupID` | 赋给 cmd |
| 扣费命令 | `service.UsageBillingCommand`(usage_billing.go:16) | 有 UserID 无 GroupID | 加 `GroupID *int64` + 指纹版本 |
| 扣费入口 | `usage_billing_repo.go:123 AllocateAndDeductWithBreakdown` | 只传 userID/cost | 传 groupID |
| 锁读快照 | `gift/repository.go lockedSnapshot` | `WHERE user_id AND active` | 锁**全部** active 赠金，Go 内按组切分 |
| 分摊算法 | `gift/allocator.go Allocate` | 纯函数 | **要改**：加 `IneligibleGiftRemaining` 字段 |
| preflight 拦截 | `billing_cache_service.go:975 checkBalanceEligibility` | userID-only，且 nil/err 时 fail-open | group-aware + **非 simple 模式 fail-closed** |
| 上层 preflight | `CheckBillingEligibility`(:774) | 已持有 `apiKey *APIKey` 与 `group *Group` | 用 **apiKey.GroupID**（非 group.ID）往下传 |
| gateway 兜底扣费 | `postUsageBilling`(gateway_service.go:8862) 直调 `userRepo.DeductBalance`(:8878) | 绕过赠金引擎，void 吞错 | 改走 group-aware 引擎 + 返回 error |
| 两个 gateway | `NewGatewayService`(:660) / `NewOpenAIGatewayService`(:383) 各建 billingDeps | 均无 giftEngine | 两侧对称注入 giftEngine 硬依赖 |
| 分组删除 | `DeleteCascade`(group_repo.go:568, 持 groups FOR UPDATE) / 裸 `Delete`(:214, 无事务) | 均不清 user_gifts | 两路径锁 groups 行后清赠金再软删，单事务 |
| 折扣赠金 | `payment_recharge_discount.go:283` | 全局发放 | 保持全局（Option B）+ 加显式测试 |
| 幂等指纹 | `usage_billing.go:54 buildUsageBillingFingerprint` + dedup 表比对(usage_billing_repo.go:85/100) | 无 group 维度 | 加 group（v2）+ 持久化版本列 + 两阶段发布 |

## 三、实施设计（cx-s2 六轮评审后的终稿）

### 3.1 Schema / 迁移
- `backend/ent/schema/user_gift.go`：加 `field.Int64("group_id").Optional().Nillable()`
  + `index.Fields("user_id", "group_id")`（扣费快照）**+ 单独 group_id 前导偏索引**
  （分组删除按 `WHERE group_id=$1` 查，`(user_id,group_id)` 复合索引无法高效服务此查询
  —— cx-s2 实现注）。`go generate ./ent`。
- 迁移 `177_user_gifts_group_id.sql`：
  ```sql
  ALTER TABLE user_gifts ADD COLUMN IF NOT EXISTS group_id BIGINT NULL;
  CREATE INDEX IF NOT EXISTS user_gifts_user_id_group_id ON user_gifts (user_id, group_id);
  CREATE INDEX IF NOT EXISTS user_gifts_group_id ON user_gifts (group_id) WHERE group_id IS NOT NULL;
  COMMENT ON COLUMN user_gifts.group_id IS 'Optional group this gift is restricted to. NULL = usable in any group.';
  ```
  不加外键（分组软删走应用层置 NULL，见 3.5；外键对软删无意义）。

### 3.2 发放（Grant）带 group —— 锁与落列都在 Grant 事务内（cx-s2 R3 #2 / R4 S10）
- `gift.GrantInput` 加 `GroupID *int64`；`keybind.UserBalanceUpdater.GrantForBindKey`
  透传 `poolKey.GroupID`；`Commit` 传池 key 的分组。
- **关键：keybind.Commit 不是事务**；`Engine.Grant`(engine.go:43) 才是事务边界
  （joins ambient tx via `TxFromContext`，否则自开短事务）。所以把
  "锁 groups 行 + 删组降级 + 插 gift + 加 balance"全部放进 `insertGiftWithBalance`
  （已在 Grant 事务内）：
  - `in.GroupID != nil`：先 `SELECT id FROM groups WHERE id=$grp AND deleted_at IS NULL
    FOR UPDATE`（与 DeleteCascade 抢同一把行锁）：
    - 组还在 → 落 `group_id = grp`。
    - 组已软删（删除赢了竞态）→ 落 `group_id = NULL`（转全局，与 §一.2 一致）。
  - `in.GroupID == nil` → 直接全局插入，不加锁。
- **不合并 transfer 与 grant**：keybind.Commit 保持现有"grant 失败不回滚 transfer"的
  best-effort 语义。需要的序列化（grant vs 删组）完全落在 Grant 事务内，与 transfer 无关。
- **claim-time pin 保留（S6）**：ownership-transfer 的 `UPDATE ... WHERE group_id =
  poolKey.GroupID`，affected==0 → 复用 `ErrPoolKeyAlreadyClaimed` 重试。保证转移的 key
  行与传给 Grant 的组一致。
- **锁序无死锁**：Grant 路径 = 先锁 groups 行、再 INSERT 自己的新 gift 行（不锁既有 gift）；
  DeleteCascade = 先锁 groups 行、再 UPDATE 既有 gift 行；两者都 groups-first，唯一共享对象
  是那一 groups 行 → 无环。billing 的 AllocateAndDeduct 锁 user→gifts、从不碰 groups 行，
  也不会与二者死锁。
- 其他发放来源（promo/oauth/recharge_discount/referral/admin-grant）默认 `GroupID=nil`
  → 全局，行为不变（折扣赠金按 §一.5 明确全局）。

### 3.3 扣费：锁全部赠金、算全局充值池、只对可用子集分摊（cx-s2 R2 #1/#2/#3 → R2 S3′）
> 修正早期"allocator 不改"的错误表述：allocator **要改**（加一个字段 + 一处减法）。

- `UsageBillingCommand` 加 `GroupID *int64`；`buildUsageBillingCommand` 赋 `p.APIKey.GroupID`。
- `Engine.AllocateAndDeduct[WithBreakdown]` + `AllocateAndDeductSimple` 签名加 `groupID *int64`。
- `lockedSnapshot`：锁用户行后，`SELECT ... FROM user_gifts WHERE user_id=$1 AND
  status='active' AND (expires_at IS NULL OR expires_at>NOW()) FOR UPDATE` ——
  **WHERE 里不加 group 过滤，锁全部 active 赠金**（全局充值池依赖全部赠金求和，
  且保证 ratio 分摊快照一致）。ORDER BY 加组维度②让可用子集"分组专属先于全局"：
  ```sql
  ORDER BY CASE deduction_mode WHEN 'priority' THEN 0 ELSE 1 END,   -- ① priority 先于 ratio
           CASE WHEN group_id IS NOT NULL THEN 0 ELSE 1 END,        -- ② 【新增】分组专属先于全局
           ratio_recharge ASC NULLS LAST, expires_at ASC NULLS LAST, id ASC
  ```
- Go 内按请求组切分锁到的行：
  - `eligible` = `group_id IS NULL OR group_id = reqGroup`（按上面顺序）；
  - `ineligibleRemaining` = Σ(其余行 remaining)。
- Allocator 改动：
  - `AllocateInput` 加 `IneligibleGiftRemaining decimal.Decimal`；`Gifts` 只装 eligible 子集。
  - `rechargePool = TotalBalance.Sub(Σeligible).Sub(IneligibleGiftRemaining)`
    = `balance − Σ(全部赠金)` = **真·全局充值池**。其余 priority→ratio→pool 三阶段不变。
  - 不变量守恒：扣费后 `new_balance = new_rechargePool + Σ(new eligible) + Σ(ineligible)`；
    ineligible 行不动；`users.balance` 只降 totalCost。
- 例（cx-s2 R1 #1）：balance 100、A 组 priority 赠金 remaining 100、请求在 B。
  锁到 [A-gift]；eligible=[]、ineligibleRemaining=100 → rechargePool = 100−0−100 = 0
  （不是 100）。A 组赠金无法在 B 组被花掉。

### 3.4 preflight：全局充值池 + 组过滤 priority 兜底 + 非 simple 模式 fail-closed
（cx-s2 R2 #2 / R3 #2 / R5 #2）
- **scope 唯一来源 = `apiKey.GroupID`（非 `group.ID`）**：`group` 可能为 nil（软删/关系
  未加载）而 `apiKey.GroupID` 非 nil；用 group.ID 会与扣费路径的 apiKey.GroupID 错位。
  `CheckBillingEligibility`(:774) 已同时持有 `apiKey` 与 `group`，取 `apiKey.GroupID`
  往下传给 `checkBalanceEligibility(ctx, userID, reqGroupID)`。
- `GetGiftBalance(ctx,userID)` **保持全局**（Σ 全部 active 赠金），供全局充值池公式；
  **只有 `HasActivePriorityGift(ctx,userID,groupID)` 变 group-aware**
  （存在 active priority 且 `group_id IS NULL OR = groupID`）。
- 判定公式：
  - `rechargePool = balance − GetGiftBalance(全局)`。>0 → 放行（真金，任意组）。
  - ≤0 → 仅当 `HasActivePriorityGift(userID, reqGroup)` 才放行。
- **fail-closed（S15）**：非 simple 模式下——
  - `priorityGiftChecker == nil` → 返回 `ErrBillingServiceUnavailable`（硬依赖违约，
    不再退化 balance-only）；
  - `GetGiftBalance` 出错 → 返回 `ErrBillingServiceUnavailable.WithCause(err)`
    （与既有 GetUserBalance 失败分支一致），**不**退化 balance-only。
  - 理由：balance 含 ineligible 赠金，balance-only 放行会重演 §3.3 要防的透支。
  - simple 模式：`CheckBillingEligibility` 顶部照旧短路，全跳过。

### 3.5 分组删除 → 赠金转全局，两路径都锁 groups 行后单事务清（cx-s2 R2 #6 / R3 #1）
- `DeleteCascade`(group_repo.go:568)：已持 `SELECT id FROM groups WHERE id=$1 AND
  deleted_at IS NULL FOR UPDATE`(:592)。在该事务内、软删 group 前加
  `UPDATE user_gifts SET group_id=NULL WHERE group_id=$1`（幂等），紧挨现有
  user_allowed_groups / account_groups 级联步骤。
- 裸 `Delete`(group_repo.go:214)：现为单条 ent delete、无事务。改写为
  开事务 → `SELECT id ... FOR UPDATE` → `UPDATE user_gifts SET group_id=NULL WHERE
  group_id=$1` → 软删 group → commit。（该路径仅 `GroupService.Delete` 触达、未注入任何
  handler → 当前不可达，但对称加固，杜绝潜在悬挂 scope。）
- 因 grant（3.2）与两删除路径都 groups-first 抢同一行锁 → grant 与删组严格串行化，
  任何交错都不会留下指向已删组的赠金。

### 3.6 幂等指纹加 group + 持久化版本 + 两阶段发布（cx-s2 R4 #3 / R5 #1 / R6 S14）
- `UsageBillingCommand` 加 `GroupID *int64`（源自 apiKey.GroupID）与指纹版本；
  `buildUsageBillingFingerprint` 增版本参（或 v1/v2 两函数），v2 公式把 group 纳入 hash。
- **持久化版本列**（不靠 hash 前缀猜版本 —— stored 只是 64 位 SHA-256）：迁移给
  `usage_billing_dedup` 与 `usage_billing_dedup_archive` 各加
  `fingerprint_version SMALLINT NOT NULL DEFAULT 1`。比对时连版本一起读：
  stored=1 → 用 legacy v1 公式（无 group）重算比对；stored=2 → 用 v2 公式比对。
- **两阶段滚动发布**（避免混版单向不兼容：新实例能读 v1，但旧实例读不懂 v2 会误判冲突）：
  - Phase 1（本 PR，先全量部署）：加版本列 + 上线**版本感知的 reader**，但**仍写 v1**
    （group 不进 hash），由**默认关闭**的开关控制。新旧实例都写/比 v1，行为零变化。
    注意：**计费的 group 隔离（3.3/3.4）不依赖指纹**，只有 dedup 身份依赖 → 隔离已生效。
  - Phase 2（确认全体实例都已是 Phase-1 代码后，翻开关）：启用 v2 写（group 进 hash，
    version=2）。此时已无 v1-only reader，v2 行只会被 v2-aware 实例读。
  - 开关 config-backed、默认 false（cx-s2 实现注）。
- **archive mover 同步带版本**（cx-s2 实现注）：`dashboard_aggregation_repo.go:244`
  的归档搬运（INSERT…SELECT）两侧都要带上 `fingerprint_version`；补 schema 测试。
- 说明：group 进指纹只防"同一 request_id/api_key_id 的请求在重试之间被改组"这种罕见场景；
  两阶段开关让这种场景也无需停机窗口即可安全。

### 3.7 gateway 兜底扣费 fail-closed + 两个 gateway 对称注入（cx-s2 R2 #4 / R4 #2 / R5 #3）
- `billingDeps` 加 `giftEngine *gift.Engine`；`NewGatewayService`(:660) 与
  `NewOpenAIGatewayService`(:383) **两个构造器都**加 `*gift.Engine` 参并在各自
  `billingDeps{}`(:9231 / :546) 处填充。
- **构造期硬校验**：`RunMode != simple` 且 `giftEngine == nil` → 启动即失败（构造器返回
  error / boot panic），从根上杜绝"计费启用却缺引擎"。
- `postUsageBilling`(:8862) 改为**返回 error**；非订阅分支去掉直调 `userRepo.DeductBalance`,
  改走 `giftEngine.AllocateAndDeductSimple(billingCtx, userID, p.APIKey.GroupID, ActualCost)`
  （group-aware，scope 源与主路径一致），其 error 上抛而非仅 slog。
- `applyUsageBilling`(:9016, 返回 `(bool,error)`) 的兜底调用处(:9023) 改为
  `return true, postUsageBilling(...)`；运行期 giftEngine 若仍为 nil → 返回计费错误
  （fail closed），**绝不**退化直扣。直扣路径从非订阅分支彻底移除。
- **重要（cx-s2 实现注）**：兜底扣费**提交之后**的附属 best-effort 失败（更新 key quota /
  rate-limit / account quota 等）**不得**冒泡成"可重试的计费错误"，否则重试会重复扣费。
  附属失败仍按现状 slog 吞掉，只有"扣费本身"的错误才上抛。
- Wire 重生成（`go generate ./cmd/server`）；`*gift.Engine` 已是 Wire provider
  （usage_billing_repo 在用），图能解析；提交 wire_gen.go。

### 3.8 展示层：全局/仅限分组 列（功能①，cx-s2 delta APPROVE）
> "我的赠金"页每行**右侧**加一列，表明该赠金是全局还是仅限某分组。

- **DTO（`gift.UserGift` + `giftListItem` + `GiftDisplayItem` 三处都加）**：
  - `gift.UserGift`(types.go:63) 加 `GroupID *int64` / `GroupName string`
    （功能②另加 `Pinned bool`，见 §3.10）。
  - `GiftDisplayItem`(types.go:55) 加 `GroupID *int64` / `GroupName string`（供 Profile 卡；
    **不加** id/pinned —— 那里无按钮）。
  - handler `giftListItem`(user_handler.go:139) 用**显式 JSON tag**统一响应形状（cx-s2 D8）：
    `GroupID *int64 json:"group_id,omitempty"`、`GroupName string json:"group_name,omitempty"`、
    **`IsGlobal bool json:"is_global"`（恒输出，前端据此统一渲染列）**。
    **`IsGlobal` 严格由 `GroupID == nil` 推导，不看 group_name 是否为空**（cx-s2 实现注）。
- **查询带出 group 名（cx-s2 D4/D7）**：`listGiftsByUserWithSort`(repository.go:415) 与
  `getGiftByID`(:474) 两处 SELECT + `listActiveGiftsForDisplay`(:244)——
  - **user_gifts 一律别名 `ug`**；共享的动态 `where` 与 COUNT(:433) 全部 `ug.` 限定
    （加 JOIN 后 id/status/created_at/updated_at/expires_at 都会 ambiguous）。
  - SELECT 加 `LEFT JOIN groups grp ON grp.id = ug.group_id AND grp.deleted_at IS NULL`,
    取 `COALESCE(grp.name,'')`。COUNT 不需 join。
  - `scanUserGift`(:493) 加 3 个扫描目标：`ug.group_id`（**用 `sql.NullInt64`**，cx-s2 实现注）、
    group_name、pinned；一次改覆盖两个 caller（列数必须对齐）。
- **前端 `UserGiftsView.vue`**：卡片右侧标签列 —— `is_global` 为 true 显示"全局"
  （**用主题默认文字色/黑色，不带色；灰色会被误认为 disabled** —— 用户要求），
  否则显示"仅限分组 {group_name}"（带色）。i18n zh/en。
- **Profile 卡**（`ProfileInfoCard.vue`）同样展示全局/分组标注（NULL=全局）。

### 3.9 接口 churn（更新 stub/mock，CLAUDE.md 强制）
- `gift.Engine`：`GrantInput.GroupID`；`AllocateAndDeduct[WithBreakdown]` /
  `AllocateAndDeductSimple` 加 groupID；allocator `AllocateInput.IneligibleGiftRemaining`。
- `priorityGiftChecker`：`HasActivePriorityGift` 加 groupID（`GetGiftBalance` 保持全局，
  不变签名）。
- `UsageBillingCommand` 加 `GroupID` + 指纹版本。
- `keybind.UserBalanceUpdater.GrantForBindKey` 加 groupID。
- 两个 gateway 构造器签名加 `*gift.Engine`；billingDeps 加字段。
- **功能②置顶**：`ActiveGift.Pinned`；`gift.UserGift.Pinned`；`giftListItem` 加
  `ID int64 json:"id,omitempty"`（gift id 恒为正，legacy 分支 id=0 被 omit 安全）
  + `Pinned bool json:"pinned"`（**不 omitempty，恒输出**）；新增 repo `PinGift`/`UnpinGift`
  与 handler 路由；allocator `Allocate` 加 Stage 0。
- `grep -r "type.*Stub\|type.*Mock" backend/internal/` 全量更新；两个 gateway 构造器测试
  传入（stub）engine。

### 3.10 置顶赠金（功能②，cx-s2 delta APPROVE，语义=绝对第一）
> 每行加"置顶"按钮，可置顶一条**未过期**赠金；只要满足使用条件即**第一个**被消费。
> 至多置顶一条；已置顶行显示"取消置顶"。置顶的若是限制分组的、而当前请求不在该组，则忽略。

- **Schema/迁移**（并入 177 或兄弟迁移 178）：`user_gifts` 加
  `pinned BOOLEAN NOT NULL DEFAULT false`；部分唯一索引在 DB 层保证一人至多一条置顶：
  `CREATE UNIQUE INDEX IF NOT EXISTS user_gifts_one_pin_per_user ON user_gifts (user_id)
   WHERE pinned;`（**IF NOT EXISTS**，cx-s2 D6）。不 backfill。
- **Pin/Unpin API**：
  - `POST /api/v1/user/gifts/:id/pin`（**单事务，先锁 user 行**，cx-s2 D2）：
    1. `SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`
       —— 与 billing/expiry/revoke 同一 user→gift 锁序（只锁当前置顶行在"无置顶"时不够）。
    2. `UPDATE user_gifts SET pinned=false WHERE user_id=$1 AND pinned`（清旧置顶）。
    3. `UPDATE user_gifts SET pinned=true WHERE id=$2 AND user_id=$1 AND status='active'
       AND remaining>0 AND (expires_at IS NULL OR expires_at>NOW())`；affected==0 → 4xx
       （非本人/已过期/已耗尽），回滚。
    - 每条 WHERE 都带 user_id 强制归属，绝不只信路径 id。部分唯一索引作 defense-in-depth。
  - `DELETE /api/v1/user/gifts/:id/pin`：`UPDATE user_gifts SET pinned=false WHERE id=$1
    AND user_id=$2 AND pinned`。**UnpinGift 只清状态、无需锁 user 行**（cx-s2 实现注）。
- **allocator Stage 0（绝对第一，cx-s2 delta 确认 sound）**：`ActiveGift` 加 `Pinned bool`;
  `lockedSnapshot` 已 SELECT 全部行，把 pinned 列读进快照即可（无需加参）。`Allocate` 在
  Stage 1 之前找 eligible 子集里那条（≤1）pinned 赠金，**按其自身 mode 先处理**：
  - pinned priority → `take=min(remaining,cost)`，扣它、减 remaining/cost。
  - pinned ratio → 用 Stage 2 同样的比例数学（gift_part/recharge_part，受 rechargePool 与
    自身 remaining 双上限）；`rechargePool≤0` 时休眠、Stage 0 取 0 并 fall through
    —— 与"可用"含 ratio 配对前置条件一致。
  - 之后 Stage 1（其余 priority，**排除**置顶那条）、Stage 2（其余 ratio，**排除**置顶那条）、
    Stage 3 充值池，照旧。按 ID 从后续列表剔除置顶项，避免重复计数。
  - **不变量不变**：Stage 0 只改"谁先扣光"的顺序，链尾舍入收口仍保证
    Σ(GiftDeltas)+RechargeDelta ≡ TotalCost。
- **分组不匹配 → 置顶自动忽略（免费）**：架构本就"锁全部赠金、Go 内按请求组切 eligible"，
  置顶若因分组不符落入 ineligible 桶就不进 eligible 集 → Stage 0 根本看不到它。无需额外判断。
- **排序维度⓪**：`lockedSnapshot` 与展示查询都把 `pinned DESC` 加为最前排序维度
  （分页查询 orderBy 改 `ug.pinned DESC, ug.expires_at ASC NULLS LAST, ug.id ASC`,
  cx-s2 D3），使置顶行 UI 置顶且 Stage 0 选取确定。前端 pin/unpin 成功后**重置到第 1 页**再刷新。
- **preflight 不受影响**：置顶只改消费顺序不改准入；pinned ratio **不会**让 rechargePool≤0
  的用户变可准入（ratio 不能独立支撑准入），与现状一致——不产生"准入后无法消费"。
- **陈旧置顶清理（不影响正确性，仅 UI 整洁）**：置顶赠金过期(expirer sweep)/耗尽(remaining→0)
  时顺手 `pinned=false`。正确性不依赖它 —— lockedSnapshot 的 WHERE(remaining>0/未过期)已把
  陈旧置顶排除出消费。分组删除→置顶的分组赠金 group_id 转 NULL(§3.5)，仍保持置顶、转为全局适用。

## 四、测试

- **发放**：领带分组池 key → 赠金 group_id=该组；领无分组池 key → group_id=NULL；
  grant 时组已删 → 落 NULL（全局）。
- **claim/grant 竞态**：transfer pin（affected==0 重试）；grant vs DeleteCascade 抢
  groups 行锁的两种交错都不留悬挂 scope。
- **扣费过滤 + 不变量**：
  - A 组 priority 赠金，在 A 组请求 → 扣赠金；在 B 组请求 → 赠金不动、扣充值池，
    且 rechargePool 精确 = balance − Σ(全部赠金)（断言 IneligibleGiftRemaining 生效）。
  - 全局赠金（NULL）在任意组都参与扣费。
  - group + 全局并存的分摊顺序（priority-组 > priority-全局 > ratio-组 > ratio-全局）。
  - ratio + group 过滤（rechargePool≤0 休眠语义不变）。
- **preflight（集成）**：
  - rechargePool>0 → 任意组放行（真金全局）。
  - rechargePool≤0 且仅 A 组有 priority 赠金：A 组放行、B 组拦截。
  - 非 simple 模式 checker=nil / GetGiftBalance 出错 → `ErrBillingServiceUnavailable`
    （fail closed），**不**再 balance-only 放行。
- **兜底扣费**：非订阅走 group-aware 引擎、error 上抛；构造期缺 giftEngine → 启动失败；
  两个 gateway 都覆盖；提交后附属失败不产生可重试计费错误。
- **指纹**：v1 存量重试匹配（无假冲突）；仅 group 不同的两请求 v2 hash 不同、不误 dedup；
  archive 带版本；两阶段开关 off/on 行为。
- **分组删除**：删 A 组 → 原 group_id=A 的赠金变 NULL、之后任意组可花；DeleteCascade 与
  裸 Delete 两路径都覆盖。
- **折扣赠金全局（Option B）**：绑分组 key 用户充值命中折扣 → 折扣赠金 group_id IS NULL、
  可在别的组花；同时原 keybind 赠金仍锁原组。
- **展示（功能①全局/分组列）**：group 赠金带 group 名 + `is_global=false`；NULL → `is_global=true`
  且不带 group 名；软删组 → group_id 已 NULL → 显示全局、无悬挂名。
- **置顶（功能②，cx-s2 delta 用例）**：
  - 一人至多一条：部分唯一索引 + 并发 pin 竞态（一方唯一冲突→友好错误）。
  - pin priority 赠金 → 第一个被消费。
  - pin ratio 赠金且同时持 priority 赠金 → **置顶 ratio 先于 priority 消费**（"绝对第一"决策）。
  - pinned ratio 且 rechargePool≤0 → 休眠、Stage 0 取 0、fall through。
  - pinned 分组赠金但请求在别组 → 忽略置顶、按常规顺序。
  - pin/unpin 归属（不能 pin/unpin 他人赠金）；UnpinGift 不锁 user 行也正确。
  - allocator 带 Stage 0 的不变量守恒；展示置顶行居顶 + is_global 列正确。
  - 契约测试两种响应形态：分页行含正 id、legacy 行 omit id 但恒输出 pinned 与 is_global。
- **契约夹具**：赠金/profile 相关精确 JSON（含 `api_contract_test.go`）同步加
  group_id / group_name / is_global / id / pinned。
- 回归：`go test -tags=unit ./...`、gift 现有 30+ 单测（见 [[project_gift_test_baseline]]）全绿。

## 五、CI 清单
- `go test -tags=unit ./...` / `-tags=integration ./...` 通过
- `golangci-lint run ./...` 无新增
- 迁移 177（含 group_id 偏索引 + dedup/archive 两表 fingerprint_version 列
  + user_gifts.pinned 列 + 一人一置顶部分唯一索引 `IF NOT EXISTS`）+
  `go generate ./ent` + `go generate ./cmd/server`(Wire) 生成代码已提交
- 所有 Stub/Mock、两个 gateway 构造器测试已更新
- 前端 `pnpm run lint` / `typecheck` 通过

## 六、评审轨迹（cx-s2, gpt-5.6-sol high，六轮）
- R1（本方案）6 点 → R2 全部处置：锁全部赠金 + IneligibleGiftRemaining 全局充值池、
  GetGiftBalance 保持全局 vs HasActivePriorityGift 组过滤、兜底走引擎、claim pin、删除入事务。
- R2 6 新点 → R3：兜底 fail-closed、preflight 用 apiKey.GroupID、grant vs 删组序列化、
  裸 Delete 事务、指纹加 group、折扣赠金归属存疑。
- R3 4 点 → R4：grant 锁+落列放进 Grant 事务（非 keybind.Commit）、两删除路径都锁 groups
  行、指纹版本化、S13 定为产品决策。
- R4 3 点 → R5：持久化 fingerprint_version 列、兜底返回 error + 构造期拒绝、S13=Option B。
- R5 3 点 → R6：两阶段指纹发布、preflight 非 simple 模式 fail-closed、两个 gateway 对称注入。
- R6 → **APPROVE**。实现注（已并入上文）：v2 开关 config-backed 默认 false；archive mover
  `dashboard_aggregation_repo.go:244` 带版本；user_gifts 加 group_id 前导偏索引；兜底提交后
  附属失败不得成为可重试计费错误。

## 七、两个新功能点评审轨迹（cx-s2 delta，四轮）
功能①全局/分组列 + 功能②置顶（绝对第一），叠加在已 APPROVE 的基线上：
- delta R1 3 点 → R2：DTO 缺 gift id、pin 用 user 行锁、分页查询也要 pinned DESC 排序。
- delta R2 3 点 → R3：加字段到 `gift.UserGift` + 改共享 `scanUserGift`、id 映射范围界定、
  部分唯一索引 `IF NOT EXISTS`。
- delta R3 2 点 → R4：JOIN 列别名限定（ug/grp）消歧、共享 DTO 契约用显式 JSON tag 收口。
- delta R4 → **APPROVE**。实现注（已并入上文）：ug.group_id 用 `sql.NullInt64` 扫；
  `IsGlobal` 严格由 `GroupID==nil` 推导（不看 group_name）；UnpinGift 只清状态无需锁 user 行；
  契约测试覆盖分页/legacy 两种响应形态。
- 产品决策：置顶跨模式语义 = **绝对第一**（置顶 ratio 也先于 priority 消费，字面兑现"置顶"）。

## 八、实现后 code review（cx-s2 gpt-5.6-sol max，对照 PR #56 实际代码）
深审 42 文件 diff 对照本 plan，确认核心算法/锁/指纹/注入全部落地正确。两个真实次要发现
（均为 plan 已承诺、实现漏掉，已修复并追加提交 a0d3cc37）：
1. **陈旧置顶清理**（§3.10）：置顶赠金被扣至耗尽（`applyDeductions`）或过期（`expirer`
   sweep）时未清 `pinned`。修复：两处 UPDATE 加 `pinned=false`。正确性不依赖它
   （`lockedSnapshot` 的 `remaining>0`/未过期谓词已把陈旧置顶排除出消费），仅 UI 整洁。
2. **Profile 展示排序维度⓪**（§3.10）：`listActiveGiftsForDisplay` 的 `sortGiftDisplayItems`
   漏了 pinned 居顶（`GiftDisplayItem` 原无 Pinned 字段）→ 置顶 ratio 会显示在 priority 之下。
   修复：`GiftDisplayItem` 加 `Pinned`（仅排序用，Profile 卡不渲染置顶按钮）+ 排序维度⓪。

经核实为**非问题**的疑点：
- 构造器 `cfg==nil` 跳过 giftEngine 硬校验：纯测试路径（生产 Wire 恒传非 nil config +
  engine），且运行时 `postUsageBilling` 有 `giftEngine==nil` fail-closed 兜底（纵深防御）。
- 迁移 177 与 ent 生成的索引重名：ent auto-migrate 从不在启动运行（`ent.go:62` 只跑 raw SQL
  迁移），ent schema 名仅 sqlite 单测用，无重复索引风险。
- 软删组的"孤儿赠金"（group_id 指向已删组、`is_global=false` 但组名空）：仅两条软删组路径
  （DeleteCascade + 裸 Delete），都在 groups 行锁内原子置 NULL，生产不可达（仅测试直改
  `deleted_at` 构造）。
- Profile legacy `/user/gifts`（无 status 参）响应带 scope 字段但前端 `listGifts()` 是死代码
  （无引用）；唯一渲染逐条赠金的是 My Gifts 分页页，已完整改造 → 非发布阻塞。

验证：后端单测 + gift/repository 集成测试 + 前端 typecheck/lint 全绿；唯一失败
`TestUsageLogRepositoryGetUserSpendingRanking` 是干净 main 上即存在的预存 sqlmock 问题，与本 PR 无关。

---

## 附：废弃方案（锁 key 分组 group_locked）

原设计给 `api_keys` 加 `group_locked`，领带分组 key 时锁死该 key 的 group 字段。虽曾获
cx-s2 对其**技术实现**的 APPROVE，但**方向错误**：只隔离"这一把 key 的定价通道"，
无法隔离账户级赠金权益（用户另建 key 即绕过）。据"约束赠金而非 key"的最终判断，整体作废。
