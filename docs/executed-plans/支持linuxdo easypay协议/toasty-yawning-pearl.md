# EasyPay「自定」自由通道：admin 配置 + 前端按 sort_order 渲染独立按钮

## Context

之前的 trick 方案（仅前端白名单 `epay` + 手动 SQL 改 `supported_types='epay'`）行不通，因为：

1. **运营需求是任意通道，不止 `epay`**：易支付协议除 `alipay/wxpay/epay` 外还有 `qqpay/jdpay/cnpay/usdt/...`，每家网关的可用 type 字符串不同。需要让 admin 在 dialog 里输入任意字符串，而不是前端硬编码白名单。
2. **每条「自定」通道的 label / 图标 / 余额倍率 / 商品名前后缀都可能不同**：默认全局 `BalanceRechargeMultiplier` / `ProductNamePrefix/Suffix` 不够用，需要 instance 级覆盖。
3. **图标应当来自外部 URL，而不是打包内置 SVG**：admin 配新通道时不需要发版前端。

业务约束：

- 「自定」与同一条 easypay 实例上的「微信 / 支付宝」**整组互斥**（二分组）：未选「自定」时，微信 / 支付宝按现有规则可任意单选 / 多选；一旦选「自定」，微信 / 支付宝整组被禁用 + 清空，反之亦然。
- 自定通道**只支持跳转 / 弹窗**，与现有 `payment_mode='popup'` 兼容；不支持站内二维码。
- 用户端按钮顺序使用 instance 的 `sort_order` 字段，覆盖前端常量 `METHOD_ORDER`（自定 type 不在常量表中，目前会落到末尾"999"）。

## 关键现状（计划基于此）

- [validateProviderRequest:209-218](backend/internal/service/payment_config_providers.go#L209-L218) **不校验 supported_types 内容** → 任意 CSV 透传到 DB
- [InstanceSupportsType:379-391](backend/internal/payment/load_balancer.go#L379-L391) 按 CSV 精确字符串匹配 → 自由文本能被 LoadBalancer 唯一路由
- [easypay.go:128](backend/internal/payment/provider/easypay.go#L128) `params["type"] = req.PaymentType` 直接透传，不做白名单
- [GetBasePaymentType:82-97](backend/internal/payment/types.go#L82-L97) 未知 type 返回原值
- [paymentFlow.ts:202-220](frontend/src/components/payment/paymentFlow.ts#L202-L220) `payment_mode='popup'` 直接走 `redirect_waiting`，无需新分支
- 后端余额倍率 [payment_order.go:60](backend/internal/service/payment_order.go#L60) `cfg.BalanceRechargeMultiplier` 当前**只读全局**
- 后端商品名前后缀 [payment_order.go:526-538](backend/internal/service/payment_order.go#L526-L538) 当前**只读全局**
- 前端用户端 [PaymentView.vue:491-548](frontend/src/views/user/PaymentView.vue#L491-L548) 按 METHOD_ORDER 排序，自定 type 不在常量里 → 默认落末尾

## 改动概览

### A. ent schema：新增 `metadata` JSON 字段

**[backend/ent/schema/payment_provider_instance.go](backend/ent/schema/payment_provider_instance.go)** —— 新增一个字段：

```go
field.String("metadata").
    SchemaType(map[string]string{dialect.Postgres: "text"}).
    Default(""),
```

存储 JSON：

```json
{
  "channels": {
    "epay":     { "label": "聚合支付", "icon_url": "https://cdn.example.com/icons/epay.png" },
    "qqpay":    { "label": "QQ 钱包", "icon_url": "..." },
    "balance_recharge_multiplier": 1.05,
    "product_name_prefix": "聚合-",
    "product_name_suffix": ""
  }
}
```

字段语义：`channels[type].{label,icon_url}` 按 `supported_types` 内每个 type 一一对应；倍率 / 前后缀是 instance 级（与 type 无关）。schema 字段命名为 `metadata`（保留通用语义，未来其他 provider 也能用）。

迁移路径：用 `make ent-gen` 生成，启动时自动应用（项目使用 [ent migrate](backend/ent/migrate/schema.go) auto-migrate，已确认）。一次性迁移成本，运行后所有现有实例的 `metadata=""`。

### B. 后端：解析 metadata + 在 instance 选择后应用倍率/前后缀/币种 = CNY

**新文件 [backend/internal/service/payment_provider_metadata.go](backend/internal/service/payment_provider_metadata.go)**（不修改已有文件，便于回滚）：

```go
type ProviderInstanceMetadata struct {
    Channels                  map[string]ChannelMetadata `json:"channels"`
    BalanceRechargeMultiplier *float64                   `json:"balance_recharge_multiplier,omitempty"`
    ProductNamePrefix         *string                    `json:"product_name_prefix,omitempty"`
    ProductNameSuffix         *string                    `json:"product_name_suffix,omitempty"`
}

type ChannelMetadata struct {
    Label   string `json:"label,omitempty"`
    IconURL string `json:"icon_url,omitempty"`
}

func parseInstanceMetadata(raw string) ProviderInstanceMetadata { ... }
```

**修改点**：

1. [payment_order.go:60](backend/internal/service/payment_order.go#L60)：在 `selectCreateOrderInstance` 返回 `sel` 之后，读 `sel.Metadata`（需要让 LoadBalancer 把原始 instance 的 metadata 字段一起返回；见 step C），如果有 instance 级 multiplier 就用它，否则用 `cfg.BalanceRechargeMultiplier`。注意：当前调用顺序是先算 `orderAmount`（用全局倍率）再选 instance —— 需要改为「先选 instance，再用 instance 倍率（fallback 全局）算 orderAmount」。这要调整 [payment_order.go:54-101](backend/internal/service/payment_order.go#L54-L101) 的次序。
2. [payment_order.go:503-538](backend/internal/service/payment_order.go#L503-L538) `buildPaymentSubject` / `applyPaymentProductNameAffix`：在已有 `sel *InstanceSelection` 参数后扩展为优先读 instance 级前后缀，否则读 cfg 的。
3. **不需要改 currency**：`paymentProviderConfigCurrency` 对 easypay 恒返回 `DefaultPaymentCurrency=CNY` ([payment_currency.go:10-19](backend/internal/service/payment_currency.go#L10-L19))，自定通道币种自然 = CNY，与全局聚合一致，不会触发混合币种保护。

### C. LoadBalancer 在 InstanceSelection 上回传 metadata

**[backend/internal/payment/load_balancer.go](backend/internal/payment/load_balancer.go)**：

- [InstanceSelection](backend/internal/payment/load_balancer.go) 结构体增加 `Metadata string`（原始 JSON 字符串，service 层自己解析），在 [buildSelection](backend/internal/payment/load_balancer.go#L114) 处填充。
- 同步更新 ent 查询字段（添加 metadata 字段到 Select 列表，如有显式 Select；否则全字段返回时无需改）。

### D. 后端：/checkout-info 下发 label / icon_url / sort_order

**[backend/internal/handler/payment_handler.go:148-160](backend/internal/handler/payment_handler.go#L148-L160)** + **[backend/internal/service/payment_config_service.go:111-118](backend/internal/service/payment_config_service.go#L111-L118)**：

`MethodLimits` 增加：

```go
type MethodLimits struct {
    PaymentType string  `json:"payment_type"`
    Currency    string  `json:"currency"`
    FeeRate     float64 `json:"fee_rate"`
    DailyLimit  float64 `json:"daily_limit"`
    SingleMin   float64 `json:"single_min"`
    SingleMax   float64 `json:"single_max"`
    Label       string  `json:"label,omitempty"`       // 新增
    IconURL     string  `json:"icon_url,omitempty"`    // 新增
    SortOrder   int     `json:"sort_order,omitempty"`  // 新增
}
```

填充点：[payment_config_limits.go:14-39](backend/internal/service/payment_config_limits.go#L14-L39) `GetAvailableMethodLimits`。对每个 paymentType：

- 标准 type（alipay/wxpay/stripe/airwallex/epay）：保持原值，三个新字段为空（前端 fallback 到 i18n + 内置图标 + METHOD_ORDER）。
- 自定 type（不在标准白名单的字符串）：从对应 instance 的 metadata.channels[type] 取 label/icon_url；sort_order 取 instance.sort_order。当多个 instance 都声明同一个自定 type 时（边缘场景），取 sort_order 最小那个的元数据（与 LoadBalancer 选择优先级一致）。

### E. 后端：admin 创建/更新支持 metadata 字段

**[backend/internal/service/payment_config_service.go:128-151](backend/internal/service/payment_config_service.go#L128-L151)** `CreateProviderInstanceRequest` / `UpdateProviderInstanceRequest`：

```go
type CreateProviderInstanceRequest struct {
    ...
    Metadata string `json:"metadata"`  // JSON 字符串，与 Limits 字段对称
}
```

**[backend/internal/service/payment_config_providers.go](backend/internal/service/payment_config_providers.go)**：

- `CreateProviderInstance`、`UpdateProviderInstance` 写入 `SetMetadata(req.Metadata)`。
- `ProviderInstanceResponse` 增加 `Metadata string` 字段，admin GET 时回填。
- 校验 `metadata` 是合法 JSON（空字符串放过，不强制结构校验，让前端先稳定后再加严）。

### F. 前端：admin dialog 增加「自定」三选一 + 元数据输入 + 互斥

**[frontend/src/components/payment/providerConfig.ts](frontend/src/components/payment/providerConfig.ts)**：

```ts
export const PROVIDER_SUPPORTED_TYPES: Record<string, string[]> = {
  easypay: ['alipay', 'wxpay'],   // 不再加 'epay'
  ...
}

export const EASYPAY_CUSTOM_TYPE_VALUE = '__custom__'  // dialog 内部 sentinel
```

**[frontend/src/components/payment/PaymentProviderDialog.vue](frontend/src/components/payment/PaymentProviderDialog.vue)** 改动：

1. 在第 54-70 行的 `availableTypes` 渲染区，对 `easypay` 追加第三个 toggle 按钮 `[自定]`（i18n key `admin.settings.payment.easypayCustomType`）。
2. 选中状态：用 `form.useCustomChannel` 布尔追踪（不污染 `form.supported_types`）。点击「自定」→ 自动清空已勾选的 alipay/wxpay 整组；点击「微信/支付宝」→ 自动关闭 useCustomChannel + 折叠自定区。未选「自定」时微信/支付宝按现状可任选其一或全选。
3. **整组互斥渲染**：`useCustomChannel=true` 时，禁用 alipay/wxpay 按钮（`disabled` + 灰化）；反之禁用「自定」按钮。微信与支付宝彼此之间**不互斥**。
4. 在「Config fields」上方插入条件块（`v-if="useCustomChannel"`）：
   - 输入框：`customType`（必填，单行文本，placeholder `epay / qqpay / usdt / ...`，提交校验非空 + ASCII safe）
   - 输入框：`customLabel`（必填，按钮文案）
   - 输入框：`customIconUrl`（必填，URL）
   - 折叠输入：`customMultiplier`（数字，可选，未填走全局；与 cfg.BalanceRechargeMultiplier 同语义）
   - 输入框：`customProductNamePrefix` / `customProductNameSuffix`（可选）
5. `handleSave` 提交时：
   - 若 `useCustomChannel=true`：
     - `payload.supported_types = [customType.trim()]`
     - `payload.metadata = JSON.stringify({ channels: { [customType]: { label, icon_url } }, balance_recharge_multiplier?, product_name_prefix?, product_name_suffix? })`
   - 否则（标准微信/支付宝）：`payload.metadata = ''`，supported_types 沿用现有勾选。
6. `loadProvider` 反序列化：从 instance.metadata 解析回填；`useCustomChannel = supported_types.length === 1 && !STANDARD_TYPES.includes(supported_types[0])`。
7. **payment_mode 自动钳制**：当 `useCustomChannel=true`，`form.payment_mode` 强制 `popup`（隐藏 qrcode 选项），与运维约束一致。
8. emit save 事件 payload 类型扩展 `metadata: string`。

**[frontend/src/components/payment/PaymentSettingsView.vue](frontend/src/components/payment/PaymentSettingsView.vue)**（或 dialog 父组件）：把 metadata 透传到 PUT/POST API。

### G. 前端：/types/payment.ts MethodLimit 增加新字段

**[frontend/src/types/payment.ts](frontend/src/types/payment.ts)** 给 `MethodLimit` interface 加：

```ts
label?: string
icon_url?: string
sort_order?: number
```

### H. 前端：用户端按钮渲染 + 排序 + 路由

**[frontend/src/components/payment/paymentFlow.ts](frontend/src/components/payment/paymentFlow.ts)**：

- 修改 `normalizeVisibleMethod`（第 94 行）：当 type 不在 `VISIBLE_METHOD_ALIASES` 表内但**字符串非空且 `getVisibleMethods` 输入里有 fee_rate/limits**（即来自后端，不是前端瞎传）时，原样返回作为「passthrough method」。
- 实现方式更稳健：`getVisibleMethods` 第 99-114 行，对 alias 表里没有的 type，**保留原 type 名**而不是丢弃。这样自定 type（如 `epay/qqpay/usdt`）能直达 PaymentView 的 visibleMethods map。
- `decidePaymentLaunch` 不需要为自定 type 加分支：第 219-220 行的 `prefersRedirect && payUrl → redirect_waiting` 已经覆盖（payment_mode 在 admin 端被钳制为 popup）。

**[frontend/src/components/payment/PaymentMethodSelector.vue](frontend/src/components/payment/PaymentMethodSelector.vue)**：

- `PaymentMethodOption` 接口加 `label?: string`、`icon_url?: string`、`sort_order?: number`。
- `methodIcon(type)`：先看 `option.icon_url`，有就直接用 URL；否则走现有 alipay/wxpay/stripe/airwallex/epay 的 fallback。
- 模板 `t(\`payment.methods.${method.type}\`)` 改为：`option.label || t(\`payment.methods.${method.type}\`, method.type)`（i18n 第二参数是 fallback string，缺 key 时直接显示原 type）。
- `methodSelectedClass(type)`：自定 type 走 `'border-primary-500 bg-primary-50 ...'` 默认色板。
- `sortedMethods` 排序逻辑（第 74-81 行）：先按 `option.sort_order ?? 999` 升序，再按 METHOD_ORDER 索引兜底。这样 backend 给的 sort_order 优先生效，没给的（标准 type）回退到 METHOD_ORDER。

**[frontend/src/views/user/PaymentView.vue](frontend/src/views/user/PaymentView.vue)**：

- 第 547-556 行 `methodOptions` 把 `label/icon_url/sort_order` 从 `visibleMethods.value[type]` 透传给 `PaymentMethodSelector`。
- 第 1022-1025 行的 `enabledMethods` 默认选择逻辑保留（按字母序），不影响。
- `paymentButtonClass`（约第 630-639 行）：未匹配标准 type 时落 `btn-primary`，无需新增 css 类。

### I. i18n

**[frontend/src/i18n/locales/zh.ts](frontend/src/i18n/locales/zh.ts)** + **[en.ts](frontend/src/i18n/locales/en.ts)**：

- `admin.settings.payment.easypayCustomType`: `'自定'` / `'Custom'`
- `admin.settings.payment.easypayCustomTypeHint`: `'输入易支付网关接受的 type 字符串，例如 epay/qqpay/usdt'`
- `admin.settings.payment.easypayCustomLabel`: `'按钮文案'` / `'Button label'`
- `admin.settings.payment.easypayCustomIconUrl`: `'按钮图标 URL'` / `'Icon URL'`
- `admin.settings.payment.easypayCustomMultiplier`: `'余额充值倍率覆盖（可选）'`
- `admin.settings.payment.easypayCustomPrefix` / `Suffix`: `'商品名前缀（可选）'` / `'后缀'`
- `admin.settings.payment.easypayCustomMutexHint`: `'选择「自定」后微信/支付宝不可勾选'`

**移除**之前临时加的 `payment.methods.epay` 两条 i18n（如果上版本已加）—— 因为 `epay` 不再是 trick 内置类型，由 admin 自由命名 + label 字段直出。

### J. 兼容性 / 不改的地方

- 后端 [PaymentStatusPanel.vue](frontend/src/components/payment/PaymentStatusPanel.vue) / [PaymentQRDialog.vue](frontend/src/components/payment/PaymentQRDialog.vue)：自定 type 始终 `payment_mode=popup`，不进 QR 分支。
- [pcApplyEnabledVisibleMethodInstances:41-74](backend/internal/service/payment_config_limits.go#L41-L74)：仅遍历 `[alipay, wxpay]`，自定 type 自动穿透。
- [providerSupportsVisibleMethod](backend/internal/service/payment_visible_method_instances.go#L63) / `enabledVisibleMethodsForProvider`：`addMethod` 只接受 alipay/wxpay，自定 type 在 easypay 分支被丢弃，不会被误识别成 alipay 实例。
- 退款 / 通知验签：易支付的 notify 不区分 type，沿用现有 [easypay.go:238-272](backend/internal/payment/provider/easypay.go#L238-L272) `VerifyNotification`，无需改。

## 验证

### 单元测试

- 新增 [backend/internal/service/payment_provider_metadata_test.go](backend/internal/service/payment_provider_metadata_test.go)：JSON 解析的边界用例（空字符串、非法 JSON、缺字段、负数倍率）。
- 修改 [backend/internal/payment/load_balancer_test.go](backend/internal/payment/load_balancer_test.go)：构造一个 supported_types='qqpay' 的 instance，断言 SelectInstance("","qqpay",...) 命中且不影响 alipay 实例。
- 修改 [backend/internal/service/payment_config_limits_test.go](backend/internal/service/payment_config_limits_test.go)：断言自定 type 在 GetAvailableMethodLimits 输出里带 label/icon_url/sort_order。
- 修改 [backend/internal/service/payment_order_test.go](backend/internal/service/payment_order_test.go)（如存在）：测 instance 倍率覆盖全局倍率。
- 修改 [frontend/src/components/payment/__tests__/PaymentProviderDialog.spec.ts](frontend/src/components/payment/__tests__/PaymentProviderDialog.spec.ts)：补「自定」三选一 + 互斥 + metadata 序列化用例。
- 修改 [frontend/src/components/payment/__tests__/PaymentMethodSelector.spec.ts](frontend/src/components/payment/__tests__/PaymentMethodSelector.spec.ts)：自定 type 渲染 label + icon_url + sort_order。
- 修改 [frontend/src/components/payment/__tests__/paymentFlow.spec.ts](frontend/src/components/payment/__tests__/paymentFlow.spec.ts)：之前 epay 用例改成自定 type，断言 getVisibleMethods 保留未知 type。

### 端到端冒烟

1. admin 在 dialog 里选 easypay → 「自定」→ 输入 type='epay'、label='聚合支付'、icon_url='https://...'、multiplier=1.05、保存 → DB 应有 `supported_types='epay'`、`metadata='{"channels":{"epay":...},"balance_recharge_multiplier":1.05}'`。
2. 用户登录后 /payment：看到「聚合支付」按钮，图标来自 URL，位置按 sort_order。
3. 输入 100 → 充值 → 创建订单 amount=100 → DB orderAmount = 105（因为 instance 倍率 1.05 而不是全局 1.0）。
4. 跳转易支付聚合页 → 完成支付 → 回跳成功。
5. 多 instance 共存：再加一条 easypay 实例 sup_types='qqpay'，sort_order=2；用户端两个按钮按 sort_order 排列。
6. 同 instance 互斥校验：dialog 里点「自定」→ alipay/wxpay 灰化不可点；点回 alipay → 自定区折叠。
7. 回滚演练：把某条「自定」实例 enabled=false → 用户端按钮立即消失。

### 性能 & 安全

- icon_url 应限制 https://，前端 admin 校验；后端不主动加载 URL，只透传给浏览器 `<img>`，无 SSRF 风险。
- metadata JSON 大小限制：与 limits 字段一致（无显式上限，依赖 ent text 字段 + 应用层应在 admin 校验时给个软上限如 4KB）。
