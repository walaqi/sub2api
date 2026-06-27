package domain

// BindKeyConfig 是表 A bind_key_gift_settings 的可扩展 per-key 配置，
// 序列化进 bind_key_gift_settings.config (JSONB)。
//
// 设计意图：新增 per-key 选项时往这里加字段即可，无需再迁移 schema。
// 所有字段 omitempty，未设置的子配置不写入 JSON，保持向后兼容。
type BindKeyConfig struct {
	// Unlimit 控制该 key 是否跳过每月一次的领取限制。
	// nil 或 true → 不限次数（不写/不查 participation 文件）；
	// 仅当显式设为 false 时才执行每月一次限制。
	Unlimit *bool `json:"unlimit,omitempty"`

	// RegistrationWindow 限制只有"注册时长"落在窗口内的用户才能领取该 key。
	// nil 或 Enabled=false 表示不限制。
	RegistrationWindow *BindKeyRegistrationWindow `json:"registration_window,omitempty"`

	// RechargeDiscount 充值折扣配置。绑定该 key 后用户在有效期内充值可额外获得余额。
	// nil 或 Enabled=false 表示不启用充值折扣。
	RechargeDiscount *BindKeyRechargeDiscount `json:"recharge_discount,omitempty"`
}

// BindKeyRegistrationWindow 是滚动相对注册窗口（单位：天，相对当前时间计算）。
//
// 条件：MinDays*24h <= (now - user.created_at) <= MaxDays*24h。
//   - MinDays: 最小注册时长，>= 0，0 表示对下界不设限（含刚注册的新用户）。
//   - MaxDays: 最大注册时长，>= 1，且必须 >= MinDays。
type BindKeyRegistrationWindow struct {
	Enabled bool `json:"enabled"`
	MinDays int  `json:"min_days"`
	MaxDays int  `json:"max_days"`
}

// BindKeyRechargeDiscount 充值折扣配置。
//
// 绑定该 key 后用户在 ValidDays 天内充值，可按 DiscountRate 比例额外获得赠金。
// MaxDiscountableAmount 是可参与折扣的充值本金上限（非 bonus 上限）。
// bonus = min(充值本金, 剩余可折扣额度) × DiscountRate。
//
// 校验约束：
//   - 0 < DiscountRate <= 10.0
//   - MaxDiscountableAmount > 0
//   - ValidDays >= 1
type BindKeyRechargeDiscount struct {
	Enabled               bool    `json:"enabled"`
	DiscountRate          float64 `json:"discount_rate"`           // 0.1 = 额外 10%
	MaxDiscountableAmount float64 `json:"max_discountable_amount"` // 可参与折扣的充值本金上限 (USD)
	ValidDays             int     `json:"valid_days"`              // 折扣有效天数（从领取时刻起算）
}
