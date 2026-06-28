package domain

import "errors"

var (
	errInvalidGiftRatio      = errors.New("gift_ratio_recharge must be > 0 when gift_deduction_mode is ratio")
	errGiftRatioTooLarge     = errors.New("gift_ratio_recharge must be <= 10")
	errInvalidGiftExpiryDays = errors.New("gift_expires_after_days must be > 0 when gift_expiry_mode is after_days")
)

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
//   - GiftDeductionMode 为 "priority" 或 "ratio"（空值归一化为 priority）
//   - GiftRatioRecharge：priority 模式必须为 nil；ratio 模式必须 > 0 且 <= 10
//   - GiftExpiryMode 为空时归一为 "discount_valid_until"；after_days 模式必须配置正数天数
type BindKeyRechargeDiscount struct {
	Enabled               bool    `json:"enabled"`
	DiscountRate          float64 `json:"discount_rate"`           // 0.1 = 额外 10%
	MaxDiscountableAmount float64 `json:"max_discountable_amount"` // 可参与折扣的充值本金上限 (USD)
	ValidDays             int     `json:"valid_days"`              // 折扣有效天数（从领取时刻起算）

	// GiftDeductionMode 控制该折扣发放的赠金的扣除方式："priority" 或 "ratio"。
	// 空值视为 "priority"（向后兼容存量未设置该字段的 JSON）。该策略在创建
	// user_recharge_discounts 行时固化，发放/继承时只读行上的值，不回查 key 配置。
	GiftDeductionMode string `json:"gift_deduction_mode,omitempty"`
	// GiftRatioRecharge 仅在 ratio 模式有效，表示每消费 1 单位充值余额同步消耗的赠金比例。
	// priority 模式必须为 nil。
	GiftRatioRecharge *float64 `json:"gift_ratio_recharge,omitempty"`
	// GiftExpiryMode 控制该折扣发放的赠金有效期："discount_valid_until" | "never" | "after_days"。
	// 空值视为 "discount_valid_until"（向后兼容存量配置和旧请求）。
	GiftExpiryMode string `json:"gift_expiry_mode,omitempty"`
	// GiftExpiresAfterDays 仅在 after_days 模式有效，表示赠金从发放时起 N 天后过期。
	GiftExpiresAfterDays *int `json:"gift_expires_after_days,omitempty"`
}

// 赠金扣除模式常量（与 user_gifts.deduction_mode / gift 包保持一致的字面量）。
const (
	GiftDeductionModePriority = "priority"
	GiftDeductionModeRatio    = "ratio"
)

// 充值折扣赠金有效期策略常量。
const (
	GiftExpiryModeDiscountValidUntil = "discount_valid_until"
	GiftExpiryModeNever              = "never"
	GiftExpiryModeAfterDays          = "after_days"
)

// NormalizeGiftDeduction 校验并归一化充值折扣赠金的扣除模式/比例。
//
// 归一化规则（写入边界，不信任 JSON 输入）：
//   - 空值/未知 mode → priority
//   - priority → ratio 强制为 nil
//   - ratio → ratio 必须 > 0 且 <= 10（沿用折扣率上限语义），否则返回 error
//
// 返回归一化后的 (mode, ratio)。priority 模式下 ratio 恒为 nil。
func NormalizeGiftDeduction(mode string, ratio *float64) (string, *float64, error) {
	if mode != GiftDeductionModeRatio {
		// 空值或任何非 ratio 的值都归一为 priority，并清空 ratio。
		return GiftDeductionModePriority, nil, nil
	}
	if ratio == nil || *ratio <= 0 {
		return "", nil, errInvalidGiftRatio
	}
	if *ratio > 10 {
		return "", nil, errGiftRatioTooLarge
	}
	r := *ratio
	return GiftDeductionModeRatio, &r, nil
}

// NormalizeGiftExpiry 校验并归一化充值折扣赠金的有效期策略。
//
// 归一化规则：
//   - 空值/未知 mode → discount_valid_until
//   - discount_valid_until / never → days 强制为 nil
//   - after_days → days 必须 > 0，否则返回 error
//
// 返回归一化后的 (mode, days)。非 after_days 模式下 days 恒为 nil。
func NormalizeGiftExpiry(mode string, days *int) (string, *int, error) {
	switch mode {
	case GiftExpiryModeAfterDays:
		if days == nil || *days <= 0 {
			return "", nil, errInvalidGiftExpiryDays
		}
		d := *days
		return GiftExpiryModeAfterDays, &d, nil
	case GiftExpiryModeNever:
		return GiftExpiryModeNever, nil, nil
	default:
		return GiftExpiryModeDiscountValidUntil, nil, nil
	}
}
