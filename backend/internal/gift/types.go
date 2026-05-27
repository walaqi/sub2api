// Package gift 实现赠金子账本：用户余额拆分为充值池与赠金池。
//
// 不变量：users.balance ≡ recharge_pool + Σ(active gifts.remaining)
// 详见设计稿 /home/chris/.claude/plans/wobbly-herding-waffle.md。
package gift

import "time"

// DeductionMode 赠金的扣除方式。
type DeductionMode string

const (
	// DeductionModePriority 优先扣除：先于充值余额消耗。
	DeductionModePriority DeductionMode = "priority"
	// DeductionModeRatio 比例扣除：与充值按 ratio_recharge 同步消耗。
	DeductionModeRatio DeductionMode = "ratio"
)

// Status 赠金状态机。
type Status string

const (
	StatusActive    Status = "active"
	StatusExhausted Status = "exhausted"
	StatusExpired   Status = "expired"
	StatusRevoked   Status = "revoked"
)

// Source 赠金来源。
type Source string

const (
	SourceKeybind        Source = "keybind"
	SourceOAuthFirstBind Source = "oauth_first_bind"
	SourcePromoCode      Source = "promo_code"
)

// GrantInput 发放赠金的入参。
type GrantInput struct {
	UserID        int64
	Amount        float64
	Mode          DeductionMode
	RatioRecharge *float64   // 仅 ratio 模式必填
	ExpiresAt     *time.Time // nil 表示永不过期
	Source        Source
	SourceRef     *string
}

// UserGift 赠金记录的对外快照（与 ent 实体解耦，便于跨包使用）。
type UserGift struct {
	ID            int64
	UserID        int64
	Amount        float64
	Remaining     float64
	Mode          DeductionMode
	RatioRecharge *float64
	ExpiresAt     *time.Time
	Source        Source
	SourceRef     *string
	Status        Status
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
