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
	SourceKeybind          Source = "keybind"
	SourceOAuthFirstBind   Source = "oauth_first_bind"
	SourcePromoCode        Source = "promo_code"
	SourceRechargeDiscount Source = "recharge_discount"
	SourceReferralInvitee  Source = "referral_invitee"
	SourceReferralInviter  Source = "referral_inviter"
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
	// GroupID 绑定分组：非 nil 时该赠金仅限该分组消费；nil = 全局通用。
	// 领取带分组池 key 时由 keybind 传入；insertGiftWithBalance 会在同一事务内
	// 锁 groups 行校验——若该组已被软删除则落 NULL（转全局）。
	GroupID *int64
}

// GiftDisplayItem 面向用户展示的单笔有效赠金快照。
// 仅含 Profile 列表需要的字段；ExpiringSoon 由后端依据 GiftExpiringSoonThreshold 判定，
// 与 GetGiftBalanceBreakdown 同源，避免前后端阈值漂移。
type GiftDisplayItem struct {
	Remaining     float64
	Mode          DeductionMode
	RatioRecharge *float64
	ExpiresAt     *time.Time
	ExpiringSoon  bool
	// GroupID / GroupName：赠金绑定分组的展示信息。GroupID==nil → 全局。
	// 供 Profile 卡片渲染"全局 / 仅限分组 X"列（此展示面无置顶按钮，故不含 id）。
	GroupID   *int64
	GroupName string
	// Pinned 仅用于排序维度⓪（置顶行居顶），使展示顺序与消费顺序一致；此展示面不渲染置顶按钮。
	Pinned bool
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
	// GroupID / GroupName：赠金绑定分组。GroupID==nil → 全局。分页"我的赠金"页展示用。
	GroupID   *int64
	GroupName string
	// Pinned：用户置顶（allocator Stage 0 最先消费）。
	Pinned bool
}
