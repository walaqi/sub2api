package service

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/Wei-Shaw/sub2api/internal/gift"
	"github.com/shopspring/decimal"
)

// RechargeDiscountRepo 是 PaymentService 依赖的充值折扣仓库接口。
type RechargeDiscountRepo interface {
	CheckApplicationExists(ctx context.Context, paymentOrderID int64) (bool, error)
	QueryBestActiveDiscountForUpdate(ctx context.Context, userID int64) (*RechargeDiscountRecord, error)
	UpdateTotalDiscounted(ctx context.Context, discountID int64, appliedAmount float64) error
	// ClaimApplication 尝试插入 application 记录（占位）。
	// 返回 claimed=true 表示本次成功插入（可继续发放），
	// claimed=false 表示 ON CONFLICT 冲突（其他并发已处理，调用方应立即退出）。
	ClaimApplication(ctx context.Context, app *RechargeDiscountApplicationRecord) (claimed bool, err error)
	UpdateApplicationGiftID(ctx context.Context, paymentOrderID int64, giftID int64) error
	// QueryActiveDiscountsReadOnly returns active discounts for display (no FOR UPDATE).
	QueryActiveDiscountsReadOnly(ctx context.Context, userID int64) ([]RechargeDiscountSummary, error)
	// QueryDiscountsForInheritance returns discounts eligible for referral inheritance.
	// It only checks the time window and intentionally ignores quota exhaustion.
	QueryDiscountsForInheritance(ctx context.Context, userID int64) ([]RechargeDiscountSummary, error)
	// QueryDiscountsForInheritanceAtTime returns referral-inheritable discounts at a historical time.
	QueryDiscountsForInheritanceAtTime(ctx context.Context, userID int64, atTime time.Time) ([]RechargeDiscountSummary, error)
	// CreateDiscount inserts a new discount record (idempotent via ON CONFLICT DO NOTHING).
	CreateDiscount(ctx context.Context, in CreateRechargeDiscountInput) (int64, error)
	// QueryOrderGiftBonus 按支付订单查该订单发放的充值折扣赠金（bonus_amount + 扣除模式）。
	// 返回 nil 表示该订单未命中折扣、未发放赠金。用于充值成功页展示"赠金 $X"。
	QueryOrderGiftBonus(ctx context.Context, paymentOrderID int64) (*OrderGiftBonus, error)
}

// OrderGiftBonus 描述一笔支付订单发放的充值折扣赠金，供充值成功页展示。
type OrderGiftBonus struct {
	// BonusAmount 发放的赠金金额（recharge_discount_applications.bonus_amount）。
	BonusAmount float64
	// DeductionMode 赠金扣除模式（随折扣行固化）："priority" | "ratio"。
	DeductionMode string
	// RatioRecharge 仅 ratio 模式非 nil。
	RatioRecharge *float64
}

// CreateRechargeDiscountInput 是 CreateDiscount 的入参。
// 用 struct 替代长参数列表，并承载 gift 扣除策略（mode/ratio）。
type CreateRechargeDiscountInput struct {
	UserID         int64
	Source         string
	SourceRef      string
	OriginAPIKeyID *int64
	Rate           float64
	MaxAmount      float64
	ValidFrom      time.Time
	ValidUntil     *time.Time
	// GiftDeductionMode 固化在 discount 行上的赠金扣除模式："priority" | "ratio"。
	// 空值由 repo 层归一化为 "priority"。
	GiftDeductionMode string
	// GiftRatioRecharge 仅 ratio 模式非 nil。
	GiftRatioRecharge *float64
	// GiftExpiryMode 固化在 discount 行上的赠金有效期策略。
	// 空值由 repo 层归一化为 "discount_valid_until"。
	GiftExpiryMode string
	// GiftExpiresAfterDays 仅 after_days 模式非 nil。
	GiftExpiresAfterDays *int
}

// RechargeDiscountRecord 充值折扣记录（service 层使用）。
type RechargeDiscountRecord struct {
	ID                    int64
	UserID                int64
	DiscountRate          float64
	MaxDiscountableAmount float64
	TotalDiscounted       float64
	ValidUntil            *time.Time
	// GiftDeductionMode / GiftRatioRecharge 是发放赠金时的扣除策略（随行固化）。
	GiftDeductionMode    string
	GiftRatioRecharge    *float64
	GiftExpiryMode       string
	GiftExpiresAfterDays *int
}

// RechargeDiscountApplicationRecord 折扣发放记录（service 层使用）。
type RechargeDiscountApplicationRecord struct {
	UserID               int64
	DiscountID           int64
	PaymentOrderID       int64
	AppliedAmount        float64
	BonusAmount          float64
	DiscountRateSnapshot float64
	GiftID               *int64
}

// resolveDiscountGiftGrantMode 把 discount 行上固化的扣除策略归一化为 gift.Grant 入参。
//
// 防御性归一化（DB 已有 check，此处兜底，不信任 DB）：复用 domain.NormalizeGiftDeduction
// 作为单一校验源，与写入边界保持一致：
//   - mode 不是 "ratio" → 一律按 priority（ratio 置 nil）
//   - mode 是 "ratio" 但 ratio nil/<=0/>10 → 返回 error。数据不合法应暴露，让订单保持
//     可重试，而非静默降级为 priority（避免发错模式）。
func resolveDiscountGiftGrantMode(mode string, ratio *float64) (gift.DeductionMode, *float64, error) {
	normMode, normRatio, err := domain.NormalizeGiftDeduction(mode, ratio)
	if err != nil {
		return "", nil, err
	}
	return gift.DeductionMode(normMode), normRatio, nil
}

// resolveDiscountGiftExpiresAt computes the gift expiry for a recharge-discount grant.
// It keeps discount validity separate from gift validity:
//   - discount_valid_until: preserve legacy behavior, use discount.valid_until
//   - never: nil expires_at
//   - after_days: now + N days
func resolveDiscountGiftExpiresAt(mode string, days *int, discountValidUntil *time.Time, now time.Time) (*time.Time, error) {
	normMode, normDays, err := domain.NormalizeGiftExpiry(mode, days)
	if err != nil {
		return nil, err
	}
	switch normMode {
	case domain.GiftExpiryModeNever:
		return nil, nil
	case domain.GiftExpiryModeAfterDays:
		expiresAt := now.Add(time.Duration(*normDays) * 24 * time.Hour)
		return &expiresAt, nil
	default:
		if discountValidUntil == nil {
			return nil, nil
		}
		t := *discountValidUntil
		return &t, nil
	}
}

// applyRechargeDiscountForOrder 在 doBalance 中 markCompleted 前调用。
// 强一致：失败返回 error，订单保持 RECHARGING 可重试。
// 幂等：recharge_discount_applications(payment_order_id) 唯一索引。
//
// 两阶段设计：
//
//	Phase 1（事务外）：快速判断是否需要处理（幂等已处理/无折扣/无bonus）→ 无需 entClient
//	Phase 2（事务内）：claim order + FOR UPDATE 锁 + 更新 + 发放 + commit → 需要 entClient
//
// 并发安全：Phase 1 是乐观读（可能读到旧值），Phase 2 的 FOR UPDATE 锁 + InsertApplication
// 唯一索引是真正的安全保障。
func (s *PaymentService) applyRechargeDiscountForOrder(ctx context.Context, o *dbent.PaymentOrder) error {
	if s.rechargeDiscountRepo == nil {
		return nil
	}

	orderAmount := o.Amount
	if orderAmount <= 0 || math.IsNaN(orderAmount) || math.IsInf(orderAmount, 0) {
		return nil
	}

	// === Phase 1: 乐观快速退出（事务外）===

	// 幂等快速检查（已处理则跳过，避免开事务）
	exists, err := s.rechargeDiscountRepo.CheckApplicationExists(ctx, o.ID)
	if err != nil {
		return fmt.Errorf("check discount application: %w", err)
	}
	if exists {
		return nil
	}

	// 乐观查询折扣（不加锁，仅用于快速退出无折扣场景）
	discount, err := s.rechargeDiscountRepo.QueryBestActiveDiscountForUpdate(ctx, o.UserID)
	if err != nil {
		return fmt.Errorf("query active discount: %w", err)
	}
	if discount == nil {
		return nil
	}

	// 计算 eligible amount
	remaining := discount.MaxDiscountableAmount - discount.TotalDiscounted
	if remaining <= 0 {
		return nil
	}

	appliedAmount := math.Min(orderAmount, remaining)
	bonus := decimal.NewFromFloat(appliedAmount).
		Mul(decimal.NewFromFloat(discount.DiscountRate)).
		Round(8).
		InexactFloat64()
	if bonus <= 0 {
		return nil
	}

	// === Phase 2: 事务内原子操作 ===

	if s.giftEngine == nil || s.entClient == nil {
		return fmt.Errorf("recharge discount: gift engine or ent client not configured")
	}

	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin discount tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := dbent.NewTxContext(ctx, tx)

	// 事务内重新幂等检查（防并发重试同时通过 Phase 1）
	existsInTx, err := s.rechargeDiscountRepo.CheckApplicationExists(txCtx, o.ID)
	if err != nil {
		return fmt.Errorf("check discount application in tx: %w", err)
	}
	if existsInTx {
		return nil
	}

	// 事务内 FOR UPDATE 重新查询（锁行，获取最新 total_discounted）
	discountLocked, err := s.rechargeDiscountRepo.QueryBestActiveDiscountForUpdate(txCtx, o.UserID)
	if err != nil {
		return fmt.Errorf("query discount for update: %w", err)
	}
	if discountLocked == nil {
		return nil
	}

	// 用锁后的最新值重新计算
	remainingLocked := discountLocked.MaxDiscountableAmount - discountLocked.TotalDiscounted
	if remainingLocked <= 0 {
		return nil
	}
	appliedAmountFinal := math.Min(orderAmount, remainingLocked)
	bonusFinal := decimal.NewFromFloat(appliedAmountFinal).
		Mul(decimal.NewFromFloat(discountLocked.DiscountRate)).
		Round(8).
		InexactFloat64()
	if bonusFinal <= 0 {
		return nil
	}

	// 先 claim order（unique index 是最终幂等保障）
	// claimed=false 表示并发已处理，立即退出不发 gift
	claimed, err := s.rechargeDiscountRepo.ClaimApplication(txCtx, &RechargeDiscountApplicationRecord{
		UserID:               o.UserID,
		DiscountID:           discountLocked.ID,
		PaymentOrderID:       o.ID,
		AppliedAmount:        appliedAmountFinal,
		BonusAmount:          bonusFinal,
		DiscountRateSnapshot: discountLocked.DiscountRate,
		GiftID:               nil,
	})
	if err != nil {
		return fmt.Errorf("claim discount application: %w", err)
	}
	if !claimed {
		// 另一个并发执行已处理该订单，安全退出
		return nil
	}

	// 更新 total_discounted
	if err := s.rechargeDiscountRepo.UpdateTotalDiscounted(txCtx, discountLocked.ID, appliedAmountFinal); err != nil {
		return fmt.Errorf("update total_discounted: %w", err)
	}

	// 读取随行固化的扣除策略，并做防御性归一化（DB 有 check，此处兜底）：
	//   - mode 不是 ratio → 一律 priority（ratio 置 nil）
	//   - mode 是 ratio 但 ratio nil/<=0 → 数据不合法，返回 error 让订单可重试，
	//     不静默降级为 priority（避免发错模式）
	grantMode, grantRatio, err := resolveDiscountGiftGrantMode(discountLocked.GiftDeductionMode, discountLocked.GiftRatioRecharge)
	if err != nil {
		return fmt.Errorf("recharge discount %d: %w", discountLocked.ID, err)
	}
	expiresAt, err := resolveDiscountGiftExpiresAt(discountLocked.GiftExpiryMode, discountLocked.GiftExpiresAfterDays, discountLocked.ValidUntil, time.Now())
	if err != nil {
		return fmt.Errorf("recharge discount %d gift expiry: %w", discountLocked.ID, err)
	}

	sourceRef := fmt.Sprintf("discount:%d:order:%d", discountLocked.ID, o.ID)
	grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
		UserID:        o.UserID,
		Amount:        bonusFinal,
		Mode:          grantMode,
		RatioRecharge: grantRatio,
		ExpiresAt:     expiresAt,
		Source:        gift.SourceRechargeDiscount,
		SourceRef:     &sourceRef,
	})
	if err != nil {
		return fmt.Errorf("grant discount bonus: %w", err)
	}

	// 回填 gift_id（可选，失败不阻塞）
	if grantResult != nil {
		_ = s.rechargeDiscountRepo.UpdateApplicationGiftID(txCtx, o.ID, grantResult.ID)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit discount tx: %w", err)
	}

	slog.Info("recharge discount applied",
		"user_id", o.UserID,
		"order_id", o.ID,
		"applied_amount", appliedAmountFinal,
		"bonus", bonusFinal,
		"discount_rate", discountLocked.DiscountRate,
	)
	return nil
}

// SetRechargeDiscountRepo 注入充值折扣仓库（可选依赖，nil 时折扣功能关闭）。
func (s *PaymentService) SetRechargeDiscountRepo(repo RechargeDiscountRepo) {
	s.rechargeDiscountRepo = repo
}
