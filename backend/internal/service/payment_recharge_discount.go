package service

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
	"github.com/shopspring/decimal"
)

// RechargeDiscountRepo 是 PaymentService 依赖的充值折扣仓库接口。
type RechargeDiscountRepo interface {
	CheckApplicationExists(ctx context.Context, paymentOrderID int64) (bool, error)
	QueryBestActiveDiscountForUpdate(ctx context.Context, userID int64) (*RechargeDiscountRecord, error)
	UpdateTotalDiscounted(ctx context.Context, discountID int64, appliedAmount float64) error
	InsertApplication(ctx context.Context, app *RechargeDiscountApplicationRecord) error
}

// RechargeDiscountRecord mirrors repository.RechargeDiscount for the service layer.
type RechargeDiscountRecord struct {
	ID                    int64
	UserID                int64
	DiscountRate          float64
	MaxDiscountableAmount float64
	TotalDiscounted       float64
	ValidUntil            *time.Time
}

// RechargeDiscountApplicationRecord mirrors repository.RechargeDiscountApplication.
type RechargeDiscountApplicationRecord struct {
	UserID               int64
	DiscountID           int64
	PaymentOrderID       int64
	AppliedAmount        float64
	BonusAmount          float64
	DiscountRateSnapshot float64
	GiftID               *int64
}

// applyRechargeDiscountForOrder 在 doBalance 中 markCompleted 前调用。
// 强一致：失败返回 error，订单保持 RECHARGING 可重试。
// 幂等：recharge_discount_applications(payment_order_id) 唯一索引。
func (s *PaymentService) applyRechargeDiscountForOrder(ctx context.Context, o *dbent.PaymentOrder) error {
	if s.rechargeDiscountRepo == nil {
		return nil
	}

	// 1. 幂等检查
	exists, err := s.rechargeDiscountRepo.CheckApplicationExists(ctx, o.ID)
	if err != nil {
		return fmt.Errorf("check discount application: %w", err)
	}
	if exists {
		return nil
	}

	// 2. 查询用户最优有效折扣（FOR UPDATE 锁行）
	discount, err := s.rechargeDiscountRepo.QueryBestActiveDiscountForUpdate(ctx, o.UserID)
	if err != nil {
		return fmt.Errorf("query active discount: %w", err)
	}
	if discount == nil {
		return nil
	}

	// 3. 计算 eligible amount
	remaining := discount.MaxDiscountableAmount - discount.TotalDiscounted
	if remaining <= 0 {
		return nil
	}
	orderAmount := o.Amount
	if orderAmount <= 0 || math.IsNaN(orderAmount) || math.IsInf(orderAmount, 0) {
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

	// 4. giftEngine required from this point
	if s.giftEngine == nil || s.entClient == nil {
		return fmt.Errorf("recharge discount: gift engine or ent client not configured")
	}
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin discount tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := dbent.NewTxContext(ctx, tx)

	// 4a. 更新 total_discounted
	if err := s.rechargeDiscountRepo.UpdateTotalDiscounted(txCtx, discount.ID, appliedAmount); err != nil {
		return fmt.Errorf("update total_discounted: %w", err)
	}

	// 4b. 发放赠金
	var expiresAt *time.Time
	if discount.ValidUntil != nil {
		t := *discount.ValidUntil
		expiresAt = &t
	}
	sourceRef := fmt.Sprintf("discount:%d:order:%d", discount.ID, o.ID)
	grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
		UserID:    o.UserID,
		Amount:    bonus,
		Mode:      gift.DeductionModePriority,
		ExpiresAt: expiresAt,
		Source:    gift.SourceRechargeDiscount,
		SourceRef: &sourceRef,
	})
	if err != nil {
		return fmt.Errorf("grant discount bonus: %w", err)
	}

	var giftID *int64
	if grantResult != nil {
		giftID = &grantResult.ID
	}

	// 4c. 写应用记录
	if err := s.rechargeDiscountRepo.InsertApplication(txCtx, &RechargeDiscountApplicationRecord{
		UserID:               o.UserID,
		DiscountID:           discount.ID,
		PaymentOrderID:       o.ID,
		AppliedAmount:        appliedAmount,
		BonusAmount:          bonus,
		DiscountRateSnapshot: discount.DiscountRate,
		GiftID:               giftID,
	}); err != nil {
		return fmt.Errorf("insert discount application: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit discount tx: %w", err)
	}

	slog.Info("recharge discount applied",
		"user_id", o.UserID,
		"order_id", o.ID,
		"applied_amount", appliedAmount,
		"bonus", bonus,
		"discount_rate", discount.DiscountRate,
	)
	return nil
}

// SetRechargeDiscountRepo 注入充值折扣仓库（可选依赖，nil 时折扣功能关闭）。
func (s *PaymentService) SetRechargeDiscountRepo(repo RechargeDiscountRepo) {
	s.rechargeDiscountRepo = repo
}
