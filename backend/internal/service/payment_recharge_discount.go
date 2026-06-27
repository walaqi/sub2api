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
	// ClaimApplication 尝试插入 application 记录（占位）。
	// 返回 claimed=true 表示本次成功插入（可继续发放），
	// claimed=false 表示 ON CONFLICT 冲突（其他并发已处理，调用方应立即退出）。
	ClaimApplication(ctx context.Context, app *RechargeDiscountApplicationRecord) (claimed bool, err error)
	UpdateApplicationGiftID(ctx context.Context, paymentOrderID int64, giftID int64) error
}

// RechargeDiscountRecord 充值折扣记录（service 层使用）。
type RechargeDiscountRecord struct {
	ID                    int64
	UserID                int64
	DiscountRate          float64
	MaxDiscountableAmount float64
	TotalDiscounted       float64
	ValidUntil            *time.Time
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

// applyRechargeDiscountForOrder 在 doBalance 中 markCompleted 前调用。
// 强一致：失败返回 error，订单保持 RECHARGING 可重试。
// 幂等：recharge_discount_applications(payment_order_id) 唯一索引。
//
// 两阶段设计：
//   Phase 1（事务外）：快速判断是否需要处理（幂等已处理/无折扣/无bonus）→ 无需 entClient
//   Phase 2（事务内）：claim order + FOR UPDATE 锁 + 更新 + 发放 + commit → 需要 entClient
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

	// 发放赠金
	var expiresAt *time.Time
	if discountLocked.ValidUntil != nil {
		t := *discountLocked.ValidUntil
		expiresAt = &t
	}
	sourceRef := fmt.Sprintf("discount:%d:order:%d", discountLocked.ID, o.ID)
	grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
		UserID:    o.UserID,
		Amount:    bonusFinal,
		Mode:      gift.DeductionModePriority,
		ExpiresAt: expiresAt,
		Source:    gift.SourceRechargeDiscount,
		SourceRef: &sourceRef,
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
