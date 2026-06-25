package service

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
)

// --- Refund Assessment Service ---
// 独立只读模块，用于退费前评估用户充值池消耗分布。
// 通过 FIFO（先进先出）算法将充值池总消耗按时间顺序分摊到各入账槽位。

// PoolSlotSource 标识槽位来源类型
const (
	SlotSourcePaymentOrder      = "payment_order"
	SlotSourceRedeemBalance     = "redeem_balance"
	SlotSourceAdminBalance      = "admin_balance"
	SlotSourceAffiliateTransfer = "affiliate_transfer"
)

// PoolSlot 表示 FIFO 队列中的一个入账槽位
type PoolSlot struct {
	Source         string    `json:"source"`
	SourceID       int64     `json:"source_id"`
	CreditedAt     time.Time `json:"credited_at"`
	Amount         float64   `json:"amount"`          // 到账余额
	PayAmount      float64   `json:"pay_amount"`      // 实付金额（免费来源=0，兑换码=面值）
	Ratio          float64   `json:"ratio"`           // pay_amount / amount（免费=0，兑换码=1）
	Consumed       float64   `json:"consumed"`        // FIFO 分配到的余额消耗
	ConsumedMoney  float64   `json:"consumed_money"`  // consumed × ratio
	Remaining      float64   `json:"remaining"`       // amount - consumed
	RefundStatus   string    `json:"refund_status"`   // "" | "refunded" | "partially_refunded"
	RefundDeducted float64   `json:"refund_deducted"` // 该订单退费时扣减的余额
	Note           string    `json:"note"`
}

// AssessmentSummary 评估汇总
type AssessmentSummary struct {
	TotalPaidCredited   float64 `json:"total_paid_credited"`    // 付费到账总额
	TotalFreeCredited   float64 `json:"total_free_credited"`    // 免费到账总额
	TotalPaidConsumed   float64 `json:"total_paid_consumed"`    // 付费槽位余额消耗之和
	TotalFreeConsumed   float64 `json:"total_free_consumed"`    // 免费槽位余额消耗之和
	TotalPaidMoneySpent float64 `json:"total_paid_money_spent"` // 付费槽位实付消耗之和
}

// RefundAssessmentResult 退费评估结果
type RefundAssessmentResult struct {
	UserID              int64             `json:"user_id"`
	UserEmail           string            `json:"email"`
	TotalRechargeUsed   float64           `json:"total_recharge_used"`   // Σ(usage_logs.recharge_cost)
	TotalGiftUsed       float64           `json:"total_gift_used"`       // Σ(usage_logs.gift_cost)
	TotalRefundDeducted float64           `json:"total_refund_deducted"` // Σ(历史退费扣减)
	EffectiveUsed       float64           `json:"effective_used"`        // API消耗 + 退费扣减
	CurrentPool         float64           `json:"current_pool"`          // 当前充值池余额
	Slots               []PoolSlot        `json:"slots"`
	Summary             AssessmentSummary `json:"summary"`
}

// RefundAssessmentService 退费评估服务（只读）
type RefundAssessmentService struct {
	entClient  *dbent.Client
	giftEngine *gift.Engine
	userRepo   UserRepository
}

// NewRefundAssessmentService creates the refund assessment service.
func NewRefundAssessmentService(entClient *dbent.Client, giftEngine *gift.Engine, userRepo UserRepository) *RefundAssessmentService {
	return &RefundAssessmentService{
		entClient:  entClient,
		giftEngine: giftEngine,
		userRepo:   userRepo,
	}
}

// Assess 根据邮箱查询用户并执行 FIFO 退费评估
func (s *RefundAssessmentService) Assess(ctx context.Context, email string) (*RefundAssessmentResult, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 1. 查询充值池总消耗
	totalRechargeUsed, totalGiftUsed, err := s.queryUsageSums(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("query usage sums: %w", err)
	}

	// 2. 查询历史退费扣减总额
	totalRefundDeducted, err := s.queryRefundDeductions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("query refund deductions: %w", err)
	}

	// 3. 收集所有入账槽位
	slots, err := s.collectSlots(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("collect slots: %w", err)
	}

	// 4. 按时间排序
	sort.Slice(slots, func(i, j int) bool {
		if slots[i].CreditedAt.Equal(slots[j].CreditedAt) {
			return slots[i].SourceID < slots[j].SourceID
		}
		return slots[i].CreditedAt.Before(slots[j].CreditedAt)
	})

	// 5. FIFO 分摊
	effectiveUsed := totalRechargeUsed + totalRefundDeducted
	currentPool := s.resolveCurrentPool(ctx, user)

	// 5.1 补偿未追踪入账（注册赠送等直接写 balance 的来源不会产生 redeem_codes 记录）
	totalEverCredited := effectiveUsed + currentPool
	slotSum := 0.0
	for _, sl := range slots {
		slotSum += sl.Amount
	}
	if gap := roundTo8(totalEverCredited - slotSum); gap > 0.01 {
		slots = append([]PoolSlot{{
			Source:     "signup_grant",
			SourceID:   0,
			CreditedAt: user.CreatedAt,
			Amount:     gap,
			PayAmount:  0,
			Ratio:      0,
			Note:       "注册赠送 / 未追踪入账",
		}}, slots...)
	}

	AllocateFIFO(slots, effectiveUsed)

	// 6. 计算汇总
	summary := computeSummary(slots)

	return &RefundAssessmentResult{
		UserID:              user.ID,
		UserEmail:           user.Email,
		TotalRechargeUsed:   totalRechargeUsed,
		TotalGiftUsed:       totalGiftUsed,
		TotalRefundDeducted: totalRefundDeducted,
		EffectiveUsed:       effectiveUsed,
		CurrentPool:         currentPool,
		Slots:               slots,
		Summary:             summary,
	}, nil
}

// AllocateFIFO 将 totalUsed 按 FIFO 顺序分摊到各 slot（纯函数，可独立测试）。
// 调用方需确保 slots 已按 CreditedAt 排序。
func AllocateFIFO(slots []PoolSlot, totalUsed float64) {
	remaining := totalUsed
	for i := range slots {
		if remaining <= 0 {
			slots[i].Consumed = 0
			slots[i].ConsumedMoney = 0
			slots[i].Remaining = slots[i].Amount
			continue
		}
		consume := math.Min(slots[i].Amount, remaining)
		slots[i].Consumed = roundTo8(consume)
		slots[i].ConsumedMoney = roundTo8(consume * slots[i].Ratio)
		slots[i].Remaining = roundTo8(slots[i].Amount - consume)
		remaining -= consume
	}
}

// --- Private query methods ---

func (s *RefundAssessmentService) queryUsageSums(ctx context.Context, userID int64) (rechargeUsed, giftUsed float64, err error) {
	rows, err := s.entClient.QueryContext(ctx, `
SELECT COALESCE(SUM(recharge_cost), 0)::double precision,
       COALESCE(SUM(gift_cost), 0)::double precision
FROM usage_logs
WHERE user_id = $1`, userID)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		if err := rows.Scan(&rechargeUsed, &giftUsed); err != nil {
			return 0, 0, err
		}
	}
	return rechargeUsed, giftUsed, rows.Err()
}

func (s *RefundAssessmentService) queryRefundDeductions(ctx context.Context, userID int64) (float64, error) {
	rows, err := s.entClient.QueryContext(ctx, `
SELECT COALESCE(SUM((pal.detail::jsonb->>'balanceDeducted')::double precision), 0)
FROM payment_audit_logs pal
INNER JOIN payment_orders po ON po.id = pal.order_id::bigint
WHERE po.user_id = $1
  AND pal.action = 'REFUND_SUCCESS'
  AND pal.detail::jsonb->>'balanceDeducted' IS NOT NULL`, userID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var total float64
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, rows.Err()
}

func (s *RefundAssessmentService) collectSlots(ctx context.Context, userID int64) ([]PoolSlot, error) {
	var slots []PoolSlot

	// 1. 付费订单
	orderSlots, err := s.queryPaymentOrderSlots(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("payment orders: %w", err)
	}
	slots = append(slots, orderSlots...)

	// 2. 兑换码 type=balance（付费，ratio=1）
	redeemSlots, err := s.queryRedeemBalanceSlots(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("redeem balance: %w", err)
	}
	slots = append(slots, redeemSlots...)

	// 3. 管理员调整 type=admin_balance, value>0（免费，ratio=0）
	adminSlots, err := s.queryAdminBalanceSlots(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("admin balance: %w", err)
	}
	slots = append(slots, adminSlots...)

	// 4. 推荐人转余额（免费，ratio=0）
	affSlots, err := s.queryAffiliateTransferSlots(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("affiliate transfer: %w", err)
	}
	slots = append(slots, affSlots...)

	return slots, nil
}

func (s *RefundAssessmentService) queryPaymentOrderSlots(ctx context.Context, userID int64) ([]PoolSlot, error) {
	// 同时查退费扣减信息
	rows, err := s.entClient.QueryContext(ctx, `
SELECT po.id,
       po.amount::double precision,
       po.pay_amount::double precision,
       po.completed_at,
       po.status,
       COALESCE((
           SELECT (pal.detail::jsonb->>'balanceDeducted')::double precision
           FROM payment_audit_logs pal
           WHERE pal.order_id = po.id::text
             AND pal.action = 'REFUND_SUCCESS'
           ORDER BY pal.created_at DESC
           LIMIT 1
       ), 0) AS refund_deducted,
       po.out_trade_no
FROM payment_orders po
WHERE po.user_id = $1
  AND po.order_type = 'balance'
  AND po.status IN ('completed', 'refunded', 'partially_refunded')
  AND po.completed_at IS NOT NULL
ORDER BY po.completed_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var slots []PoolSlot
	for rows.Next() {
		var (
			id             int64
			amount         float64
			payAmount      float64
			completedAt    time.Time
			status         string
			refundDeducted float64
			outTradeNo     string
		)
		if err := rows.Scan(&id, &amount, &payAmount, &completedAt, &status, &refundDeducted, &outTradeNo); err != nil {
			return nil, err
		}
		ratio := 0.0
		if amount > 0 {
			ratio = payAmount / amount
		}
		refundStatus := ""
		switch status {
		case "refunded":
			refundStatus = "refunded"
		case "partially_refunded":
			refundStatus = "partially_refunded"
		}
		slots = append(slots, PoolSlot{
			Source:         SlotSourcePaymentOrder,
			SourceID:       id,
			CreditedAt:     completedAt,
			Amount:         amount,
			PayAmount:      payAmount,
			Ratio:          roundTo8(ratio),
			RefundStatus:   refundStatus,
			RefundDeducted: refundDeducted,
			Note:           fmt.Sprintf("订单 #%d (%s)", id, outTradeNo),
		})
	}
	return slots, rows.Err()
}

func (s *RefundAssessmentService) queryRedeemBalanceSlots(ctx context.Context, userID int64) ([]PoolSlot, error) {
	rows, err := s.entClient.QueryContext(ctx, `
SELECT rc.id,
       rc.value::double precision,
       rc.used_at,
       rc.code,
       COALESCE(po.pay_amount::double precision, rc.value::double precision) AS real_pay_amount
FROM redeem_codes rc
LEFT JOIN payment_orders po
  ON po.recharge_code = rc.code
  AND po.user_id = $1
WHERE rc.used_by = $1
  AND rc.type = 'balance'
  AND rc.value > 0
  AND rc.used_at IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM payment_orders po2
      WHERE po2.recharge_code = rc.code
        AND po2.user_id = $1
        AND po2.order_type = 'balance'
        AND po2.status IN ('completed', 'refunded', 'partially_refunded')
        AND po2.completed_at IS NOT NULL
  )
ORDER BY rc.used_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var slots []PoolSlot
	for rows.Next() {
		var (
			id           int64
			value        float64
			usedAt       time.Time
			code         string
			realPayAmt   float64
		)
		if err := rows.Scan(&id, &value, &usedAt, &code, &realPayAmt); err != nil {
			return nil, err
		}
		ratio := 0.0
		if value > 0 {
			ratio = realPayAmt / value
		}
		slots = append(slots, PoolSlot{
			Source:     SlotSourceRedeemBalance,
			SourceID:   id,
			CreditedAt: usedAt,
			Amount:     value,
			PayAmount:  realPayAmt,
			Ratio:      roundTo8(ratio),
			Note:       fmt.Sprintf("兑换码 %s", maskCode(code)),
		})
	}
	return slots, rows.Err()
}

func (s *RefundAssessmentService) queryAdminBalanceSlots(ctx context.Context, userID int64) ([]PoolSlot, error) {
	rows, err := s.entClient.QueryContext(ctx, `
SELECT id, value::double precision, used_at, COALESCE(notes, '')
FROM redeem_codes
WHERE used_by = $1
  AND type = 'admin_balance'
  AND value > 0
  AND used_at IS NOT NULL
ORDER BY used_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var slots []PoolSlot
	for rows.Next() {
		var (
			id     int64
			value  float64
			usedAt time.Time
			notes  string
		)
		if err := rows.Scan(&id, &value, &usedAt, &notes); err != nil {
			return nil, err
		}
		note := "管理员调整"
		if notes != "" {
			note = fmt.Sprintf("管理员调整: %s", truncateNote(notes, 40))
		}
		slots = append(slots, PoolSlot{
			Source:     SlotSourceAdminBalance,
			SourceID:   id,
			CreditedAt: usedAt,
			Amount:     value,
			PayAmount:  0,
			Ratio:      0,
			Note:       note,
		})
	}
	return slots, rows.Err()
}

func (s *RefundAssessmentService) queryAffiliateTransferSlots(ctx context.Context, userID int64) ([]PoolSlot, error) {
	rows, err := s.entClient.QueryContext(ctx, `
SELECT id, amount::double precision, created_at
FROM user_affiliate_ledger
WHERE user_id = $1
  AND action = 'transfer'
  AND amount > 0
ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var slots []PoolSlot
	for rows.Next() {
		var (
			id        int64
			amount    float64
			createdAt time.Time
		)
		if err := rows.Scan(&id, &amount, &createdAt); err != nil {
			return nil, err
		}
		slots = append(slots, PoolSlot{
			Source:     SlotSourceAffiliateTransfer,
			SourceID:   id,
			CreditedAt: createdAt,
			Amount:     amount,
			PayAmount:  0,
			Ratio:      0,
			Note:       "推荐返佣转入",
		})
	}
	return slots, rows.Err()
}

// --- Helpers ---

func computeSummary(slots []PoolSlot) AssessmentSummary {
	var s AssessmentSummary
	for _, slot := range slots {
		if slot.Ratio > 0 {
			s.TotalPaidCredited += slot.Amount
			s.TotalPaidConsumed += slot.Consumed
			s.TotalPaidMoneySpent += slot.ConsumedMoney
		} else {
			s.TotalFreeCredited += slot.Amount
			s.TotalFreeConsumed += slot.Consumed
		}
	}
	s.TotalPaidCredited = roundTo8(s.TotalPaidCredited)
	s.TotalFreeCredited = roundTo8(s.TotalFreeCredited)
	s.TotalPaidConsumed = roundTo8(s.TotalPaidConsumed)
	s.TotalFreeConsumed = roundTo8(s.TotalFreeConsumed)
	s.TotalPaidMoneySpent = roundTo8(s.TotalPaidMoneySpent)
	return s
}

func roundTo8(v float64) float64 {
	return math.Round(v*1e8) / 1e8
}

func maskCode(code string) string {
	if len(code) <= 6 {
		return code
	}
	return code[:3] + "***" + code[len(code)-3:]
}

func truncateNote(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "…"
}

// resolveCurrentPool 获取用户当前充值池余额（复用 gift engine 或直接取 user.Balance）。
func (s *RefundAssessmentService) resolveCurrentPool(ctx context.Context, user *User) float64 {
	pool := 0.0
	if s.giftEngine != nil {
		if p, err := s.giftEngine.GetRechargePool(ctx, user.ID); err == nil {
			pool = p
		}
	} else {
		pool = user.Balance
	}
	if pool < 0 {
		pool = 0
	}
	return pool
}
