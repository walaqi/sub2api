package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/domain"
)

// rechargeDiscountRepoImpl implements RechargeDiscountRepo using raw SQL via ent client.
// Lives in service package to avoid circular imports (repository → service → repository).
type rechargeDiscountRepoImpl struct {
	client *dbent.Client
}

// NewRechargeDiscountRepoAdapter creates a RechargeDiscountRepo backed by the ent client.
func NewRechargeDiscountRepoAdapter(client *dbent.Client) RechargeDiscountRepo {
	if client == nil {
		return nil
	}
	return &rechargeDiscountRepoImpl{client: client}
}

func (r *rechargeDiscountRepoImpl) execer(ctx context.Context) interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
} {
	if tx := dbent.TxFromContext(ctx); tx != nil {
		return tx.Client()
	}
	return r.client
}

func (r *rechargeDiscountRepoImpl) CheckApplicationExists(ctx context.Context, paymentOrderID int64) (bool, error) {
	rows, err := r.execer(ctx).QueryContext(ctx,
		`SELECT 1 FROM recharge_discount_applications WHERE payment_order_id = $1 LIMIT 1`, paymentOrderID)
	if err != nil {
		return false, fmt.Errorf("check application exists: %w", err)
	}
	defer func() { _ = rows.Close() }()
	exists := rows.Next()
	return exists, rows.Close()
}

func (r *rechargeDiscountRepoImpl) QueryBestActiveDiscountForUpdate(ctx context.Context, userID int64) (*RechargeDiscountRecord, error) {
	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, user_id, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_until,
       gift_deduction_mode,
       gift_ratio_recharge::double precision,
       gift_expiry_mode,
       gift_expires_after_days
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= NOW()
  AND (valid_until IS NULL OR valid_until >= NOW())
  AND total_discounted < max_discountable_amount
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST
LIMIT 1
FOR UPDATE`, userID)
	if err != nil {
		return nil, fmt.Errorf("query best active discount: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	var d RechargeDiscountRecord
	var validUntil sql.NullTime
	var ratio sql.NullFloat64
	var expiryDays sql.NullInt64
	if err := rows.Scan(&d.ID, &d.UserID, &d.DiscountRate, &d.MaxDiscountableAmount, &d.TotalDiscounted, &validUntil, &d.GiftDeductionMode, &ratio, &d.GiftExpiryMode, &expiryDays); err != nil {
		return nil, err
	}
	if validUntil.Valid {
		d.ValidUntil = &validUntil.Time
	}
	if ratio.Valid {
		v := ratio.Float64
		d.GiftRatioRecharge = &v
	}
	if expiryDays.Valid {
		v := int(expiryDays.Int64)
		d.GiftExpiresAfterDays = &v
	}
	return &d, rows.Close()
}

func (r *rechargeDiscountRepoImpl) UpdateTotalDiscounted(ctx context.Context, discountID int64, appliedAmount float64) error {
	_, err := r.execer(ctx).ExecContext(ctx,
		`UPDATE user_recharge_discounts SET total_discounted = total_discounted + $1, updated_at = NOW() WHERE id = $2`,
		appliedAmount, discountID)
	if err != nil {
		return fmt.Errorf("update total_discounted: %w", err)
	}
	return nil
}

func (r *rechargeDiscountRepoImpl) ClaimApplication(ctx context.Context, app *RechargeDiscountApplicationRecord) (bool, error) {
	res, err := r.execer(ctx).ExecContext(ctx, `
INSERT INTO recharge_discount_applications (user_id, discount_id, payment_order_id, applied_amount, bonus_amount, discount_rate_snapshot, gift_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (payment_order_id) DO NOTHING`,
		app.UserID, app.DiscountID, app.PaymentOrderID, app.AppliedAmount, app.BonusAmount, app.DiscountRateSnapshot, nullableInt64Ptr(app.GiftID))
	if err != nil {
		return false, fmt.Errorf("insert recharge_discount_applications: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (r *rechargeDiscountRepoImpl) UpdateApplicationGiftID(ctx context.Context, paymentOrderID int64, giftID int64) error {
	_, err := r.execer(ctx).ExecContext(ctx,
		`UPDATE recharge_discount_applications SET gift_id = $1 WHERE payment_order_id = $2`,
		giftID, paymentOrderID)
	if err != nil {
		return fmt.Errorf("update application gift_id: %w", err)
	}
	return nil
}

// CreateDiscount inserts a new discount record. Uses ON CONFLICT DO NOTHING for idempotency.
// The gift deduction mode/ratio are normalized (empty/unknown → priority, priority forces ratio nil).
func (r *rechargeDiscountRepoImpl) CreateDiscount(ctx context.Context, in CreateRechargeDiscountInput) (int64, error) {
	var validUntilArg any
	if in.ValidUntil != nil {
		validUntilArg = *in.ValidUntil
	}
	var keyIDArg any
	if in.OriginAPIKeyID != nil {
		keyIDArg = *in.OriginAPIKeyID
	}

	// 归一化赠金策略（写入边界兜底，与 DB check 双重保障）。
	mode, ratio, err := domain.NormalizeGiftDeduction(in.GiftDeductionMode, in.GiftRatioRecharge)
	if err != nil {
		return 0, fmt.Errorf("invalid gift deduction config: %w", err)
	}
	var ratioArg any
	if ratio != nil {
		ratioArg = *ratio
	}
	expiryMode, expiryDays, err := domain.NormalizeGiftExpiry(in.GiftExpiryMode, in.GiftExpiresAfterDays)
	if err != nil {
		return 0, fmt.Errorf("invalid gift expiry config: %w", err)
	}
	var expiryDaysArg any
	if expiryDays != nil {
		expiryDaysArg = *expiryDays
	}

	rows, err := r.execer(ctx).QueryContext(ctx, `
INSERT INTO user_recharge_discounts (user_id, source, source_ref, origin_api_key_id, discount_rate, max_discountable_amount, valid_from, valid_until, gift_deduction_mode, gift_ratio_recharge, gift_expiry_mode, gift_expires_after_days)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (user_id, source, source_ref) DO NOTHING
RETURNING id`, in.UserID, in.Source, in.SourceRef, keyIDArg, in.Rate, in.MaxAmount, in.ValidFrom, validUntilArg, mode, ratioArg, expiryMode, expiryDaysArg)
	if err != nil {
		return 0, fmt.Errorf("insert user_recharge_discounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var id int64
	if rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		return id, rows.Close()
	}
	// ON CONFLICT hit — return 0 (already exists)
	return 0, rows.Close()
}

func nullableInt64Ptr(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// QueryActiveDiscountsReadOnly returns all active (non-exhausted, non-expired) discounts for a user.
// Read-only: no FOR UPDATE, safe to call outside transactions.
func (r *rechargeDiscountRepoImpl) QueryActiveDiscountsReadOnly(ctx context.Context, userID int64) ([]RechargeDiscountSummary, error) {
	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, source, source_ref, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_from, valid_until,
       gift_deduction_mode, gift_ratio_recharge::double precision,
       gift_expiry_mode, gift_expires_after_days
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= NOW()
  AND (valid_until IS NULL OR valid_until >= NOW())
  AND total_discounted < max_discountable_amount
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST`, userID)
	if err != nil {
		return nil, fmt.Errorf("query active discounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanRechargeDiscountSummaries(rows)
}

// QueryDiscountsForInheritance returns discounts eligible for referral inheritance.
// Unlike active discounts for recharge application, quota exhaustion does not matter here.
func (r *rechargeDiscountRepoImpl) QueryDiscountsForInheritance(ctx context.Context, userID int64) ([]RechargeDiscountSummary, error) {
	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, source, source_ref, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_from, valid_until,
       gift_deduction_mode, gift_ratio_recharge::double precision,
       gift_expiry_mode, gift_expires_after_days
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= NOW()
  AND (valid_until IS NULL OR valid_until >= NOW())
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST`, userID)
	if err != nil {
		return nil, fmt.Errorf("query inheritance discounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanRechargeDiscountSummaries(rows)
}

// QueryDiscountsForInheritanceAtTime returns discounts eligible for referral inheritance
// at a specific historical bind time.
func (r *rechargeDiscountRepoImpl) QueryDiscountsForInheritanceAtTime(ctx context.Context, userID int64, atTime time.Time) ([]RechargeDiscountSummary, error) {
	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, source, source_ref, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_from, valid_until,
       gift_deduction_mode, gift_ratio_recharge::double precision,
       gift_expiry_mode, gift_expires_after_days
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= $2
  AND (valid_until IS NULL OR valid_until >= $2)
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST`, userID, atTime)
	if err != nil {
		return nil, fmt.Errorf("query inheritance discounts at time: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanRechargeDiscountSummaries(rows)
}

func (r *rechargeDiscountRepoImpl) QueryDiscountsForEligibilityAfterRecharge(ctx context.Context, userID int64, minAppliedAmount float64) ([]RechargeDiscountSummary, error) {
	return r.queryDiscountsForEligibilityAfterRechargeAtTime(ctx, userID, time.Now(), minAppliedAmount)
}

func (r *rechargeDiscountRepoImpl) QueryDiscountsForEligibilityAfterRechargeAtTime(ctx context.Context, userID int64, atTime time.Time, minAppliedAmount float64) ([]RechargeDiscountSummary, error) {
	return r.queryDiscountsForEligibilityAfterRechargeAtTime(ctx, userID, atTime, minAppliedAmount)
}

func (r *rechargeDiscountRepoImpl) queryDiscountsForEligibilityAfterRechargeAtTime(ctx context.Context, userID int64, atTime time.Time, minAppliedAmount float64) ([]RechargeDiscountSummary, error) {
	if minAppliedAmount <= 0 {
		rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, source, source_ref, discount_rate,
       max_discountable_amount::double precision,
       total_discounted::double precision,
       valid_from, valid_until,
       gift_deduction_mode, gift_ratio_recharge::double precision,
       gift_expiry_mode, gift_expires_after_days
FROM user_recharge_discounts d
WHERE d.user_id = $1
  AND d.valid_from <= $2
  AND (d.valid_until IS NULL OR d.valid_until >= $2)
  AND EXISTS (
    SELECT 1
    FROM recharge_discount_applications a
    WHERE a.discount_id = d.id
      AND a.created_at <= $2
  )
ORDER BY d.discount_rate DESC, d.valid_until ASC NULLS LAST`, userID, atTime)
		if err != nil {
			return nil, fmt.Errorf("query recharge eligibility discounts: %w", err)
		}
		defer func() { _ = rows.Close() }()
		return scanRechargeDiscountSummaries(rows)
	}

	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT d.id, d.source, d.source_ref, d.discount_rate,
       d.max_discountable_amount::double precision,
       d.total_discounted::double precision,
       d.valid_from, d.valid_until,
       d.gift_deduction_mode, d.gift_ratio_recharge::double precision,
       d.gift_expiry_mode, d.gift_expires_after_days
FROM user_recharge_discounts d
JOIN recharge_discount_applications a ON a.discount_id = d.id
WHERE d.user_id = $1
  AND d.valid_from <= $2
  AND (d.valid_until IS NULL OR d.valid_until >= $2)
  AND a.created_at <= $2
GROUP BY d.id
HAVING SUM(a.applied_amount) >= $3
ORDER BY d.discount_rate DESC, d.valid_until ASC NULLS LAST`, userID, atTime, minAppliedAmount)
	if err != nil {
		return nil, fmt.Errorf("query recharge eligibility discounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanRechargeDiscountSummaries(rows)
}

func scanRechargeDiscountSummaries(rows *sql.Rows) ([]RechargeDiscountSummary, error) {
	var results []RechargeDiscountSummary
	for rows.Next() {
		var d RechargeDiscountSummary
		var validUntil sql.NullTime
		var ratio sql.NullFloat64
		var expiryDays sql.NullInt64
		if err := rows.Scan(&d.ID, &d.Source, &d.SourceRef, &d.DiscountRate, &d.MaxDiscountableAmount, &d.TotalDiscounted, &d.ValidFrom, &validUntil, &d.GiftDeductionMode, &ratio, &d.GiftExpiryMode, &expiryDays); err != nil {
			return nil, err
		}
		if validUntil.Valid {
			d.ValidUntil = &validUntil.Time
		}
		if ratio.Valid {
			v := ratio.Float64
			d.GiftRatioRecharge = &v
		}
		if expiryDays.Valid {
			v := int(expiryDays.Int64)
			d.GiftExpiresAfterDays = &v
		}
		results = append(results, d)
	}
	return results, rows.Err()
}

// RechargeDiscountSummary is the read-only view of an active discount for user display.
type RechargeDiscountSummary struct {
	ID                    int64
	Source                string
	SourceRef             string
	DiscountRate          float64
	MaxDiscountableAmount float64
	TotalDiscounted       float64
	ValidFrom             time.Time
	ValidUntil            *time.Time
	// GiftDeductionMode / GiftRatioRecharge / GiftExpiry* 是该折扣发放赠金的策略（随行固化）。
	GiftDeductionMode    string
	GiftRatioRecharge    *float64
	GiftExpiryMode       string
	GiftExpiresAfterDays *int
}
