package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
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
       valid_until
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
	if err := rows.Scan(&d.ID, &d.UserID, &d.DiscountRate, &d.MaxDiscountableAmount, &d.TotalDiscounted, &validUntil); err != nil {
		return nil, err
	}
	if validUntil.Valid {
		d.ValidUntil = &validUntil.Time
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
func (r *rechargeDiscountRepoImpl) CreateDiscount(ctx context.Context, userID int64, source, sourceRef string, originAPIKeyID *int64, rate, maxAmount float64, validFrom time.Time, validUntil *time.Time) (int64, error) {
	var validUntilArg any
	if validUntil != nil {
		validUntilArg = *validUntil
	}
	var keyIDArg any
	if originAPIKeyID != nil {
		keyIDArg = *originAPIKeyID
	}

	rows, err := r.execer(ctx).QueryContext(ctx, `
INSERT INTO user_recharge_discounts (user_id, source, source_ref, origin_api_key_id, discount_rate, max_discountable_amount, valid_from, valid_until)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (user_id, source, source_ref) DO NOTHING
RETURNING id`, userID, source, sourceRef, keyIDArg, rate, maxAmount, validFrom, validUntilArg)
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
       valid_from, valid_until
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
       valid_from, valid_until
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
       valid_from, valid_until
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

func scanRechargeDiscountSummaries(rows *sql.Rows) ([]RechargeDiscountSummary, error) {
	var results []RechargeDiscountSummary
	for rows.Next() {
		var d RechargeDiscountSummary
		var validUntil sql.NullTime
		if err := rows.Scan(&d.ID, &d.Source, &d.SourceRef, &d.DiscountRate, &d.MaxDiscountableAmount, &d.TotalDiscounted, &d.ValidFrom, &validUntil); err != nil {
			return nil, err
		}
		if validUntil.Valid {
			d.ValidUntil = &validUntil.Time
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
}
