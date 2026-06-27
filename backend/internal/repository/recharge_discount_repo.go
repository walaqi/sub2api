package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
)

// RechargeDiscount represents a row in user_recharge_discounts.
type RechargeDiscount struct {
	ID                    int64
	UserID                int64
	Source                string
	SourceRef             string
	OriginAPIKeyID        *int64
	TotalDiscounted       float64
	DiscountRate          float64
	MaxDiscountableAmount float64
	ValidFrom             time.Time
	ValidUntil            *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// RechargeDiscountApplication represents a row in recharge_discount_applications.
type RechargeDiscountApplication struct {
	ID                   int64
	UserID               int64
	DiscountID           int64
	PaymentOrderID       int64
	AppliedAmount        float64
	BonusAmount          float64
	DiscountRateSnapshot float64
	GiftID               *int64
	CreatedAt            time.Time
}

// RechargeDiscountRepository handles persistence for the user_recharge_discounts
// and recharge_discount_applications tables.
type RechargeDiscountRepository struct {
	client *dbent.Client
}

func NewRechargeDiscountRepository(client *dbent.Client) *RechargeDiscountRepository {
	return &RechargeDiscountRepository{client: client}
}

// CreateDiscount inserts a new discount record. Uses ON CONFLICT DO NOTHING for idempotency.
// Returns the created/existing record ID.
func (r *RechargeDiscountRepository) CreateDiscount(ctx context.Context, d *RechargeDiscount) (int64, error) {
	var id int64
	rows, err := r.execer(ctx).QueryContext(ctx, `
INSERT INTO user_recharge_discounts (user_id, source, source_ref, origin_api_key_id, discount_rate, max_discountable_amount, valid_from, valid_until)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (user_id, source, source_ref) DO NOTHING
RETURNING id`, d.UserID, d.Source, d.SourceRef, nullableInt64(d.OriginAPIKeyID), d.DiscountRate, d.MaxDiscountableAmount, d.ValidFrom, nullableTime(d.ValidUntil))
	if err != nil {
		return 0, fmt.Errorf("insert user_recharge_discounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		return id, rows.Close()
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	// ON CONFLICT hit — fetch existing ID
	existingRows, err := r.execer(ctx).QueryContext(ctx,
		`SELECT id FROM user_recharge_discounts WHERE user_id = $1 AND source = $2 AND source_ref = $3 LIMIT 1`,
		d.UserID, d.Source, d.SourceRef)
	if err != nil {
		return 0, fmt.Errorf("query existing discount: %w", err)
	}
	defer func() { _ = existingRows.Close() }()
	if existingRows.Next() {
		if err := existingRows.Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, existingRows.Close()
}

// QueryBestActiveDiscountForUpdate returns the user's best active discount (highest rate,
// then nearest expiry) with a FOR UPDATE lock for concurrent safety.
// Returns nil if no active discount exists.
func (r *RechargeDiscountRepository) QueryBestActiveDiscountForUpdate(ctx context.Context, userID int64) (*RechargeDiscount, error) {
	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, user_id, source, source_ref, origin_api_key_id,
       total_discounted::double precision, discount_rate,
       max_discountable_amount::double precision, valid_from, valid_until
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

	var d RechargeDiscount
	var originKeyID sql.NullInt64
	var validUntil sql.NullTime
	if err := rows.Scan(&d.ID, &d.UserID, &d.Source, &d.SourceRef, &originKeyID,
		&d.TotalDiscounted, &d.DiscountRate, &d.MaxDiscountableAmount, &d.ValidFrom, &validUntil); err != nil {
		return nil, err
	}
	if originKeyID.Valid {
		d.OriginAPIKeyID = &originKeyID.Int64
	}
	if validUntil.Valid {
		d.ValidUntil = &validUntil.Time
	}
	return &d, rows.Close()
}

// QueryBestActiveDiscount returns the user's best active discount without locking.
// Used for read-only status queries.
func (r *RechargeDiscountRepository) QueryBestActiveDiscount(ctx context.Context, userID int64) (*RechargeDiscount, error) {
	rows, err := r.execer(ctx).QueryContext(ctx, `
SELECT id, user_id, source, source_ref, origin_api_key_id,
       total_discounted::double precision, discount_rate,
       max_discountable_amount::double precision, valid_from, valid_until
FROM user_recharge_discounts
WHERE user_id = $1
  AND valid_from <= NOW()
  AND (valid_until IS NULL OR valid_until >= NOW())
  AND total_discounted < max_discountable_amount
ORDER BY discount_rate DESC, valid_until ASC NULLS LAST
LIMIT 1`, userID)
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

	var d RechargeDiscount
	var originKeyID sql.NullInt64
	var validUntil sql.NullTime
	if err := rows.Scan(&d.ID, &d.UserID, &d.Source, &d.SourceRef, &originKeyID,
		&d.TotalDiscounted, &d.DiscountRate, &d.MaxDiscountableAmount, &d.ValidFrom, &validUntil); err != nil {
		return nil, err
	}
	if originKeyID.Valid {
		d.OriginAPIKeyID = &originKeyID.Int64
	}
	if validUntil.Valid {
		d.ValidUntil = &validUntil.Time
	}
	return &d, rows.Close()
}

// UpdateTotalDiscounted adds appliedAmount to the discount's total_discounted.
func (r *RechargeDiscountRepository) UpdateTotalDiscounted(ctx context.Context, discountID int64, appliedAmount float64) error {
	_, err := r.execer(ctx).ExecContext(ctx,
		`UPDATE user_recharge_discounts SET total_discounted = total_discounted + $1, updated_at = NOW() WHERE id = $2`,
		appliedAmount, discountID)
	if err != nil {
		return fmt.Errorf("update total_discounted: %w", err)
	}
	return nil
}

// CheckApplicationExists returns true if a discount application already exists for the given order.
func (r *RechargeDiscountRepository) CheckApplicationExists(ctx context.Context, paymentOrderID int64) (bool, error) {
	rows, err := r.execer(ctx).QueryContext(ctx,
		`SELECT 1 FROM recharge_discount_applications WHERE payment_order_id = $1 LIMIT 1`, paymentOrderID)
	if err != nil {
		return false, fmt.Errorf("check application exists: %w", err)
	}
	defer func() { _ = rows.Close() }()
	exists := rows.Next()
	return exists, rows.Close()
}

// InsertApplication records a discount application (idempotent via unique index on payment_order_id).
func (r *RechargeDiscountRepository) InsertApplication(ctx context.Context, app *RechargeDiscountApplication) error {
	_, err := r.execer(ctx).ExecContext(ctx, `
INSERT INTO recharge_discount_applications (user_id, discount_id, payment_order_id, applied_amount, bonus_amount, discount_rate_snapshot, gift_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (payment_order_id) DO NOTHING`,
		app.UserID, app.DiscountID, app.PaymentOrderID, app.AppliedAmount, app.BonusAmount, app.DiscountRateSnapshot, nullableInt64(app.GiftID))
	if err != nil {
		return fmt.Errorf("insert recharge_discount_applications: %w", err)
	}
	return nil
}

// execer returns a query executor from context (supports transactions).
func (r *RechargeDiscountRepository) execer(ctx context.Context) interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
} {
	if tx := dbent.TxFromContext(ctx); tx != nil {
		return tx.Client()
	}
	return r.client
}

func nullableInt64(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullableTime(v *time.Time) any {
	if v == nil {
		return nil
	}
	return *v
}
