//go:build integration

package service

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDSN = "host=localhost port=5432 user=sub2api password=sub2api dbname=sub2api sslmode=disable"

func setupIntegrationDB(t *testing.T) (*dbent.Client, *sql.DB) {
	t.Helper()
	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	// 本包无 testcontainers harness，直连外部 PG（本地 5432）。CI 等无 PG 环境
	// 下应跳过而非失败——这些用例覆盖并发支付/赠金逻辑，需真实 PG 才有意义。
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		t.Skipf("integration DB unavailable at %s, skipping: %v", testDSN, err)
	}

	client, err := dbent.Open("postgres", testDSN)
	require.NoError(t, err)

	// Clean test data before each test
	_, _ = sqlDB.Exec("DELETE FROM recharge_discount_applications WHERE user_id >= 900000")
	_, _ = sqlDB.Exec("DELETE FROM user_recharge_discounts WHERE user_id >= 900000")
	_, _ = sqlDB.Exec("DELETE FROM user_gifts WHERE user_id >= 900000")

	t.Cleanup(func() {
		_, _ = sqlDB.Exec("DELETE FROM recharge_discount_applications WHERE user_id >= 900000")
		_, _ = sqlDB.Exec("DELETE FROM user_recharge_discounts WHERE user_id >= 900000")
		_, _ = sqlDB.Exec("DELETE FROM user_gifts WHERE user_id >= 900000")
		_ = client.Close()
		_ = sqlDB.Close()
	})
	return client, sqlDB
}

func insertTestDiscount(t *testing.T, db *sql.DB, userID int64, rate, max float64, validDays int) int64 {
	t.Helper()
	now := time.Now()
	validUntil := now.Add(time.Duration(validDays) * 24 * time.Hour)
	sourceRef := fmt.Sprintf("test:%d:%d", userID, now.UnixNano())
	var id int64
	err := db.QueryRow(`
INSERT INTO user_recharge_discounts (user_id, source, source_ref, discount_rate, max_discountable_amount, valid_from, valid_until)
VALUES ($1, 'bind_key', $2, $3, $4, $5, $6)
RETURNING id`, userID, sourceRef, rate, max, now, validUntil).Scan(&id)
	require.NoError(t, err)
	return id
}

// insertTestDiscountWithPolicy is like insertTestDiscount but also fixes the gift
// deduction and expiry policies on the row, so end-to-end tests can verify the
// policy is carried through SELECT/scan/Grant onto user_gifts.
func insertTestDiscountWithPolicy(t *testing.T, db *sql.DB, userID int64, rate, max float64, validDays int, mode string, ratio *float64, expiryMode string, expiryDays *int) int64 {
	t.Helper()
	now := time.Now()
	validUntil := now.Add(time.Duration(validDays) * 24 * time.Hour)
	sourceRef := fmt.Sprintf("test:%d:%d", userID, now.UnixNano())
	var ratioArg any
	if ratio != nil {
		ratioArg = *ratio
	}
	var expiryDaysArg any
	if expiryDays != nil {
		expiryDaysArg = *expiryDays
	}
	var id int64
	err := db.QueryRow(`
INSERT INTO user_recharge_discounts (user_id, source, source_ref, discount_rate, max_discountable_amount, valid_from, valid_until, gift_deduction_mode, gift_ratio_recharge, gift_expiry_mode, gift_expires_after_days)
VALUES ($1, 'bind_key', $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id`, userID, sourceRef, rate, max, now, validUntil, mode, ratioArg, expiryMode, expiryDaysArg).Scan(&id)
	require.NoError(t, err)
	return id
}

// TestIntegration_ClaimConflict_OnlyOneWins verifies that concurrent claims for the
// same payment_order_id result in exactly one claimed=true.
func TestIntegration_ClaimConflict_OnlyOneWins(t *testing.T) {
	client, db := setupIntegrationDB(t)
	repo := &rechargeDiscountRepoImpl{client: client}
	ctx := context.Background()

	userID := int64(900001)
	discountID := insertTestDiscount(t, db, userID, 0.1, 100, 30)
	orderID := int64(990001)

	const goroutines = 10
	var claimedCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			// Each goroutine opens its own transaction
			tx, err := client.Tx(ctx)
			if err != nil {
				return
			}
			defer func() { _ = tx.Rollback() }()
			txCtx := dbent.NewTxContext(ctx, tx)

			claimed, err := repo.ClaimApplication(txCtx, &RechargeDiscountApplicationRecord{
				UserID:               userID,
				DiscountID:           discountID,
				PaymentOrderID:       orderID,
				AppliedAmount:        50,
				BonusAmount:          5,
				DiscountRateSnapshot: 0.1,
			})
			if err != nil {
				return
			}
			if claimed {
				claimedCount.Add(1)
			}
			_ = tx.Commit()
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), claimedCount.Load(), "exactly one goroutine should win the claim")

	// Verify only one row exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM recharge_discount_applications WHERE payment_order_id = $1", orderID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestIntegration_ConcurrentOrders_DoNotExceedMax verifies that multiple concurrent
// orders consuming the same discount never exceed max_discountable_amount.
func TestIntegration_ConcurrentOrders_DoNotExceedMax(t *testing.T) {
	client, db := setupIntegrationDB(t)
	repo := &rechargeDiscountRepoImpl{client: client}
	ctx := context.Background()

	userID := int64(900002)
	maxAmount := 50.0
	discountID := insertTestDiscount(t, db, userID, 0.1, maxAmount, 30)

	// 10 concurrent orders each trying to use $20 of the $50 limit
	// Only first 2 (maybe 3 partial) should succeed; total <= $50
	const goroutines = 10
	orderAmount := 20.0
	var successCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		orderID := int64(990100 + i)
		go func(oid int64) {
			defer wg.Done()
			tx, err := client.Tx(ctx)
			if err != nil {
				return
			}
			defer func() { _ = tx.Rollback() }()
			txCtx := dbent.NewTxContext(ctx, tx)

			// Query with FOR UPDATE (serializes access)
			discount, err := repo.QueryBestActiveDiscountForUpdate(txCtx, userID)
			if err != nil || discount == nil {
				return
			}

			remaining := discount.MaxDiscountableAmount - discount.TotalDiscounted
			if remaining <= 0 {
				return
			}
			applied := remaining
			if orderAmount < remaining {
				applied = orderAmount
			}

			claimed, err := repo.ClaimApplication(txCtx, &RechargeDiscountApplicationRecord{
				UserID:               userID,
				DiscountID:           discountID,
				PaymentOrderID:       oid,
				AppliedAmount:        applied,
				BonusAmount:          applied * 0.1,
				DiscountRateSnapshot: 0.1,
			})
			if err != nil || !claimed {
				return
			}

			if err := repo.UpdateTotalDiscounted(txCtx, discountID, applied); err != nil {
				return
			}

			if err := tx.Commit(); err != nil {
				return
			}
			successCount.Add(1)
		}(orderID)
	}
	wg.Wait()

	// Verify total_discounted never exceeds max
	var totalDiscounted float64
	err := db.QueryRow("SELECT total_discounted::double precision FROM user_recharge_discounts WHERE id = $1", discountID).Scan(&totalDiscounted)
	require.NoError(t, err)
	assert.LessOrEqual(t, totalDiscounted, maxAmount, "total_discounted must not exceed max_discountable_amount")

	// Verify number of applications matches what we expect
	var appCount int
	err = db.QueryRow("SELECT COUNT(*) FROM recharge_discount_applications WHERE discount_id = $1", discountID).Scan(&appCount)
	require.NoError(t, err)
	assert.Equal(t, int(successCount.Load()), appCount)

	t.Logf("concurrent orders: %d succeeded, total_discounted=%.2f / max=%.2f", successCount.Load(), totalDiscounted, maxAmount)
}

// TestIntegration_ForUpdate_SerializesAccess verifies that FOR UPDATE actually blocks
// concurrent transactions until commit.
func TestIntegration_ForUpdate_SerializesAccess(t *testing.T) {
	client, db := setupIntegrationDB(t)
	repo := &rechargeDiscountRepoImpl{client: client}
	ctx := context.Background()

	userID := int64(900003)
	insertTestDiscount(t, db, userID, 0.1, 100, 30)

	// Two goroutines: first one locks and sleeps, second one should block
	var order sync.Mutex
	var sequence []string
	order.Lock() // prevent race on sequence slice

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: lock row, hold for 200ms
	go func() {
		defer wg.Done()
		tx, _ := client.Tx(ctx)
		defer func() { _ = tx.Rollback() }()
		txCtx := dbent.NewTxContext(ctx, tx)

		_, _ = repo.QueryBestActiveDiscountForUpdate(txCtx, userID)
		order.Unlock() // signal that lock is held
		time.Sleep(200 * time.Millisecond)

		order.Lock()
		sequence = append(sequence, "g1_commit")
		order.Unlock()
		_ = tx.Commit()
	}()

	// Wait for goroutine 1 to acquire lock
	order.Lock()
	order.Unlock()
	time.Sleep(20 * time.Millisecond) // small delay to ensure g1 is holding

	// Goroutine 2: should block on FOR UPDATE until g1 commits
	go func() {
		defer wg.Done()
		tx, _ := client.Tx(ctx)
		defer func() { _ = tx.Rollback() }()
		txCtx := dbent.NewTxContext(ctx, tx)

		_, _ = repo.QueryBestActiveDiscountForUpdate(txCtx, userID)
		order.Lock()
		sequence = append(sequence, "g2_acquired")
		order.Unlock()
		_ = tx.Commit()
	}()

	wg.Wait()

	order.Lock()
	defer order.Unlock()
	// g1 should commit before g2 acquires
	require.Len(t, sequence, 2)
	assert.Equal(t, "g1_commit", sequence[0])
	assert.Equal(t, "g2_acquired", sequence[1])
}

// TestIntegration_FullFlow_BindKeyThenApplyDiscount tests the end-to-end flow:
// create discount → apply on payment → verify gift created + application recorded.
func TestIntegration_FullFlow_BindKeyThenApplyDiscount(t *testing.T) {
	client, db := setupIntegrationDB(t)
	ctx := context.Background()

	userID := int64(900004)
	discountID := insertTestDiscount(t, db, userID, 0.15, 200, 30)

	// Simulate a user with balance (needed for gift.Engine)
	// We need an actual users row for gift engine to work
	var userExists bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&userExists)
	if !userExists {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, balance, status, username, concurrency, total_recharged) VALUES ($1, $2, '', 'user', 100, 'active', 'test_discount_user', 5, 0)`,
			userID, fmt.Sprintf("test_discount_%d@test.local", userID))
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM user_gifts WHERE user_id = $1", userID) })
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM users WHERE id = $1", userID) })
	}

	// Create gift engine
	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	giftEngine := gift.NewEngine(client, sqlDB)

	// Build PaymentService with real repo
	repo := NewRechargeDiscountRepoAdapter(client)
	svc := &PaymentService{
		entClient:            client,
		giftEngine:           giftEngine,
		rechargeDiscountRepo: repo,
	}

	// Simulate payment order
	order := &dbent.PaymentOrder{
		ID:     int64(990200),
		UserID: userID,
		Amount: 80, // $80 recharge
	}

	err = svc.applyRechargeDiscountForOrder(ctx, order)
	require.NoError(t, err)

	// Verify application was created
	var appCount int
	err = db.QueryRow("SELECT COUNT(*) FROM recharge_discount_applications WHERE payment_order_id = $1", order.ID).Scan(&appCount)
	require.NoError(t, err)
	assert.Equal(t, 1, appCount)

	// Verify total_discounted updated
	var totalDiscounted float64
	err = db.QueryRow("SELECT total_discounted::double precision FROM user_recharge_discounts WHERE id = $1", discountID).Scan(&totalDiscounted)
	require.NoError(t, err)
	assert.InDelta(t, 80.0, totalDiscounted, 0.001)

	// Verify gift was created (source=recharge_discount)
	var giftCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id = $1 AND source = 'recharge_discount'", userID).Scan(&giftCount)
	require.NoError(t, err)
	assert.Equal(t, 1, giftCount)

	// Verify bonus amount: $80 * 0.15 = $12
	var giftAmount float64
	err = db.QueryRow("SELECT amount::double precision FROM user_gifts WHERE user_id = $1 AND source = 'recharge_discount' ORDER BY id DESC LIMIT 1", userID).Scan(&giftAmount)
	require.NoError(t, err)
	assert.InDelta(t, 12.0, giftAmount, 0.001)

	// Verify idempotency: calling again should be a no-op
	err = svc.applyRechargeDiscountForOrder(ctx, order)
	require.NoError(t, err)

	// Still only 1 application, 1 gift
	err = db.QueryRow("SELECT COUNT(*) FROM recharge_discount_applications WHERE payment_order_id = $1", order.ID).Scan(&appCount)
	require.NoError(t, err)
	assert.Equal(t, 1, appCount)

	err = db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id = $1 AND source = 'recharge_discount'", userID).Scan(&giftCount)
	require.NoError(t, err)
	assert.Equal(t, 1, giftCount)
}

// TestIntegration_FullFlow_GrantsRatioMode verifies the full SELECT/scan/Grant chain
// carries the discount row's gift_deduction_mode/gift_ratio_recharge through onto the
// created user_gifts row. Guards against dropping the new columns anywhere in the chain.
func TestIntegration_FullFlow_GrantsRatioMode(t *testing.T) {
	client, db := setupIntegrationDB(t)
	ctx := context.Background()

	userID := int64(900005)
	ratio := 0.5
	insertTestDiscountWithPolicy(t, db, userID, 0.15, 200, 30, "ratio", &ratio, "discount_valid_until", nil)

	var userExists bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&userExists)
	if !userExists {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, balance, status, username, concurrency, total_recharged) VALUES ($1, $2, '', 'user', 100, 'active', 'test_ratio_user', 5, 0)`,
			userID, fmt.Sprintf("test_ratio_%d@test.local", userID))
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM user_gifts WHERE user_id = $1", userID) })
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM users WHERE id = $1", userID) })
	}

	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	giftEngine := gift.NewEngine(client, sqlDB)

	repo := NewRechargeDiscountRepoAdapter(client)
	svc := &PaymentService{
		entClient:            client,
		giftEngine:           giftEngine,
		rechargeDiscountRepo: repo,
	}

	order := &dbent.PaymentOrder{ID: int64(990201), UserID: userID, Amount: 80}
	err = svc.applyRechargeDiscountForOrder(ctx, order)
	require.NoError(t, err)

	// The created gift must carry deduction_mode='ratio' and ratio_recharge=0.5.
	var giftMode string
	var giftRatio sql.NullFloat64
	err = db.QueryRow(`SELECT deduction_mode, ratio_recharge::double precision FROM user_gifts
WHERE user_id = $1 AND source = 'recharge_discount' ORDER BY id DESC LIMIT 1`, userID).Scan(&giftMode, &giftRatio)
	require.NoError(t, err)
	assert.Equal(t, "ratio", giftMode)
	require.True(t, giftRatio.Valid, "ratio_recharge should be set for ratio mode")
	assert.InDelta(t, 0.5, giftRatio.Float64, 0.0001)
}

// TestIntegration_FullFlow_GrantsPriorityMode verifies a priority-mode discount grants
// a priority gift with NULL ratio_recharge (default path, no columns leaked).
func TestIntegration_FullFlow_GrantsPriorityMode(t *testing.T) {
	client, db := setupIntegrationDB(t)
	ctx := context.Background()

	userID := int64(900006)
	insertTestDiscountWithPolicy(t, db, userID, 0.15, 200, 30, "priority", nil, "discount_valid_until", nil)

	var userExists bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&userExists)
	if !userExists {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, balance, status, username, concurrency, total_recharged) VALUES ($1, $2, '', 'user', 100, 'active', 'test_prio_user', 5, 0)`,
			userID, fmt.Sprintf("test_prio_%d@test.local", userID))
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM user_gifts WHERE user_id = $1", userID) })
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM users WHERE id = $1", userID) })
	}

	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	giftEngine := gift.NewEngine(client, sqlDB)

	repo := NewRechargeDiscountRepoAdapter(client)
	svc := &PaymentService{
		entClient:            client,
		giftEngine:           giftEngine,
		rechargeDiscountRepo: repo,
	}

	order := &dbent.PaymentOrder{ID: int64(990202), UserID: userID, Amount: 80}
	err = svc.applyRechargeDiscountForOrder(ctx, order)
	require.NoError(t, err)

	var giftMode string
	var giftRatio sql.NullFloat64
	err = db.QueryRow(`SELECT deduction_mode, ratio_recharge::double precision FROM user_gifts
WHERE user_id = $1 AND source = 'recharge_discount' ORDER BY id DESC LIMIT 1`, userID).Scan(&giftMode, &giftRatio)
	require.NoError(t, err)
	assert.Equal(t, "priority", giftMode)
	assert.False(t, giftRatio.Valid, "ratio_recharge should be NULL for priority mode")
}

// TestIntegration_FullFlow_GiftExpiryNever verifies gift_expiry_mode='never'
// creates a recharge-discount gift with NULL expires_at even though the discount
// itself has a finite valid_until.
func TestIntegration_FullFlow_GiftExpiryNever(t *testing.T) {
	client, db := setupIntegrationDB(t)
	ctx := context.Background()

	userID := int64(900007)
	insertTestDiscountWithPolicy(t, db, userID, 0.15, 200, 15, "priority", nil, "never", nil)

	var userExists bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&userExists)
	if !userExists {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, balance, status, username, concurrency, total_recharged) VALUES ($1, $2, '', 'user', 100, 'active', 'test_never_user', 5, 0)`,
			userID, fmt.Sprintf("test_never_%d@test.local", userID))
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM users WHERE id = $1", userID) })
	}

	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	giftEngine := gift.NewEngine(client, sqlDB)

	svc := &PaymentService{
		entClient:            client,
		giftEngine:           giftEngine,
		rechargeDiscountRepo: NewRechargeDiscountRepoAdapter(client),
	}

	order := &dbent.PaymentOrder{ID: int64(990203), UserID: userID, Amount: 80}
	err = svc.applyRechargeDiscountForOrder(ctx, order)
	require.NoError(t, err)

	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT expires_at FROM user_gifts
WHERE user_id = $1 AND source = 'recharge_discount' ORDER BY id DESC LIMIT 1`, userID).Scan(&expiresAt)
	require.NoError(t, err)
	assert.False(t, expiresAt.Valid, "expires_at should be NULL for never mode")
}

// TestIntegration_FullFlow_GiftExpiryAfterDays verifies after_days computes
// gift expiry from grant time instead of reusing discount.valid_until.
func TestIntegration_FullFlow_GiftExpiryAfterDays(t *testing.T) {
	client, db := setupIntegrationDB(t)
	ctx := context.Background()

	userID := int64(900008)
	expiryDays := 3
	insertTestDiscountWithPolicy(t, db, userID, 0.15, 200, 15, "priority", nil, "after_days", &expiryDays)

	var userExists bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&userExists)
	if !userExists {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, balance, status, username, concurrency, total_recharged) VALUES ($1, $2, '', 'user', 100, 'active', 'test_after_days_user', 5, 0)`,
			userID, fmt.Sprintf("test_after_days_%d@test.local", userID))
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = db.Exec("DELETE FROM users WHERE id = $1", userID) })
	}

	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	giftEngine := gift.NewEngine(client, sqlDB)

	svc := &PaymentService{
		entClient:            client,
		giftEngine:           giftEngine,
		rechargeDiscountRepo: NewRechargeDiscountRepoAdapter(client),
	}

	before := time.Now().Add(time.Duration(expiryDays) * 24 * time.Hour)
	order := &dbent.PaymentOrder{ID: int64(990204), UserID: userID, Amount: 80}
	err = svc.applyRechargeDiscountForOrder(ctx, order)
	require.NoError(t, err)
	after := time.Now().Add(time.Duration(expiryDays) * 24 * time.Hour)

	var expiresAt sql.NullTime
	err = db.QueryRow(`SELECT expires_at FROM user_gifts
WHERE user_id = $1 AND source = 'recharge_discount' ORDER BY id DESC LIMIT 1`, userID).Scan(&expiresAt)
	require.NoError(t, err)
	require.True(t, expiresAt.Valid)
	assert.True(t, !expiresAt.Time.Before(before) && !expiresAt.Time.After(after), "expires_at=%s should be within [%s, %s]", expiresAt.Time, before, after)
}

// TestIntegration_QueryOrderGiftBonus 验证按订单查赠金：命中折扣后返回 bonus_amount + 扣除模式；
// 无 application 时返回 nil。用于充值成功页展示"赠金 $X(扣除模式)"。
func TestIntegration_QueryOrderGiftBonus(t *testing.T) {
	client, db := setupIntegrationDB(t)
	repo := &rechargeDiscountRepoImpl{client: client}
	ctx := context.Background()

	// --- 无 application 的订单 → nil ---
	bonus, err := repo.QueryOrderGiftBonus(ctx, int64(990900))
	require.NoError(t, err)
	assert.Nil(t, bonus, "无 application 的订单应返回 nil")

	// --- priority 模式：rate 0.1，充值本金 50 → bonus 5 ---
	userID := int64(900010)
	discountID := insertTestDiscountWithPolicy(t, db, userID, 0.1, 100, 30, "priority", nil, "discount_valid_until", nil)
	priorityOrderID := int64(990901)
	claimed, err := repo.ClaimApplication(ctx, &RechargeDiscountApplicationRecord{
		UserID:               userID,
		DiscountID:           discountID,
		PaymentOrderID:       priorityOrderID,
		AppliedAmount:        50,
		BonusAmount:          5,
		DiscountRateSnapshot: 0.1,
	})
	require.NoError(t, err)
	require.True(t, claimed)

	bonus, err = repo.QueryOrderGiftBonus(ctx, priorityOrderID)
	require.NoError(t, err)
	require.NotNil(t, bonus)
	assert.InDelta(t, 5.0, bonus.BonusAmount, 0.0001)
	assert.Equal(t, "priority", bonus.DeductionMode)
	assert.Nil(t, bonus.RatioRecharge)

	// --- ratio 模式：扣除模式与比例应随折扣行返回 ---
	ratioUserID := int64(900011)
	ratioVal := 2.0
	ratioDiscountID := insertTestDiscountWithPolicy(t, db, ratioUserID, 0.2, 100, 30, "ratio", &ratioVal, "discount_valid_until", nil)
	ratioOrderID := int64(990902)
	claimed, err = repo.ClaimApplication(ctx, &RechargeDiscountApplicationRecord{
		UserID:               ratioUserID,
		DiscountID:           ratioDiscountID,
		PaymentOrderID:       ratioOrderID,
		AppliedAmount:        40,
		BonusAmount:          8,
		DiscountRateSnapshot: 0.2,
	})
	require.NoError(t, err)
	require.True(t, claimed)

	bonus, err = repo.QueryOrderGiftBonus(ctx, ratioOrderID)
	require.NoError(t, err)
	require.NotNil(t, bonus)
	assert.InDelta(t, 8.0, bonus.BonusAmount, 0.0001)
	assert.Equal(t, "ratio", bonus.DeductionMode)
	require.NotNil(t, bonus.RatioRecharge)
	assert.InDelta(t, 2.0, *bonus.RatioRecharge, 0.0001)
}
