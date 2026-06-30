//go:build integration

package keybind

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/lib/pq"
)

const integrationDSN = "host=localhost port=5432 user=sub2api password=sub2api dbname=sub2api sslmode=disable"

func TestIntegration_CreateBindKeyDiscount_Rate10_Succeeds(t *testing.T) {
	client, err := dbent.Open("postgres", integrationDSN)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	creator := NewEntDiscountCreator(client)
	ctx := context.Background()

	// rate=10.0 should succeed (DB CHECK <= 10)
	id, err := creator.CreateBindKeyDiscount(ctx, 800100, 999901, 10.0, 100, 3, "priority", nil, "", nil)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// Cleanup
	_, _ = client.ExecContext(ctx, "DELETE FROM user_recharge_discounts WHERE id = $1", id)
}

func TestIntegration_CreateBindKeyDiscount_Rate10_5_Rejected(t *testing.T) {
	client, err := dbent.Open("postgres", integrationDSN)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	creator := NewEntDiscountCreator(client)
	ctx := context.Background()

	// rate=10.5 should be rejected by code validation (before hitting DB)
	id, err := creator.CreateBindKeyDiscount(ctx, 800101, 999902, 10.5, 100, 3, "priority", nil, "", nil)
	assert.Error(t, err)
	assert.Equal(t, int64(0), id)
}

func TestIntegration_CreateBindKeyDiscount_Rate5_Succeeds(t *testing.T) {
	client, err := dbent.Open("postgres", integrationDSN)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	creator := NewEntDiscountCreator(client)
	ctx := context.Background()

	// rate=5.0 — typical high-multiplier use case
	id, err := creator.CreateBindKeyDiscount(ctx, 800102, 999903, 5.0, 3000, 5, "priority", nil, "", nil)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// Cleanup
	_, _ = client.ExecContext(ctx, "DELETE FROM user_recharge_discounts WHERE id = $1", id)
}

func TestIntegration_CreateBindKeyDiscount_PersistsGiftExpiryNever(t *testing.T) {
	client, err := dbent.Open("postgres", integrationDSN)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	sqlDB, err := sql.Open("postgres", integrationDSN)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	creator := NewEntDiscountCreator(client)
	ctx := context.Background()

	ratio := 0.5
	id, err := creator.CreateBindKeyDiscount(ctx, 800103, 999904, 0.2, 100, 3, "ratio", &ratio, "never", nil)
	require.NoError(t, err)
	require.Greater(t, id, int64(0))
	t.Cleanup(func() { _, _ = client.ExecContext(ctx, "DELETE FROM user_recharge_discounts WHERE id = $1", id) })

	var mode string
	var giftRatio sql.NullFloat64
	var expiryMode string
	var expiryDays sql.NullInt64
	err = sqlDB.QueryRowContext(ctx, `
SELECT gift_deduction_mode, gift_ratio_recharge::double precision, gift_expiry_mode, gift_expires_after_days
FROM user_recharge_discounts WHERE id = $1`, id).Scan(&mode, &giftRatio, &expiryMode, &expiryDays)
	require.NoError(t, err)
	assert.Equal(t, "ratio", mode)
	require.True(t, giftRatio.Valid)
	assert.InDelta(t, 0.5, giftRatio.Float64, 0.0001)
	assert.Equal(t, "never", expiryMode)
	assert.False(t, expiryDays.Valid)
}
