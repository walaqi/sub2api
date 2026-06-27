//go:build integration

package keybind

import (
	"context"
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
	id, err := creator.CreateBindKeyDiscount(ctx, 800100, 999901, 10.0, 100, 3)
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
	id, err := creator.CreateBindKeyDiscount(ctx, 800101, 999902, 10.5, 100, 3)
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
	id, err := creator.CreateBindKeyDiscount(ctx, 800102, 999903, 5.0, 3000, 5)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// Cleanup
	_, _ = client.ExecContext(ctx, "DELETE FROM user_recharge_discounts WHERE id = $1", id)
}
