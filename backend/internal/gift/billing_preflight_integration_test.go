//go:build unit

package gift

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/enttest"
)

var preflightDBSeq atomic.Int64

func integRatioPtr(v float64) *float64 { return &v }

func newPreflightTestEngine(t *testing.T) (*Engine, *dbent.Client, *sql.DB) {
	t.Helper()
	dsn := fmt.Sprintf("file:gift_preflight_%d?mode=memory&cache=shared&_fk=1", preflightDBSeq.Add(1))
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	drv := entsql.OpenDB(dialect.SQLite, db)
	client := enttest.NewClient(t, enttest.WithOptions(dbent.Driver(drv)))
	t.Cleanup(func() { _ = client.Close() })
	eng := &Engine{repo: newRepository(client, db)}
	return eng, client, db
}

func seedPreflightUser(t *testing.T, client *dbent.Client, balance float64) int64 {
	t.Helper()
	u, err := client.User.Create().
		SetEmail(fmt.Sprintf("preflight%d@example.com", preflightDBSeq.Load())).
		SetPasswordHash("x").
		SetBalance(balance).
		Save(context.Background())
	require.NoError(t, err)
	return u.ID
}

// ---------------------------------------------------------------------------
// HasActivePriorityGift: SQL correctness (ent query, SQLite compatible)
// ---------------------------------------------------------------------------

func TestHasActivePriorityGift_TrueWhenActivePriorityExists(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)

	_, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 50, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)

	has, err := eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.True(t, has)
}

func TestHasActivePriorityGift_FalseWhenOnlyRatioGift(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)

	_, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 60, Mode: DeductionModeRatio, RatioRecharge: integRatioPtr(2), Source: SourceKeybind})
	require.NoError(t, err)

	has, err := eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.False(t, has)
}

func TestHasActivePriorityGift_FalseWhenExpired(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)

	future := time.Now().Add(24 * time.Hour)
	g, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 50, Mode: DeductionModePriority, ExpiresAt: &future, Source: SourceKeybind})
	require.NoError(t, err)

	// Force expire
	past := time.Now().Add(-time.Hour)
	_, err = client.UserGift.UpdateOneID(g.ID).SetExpiresAt(past).Save(ctx)
	require.NoError(t, err)

	has, err := eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.False(t, has)
}

func TestHasActivePriorityGift_FalseWhenExhausted(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)

	g, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 50, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)

	// Exhaust: remaining=0, status=exhausted
	_, err = client.UserGift.UpdateOneID(g.ID).SetRemaining(0).SetStatus(string(StatusExhausted)).Save(ctx)
	require.NoError(t, err)

	has, err := eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.False(t, has)
}

func TestHasActivePriorityGift_FalseWhenRevoked(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)

	g, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 50, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)

	_, err = client.UserGift.UpdateOneID(g.ID).SetStatus(string(StatusRevoked)).Save(ctx)
	require.NoError(t, err)

	has, err := eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.False(t, has)
}

func TestHasActivePriorityGift_FalseWhenNoGifts(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)
	_ = client

	has, err := eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.False(t, has)
}

// ---------------------------------------------------------------------------
// GetGiftBalance: correctness (used by preflight to compute rechargePool)
// ---------------------------------------------------------------------------

func TestGetGiftBalance_SumsOnlyActiveNonExpired(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 200)

	// Active priority, no expiry → counts
	_, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 30, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)

	// Active ratio → counts
	_, err = eng.Grant(ctx, GrantInput{UserID: uid, Amount: 20, Mode: DeductionModeRatio, RatioRecharge: integRatioPtr(1), Source: SourceKeybind})
	require.NoError(t, err)

	// Expired priority → does NOT count
	future := time.Now().Add(24 * time.Hour)
	expired, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 10, Mode: DeductionModePriority, ExpiresAt: &future, Source: SourceKeybind})
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	_, err = client.UserGift.UpdateOneID(expired.ID).SetExpiresAt(past).Save(ctx)
	require.NoError(t, err)

	// Exhausted → does NOT count
	exhausted, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 15, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)
	_, err = client.UserGift.UpdateOneID(exhausted.ID).SetRemaining(0).SetStatus(string(StatusExhausted)).Save(ctx)
	require.NoError(t, err)

	bal, err := eng.GetGiftBalance(ctx, uid)
	require.NoError(t, err)
	// Only 30 + 20 = 50 counted
	require.InDelta(t, 50.0, bal, 0.001)
}

func TestGetGiftBalance_ZeroWhenNoActiveGifts(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)
	_ = client

	bal, err := eng.GetGiftBalance(ctx, uid)
	require.NoError(t, err)
	require.InDelta(t, 0.0, bal, 0.001)
}

// ---------------------------------------------------------------------------
// Allocate (pure function) integration scenarios
// These verify the algorithm produces correct results for realistic scenarios
// without requiring PostgreSQL (no raw SQL path).
// ---------------------------------------------------------------------------

func TestAllocate_User518Scenario_RatioGiftUntouched(t *testing.T) {
	// Exact reproduction of user 518's case as a pure-function test:
	// balance=60, ratio gift=60, rechargePool=0
	// Billing cost=0.53: ratio stage skipped, full cost to recharge overdraft.
	// Gift is NOT deducted, NOT revoked.
	in := AllocateInput{
		TotalCost:    d("0.53"),
		TotalBalance: d("60"),
		Gifts: []ActiveGift{
			{ID: 155, Mode: DeductionModeRatio, Remaining: d("60"), RatioRecharge: d("2")},
		},
	}
	res, err := Allocate(in)
	require.NoError(t, err)

	// gift_cost = 0 (ratio not consumed)
	_, giftTouched := res.GiftDeltas[155]
	require.False(t, giftTouched, "ratio gift should not be consumed when rechargePool=0")

	// recharge_cost = 0.53 (full cost)
	require.True(t, res.RechargeDelta.Equal(d("0.53")), "expected recharge=0.53, got %s", res.RechargeDelta)

	// Conservation
	assertConservation(t, in, res)
}

func TestAllocate_User518SecondRequest_StillUntouched(t *testing.T) {
	// After first overdraft: balance=59.47, gift=60, rechargePool=-0.53
	// Second request should also skip ratio, overdraft further.
	// This verifies no infinite-loop or panics.
	in := AllocateInput{
		TotalCost:    d("0.53"),
		TotalBalance: d("59.47"),
		Gifts: []ActiveGift{
			{ID: 155, Mode: DeductionModeRatio, Remaining: d("60"), RatioRecharge: d("2")},
		},
	}
	res, err := Allocate(in)
	require.NoError(t, err)

	_, giftTouched := res.GiftDeltas[155]
	require.False(t, giftTouched)
	require.True(t, res.RechargeDelta.Equal(d("0.53")))
	assertConservation(t, in, res)
}

func TestAllocate_PriorityGiftCoversFullCostWhenRechargePoolZero(t *testing.T) {
	// User has priority gift, rechargePool=0. Priority covers independently.
	in := AllocateInput{
		TotalCost:    d("10"),
		TotalBalance: d("50"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, err := Allocate(in)
	require.NoError(t, err)

	require.True(t, res.GiftDeltas[1].Equal(d("10")))
	require.True(t, res.RechargeDelta.IsZero())
	assertConservation(t, in, res)
}

func TestAllocate_RatioConsumedWhenRechargePoolPositive(t *testing.T) {
	// balance=100, ratio gift=30 (r=2) → rechargePool=70 > 0
	// Deduct 9: T = min(9, 45, 210) = 9
	//   gift=9·2/3=6, recharge=9/3=3
	in := AllocateInput{
		TotalCost:    d("9"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("30"), RatioRecharge: d("2")},
		},
	}
	res, err := Allocate(in)
	require.NoError(t, err)

	require.True(t, res.GiftDeltas[1].Equal(d("6")))
	require.True(t, res.RechargeDelta.Equal(d("3")))
	assertConservation(t, in, res)
}
