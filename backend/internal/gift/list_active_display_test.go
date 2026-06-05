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

var listDisplayDBSeq atomic.Int64

func newDisplayTestEngine(t *testing.T) (*Engine, *dbent.Client) {
	t.Helper()
	dsn := fmt.Sprintf("file:gift_list_display_%d?mode=memory&cache=shared&_fk=1", listDisplayDBSeq.Add(1))
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	drv := entsql.OpenDB(dialect.SQLite, db)
	client := enttest.NewClient(t, enttest.WithOptions(dbent.Driver(drv)))
	t.Cleanup(func() { _ = client.Close() })
	return &Engine{repo: newRepository(client, db)}, client
}

func seedUser(t *testing.T, client *dbent.Client) int64 {
	t.Helper()
	u, err := client.User.Create().
		SetEmail(fmt.Sprintf("u%d@example.com", listDisplayDBSeq.Load())).
		SetPasswordHash("x").
		Save(context.Background())
	require.NoError(t, err)
	return u.ID
}

func ratioPtr(v float64) *float64 { return &v }

func TestListActiveGiftsForDisplay_OrderAndFields(t *testing.T) {
	eng, client := newDisplayTestEngine(t)
	ctx := context.Background()
	uid := seedUser(t, client)

	soon := time.Now().Add(48 * time.Hour) // < 120h → expiring soon
	far := time.Now().Add(60 * 24 * time.Hour)

	// Insert out of display order to prove sorting.
	// ratio 1:2, far expiry
	_, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 10, Mode: DeductionModeRatio, RatioRecharge: ratioPtr(2), ExpiresAt: &far, Source: SourceKeybind})
	require.NoError(t, err)
	// priority, no expiry
	_, err = eng.Grant(ctx, GrantInput{UserID: uid, Amount: 20, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)
	// ratio 1:1, soon expiry
	_, err = eng.Grant(ctx, GrantInput{UserID: uid, Amount: 30, Mode: DeductionModeRatio, RatioRecharge: ratioPtr(1), ExpiresAt: &soon, Source: SourceKeybind})
	require.NoError(t, err)

	items, err := eng.ListActiveGiftsForDisplay(ctx, uid)
	require.NoError(t, err)
	require.Len(t, items, 3)

	// Expected consumption order: priority first, then ratio ascending by ratio_recharge.
	require.Equal(t, DeductionModePriority, items[0].Mode)
	require.Nil(t, items[0].ExpiresAt)
	require.False(t, items[0].ExpiringSoon)

	require.Equal(t, DeductionModeRatio, items[1].Mode)
	require.NotNil(t, items[1].RatioRecharge)
	require.InDelta(t, 1.0, *items[1].RatioRecharge, 1e-9)
	require.True(t, items[1].ExpiringSoon)

	require.Equal(t, DeductionModeRatio, items[2].Mode)
	require.NotNil(t, items[2].RatioRecharge)
	require.InDelta(t, 2.0, *items[2].RatioRecharge, 1e-9)
	require.False(t, items[2].ExpiringSoon)
}

func TestListActiveGiftsForDisplay_ExcludesExpiredExhaustedRevoked(t *testing.T) {
	eng, client := newDisplayTestEngine(t)
	ctx := context.Background()
	uid := seedUser(t, client)

	active, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 5, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)
	require.NotNil(t, active)

	// Already-expired gift: set expires_at in the past directly via ent.
	past := time.Now().Add(-time.Hour)
	expired, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 7, Mode: DeductionModePriority, ExpiresAt: timePtrFuture(), Source: SourceKeybind})
	require.NoError(t, err)
	_, err = client.UserGift.UpdateOneID(expired.ID).SetExpiresAt(past).Save(ctx)
	require.NoError(t, err)

	// Exhausted gift: remaining 0.
	exhausted, err := eng.Grant(ctx, GrantInput{UserID: uid, Amount: 9, Mode: DeductionModePriority, Source: SourceKeybind})
	require.NoError(t, err)
	_, err = client.UserGift.UpdateOneID(exhausted.ID).SetRemaining(0).SetStatus(string(StatusExhausted)).Save(ctx)
	require.NoError(t, err)

	items, err := eng.ListActiveGiftsForDisplay(ctx, uid)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.InDelta(t, 5.0, items[0].Remaining, 1e-9)
}

func timePtrFuture() *time.Time {
	t := time.Now().Add(240 * time.Hour)
	return &t
}
