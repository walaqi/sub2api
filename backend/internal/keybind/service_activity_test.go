//go:build unit

package keybind

import (
	"context"
	"testing"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/stretchr/testify/require"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newActivityService builds a keybind Service backed by an in-memory ent client
// and a miniredis, with the given pool user. It's the minimal wiring needed to
// exercise ReserveForActivity / UserHasClaimedActivityKey.
func newActivityService(t *testing.T, client *dbent.Client, poolUserID int64) *Service {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return &Service{
		client:              client,
		redis:               rdb,
		poolUserID:          poolUserID,
		giftSettingResolver: NewBindKeyGiftSettingResolver(client),
	}
}

// makePoolUser creates the pool user that owns claimable keys.
func makePoolUser(t *testing.T, client *dbent.Client) int64 {
	t.Helper()
	u, err := client.User.Create().
		SetEmail("pool@activity.test").
		SetPasswordHash("x").
		Save(context.Background())
	require.NoError(t, err)
	return u.ID
}

// makeActivityKey creates an active pool key with the given quota and ties it to
// activityID via a bind_key_gift_settings row.
func makeActivityKey(t *testing.T, client *dbent.Client, ownerID int64, key string, quota float64, activityID *int64) int64 {
	t.Helper()
	ctx := context.Background()
	k, err := client.APIKey.Create().
		SetUserID(ownerID).
		SetKey(key).
		SetName(key).
		SetQuota(quota).
		Save(ctx)
	require.NoError(t, err)
	create := client.BindKeyGiftSetting.Create().
		SetAPIKeyID(k.ID).
		SetDeductionMode("priority").
		SetConfig(&domain.BindKeyConfig{})
	if activityID != nil {
		create = create.SetActivityID(*activityID)
	}
	_, err = create.Save(ctx)
	require.NoError(t, err)
	return k.ID
}

func int64Ptr(v int64) *int64 { return &v }

func TestReserveForActivity(t *testing.T) {
	ctx := context.Background()

	t.Run("reserves a key tied to the activity", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		svc := newActivityService(t, client, poolID)
		makeActivityKey(t, client, poolID, "sk-act-1", 100, int64Ptr(7))

		res, err := svc.ReserveForActivity(ctx, 7)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.NotEmpty(t, res.ReservationID)
		require.Equal(t, float64(100), res.QuotaLimit)
	})

	t.Run("no key for activity -> ErrNoActivityKey", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		svc := newActivityService(t, client, poolID)
		// A key exists, but for a different activity.
		makeActivityKey(t, client, poolID, "sk-act-other", 100, int64Ptr(99))

		_, err := svc.ReserveForActivity(ctx, 7)
		require.ErrorIs(t, err, ErrNoActivityKey)
	})

	t.Run("key not owned by pool user (already claimed) is skipped", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		claimer := makeUser(t, client, 0)
		svc := newActivityService(t, client, poolID)
		// Key tied to activity 7 but already owned by a claimer → not claimable.
		makeActivityKey(t, client, claimer, "sk-act-claimed", 100, int64Ptr(7))

		_, err := svc.ReserveForActivity(ctx, 7)
		require.ErrorIs(t, err, ErrNoActivityKey)
	})

	t.Run("key below 50% quota is skipped", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		svc := newActivityService(t, client, poolID)
		ctx := context.Background()
		// Quota 100 but 60 used → 40% remaining → ineligible.
		k, err := client.APIKey.Create().
			SetUserID(poolID).SetKey("sk-act-lowquota").SetName("lq").
			SetQuota(100).SetQuotaUsed(60).Save(ctx)
		require.NoError(t, err)
		_, err = client.BindKeyGiftSetting.Create().
			SetAPIKeyID(k.ID).SetDeductionMode("priority").SetActivityID(7).
			SetConfig(&domain.BindKeyConfig{}).Save(ctx)
		require.NoError(t, err)

		_, err = svc.ReserveForActivity(ctx, 7)
		require.ErrorIs(t, err, ErrNoActivityKey)
	})

	t.Run("activityID <= 0 -> ErrNoActivityKey", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		svc := newActivityService(t, client, poolID)
		_, err := svc.ReserveForActivity(ctx, 0)
		require.ErrorIs(t, err, ErrNoActivityKey)
	})

	t.Run("disabled service -> disabled error", func(t *testing.T) {
		svc := &Service{poolUserID: 0}
		_, err := svc.ReserveForActivity(ctx, 7)
		require.Error(t, err)
	})
}

func TestUserHasClaimedActivityKey(t *testing.T) {
	ctx := context.Background()

	t.Run("false when user owns no activity key", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		claimer := makeUser(t, client, 0)
		svc := newActivityService(t, client, poolID)
		makeActivityKey(t, client, poolID, "sk-a", 100, int64Ptr(7))

		got, err := svc.UserHasClaimedActivityKey(ctx, claimer, 7)
		require.NoError(t, err)
		require.False(t, got)
	})

	t.Run("true after the key is owned by the user", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		claimer := makeUser(t, client, 0)
		svc := newActivityService(t, client, poolID)
		// Key tied to activity 7, already owned by claimer (simulates a
		// completed commit that transferred ownership).
		makeActivityKey(t, client, claimer, "sk-owned", 100, int64Ptr(7))

		got, err := svc.UserHasClaimedActivityKey(ctx, claimer, 7)
		require.NoError(t, err)
		require.True(t, got)
	})

	t.Run("false for a different activity", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		claimer := makeUser(t, client, 0)
		svc := newActivityService(t, client, poolID)
		makeActivityKey(t, client, claimer, "sk-owned-99", 100, int64Ptr(99))

		got, err := svc.UserHasClaimedActivityKey(ctx, claimer, 7)
		require.NoError(t, err)
		require.False(t, got)
	})

	t.Run("false on non-positive ids", func(t *testing.T) {
		client := newWindowTestClient(t)
		poolID := makePoolUser(t, client)
		svc := newActivityService(t, client, poolID)
		got, err := svc.UserHasClaimedActivityKey(ctx, 0, 7)
		require.NoError(t, err)
		require.False(t, got)
		got, err = svc.UserHasClaimedActivityKey(ctx, 5, 0)
		require.NoError(t, err)
		require.False(t, got)
	})
}
