//go:build unit

package keybind

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/stretchr/testify/require"
)

func boolPtr(v bool) *bool { return &v }

func TestIsKeyUnlimited(t *testing.T) {
	ctx := context.Background()

	t.Run("no setting row -> limited (default)", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		require.False(t, svc.isKeyUnlimited(ctx, 9999))
	})

	t.Run("unlimit=nil -> limited (default)", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(101)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{}).
			Save(ctx)
		require.NoError(t, err)
		require.False(t, svc.isKeyUnlimited(ctx, keyID))
	})

	t.Run("unlimit=true -> unlimited", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(102)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{Unlimit: boolPtr(true)}).
			Save(ctx)
		require.NoError(t, err)
		require.True(t, svc.isKeyUnlimited(ctx, keyID))
	})

	t.Run("unlimit=false -> limited", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(103)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{Unlimit: boolPtr(false)}).
			Save(ctx)
		require.NoError(t, err)
		require.False(t, svc.isKeyUnlimited(ctx, keyID))
	})

	t.Run("nil resolver -> limited", func(t *testing.T) {
		svc := &Service{giftSettingResolver: nil}
		require.False(t, svc.isKeyUnlimited(ctx, 1))
	})

	t.Run("keyID <= 0 -> limited", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		require.False(t, svc.isKeyUnlimited(ctx, 0))
		require.False(t, svc.isKeyUnlimited(ctx, -1))
	})
}

func TestResolveUnlimitField(t *testing.T) {
	ctx := context.Background()

	t.Run("unlimit persisted and resolved correctly", func(t *testing.T) {
		client := newWindowTestClient(t)
		const keyID = int64(201)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{Unlimit: boolPtr(false)}).
			Save(ctx)
		require.NoError(t, err)

		r := NewBindKeyGiftSettingResolver(client)
		got, err := r.Resolve(ctx, keyID)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.NotNil(t, got.Unlimit)
		require.False(t, *got.Unlimit)
	})

	t.Run("unlimit=true persisted and resolved", func(t *testing.T) {
		client := newWindowTestClient(t)
		const keyID = int64(202)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{Unlimit: boolPtr(true)}).
			Save(ctx)
		require.NoError(t, err)

		r := NewBindKeyGiftSettingResolver(client)
		got, err := r.Resolve(ctx, keyID)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.NotNil(t, got.Unlimit)
		require.True(t, *got.Unlimit)
	})

	t.Run("unlimit nil when not in config", func(t *testing.T) {
		client := newWindowTestClient(t)
		const keyID = int64(203)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{}).
			Save(ctx)
		require.NoError(t, err)

		r := NewBindKeyGiftSettingResolver(client)
		got, err := r.Resolve(ctx, keyID)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Nil(t, got.Unlimit)
	})
}

func TestCheckEligibility_Unlimit(t *testing.T) {
	ctx := context.Background()

	t.Run("not participated -> eligible regardless of unlimit", func(t *testing.T) {
		client := newWindowTestClient(t)
		dataDir := t.TempDir()
		poolUser, err := client.User.Create().
			SetEmail("pool@test.com").
			SetPasswordHash("x").
			Save(ctx)
		require.NoError(t, err)

		svc := &Service{
			client:              client,
			poolUserID:          poolUser.ID,
			participation:       NewParticipationStore(dataDir),
			giftSettingResolver: NewBindKeyGiftSettingResolver(client),
		}

		claimUser := makeUser(t, client, 0)
		res, err := svc.CheckEligibility(ctx, claimUser)
		require.NoError(t, err)
		require.True(t, res.Eligible)
		require.False(t, res.AlreadyParticipated)
	})

	t.Run("participated + pool has unlimited key -> eligible", func(t *testing.T) {
		client := newWindowTestClient(t)
		dataDir := t.TempDir()
		poolUser, err := client.User.Create().
			SetEmail("pool@test.com").
			SetPasswordHash("x").
			Save(ctx)
		require.NoError(t, err)

		// Create an active pool key
		poolKey, err := client.APIKey.Create().
			SetUserID(poolUser.ID).
			SetKey("sk-test-unlimited-001").
			SetName("pool-key-1").
			Save(ctx)
		require.NoError(t, err)

		// Mark key as unlimited (default, no setting row needed, but let's be explicit)
		_, err = client.BindKeyGiftSetting.Create().
			SetAPIKeyID(poolKey.ID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{Unlimit: boolPtr(true)}).
			Save(ctx)
		require.NoError(t, err)

		svc := &Service{
			client:              client,
			poolUserID:          poolUser.ID,
			participation:       NewParticipationStore(dataDir),
			giftSettingResolver: NewBindKeyGiftSettingResolver(client),
		}

		claimUser := makeUser(t, client, 0)
		// Mark as already participated
		require.NoError(t, svc.participation.MarkParticipated(ctx, claimUser))

		res, err := svc.CheckEligibility(ctx, claimUser)
		require.NoError(t, err)
		require.True(t, res.AlreadyParticipated)
		require.True(t, res.Eligible)
	})

	t.Run("participated + pool only has limited keys -> not eligible", func(t *testing.T) {
		client := newWindowTestClient(t)
		dataDir := t.TempDir()
		poolUser, err := client.User.Create().
			SetEmail("pool@test.com").
			SetPasswordHash("x").
			Save(ctx)
		require.NoError(t, err)

		// Create an active pool key with unlimit=false
		poolKey, err := client.APIKey.Create().
			SetUserID(poolUser.ID).
			SetKey("sk-test-limited-001").
			SetName("pool-key-limited").
			Save(ctx)
		require.NoError(t, err)

		_, err = client.BindKeyGiftSetting.Create().
			SetAPIKeyID(poolKey.ID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{Unlimit: boolPtr(false)}).
			Save(ctx)
		require.NoError(t, err)

		svc := &Service{
			client:              client,
			poolUserID:          poolUser.ID,
			participation:       NewParticipationStore(dataDir),
			giftSettingResolver: NewBindKeyGiftSettingResolver(client),
		}

		claimUser := makeUser(t, client, 0)
		require.NoError(t, svc.participation.MarkParticipated(ctx, claimUser))

		res, err := svc.CheckEligibility(ctx, claimUser)
		require.NoError(t, err)
		require.True(t, res.AlreadyParticipated)
		require.False(t, res.Eligible)
	})

	t.Run("participated + pool has no keys -> not eligible", func(t *testing.T) {
		client := newWindowTestClient(t)
		dataDir := t.TempDir()
		poolUser, err := client.User.Create().
			SetEmail("pool@test.com").
			SetPasswordHash("x").
			Save(ctx)
		require.NoError(t, err)

		svc := &Service{
			client:              client,
			poolUserID:          poolUser.ID,
			participation:       NewParticipationStore(dataDir),
			giftSettingResolver: NewBindKeyGiftSettingResolver(client),
		}

		claimUser := makeUser(t, client, 0)
		require.NoError(t, svc.participation.MarkParticipated(ctx, claimUser))

		res, err := svc.CheckEligibility(ctx, claimUser)
		require.NoError(t, err)
		require.True(t, res.AlreadyParticipated)
		require.False(t, res.Eligible)
	})

	t.Run("participated + pool key has no config row (default limited) -> not eligible", func(t *testing.T) {
		client := newWindowTestClient(t)
		dataDir := t.TempDir()
		poolUser, err := client.User.Create().
			SetEmail("pool@test.com").
			SetPasswordHash("x").
			Save(ctx)
		require.NoError(t, err)

		// Pool key with no bind_key_gift_settings row → isKeyUnlimited defaults false
		_, err = client.APIKey.Create().
			SetUserID(poolUser.ID).
			SetKey("sk-test-noconfig-001").
			SetName("pool-key-noconfig").
			Save(ctx)
		require.NoError(t, err)

		svc := &Service{
			client:              client,
			poolUserID:          poolUser.ID,
			participation:       NewParticipationStore(dataDir),
			giftSettingResolver: NewBindKeyGiftSettingResolver(client),
		}

		claimUser := makeUser(t, client, 0)
		require.NoError(t, svc.participation.MarkParticipated(ctx, claimUser))

		res, err := svc.CheckEligibility(ctx, claimUser)
		require.NoError(t, err)
		require.True(t, res.AlreadyParticipated)
		require.False(t, res.Eligible)
	})
}
