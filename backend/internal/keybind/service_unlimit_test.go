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

	t.Run("no setting row -> unlimited (default)", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		require.True(t, svc.isKeyUnlimited(ctx, 9999))
	})

	t.Run("unlimit=nil -> unlimited (default)", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(101)
		// config with unlimit unset (nil)
		_, err := client.BindKeyGiftSetting.Create().
			SetAPIKeyID(keyID).
			SetDeductionMode("priority").
			SetConfig(&domain.BindKeyConfig{}).
			Save(ctx)
		require.NoError(t, err)
		require.True(t, svc.isKeyUnlimited(ctx, keyID))
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

	t.Run("nil resolver -> unlimited", func(t *testing.T) {
		svc := &Service{giftSettingResolver: nil}
		require.True(t, svc.isKeyUnlimited(ctx, 1))
	})

	t.Run("keyID <= 0 -> unlimited", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		require.True(t, svc.isKeyUnlimited(ctx, 0))
		require.True(t, svc.isKeyUnlimited(ctx, -1))
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
