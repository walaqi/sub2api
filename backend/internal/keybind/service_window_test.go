//go:build unit

package keybind

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/enttest"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/stretchr/testify/require"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "modernc.org/sqlite"
)

var windowDBSeq atomic.Int64

func newWindowTestClient(t *testing.T) *dbent.Client {
	t.Helper()
	dsn := fmt.Sprintf("file:keybind_window_%d?mode=memory&cache=shared&_fk=1", windowDBSeq.Add(1))
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	drv := entsql.OpenDB(dialect.SQLite, db)
	client := enttest.NewClient(t, enttest.WithOptions(dbent.Driver(drv)))
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// makeUser creates a user whose created_at is `age` in the past.
func makeUser(t *testing.T, client *dbent.Client, age time.Duration) int64 {
	t.Helper()
	u, err := client.User.Create().
		SetEmail("u@example.com").
		SetPasswordHash("x").
		SetCreatedAt(time.Now().Add(-age)).
		Save(context.Background())
	require.NoError(t, err)
	return u.ID
}

// setWindow writes a per-key registration window into table A.
func setWindow(t *testing.T, client *dbent.Client, keyID int64, win *domain.BindKeyRegistrationWindow) {
	t.Helper()
	_, err := client.BindKeyGiftSetting.Create().
		SetAPIKeyID(keyID).
		SetDeductionMode("priority").
		SetConfig(&domain.BindKeyConfig{RegistrationWindow: win}).
		Save(context.Background())
	require.NoError(t, err)
}

func newWindowService(client *dbent.Client) *Service {
	return &Service{
		client:              client,
		giftSettingResolver: NewBindKeyGiftSettingResolver(client),
	}
}

func TestResolveRegistrationWindow(t *testing.T) {
	client := newWindowTestClient(t)
	const keyID = int64(1001)
	setWindow(t, client, keyID, &domain.BindKeyRegistrationWindow{Enabled: true, MinDays: 0, MaxDays: 30})

	r := NewBindKeyGiftSettingResolver(client)
	got, err := r.Resolve(context.Background(), keyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.RegistrationWindow)
	require.True(t, got.RegistrationWindow.Enabled)
	require.Equal(t, 0, got.RegistrationWindow.MinDays)
	require.Equal(t, 30, got.RegistrationWindow.MaxDays)

	// No row for an unrelated key → nil setting.
	none, err := r.Resolve(context.Background(), 9999)
	require.NoError(t, err)
	require.Nil(t, none)
}

func TestCheckRegistrationWindow(t *testing.T) {
	ctx := context.Background()

	t.Run("no setting -> allowed", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		userID := makeUser(t, client, 100*24*time.Hour)
		require.NoError(t, svc.checkRegistrationWindow(ctx, userID, 1))
	})

	t.Run("disabled window -> allowed", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(2)
		setWindow(t, client, keyID, &domain.BindKeyRegistrationWindow{Enabled: false, MinDays: 0, MaxDays: 7})
		userID := makeUser(t, client, 100*24*time.Hour)
		require.NoError(t, svc.checkRegistrationWindow(ctx, userID, keyID))
	})

	t.Run("inside [0,30] -> allowed", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(3)
		setWindow(t, client, keyID, &domain.BindKeyRegistrationWindow{Enabled: true, MinDays: 0, MaxDays: 30})
		userID := makeUser(t, client, 10*24*time.Hour)
		require.NoError(t, svc.checkRegistrationWindow(ctx, userID, keyID))
	})

	t.Run("older than max -> rejected", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(4)
		setWindow(t, client, keyID, &domain.BindKeyRegistrationWindow{Enabled: true, MinDays: 0, MaxDays: 30})
		userID := makeUser(t, client, 40*24*time.Hour)
		err := svc.checkRegistrationWindow(ctx, userID, keyID)
		require.ErrorIs(t, err, ErrRegistrationWindow)
	})

	t.Run("younger than min -> rejected", func(t *testing.T) {
		client := newWindowTestClient(t)
		svc := newWindowService(client)
		const keyID = int64(5)
		setWindow(t, client, keyID, &domain.BindKeyRegistrationWindow{Enabled: true, MinDays: 7, MaxDays: 30})
		userID := makeUser(t, client, 3*24*time.Hour)
		err := svc.checkRegistrationWindow(ctx, userID, keyID)
		require.ErrorIs(t, err, ErrRegistrationWindow)
	})
}
