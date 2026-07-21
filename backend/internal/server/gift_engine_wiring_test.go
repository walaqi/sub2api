//go:build unit

package server_test

import (
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/enttest"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/server"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

var giftWiringDBSeq atomic.Int64

// TestProvideGiftEngine_WiresPriorityGiftChecker guards against the DI regression
// where billing preflight's gift checker was left unwired.
//
// History: the fix in 795878fd hand-edited the generated wire_gen.go to call
// billingCache.SetPriorityGiftChecker(engine); the very next day 286ad5a1 ran
// `go generate ./cmd/server`, which regenerated wire_gen.go from scratch and
// silently dropped that line. Preflight then degraded to the legacy
// balance-only check, letting users overdraft against frozen ratio gifts for
// hours (user 518). The fix moves the wiring into this hand-written provider so
// it survives regeneration — this test asserts the provider actually performs it.
func TestProvideGiftEngine_WiresPriorityGiftChecker(t *testing.T) {
	dsn := fmt.Sprintf("file:gift_wiring_%d?mode=memory&cache=shared&_fk=1", giftWiringDBSeq.Add(1))
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)

	drv := entsql.OpenDB(dialect.SQLite, db)
	client := enttest.NewClient(t, enttest.WithOptions(dbent.Driver(drv)))
	t.Cleanup(func() { _ = client.Close() })

	billingCache := service.ProvideBillingCacheService(nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil)
	t.Cleanup(billingCache.Stop)

	require.False(t, billingCache.HasPriorityGiftChecker(),
		"precondition: checker must be unset before ProvideGiftEngine runs")

	engine := server.ProvideGiftEngine(client, db, billingCache)
	require.NotNil(t, engine)

	require.True(t, billingCache.HasPriorityGiftChecker(),
		"ProvideGiftEngine must wire the gift engine into billing preflight "+
			"(SetPriorityGiftChecker); a regression here re-enables unbounded "+
			"overdraft against frozen ratio gifts")
}
