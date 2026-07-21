//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func mustCreateGroupForQuota5h(t *testing.T, client *dbent.Client) int64 {
	t.Helper()
	g := mustCreateGroup(t, client, &service.Group{
		Name: fmt.Sprintf("gm5h-test-%d", time.Now().UnixNano()),
	})
	return g.ID
}

// 记录不存在 → 第一次累加 INSERT，usage = cost。
func TestGroupModelQuota5hRepo_IncrementCreatesRow(t *testing.T) {
	ctx := context.Background()
	tx := testEntTx(t)
	txCtx := dbent.NewTxContext(ctx, tx)
	client := tx.Client()

	userID := mustCreateUserForQuota(t, client)
	groupID := mustCreateGroupForQuota5h(t, client)
	repo := NewGroupModelQuota5hRepository(client)

	now := time.Now().UTC()
	require.NoError(t, repo.IncrementUsageWithReset(txCtx, userID, groupID, "claude-opus-4-8", 1.5, now))

	rec, err := repo.GetUsage(txCtx, userID, groupID, "claude-opus-4-8")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.InDelta(t, 1.5, rec.UsageUSD, 1e-9)
}

// 同一 5h 窗口内多次累加 → 相加。
func TestGroupModelQuota5hRepo_IncrementAccumulatesWithinWindow(t *testing.T) {
	ctx := context.Background()
	tx := testEntTx(t)
	txCtx := dbent.NewTxContext(ctx, tx)
	client := tx.Client()

	userID := mustCreateUserForQuota(t, client)
	groupID := mustCreateGroupForQuota5h(t, client)
	repo := NewGroupModelQuota5hRepository(client)

	now := time.Now().UTC()
	require.NoError(t, repo.IncrementUsageWithReset(txCtx, userID, groupID, "m", 1.0, now))
	// 1 小时后（仍在同一 5h 窗口内）再累加。
	require.NoError(t, repo.IncrementUsageWithReset(txCtx, userID, groupID, "m", 0.5, now.Add(time.Hour)))

	rec, err := repo.GetUsage(txCtx, userID, groupID, "m")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.InDelta(t, 1.5, rec.UsageUSD, 1e-9, "should accumulate within 5h window")
}

// 窗口过期（间隔 >= 5h）→ 重置为本次 cost，window_start 推进。
func TestGroupModelQuota5hRepo_IncrementResetsAfterWindowExpiry(t *testing.T) {
	ctx := context.Background()
	tx := testEntTx(t)
	txCtx := dbent.NewTxContext(ctx, tx)
	client := tx.Client()

	userID := mustCreateUserForQuota(t, client)
	groupID := mustCreateGroupForQuota5h(t, client)
	repo := NewGroupModelQuota5hRepository(client)

	start := time.Now().UTC().Add(-6 * time.Hour) // 6h 前建窗口
	require.NoError(t, repo.IncrementUsageWithReset(txCtx, userID, groupID, "m", 4.0, start))

	// now 距 start 已 6h（>= 5h），窗口过期 → 重置。
	now := start.Add(6 * time.Hour)
	require.NoError(t, repo.IncrementUsageWithReset(txCtx, userID, groupID, "m", 0.3, now))

	rec, err := repo.GetUsage(txCtx, userID, groupID, "m")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.InDelta(t, 0.3, rec.UsageUSD, 1e-9, "should reset (not accumulate) after window expiry")
	require.True(t, rec.WindowStart.After(start.Add(5*time.Hour)), "window_start should advance")
}

// GetUsage 未命中返回 (nil, nil)。
func TestGroupModelQuota5hRepo_GetUsageMiss(t *testing.T) {
	ctx := context.Background()
	tx := testEntTx(t)
	txCtx := dbent.NewTxContext(ctx, tx)
	client := tx.Client()

	userID := mustCreateUserForQuota(t, client)
	groupID := mustCreateGroupForQuota5h(t, client)
	repo := NewGroupModelQuota5hRepository(client)

	rec, err := repo.GetUsage(txCtx, userID, groupID, "never-used")
	require.NoError(t, err)
	require.Nil(t, rec)
}
