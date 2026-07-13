//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/Wei-Shaw/sub2api/internal/gift"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func newGiftScopeUser(t *testing.T, balance float64) int64 {
	t.Helper()
	client := testEntClient(t)
	u := mustCreateUser(t, client, &service.User{
		Email:        fmt.Sprintf("gift-scope-%s@example.com", uuid.NewString()),
		PasswordHash: "hash",
		Balance:      balance,
	})
	return u.ID
}

// TestGiftEngine_GroupScopedDeduction_CrossGroupNotSpent 验证：A 组 priority 赠金
// 在 B 组请求时不被消费，充值池按全局余额算（含 A 组赠金的 remaining 从池扣除）。
func TestGiftEngine_GroupScopedDeduction_CrossGroupNotSpent(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)

	uid := newGiftScopeUser(t, 100)
	grpA := mustCreateGroup(t, client, &service.Group{Name: "scope-A-" + uuid.NewString()})

	// A 组 priority 赠金 100 → balance 变 200（Grant 会 +balance）。
	_, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 100, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind, GroupID: &grpA.ID})
	require.NoError(t, err)

	tx, err := integrationDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	// 请求在 B 组（用一个不同的 group id）：A 组赠金不可用。扣 30。
	otherGroup := grpA.ID + 100000
	_, breakdown, err := eng.AllocateAndDeductWithBreakdown(ctx, tx, uid, &otherGroup, 30)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	// 赠金分文未扣，全部走充值池。
	require.InDelta(t, 0, breakdown.GiftCost, 1e-9, "cross-group gift must not be spent")
	require.InDelta(t, 30, breakdown.RechargeCost, 1e-9)

	// A 组赠金 remaining 仍是 100。
	var remaining float64
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT remaining FROM user_gifts WHERE user_id=$1", uid).Scan(&remaining))
	require.InDelta(t, 100, remaining, 1e-9)
}

// TestGiftEngine_GroupScopedDeduction_SameGroupSpent 验证：A 组赠金在 A 组请求时被消费。
func TestGiftEngine_GroupScopedDeduction_SameGroupSpent(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)

	uid := newGiftScopeUser(t, 100)
	grpA := mustCreateGroup(t, client, &service.Group{Name: "scope-same-" + uuid.NewString()})
	_, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 50, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind, GroupID: &grpA.ID})
	require.NoError(t, err)

	tx, err := integrationDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, breakdown, err := eng.AllocateAndDeductWithBreakdown(ctx, tx, uid, &grpA.ID, 20)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	require.InDelta(t, 20, breakdown.GiftCost, 1e-9, "gift usable in its own group")
	require.InDelta(t, 0, breakdown.RechargeCost, 1e-9)
}

// TestGiftEngine_GrantDeletedGroupFallsBackToGlobal 验证：grant 时目标组不存在 → 落全局。
func TestGiftEngine_GrantDeletedGroupFallsBackToGlobal(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)
	uid := newGiftScopeUser(t, 0)

	ghost := int64(999999999)
	g, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 30, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind, GroupID: &ghost})
	require.NoError(t, err)

	var groupID *int64
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT group_id FROM user_gifts WHERE id=$1", g.ID).Scan(&groupID))
	require.Nil(t, groupID, "grant for absent group must fall back to global")
}

// TestGiftEngine_PinUnpin 验证置顶/取消置顶的 FOR UPDATE 路径与一人至多一条约束。
func TestGiftEngine_PinUnpin(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)
	uid := newGiftScopeUser(t, 0)

	g1, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 10, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind})
	require.NoError(t, err)
	g2, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 10, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind})
	require.NoError(t, err)

	require.NoError(t, eng.PinGift(ctx, uid, g1.ID))
	require.NoError(t, eng.PinGift(ctx, uid, g2.ID)) // 置顶第二条 → 第一条自动取消

	var pinnedCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM user_gifts WHERE user_id=$1 AND pinned", uid).Scan(&pinnedCount))
	require.Equal(t, 1, pinnedCount, "at most one pinned gift per user")

	var pinnedID int64
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT id FROM user_gifts WHERE user_id=$1 AND pinned", uid).Scan(&pinnedID))
	require.Equal(t, g2.ID, pinnedID)

	require.NoError(t, eng.UnpinGift(ctx, uid, g2.ID))
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM user_gifts WHERE user_id=$1 AND pinned", uid).Scan(&pinnedCount))
	require.Equal(t, 0, pinnedCount)
}

// TestGiftEngine_PinRejectsExhausted 验证耗尽的赠金不可置顶。
func TestGiftEngine_PinRejectsExhausted(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)
	uid := newGiftScopeUser(t, 0)

	g, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 10, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind})
	require.NoError(t, err)
	_, err = integrationDB.ExecContext(ctx, "UPDATE user_gifts SET remaining=0, status='exhausted' WHERE id=$1", g.ID)
	require.NoError(t, err)

	require.ErrorIs(t, eng.PinGift(ctx, uid, g.ID), gift.ErrGiftNotPinnable)
}

// TestGroupDeleteCascade_ScopedGiftsGoGlobal 验证：DeleteCascade 删组后，绑该组的赠金转全局。
func TestGroupDeleteCascade_ScopedGiftsGoGlobal(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)
	repo := NewGroupRepository(client, integrationDB)

	uid := newGiftScopeUser(t, 0)
	grp := mustCreateGroup(t, client, &service.Group{Name: "doomed-" + uuid.NewString()})
	g, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 30, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind, GroupID: &grp.ID})
	require.NoError(t, err)

	// 确认落库为该组。
	var before *int64
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT group_id FROM user_gifts WHERE id=$1", g.ID).Scan(&before))
	require.NotNil(t, before)
	require.Equal(t, grp.ID, *before)

	_, err = repo.DeleteCascade(ctx, grp.ID)
	require.NoError(t, err)

	// 删组后转全局。
	var after *int64
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT group_id FROM user_gifts WHERE id=$1", g.ID).Scan(&after))
	require.Nil(t, after, "scoped gift must go global after its group is deleted")
}

// TestGroupBareDelete_ScopedGiftsGoGlobal 验证裸 Delete 路径同样转全局（且事务内原子）。
func TestGroupBareDelete_ScopedGiftsGoGlobal(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	eng := gift.NewEngine(client, integrationDB)
	repo := NewGroupRepository(client, integrationDB)

	uid := newGiftScopeUser(t, 0)
	grp := mustCreateGroup(t, client, &service.Group{Name: "bare-doomed-" + uuid.NewString()})
	g, err := eng.Grant(ctx, gift.GrantInput{UserID: uid, Amount: 30, Mode: gift.DeductionModePriority, Source: gift.SourceKeybind, GroupID: &grp.ID})
	require.NoError(t, err)

	require.NoError(t, repo.Delete(ctx, grp.ID))

	var after *int64
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT group_id FROM user_gifts WHERE id=$1", g.ID).Scan(&after))
	require.Nil(t, after, "bare Delete must also clear scoped gifts to global")
}
