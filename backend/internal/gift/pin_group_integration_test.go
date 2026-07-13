//go:build unit

package gift

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dbent "github.com/Wei-Shaw/sub2api/ent"
)

// seedGiftDirect 直接经 ent 播种一笔 active 赠金（绕过 Grant 的 groups FOR UPDATE 锁，
// 使 group-aware 查询逻辑可在 sqlite 单测层验证）。FOR UPDATE 相关的 Grant/pin 路径
// 走 Postgres 集成测试（internal/repository）。
func seedGiftDirect(t *testing.T, client *dbent.Client, uid int64, amount float64, mode DeductionMode, groupID *int64) int64 {
	t.Helper()
	c := client.UserGift.Create().
		SetUserID(uid).
		SetAmount(amount).
		SetRemaining(amount).
		SetDeductionMode(string(mode)).
		SetSource(string(SourceKeybind)).
		SetStatus(string(StatusActive))
	if groupID != nil {
		c = c.SetGroupID(*groupID)
	}
	if mode == DeductionModeRatio {
		c = c.SetRatioRecharge(2)
	}
	g, err := c.Save(context.Background())
	require.NoError(t, err)
	return g.ID
}

func TestHasActivePriorityGift_GroupScoped(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)
	gid := int64(5)
	seedGiftDirect(t, client, uid, 50, DeductionModePriority, &gid)

	// 在该组：可用 → true。
	has, err := eng.HasActivePriorityGift(ctx, uid, &gid)
	require.NoError(t, err)
	require.True(t, has, "priority gift usable in its own group")

	// 在别组：不可用 → false。
	other := int64(7)
	has, err = eng.HasActivePriorityGift(ctx, uid, &other)
	require.NoError(t, err)
	require.False(t, has, "group-scoped priority gift must not count in another group")

	// 无分组请求：只看全局赠金 → false。
	has, err = eng.HasActivePriorityGift(ctx, uid, nil)
	require.NoError(t, err)
	require.False(t, has, "group-scoped gift must not count for a groupless request")
}

func TestHasActivePriorityGift_GlobalCountsEverywhere(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)
	seedGiftDirect(t, client, uid, 50, DeductionModePriority, nil) // 全局

	for _, gid := range []*int64{nil, i64(1), i64(2)} {
		has, err := eng.HasActivePriorityGift(ctx, uid, gid)
		require.NoError(t, err)
		require.True(t, has, "global priority gift must count in any group")
	}
}

// TestListActiveGiftsForDisplay_GroupFieldsAndOrdering 验证展示层带出 group_id/group_name，
// 且排序为 priority → 分组专属 → 全局。
func TestListActiveGiftsForDisplay_GroupFieldsAndOrdering(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)
	gid := seedGroupUnit(t, client, "grp-display")

	// 全局 priority + 分组专属 priority。
	seedGiftDirect(t, client, uid, 30, DeductionModePriority, nil)
	seedGiftDirect(t, client, uid, 40, DeductionModePriority, &gid)

	items, err := eng.ListActiveGiftsForDisplay(ctx, uid)
	require.NoError(t, err)
	require.Len(t, items, 2)

	// 维度②：分组专属排在全局之前。
	require.NotNil(t, items[0].GroupID, "group-scoped gift should sort before global")
	require.Equal(t, gid, *items[0].GroupID)
	require.Equal(t, "grp-display", items[0].GroupName)
	require.Nil(t, items[1].GroupID, "global gift second")
	require.Equal(t, "", items[1].GroupName)
}

func seedGroupUnit(t *testing.T, client *dbent.Client, name string) int64 {
	t.Helper()
	gr, err := client.Group.Create().
		SetName(name).
		SetPlatform("anthropic").
		SetStatus("active").
		Save(context.Background())
	require.NoError(t, err)
	return gr.ID
}

// TestListActiveGiftsForDisplay_DeletedGroupShowsGlobal 验证软删组的赠金展示为全局（无组名）。
func TestListActiveGiftsForDisplay_DeletedGroupShowsGlobal(t *testing.T) {
	eng, client, _ := newPreflightTestEngine(t)
	ctx := context.Background()
	uid := seedPreflightUser(t, client, 100)
	gid := seedGroupUnit(t, client, "grp-doomed")
	seedGiftDirect(t, client, uid, 30, DeductionModePriority, &gid)

	// 软删该组（设置 deleted_at）。
	_, err := client.Group.UpdateOneID(gid).SetDeletedAt(time.Now()).Save(ctx)
	require.NoError(t, err)

	items, err := eng.ListActiveGiftsForDisplay(ctx, uid)
	require.NoError(t, err)
	require.Len(t, items, 1)
	// group_id 仍指向已软删组，但 join 过滤 deleted_at → 无组名（前端据 is_global 逻辑判定）。
	require.Equal(t, "", items[0].GroupName, "soft-deleted group yields no name")
}
