//go:build unit

package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// userRPMCacheStub 记录每种计数器被调用的次数，并可注入返回值与错误。
type userRPMCacheStub struct {
	userGroupCalls int32
	userCalls      int32

	userGroupCounts []int // 依次返回的计数值
	userGroupErr    error
	userCounts      []int
	userErr         error
}

func (s *userRPMCacheStub) IncrementUserGroupRPM(_ context.Context, _, _ int64) (int, error) {
	idx := int(atomic.AddInt32(&s.userGroupCalls, 1)) - 1
	if s.userGroupErr != nil {
		return 0, s.userGroupErr
	}
	if idx < len(s.userGroupCounts) {
		return s.userGroupCounts[idx], nil
	}
	return 1, nil
}

func (s *userRPMCacheStub) IncrementUserRPM(_ context.Context, _ int64) (int, error) {
	idx := int(atomic.AddInt32(&s.userCalls, 1)) - 1
	if s.userErr != nil {
		return 0, s.userErr
	}
	if idx < len(s.userCounts) {
		return s.userCounts[idx], nil
	}
	return 1, nil
}

func (s *userRPMCacheStub) GetUserGroupRPM(_ context.Context, _, _ int64) (int, error) {
	return 0, nil
}

func (s *userRPMCacheStub) GetUserRPM(_ context.Context, _ int64) (int, error) {
	return 0, nil
}

// rpmOverrideRepoStub 专用于 checkRPM 分支测试，只实现必要方法。
type rpmOverrideRepoStub struct {
	UserGroupRateRepository

	override *int
	err      error
	calls    int32
}

func (s *rpmOverrideRepoStub) GetRPMOverrideByUserAndGroup(_ context.Context, _, _ int64) (*int, error) {
	atomic.AddInt32(&s.calls, 1)
	if s.err != nil {
		return nil, s.err
	}
	return s.override, nil
}

func newBillingServiceForRPM(t *testing.T, cache UserRPMCache, rateRepo UserGroupRateRepository) *BillingCacheService {
	t.Helper()
	// 用 nil BillingCache 走 "无缓存" 分支，避免 CheckBillingEligibility 副作用。
	// 我们只直接测 checkRPM。
	svc := NewBillingCacheService(nil, nil, nil, nil, cache, rateRepo, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	return svc
}

func TestBillingCacheService_CheckRPM_OverrideTakesPrecedenceOverGroup(t *testing.T) {
	override := 2
	// user-group 计数: 1, 2, 3；user 计数: 默认返回 1（远小于 RPMLimit=100，不干扰）
	cache := &userRPMCacheStub{userGroupCounts: []int{1, 2, 3}}
	repo := &rpmOverrideRepoStub{override: &override}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 100} // 全局上限设高，不干扰 override 测试
	group := &Group{ID: 10, RPMLimit: 100}

	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrGroupRPMExceeded)

	require.EqualValues(t, 3, atomic.LoadInt32(&cache.userGroupCalls), "override 命中分支应走 user-group 计数")
	// 并行设计：前 2 次 override 未超→继续检查 user；第 3 次 override 超了→直接 return，不检查 user
	require.EqualValues(t, 2, atomic.LoadInt32(&cache.userCalls), "override 超限前 user 计数器应被调用")
	require.EqualValues(t, 3, atomic.LoadInt32(&repo.calls))
}

func TestBillingCacheService_CheckRPM_UserLimitIsGlobalHardCap(t *testing.T) {
	override := 100 // override 很高
	// user-group 计数: 默认返回 1（远小于 override）；user 计数: 1, 2, 3
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3}}
	repo := &rpmOverrideRepoStub{override: &override}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 2} // 全局硬上限=2，应覆盖 override=100
	group := &Group{ID: 10, RPMLimit: 100}

	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrUserRPMExceeded, "user 全局硬上限应优先于 override")
}

func TestBillingCacheService_CheckRPM_OverrideZeroSkipsGroupButUserStillApplies(t *testing.T) {
	zero := 0
	// user 计数: 依次返回 1..6
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3, 4, 5, 6}}
	repo := &rpmOverrideRepoStub{override: &zero}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 5}
	group := &Group{ID: 10, RPMLimit: 100}

	// override=0 跳过分组计数，但 user.RPMLimit=5 仍生效
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group), "request %d should pass", i+1)
	}
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrUserRPMExceeded,
		"override=0 跳过分组但 user 全局上限仍应生效")
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls), "override=0 不应触发分组计数器")
	require.EqualValues(t, 6, atomic.LoadInt32(&cache.userCalls), "user 计数器应被调用")
}

func TestBillingCacheService_CheckRPM_OverrideZeroAndUserZeroIsFullyUnlimited(t *testing.T) {
	zero := 0
	cache := &userRPMCacheStub{}
	repo := &rpmOverrideRepoStub{override: &zero}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 0} // user 也不限
	group := &Group{ID: 10, RPMLimit: 100}

	for i := 0; i < 50; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group))
	}
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls), "override=0 不触发分组计数")
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userCalls), "user.RPMLimit=0 也不触发用户计数")
}

func TestBillingCacheService_CheckRPM_NilOverrideFallsThroughToGroup(t *testing.T) {
	// user-group 计数: 5, 6；user 计数: 默认 1（不干扰）
	cache := &userRPMCacheStub{userGroupCounts: []int{5, 6}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 999} // 全局上限很高，group 先超
	group := &Group{ID: 10, RPMLimit: 5}

	require.NoError(t, svc.checkRPM(context.Background(), user, group))                      // ug=5, user=1, 都没超
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrGroupRPMExceeded) // ug=6 > 5

	require.EqualValues(t, 2, atomic.LoadInt32(&cache.userGroupCalls))
	// 并行模式：第 1 次 group 没超 → 继续检查 user；第 2 次 group 超了 → 直接 return，不检查 user
	require.EqualValues(t, 1, atomic.LoadInt32(&cache.userCalls), "group 未超时 user 也应检查；group 超时直接返回")
}

func TestBillingCacheService_CheckRPM_OverrideLookupErrorFallsThroughToGroup(t *testing.T) {
	cache := &userRPMCacheStub{userGroupCounts: []int{3}}
	repo := &rpmOverrideRepoStub{err: errors.New("db down")}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 0}
	group := &Group{ID: 10, RPMLimit: 10}

	// override 查询失败后应继续尝试 group 分支（不直接拒绝）
	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.EqualValues(t, 1, atomic.LoadInt32(&cache.userGroupCalls))
	require.EqualValues(t, 1, atomic.LoadInt32(&repo.calls))
}

func TestBillingCacheService_CheckRPM_UserLevelFallbackWhenGroupUnlimited(t *testing.T) {
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 2}
	group := &Group{ID: 10, RPMLimit: 0} // 分组未设限

	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrUserRPMExceeded)

	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls), "group 未设限时不应 INCR user-group 键")
	require.EqualValues(t, 3, atomic.LoadInt32(&cache.userCalls))
}

func TestBillingCacheService_CheckRPM_NoLimitsConfiguredIsNoop(t *testing.T) {
	cache := &userRPMCacheStub{}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 0}
	group := &Group{ID: 10, RPMLimit: 0}

	for i := 0; i < 10; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group))
	}
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls))
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userCalls))
}

func TestBillingCacheService_CheckRPM_RedisErrorFailOpen(t *testing.T) {
	cache := &userRPMCacheStub{userGroupErr: errors.New("redis unavailable")}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 0}
	group := &Group{ID: 10, RPMLimit: 5}

	// Redis 故障时应 fail-open，不拒绝请求
	require.NoError(t, svc.checkRPM(context.Background(), user, group))
	require.EqualValues(t, 1, atomic.LoadInt32(&cache.userGroupCalls))
}

func TestBillingCacheService_CheckRPM_NoGroupUsesUserOnly(t *testing.T) {
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3}}
	repo := &rpmOverrideRepoStub{}
	svc := newBillingServiceForRPM(t, cache, repo)

	user := &User{ID: 1, RPMLimit: 2}

	// 无 group（纯用户级限流场景），不应查询 rpm_override。
	require.NoError(t, svc.checkRPM(context.Background(), user, nil))
	require.NoError(t, svc.checkRPM(context.Background(), user, nil))
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, nil), ErrUserRPMExceeded)

	require.EqualValues(t, 0, atomic.LoadInt32(&repo.calls), "无 group 时不应查询 rpm_override")
	require.EqualValues(t, 3, atomic.LoadInt32(&cache.userCalls))
}

func TestBillingCacheService_CheckRPM_NilUserIsNoop(t *testing.T) {
	cache := &userRPMCacheStub{}
	repo := &rpmOverrideRepoStub{}
	svc := newBillingServiceForRPM(t, cache, repo)

	require.NoError(t, svc.checkRPM(context.Background(), nil, &Group{ID: 1, RPMLimit: 10}))
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls))
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userCalls))
	require.EqualValues(t, 0, atomic.LoadInt32(&repo.calls))
}

// ── 多账户限流（suspect throttle）注入测试 ──

// throttleSettingsStub 提供固定的限流配置（模拟 SettingService 的缓存 getter）。
type throttleSettingsStub struct {
	settings *SuspectThrottleSettings
}

func (s *throttleSettingsStub) GetSuspectThrottleSettingsCached(_ context.Context) *SuspectThrottleSettings {
	return s.settings
}

// suspectMembershipStub 记录调用次数并返回固定命中结果/错误。
type suspectMembershipStub struct {
	suspect bool
	err     error
	calls   int32
}

func (s *suspectMembershipStub) IsSuspect(_ context.Context, _ int64) (bool, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.suspect, s.err
}

func enableThrottle(svc *BillingCacheService, settings *SuspectThrottleSettings, suspect bool, err error) *suspectMembershipStub {
	store := &suspectMembershipStub{suspect: suspect, err: err}
	svc.SetSuspectThrottle(&throttleSettingsStub{settings: settings}, store)
	return store
}

func TestBillingCacheService_CheckRPM_ThrottleDisabledSkipsRedis(t *testing.T) {
	cache := &userRPMCacheStub{}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)

	// 开关关闭：即使接入了 store，也不应查询 IsSuspect。
	store := enableThrottle(svc, &SuspectThrottleSettings{Enabled: false, RatePercent: 50, FloorRPM: 30}, true, nil)

	user := &User{ID: 1, RPMLimit: 0}
	group := &Group{ID: 10, RPMLimit: 0}
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group))
	}
	require.EqualValues(t, 0, atomic.LoadInt32(&store.calls), "开关关闭时不应查询 IsSuspect")
}

func TestBillingCacheService_CheckRPM_ThrottleNotSuspectIsZeroOverhead(t *testing.T) {
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)

	store := enableThrottle(svc, &SuspectThrottleSettings{Enabled: true, RatePercent: 50, FloorRPM: 30}, false, nil)

	user := &User{ID: 1, RPMLimit: 2}
	// 未命中名单 → 现有逻辑零改动（阈值仍为 2）。
	require.NoError(t, svc.checkRPM(context.Background(), user, nil))
	require.NoError(t, svc.checkRPM(context.Background(), user, nil))
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, nil), ErrUserRPMExceeded)
	require.EqualValues(t, 3, atomic.LoadInt32(&store.calls), "开关开启时每请求查询一次")
}

func TestBillingCacheService_CheckRPM_ThrottleScalesUserLimit(t *testing.T) {
	// user.RPMLimit=10，限流 50% → effective=5；第 6 次超限。
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3, 4, 5, 6}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)
	enableThrottle(svc, &SuspectThrottleSettings{Enabled: true, RatePercent: 50, FloorRPM: 30}, true, nil)

	user := &User{ID: 1, RPMLimit: 10}
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, nil), "request %d should pass", i+1)
	}
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, nil), ErrUserRPMExceeded,
		"限流 50% 后 user.RPMLimit=10 的有效阈值应为 5")
}

func TestBillingCacheService_CheckRPM_ThrottleFloorForUnlimitedUser(t *testing.T) {
	// user.RPMLimit=0（无限额）命中名单 → 套用 FloorRPM=3；第 4 次超限。
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3, 4}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)
	enableThrottle(svc, &SuspectThrottleSettings{Enabled: true, RatePercent: 50, FloorRPM: 3}, true, nil)

	user := &User{ID: 1, RPMLimit: 0}
	group := &Group{ID: 10, RPMLimit: 0} // 组也无限制 → 兜底只在 user 层
	for i := 0; i < 3; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group), "request %d should pass", i+1)
	}
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrUserRPMExceeded,
		"无限额用户命中名单应套 FloorRPM=3 兜底")
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls), "组无限制时兜底不在组层重复套用")
}

func TestBillingCacheService_CheckRPM_ThrottleOverrideZeroStaysExempt(t *testing.T) {
	// override=0 是有意豁免，限流不应把它误判成兜底；user.RPMLimit=0 → 套 FloorRPM。
	zero := 0
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3, 4}}
	repo := &rpmOverrideRepoStub{override: &zero}
	svc := newBillingServiceForRPM(t, cache, repo)
	enableThrottle(svc, &SuspectThrottleSettings{Enabled: true, RatePercent: 50, FloorRPM: 3}, true, nil)

	user := &User{ID: 1, RPMLimit: 0}
	group := &Group{ID: 10, RPMLimit: 100}
	for i := 0; i < 3; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group), "request %d should pass", i+1)
	}
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrUserRPMExceeded)
	require.EqualValues(t, 0, atomic.LoadInt32(&cache.userGroupCalls),
		"override=0 应保持豁免，不缩放、不在组层套兜底")
}

func TestBillingCacheService_CheckRPM_ThrottleScalesGroupLimit(t *testing.T) {
	// group.RPMLimit=10，限流 50% → effective=5；第 6 次超限。
	cache := &userRPMCacheStub{userGroupCounts: []int{1, 2, 3, 4, 5, 6}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)
	enableThrottle(svc, &SuspectThrottleSettings{Enabled: true, RatePercent: 50, FloorRPM: 30}, true, nil)

	user := &User{ID: 1, RPMLimit: 0} // user 无限额；但 user 层会套 FloorRPM=30（计数默认 1，不超）
	group := &Group{ID: 10, RPMLimit: 10}
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, group), "request %d should pass", i+1)
	}
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, group), ErrGroupRPMExceeded,
		"限流 50% 后 group.RPMLimit=10 的有效阈值应为 5")
}

func TestBillingCacheService_CheckRPM_ThrottleLookupErrorFailOpen(t *testing.T) {
	// IsSuspect 查询失败 → fail-open，不限流（阈值保持原值）。
	cache := &userRPMCacheStub{userCounts: []int{1, 2, 3, 4, 5}}
	repo := &rpmOverrideRepoStub{override: nil}
	svc := newBillingServiceForRPM(t, cache, repo)
	enableThrottle(svc, &SuspectThrottleSettings{Enabled: true, RatePercent: 50, FloorRPM: 3}, false, errors.New("redis down"))

	user := &User{ID: 1, RPMLimit: 4}
	// 名单查询失败 → 不缩放，阈值仍为 4。
	for i := 0; i < 4; i++ {
		require.NoError(t, svc.checkRPM(context.Background(), user, nil), "request %d should pass", i+1)
	}
	require.ErrorIs(t, svc.checkRPM(context.Background(), user, nil), ErrUserRPMExceeded)
}

