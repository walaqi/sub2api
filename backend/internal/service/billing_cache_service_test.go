//go:build unit

package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type billingCacheWorkerStub struct {
	balanceUpdates      int64
	subscriptionUpdates int64
}

func (b *billingCacheWorkerStub) GetUserBalance(ctx context.Context, userID int64) (float64, error) {
	return 0, errors.New("not implemented")
}

func (b *billingCacheWorkerStub) SetUserBalance(ctx context.Context, userID int64, balance float64) error {
	atomic.AddInt64(&b.balanceUpdates, 1)
	return nil
}

func (b *billingCacheWorkerStub) DeductUserBalance(ctx context.Context, userID int64, amount float64) error {
	atomic.AddInt64(&b.balanceUpdates, 1)
	return nil
}

func (b *billingCacheWorkerStub) InvalidateUserBalance(ctx context.Context, userID int64) error {
	return nil
}

func (b *billingCacheWorkerStub) GetSubscriptionCache(ctx context.Context, userID, groupID int64) (*SubscriptionCacheData, error) {
	return nil, errors.New("not implemented")
}

func (b *billingCacheWorkerStub) SetSubscriptionCache(ctx context.Context, userID, groupID int64, data *SubscriptionCacheData) error {
	atomic.AddInt64(&b.subscriptionUpdates, 1)
	return nil
}

func (b *billingCacheWorkerStub) UpdateSubscriptionUsage(ctx context.Context, userID, groupID int64, cost float64) error {
	atomic.AddInt64(&b.subscriptionUpdates, 1)
	return nil
}

func (b *billingCacheWorkerStub) InvalidateSubscriptionCache(ctx context.Context, userID, groupID int64) error {
	return nil
}

func (b *billingCacheWorkerStub) GetAPIKeyRateLimit(ctx context.Context, keyID int64) (*APIKeyRateLimitCacheData, error) {
	return nil, errors.New("not implemented")
}

func (b *billingCacheWorkerStub) SetAPIKeyRateLimit(ctx context.Context, keyID int64, data *APIKeyRateLimitCacheData) error {
	return nil
}

func (b *billingCacheWorkerStub) UpdateAPIKeyRateLimitUsage(ctx context.Context, keyID int64, cost float64) error {
	return nil
}

func (b *billingCacheWorkerStub) InvalidateAPIKeyRateLimit(ctx context.Context, keyID int64) error {
	return nil
}

func (b *billingCacheWorkerStub) GetUserPlatformQuotaCache(ctx context.Context, userID int64, platform string) (*UserPlatformQuotaCacheEntry, bool, error) {
	return nil, false, nil
}

func (b *billingCacheWorkerStub) SetUserPlatformQuotaCache(ctx context.Context, userID int64, platform string, entry *UserPlatformQuotaCacheEntry, ttl time.Duration) error {
	return nil
}

func (b *billingCacheWorkerStub) DeleteUserPlatformQuotaCache(ctx context.Context, userID int64, platform string) error {
	return nil
}

func (b *billingCacheWorkerStub) IncrUserPlatformQuotaUsageCache(ctx context.Context, userID int64, platform string, cost float64, ttl time.Duration, markDirty bool) error {
	return nil
}

func (b *billingCacheWorkerStub) PopDirtyUserPlatformQuotaKeys(ctx context.Context, n int) ([]UserPlatformQuotaKey, error) {
	return nil, nil
}

func (b *billingCacheWorkerStub) ReaddDirtyUserPlatformQuotaKeys(ctx context.Context, keys []UserPlatformQuotaKey) error {
	return nil
}

func (b *billingCacheWorkerStub) BatchGetUserPlatformQuotaCache(ctx context.Context, keys []UserPlatformQuotaKey) ([]*UserPlatformQuotaCacheEntry, error) {
	return nil, nil
}

func TestBillingCacheServiceQueueHighLoad(t *testing.T) {
	cache := &billingCacheWorkerStub{}
	svc := NewBillingCacheService(cache, nil, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)

	start := time.Now()
	for i := 0; i < cacheWriteBufferSize*2; i++ {
		svc.QueueDeductBalance(1, 1)
	}
	require.Less(t, time.Since(start), 2*time.Second)

	svc.QueueUpdateSubscriptionUsage(1, 2, 1.5)

	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&cache.balanceUpdates) > 0
	}, 2*time.Second, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&cache.subscriptionUpdates) > 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestBillingCacheServiceEnqueueAfterStopReturnsFalse(t *testing.T) {
	cache := &billingCacheWorkerStub{}
	svc := NewBillingCacheService(cache, nil, nil, nil, nil, nil, &config.Config{}, nil)
	svc.Stop()

	enqueued := svc.enqueueCacheWrite(cacheWriteTask{
		kind:   cacheWriteDeductBalance,
		userID: 1,
		amount: 1,
	})
	require.False(t, enqueued)
}

// --- checkBalanceEligibility tests ---

type balanceEligibilityUserRepoStub struct {
	mockUserRepo
	balance float64
}

func (s *balanceEligibilityUserRepoStub) GetByID(_ context.Context, _ int64) (*User, error) {
	return &User{Balance: s.balance}, nil
}

type priorityGiftCheckerStub struct {
	has         bool
	err         error
	giftBalance float64
	giftErr     error
}

func (s *priorityGiftCheckerStub) HasActivePriorityGift(_ context.Context, _ int64, _ *int64) (bool, error) {
	return s.has, s.err
}

func (s *priorityGiftCheckerStub) GetGiftBalance(_ context.Context, _ int64) (float64, error) {
	return s.giftBalance, s.giftErr
}

func TestCheckBalanceEligibility_PositiveRechargePool_Passes(t *testing.T) {
	// balance=100, gift=30 → rechargePool=70 > 0 → pass
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 100}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftBalance: 30})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.NoError(t, err)
}

func TestCheckBalanceEligibility_ZeroRechargePool_NoPriorityGift_Rejects(t *testing.T) {
	// User 518 scenario: balance=60, gift=60 → rechargePool=0, only ratio gift → reject
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 60}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftBalance: 60, has: false})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrInsufficientBalance)
}

func TestCheckBalanceEligibility_ZeroRechargePool_HasPriorityGift_Passes(t *testing.T) {
	// balance=50, gift=50 → rechargePool=0, but has priority gift → pass
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 50}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftBalance: 50, has: true})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.NoError(t, err)
}

func TestCheckBalanceEligibility_NegativeRechargePool_HasPriorityGift_Passes(t *testing.T) {
	// balance=40, gift=50 → rechargePool=-10, has priority gift → pass
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 40}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftBalance: 50, has: true})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.NoError(t, err)
}

func TestCheckBalanceEligibility_NegativeBalance_NoGift_Rejects(t *testing.T) {
	// balance=-5, gift=0 → rechargePool=-5, no priority → reject
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: -5}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftBalance: 0, has: false})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrInsufficientBalance)
}

func TestCheckBalanceEligibility_CheckerNil_StandardMode_FailsClosed(t *testing.T) {
	// 组绑赠金上线后：standard 模式下未接 gift checker 是硬依赖违约 → fail closed
	// （返回 ErrBillingServiceUnavailable，绝不退化 balance-only），无论余额正负。
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 10}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrBillingServiceUnavailable)

	svc2 := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 0}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc2.Stop)

	err = svc2.checkBalanceEligibility(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrBillingServiceUnavailable)
}

func TestCheckBalanceEligibility_CheckerNil_SimpleMode_FallsBackToBalance(t *testing.T) {
	// simple 模式：极端兜底退化 balance-only（simple 本就跳过计费）。
	simpleCfg := &config.Config{RunMode: config.RunModeSimple}
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 10}, nil, nil, nil, nil, simpleCfg, nil)
	t.Cleanup(svc.Stop)
	require.NoError(t, svc.checkBalanceEligibility(context.Background(), 1, nil))

	svc2 := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 0}, nil, nil, nil, nil, simpleCfg, nil)
	t.Cleanup(svc2.Stop)
	require.ErrorIs(t, svc2.checkBalanceEligibility(context.Background(), 1, nil), ErrInsufficientBalance)
}

func TestCheckBalanceEligibility_GiftBalanceError_StandardMode_FailsClosed(t *testing.T) {
	// 组绑赠金上线后：GetGiftBalance 出错 → fail closed（不退化 balance-only，
	// 否则 balance 含别组赠金会误放行导致透支）。
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 60}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftErr: errors.New("db down")})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrBillingServiceUnavailable)
}

func TestCheckBalanceEligibility_PriorityCheckError_Rejects(t *testing.T) {
	// rechargePool ≤ 0, HasActivePriorityGift errors → conservative reject
	svc := NewBillingCacheService(nil, &balanceEligibilityUserRepoStub{balance: 60}, nil, nil, nil, nil, &config.Config{}, nil)
	t.Cleanup(svc.Stop)
	svc.SetPriorityGiftChecker(&priorityGiftCheckerStub{giftBalance: 60, err: errors.New("db down")})

	err := svc.checkBalanceEligibility(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrInsufficientBalance)
}
