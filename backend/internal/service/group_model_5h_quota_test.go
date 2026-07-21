//go:build unit

package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

// fakeGM5hCache 是 GroupModelQuota5hCache 的可控实现。
type fakeGM5hCache struct {
	mu        sync.Mutex
	entry     *GroupModelQuota5hCacheEntry
	hit       bool
	getErr    error
	setCalls  int
	incrCalls []gm5hIncrCall
}

type gm5hIncrCall struct {
	userID  int64
	groupID int64
	model   string
	cost    float64
}

func (f *fakeGM5hCache) GetGroupModelQuota5hCache(_ context.Context, _, _ int64, _ string) (*GroupModelQuota5hCacheEntry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	return f.entry, f.hit, nil
}

func (f *fakeGM5hCache) SetGroupModelQuota5hCache(_ context.Context, _, _ int64, _ string, _ *GroupModelQuota5hCacheEntry, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	return nil
}

func (f *fakeGM5hCache) IncrGroupModelQuota5hUsageCache(_ context.Context, userID, groupID int64, model string, cost float64, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incrCalls = append(f.incrCalls, gm5hIncrCall{userID, groupID, model, cost})
	return nil
}

func (f *fakeGM5hCache) getSetCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setCalls
}

// fakeGM5hRepo 是 GroupModelQuota5hRepository 的可控实现。
type fakeGM5hRepo struct {
	mu        sync.Mutex
	rec       *GroupModelQuota5hRecord
	getErr    error
	incrCalls int
}

func (f *fakeGM5hRepo) GetUsage(_ context.Context, _, _ int64, _ string) (*GroupModelQuota5hRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.rec, nil
}

func (f *fakeGM5hRepo) IncrementUsageWithReset(_ context.Context, _, _ int64, _ string, _ float64, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incrCalls++
	return nil
}

func newGM5hService(cache GroupModelQuota5hCache, repo GroupModelQuota5hRepository) *BillingCacheService {
	cfg := &config.Config{}
	s := &BillingCacheService{cfg: cfg}
	s.SetGroupModelQuota5h(cache, repo)
	return s
}

func gm5hGroup(limits map[string]float64) *Group {
	return &Group{ID: 7, Status: "active", Model5hLimits: limits}
}

func TestCheckGroupModelQuota5h_FeatureNotWired_Allows(t *testing.T) {
	cfg := &config.Config{}
	s := &BillingCacheService{cfg: cfg} // 未 SetGroupModelQuota5h
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 1}), "m")
	if err != nil {
		t.Fatalf("feature not wired should allow, got %v", err)
	}
}

func TestCheckGroupModelQuota5h_ModelNotConfigured_Allows(t *testing.T) {
	cache := &fakeGM5hCache{}
	s := newGM5hService(cache, &fakeGM5hRepo{})
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"other-model": 1}), "claude-opus-4-8")
	if err != nil {
		t.Fatalf("unconfigured model should allow, got %v", err)
	}
	if len(cache.incrCalls) != 0 || cache.getSetCalls() != 0 {
		t.Error("unconfigured model should not touch cache")
	}
}

func TestCheckGroupModelQuota5h_CacheHit_UnderLimit_Allows(t *testing.T) {
	now := time.Now()
	cache := &fakeGM5hCache{
		hit: true,
		entry: &GroupModelQuota5hCacheEntry{
			UsageUSD:      1.0,
			WindowStart:   &now,
			SchemaVersion: GroupModelQuota5hCacheSchemaV1,
		},
	}
	s := newGM5hService(cache, &fakeGM5hRepo{})
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if err != nil {
		t.Fatalf("usage 1.0 < limit 3.0 should allow, got %v", err)
	}
}

func TestCheckGroupModelQuota5h_CacheHit_OverLimit_Blocks(t *testing.T) {
	now := time.Now()
	cache := &fakeGM5hCache{
		hit: true,
		entry: &GroupModelQuota5hCacheEntry{
			UsageUSD:      3.0,
			WindowStart:   &now,
			SchemaVersion: GroupModelQuota5hCacheSchemaV1,
		},
	}
	s := newGM5hService(cache, &fakeGM5hRepo{})
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if !errors.Is(err, ErrGroupModelQuota5hExhausted) {
		t.Fatalf("usage 3.0 >= limit 3.0 should block, got %v", err)
	}
}

func TestCheckGroupModelQuota5h_CacheHit_ExpiredWindow_ResetsAndAllows(t *testing.T) {
	old := time.Now().Add(-6 * time.Hour) // 超过 5h → 窗口过期
	cache := &fakeGM5hCache{
		hit: true,
		entry: &GroupModelQuota5hCacheEntry{
			UsageUSD:      100.0, // 旧窗口用量很高，但已过期应清零
			WindowStart:   &old,
			SchemaVersion: GroupModelQuota5hCacheSchemaV1,
		},
	}
	s := newGM5hService(cache, &fakeGM5hRepo{})
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if err != nil {
		t.Fatalf("expired window should reset usage to 0 and allow, got %v", err)
	}
}

func TestCheckGroupModelQuota5h_CacheMiss_DBUnderLimit_Allows_AndBackfills(t *testing.T) {
	now := time.Now()
	cache := &fakeGM5hCache{hit: false}
	repo := &fakeGM5hRepo{rec: &GroupModelQuota5hRecord{UsageUSD: 0.5, WindowStart: now}}
	s := newGM5hService(cache, repo)
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if err != nil {
		t.Fatalf("DB usage 0.5 < limit 3.0 should allow, got %v", err)
	}
	// 回填 Redis
	if cache.getSetCalls() == 0 {
		t.Error("cache miss with DB hit should backfill Redis")
	}
}

func TestCheckGroupModelQuota5h_CacheMiss_DBOverLimit_Blocks(t *testing.T) {
	now := time.Now()
	cache := &fakeGM5hCache{hit: false}
	repo := &fakeGM5hRepo{rec: &GroupModelQuota5hRecord{UsageUSD: 5.0, WindowStart: now}}
	s := newGM5hService(cache, repo)
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if !errors.Is(err, ErrGroupModelQuota5hExhausted) {
		t.Fatalf("DB usage 5.0 >= limit 3.0 should block, got %v", err)
	}
}

func TestCheckGroupModelQuota5h_CacheMiss_NoDBRecord_Allows(t *testing.T) {
	cache := &fakeGM5hCache{hit: false}
	repo := &fakeGM5hRepo{rec: nil}
	s := newGM5hService(cache, repo)
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if err != nil {
		t.Fatalf("no DB record (zero usage) should allow, got %v", err)
	}
}

func TestCheckGroupModelQuota5h_CacheErr_DBErr_FailOpen(t *testing.T) {
	cache := &fakeGM5hCache{getErr: errors.New("redis down")}
	repo := &fakeGM5hRepo{getErr: errors.New("db down")}
	s := newGM5hService(cache, repo)
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if err != nil {
		t.Fatalf("both cache and DB down should fail-open (allow), got %v", err)
	}
}

func TestCheckGroupModelQuota5h_CacheErr_DBUnderLimit_NoBackfill(t *testing.T) {
	now := time.Now()
	cache := &fakeGM5hCache{getErr: errors.New("redis down")}
	repo := &fakeGM5hRepo{rec: &GroupModelQuota5hRecord{UsageUSD: 0.5, WindowStart: now}}
	s := newGM5hService(cache, repo)
	err := s.checkGroupModelQuota5hEligibility(context.Background(),
		&User{ID: 1}, gm5hGroup(map[string]float64{"m": 3.0}), "m")
	if err != nil {
		t.Fatalf("DB under limit should allow, got %v", err)
	}
	// Redis GET 故障时不应回填（避免注定失败的写）
	if cache.getSetCalls() != 0 {
		t.Error("must not backfill cache when Redis GET failed")
	}
}

// 关键：对订阅用户也生效。checkGroupModelQuota5hEligibility 不看计费模式。
func TestCheckGroupModelQuota5h_AppliesToSubscriptionUser(t *testing.T) {
	now := time.Now()
	cache := &fakeGM5hCache{
		hit: true,
		entry: &GroupModelQuota5hCacheEntry{
			UsageUSD:      10.0,
			WindowStart:   &now,
			SchemaVersion: GroupModelQuota5hCacheSchemaV1,
		},
	}
	s := newGM5hService(cache, &fakeGM5hRepo{})
	// 订阅分组同样受 5h 限额约束
	subGroup := &Group{ID: 7, Status: "active", SubscriptionType: "subscription",
		Model5hLimits: map[string]float64{"m": 3.0}}
	err := s.checkGroupModelQuota5hEligibility(context.Background(), &User{ID: 1}, subGroup, "m")
	if !errors.Is(err, ErrGroupModelQuota5hExhausted) {
		t.Fatalf("5h limit must apply to subscription users too, got %v", err)
	}
}

func TestHasGroupModel5hLimit(t *testing.T) {
	s := newGM5hService(&fakeGM5hCache{}, &fakeGM5hRepo{})
	if !s.HasGroupModel5hLimit(gm5hGroup(map[string]float64{"m": 1}), "m") {
		t.Error("configured model should report has-limit")
	}
	if s.HasGroupModel5hLimit(gm5hGroup(map[string]float64{"m": 1}), "other") {
		t.Error("unconfigured model should report no-limit")
	}
	// 未接线时恒 false
	notWired := &BillingCacheService{cfg: &config.Config{}}
	if notWired.HasGroupModel5hLimit(gm5hGroup(map[string]float64{"m": 1}), "m") {
		t.Error("feature not wired should report no-limit")
	}
}

func TestIncrementGroupModelQuota5hUsage_CallsCache(t *testing.T) {
	cache := &fakeGM5hCache{}
	repo := &fakeGM5hRepo{}
	s := newGM5hService(cache, repo)
	s.IncrementGroupModelQuota5hUsage(1, 7, "m", 0.25)
	cache.mu.Lock()
	n := len(cache.incrCalls)
	var call gm5hIncrCall
	if n > 0 {
		call = cache.incrCalls[0]
	}
	cache.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 cache incr, got %d", n)
	}
	if call != (gm5hIncrCall{1, 7, "m", 0.25}) {
		t.Errorf("incr call = %+v", call)
	}
	// DB 异步写：等待 goroutine 落地。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		done := repo.incrCalls == 1
		repo.mu.Unlock()
		if done {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("expected DB IncrementUsageWithReset to be called async")
}

func TestIncrementGroupModelQuota5hUsage_SkipsZeroCost(t *testing.T) {
	cache := &fakeGM5hCache{}
	s := newGM5hService(cache, &fakeGM5hRepo{})
	s.IncrementGroupModelQuota5hUsage(1, 7, "m", 0)
	s.IncrementGroupModelQuota5hUsage(1, 7, "", 1.0)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.incrCalls) != 0 {
		t.Errorf("zero cost / empty model should be skipped, got %d calls", len(cache.incrCalls))
	}
}
