//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// stRepoStub is a minimal SettingRepository that records GetValue calls so the
// R2 cache-behavior assertions can verify the hot-path getter does not hit DB
// on a cache hit.
type stRepoStub struct {
	getValueFn func(ctx context.Context, key string) (string, error)
	calls      int
}

func (s *stRepoStub) Get(ctx context.Context, key string) (*Setting, error) {
	panic("unexpected Get call")
}

func (s *stRepoStub) GetValue(ctx context.Context, key string) (string, error) {
	s.calls++
	if s.getValueFn == nil {
		panic("unexpected GetValue call")
	}
	return s.getValueFn(ctx, key)
}

func (s *stRepoStub) Set(ctx context.Context, key, value string) error {
	panic("unexpected Set call")
}

func (s *stRepoStub) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	panic("unexpected GetMultiple call")
}

func (s *stRepoStub) SetMultiple(ctx context.Context, settings map[string]string) error {
	panic("unexpected SetMultiple call")
}

func (s *stRepoStub) GetAll(ctx context.Context) (map[string]string, error) {
	panic("unexpected GetAll call")
}

func (s *stRepoStub) Delete(ctx context.Context, key string) error {
	panic("unexpected Delete call")
}

func resetSuspectThrottleTestCache(t *testing.T) {
	t.Helper()
	suspectThrottleCache.Store((*cachedSuspectThrottleSettings)(nil))
	suspectThrottleSF.Forget("suspect_throttle")
	t.Cleanup(func() {
		suspectThrottleCache.Store((*cachedSuspectThrottleSettings)(nil))
		suspectThrottleSF.Forget("suspect_throttle")
	})
}

// R2: the hot-path getter must serve a cache hit without touching the DB.
func TestGetSuspectThrottleSettingsCached_CachesResult(t *testing.T) {
	resetSuspectThrottleTestCache(t)

	repo := &stRepoStub{
		getValueFn: func(_ context.Context, key string) (string, error) {
			require.Equal(t, SettingKeySuspectThrottleSettings, key)
			return `{"enabled":true,"rate_percent":40,"floor_rpm":20,"min_users":4,"window_hours":12,"interval_min":2,"ttl_minutes":15}`, nil
		},
	}
	svc := NewSettingService(repo, &config.Config{})

	first := svc.GetSuspectThrottleSettingsCached(context.Background())
	require.NotNil(t, first)
	require.True(t, first.Enabled)
	require.Equal(t, 40, first.RatePercent)
	require.Equal(t, 4, first.MinUsers)

	// Second call must be served from the in-memory snapshot: zero extra DB reads.
	second := svc.GetSuspectThrottleSettingsCached(context.Background())
	require.True(t, second.Enabled)
	require.Equal(t, 1, repo.calls, "cache hit must not hit DB again")
}

// Not-found (fresh install) defaults to disabled and is cached.
func TestGetSuspectThrottleSettingsCached_DefaultsWhenUnset(t *testing.T) {
	resetSuspectThrottleTestCache(t)

	repo := &stRepoStub{
		getValueFn: func(_ context.Context, _ string) (string, error) {
			return "", ErrSettingNotFound
		},
	}
	svc := NewSettingService(repo, &config.Config{})

	settings := svc.GetSuspectThrottleSettingsCached(context.Background())
	require.NotNil(t, settings)
	require.False(t, settings.Enabled)
	require.Equal(t, DefaultSuspectThrottleRatePercent, settings.RatePercent)

	// Cached: subsequent calls do not re-read.
	svc.GetSuspectThrottleSettingsCached(context.Background())
	require.Equal(t, 1, repo.calls)
}

// Malformed JSON falls back to defaults (and does not panic).
func TestGetSuspectThrottleSettingsCached_MalformedFallsBack(t *testing.T) {
	resetSuspectThrottleTestCache(t)

	repo := &stRepoStub{
		getValueFn: func(_ context.Context, _ string) (string, error) {
			return "{not-json", nil
		},
	}
	svc := NewSettingService(repo, &config.Config{})

	settings := svc.GetSuspectThrottleSettingsCached(context.Background())
	require.NotNil(t, settings)
	require.False(t, settings.Enabled)
	require.Equal(t, DefaultSuspectThrottleRatePercent, settings.RatePercent)
}

// Out-of-range values are normalized.
func TestGetSuspectThrottleSettings_Normalizes(t *testing.T) {
	resetSuspectThrottleTestCache(t)

	repo := &stRepoStub{
		getValueFn: func(_ context.Context, _ string) (string, error) {
			return `{"enabled":true,"rate_percent":999,"floor_rpm":0,"min_users":1}`, nil
		},
	}
	svc := NewSettingService(repo, &config.Config{})

	settings, err := svc.GetSuspectThrottleSettings(context.Background())
	require.NoError(t, err)
	require.True(t, settings.Enabled)
	require.Equal(t, DefaultSuspectThrottleRatePercent, settings.RatePercent, "999% 越界应归一化")
	require.Equal(t, DefaultSuspectThrottleFloorRPM, settings.FloorRPM)
	require.Equal(t, DefaultSuspectThrottleMinUsers, settings.MinUsers, "min_users<2 应归一化")
}
