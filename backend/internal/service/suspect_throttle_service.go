package service

import (
	"context"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// SuspectThrottleService is the background ticker that, while the feature is
// enabled, periodically re-runs multi-account detection and writes the
// cross-dimension-qualified user IDs into the SuspectStore with a per-entry TTL.
//
// It mirrors IdempotencyCleanupService's lifecycle (Start/Stop/runLoop, run-once
// guards). The run interval and TTL come from SuspectThrottleSettings, read each
// tick through the cached getter so config changes take effect within one cycle.
type SuspectThrottleService struct {
	detection      *AbuseDetectionService
	store          SuspectStore
	settingService *SettingService

	// tickInterval is how often the loop wakes to re-read settings and maybe run.
	// The effective detection cadence is governed by settings.IntervalMin; the
	// loop wakes at a fixed small interval and runs when due.
	tickInterval time.Duration

	mu        sync.Mutex
	lastRun   time.Time
	stopOnce  sync.Once
	startOnce sync.Once
	stopCh    chan struct{}
}

// NewSuspectThrottleService creates the background throttle service.
func NewSuspectThrottleService(
	detection *AbuseDetectionService,
	store SuspectStore,
	settingService *SettingService,
) *SuspectThrottleService {
	return &SuspectThrottleService{
		detection:      detection,
		store:          store,
		settingService: settingService,
		tickInterval:   30 * time.Second,
		stopCh:         make(chan struct{}),
	}
}

// Start launches the loop. Safe to call once; no-op if dependencies are missing.
func (s *SuspectThrottleService) Start() {
	if s == nil || s.detection == nil || s.store == nil || s.settingService == nil {
		return
	}
	s.startOnce.Do(func() {
		logger.LegacyPrintf("service.suspect_throttle", "[SuspectThrottle] started tick=%s", s.tickInterval)
		go s.runLoop()
	})
}

// Stop terminates the loop. Safe to call multiple times.
func (s *SuspectThrottleService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
		logger.LegacyPrintf("service.suspect_throttle", "[SuspectThrottle] stopped")
	})
}

func (s *SuspectThrottleService) runLoop() {
	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()

	// Run once on startup so a freshly-(re)started process re-populates the list.
	s.maybeRun()

	for {
		select {
		case <-ticker.C:
			s.maybeRun()
		case <-s.stopCh:
			return
		}
	}
}

// maybeRun checks the cached settings and runs a detection cycle when enabled
// and the configured interval has elapsed since the last run.
func (s *SuspectThrottleService) maybeRun() {
	settings := s.settingService.GetSuspectThrottleSettingsCached(context.Background())
	if settings == nil || !settings.Enabled {
		return // 开关关闭：跳过本轮，靠 TTL 自然消散，不主动清。
	}

	interval := time.Duration(settings.IntervalMin) * time.Minute
	if interval <= 0 {
		interval = time.Duration(DefaultSuspectThrottleIntervalMin) * time.Minute
	}

	s.mu.Lock()
	due := s.lastRun.IsZero() || time.Since(s.lastRun) >= interval
	if due {
		s.lastRun = time.Now()
	}
	s.mu.Unlock()
	if !due {
		return
	}

	s.runCycle(settings)
}

// runCycle performs one detection pass and marks the qualifying users.
func (s *SuspectThrottleService) runCycle(settings *SuspectThrottleSettings) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Fetch all three dimensions; the cross-dimension guard is applied below.
	groups, err := s.detection.ListSuspectGroups(ctx, settings.WindowHours, settings.MinUsers, nil)
	if err != nil {
		logger.LegacyPrintf("service.suspect_throttle", "[SuspectThrottle] detection failed err=%v", err)
		return
	}

	users := computeAutoThrottleUsers(groups)
	if len(users) == 0 {
		return
	}

	ttl := time.Duration(settings.TTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = time.Duration(DefaultSuspectThrottleTTLMinutes) * time.Minute
	}

	now := time.Now()
	marked := 0
	for userID, dims := range users {
		meta := SuspectMeta{Dimensions: dims, MarkedAt: now}
		if err := s.store.Mark(ctx, userID, meta, ttl); err != nil {
			logger.LegacyPrintf("service.suspect_throttle", "[SuspectThrottle] mark user=%d failed err=%v", userID, err)
			continue
		}
		marked++
	}
	logger.LegacyPrintf("service.suspect_throttle", "[SuspectThrottle] marked=%d groups=%d ttl=%s", marked, len(groups), ttl)
}
