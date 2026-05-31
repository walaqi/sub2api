package service

import (
	"context"
	"sort"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
)

// SuspectStore persists the automatic throttle list in Redis. Each suspect user
// is a string key throttle:suspect:{userID} carrying its hit metadata, with a
// per-entry TTL so the list decays on its own when abuse stops (see R5).
type SuspectStore interface {
	// Mark records userID as suspect with the given metadata and TTL (overwrites/renews).
	Mark(ctx context.Context, userID int64, meta SuspectMeta, ttl time.Duration) error
	// IsSuspect reports whether userID currently has a live suspect entry.
	IsSuspect(ctx context.Context, userID int64) (bool, error)
	// List returns all current suspect entries (admin observability, R8).
	List(ctx context.Context) ([]SuspectEntry, error)
	// Clear removes all suspect entries (admin "clear now").
	Clear(ctx context.Context) (int, error)
}

// SuspectMeta is the metadata stored alongside a suspect entry for observability.
type SuspectMeta struct {
	// Dimensions is the set of dimensions that flagged this user (e.g. "device", "ip").
	Dimensions []string `json:"dimensions"`
	// MarkedAt is when the user was (re)marked.
	MarkedAt time.Time `json:"marked_at"`
}

// SuspectEntry is one live suspect with its remaining TTL.
type SuspectEntry struct {
	UserID     int64     `json:"user_id"`
	Dimensions []string  `json:"dimensions"`
	MarkedAt   time.Time `json:"marked_at"`
	TTLSeconds int64     `json:"ttl_seconds"`
}

// AbuseDetectionService runs the multi-account suspect-group detection on top of
// the usage_logs aggregation. It is read-only; the automatic throttle list is
// produced by SuspectThrottleService which reuses computeAutoThrottleUsers here.
type AbuseDetectionService struct {
	usageLogRepo UsageLogRepository
}

// NewAbuseDetectionService creates an AbuseDetectionService.
func NewAbuseDetectionService(usageLogRepo UsageLogRepository) *AbuseDetectionService {
	return &AbuseDetectionService{usageLogRepo: usageLogRepo}
}

// ListSuspectGroups returns the suspect groups for the given window/threshold/dimensions.
// All requested dimensions are returned (OR semantics) for admin display.
func (s *AbuseDetectionService) ListSuspectGroups(ctx context.Context, windowHours, minUsers int, dimensions []string) ([]usagestats.SuspectGroup, error) {
	if s == nil || s.usageLogRepo == nil {
		return nil, nil
	}
	if windowHours < 1 {
		windowHours = DefaultSuspectThrottleWindowHours
	}
	if minUsers < 2 {
		minUsers = DefaultSuspectThrottleMinUsers
	}
	end := time.Now()
	start := end.Add(-time.Duration(windowHours) * time.Hour)
	return s.usageLogRepo.FindSuspectedMultiAccountGroups(ctx, usagestats.SuspectGroupFilters{
		StartTime:  start,
		EndTime:    end,
		MinUsers:   minUsers,
		Dimensions: dimensions,
	})
}

// computeAutoThrottleUsers applies the R4 cross-dimension guard: a user is only
// auto-throttled when it appears in an IP-dimension group AND in a device- or
// fingerprint-dimension group within the same window. IP single-dimension hits
// are display-only and never enter the automatic list on their own, since shared
// egress IPs (NAT / CGNAT / VPN) routinely group legitimate users.
//
// It returns the qualifying user IDs mapped to the dimensions that flagged them
// (for observability), derived from the already-fetched suspect groups.
func computeAutoThrottleUsers(groups []usagestats.SuspectGroup) map[int64][]string {
	// Per user: which dimension-classes flagged it.
	ipUsers := make(map[int64]bool)
	deviceUsers := make(map[int64]bool)
	fingerprintUsers := make(map[int64]bool)
	for _, g := range groups {
		for _, m := range g.Members {
			switch g.Dimension {
			case usagestats.AbuseDimensionIP:
				ipUsers[m.UserID] = true
			case usagestats.AbuseDimensionDevice:
				deviceUsers[m.UserID] = true
			case usagestats.AbuseDimensionFingerprint:
				fingerprintUsers[m.UserID] = true
			}
		}
	}

	result := make(map[int64][]string)
	for userID := range ipUsers {
		dims := make([]string, 0, 2)
		if deviceUsers[userID] {
			dims = append(dims, usagestats.AbuseDimensionDevice)
		}
		if fingerprintUsers[userID] {
			dims = append(dims, usagestats.AbuseDimensionFingerprint)
		}
		if len(dims) == 0 {
			continue // IP-only → display-only, not auto-throttled.
		}
		dims = append(dims, usagestats.AbuseDimensionIP)
		sort.Strings(dims)
		result[userID] = dims
	}
	return result
}
