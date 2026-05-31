package usagestats

import "time"

// Abuse-detection dimension identifiers. A "suspect group" is a set of platform
// users that share the same value along one of these dimensions within a time
// window. device_id and client_fingerprint are high-precision but spoofable;
// ip_address is the weakest single signal (NAT / CGNAT / shared egress) and is
// display-only for the automatic throttle (see SuspectThrottleService).
const (
	AbuseDimensionDevice      = "device"
	AbuseDimensionFingerprint = "fingerprint"
	AbuseDimensionIP          = "ip"
)

// IsValidAbuseDimension reports whether dim is one of the recognized dimensions.
func IsValidAbuseDimension(dim string) bool {
	switch dim {
	case AbuseDimensionDevice, AbuseDimensionFingerprint, AbuseDimensionIP:
		return true
	default:
		return false
	}
}

// SuspectGroupMember is one platform user within a suspect group, with its
// activity footprint along the group's dimension.
type SuspectGroupMember struct {
	UserID    int64     `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Requests  int64     `json:"requests"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// SuspectGroup is one "farm": multiple users sharing a single device_id /
// client_fingerprint / ip_address value within the detection window.
type SuspectGroup struct {
	// Dimension is one of AbuseDimension*.
	Dimension string `json:"dimension"`
	// Value is the shared identifier (device_id / client_fingerprint / ip_address).
	Value string `json:"value"`
	// UserCount is COUNT(DISTINCT user_id) for this value (>= the configured threshold).
	UserCount int64 `json:"user_count"`
	// TotalRequests is the summed request count across all members.
	TotalRequests int64 `json:"total_requests"`
	// FirstSeen / LastSeen span the activity window for the whole group.
	FirstSeen time.Time            `json:"first_seen"`
	LastSeen  time.Time            `json:"last_seen"`
	Members   []SuspectGroupMember `json:"members"`
}

// SuspectGroupFilters parameterizes a multi-account suspect-group query.
type SuspectGroupFilters struct {
	// StartTime / EndTime bound the detection window (created_at >= StartTime AND < EndTime).
	StartTime time.Time
	EndTime   time.Time
	// MinUsers is the COUNT(DISTINCT user_id) HAVING threshold (N).
	MinUsers int
	// Dimensions selects which dimensions to scan; empty means all three.
	Dimensions []string
	// MaxGroups caps the number of returned groups per dimension (0 = a sane default).
	MaxGroups int
}
