//go:build unit

package service

import (
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/stretchr/testify/require"
)

func mkGroup(dim string, userIDs ...int64) usagestats.SuspectGroup {
	members := make([]usagestats.SuspectGroupMember, 0, len(userIDs))
	for _, id := range userIDs {
		members = append(members, usagestats.SuspectGroupMember{UserID: id, Requests: 1, LastSeen: time.Now()})
	}
	return usagestats.SuspectGroup{
		Dimension: dim,
		Value:     dim + "-val",
		UserCount: int64(len(userIDs)),
		Members:   members,
	}
}

// R4: IP single-dimension hits must NOT enter the auto-throttle list on their
// own. Only users that also appear in a device- or fingerprint-dimension group
// (cross-dimension) qualify.
func TestComputeAutoThrottleUsers_IPOnlyIsExcluded(t *testing.T) {
	groups := []usagestats.SuspectGroup{
		// Shared egress IP groups many users — but IP alone is not enough.
		mkGroup(usagestats.AbuseDimensionIP, 1, 2, 3, 4, 5),
	}
	result := computeAutoThrottleUsers(groups)
	require.Empty(t, result, "IP 单维度命中不应进入自动名单")
}

func TestComputeAutoThrottleUsers_DeviceIntersectIP(t *testing.T) {
	groups := []usagestats.SuspectGroup{
		mkGroup(usagestats.AbuseDimensionIP, 1, 2, 3),
		mkGroup(usagestats.AbuseDimensionDevice, 2, 9), // user 2 in both device & IP
	}
	result := computeAutoThrottleUsers(groups)
	require.Len(t, result, 1)
	require.Contains(t, result, int64(2))
	require.Equal(t, []string{usagestats.AbuseDimensionDevice, usagestats.AbuseDimensionIP}, result[2])
	// user 9 only in device (no IP) → excluded; users 1,3 only in IP → excluded.
	require.NotContains(t, result, int64(9))
	require.NotContains(t, result, int64(1))
}

func TestComputeAutoThrottleUsers_FingerprintIntersectIP(t *testing.T) {
	groups := []usagestats.SuspectGroup{
		mkGroup(usagestats.AbuseDimensionIP, 7, 8),
		mkGroup(usagestats.AbuseDimensionFingerprint, 7),
	}
	result := computeAutoThrottleUsers(groups)
	require.Len(t, result, 1)
	require.Contains(t, result, int64(7))
	require.Equal(t, []string{usagestats.AbuseDimensionFingerprint, usagestats.AbuseDimensionIP}, result[7])
}

func TestComputeAutoThrottleUsers_DeviceWithoutIPExcluded(t *testing.T) {
	groups := []usagestats.SuspectGroup{
		mkGroup(usagestats.AbuseDimensionDevice, 1, 2),
		mkGroup(usagestats.AbuseDimensionFingerprint, 1, 2),
	}
	// Strong device+fingerprint signal but no shared IP → still requires IP cross.
	result := computeAutoThrottleUsers(groups)
	require.Empty(t, result, "无 IP 交叉时不进入自动名单（默认护栏要求与 IP 交叉）")
}

func TestComputeAutoThrottleUsers_AllThreeDimensions(t *testing.T) {
	groups := []usagestats.SuspectGroup{
		mkGroup(usagestats.AbuseDimensionIP, 5),
		mkGroup(usagestats.AbuseDimensionDevice, 5),
		mkGroup(usagestats.AbuseDimensionFingerprint, 5),
	}
	result := computeAutoThrottleUsers(groups)
	require.Len(t, result, 1)
	require.Equal(t,
		[]string{usagestats.AbuseDimensionDevice, usagestats.AbuseDimensionFingerprint, usagestats.AbuseDimensionIP},
		result[5])
}
