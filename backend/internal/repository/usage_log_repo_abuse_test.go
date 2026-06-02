package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/stretchr/testify/require"
)

// TestFindSuspectedMultiAccountGroups_DeviceDimension verifies the two-stage
// aggregation maps rows into per-value groups with accumulated member footprints.
func TestFindSuspectedMultiAccountGroups_DeviceDimension(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &usageLogRepository{sql: db}

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	t1 := start.Add(time.Hour)
	t2 := start.Add(2 * time.Hour)

	// Two users sharing device "dev-A"; the query is the device-dimension scan.
	rows := sqlmock.NewRows([]string{"dim_value", "user_id", "email", "username", "requests", "first_seen", "last_seen"}).
		AddRow("dev-A", int64(11), "a@x.com", "alice", int64(50), t1, t2).
		AddRow("dev-A", int64(22), "b@x.com", "bob", int64(30), t1, t2)

	// device_id IS NOT NULL guard must be present (NULL-collapse protection),
	// and disabled users must be excluded from the count/members ($5).
	mock.ExpectQuery(`device_id IS NOT NULL[\s\S]*status <> \$5[\s\S]*HAVING COUNT\(DISTINCT ul\.user_id\) >=`).
		WithArgs(start, end, 3, 200, "disabled").
		WillReturnRows(rows)

	groups, err := repo.FindSuspectedMultiAccountGroups(context.Background(), usagestats.SuspectGroupFilters{
		StartTime:  start,
		EndTime:    end,
		MinUsers:   3,
		Dimensions: []string{usagestats.AbuseDimensionDevice},
	})
	require.NoError(t, err)
	require.Len(t, groups, 1)

	g := groups[0]
	require.Equal(t, usagestats.AbuseDimensionDevice, g.Dimension)
	require.Equal(t, "dev-A", g.Value)
	require.Equal(t, int64(2), g.UserCount)
	require.Equal(t, int64(80), g.TotalRequests)
	require.Len(t, g.Members, 2)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestFindSuspectedMultiAccountGroups_NullSemantics is the R-region regression:
// the WHERE ... IS NOT NULL clause must exclude empty device_id / fingerprint
// rows so they cannot collapse into one giant false-positive group. We assert the
// guard is in the SQL and that a result set with no qualifying values yields no groups.
func TestFindSuspectedMultiAccountGroups_NullSemantics(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &usageLogRepository{sql: db}

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	// flagged CTE returns nothing (all NULL device_ids were filtered out) → empty result.
	empty := sqlmock.NewRows([]string{"dim_value", "user_id", "email", "username", "requests", "first_seen", "last_seen"})
	mock.ExpectQuery(`client_fingerprint IS NOT NULL`).
		WithArgs(start, end, 3, 200, "disabled").
		WillReturnRows(empty)

	groups, err := repo.FindSuspectedMultiAccountGroups(context.Background(), usagestats.SuspectGroupFilters{
		StartTime:  start,
		EndTime:    end,
		MinUsers:   3,
		Dimensions: []string{usagestats.AbuseDimensionFingerprint},
	})
	require.NoError(t, err)
	require.Empty(t, groups)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestFindSuspectedMultiAccountGroups_MinUsersFloor ensures a sub-2 threshold is
// floored to 2 (a "group" needs at least two distinct users to be meaningful).
func TestFindSuspectedMultiAccountGroups_MinUsersFloor(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &usageLogRepository{sql: db}

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	empty := sqlmock.NewRows([]string{"dim_value", "user_id", "email", "username", "requests", "first_seen", "last_seen"})
	mock.ExpectQuery(`ip_address IS NOT NULL`).
		WithArgs(start, end, 2, 200, "disabled"). // MinUsers=1 floored to 2
		WillReturnRows(empty)

	_, err := repo.FindSuspectedMultiAccountGroups(context.Background(), usagestats.SuspectGroupFilters{
		StartTime:  start,
		EndTime:    end,
		MinUsers:   1,
		Dimensions: []string{usagestats.AbuseDimensionIP},
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
