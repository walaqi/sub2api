//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// bulkUsersRepoStub embeds userRepoStub and adds programmable role lookup +
// status update recording for BulkUpdateUsers tests (R1 / R7).
type bulkUsersRepoStub struct {
	*userRepoStub

	roles            map[int64]string // returned by GetRolesByIDs
	rolesErr         error
	statusUpdatedIDs []int64
	statusValue      string
	statusErr        error
}

func (s *bulkUsersRepoStub) GetRolesByIDs(_ context.Context, userIDs []int64) (map[int64]string, error) {
	if s.rolesErr != nil {
		return nil, s.rolesErr
	}
	out := make(map[int64]string, len(userIDs))
	for _, id := range userIDs {
		if role, ok := s.roles[id]; ok {
			out[id] = role
		}
	}
	return out, nil
}

func (s *bulkUsersRepoStub) BatchUpdateStatus(_ context.Context, userIDs []int64, status string) (int, error) {
	if s.statusErr != nil {
		return 0, s.statusErr
	}
	s.statusUpdatedIDs = append(s.statusUpdatedIDs, userIDs...)
	s.statusValue = status
	return len(userIDs), nil
}

func newBulkUsersService(roles map[int64]string) (*adminServiceImpl, *bulkUsersRepoStub, *authCacheInvalidatorStub) {
	repo := &bulkUsersRepoStub{userRepoStub: &userRepoStub{}, roles: roles}
	invalidator := &authCacheInvalidatorStub{}
	svc := &adminServiceImpl{
		userRepo:             repo,
		authCacheInvalidator: invalidator,
	}
	return svc, repo, invalidator
}

// R1: a successful bulk disable must invalidate the auth cache for every
// affected user so the disable takes effect immediately on the API Key path.
func TestAdminService_BulkUpdateUsers_InvalidatesAuthCache(t *testing.T) {
	svc, repo, invalidator := newBulkUsersService(map[int64]string{
		1: "user", 2: "user", 3: "user",
	})

	result, err := svc.BulkUpdateUsers(context.Background(), &BulkUpdateUsersInput{
		UserIDs: []int64{1, 2, 3},
		Status:  StatusDisabled,
	})
	require.NoError(t, err)
	require.Equal(t, 3, result.Success)
	require.ElementsMatch(t, []int64{1, 2, 3}, result.SuccessIDs)
	require.Equal(t, StatusDisabled, repo.statusValue)
	require.ElementsMatch(t, []int64{1, 2, 3}, repo.statusUpdatedIDs)
	// R1 核心断言：每个受影响用户都触发缓存失效。
	require.ElementsMatch(t, []int64{1, 2, 3}, invalidator.userIDs)
}

// R7: admin-role users must be skipped on disable and reported in SkippedIDs;
// they must not be written nor have their cache invalidated.
func TestAdminService_BulkUpdateUsers_SkipsAdminUsers(t *testing.T) {
	svc, repo, invalidator := newBulkUsersService(map[int64]string{
		1: "user", 2: "admin", 3: "user",
	})

	result, err := svc.BulkUpdateUsers(context.Background(), &BulkUpdateUsersInput{
		UserIDs: []int64{1, 2, 3},
		Status:  StatusDisabled,
	})
	require.NoError(t, err)
	require.Equal(t, 2, result.Success)
	require.Equal(t, 1, result.Skipped)
	require.ElementsMatch(t, []int64{1, 3}, result.SuccessIDs)
	require.Equal(t, []int64{2}, result.SkippedIDs)
	// admin 不应被写入，也不应失效缓存。
	require.ElementsMatch(t, []int64{1, 3}, repo.statusUpdatedIDs)
	require.NotContains(t, invalidator.userIDs, int64(2))
	require.ElementsMatch(t, []int64{1, 3}, invalidator.userIDs)
}

// Unknown / soft-deleted ids (no role row) are reported as failed on disable.
func TestAdminService_BulkUpdateUsers_UnknownIDsFail(t *testing.T) {
	svc, _, invalidator := newBulkUsersService(map[int64]string{
		1: "user", // id 9 missing
	})

	result, err := svc.BulkUpdateUsers(context.Background(), &BulkUpdateUsersInput{
		UserIDs: []int64{1, 9},
		Status:  StatusDisabled,
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.Success)
	require.Equal(t, 1, result.Failed)
	require.Equal(t, []int64{9}, result.FailedIDs)
	require.ElementsMatch(t, []int64{1}, invalidator.userIDs)
}

// Re-activation does not run the admin role guard (enabling admins is harmless)
// but still invalidates the cache for every affected user.
func TestAdminService_BulkUpdateUsers_ActivateSkipsRoleGuard(t *testing.T) {
	svc, repo, invalidator := newBulkUsersService(map[int64]string{
		1: "admin", 2: "user",
	})

	result, err := svc.BulkUpdateUsers(context.Background(), &BulkUpdateUsersInput{
		UserIDs: []int64{1, 2},
		Status:  StatusActive,
	})
	require.NoError(t, err)
	require.Equal(t, 2, result.Success)
	require.Empty(t, result.SkippedIDs)
	require.Equal(t, StatusActive, repo.statusValue)
	require.ElementsMatch(t, []int64{1, 2}, invalidator.userIDs)
}

func TestAdminService_BulkUpdateUsers_RejectsInvalidStatus(t *testing.T) {
	svc, _, _ := newBulkUsersService(nil)
	_, err := svc.BulkUpdateUsers(context.Background(), &BulkUpdateUsersInput{
		UserIDs: []int64{1},
		Status:  "banned",
	})
	require.Error(t, err)
}

func TestAdminService_BulkUpdateUsers_DeduplicatesIDs(t *testing.T) {
	svc, repo, invalidator := newBulkUsersService(map[int64]string{1: "user"})

	result, err := svc.BulkUpdateUsers(context.Background(), &BulkUpdateUsersInput{
		UserIDs: []int64{1, 1, 1, 0, -5},
		Status:  StatusDisabled,
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.Success)
	require.ElementsMatch(t, []int64{1}, repo.statusUpdatedIDs)
	require.ElementsMatch(t, []int64{1}, invalidator.userIDs)
}
