//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AnnouncementReadStatusSuite struct {
	suite.Suite
	ctx context.Context
}

func TestAnnouncementReadStatusSuite(t *testing.T) {
	suite.Run(t, new(AnnouncementReadStatusSuite))
}

func (s *AnnouncementReadStatusSuite) SetupTest() {
	s.ctx = context.Background()
}

func (s *AnnouncementReadStatusSuite) TestListUserReadStatusByReadAt_SortDescNullsLast() {
	t := s.T()
	client := testEntClient(t)

	// Create test users
	u1, err := client.User.Create().
		SetEmail("readstatus-read1@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u1).Exec(s.ctx) })

	u2, err := client.User.Create().
		SetEmail("readstatus-read2@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u2).Exec(s.ctx) })

	u3, err := client.User.Create().
		SetEmail("readstatus-unread@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u3).Exec(s.ctx) })

	// Create announcement
	ann, err := client.Announcement.Create().
		SetTitle("test-read-sort").
		SetContent("content").
		SetStatus("active").
		SetNotifyMode("silent").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Announcement.DeleteOne(ann).Exec(s.ctx) })

	// u1 read earlier, u2 read later, u3 never read
	readTime1 := time.Now().Add(-2 * time.Hour)
	readTime2 := time.Now().Add(-1 * time.Hour)

	ar1, err := client.AnnouncementRead.Create().
		SetAnnouncementID(int64(ann.ID)).
		SetUserID(int64(u1.ID)).
		SetReadAt(readTime1).
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.AnnouncementRead.DeleteOne(ar1).Exec(s.ctx) })

	ar2, err := client.AnnouncementRead.Create().
		SetAnnouncementID(int64(ann.ID)).
		SetUserID(int64(u2.ID)).
		SetReadAt(readTime2).
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.AnnouncementRead.DeleteOne(ar2).Exec(s.ctx) })

	// Build service with real repos
	announcementRepo := NewAnnouncementRepository(client)
	readRepo := NewAnnouncementReadRepository(client)
	userRepo := NewUserRepository(client, integrationDB)
	userSubRepo := NewUserSubscriptionRepository(client)
	svc := service.NewAnnouncementService(announcementRepo, readRepo, userRepo, userSubRepo, client)

	// Sort by read_at DESC — u2 (most recent read) first, u1 second, u3 (unread) last
	params := pagination.PaginationParams{
		Page:      1,
		PageSize:  50,
		SortBy:    "read_at",
		SortOrder: "desc",
	}

	items, page, err := svc.ListUserReadStatus(s.ctx, int64(ann.ID), params, "readstatus-")
	require.NoError(t, err)
	require.NotNil(t, page)
	require.Equal(t, int64(3), page.Total)
	require.Len(t, items, 3)

	// First item should be u2 (most recent read_at)
	require.Equal(t, int64(u2.ID), items[0].UserID)
	require.NotNil(t, items[0].ReadAt)

	// Second item should be u1 (earlier read_at)
	require.Equal(t, int64(u1.ID), items[1].UserID)
	require.NotNil(t, items[1].ReadAt)

	// Third item should be u3 (unread, NULLS LAST)
	require.Equal(t, int64(u3.ID), items[2].UserID)
	require.Nil(t, items[2].ReadAt)
}

func (s *AnnouncementReadStatusSuite) TestListUserReadStatusByReadAt_SortAsc() {
	t := s.T()
	client := testEntClient(t)

	// Create test users
	u1, err := client.User.Create().
		SetEmail("readstatus-asc-read@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u1).Exec(s.ctx) })

	u2, err := client.User.Create().
		SetEmail("readstatus-asc-unread@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u2).Exec(s.ctx) })

	// Create announcement
	ann, err := client.Announcement.Create().
		SetTitle("test-read-sort-asc").
		SetContent("content").
		SetStatus("active").
		SetNotifyMode("silent").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Announcement.DeleteOne(ann).Exec(s.ctx) })

	// u1 has read
	readTime := time.Now().Add(-1 * time.Hour)
	ar, err := client.AnnouncementRead.Create().
		SetAnnouncementID(int64(ann.ID)).
		SetUserID(int64(u1.ID)).
		SetReadAt(readTime).
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.AnnouncementRead.DeleteOne(ar).Exec(s.ctx) })

	// Build service
	announcementRepo := NewAnnouncementRepository(client)
	readRepo := NewAnnouncementReadRepository(client)
	userRepo := NewUserRepository(client, integrationDB)
	userSubRepo := NewUserSubscriptionRepository(client)
	svc := service.NewAnnouncementService(announcementRepo, readRepo, userRepo, userSubRepo, client)

	// Sort by read_at ASC NULLS LAST — u1 (has read_at) first, u2 (unread) last
	params := pagination.PaginationParams{
		Page:      1,
		PageSize:  50,
		SortBy:    "read_at",
		SortOrder: "asc",
	}

	items, page, err := svc.ListUserReadStatus(s.ctx, int64(ann.ID), params, "readstatus-asc-")
	require.NoError(t, err)
	require.NotNil(t, page)
	require.Equal(t, int64(2), page.Total)
	require.Len(t, items, 2)

	// ASC: read user first, unread last (NULLS LAST)
	require.Equal(t, int64(u1.ID), items[0].UserID)
	require.NotNil(t, items[0].ReadAt)
	require.Equal(t, int64(u2.ID), items[1].UserID)
	require.Nil(t, items[1].ReadAt)
}

func (s *AnnouncementReadStatusSuite) TestListUserReadStatusByReadAt_WithSearch() {
	t := s.T()
	client := testEntClient(t)

	u1, err := client.User.Create().
		SetEmail("readstatus-search-match@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u1).Exec(s.ctx) })

	u2, err := client.User.Create().
		SetEmail("readstatus-search-other@test.com").
		SetPasswordHash("x").
		SetRole("user").
		SetStatus("active").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.User.DeleteOne(u2).Exec(s.ctx) })

	ann, err := client.Announcement.Create().
		SetTitle("test-read-sort-search").
		SetContent("content").
		SetStatus("active").
		SetNotifyMode("silent").
		Save(s.ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Announcement.DeleteOne(ann).Exec(s.ctx) })

	// Build service
	announcementRepo := NewAnnouncementRepository(client)
	readRepo := NewAnnouncementReadRepository(client)
	userRepo := NewUserRepository(client, integrationDB)
	userSubRepo := NewUserSubscriptionRepository(client)
	svc := service.NewAnnouncementService(announcementRepo, readRepo, userRepo, userSubRepo, client)

	params := pagination.PaginationParams{
		Page:      1,
		PageSize:  50,
		SortBy:    "read_at",
		SortOrder: "desc",
	}

	// Search should filter to only "match" user
	items, page, err := svc.ListUserReadStatus(s.ctx, int64(ann.ID), params, "readstatus-search-match")
	require.NoError(t, err)
	require.NotNil(t, page)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, items, 1)
	require.Equal(t, int64(u1.ID), items[0].UserID)
}
