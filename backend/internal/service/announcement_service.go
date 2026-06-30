package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
)

type AnnouncementService struct {
	announcementRepo AnnouncementRepository
	readRepo         AnnouncementReadRepository
	userRepo         UserRepository
	userSubRepo      UserSubscriptionRepository
	entClient        *dbent.Client
}

func NewAnnouncementService(
	announcementRepo AnnouncementRepository,
	readRepo AnnouncementReadRepository,
	userRepo UserRepository,
	userSubRepo UserSubscriptionRepository,
	entClient *dbent.Client,
) *AnnouncementService {
	return &AnnouncementService{
		announcementRepo: announcementRepo,
		readRepo:         readRepo,
		userRepo:         userRepo,
		userSubRepo:      userSubRepo,
		entClient:        entClient,
	}
}

type CreateAnnouncementInput struct {
	Title      string
	Content    string
	Status     string
	NotifyMode string
	Targeting  AnnouncementTargeting
	StartsAt   *time.Time
	EndsAt     *time.Time
	ActorID    *int64 // 管理员用户ID
}

type UpdateAnnouncementInput struct {
	Title      *string
	Content    *string
	Status     *string
	NotifyMode *string
	Targeting  *AnnouncementTargeting
	StartsAt   **time.Time
	EndsAt     **time.Time
	ActorID    *int64 // 管理员用户ID
}

type UserAnnouncement struct {
	Announcement Announcement
	ReadAt       *time.Time
}

type AnnouncementUserReadStatus struct {
	UserID   int64      `json:"user_id"`
	Email    string     `json:"email"`
	Username string     `json:"username"`
	Balance  float64    `json:"balance"`
	Eligible bool       `json:"eligible"`
	ReadAt   *time.Time `json:"read_at,omitempty"`
}

func (s *AnnouncementService) Create(ctx context.Context, input *CreateAnnouncementInput) (*Announcement, error) {
	if input == nil {
		return nil, ErrAnnouncementNilInput
	}

	title := strings.TrimSpace(input.Title)
	content := strings.TrimSpace(input.Content)
	if title == "" || len(title) > 200 {
		return nil, ErrAnnouncementInvalidTitle
	}
	if content == "" {
		return nil, ErrAnnouncementContentRequired
	}

	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = AnnouncementStatusDraft
	}
	if !isValidAnnouncementStatus(status) {
		return nil, ErrAnnouncementInvalidStatus
	}

	targeting, err := domain.AnnouncementTargeting(input.Targeting).NormalizeAndValidate()
	if err != nil {
		return nil, err
	}

	notifyMode := strings.TrimSpace(input.NotifyMode)
	if notifyMode == "" {
		notifyMode = AnnouncementNotifyModeSilent
	}
	if !isValidAnnouncementNotifyMode(notifyMode) {
		return nil, ErrAnnouncementInvalidNotifyMode
	}

	if input.StartsAt != nil && input.EndsAt != nil {
		if !input.StartsAt.Before(*input.EndsAt) {
			return nil, ErrAnnouncementInvalidSchedule
		}
	}

	a := &Announcement{
		Title:      title,
		Content:    content,
		Status:     status,
		NotifyMode: notifyMode,
		Targeting:  targeting,
		StartsAt:   input.StartsAt,
		EndsAt:     input.EndsAt,
	}
	if input.ActorID != nil && *input.ActorID > 0 {
		a.CreatedBy = input.ActorID
		a.UpdatedBy = input.ActorID
	}

	if err := s.announcementRepo.Create(ctx, a); err != nil {
		return nil, fmt.Errorf("create announcement: %w", err)
	}
	return a, nil
}

func (s *AnnouncementService) Update(ctx context.Context, id int64, input *UpdateAnnouncementInput) (*Announcement, error) {
	if input == nil {
		return nil, ErrAnnouncementNilInput
	}

	a, err := s.announcementRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Title != nil {
		title := strings.TrimSpace(*input.Title)
		if title == "" || len(title) > 200 {
			return nil, ErrAnnouncementInvalidTitle
		}
		a.Title = title
	}
	if input.Content != nil {
		content := strings.TrimSpace(*input.Content)
		if content == "" {
			return nil, ErrAnnouncementContentRequired
		}
		a.Content = content
	}
	if input.Status != nil {
		status := strings.TrimSpace(*input.Status)
		if !isValidAnnouncementStatus(status) {
			return nil, ErrAnnouncementInvalidStatus
		}
		a.Status = status
	}

	if input.NotifyMode != nil {
		notifyMode := strings.TrimSpace(*input.NotifyMode)
		if !isValidAnnouncementNotifyMode(notifyMode) {
			return nil, ErrAnnouncementInvalidNotifyMode
		}
		a.NotifyMode = notifyMode
	}

	if input.Targeting != nil {
		targeting, err := domain.AnnouncementTargeting(*input.Targeting).NormalizeAndValidate()
		if err != nil {
			return nil, err
		}
		a.Targeting = targeting
	}

	if input.StartsAt != nil {
		a.StartsAt = *input.StartsAt
	}
	if input.EndsAt != nil {
		a.EndsAt = *input.EndsAt
	}

	if a.StartsAt != nil && a.EndsAt != nil {
		if !a.StartsAt.Before(*a.EndsAt) {
			return nil, ErrAnnouncementInvalidSchedule
		}
	}

	if input.ActorID != nil && *input.ActorID > 0 {
		a.UpdatedBy = input.ActorID
	}

	if err := s.announcementRepo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("update announcement: %w", err)
	}
	return a, nil
}

func (s *AnnouncementService) Delete(ctx context.Context, id int64) error {
	if err := s.announcementRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete announcement: %w", err)
	}
	return nil
}

func (s *AnnouncementService) GetByID(ctx context.Context, id int64) (*Announcement, error) {
	return s.announcementRepo.GetByID(ctx, id)
}

func (s *AnnouncementService) List(ctx context.Context, params pagination.PaginationParams, filters AnnouncementListFilters) ([]Announcement, *pagination.PaginationResult, error) {
	return s.announcementRepo.List(ctx, params, filters)
}

func (s *AnnouncementService) ListForUser(ctx context.Context, userID int64, unreadOnly bool) ([]UserAnnouncement, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	activeSubs, err := s.userSubRepo.ListActiveByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list active subscriptions: %w", err)
	}
	activeGroupIDs := make(map[int64]struct{}, len(activeSubs))
	for i := range activeSubs {
		activeGroupIDs[activeSubs[i].GroupID] = struct{}{}
	}

	targetCtx := domain.UserTargetingContext{
		Balance:                    user.Balance,
		ActiveSubscriptionGroupIDs: activeGroupIDs,
	}
	s.fillReferralTargeting(ctx, userID, &targetCtx)

	now := time.Now()
	anns, err := s.announcementRepo.ListActive(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("list active announcements: %w", err)
	}

	visible := make([]Announcement, 0, len(anns))
	ids := make([]int64, 0, len(anns))
	for i := range anns {
		a := anns[i]
		if !a.IsActiveAt(now) {
			continue
		}
		if !a.Targeting.Matches(targetCtx) {
			continue
		}
		visible = append(visible, a)
		ids = append(ids, a.ID)
	}

	if len(visible) == 0 {
		return []UserAnnouncement{}, nil
	}

	readMap, err := s.readRepo.GetReadMapByUser(ctx, userID, ids)
	if err != nil {
		return nil, fmt.Errorf("get read map: %w", err)
	}

	out := make([]UserAnnouncement, 0, len(visible))
	for i := range visible {
		a := visible[i]
		readAt, ok := readMap[a.ID]
		if unreadOnly && ok {
			continue
		}
		var ptr *time.Time
		if ok {
			t := readAt
			ptr = &t
		}
		out = append(out, UserAnnouncement{
			Announcement: a,
			ReadAt:       ptr,
		})
	}

	// 未读优先、同状态按创建时间倒序
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i], out[j]
		if (ai.ReadAt == nil) != (aj.ReadAt == nil) {
			return ai.ReadAt == nil
		}
		return ai.Announcement.ID > aj.Announcement.ID
	})

	return out, nil
}

func (s *AnnouncementService) MarkRead(ctx context.Context, userID, announcementID int64) error {
	// 安全：仅允许标记当前用户“可见”的公告
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	a, err := s.announcementRepo.GetByID(ctx, announcementID)
	if err != nil {
		return err
	}

	now := time.Now()
	if !a.IsActiveAt(now) {
		return ErrAnnouncementNotFound
	}

	activeSubs, err := s.userSubRepo.ListActiveByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("list active subscriptions: %w", err)
	}
	activeGroupIDs := make(map[int64]struct{}, len(activeSubs))
	for i := range activeSubs {
		activeGroupIDs[activeSubs[i].GroupID] = struct{}{}
	}

	targetCtx := domain.UserTargetingContext{
		Balance:                    user.Balance,
		ActiveSubscriptionGroupIDs: activeGroupIDs,
	}
	s.fillReferralTargeting(ctx, userID, &targetCtx)

	if !a.Targeting.Matches(targetCtx) {
		return ErrAnnouncementNotFound
	}

	if err := s.readRepo.MarkRead(ctx, announcementID, userID, now); err != nil {
		return fmt.Errorf("mark read: %w", err)
	}
	return nil
}

func (s *AnnouncementService) ListUserReadStatus(
	ctx context.Context,
	announcementID int64,
	params pagination.PaginationParams,
	search string,
) ([]AnnouncementUserReadStatus, *pagination.PaginationResult, error) {
	ann, err := s.announcementRepo.GetByID(ctx, announcementID)
	if err != nil {
		return nil, nil, err
	}

	// When sorting by read_at, use a custom SQL path with LEFT JOIN
	sortBy := strings.ToLower(strings.TrimSpace(params.SortBy))
	if sortBy == "read_at" && s.entClient != nil {
		return s.listUserReadStatusByReadAt(ctx, ann, announcementID, params, search)
	}

	filters := UserListFilters{
		Search: strings.TrimSpace(search),
	}

	users, page, err := s.userRepo.ListWithFilters(ctx, params, filters)
	if err != nil {
		return nil, nil, fmt.Errorf("list users: %w", err)
	}

	return s.buildReadStatusResult(ctx, ann, announcementID, users, page)
}

// buildReadStatusResult takes paginated users and enriches them with read status and eligibility.
func (s *AnnouncementService) buildReadStatusResult(
	ctx context.Context,
	ann *Announcement,
	announcementID int64,
	users []User,
	page *pagination.PaginationResult,
) ([]AnnouncementUserReadStatus, *pagination.PaginationResult, error) {
	userIDs := make([]int64, 0, len(users))
	for i := range users {
		userIDs = append(userIDs, users[i].ID)
	}

	readMap, err := s.readRepo.GetReadMapByUsers(ctx, announcementID, userIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("get read map: %w", err)
	}

	out := make([]AnnouncementUserReadStatus, 0, len(users))
	for i := range users {
		u := users[i]
		subs, err := s.userSubRepo.ListActiveByUserID(ctx, u.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("list active subscriptions: %w", err)
		}
		activeGroupIDs := make(map[int64]struct{}, len(subs))
		for j := range subs {
			activeGroupIDs[subs[j].GroupID] = struct{}{}
		}

		readAt, ok := readMap[u.ID]
		var ptr *time.Time
		if ok {
			t := readAt
			ptr = &t
		}

		out = append(out, AnnouncementUserReadStatus{
			UserID:   u.ID,
			Email:    u.Email,
			Username: u.Username,
			Balance:  u.Balance,
			Eligible: func() bool {
				tc := domain.UserTargetingContext{Balance: u.Balance, ActiveSubscriptionGroupIDs: activeGroupIDs}
				s.fillReferralTargeting(ctx, u.ID, &tc)
				return domain.AnnouncementTargeting(ann.Targeting).Matches(tc)
			}(),
			ReadAt: ptr,
		})
	}

	return out, page, nil
}

// listUserReadStatusByReadAt uses a custom SQL query to sort by read_at (from announcement_reads).
// read_at DESC: read users first (most recent first), then unread users.
func (s *AnnouncementService) listUserReadStatusByReadAt(
	ctx context.Context,
	ann *Announcement,
	announcementID int64,
	params pagination.PaginationParams,
	search string,
) ([]AnnouncementUserReadStatus, *pagination.PaginationResult, error) {
	searchTrimmed := strings.TrimSpace(search)

	// Build WHERE clause (for users table only, no announcement_id needed)
	whereClauses := []string{"u.deleted_at IS NULL"}
	var countArgs []any
	countArgIdx := 1

	if searchTrimmed != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("(u.email ILIKE '%%' || $%d || '%%' OR u.username ILIKE '%%' || $%d || '%%')", countArgIdx, countArgIdx))
		countArgs = append(countArgs, searchTrimmed)
		countArgIdx++ //nolint:ineffassign // kept for clarity matching dataArgIdx pattern
	}

	where := strings.Join(whereClauses, " AND ")

	// Sort order: read_at DESC NULLS LAST (read users first, unread at bottom)
	orderDir := "DESC NULLS LAST"
	if params.NormalizedSortOrder(pagination.SortOrderDesc) == pagination.SortOrderAsc {
		orderDir = "ASC NULLS LAST"
	}

	// Count query (uses only countArgs, no announcementID)
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM users u WHERE %s`, where)
	var total int64
	countRows, err := s.entClient.QueryContext(ctx, countQuery, countArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("count users: %w", err)
	}
	if countRows.Next() {
		if err := countRows.Scan(&total); err != nil {
			_ = countRows.Close()
			return nil, nil, err
		}
	}
	_ = countRows.Close()
	if err := countRows.Err(); err != nil {
		return nil, nil, err
	}

	if total == 0 {
		return []AnnouncementUserReadStatus{}, &pagination.PaginationResult{
			Total: 0, Page: params.Page, PageSize: params.PageSize, Pages: 0,
		}, nil
	}

	// Data query with LEFT JOIN — args start with announcementID ($1), then search ($2 if present), then offset/limit
	dataArgs := []any{announcementID}
	dataArgIdx := 2

	// Rebuild WHERE with shifted parameter indices (since $1 is now announcementID for the JOIN)
	dataWhereClauses := []string{"u.deleted_at IS NULL"}
	if searchTrimmed != "" {
		dataWhereClauses = append(dataWhereClauses, fmt.Sprintf("(u.email ILIKE '%%' || $%d || '%%' OR u.username ILIKE '%%' || $%d || '%%')", dataArgIdx, dataArgIdx))
		dataArgs = append(dataArgs, searchTrimmed)
		dataArgIdx++
	}
	dataWhere := strings.Join(dataWhereClauses, " AND ")

	dataQuery := fmt.Sprintf(`
		SELECT u.id, u.email, COALESCE(u.username, ''), u.balance, ar.read_at
		FROM users u
		LEFT JOIN announcement_reads ar ON ar.user_id = u.id AND ar.announcement_id = $1
		WHERE %s
		ORDER BY ar.read_at %s, u.id DESC
		OFFSET $%d LIMIT $%d
	`, dataWhere, orderDir, dataArgIdx, dataArgIdx+1)
	dataArgs = append(dataArgs, params.Offset(), params.Limit())

	rows, err := s.entClient.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("query users by read_at: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	var readMap = make(map[int64]time.Time)
	for rows.Next() {
		var uid int64
		var email, username string
		var balance float64
		var readAt sql.NullTime
		if err := rows.Scan(&uid, &email, &username, &balance, &readAt); err != nil {
			return nil, nil, err
		}
		users = append(users, User{ID: uid, Email: email, Username: username, Balance: balance})
		if readAt.Valid {
			readMap[uid] = readAt.Time
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Build result
	out := make([]AnnouncementUserReadStatus, 0, len(users))
	for i := range users {
		u := users[i]
		subs, err := s.userSubRepo.ListActiveByUserID(ctx, u.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("list active subscriptions: %w", err)
		}
		activeGroupIDs := make(map[int64]struct{}, len(subs))
		for j := range subs {
			activeGroupIDs[subs[j].GroupID] = struct{}{}
		}

		var ptr *time.Time
		if t, ok := readMap[u.ID]; ok {
			ptr = &t
		}

		out = append(out, AnnouncementUserReadStatus{
			UserID:   u.ID,
			Email:    u.Email,
			Username: u.Username,
			Balance:  u.Balance,
			Eligible: func() bool {
				tc := domain.UserTargetingContext{Balance: u.Balance, ActiveSubscriptionGroupIDs: activeGroupIDs}
				s.fillReferralTargeting(ctx, u.ID, &tc)
				return domain.AnnouncementTargeting(ann.Targeting).Matches(tc)
			}(),
			ReadAt: ptr,
		})
	}

	pages := int64(0)
	if params.PageSize > 0 {
		pages = (total + int64(params.PageSize) - 1) / int64(params.PageSize)
	}

	return out, &pagination.PaginationResult{
		Total:    total,
		Page:     params.Page,
		PageSize: params.PageSize,
		Pages:    int(pages),
	}, nil
}

func isValidAnnouncementStatus(status string) bool {
	switch status {
	case AnnouncementStatusDraft, AnnouncementStatusActive, AnnouncementStatusArchived:
		return true
	default:
		return false
	}
}

func isValidAnnouncementNotifyMode(mode string) bool {
	switch mode {
	case AnnouncementNotifyModeSilent, AnnouncementNotifyModePopup:
		return true
	default:
		return false
	}
}

// fillReferralTargeting 查询用户的 affiliate 状态并填充到 UserTargetingContext。
// 查询失败时 ReferralKnown 保持 false → referral 条件 fail-closed（一律不命中），
// 避免 DB 异常时 no_inviter 误投放给非目标用户。
func (s *AnnouncementService) fillReferralTargeting(ctx context.Context, userID int64, tc *domain.UserTargetingContext) {
	if s.entClient == nil {
		return
	}
	rows, err := s.entClient.QueryContext(ctx,
		`SELECT inviter_id, aff_count FROM user_affiliates WHERE user_id = $1 LIMIT 1`, userID)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		var inviterID sql.NullInt64
		var affCount int
		if err := rows.Scan(&inviterID, &affCount); err != nil {
			return
		}
		tc.ReferralKnown = true
		tc.HasInviter = inviterID.Valid && inviterID.Int64 > 0
		tc.IsInviter = affCount > 0
	} else {
		// 无 user_affiliates 行 = 确认该用户非被邀请人也非邀请人
		tc.ReferralKnown = true
	}
}
