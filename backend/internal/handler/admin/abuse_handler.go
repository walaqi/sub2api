package admin

import (
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// AbuseHandler serves the multi-account abuse detection admin endpoints:
// suspect-group listing, bulk user disable, throttle settings, and the live
// auto-throttle list.
type AbuseHandler struct {
	detection      *service.AbuseDetectionService
	adminService   service.AdminService
	settingService *service.SettingService
	suspectStore   service.SuspectStore
}

// NewAbuseHandler creates an AbuseHandler.
func NewAbuseHandler(
	detection *service.AbuseDetectionService,
	adminService service.AdminService,
	settingService *service.SettingService,
	suspectStore service.SuspectStore,
) *AbuseHandler {
	return &AbuseHandler{
		detection:      detection,
		adminService:   adminService,
		settingService: settingService,
		suspectStore:   suspectStore,
	}
}

// ListSuspects GET /admin/abuse/suspects?window_hours=&min_users=&dimensions=
// Returns suspect groups across the requested dimensions for admin review.
func (h *AbuseHandler) ListSuspects(c *gin.Context) {
	windowHours := parseIntDefault(c.Query("window_hours"), service.DefaultSuspectThrottleWindowHours)
	minUsers := parseIntDefault(c.Query("min_users"), service.DefaultSuspectThrottleMinUsers)

	var dimensions []string
	if raw := strings.TrimSpace(c.Query("dimensions")); raw != "" {
		for _, d := range strings.Split(raw, ",") {
			d = strings.TrimSpace(d)
			if usagestats.IsValidAbuseDimension(d) {
				dimensions = append(dimensions, d)
			}
		}
	}

	groups, err := h.detection.ListSuspectGroups(c.Request.Context(), windowHours, minUsers, dimensions)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{
		"window_hours": windowHours,
		"min_users":    minUsers,
		"groups":       groups,
	})
}

// BulkDisableUsersRequest is the body for bulk user status updates.
type BulkDisableUsersRequest struct {
	UserIDs []int64 `json:"user_ids" binding:"required"`
	Status  string  `json:"status" binding:"required,oneof=active disabled"`
}

// BulkUpdateUsers POST /admin/abuse/users/bulk-update
// Disables (or re-activates) multiple platform users at once. Admin-role users
// are skipped; the auth cache is invalidated so a disable takes effect at once.
func (h *AbuseHandler) BulkUpdateUsers(c *gin.Context) {
	var req BulkDisableUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	if len(req.UserIDs) == 0 {
		response.BadRequest(c, "user_ids is required")
		return
	}

	result, err := h.adminService.BulkUpdateUsers(c.Request.Context(), &service.BulkUpdateUsersInput{
		UserIDs: req.UserIDs,
		Status:  req.Status,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

// GetThrottleSettings GET /admin/abuse/throttle-settings
func (h *AbuseHandler) GetThrottleSettings(c *gin.Context) {
	settings, err := h.settingService.GetSuspectThrottleSettings(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, settings)
}

// UpdateThrottleSettings PUT /admin/abuse/throttle-settings
func (h *AbuseHandler) UpdateThrottleSettings(c *gin.Context) {
	var settings service.SuspectThrottleSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	if err := h.settingService.SetSuspectThrottleSettings(c.Request.Context(), &settings); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, &settings)
}

// ListThrottled GET /admin/abuse/throttled
// Returns the current auto-throttle list (R8 observability).
func (h *AbuseHandler) ListThrottled(c *gin.Context) {
	entries, err := h.suspectStore.List(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{
		"count":   len(entries),
		"entries": entries,
	})
}

// ClearThrottled DELETE /admin/abuse/throttled
// Immediately clears the entire auto-throttle list.
func (h *AbuseHandler) ClearThrottled(c *gin.Context) {
	cleared, err := h.suspectStore.Clear(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"cleared": cleared})
}

func parseIntDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}
