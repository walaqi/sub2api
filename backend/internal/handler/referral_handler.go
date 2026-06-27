package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ReferralHandler handles user-facing referral reward queries.
type ReferralHandler struct {
	referralService *service.ReferralRewardService
}

// NewReferralHandler creates a new ReferralHandler.
func NewReferralHandler(referralService *service.ReferralRewardService) *ReferralHandler {
	return &ReferralHandler{referralService: referralService}
}

// GetStatus GET /api/v1/user/referral/status
// Returns the user's referral reward status (invitee reward, inviter progress).
func (h *ReferralHandler) GetStatus(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "not authenticated")
		return
	}

	status, err := h.referralService.GetReferralStatus(c.Request.Context(), subject.UserID)
	if err != nil {
		response.InternalError(c, "query referral status failed: "+err.Error())
		return
	}

	response.Success(c, status)
}
