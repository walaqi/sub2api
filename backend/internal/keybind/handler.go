package keybind

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"

	"github.com/gin-gonic/gin"
)

// Handler exposes the keybind service over HTTP.
type Handler struct {
	svc *Service
}

// NewHandler wraps a Service.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

type reserveRequest struct {
	Keys []string `json:"keys"`
}

type commitRequest struct {
	ReservationID string `json:"reservation_id"`
}

// Reserve handles POST /api/v1/bind-key/reserve.
// Public endpoint — no JWT required (so anonymous users can stake a claim
// before registering).
func (h *Handler) Reserve(c *gin.Context) {
	var req reserveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	result, err := h.svc.Reserve(c.Request.Context(), req.Keys)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

// Commit handles POST /api/v1/bind-key/commit.
// Requires JWT auth — user_id is taken from the token, not the request body.
func (h *Handler) Commit(c *gin.Context) {
	subject, ok := servermiddleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "user not authenticated")
		return
	}

	var req commitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	result, err := h.svc.Commit(c.Request.Context(), subject.UserID, req.ReservationID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

// Eligibility handles GET /api/v1/bind-key/eligibility.
// Requires JWT auth — anonymous callers don't have a stable identity to
// gate on, and the client only renders this in the authenticated flow.
func (h *Handler) Eligibility(c *gin.Context) {
	subject, ok := servermiddleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	res, err := h.svc.CheckEligibility(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}
