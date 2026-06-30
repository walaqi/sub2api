package activity

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

type signupRequest struct {
	ReceiveEmail string `json:"receive_email" binding:"required"`
}

type createEventRequest struct {
	Name        string     `json:"name" binding:"required"`
	Description string     `json:"description" binding:"required"`
	StartsAt    *time.Time `json:"starts_at"`
	EndsAt      *time.Time `json:"ends_at"`
}

type updateEventRequest struct {
	Name        string          `json:"name" binding:"required"`
	Description string          `json:"description" binding:"required"`
	Status      string          `json:"status"`
	StartsAt    *time.Time      `json:"starts_at"`
	EndsAt      json.RawMessage `json:"ends_at"`
}

func (h *Handler) ListActiveEvents(c *gin.Context) {
	subject, ok := servermiddleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "user not authenticated")
		return
	}

	events, err := h.svc.ListActiveEvents(c.Request.Context(), subject.UserID)
	if err != nil {
		response.InternalError(c, "failed to list activity events")
		return
	}
	response.Success(c, events)
}

func (h *Handler) Signup(c *gin.Context) {
	subject, ok := servermiddleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "user not authenticated")
		return
	}

	activityID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}

	var req signupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	signup, err := h.svc.Signup(c.Request.Context(), activityID, subject.UserID, req.ReceiveEmail)
	if errors.Is(err, ErrInvalidInput) {
		response.BadRequest(c, "invalid receive_email")
		return
	}
	if errors.Is(err, ErrEventNotAvailable) {
		response.Error(c, http.StatusConflict, "activity event is not available")
		return
	}
	if err != nil {
		response.InternalError(c, "failed to submit activity signup")
		return
	}
	response.Success(c, signup)
}

func (h *Handler) CreateEvent(c *gin.Context) {
	var req createEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	id, err := h.svc.CreateEvent(c.Request.Context(), CreateEventInput(req))
	if errors.Is(err, ErrInvalidInput) {
		response.BadRequest(c, "invalid activity event")
		return
	}
	if err != nil {
		response.InternalError(c, "failed to create activity event")
		return
	}
	response.Created(c, gin.H{"id": id})
}

func (h *Handler) UpdateEvent(c *gin.Context) {
	activityID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}

	var req updateEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}

	endsAt, clearEndsAt, ok := parseOptionalTimeField(c, req.EndsAt, "ends_at")
	if !ok {
		return
	}

	event, err := h.svc.UpdateEvent(c.Request.Context(), UpdateEventInput{
		ID:          activityID,
		Name:        req.Name,
		Description: req.Description,
		Status:      req.Status,
		StartsAt:    req.StartsAt,
		EndsAt:      endsAt,
		ClearEndsAt: clearEndsAt,
	})
	if errors.Is(err, ErrInvalidInput) {
		response.BadRequest(c, "invalid activity event")
		return
	}
	if errors.Is(err, ErrEventNotAvailable) {
		response.NotFound(c, "activity event not found")
		return
	}
	if err != nil {
		response.InternalError(c, "failed to update activity event")
		return
	}
	response.Success(c, event)
}

func (h *Handler) ListSignups(c *gin.Context) {
	activityID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}

	signups, err := h.svc.ListSignups(c.Request.Context(), activityID)
	if err != nil {
		response.InternalError(c, "failed to list activity signups")
		return
	}
	response.Success(c, signups)
}

func parseIDParam(c *gin.Context, name string) (int64, bool) {
	id, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "invalid "+name)
		return 0, false
	}
	return id, true
}

func parseOptionalTimeField(c *gin.Context, raw json.RawMessage, name string) (*time.Time, bool, bool) {
	if len(raw) == 0 {
		return nil, false, true
	}
	if string(raw) == "null" {
		return nil, true, true
	}
	var parsed time.Time
	if err := json.Unmarshal(raw, &parsed); err != nil {
		response.BadRequest(c, "invalid "+name)
		return nil, false, false
	}
	return &parsed, false, true
}
