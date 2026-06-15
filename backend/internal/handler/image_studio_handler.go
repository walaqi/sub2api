package handler

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// ImageStudioHandler 处理 image-studio 子应用的入口票据签发。
type ImageStudioHandler struct {
	imageStudioService *service.ImageStudioService
}

// NewImageStudioHandler 构造 handler。
func NewImageStudioHandler(imageStudioService *service.ImageStudioService) *ImageStudioHandler {
	return &ImageStudioHandler{imageStudioService: imageStudioService}
}

// GetTicket 为当前登录用户签发一张入口票据。
// GET /api/v1/image-studio/ticket
func (h *ImageStudioHandler) GetTicket(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	ticket, err := h.imageStudioService.MintTicket(subject.UserID)
	if err != nil {
		if err == service.ErrImageStudioDisabled {
			response.Error(c, http.StatusNotFound, "Image studio is not enabled")
			return
		}
		response.InternalError(c, "Failed to issue image studio ticket")
		return
	}

	response.Success(c, ticket)
}
