package handler

import (
	"net/http"
	"strconv"
	"strings"

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

// ListImageKeys 列出指定用户「能出图」的 key 候选（不含明文）。
// GET /internal/cred/keys?uid=<userID>
//
// 这是 service-to-service 内部端点（由 InternalSecretMiddleware 保护），
// 供 image-studio 后端渲染 key 选择器。uid 由调用方（image-studio）从入口票据的
// sub claim 解析后透传，不依赖会话身份。
func (h *ImageStudioHandler) ListImageKeys(c *gin.Context) {
	userID, ok := parseUIDQuery(c)
	if !ok {
		return
	}

	list, err := h.imageStudioService.ListImageCapableKeys(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "Failed to list image-capable keys")
		return
	}
	response.Success(c, list)
}

// ResolveImageCred 按 uid + key_id 返回真正凭证（含明文 key）。
// GET /internal/cred?uid=<userID>&key_id=<id>
//
// service-to-service 内部端点。返回前 service 层会再校验归属/额度/出图条件，
// 越权（uid 与 key_id 不匹配）会得到 ErrNoImageCapableKey → 404。
func (h *ImageStudioHandler) ResolveImageCred(c *gin.Context) {
	userID, ok := parseUIDQuery(c)
	if !ok {
		return
	}
	keyIDStr := strings.TrimSpace(c.Query("key_id"))
	keyID, err := strconv.ParseInt(keyIDStr, 10, 64)
	if err != nil || keyID <= 0 {
		response.Error(c, http.StatusBadRequest, "Invalid key_id")
		return
	}

	cred, err := h.imageStudioService.ResolveImageCred(c.Request.Context(), userID, keyID)
	if err != nil {
		if err == service.ErrNoImageCapableKey {
			response.Error(c, http.StatusNotFound, "No image-capable key for the given selection")
			return
		}
		response.InternalError(c, "Failed to resolve image credential")
		return
	}
	response.Success(c, cred)
}

// parseUIDQuery 解析 uid 查询参数，失败时已写好响应并返回 false。
func parseUIDQuery(c *gin.Context) (int64, bool) {
	uidStr := strings.TrimSpace(c.Query("uid"))
	userID, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil || userID <= 0 {
		response.Error(c, http.StatusBadRequest, "Invalid uid")
		return 0, false
	}
	return userID, true
}
