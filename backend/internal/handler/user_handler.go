package handler

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/gift"
	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/handler/quotaview"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// UserHandler handles user-related requests
type UserHandler struct {
	userService           *service.UserService
	authService           *service.AuthService
	emailService          *service.EmailService
	emailCache            service.EmailCache
	affiliateService      *service.AffiliateService
	giftEngine            *gift.Engine
	userPlatformQuotaRepo service.UserPlatformQuotaRepository
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(
	userService *service.UserService,
	authService *service.AuthService,
	emailService *service.EmailService,
	emailCache service.EmailCache,
	affiliateService *service.AffiliateService,
	giftEngine *gift.Engine,
	userPlatformQuotaRepo service.UserPlatformQuotaRepository,
) *UserHandler {
	return &UserHandler{
		userService:           userService,
		authService:           authService,
		emailService:          emailService,
		emailCache:            emailCache,
		affiliateService:      affiliateService,
		giftEngine:            giftEngine,
		userPlatformQuotaRepo: userPlatformQuotaRepo,
	}
}

// GetMyPlatformQuotas GET /user/platform-quotas
// 返回当前 JWT 用户的 platform quota 状态。
// D14: 对每条记录逐档判断窗口过期，过期档位 usage=0、window_resets_at=null（不写 DB）
func (h *UserHandler) GetMyPlatformQuotas(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.userPlatformQuotaRepo == nil {
		response.Success(c, map[string]any{"platform_quotas": []any{}})
		return
	}
	records, err := h.userPlatformQuotaRepo.ListByUser(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	now := time.Now().UTC()
	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, quotaview.LazyZeroQuotaForResponse(r, now, false))
	}
	response.Success(c, map[string]any{"platform_quotas": out})
}

// ChangePasswordRequest represents the change password request payload
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// UpdateProfileRequest represents the update profile request payload
type UpdateProfileRequest struct {
	Username               *string  `json:"username"`
	AvatarURL              *string  `json:"avatar_url"`
	BalanceNotifyEnabled   *bool    `json:"balance_notify_enabled"`
	BalanceNotifyThreshold *float64 `json:"balance_notify_threshold"`
}

type userProfileResponse struct {
	dto.User
	AvatarURL         string                                 `json:"avatar_url,omitempty"`
	AvatarSource      *userProfileSourceContext              `json:"avatar_source,omitempty"`
	UsernameSource    *userProfileSourceContext              `json:"username_source,omitempty"`
	DisplayNameSource *userProfileSourceContext              `json:"display_name_source,omitempty"`
	NicknameSource    *userProfileSourceContext              `json:"nickname_source,omitempty"`
	ProfileSources    map[string]*userProfileSourceContext   `json:"profile_sources,omitempty"`
	Identities        service.UserIdentitySummarySet         `json:"identities"`
	AuthBindings      map[string]service.UserIdentitySummary `json:"auth_bindings"`
	IdentityBindings  map[string]service.UserIdentitySummary `json:"identity_bindings"`
	EmailBound        bool                                   `json:"email_bound"`
	LinuxDoBound      bool                                   `json:"linuxdo_bound"`
	OIDCBound         bool                                   `json:"oidc_bound"`
	WeChatBound       bool                                   `json:"wechat_bound"`
	DingTalkBound     bool                                   `json:"dingtalk_bound"`
}

type userProfileSourceContext struct {
	Provider string `json:"provider,omitempty"`
	Source   string `json:"source,omitempty"`
}

// GetProfile handles getting user profile
// GET /api/v1/users/me
func (h *UserHandler) GetProfile(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	userData, err := h.userService.GetProfile(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, userData)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

// giftListItem 是 ListGifts 返回的单笔赠金 DTO（面向当前登录用户）。
// 单一 DTO 用显式 JSON tag 收口两种响应形态（plan.md §3.8/D8）：
//   - ID：gift id 恒为正，故 omitempty；分页行带正 id，legacy（Profile 卡）行 id=0 被省略。
//   - Pinned：不 omitempty，恒输出；分页行 true/false，legacy 行恒 false（无害）。
//   - IsGlobal：恒输出，前端据此在两个展示面统一渲染"全局 / 仅限分组"列。
//     严格由 group_id==nil 推导，不看 group_name（cx-s2 实现注）。
type giftListItem struct {
	ID            int64    `json:"id,omitempty"`
	Remaining     float64  `json:"remaining"`
	DeductionMode string   `json:"deduction_mode"`
	RatioRecharge *float64 `json:"ratio_recharge,omitempty"`
	// ExpiresAtUnixMs 为 nil 表示永不过期。用毫秒时间戳与前端 BindKey 赠金展示保持一致。
	ExpiresAtUnixMs *int64  `json:"expires_at_unix_ms,omitempty"`
	ExpiringSoon    bool    `json:"expiring_soon"`
	Source          string  `json:"source,omitempty"`
	SourceRef       string  `json:"source_ref,omitempty"`
	Amount          float64 `json:"amount,omitempty"`
	Status          string  `json:"status,omitempty"`
	CreatedAtUnixMs *int64  `json:"created_at_unix_ms,omitempty"`
	// 分组 / 置顶展示字段。
	GroupID   *int64 `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	IsGlobal  bool   `json:"is_global"`
	Pinned    bool   `json:"pinned"`
}

// giftListResponse 是分页模式的响应。
type giftListResponse struct {
	Items []giftListItem `json:"items"`
	Total int64          `json:"total"`
	Page  int            `json:"page"`
}

// ListGifts handles listing the current user's gift credits.
// GET /api/v1/user/gifts
// 无参数：返回 active 赠金列表（兼容旧行为，供 Profile 页简要展示）。
// 有 status 参数：分页返回赠金列表（含 source），供"我的赠金"页面。
func (h *UserHandler) ListGifts(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.giftEngine == nil {
		if c.Query("status") != "" {
			response.Success(c, giftListResponse{Items: []giftListItem{}, Total: 0, Page: 1})
		} else {
			response.Success(c, []giftListItem{})
		}
		return
	}

	statusParam := c.Query("status")

	// 分页模式：有 status 参数时使用 ListGiftsByUser
	if statusParam != "" {
		page := 1
		pageSize := 20
		if v := c.Query("page"); v != "" {
			if p, err := strconv.Atoi(v); err == nil && p > 0 {
				page = p
			}
		}
		if v := c.Query("page_size"); v != "" {
			if ps, err := strconv.Atoi(v); err == nil && ps > 0 && ps <= 100 {
				pageSize = ps
			}
		}

		var giftStatus gift.Status
		switch statusParam {
		case "active":
			giftStatus = gift.StatusActive
		case "expired":
			giftStatus = gift.StatusExpired
		case "exhausted":
			giftStatus = gift.StatusExhausted
		default:
			giftStatus = gift.Status(statusParam)
		}

		gifts, total, err := h.giftEngine.ListGiftsByUserExpiryAsc(c.Request.Context(), subject.UserID, giftStatus, page, pageSize)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}

		items := make([]giftListItem, 0, len(gifts))
		now := time.Now()
		for i := range gifts {
			g := gifts[i]
			// 语义修正：status='active' 但已自然过期（expirer 尚未 sweep）→ 对外展示为 expired
			displayStatus := string(g.Status)
			if g.Status == gift.StatusActive && g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
				displayStatus = string(gift.StatusExpired)
			}
			item := giftListItem{
				ID:            g.ID,
				Remaining:     g.Remaining,
				DeductionMode: string(g.Mode),
				RatioRecharge: g.RatioRecharge,
				Source:        string(g.Source),
				SourceRef:     derefStr(g.SourceRef),
				Amount:        g.Amount,
				Status:        displayStatus,
				GroupID:       g.GroupID,
				GroupName:     g.GroupName,
				IsGlobal:      g.GroupID == nil,
				Pinned:        g.Pinned,
			}
			if g.ExpiresAt != nil {
				ms := g.ExpiresAt.UnixMilli()
				item.ExpiresAtUnixMs = &ms
			}
			createdMs := g.CreatedAt.UnixMilli()
			item.CreatedAtUnixMs = &createdMs
			items = append(items, item)
		}
		response.Success(c, giftListResponse{Items: items, Total: total, Page: page})
		return
	}

	// 兼容旧行为：无参数时返回 active 赠金列表（Profile 展示用）
	gifts, err := h.giftEngine.ListActiveGiftsForDisplay(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	items := make([]giftListItem, 0, len(gifts))
	for i := range gifts {
		g := gifts[i]
		item := giftListItem{
			Remaining:     g.Remaining,
			DeductionMode: string(g.Mode),
			RatioRecharge: g.RatioRecharge,
			ExpiringSoon:  g.ExpiringSoon,
			GroupID:       g.GroupID,
			GroupName:     g.GroupName,
			IsGlobal:      g.GroupID == nil,
			// legacy（Profile 卡）分支无置顶按钮：id 省略、pinned 恒 false。
		}
		if g.ExpiresAt != nil {
			ms := g.ExpiresAt.UnixMilli()
			item.ExpiresAtUnixMs = &ms
		}
		items = append(items, item)
	}
	response.Success(c, items)
}

// PinGift 置顶当前用户的一笔赠金（allocator Stage 0 最先消费）。
// POST /api/v1/user/gifts/:id/pin
// 一人至多一条置顶；目标须属于本人、active、未过期、未耗尽。
func (h *UserHandler) PinGift(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.giftEngine == nil {
		response.BadRequest(c, "gift subsystem not available")
		return
	}
	giftID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || giftID <= 0 {
		response.BadRequest(c, "invalid gift id")
		return
	}
	if err := h.giftEngine.PinGift(c.Request.Context(), subject.UserID, giftID); err != nil {
		if errors.Is(err, gift.ErrGiftNotPinnable) {
			response.BadRequest(c, "gift cannot be pinned (not found, expired, or exhausted)")
			return
		}
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"pinned": true})
}

// UnpinGift 取消当前用户某笔赠金的置顶。
// DELETE /api/v1/user/gifts/:id/pin
// 幂等：未置顶/非本人视为成功。
func (h *UserHandler) UnpinGift(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.giftEngine == nil {
		response.BadRequest(c, "gift subsystem not available")
		return
	}
	giftID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || giftID <= 0 {
		response.BadRequest(c, "invalid gift id")
		return
	}
	if err := h.giftEngine.UnpinGift(c.Request.Context(), subject.UserID, giftID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"pinned": false})
}

// ChangePassword handles changing user password
// POST /api/v1/users/me/password
func (h *UserHandler) ChangePassword(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	svcReq := service.ChangePasswordRequest{
		CurrentPassword: req.OldPassword,
		NewPassword:     req.NewPassword,
	}
	err := h.userService.ChangePassword(c.Request.Context(), subject.UserID, svcReq)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Password changed successfully"})
}

// UpdateProfile handles updating user profile
// PUT /api/v1/users/me
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	svcReq := service.UpdateProfileRequest{
		Username:               req.Username,
		AvatarURL:              req.AvatarURL,
		BalanceNotifyEnabled:   req.BalanceNotifyEnabled,
		BalanceNotifyThreshold: req.BalanceNotifyThreshold,
	}
	updatedUser, err := h.userService.UpdateProfile(c.Request.Context(), subject.UserID, svcReq)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, updatedUser)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

// GetAffiliate returns the current user's affiliate details.
// GET /api/v1/user/aff
func (h *UserHandler) GetAffiliate(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	detail, err := h.affiliateService.GetAffiliateDetail(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, detail)
}

// TransferAffiliateQuota transfers all available affiliate quota into current balance.
// POST /api/v1/user/aff/transfer
func (h *UserHandler) TransferAffiliateQuota(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	transferred, balance, err := h.affiliateService.TransferAffiliateQuota(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{
		"transferred_quota": transferred,
		"balance":           balance,
	})
}

type StartIdentityBindingRequest struct {
	Provider   string `json:"provider" binding:"required"`
	RedirectTo string `json:"redirect_to"`
}

type BindEmailIdentityRequest struct {
	Email      string `json:"email" binding:"required,email"`
	VerifyCode string `json:"verify_code" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type SendEmailBindingCodeRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// StartIdentityBinding returns the backend authorize URL for starting a third-party identity bind flow.
// POST /api/v1/user/auth-identities/bind/start
func (h *UserHandler) StartIdentityBinding(c *gin.Context) {
	if _, ok := middleware2.GetAuthSubjectFromContext(c); !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req StartIdentityBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	result, err := h.userService.PrepareIdentityBindingStart(c.Request.Context(), service.StartUserIdentityBindingRequest{
		Provider:   req.Provider,
		RedirectTo: req.RedirectTo,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, result)
}

// BindEmailIdentity verifies and binds a local email identity for the current user.
// POST /api/v1/user/account-bindings/email
func (h *UserHandler) BindEmailIdentity(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.authService == nil {
		response.InternalError(c, "Auth service not configured")
		return
	}

	var req BindEmailIdentityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	updatedUser, err := h.authService.BindEmailIdentity(
		c.Request.Context(),
		subject.UserID,
		req.Email,
		req.VerifyCode,
		req.Password,
	)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, updatedUser)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

// UnbindIdentity removes a third-party sign-in provider from the current user.
// DELETE /api/v1/user/account-bindings/:provider
func (h *UserHandler) UnbindIdentity(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	updatedUser, unbound, err := h.userService.UnbindUserAuthProviderWithResult(
		c.Request.Context(),
		subject.UserID,
		c.Param("provider"),
	)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if unbound && h.authService != nil {
		if err := h.authService.RevokeAllUserTokens(c.Request.Context(), subject.UserID); err != nil {
			response.ErrorFrom(c, err)
			return
		}
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, updatedUser)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

// SendEmailBindingCode sends a verification code for the current user's email binding flow.
// POST /api/v1/user/account-bindings/email/send-code
func (h *UserHandler) SendEmailBindingCode(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.authService == nil {
		response.InternalError(c, "Auth service not configured")
		return
	}

	var req SendEmailBindingCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	if err := h.authService.SendEmailIdentityBindCode(c.Request.Context(), subject.UserID, req.Email, c.GetHeader("Accept-Language")); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Verification code sent successfully"})
}

// SendNotifyEmailCodeRequest represents the request to send notify email verification code
type SendNotifyEmailCodeRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// SendNotifyEmailCode sends verification code to extra notification email
// POST /api/v1/user/notify-email/send-code
func (h *UserHandler) SendNotifyEmailCode(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req SendNotifyEmailCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	err := h.userService.SendNotifyEmailCode(c.Request.Context(), subject.UserID, req.Email, h.emailService, h.emailCache, c.GetHeader("Accept-Language"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Verification code sent successfully"})
}

// VerifyNotifyEmailRequest represents the request to verify and add notify email
type VerifyNotifyEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required,len=6"`
}

// VerifyNotifyEmail verifies code and adds email to notification list
// POST /api/v1/user/notify-email/verify
func (h *UserHandler) VerifyNotifyEmail(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req VerifyNotifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	err := h.userService.VerifyAndAddNotifyEmail(c.Request.Context(), subject.UserID, req.Email, req.Code, h.emailCache)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	// Return updated user
	updatedUser, err := h.userService.GetByID(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, updatedUser)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

// RemoveNotifyEmailRequest represents the request to remove a notify email
type RemoveNotifyEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// RemoveNotifyEmail removes email from notification list
// DELETE /api/v1/user/notify-email
func (h *UserHandler) RemoveNotifyEmail(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req RemoveNotifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	err := h.userService.RemoveNotifyEmail(c.Request.Context(), subject.UserID, req.Email)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	// Return updated user
	updatedUser, err := h.userService.GetByID(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, updatedUser)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

// ToggleNotifyEmailRequest represents the request to toggle a notify email's disabled state
type ToggleNotifyEmailRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Disabled bool   `json:"disabled"`
}

// ToggleNotifyEmail toggles the disabled state of a notification email
// PUT /api/v1/user/notify-email/toggle
func (h *UserHandler) ToggleNotifyEmail(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}

	var req ToggleNotifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	err := h.userService.ToggleNotifyEmail(c.Request.Context(), subject.UserID, req.Email, req.Disabled)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	updatedUser, err := h.userService.GetByID(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	profileResp, err := h.buildUserProfileResponse(c.Request.Context(), subject.UserID, updatedUser)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, profileResp)
}

func (h *UserHandler) buildUserProfileResponse(ctx context.Context, userID int64, user *service.User) (userProfileResponse, error) {
	identities, err := h.userService.GetProfileIdentitySummaries(ctx, userID, user)
	if err != nil {
		return userProfileResponse{}, err
	}
	resp := userProfileResponseFromService(user, identities)
	applyGiftBalanceBreakdown(ctx, h.giftEngine, userID, &resp)
	return resp, nil
}

// applyGiftBalanceBreakdown 把赠金拆分注入 userProfileResponse。
// gift_balance = Σ(active gifts.remaining)；recharge_balance = balance - gift_balance；
// gift_expiring_soon = 120h 内即将过期的赠金额。失败时静默降级，不阻塞 profile 返回。
// 同时供 AuthHandler.GetCurrentUser 复用，避免 /auth/me 与 /user/profile 行为不一致。
func applyGiftBalanceBreakdown(ctx context.Context, engine *gift.Engine, userID int64, resp *userProfileResponse) {
	if engine == nil || resp == nil {
		return
	}
	giftBal, expiringSoon, err := engine.GetGiftBalanceBreakdown(ctx, userID)
	if err != nil {
		return
	}
	resp.GiftBalance = giftBal
	resp.RechargeBalance = resp.Balance - giftBal
	resp.GiftExpiringSoon = expiringSoon
}

func userProfileResponseFromService(user *service.User, identities service.UserIdentitySummarySet) userProfileResponse {
	base := dto.UserFromService(user)
	if base == nil {
		return userProfileResponse{}
	}
	bindings := userProfileBindingMap(identities)
	profileSources, avatarSource, usernameSource := inferUserProfileSources(user, identities)
	return userProfileResponse{
		User:              *base,
		AvatarURL:         user.AvatarURL,
		AvatarSource:      avatarSource,
		UsernameSource:    usernameSource,
		DisplayNameSource: usernameSource,
		NicknameSource:    usernameSource,
		ProfileSources:    profileSources,
		Identities:        identities,
		AuthBindings:      bindings,
		IdentityBindings:  bindings,
		EmailBound:        identities.Email.Bound,
		LinuxDoBound:      identities.LinuxDo.Bound,
		OIDCBound:         identities.OIDC.Bound,
		WeChatBound:       identities.WeChat.Bound,
		DingTalkBound:     identities.DingTalk.Bound,
	}
}

func userProfileBindingMap(identities service.UserIdentitySummarySet) map[string]service.UserIdentitySummary {
	return map[string]service.UserIdentitySummary{
		"email":    identities.Email,
		"linuxdo":  identities.LinuxDo,
		"oidc":     identities.OIDC,
		"wechat":   identities.WeChat,
		"dingtalk": identities.DingTalk,
	}
}

func inferUserProfileSources(user *service.User, identities service.UserIdentitySummarySet) (
	map[string]*userProfileSourceContext,
	*userProfileSourceContext,
	*userProfileSourceContext,
) {
	if user == nil {
		return nil, nil, nil
	}

	thirdParty := thirdPartyIdentityProviders(identities)
	var avatarSource *userProfileSourceContext
	avatarValue := strings.TrimSpace(user.AvatarURL)
	for _, summary := range thirdParty {
		if avatarValue != "" && avatarValue == strings.TrimSpace(summary.AvatarURL) {
			avatarSource = buildUserProfileSourceContext(summary.Provider)
			break
		}
	}

	usernameValue := strings.TrimSpace(user.Username)
	var usernameSource *userProfileSourceContext
	for _, summary := range thirdParty {
		if usernameValue != "" && usernameValue == strings.TrimSpace(summary.DisplayName) {
			usernameSource = buildUserProfileSourceContext(summary.Provider)
			break
		}
	}

	profileSources := map[string]*userProfileSourceContext{}
	if avatarSource != nil {
		profileSources["avatar"] = avatarSource
	}
	if usernameSource != nil {
		profileSources["username"] = usernameSource
		profileSources["display_name"] = usernameSource
		profileSources["nickname"] = usernameSource
	}
	if len(profileSources) == 0 {
		return nil, avatarSource, usernameSource
	}
	return profileSources, avatarSource, usernameSource
}

func thirdPartyIdentityProviders(identities service.UserIdentitySummarySet) []service.UserIdentitySummary {
	out := make([]service.UserIdentitySummary, 0, 3)
	for _, summary := range []service.UserIdentitySummary{identities.LinuxDo, identities.OIDC, identities.WeChat, identities.DingTalk} {
		if summary.Bound {
			out = append(out, summary)
		}
	}
	return out
}

func buildUserProfileSourceContext(provider string) *userProfileSourceContext {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return nil
	}
	return &userProfileSourceContext{
		Provider: provider,
		Source:   provider,
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
