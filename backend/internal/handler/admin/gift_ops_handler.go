// Package admin · gift_ops_handler.go
//
// 运维 API 入口：外部独立 ops 系统通过 admin JWT 调用，覆盖：
//
//	A. 表 A 配置管理（绑 key 赠金参数）
//	B. 赠金账本运维（任意 mode 发放 / 列表 / 撤销 / 充值池增额）
//	C. 用户余额拆分查询
//
// 鉴权由现有 admin_auth 中间件把关，本 handler 不做额外鉴权。
package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/bindkeygiftsetting"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/Wei-Shaw/sub2api/internal/gift"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// GiftOpsHandler 提供赠金子系统的运维 API。
type GiftOpsHandler struct {
	engine    *gift.Engine
	userSvc   *service.UserService
	entClient *dbent.Client
}

// NewGiftOpsHandler 构造运维 handler。
func NewGiftOpsHandler(engine *gift.Engine, userSvc *service.UserService, entClient *dbent.Client) *GiftOpsHandler {
	return &GiftOpsHandler{engine: engine, userSvc: userSvc, entClient: entClient}
}

// =========================================================================
// A. 表 A 配置：bind_key_gift_settings
// =========================================================================

// BindKeyGiftSettingPayload 是 upsert 表 A 的请求体。
type BindKeyGiftSettingPayload struct {
	APIKeyID         int64    `json:"api_key_id" binding:"required"`
	DeductionMode    string   `json:"deduction_mode" binding:"required"`
	RatioRecharge    *float64 `json:"ratio_recharge,omitempty"`
	ExpiresAfterDays *int     `json:"expires_after_days,omitempty"`
}

// BindKeyGiftSettingResponse 是表 A 的响应 DTO。
type BindKeyGiftSettingResponse struct {
	ID               int64                 `json:"id"`
	APIKeyID         int64                 `json:"api_key_id"`
	DeductionMode    string                `json:"deduction_mode"`
	RatioRecharge    *float64              `json:"ratio_recharge,omitempty"`
	ExpiresAfterDays *int                  `json:"expires_after_days,omitempty"`
	Config           *domain.BindKeyConfig `json:"config,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
}

// UpsertBindKeyGiftSetting POST /api/v1/admin/ops/bind-key-gifts
// 同 api_key_id 已存在则覆盖，不存在则创建。
func (h *GiftOpsHandler) UpsertBindKeyGiftSetting(c *gin.Context) {
	var req BindKeyGiftSettingPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if err := validateBindKeyGiftPayload(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	ctx := c.Request.Context()
	existing, err := h.entClient.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(req.APIKeyID)).
		Only(ctx)
	var saved *dbent.BindKeyGiftSetting
	if err != nil && !dbent.IsNotFound(err) {
		response.InternalError(c, "query setting failed: "+err.Error())
		return
	}
	if dbent.IsNotFound(err) {
		create := h.entClient.BindKeyGiftSetting.Create().
			SetAPIKeyID(req.APIKeyID).
			SetDeductionMode(req.DeductionMode)
		if req.RatioRecharge != nil {
			create = create.SetRatioRecharge(*req.RatioRecharge)
		}
		if req.ExpiresAfterDays != nil {
			create = create.SetExpiresAfterDays(*req.ExpiresAfterDays)
		}
		saved, err = create.Save(ctx)
	} else {
		update := existing.Update().SetDeductionMode(req.DeductionMode)
		if req.RatioRecharge != nil {
			update = update.SetRatioRecharge(*req.RatioRecharge)
		} else {
			update = update.ClearRatioRecharge()
		}
		if req.ExpiresAfterDays != nil {
			update = update.SetExpiresAfterDays(*req.ExpiresAfterDays)
		} else {
			update = update.ClearExpiresAfterDays()
		}
		saved, err = update.Save(ctx)
	}
	if err != nil {
		response.InternalError(c, "save setting failed: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": bindKeyGiftSettingDTO(saved)})
}

// GetBindKeyGiftSetting GET /api/v1/admin/ops/bind-key-gifts/:api_key_id
func (h *GiftOpsHandler) GetBindKeyGiftSetting(c *gin.Context) {
	apiKeyID, err := strconv.ParseInt(c.Param("api_key_id"), 10, 64)
	if err != nil || apiKeyID <= 0 {
		response.BadRequest(c, "invalid api_key_id")
		return
	}
	row, err := h.entClient.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(apiKeyID)).
		Only(c.Request.Context())
	if err != nil {
		if dbent.IsNotFound(err) {
			response.NotFound(c, "setting not found")
			return
		}
		response.InternalError(c, "query failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": bindKeyGiftSettingDTO(row)})
}

// ListBindKeyGiftSettings GET /api/v1/admin/ops/bind-key-gifts?page=1&page_size=50
func (h *GiftOpsHandler) ListBindKeyGiftSettings(c *gin.Context) {
	page, pageSize := parsePagination(c, 50, 200)
	ctx := c.Request.Context()
	total, err := h.entClient.BindKeyGiftSetting.Query().Count(ctx)
	if err != nil {
		response.InternalError(c, "count failed: "+err.Error())
		return
	}
	rows, err := h.entClient.BindKeyGiftSetting.Query().
		Order(dbent.Desc(bindkeygiftsetting.FieldID)).
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		All(ctx)
	if err != nil {
		response.InternalError(c, "query failed: "+err.Error())
		return
	}
	items := make([]BindKeyGiftSettingResponse, 0, len(rows))
	for _, r := range rows {
		items = append(items, bindKeyGiftSettingDTO(r))
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  items,
		"total": total,
		"page":  page, "page_size": pageSize,
	})
}

// DeleteBindKeyGiftSetting DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id
func (h *GiftOpsHandler) DeleteBindKeyGiftSetting(c *gin.Context) {
	apiKeyID, err := strconv.ParseInt(c.Param("api_key_id"), 10, 64)
	if err != nil || apiKeyID <= 0 {
		response.BadRequest(c, "invalid api_key_id")
		return
	}
	n, err := h.entClient.BindKeyGiftSetting.Delete().
		Where(bindkeygiftsetting.APIKeyIDEQ(apiKeyID)).
		Exec(c.Request.Context())
	if err != nil {
		response.InternalError(c, "delete failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": n})
}

// RegistrationWindowPayload 是设置 per-key 注册时间窗口的请求体。
type RegistrationWindowPayload struct {
	Enabled bool `json:"enabled"`
	MinDays int  `json:"min_days"`
	MaxDays int  `json:"max_days"`
}

// SetBindKeyRegistrationWindow PUT /api/v1/admin/ops/bind-key-gifts/:api_key_id/registration-window
//
// 设置某条池 key 的注册时间窗口（存表 A 的 config.registration_window）。
// 与赠金字段独立：只写 config，不动 deduction_mode/ratio_recharge/expires_after_days。
// 行不存在时创建一条仅含窗口的占位行（deduction_mode=priority，赠金语义等价于"无行"）。
func (h *GiftOpsHandler) SetBindKeyRegistrationWindow(c *gin.Context) {
	apiKeyID, err := strconv.ParseInt(c.Param("api_key_id"), 10, 64)
	if err != nil || apiKeyID <= 0 {
		response.BadRequest(c, "invalid api_key_id")
		return
	}
	var req RegistrationWindowPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.MinDays < 0 {
		response.BadRequest(c, "min_days must be >= 0")
		return
	}
	if req.MaxDays < 1 {
		response.BadRequest(c, "max_days must be >= 1")
		return
	}
	if req.MaxDays < req.MinDays {
		response.BadRequest(c, "max_days must be >= min_days")
		return
	}

	ctx := c.Request.Context()
	window := &domain.BindKeyRegistrationWindow{
		Enabled: req.Enabled,
		MinDays: req.MinDays,
		MaxDays: req.MaxDays,
	}

	existing, err := h.entClient.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(apiKeyID)).
		Only(ctx)
	if err != nil && !dbent.IsNotFound(err) {
		response.InternalError(c, "query setting failed: "+err.Error())
		return
	}

	var saved *dbent.BindKeyGiftSetting
	if dbent.IsNotFound(err) {
		cfg := &domain.BindKeyConfig{RegistrationWindow: window}
		saved, err = h.entClient.BindKeyGiftSetting.Create().
			SetAPIKeyID(apiKeyID).
			SetDeductionMode(string(gift.DeductionModePriority)).
			SetConfig(cfg).
			Save(ctx)
	} else {
		cfg := mergeRegistrationWindow(existing.Config, window)
		saved, err = existing.Update().SetConfig(cfg).Save(ctx)
	}
	if err != nil {
		response.InternalError(c, "save registration window failed: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": bindKeyGiftSettingDTO(saved)})
}

// DeleteBindKeyRegistrationWindow DELETE /api/v1/admin/ops/bind-key-gifts/:api_key_id/registration-window
//
// 清除某条池 key 的注册时间窗口，保留其赠金配置。行不存在时为 no-op。
func (h *GiftOpsHandler) DeleteBindKeyRegistrationWindow(c *gin.Context) {
	apiKeyID, err := strconv.ParseInt(c.Param("api_key_id"), 10, 64)
	if err != nil || apiKeyID <= 0 {
		response.BadRequest(c, "invalid api_key_id")
		return
	}
	ctx := c.Request.Context()
	existing, err := h.entClient.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(apiKeyID)).
		Only(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			c.JSON(http.StatusOK, gin.H{"deleted": 0})
			return
		}
		response.InternalError(c, "query setting failed: "+err.Error())
		return
	}
	if existing.Config == nil || existing.Config.RegistrationWindow == nil {
		c.JSON(http.StatusOK, gin.H{"deleted": 0})
		return
	}
	cfg := mergeRegistrationWindow(existing.Config, nil)
	if _, err := existing.Update().SetConfig(cfg).Save(ctx); err != nil {
		response.InternalError(c, "clear registration window failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": 1})
}

// mergeRegistrationWindow 返回一份新的 config，把 window 写入/清除（nil=清除），
// 保留其它扩展配置字段不变。
func mergeRegistrationWindow(cur *domain.BindKeyConfig, window *domain.BindKeyRegistrationWindow) *domain.BindKeyConfig {
	out := &domain.BindKeyConfig{}
	if cur != nil {
		*out = *cur
	}
	out.RegistrationWindow = window
	return out
}

// GrantGiftPayload 给指定用户发任意 mode 赠金。
type GrantGiftPayload struct {
	UserID        int64      `json:"user_id" binding:"required"`
	Amount        float64    `json:"amount" binding:"required"`
	DeductionMode string     `json:"deduction_mode" binding:"required"`
	RatioRecharge *float64   `json:"ratio_recharge,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Source        string     `json:"source,omitempty"` // 默认 "manual"
	SourceRef     *string    `json:"source_ref,omitempty"`
}

// GrantGift POST /api/v1/admin/ops/gifts/grant
func (h *GiftOpsHandler) GrantGift(c *gin.Context) {
	var req GrantGiftPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.Amount <= 0 {
		response.BadRequest(c, "amount must be > 0")
		return
	}
	mode := gift.DeductionMode(req.DeductionMode)
	switch mode {
	case gift.DeductionModePriority:
		if req.RatioRecharge != nil {
			response.BadRequest(c, "priority mode must not include ratio_recharge")
			return
		}
	case gift.DeductionModeRatio:
		if req.RatioRecharge == nil || *req.RatioRecharge <= 0 {
			response.BadRequest(c, "ratio mode requires positive ratio_recharge")
			return
		}
	default:
		response.BadRequest(c, "deduction_mode must be priority or ratio")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		response.BadRequest(c, "expires_at must be in the future")
		return
	}
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "manual"
	}

	out, err := h.engine.Grant(c.Request.Context(), gift.GrantInput{
		UserID:        req.UserID,
		Amount:        req.Amount,
		Mode:          mode,
		RatioRecharge: req.RatioRecharge,
		ExpiresAt:     req.ExpiresAt,
		Source:        gift.Source(source),
		SourceRef:     req.SourceRef,
	})
	if err != nil {
		response.InternalError(c, "grant failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": userGiftDTO(out)})
}

// ListGifts GET /api/v1/admin/ops/gifts?user_id=X&status=&page=&page_size=
func (h *GiftOpsHandler) ListGifts(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Query("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		response.BadRequest(c, "invalid user_id")
		return
	}
	status := gift.Status(strings.TrimSpace(c.Query("status")))
	page, pageSize := parsePagination(c, 50, 200)
	gifts, total, err := h.engine.ListGiftsByUser(c.Request.Context(), userID, status, page, pageSize)
	if err != nil {
		response.InternalError(c, "list failed: "+err.Error())
		return
	}
	items := make([]any, 0, len(gifts))
	for i := range gifts {
		items = append(items, userGiftDTO(&gifts[i]))
	}
	c.JSON(http.StatusOK, gin.H{
		"data": items, "total": total, "page": page, "page_size": pageSize,
	})
}

// GetGift GET /api/v1/admin/ops/gifts/:gift_id
func (h *GiftOpsHandler) GetGift(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("gift_id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "invalid gift_id")
		return
	}
	g, err := h.engine.GetGiftByID(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": userGiftDTO(g)})
}

// RevokeGiftPayload 撤销请求体。
type RevokeGiftPayload struct {
	Reason string `json:"reason,omitempty"`
}

// RevokeGift POST /api/v1/admin/ops/gifts/:gift_id/revoke
// 仅 active 可撤销；非 active 返回 409 Conflict。
func (h *GiftOpsHandler) RevokeGift(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("gift_id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "invalid gift_id")
		return
	}
	var req RevokeGiftPayload
	_ = c.ShouldBindJSON(&req) // body 可选
	if err := h.engine.RevokeGift(c.Request.Context(), id, req.Reason); err != nil {
		if errors.Is(err, gift.ErrGiftNotRevocable) {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		response.InternalError(c, "revoke failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked_id": id})
}

// RechargeUserPayload 给充值池增额（amount 可正可负，由运维负责合理性）。
type RechargeUserPayload struct {
	Amount float64 `json:"amount" binding:"required"`
	Notes  string  `json:"notes,omitempty"`
}

// RechargeUser POST /api/v1/admin/ops/gifts/users/:user_id/recharge
// 直接给 users.balance 增减；正数同步累加 total_recharged（视为真实充值），
// 负数仅扣 balance、不动 total_recharged，避免污染累计充值统计。
func (h *GiftOpsHandler) RechargeUser(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		response.BadRequest(c, "invalid user_id")
		return
	}
	var req RechargeUserPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.Amount == 0 {
		response.BadRequest(c, "amount must not be zero")
		return
	}

	ctx := c.Request.Context()
	// 复用 UserService.UpdateBalance 风格：正数 +balance + total_recharged；负数仅 -balance。
	// 当前 admin user_handler 已有等价逻辑，这里直接走更底层 UserService 入口。
	if err := h.userSvc.UpdateBalance(ctx, userID, req.Amount); err != nil {
		response.InternalError(c, "update balance failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": userID, "delta": req.Amount})
}

// =========================================================================
// C. 用户余额拆分查询
// =========================================================================

// GetUserBalance GET /api/v1/admin/ops/users/:user_id/balance
// 返回 total_balance / gift_balance / recharge_balance / gift_expiring_soon。
func (h *GiftOpsHandler) GetUserBalance(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		response.BadRequest(c, "invalid user_id")
		return
	}
	ctx := c.Request.Context()
	user, err := h.userSvc.GetByID(ctx, userID)
	if err != nil {
		response.NotFound(c, err.Error())
		return
	}
	giftBal, expiringSoon, err := h.engine.GetGiftBalanceBreakdown(ctx, userID)
	if err != nil {
		response.InternalError(c, "balance breakdown failed: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":            userID,
		"total_balance":      user.Balance,
		"gift_balance":       giftBal,
		"recharge_balance":   user.Balance - giftBal,
		"gift_expiring_soon": expiringSoon,
		"total_recharged":    user.TotalRecharged,
	})
}

// =========================================================================
// helpers
// =========================================================================

func validateBindKeyGiftPayload(req *BindKeyGiftSettingPayload) error {
	if req.APIKeyID <= 0 {
		return errors.New("api_key_id must be positive")
	}
	mode := gift.DeductionMode(req.DeductionMode)
	switch mode {
	case gift.DeductionModePriority:
		if req.RatioRecharge != nil {
			return errors.New("priority mode must not include ratio_recharge")
		}
	case gift.DeductionModeRatio:
		if req.RatioRecharge == nil || *req.RatioRecharge <= 0 {
			return errors.New("ratio mode requires positive ratio_recharge")
		}
	default:
		return errors.New("deduction_mode must be priority or ratio")
	}
	if req.ExpiresAfterDays != nil && *req.ExpiresAfterDays <= 0 {
		return errors.New("expires_after_days must be positive when provided")
	}
	return nil
}

func bindKeyGiftSettingDTO(r *dbent.BindKeyGiftSetting) BindKeyGiftSettingResponse {
	if r == nil {
		return BindKeyGiftSettingResponse{}
	}
	out := BindKeyGiftSettingResponse{
		ID:            r.ID,
		APIKeyID:      r.APIKeyID,
		DeductionMode: r.DeductionMode,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
	if r.RatioRecharge != nil {
		v := *r.RatioRecharge
		out.RatioRecharge = &v
	}
	if r.ExpiresAfterDays != nil {
		v := *r.ExpiresAfterDays
		out.ExpiresAfterDays = &v
	}
	out.Config = r.Config
	return out
}

func userGiftDTO(g *gift.UserGift) any {
	if g == nil {
		return nil
	}
	return gin.H{
		"id":             g.ID,
		"user_id":        g.UserID,
		"amount":         g.Amount,
		"remaining":      g.Remaining,
		"deduction_mode": string(g.Mode),
		"ratio_recharge": g.RatioRecharge,
		"expires_at":     g.ExpiresAt,
		"source":         string(g.Source),
		"source_ref":     g.SourceRef,
		"status":         string(g.Status),
		"created_at":     g.CreatedAt,
		"updated_at":     g.UpdatedAt,
	}
}

// parsePagination 读取 ?page=&page_size= 并加上下限保护。
func parsePagination(c *gin.Context, defaultSize, maxSize int) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	if page <= 0 {
		page = 1
	}
	size, _ := strconv.Atoi(c.Query("page_size"))
	if size <= 0 {
		size = defaultSize
	}
	if size > maxSize {
		size = maxSize
	}
	return page, size
}

// 占位以避免 unused import 报错（context 在 handler 签名外没用到）。
var _ = context.Background
