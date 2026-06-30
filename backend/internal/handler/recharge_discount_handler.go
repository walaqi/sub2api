package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// RechargeDiscountHandler handles user-facing recharge discount queries.
type RechargeDiscountHandler struct {
	repo service.RechargeDiscountRepo
}

// NewRechargeDiscountHandler creates a new RechargeDiscountHandler.
func NewRechargeDiscountHandler(repo service.RechargeDiscountRepo) *RechargeDiscountHandler {
	return &RechargeDiscountHandler{repo: repo}
}

// GetMyActiveDiscount GET /api/v1/user/recharge-discount
// Returns the user's best active recharge discount (if any) for display on payment page.
func (h *RechargeDiscountHandler) GetMyActiveDiscount(c *gin.Context) {
	if h.repo == nil {
		response.Success(c, nil)
		return
	}

	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "not authenticated")
		return
	}

	discounts, err := h.repo.QueryActiveDiscountsReadOnly(c.Request.Context(), subject.UserID)
	if err != nil {
		response.InternalError(c, "query active discount failed: "+err.Error())
		return
	}
	if len(discounts) == 0 {
		response.Success(c, nil)
		return
	}

	// Return the best one (already sorted by rate DESC)
	best := discounts[0]
	remaining := best.MaxDiscountableAmount - best.TotalDiscounted

	type discountDTO struct {
		ID                    int64    `json:"id"`
		Source                string   `json:"source"`
		DiscountRate          float64  `json:"discount_rate"`
		MaxDiscountableAmount float64  `json:"max_discountable_amount"`
		TotalDiscounted       float64  `json:"total_discounted"`
		RemainingQuota        float64  `json:"remaining_quota"`
		ValidUntilUnixMs      *int64   `json:"valid_until_unix_ms"`
		GiftDeductionMode     string   `json:"gift_deduction_mode"`
		GiftRatioRecharge     *float64 `json:"gift_ratio_recharge,omitempty"`
		GiftExpiryMode        string   `json:"gift_expiry_mode"`
		GiftExpiresAfterDays  *int     `json:"gift_expires_after_days,omitempty"`
	}

	dto := discountDTO{
		ID:                    best.ID,
		Source:                best.Source,
		DiscountRate:          best.DiscountRate,
		MaxDiscountableAmount: best.MaxDiscountableAmount,
		TotalDiscounted:       best.TotalDiscounted,
		RemainingQuota:        remaining,
		GiftDeductionMode:     best.GiftDeductionMode,
		GiftRatioRecharge:     best.GiftRatioRecharge,
		GiftExpiryMode:        best.GiftExpiryMode,
		GiftExpiresAfterDays:  best.GiftExpiresAfterDays,
	}
	if best.ValidUntil != nil {
		ms := best.ValidUntil.UnixMilli()
		dto.ValidUntilUnixMs = &ms
	}

	response.Success(c, dto)
}
