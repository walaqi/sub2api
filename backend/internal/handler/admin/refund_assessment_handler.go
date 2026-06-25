package admin

import (
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// RefundAssessmentHandler 退费评估管理员接口
type RefundAssessmentHandler struct {
	assessmentService *service.RefundAssessmentService
}

// NewRefundAssessmentHandler creates the handler.
func NewRefundAssessmentHandler(assessmentService *service.RefundAssessmentService) *RefundAssessmentHandler {
	return &RefundAssessmentHandler{assessmentService: assessmentService}
}

// refundAssessmentSlotDTO 前端展示用 DTO
type refundAssessmentSlotDTO struct {
	Source         string  `json:"source"`
	SourceID       int64   `json:"source_id"`
	CreditedAt     int64   `json:"credited_at"`      // unix ms
	Amount         float64 `json:"amount"`
	PayAmount      float64 `json:"pay_amount"`
	Ratio          float64 `json:"ratio"`
	Consumed       float64 `json:"consumed"`
	ConsumedMoney  float64 `json:"consumed_money"`
	Remaining      float64 `json:"remaining"`
	RefundStatus   string  `json:"refund_status"`
	RefundDeducted float64 `json:"refund_deducted"`
	Note           string  `json:"note"`
}

type refundAssessmentSummaryDTO struct {
	TotalPaidCredited   float64 `json:"total_paid_credited"`
	TotalFreeCredited   float64 `json:"total_free_credited"`
	TotalPaidConsumed   float64 `json:"total_paid_consumed"`
	TotalFreeConsumed   float64 `json:"total_free_consumed"`
	TotalPaidMoneySpent float64 `json:"total_paid_money_spent"`
}

type refundAssessmentResponseDTO struct {
	UserID              int64                      `json:"user_id"`
	Email               string                     `json:"email"`
	TotalRechargeUsed   float64                    `json:"total_recharge_used"`
	TotalGiftUsed       float64                    `json:"total_gift_used"`
	TotalRefundDeducted float64                    `json:"total_refund_deducted"`
	EffectiveUsed       float64                    `json:"effective_used"`
	CurrentPool         float64                    `json:"current_pool"`
	Slots               []refundAssessmentSlotDTO  `json:"slots"`
	Summary             refundAssessmentSummaryDTO `json:"summary"`
}

// GetAssessment 退费评估查询
// GET /api/v1/admin/refund-assessment?email=user@example.com
func (h *RefundAssessmentHandler) GetAssessment(c *gin.Context) {
	email := strings.TrimSpace(c.Query("email"))
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_PARAM", "message": "email is required"})
		return
	}

	result, err := h.assessmentService.Assess(c.Request.Context(), email)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			c.JSON(http.StatusNotFound, gin.H{"code": "USER_NOT_FOUND", "message": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"code": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	// 转换为 DTO
	slots := make([]refundAssessmentSlotDTO, 0, len(result.Slots))
	for _, s := range result.Slots {
		slots = append(slots, refundAssessmentSlotDTO{
			Source:         s.Source,
			SourceID:       s.SourceID,
			CreditedAt:     s.CreditedAt.UnixMilli(),
			Amount:         s.Amount,
			PayAmount:      s.PayAmount,
			Ratio:          s.Ratio,
			Consumed:       s.Consumed,
			ConsumedMoney:  s.ConsumedMoney,
			Remaining:      s.Remaining,
			RefundStatus:   s.RefundStatus,
			RefundDeducted: s.RefundDeducted,
			Note:           s.Note,
		})
	}

	resp := refundAssessmentResponseDTO{
		UserID:              result.UserID,
		Email:               result.UserEmail,
		TotalRechargeUsed:   result.TotalRechargeUsed,
		TotalGiftUsed:       result.TotalGiftUsed,
		TotalRefundDeducted: result.TotalRefundDeducted,
		EffectiveUsed:       result.EffectiveUsed,
		CurrentPool:         result.CurrentPool,
		Slots:               slots,
		Summary: refundAssessmentSummaryDTO{
			TotalPaidCredited:   result.Summary.TotalPaidCredited,
			TotalFreeCredited:   result.Summary.TotalFreeCredited,
			TotalPaidConsumed:   result.Summary.TotalPaidConsumed,
			TotalFreeConsumed:   result.Summary.TotalFreeConsumed,
			TotalPaidMoneySpent: result.Summary.TotalPaidMoneySpent,
		},
	}

	c.JSON(http.StatusOK, gin.H{"code": "OK", "data": resp})
}
