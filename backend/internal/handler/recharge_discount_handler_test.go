package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type discountRepoStub struct {
	discounts []service.RechargeDiscountSummary
	err       error
}

func (s *discountRepoStub) CheckApplicationExists(_ context.Context, _ int64) (bool, error) {
	return false, nil
}
func (s *discountRepoStub) QueryBestActiveDiscountForUpdate(_ context.Context, _ int64) (*service.RechargeDiscountRecord, error) {
	return nil, nil
}
func (s *discountRepoStub) UpdateTotalDiscounted(_ context.Context, _ int64, _ float64) error {
	return nil
}
func (s *discountRepoStub) ClaimApplication(_ context.Context, _ *service.RechargeDiscountApplicationRecord) (bool, error) {
	return false, nil
}
func (s *discountRepoStub) UpdateApplicationGiftID(_ context.Context, _ int64, _ int64) error {
	return nil
}
func (s *discountRepoStub) QueryActiveDiscountsReadOnly(_ context.Context, _ int64) ([]service.RechargeDiscountSummary, error) {
	return s.discounts, s.err
}

func (s *discountRepoStub) QueryDiscountsForInheritance(_ context.Context, _ int64) ([]service.RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *discountRepoStub) QueryDiscountsForInheritanceAtTime(_ context.Context, _ int64, _ time.Time) ([]service.RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *discountRepoStub) CreateDiscount(_ context.Context, _ service.CreateRechargeDiscountInput) (int64, error) {
	return 0, nil
}

func (s *discountRepoStub) QueryOrderGiftBonus(_ context.Context, _ int64) (*service.OrderGiftBonus, error) {
	return nil, nil
}

func TestGetMyActiveDiscount_NilRepo_ReturnsNull(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewRechargeDiscountHandler(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 1})

	h.GetMyActiveDiscount(c)

	assert.Equal(t, http.StatusOK, w.Code)
	// response.Success(c, nil) omits data field (omitempty) — no "data" key in response
	assert.NotContains(t, w.Body.String(), `"discount_rate"`)
}

func TestGetMyActiveDiscount_NoAuth_Returns401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &discountRepoStub{}
	h := NewRechargeDiscountHandler(repo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	// No auth subject set

	h.GetMyActiveDiscount(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetMyActiveDiscount_NoDiscount_ReturnsNull(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &discountRepoStub{discounts: nil}
	h := NewRechargeDiscountHandler(repo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 42})

	h.GetMyActiveDiscount(c)

	assert.Equal(t, http.StatusOK, w.Code)
	// No discount → response.Success(c, nil) omits data field
	assert.NotContains(t, w.Body.String(), `"discount_rate"`)
}

func TestGetMyActiveDiscount_HasDiscount_ReturnsBest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	validUntil := time.Now().Add(24 * time.Hour)
	repo := &discountRepoStub{
		discounts: []service.RechargeDiscountSummary{
			{
				ID:                    5,
				Source:                "bind_key",
				SourceRef:             "api_key:42",
				DiscountRate:          0.15,
				MaxDiscountableAmount: 500,
				TotalDiscounted:       120,
				ValidFrom:             time.Now().Add(-24 * time.Hour),
				ValidUntil:            &validUntil,
			},
		},
	}
	h := NewRechargeDiscountHandler(repo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 42})

	h.GetMyActiveDiscount(c)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"discount_rate":0.15`)
	assert.Contains(t, body, `"remaining_quota":380`)
	assert.Contains(t, body, `"source":"bind_key"`)
	assert.Contains(t, body, `"valid_until_unix_ms"`)
}

func TestGetMyActiveDiscount_RepoError_Returns500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &discountRepoStub{err: assert.AnError}
	h := NewRechargeDiscountHandler(repo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 42})

	h.GetMyActiveDiscount(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetMyActiveDiscount_DiscountNoExpiry_NullValidUntil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &discountRepoStub{
		discounts: []service.RechargeDiscountSummary{
			{
				ID:                    3,
				Source:                "referral_inherit",
				DiscountRate:          0.2,
				MaxDiscountableAmount: 1000,
				TotalDiscounted:       0,
				ValidFrom:             time.Now().Add(-1 * time.Hour),
				ValidUntil:            nil,
			},
		},
	}
	h := NewRechargeDiscountHandler(repo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 42})

	h.GetMyActiveDiscount(c)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"valid_until_unix_ms":null`)
	assert.Contains(t, body, `"remaining_quota":1000`)
	_ = require.NotNil
}
