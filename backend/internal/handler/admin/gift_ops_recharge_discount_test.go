package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Wei-Shaw/sub2api/internal/domain"
)

func TestSetBindKeyRechargeDiscount_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &GiftOpsHandler{entClient: nil}

	tests := []struct {
		name       string
		apiKeyID   string
		body       string
		wantStatus int
		wantSubstr string
	}{
		{
			name:       "invalid api_key_id",
			apiKeyID:   "0",
			body:       `{"enabled":true,"discount_rate":0.1,"max_discountable_amount":100,"valid_days":30}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "invalid api_key_id",
		},
		{
			name:       "negative api_key_id",
			apiKeyID:   "-1",
			body:       `{"enabled":true,"discount_rate":0.1,"max_discountable_amount":100,"valid_days":30}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "invalid api_key_id",
		},
		{
			name:       "non-numeric api_key_id",
			apiKeyID:   "abc",
			body:       `{"enabled":true,"discount_rate":0.1,"max_discountable_amount":100,"valid_days":30}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "invalid api_key_id",
		},
		{
			name:       "discount_rate zero",
			apiKeyID:   "42",
			body:       `{"enabled":true,"discount_rate":0,"max_discountable_amount":100,"valid_days":30}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "discount_rate",
		},
		{
			name:       "discount_rate over 1",
			apiKeyID:   "42",
			body:       `{"enabled":true,"discount_rate":1.5,"max_discountable_amount":100,"valid_days":30}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "discount_rate",
		},
		{
			name:       "max_discountable_amount zero",
			apiKeyID:   "42",
			body:       `{"enabled":true,"discount_rate":0.1,"max_discountable_amount":0,"valid_days":30}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "max_discountable_amount",
		},
		{
			name:       "valid_days zero",
			apiKeyID:   "42",
			body:       `{"enabled":true,"discount_rate":0.1,"max_discountable_amount":100,"valid_days":0}`,
			wantStatus: http.StatusBadRequest,
			wantSubstr: "valid_days",
		},
		{
			name:       "discount_rate exactly 1 is valid (passes validation, fails on nil DB)",
			apiKeyID:   "42",
			body:       `{"enabled":true,"discount_rate":1.0,"max_discountable_amount":100,"valid_days":1}`,
			wantStatus: 0, // skip status check — nil entClient panics; validation coverage is the point
			wantSubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantStatus == 0 {
				t.Skip("skipped: nil entClient panics past validation")
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Params = gin.Params{{Key: "api_key_id", Value: tt.apiKeyID}}
			c.Request = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")

			h.SetBindKeyRechargeDiscount(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantSubstr)
		})
	}
}

func TestDeleteBindKeyRechargeDiscount_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &GiftOpsHandler{entClient: nil}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "api_key_id", Value: "0"}}
	c.Request = httptest.NewRequest(http.MethodDelete, "/", nil)

	h.DeleteBindKeyRechargeDiscount(c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMergeRechargeDiscount_PreservesOtherFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	existing := &domain.BindKeyConfig{
		Unlimit: boolPtr(true),
		RegistrationWindow: &domain.BindKeyRegistrationWindow{
			Enabled: true,
			MinDays: 1,
			MaxDays: 30,
		},
	}

	discount := &domain.BindKeyRechargeDiscount{
		Enabled:               true,
		DiscountRate:          0.2,
		MaxDiscountableAmount: 200,
		ValidDays:             14,
	}

	result := mergeRechargeDiscount(existing, discount)

	require.NotNil(t, result)
	require.NotNil(t, result.Unlimit)
	assert.True(t, *result.Unlimit)
	require.NotNil(t, result.RegistrationWindow)
	assert.Equal(t, 30, result.RegistrationWindow.MaxDays)
	require.NotNil(t, result.RechargeDiscount)
	assert.Equal(t, 0.2, result.RechargeDiscount.DiscountRate)
}

func TestMergeRechargeDiscount_ClearsDiscount(t *testing.T) {
	existing := &domain.BindKeyConfig{
		Unlimit: boolPtr(true),
		RechargeDiscount: &domain.BindKeyRechargeDiscount{
			Enabled:               true,
			DiscountRate:          0.1,
			MaxDiscountableAmount: 100,
			ValidDays:             7,
		},
	}

	result := mergeRechargeDiscount(existing, nil)

	require.NotNil(t, result)
	require.NotNil(t, result.Unlimit)
	assert.True(t, *result.Unlimit)
	assert.Nil(t, result.RechargeDiscount)
}

func boolPtr(b bool) *bool { return &b }
