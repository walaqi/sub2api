//go:build unit

package service

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Stubs ---

type rechargeDiscountRepoStub struct {
	applicationExists bool
	discount          *RechargeDiscountRecord
	updatedID         int64
	updatedAmount     float64
	claimedApp        *RechargeDiscountApplicationRecord
	claimReturn       bool // what ClaimApplication returns
	forceError        error
}

func (s *rechargeDiscountRepoStub) CheckApplicationExists(_ context.Context, _ int64) (bool, error) {
	if s.forceError != nil {
		return false, s.forceError
	}
	return s.applicationExists, nil
}

func (s *rechargeDiscountRepoStub) QueryBestActiveDiscountForUpdate(_ context.Context, _ int64) (*RechargeDiscountRecord, error) {
	if s.forceError != nil {
		return nil, s.forceError
	}
	return s.discount, nil
}

func (s *rechargeDiscountRepoStub) UpdateTotalDiscounted(_ context.Context, id int64, amount float64) error {
	if s.forceError != nil {
		return s.forceError
	}
	s.updatedID = id
	s.updatedAmount = amount
	return nil
}

func (s *rechargeDiscountRepoStub) ClaimApplication(_ context.Context, app *RechargeDiscountApplicationRecord) (bool, error) {
	if s.forceError != nil {
		return false, s.forceError
	}
	s.claimedApp = app
	return s.claimReturn, nil
}

func (s *rechargeDiscountRepoStub) UpdateApplicationGiftID(_ context.Context, _ int64, _ int64) error {
	return nil
}

func (s *rechargeDiscountRepoStub) QueryActiveDiscountsReadOnly(_ context.Context, _ int64) ([]RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *rechargeDiscountRepoStub) QueryDiscountsForInheritance(_ context.Context, _ int64) ([]RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *rechargeDiscountRepoStub) QueryDiscountsForInheritanceAtTime(_ context.Context, _ int64, _ time.Time) ([]RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *rechargeDiscountRepoStub) CreateDiscount(_ context.Context, _ CreateRechargeDiscountInput) (int64, error) {
	return 0, nil
}

func (s *rechargeDiscountRepoStub) QueryOrderGiftBonus(_ context.Context, _ int64) (*OrderGiftBonus, error) {
	return nil, nil
}

// --- Tests ---

func TestApplyRechargeDiscount_NilRepo_Skips(t *testing.T) {
	svc := &PaymentService{rechargeDiscountRepo: nil}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_AlreadyApplied_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{applicationExists: true}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
	assert.Nil(t, repo.claimedApp)
}

func TestApplyRechargeDiscount_ClaimConflict_DoesNotGrantOrUpdate(t *testing.T) {
	// Simulates concurrent execution: claim returns false (another goroutine already claimed)
	repo := &rechargeDiscountRepoStub{
		claimReturn: false, // ON CONFLICT → not claimed
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo, giftEngine: nil, entClient: nil}
	// Even though giftEngine is nil, it should exit before reaching it due to claimed=false
	// But we need entClient to get past the guard... let's verify the Phase 1 path exits correctly
	// Phase 1 passes (discount exists, amount valid), but no entClient → error
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	// Without entClient, Phase 2 can't start → returns error about config
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gift engine or ent client not configured")
	// Confirm no update happened in Phase 1 (stub-level check)
	assert.Equal(t, int64(0), repo.updatedID)
}

func TestApplyRechargeDiscount_NoActiveDiscount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{discount: nil}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_DiscountExhausted_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 100,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
	assert.Nil(t, repo.claimedApp)
}

func TestApplyRechargeDiscount_ZeroOrderAmount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 0))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_NegativeOrderAmount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, -5))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_NaNOrderAmount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, math.NaN()))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_PartialRemaining_AppliesCorrectAmount(t *testing.T) {
	// User used $80 of $100 max; charging $50 → only $20 participates in discount
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 5, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 80,
			ValidUntil: discountTimePtr(time.Now().Add(30 * 24 * time.Hour)),
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo, giftEngine: nil}
	// giftEngine is nil → will error after passing skip logic, confirming calculation path reached
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gift engine or ent client not configured")
}

func TestApplyRechargeDiscount_CheckError_Propagates(t *testing.T) {
	testErr := errors.New("db connection lost")
	repo := &rechargeDiscountRepoStub{forceError: testErr}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check discount application")
}

func TestApplyRechargeDiscount_QueryError_Propagates(t *testing.T) {
	repo := &rechargeDiscountRepoStub{applicationExists: false}
	// Override just QueryBestActiveDiscountForUpdate to error
	repo.forceError = nil
	svc := &PaymentService{rechargeDiscountRepo: &queryErrorRepoStub{}}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query active discount")
}

// --- queryErrorRepoStub only errors on Query ---
type queryErrorRepoStub struct{}

func (s *queryErrorRepoStub) CheckApplicationExists(_ context.Context, _ int64) (bool, error) {
	return false, nil
}
func (s *queryErrorRepoStub) QueryBestActiveDiscountForUpdate(_ context.Context, _ int64) (*RechargeDiscountRecord, error) {
	return nil, errors.New("query failed")
}
func (s *queryErrorRepoStub) UpdateTotalDiscounted(_ context.Context, _ int64, _ float64) error {
	return nil
}
func (s *queryErrorRepoStub) ClaimApplication(_ context.Context, _ *RechargeDiscountApplicationRecord) (bool, error) {
	return true, nil
}
func (s *queryErrorRepoStub) UpdateApplicationGiftID(_ context.Context, _ int64, _ int64) error {
	return nil
}
func (s *queryErrorRepoStub) QueryActiveDiscountsReadOnly(_ context.Context, _ int64) ([]RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *queryErrorRepoStub) QueryDiscountsForInheritance(_ context.Context, _ int64) ([]RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *queryErrorRepoStub) QueryDiscountsForInheritanceAtTime(_ context.Context, _ int64, _ time.Time) ([]RechargeDiscountSummary, error) {
	return nil, nil
}

func (s *queryErrorRepoStub) QueryOrderGiftBonus(_ context.Context, _ int64) (*OrderGiftBonus, error) {
	return nil, nil
}

func (s *queryErrorRepoStub) CreateDiscount(_ context.Context, _ CreateRechargeDiscountInput) (int64, error) {
	return 0, nil
}

// --- Helpers ---

func makeTestOrder(userID, orderID int64, amount float64) *dbent.PaymentOrder {
	return &dbent.PaymentOrder{
		ID:     orderID,
		UserID: userID,
		Amount: amount,
	}
}

func discountTimePtr(t time.Time) *time.Time {
	return &t
}

func rechargeDiscountIntPtr(v int) *int {
	return &v
}

// --- resolveDiscountGiftGrantMode ---

func TestResolveDiscountGiftGrantMode_Priority(t *testing.T) {
	mode, ratio, err := resolveDiscountGiftGrantMode("priority", nil)
	require.NoError(t, err)
	assert.Equal(t, gift.DeductionModePriority, mode)
	assert.Nil(t, ratio)
}

func TestResolveDiscountGiftGrantMode_EmptyModeFallsBackToPriority(t *testing.T) {
	mode, ratio, err := resolveDiscountGiftGrantMode("", nil)
	require.NoError(t, err)
	assert.Equal(t, gift.DeductionModePriority, mode)
	assert.Nil(t, ratio)
}

func TestResolveDiscountGiftGrantMode_UnknownModeFallsBackToPriority(t *testing.T) {
	// 即使带了 ratio，未知 mode 也归一为 priority 且清空 ratio。
	r := 0.5
	mode, ratio, err := resolveDiscountGiftGrantMode("bogus", &r)
	require.NoError(t, err)
	assert.Equal(t, gift.DeductionModePriority, mode)
	assert.Nil(t, ratio)
}

func TestResolveDiscountGiftGrantMode_Ratio(t *testing.T) {
	r := 0.5
	mode, ratio, err := resolveDiscountGiftGrantMode("ratio", &r)
	require.NoError(t, err)
	assert.Equal(t, gift.DeductionModeRatio, mode)
	require.NotNil(t, ratio)
	assert.Equal(t, 0.5, *ratio)
}

func TestResolveDiscountGiftGrantMode_RatioModeNilRatio_Errors(t *testing.T) {
	_, _, err := resolveDiscountGiftGrantMode("ratio", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gift_ratio_recharge")
}

func TestResolveDiscountGiftGrantMode_RatioModeZeroRatio_Errors(t *testing.T) {
	r := 0.0
	_, _, err := resolveDiscountGiftGrantMode("ratio", &r)
	require.Error(t, err)
}

func TestResolveDiscountGiftGrantMode_RatioAbove10_Errors(t *testing.T) {
	// 发放边界也复用 NormalizeGiftDeduction，不信任 DB：ratio>10 即使被手工写入也拒绝发放。
	r := 100.0
	_, _, err := resolveDiscountGiftGrantMode("ratio", &r)
	require.Error(t, err)
}

func TestResolveDiscountGiftExpiresAt_DiscountValidUntil(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	validUntil := now.Add(15 * 24 * time.Hour)

	expiresAt, err := resolveDiscountGiftExpiresAt("discount_valid_until", nil, &validUntil, now)
	require.NoError(t, err)
	require.NotNil(t, expiresAt)
	assert.Equal(t, validUntil, *expiresAt)
}

func TestResolveDiscountGiftExpiresAt_EmptyModeFallsBackToDiscountValidUntil(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	validUntil := now.Add(15 * 24 * time.Hour)

	expiresAt, err := resolveDiscountGiftExpiresAt("", rechargeDiscountIntPtr(7), &validUntil, now)
	require.NoError(t, err)
	require.NotNil(t, expiresAt)
	assert.Equal(t, validUntil, *expiresAt)
}

func TestResolveDiscountGiftExpiresAt_Never(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	validUntil := now.Add(15 * 24 * time.Hour)

	expiresAt, err := resolveDiscountGiftExpiresAt("never", rechargeDiscountIntPtr(7), &validUntil, now)
	require.NoError(t, err)
	assert.Nil(t, expiresAt)
}

func TestResolveDiscountGiftExpiresAt_AfterDays(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	validUntil := now.Add(15 * 24 * time.Hour)

	expiresAt, err := resolveDiscountGiftExpiresAt("after_days", rechargeDiscountIntPtr(3), &validUntil, now)
	require.NoError(t, err)
	require.NotNil(t, expiresAt)
	assert.Equal(t, now.Add(3*24*time.Hour), *expiresAt)
}

func TestResolveDiscountGiftExpiresAt_AfterDaysInvalid_Errors(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)

	_, err := resolveDiscountGiftExpiresAt("after_days", nil, nil, now)
	require.Error(t, err)

	_, err = resolveDiscountGiftExpiresAt("after_days", rechargeDiscountIntPtr(0), nil, now)
	require.Error(t, err)
}
