package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Wei-Shaw/sub2api/internal/gift"
)

// --- Stubs for ReferralRewardService tests ---

type settingServiceStub struct {
	enabled bool
	config  ReferralRewardConfig
}

func (s *settingServiceStub) IsReferralRewardEnabled(_ context.Context) bool {
	return s.enabled
}

func (s *settingServiceStub) GetReferralRewardConfig(_ context.Context) ReferralRewardConfig {
	return s.config
}

type giftEngineStub struct {
	grants []gift.GrantInput
	nextID int64
	err    error
}

func (g *giftEngineStub) Grant(_ context.Context, input gift.GrantInput) (*gift.UserGift, error) {
	if g.err != nil {
		return nil, g.err
	}
	g.grants = append(g.grants, input)
	g.nextID++
	return &gift.UserGift{ID: g.nextID, UserID: input.UserID, Amount: input.Amount}, nil
}

type discountRepoForReferralStub struct {
	discounts    []RechargeDiscountSummary
	createdCalls []createDiscountCall
}

type createDiscountCall struct {
	UserID     int64
	Source     string
	SourceRef  string
	Rate       float64
	MaxAmount  float64
	ValidUntil *time.Time
}

func (r *discountRepoForReferralStub) CheckApplicationExists(_ context.Context, _ int64) (bool, error) {
	return false, nil
}
func (r *discountRepoForReferralStub) QueryBestActiveDiscountForUpdate(_ context.Context, _ int64) (*RechargeDiscountRecord, error) {
	return nil, nil
}
func (r *discountRepoForReferralStub) UpdateTotalDiscounted(_ context.Context, _ int64, _ float64) error {
	return nil
}
func (r *discountRepoForReferralStub) ClaimApplication(_ context.Context, _ *RechargeDiscountApplicationRecord) (bool, error) {
	return false, nil
}
func (r *discountRepoForReferralStub) UpdateApplicationGiftID(_ context.Context, _ int64, _ int64) error {
	return nil
}
func (r *discountRepoForReferralStub) QueryActiveDiscountsReadOnly(_ context.Context, _ int64) ([]RechargeDiscountSummary, error) {
	return r.discounts, nil
}
func (r *discountRepoForReferralStub) CreateDiscount(_ context.Context, userID int64, source, sourceRef string, _ *int64, rate, maxAmount float64, _ time.Time, validUntil *time.Time) (int64, error) {
	r.createdCalls = append(r.createdCalls, createDiscountCall{
		UserID:     userID,
		Source:     source,
		SourceRef:  sourceRef,
		Rate:       rate,
		MaxAmount:  maxAmount,
		ValidUntil: validUntil,
	})
	return int64(len(r.createdCalls)), nil
}

// --- Tests ---

func TestInheritDiscountFromInviter_NoDiscount_NoOp(t *testing.T) {
	repo := &discountRepoForReferralStub{discounts: nil}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2)
	assert.NoError(t, err)
	assert.Empty(t, repo.createdCalls)
}

func TestInheritDiscountFromInviter_HasDiscount_CreatesInherited(t *testing.T) {
	validUntil := time.Now().Add(10 * 24 * time.Hour) // 10 days from now
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				ID:                    1,
				Source:                "bind_key",
				DiscountRate:          0.15,
				MaxDiscountableAmount: 500,
				TotalDiscounted:       200,
				ValidUntil:            &validUntil,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 10, 20)
	require.NoError(t, err)
	require.Len(t, repo.createdCalls, 1)

	call := repo.createdCalls[0]
	assert.Equal(t, int64(20), call.UserID)
	assert.Equal(t, "referral_inherit", call.Source)
	assert.Equal(t, "inviter:10", call.SourceRef)
	assert.Equal(t, 0.15, call.Rate)
	assert.Equal(t, 500.0, call.MaxAmount) // 使用邀请人的 max_discountable_amount（非 remaining）
	// ValidUntil = now + 30 days (default DiscountValidDays, settingService is nil)
	assert.NotNil(t, call.ValidUntil)
	assert.True(t, call.ValidUntil.After(time.Now().Add(29*24*time.Hour)))
	assert.True(t, call.ValidUntil.Before(time.Now().Add(31*24*time.Hour)))
}

func TestInheritDiscountFromInviter_InviterExhausted_StillCreatesForInvitee(t *testing.T) {
	// 邀请人折扣已耗尽，但被邀请人获得的是全新的 full-amount 折扣
	validUntil := time.Now().Add(5 * 24 * time.Hour)
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				DiscountRate:          0.1,
				MaxDiscountableAmount: 100,
				TotalDiscounted:       100, // fully used by inviter
				ValidUntil:            &validUntil,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2)
	assert.NoError(t, err)
	// 被邀请人仍然获得折扣（使用邀请人的 max_discountable_amount）
	require.Len(t, repo.createdCalls, 1)
	assert.Equal(t, 100.0, repo.createdCalls[0].MaxAmount)
}

func TestInheritDiscountFromInviter_NilRepo_NoOp(t *testing.T) {
	svc := &ReferralRewardService{discountRepo: nil}
	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2)
	assert.NoError(t, err)
}

func TestTrackSpend_ZeroAmount_NoOp(t *testing.T) {
	svc := &ReferralRewardService{}
	err := svc.TrackSpendAndMaybeGrantInviterReward(context.Background(), 1, "event1", 0)
	assert.NoError(t, err)
}

func TestTrackSpend_NegativeAmount_NoOp(t *testing.T) {
	svc := &ReferralRewardService{}
	err := svc.TrackSpendAndMaybeGrantInviterReward(context.Background(), 1, "event1", -5)
	assert.NoError(t, err)
}

func TestTrackSpend_NilService_NoOp(t *testing.T) {
	var svc *ReferralRewardService
	err := svc.TrackSpendAndMaybeGrantInviterReward(context.Background(), 1, "event1", 10)
	assert.NoError(t, err)
}
