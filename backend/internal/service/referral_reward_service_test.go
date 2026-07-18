package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Stubs for ReferralRewardService tests ---

type referralConfigSettingRepoStub struct {
	values map[string]string
}

func (s *referralConfigSettingRepoStub) Get(_ context.Context, key string) (*Setting, error) {
	v, err := s.GetValue(context.Background(), key)
	if err != nil {
		return nil, err
	}
	return &Setting{Key: key, Value: v}, nil
}

func (s *referralConfigSettingRepoStub) GetValue(_ context.Context, key string) (string, error) {
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return "", ErrSettingNotFound
}

func (s *referralConfigSettingRepoStub) Set(_ context.Context, _ string, _ string) error {
	return nil
}

func (s *referralConfigSettingRepoStub) GetMultiple(_ context.Context, keys []string) (map[string]string, error) {
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if v, ok := s.values[key]; ok {
			result[key] = v
		}
	}
	return result, nil
}

func (s *referralConfigSettingRepoStub) SetMultiple(_ context.Context, settings map[string]string) error {
	if s.values == nil {
		s.values = map[string]string{}
	}
	for k, v := range settings {
		s.values[k] = v
	}
	return nil
}

func (s *referralConfigSettingRepoStub) GetAll(_ context.Context) (map[string]string, error) {
	return s.values, nil
}

func (s *referralConfigSettingRepoStub) Delete(_ context.Context, key string) error {
	delete(s.values, key)
	return nil
}

type discountRepoForReferralStub struct {
	discounts    []RechargeDiscountSummary
	atTime       map[int64][]RechargeDiscountSummary
	createdCalls []createDiscountCall
}

type createDiscountCall struct {
	UserID               int64
	Source               string
	SourceRef            string
	Rate                 float64
	MaxAmount            float64
	ValidUntil           *time.Time
	GiftDeductionMode    string
	GiftRatioRecharge    *float64
	GiftExpiryMode       string
	GiftExpiresAfterDays *int
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
func (r *discountRepoForReferralStub) QueryDiscountsForInheritance(_ context.Context, _ int64) ([]RechargeDiscountSummary, error) {
	return r.discounts, nil
}
func (r *discountRepoForReferralStub) QueryDiscountsForInheritanceAtTime(_ context.Context, _ int64, atTime time.Time) ([]RechargeDiscountSummary, error) {
	if r.atTime == nil {
		return r.discounts, nil
	}
	return r.atTime[atTime.Unix()], nil
}
func (r *discountRepoForReferralStub) QueryOrderGiftBonus(_ context.Context, _ int64) (*OrderGiftBonus, error) {
	return nil, nil
}

// inviterRechargeReaderStub 打桩 recharge 模式资格判定的累计充值读取。
type inviterRechargeReaderStub struct {
	byUser map[int64]float64
	err    error
	calls  []int64
}

func (r *inviterRechargeReaderStub) TotalRecharged(_ context.Context, userID int64) (float64, error) {
	r.calls = append(r.calls, userID)
	if r.err != nil {
		return 0, r.err
	}
	return r.byUser[userID], nil
}

func (r *discountRepoForReferralStub) CreateDiscount(_ context.Context, in CreateRechargeDiscountInput) (int64, error) {
	r.createdCalls = append(r.createdCalls, createDiscountCall{
		UserID:               in.UserID,
		Source:               in.Source,
		SourceRef:            in.SourceRef,
		Rate:                 in.Rate,
		MaxAmount:            in.MaxAmount,
		ValidUntil:           in.ValidUntil,
		GiftDeductionMode:    in.GiftDeductionMode,
		GiftRatioRecharge:    in.GiftRatioRecharge,
		GiftExpiryMode:       in.GiftExpiryMode,
		GiftExpiresAfterDays: in.GiftExpiresAfterDays,
	})
	return int64(len(r.createdCalls)), nil
}

// --- Tests ---

func TestInheritDiscountFromInviter_NoDiscount_NoOp(t *testing.T) {
	repo := &discountRepoForReferralStub{discounts: nil}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2, time.Now())
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

	err := svc.inheritDiscountFromInviter(context.Background(), 10, 20, time.Now())
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

func TestInheritDiscountFromInviter_CopiesMode_Priority(t *testing.T) {
	// 邀请人 best discount 为 priority → 被邀请人继承 priority，ratio 为 nil。
	validUntil := time.Now().Add(15 * 24 * time.Hour)
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				ID:                    1,
				DiscountRate:          0.2,
				MaxDiscountableAmount: 300,
				ValidUntil:            &validUntil,
				GiftDeductionMode:     "priority",
				GiftRatioRecharge:     nil,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 10, 20, time.Now())
	require.NoError(t, err)
	require.Len(t, repo.createdCalls, 1)
	assert.Equal(t, "priority", repo.createdCalls[0].GiftDeductionMode)
	assert.Nil(t, repo.createdCalls[0].GiftRatioRecharge)
}

func TestInheritDiscountFromInviter_CopiesMode_Ratio(t *testing.T) {
	// 邀请人 best discount 为 ratio → 被邀请人继承同样的 mode + ratio 值。
	validUntil := time.Now().Add(15 * 24 * time.Hour)
	ratio := 0.5
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				ID:                    1,
				DiscountRate:          0.2,
				MaxDiscountableAmount: 300,
				ValidUntil:            &validUntil,
				GiftDeductionMode:     "ratio",
				GiftRatioRecharge:     &ratio,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 10, 20, time.Now())
	require.NoError(t, err)
	require.Len(t, repo.createdCalls, 1)
	assert.Equal(t, "ratio", repo.createdCalls[0].GiftDeductionMode)
	require.NotNil(t, repo.createdCalls[0].GiftRatioRecharge)
	assert.Equal(t, 0.5, *repo.createdCalls[0].GiftRatioRecharge)
}

func TestInheritDiscountFromInviter_CopiesGiftExpiry_AfterDays(t *testing.T) {
	validUntil := time.Now().Add(15 * 24 * time.Hour)
	expiryDays := 7
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				ID:                    1,
				DiscountRate:          0.2,
				MaxDiscountableAmount: 300,
				ValidUntil:            &validUntil,
				GiftExpiryMode:        "after_days",
				GiftExpiresAfterDays:  &expiryDays,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 10, 20, time.Now())
	require.NoError(t, err)
	require.Len(t, repo.createdCalls, 1)
	assert.Equal(t, "after_days", repo.createdCalls[0].GiftExpiryMode)
	require.NotNil(t, repo.createdCalls[0].GiftExpiresAfterDays)
	assert.Equal(t, 7, *repo.createdCalls[0].GiftExpiresAfterDays)
}

func TestInheritDiscountFromInviter_PartiallyUsed_InheritsFullMaxAmount(t *testing.T) {
	// 邀请人折扣已部分使用，但被邀请人继承的是完整 max_discountable_amount（非 remaining）。
	// 继承查询不看 total_discounted；本测试验证部分使用场景仍继承完整 max。
	validUntil := time.Now().Add(20 * 24 * time.Hour)
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				DiscountRate:          0.1,
				MaxDiscountableAmount: 100,
				TotalDiscounted:       80, // 部分使用（生产中 80 < 100 会被查出来）
				ValidUntil:            &validUntil,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2, time.Now())
	assert.NoError(t, err)
	// 被邀请人获得完整 max_discountable_amount，不受邀请人已消费额度影响
	require.Len(t, repo.createdCalls, 1)
	assert.Equal(t, 100.0, repo.createdCalls[0].MaxAmount)
}

func TestInheritDiscountFromInviter_ExhaustedButInTimeWindow_Inherits(t *testing.T) {
	validUntil := time.Now().Add(20 * 24 * time.Hour)
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{
			{
				DiscountRate:          0.1,
				MaxDiscountableAmount: 100,
				TotalDiscounted:       100,
				ValidUntil:            &validUntil,
			},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2, time.Now())
	assert.NoError(t, err)
	require.Len(t, repo.createdCalls, 1)
	assert.Equal(t, 100.0, repo.createdCalls[0].MaxAmount)
}

func TestInheritDiscountFromInviter_NilRepo_NoOp(t *testing.T) {
	svc := &ReferralRewardService{discountRepo: nil}
	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2, time.Now())
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

func TestHasInviterRewardEligibility_UsesInheritanceQuery(t *testing.T) {
	repo := &discountRepoForReferralStub{discounts: []RechargeDiscountSummary{{ID: 1}}}
	svc := &ReferralRewardService{discountRepo: repo}

	assert.True(t, svc.hasInviterRewardEligibility(context.Background(), 1))
}

func TestHasInviterRewardEligibilityAtTime_UsesHistoricalQuery(t *testing.T) {
	atTime := time.Unix(1000, 0)
	repo := &discountRepoForReferralStub{
		atTime: map[int64][]RechargeDiscountSummary{
			atTime.Unix(): {{ID: 1}},
		},
	}
	svc := &ReferralRewardService{discountRepo: repo}

	assert.True(t, svc.hasInviterRewardEligibilityAtTime(context.Background(), 1, atTime))
	assert.False(t, svc.hasInviterRewardEligibilityAtTime(context.Background(), 1, time.Unix(2000, 0)))
}

func TestReferralEligibility_RechargeMode_UsesTotalRecharged(t *testing.T) {
	// recharge 模式只看累计充值额，完全不查券表。
	discountRepo := &discountRepoForReferralStub{discounts: []RechargeDiscountSummary{{ID: 1}}}
	rechargeRepo := &inviterRechargeReaderStub{byUser: map[int64]float64{
		1: 30.0, // >= 门槛 25.5 → 有资格
		2: 10.0, // <  门槛 25.5 → 无资格
	}}
	svc := &ReferralRewardService{
		discountRepo:   discountRepo,
		rechargeReader: rechargeRepo,
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
			SettingKeyReferralEligibilityGrantMode:   ReferralEligibilityGrantModeRecharge,
			SettingKeyReferralEligibilityRechargeMin: "25.50",
		}}},
	}

	assert.True(t, svc.hasInviterRewardEligibility(context.Background(), 1))
	assert.False(t, svc.hasInviterRewardEligibility(context.Background(), 2))
	// 未查券表（继承查询不应被资格判定触发）。
	assert.Empty(t, discountRepo.createdCalls)
}

func TestReferralEligibility_RechargeMode_ZeroThresholdRequiresAnyRecharge(t *testing.T) {
	// 门槛为 0：只要有过任意充值即算资格。
	rechargeRepo := &inviterRechargeReaderStub{byUser: map[int64]float64{
		1: 0.01,
		2: 0,
	}}
	svc := &ReferralRewardService{
		rechargeReader: rechargeRepo,
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
			SettingKeyReferralEligibilityGrantMode:   ReferralEligibilityGrantModeRecharge,
			SettingKeyReferralEligibilityRechargeMin: "0",
		}}},
	}

	assert.True(t, svc.hasInviterRewardEligibility(context.Background(), 1))
	assert.False(t, svc.hasInviterRewardEligibility(context.Background(), 2))
}

func TestReferralEligibility_RechargeMode_IgnoresBoundAt(t *testing.T) {
	// recharge 模式下 atTime 被忽略（total_recharged 无历史时点台账），
	// 无论传哪个绑定时间点，都读当前累计充值额判定。
	rechargeRepo := &inviterRechargeReaderStub{byUser: map[int64]float64{1: 20.0}}
	svc := &ReferralRewardService{
		rechargeReader: rechargeRepo,
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
			SettingKeyReferralEligibilityGrantMode:   ReferralEligibilityGrantModeRecharge,
			SettingKeyReferralEligibilityRechargeMin: "10",
		}}},
	}

	assert.True(t, svc.hasInviterRewardEligibilityAtTime(context.Background(), 1, time.Unix(5000, 0)))
	assert.True(t, svc.hasInviterRewardEligibilityAtTime(context.Background(), 1, time.Unix(9999, 0)))
	assert.Equal(t, []int64{1, 1}, rechargeRepo.calls)
}

func TestReferralEligibility_RechargeMode_ReaderErrorFailsClosed(t *testing.T) {
	rechargeRepo := &inviterRechargeReaderStub{err: errors.New("db down")}
	svc := &ReferralRewardService{
		rechargeReader: rechargeRepo,
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
			SettingKeyReferralEligibilityGrantMode:   ReferralEligibilityGrantModeRecharge,
			SettingKeyReferralEligibilityRechargeMin: "10",
		}}},
	}

	// 读取失败 → fail closed（无资格），不误发奖励。
	assert.False(t, svc.hasInviterRewardEligibility(context.Background(), 1))
}

func TestInheritDiscountFromInviter_AlwaysUsesDiscountTable(t *testing.T) {
	// 折扣继承与资格获得方式无关：始终查邀请人名下的有效充值折扣券。
	// recharge 模式下靠纯充值达标（无券）的邀请人，继承查询为空 → 空转。
	boundAt := time.Unix(8000, 0)
	repo := &discountRepoForReferralStub{
		discounts: []RechargeDiscountSummary{{ID: 1, DiscountRate: 0.2, MaxDiscountableAmount: 100}},
		atTime:    map[int64][]RechargeDiscountSummary{}, // boundAt 时点无券
	}
	svc := &ReferralRewardService{
		discountRepo:   repo,
		rechargeReader: &inviterRechargeReaderStub{byUser: map[int64]float64{1: 999}},
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
			SettingKeyReferralEligibilityGrantMode: ReferralEligibilityGrantModeRecharge,
		}}},
	}

	// 无券 → 不继承（即便充值达标、有资格）。
	err := svc.inheritDiscountFromInviter(context.Background(), 1, 2, boundAt)
	assert.NoError(t, err)
	assert.Empty(t, repo.createdCalls)

	// 有券 → 继承。
	repo2 := &discountRepoForReferralStub{
		atTime: map[int64][]RechargeDiscountSummary{
			boundAt.Unix(): {{ID: 1, DiscountRate: 0.2, MaxDiscountableAmount: 100}},
		},
	}
	svc.discountRepo = repo2
	err = svc.inheritDiscountFromInviter(context.Background(), 1, 2, boundAt)
	assert.NoError(t, err)
	require.Len(t, repo2.createdCalls, 1)
	assert.Equal(t, "referral_inherit", repo2.createdCalls[0].Source)
}

func TestGetReferralRewardConfig_InviterGiftModeDefaultsPriority(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.Equal(t, "priority", cfg.InviterGiftMode)
	assert.Equal(t, 0.5, cfg.InviterGiftRatio)
}

func TestGetReferralRewardConfig_InviterGiftModeRatio(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
		SettingKeyReferralInviterGiftMode:          "ratio",
		SettingKeyReferralInviterGiftRatioRecharge: "0.75",
	}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.Equal(t, "ratio", cfg.InviterGiftMode)
	assert.Equal(t, 0.75, cfg.InviterGiftRatio)
}

func TestGetReferralRewardConfig_EligibilityDefaults(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.Equal(t, ReferralEligibilityGrantModeBindKeyClaim, cfg.EligibilityGrantMode)
	assert.Equal(t, 0.0, cfg.EligibilityRechargeMinAmount)
}

func TestGetReferralRewardConfig_EligibilityRechargeMode(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
		SettingKeyReferralEligibilityGrantMode:   ReferralEligibilityGrantModeRecharge,
		SettingKeyReferralEligibilityRechargeMin: "30.25",
	}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.Equal(t, ReferralEligibilityGrantModeRecharge, cfg.EligibilityGrantMode)
	assert.Equal(t, 30.25, cfg.EligibilityRechargeMinAmount)
}

func TestGetReferralRewardConfig_EligibilityInvalidFallback(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
		SettingKeyReferralEligibilityGrantMode:   "unknown",
		SettingKeyReferralEligibilityRechargeMin: "-1",
	}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.Equal(t, ReferralEligibilityGrantModeBindKeyClaim, cfg.EligibilityGrantMode)
	assert.Equal(t, 0.0, cfg.EligibilityRechargeMinAmount)
}

func TestGetReferralRewardConfig_InviterRewardQuotaDefaults(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	// 默认关闭，行为不变；step=50, per_batch=10
	assert.False(t, cfg.InviterRewardQuotaEnabled)
	assert.Equal(t, 50.0, cfg.InviterRewardQuotaRechargeStep)
	assert.Equal(t, 10, cfg.InviterRewardQuotaPerBatch)
}

func TestGetReferralRewardConfig_InviterRewardQuotaEnabled(t *testing.T) {
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
		SettingKeyReferralInviterRewardQuotaEnabled:      "true",
		SettingKeyReferralInviterRewardQuotaRechargeStep: "100",
		SettingKeyReferralInviterRewardQuotaPerBatch:     "5",
	}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.True(t, cfg.InviterRewardQuotaEnabled)
	assert.Equal(t, 100.0, cfg.InviterRewardQuotaRechargeStep)
	assert.Equal(t, 5, cfg.InviterRewardQuotaPerBatch)
}

func TestGetReferralRewardConfig_InviterRewardQuotaInvalidFallback(t *testing.T) {
	// step<=0 / per_batch<=0 / 非法值 → 回退默认值，开关按非 "true" 关闭。
	svc := &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
		SettingKeyReferralInviterRewardQuotaEnabled:      "1", // 非 "true" → false
		SettingKeyReferralInviterRewardQuotaRechargeStep: "0",
		SettingKeyReferralInviterRewardQuotaPerBatch:     "-3",
	}}}

	cfg := svc.GetReferralRewardConfig(context.Background())

	assert.False(t, cfg.InviterRewardQuotaEnabled)
	assert.Equal(t, 50.0, cfg.InviterRewardQuotaRechargeStep)
	assert.Equal(t, 10, cfg.InviterRewardQuotaPerBatch)
}

func TestAccrueInviterRewardQuota_QuotaDisabled_NoOp(t *testing.T) {
	// 配额开关关时，AccrueInviterRewardQuota 直接跳过（不访问 DB，entClient=nil 也安全）。
	svc := &ReferralRewardService{
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{}}},
	}
	err := svc.AccrueInviterRewardQuota(context.Background(), 1, ReferralQuotaSourcePaymentOrder, 100, 50)
	assert.NoError(t, err)
}

func TestAccrueInviterRewardQuota_NonPositiveAmount_NoOp(t *testing.T) {
	svc := &ReferralRewardService{
		settingService: &SettingService{settingRepo: &referralConfigSettingRepoStub{values: map[string]string{
			SettingKeyReferralInviterRewardQuotaEnabled: "true",
		}}},
	}
	assert.NoError(t, svc.AccrueInviterRewardQuota(context.Background(), 1, ReferralQuotaSourcePaymentOrder, 100, 0))
	assert.NoError(t, svc.AccrueInviterRewardQuota(context.Background(), 1, ReferralQuotaSourcePaymentOrder, 100, -5))
}

func TestAccrueInviterRewardQuota_NilService_NoOp(t *testing.T) {
	var svc *ReferralRewardService
	assert.NoError(t, svc.AccrueInviterRewardQuota(context.Background(), 1, ReferralQuotaSourcePaymentOrder, 100, 50))
}
