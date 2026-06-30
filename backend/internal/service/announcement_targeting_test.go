package service

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestAnnouncementTargeting_Matches_EmptyMatchesAll(t *testing.T) {
	var targeting AnnouncementTargeting
	require.True(t, targeting.Matches(domain.UserTargetingContext{}))
	require.True(t, targeting.Matches(domain.UserTargetingContext{Balance: 123.45, ActiveSubscriptionGroupIDs: map[int64]struct{}{1: {}}}))
}

func TestAnnouncementTargeting_NormalizeAndValidate_RejectsEmptyGroup(t *testing.T) {
	targeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: nil},
		},
	}
	_, err := targeting.NormalizeAndValidate()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAnnouncementInvalidTarget)
}

func TestAnnouncementTargeting_NormalizeAndValidate_RejectsInvalidCondition(t *testing.T) {
	targeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{
				AllOf: []AnnouncementCondition{
					{Type: "balance", Operator: "between", Value: 10},
				},
			},
		},
	}
	_, err := targeting.NormalizeAndValidate()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAnnouncementInvalidTarget)
}

func TestAnnouncementTargeting_Matches_AndOrSemantics(t *testing.T) {
	targeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{
				AllOf: []AnnouncementCondition{
					{Type: AnnouncementConditionTypeBalance, Operator: AnnouncementOperatorGTE, Value: 100},
					{Type: AnnouncementConditionTypeSubscription, Operator: AnnouncementOperatorIn, GroupIDs: []int64{10}},
				},
			},
			{
				AllOf: []AnnouncementCondition{
					{Type: AnnouncementConditionTypeBalance, Operator: AnnouncementOperatorLT, Value: 5},
				},
			},
		},
	}

	// 命中第 2 组（balance < 5）
	require.True(t, targeting.Matches(domain.UserTargetingContext{Balance: 4.99}))
	require.False(t, targeting.Matches(domain.UserTargetingContext{Balance: 5}))

	// 命中第 1 组（balance >= 100 AND 订阅 in [10]）
	require.False(t, targeting.Matches(domain.UserTargetingContext{Balance: 100, ActiveSubscriptionGroupIDs: map[int64]struct{}{}}))
	require.False(t, targeting.Matches(domain.UserTargetingContext{Balance: 99.9, ActiveSubscriptionGroupIDs: map[int64]struct{}{10: {}}}))
	require.True(t, targeting.Matches(domain.UserTargetingContext{Balance: 100, ActiveSubscriptionGroupIDs: map[int64]struct{}{10: {}}}))
}

func TestAnnouncementTargeting_Matches_ReferralCondition(t *testing.T) {
	// 只展示给被邀请人
	hasInviterTargeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: AnnouncementConditionTypeReferral, Operator: AnnouncementOperatorEQ, ReferralValue: "has_inviter"},
			}},
		},
	}
	require.True(t, hasInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: true}))
	require.False(t, hasInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: false}))

	// 只展示给邀请人
	isInviterTargeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: AnnouncementConditionTypeReferral, Operator: AnnouncementOperatorEQ, ReferralValue: "is_inviter"},
			}},
		},
	}
	require.True(t, isInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, IsInviter: true}))
	require.False(t, isInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, IsInviter: false}))

	// 只展示给非被邀请人
	noInviterTargeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: AnnouncementConditionTypeReferral, Operator: AnnouncementOperatorEQ, ReferralValue: "no_inviter"},
			}},
		},
	}
	require.True(t, noInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: false}))
	require.False(t, noInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: true}))

	// 无效 referral_value → 不命中
	invalidTargeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: AnnouncementConditionTypeReferral, Operator: AnnouncementOperatorEQ, ReferralValue: "invalid"},
			}},
		},
	}
	require.False(t, invalidTargeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: true, IsInviter: true}))

	// ReferralKnown=false → fail-closed，所有 referral 条件不命中
	require.False(t, hasInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: false, HasInviter: true}))
	require.False(t, noInviterTargeting.Matches(domain.UserTargetingContext{ReferralKnown: false, HasInviter: false}))
}

func TestAnnouncementTargeting_NormalizeAndValidate_ReferralCondition(t *testing.T) {
	// Valid
	targeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: "referral", Operator: "eq", ReferralValue: "has_inviter"},
			}},
		},
	}
	result, err := targeting.NormalizeAndValidate()
	require.NoError(t, err)
	require.Len(t, result.AnyOf, 1)
	require.Equal(t, "has_inviter", result.AnyOf[0].AllOf[0].ReferralValue)

	// Invalid operator
	targeting2 := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: "referral", Operator: "gt", ReferralValue: "has_inviter"},
			}},
		},
	}
	_, err = targeting2.NormalizeAndValidate()
	require.Error(t, err)

	// Invalid referral_value
	targeting3 := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: "referral", Operator: "eq", ReferralValue: "bad_value"},
			}},
		},
	}
	_, err = targeting3.NormalizeAndValidate()
	require.Error(t, err)
}

func TestAnnouncementTargeting_Matches_CombinedReferralAndBalance(t *testing.T) {
	// 被邀请人 AND 余额 < 5 → 展示引导充值弹窗
	targeting := AnnouncementTargeting{
		AnyOf: []AnnouncementConditionGroup{
			{AllOf: []AnnouncementCondition{
				{Type: AnnouncementConditionTypeReferral, Operator: AnnouncementOperatorEQ, ReferralValue: "has_inviter"},
				{Type: AnnouncementConditionTypeBalance, Operator: AnnouncementOperatorLT, Value: 5},
			}},
		},
	}

	// 被邀请人 + 低余额 → 命中
	require.True(t, targeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: true, Balance: 3}))
	// 被邀请人 + 高余额 → 不命中
	require.False(t, targeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: true, Balance: 10}))
	// 非被邀请人 + 低余额 → 不命中
	require.False(t, targeting.Matches(domain.UserTargetingContext{ReferralKnown: true, HasInviter: false, Balance: 3}))
	// ReferralKnown=false → fail-closed
	require.False(t, targeting.Matches(domain.UserTargetingContext{ReferralKnown: false, HasInviter: true, Balance: 3}))
}
