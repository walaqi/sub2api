package service

import (
	"errors"
	"testing"
	"time"

	"github.com/zeromicro/go-zero/core/collection"
)

func TestProvideTimingWheelService_ReturnsError(t *testing.T) {
	original := newTimingWheel
	t.Cleanup(func() { newTimingWheel = original })

	newTimingWheel = func(_ time.Duration, _ int, _ collection.Execute) (*collection.TimingWheel, error) {
		return nil, errors.New("boom")
	}

	svc, err := ProvideTimingWheelService()
	if err == nil {
		t.Fatalf("期望返回 error，但得到 nil")
	}
	if svc != nil {
		t.Fatalf("期望返回 nil svc，但得到非空")
	}
}

func TestProvideTimingWheelService_Success(t *testing.T) {
	svc, err := ProvideTimingWheelService()
	if err != nil {
		t.Fatalf("期望 err 为 nil，但得到: %v", err)
	}
	if svc == nil {
		t.Fatalf("期望 svc 非空，但得到 nil")
	}
	svc.Stop()
}

// TestProvideRedeemService_WiresReferralReward 守护 RedeemService 的邀请奖励注入。
// 背景：referralReward 曾以 wire_gen.go 手工 setter 注入，会被 go generate 冲掉
// （同 gift_engine SetPriorityGiftChecker 事故）。现改为 ProvideRedeemService 内注入，
// 本测试防止未来有人退回 NewRedeemService 导致兑换赚配额静默失效。
func TestProvideRedeemService_WiresReferralReward(t *testing.T) {
	referral := &ReferralRewardService{}
	svc := ProvideRedeemService(nil, nil, nil, nil, nil, nil, nil, nil, referral)
	if svc == nil {
		t.Fatalf("期望 svc 非空，但得到 nil")
	}
	if svc.referralReward != referral {
		t.Fatalf("ProvideRedeemService 未注入 referralReward（兑换赚配额将静默失效）")
	}
}

// TestProvidePaymentService_WiresReferralReward 守护 PaymentService 的邀请奖励注入。
// 同上：防止退回 NewPaymentService 或 go generate 冲掉手工 setter 导致充值赚配额静默失效。
func TestProvidePaymentService_WiresReferralReward(t *testing.T) {
	referral := &ReferralRewardService{}
	svc := ProvidePaymentService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, referral)
	if svc == nil {
		t.Fatalf("期望 svc 非空，但得到 nil")
	}
	if svc.referralReward != referral {
		t.Fatalf("ProvidePaymentService 未注入 referralReward（充值赚配额将静默失效）")
	}
}
