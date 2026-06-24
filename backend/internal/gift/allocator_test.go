package gift

import (
	"testing"

	"github.com/shopspring/decimal"
)

// 测试不变量：Σ(GiftDeltas) + RechargeDelta ≡ TotalCost。
func assertConservation(t *testing.T, in AllocateInput, res AllocateResult) {
	t.Helper()
	sum := res.RechargeDelta
	for _, d := range res.GiftDeltas {
		sum = sum.Add(d)
	}
	if !sum.Equal(in.TotalCost) {
		t.Fatalf("conservation broken: Σ(deltas)=%s, totalCost=%s", sum.String(), in.TotalCost.String())
	}
}

func d(s string) decimal.Decimal {
	v, err := decimal.NewFromString(s)
	if err != nil {
		panic(err)
	}
	return v
}

func TestAllocate_PurePriority(t *testing.T) {
	in := AllocateInput{
		TotalCost:    d("30"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, err := Allocate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.GiftDeltas[1].Equal(d("30")) {
		t.Fatalf("priority gift should absorb 30, got %s", res.GiftDeltas[1])
	}
	if !res.RechargeDelta.Equal(decimal.Zero) {
		t.Fatalf("recharge_pool should not be touched, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_PriorityExhaustsThenRecharge(t *testing.T) {
	// priority=20, 充值池=80（balance=100-20）, 扣 60 → priority 全 20 + recharge 40
	in := AllocateInput{
		TotalCost:    d("60"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("20")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("20")) {
		t.Fatalf("priority should be fully consumed: %s", res.GiftDeltas[1])
	}
	if !res.RechargeDelta.Equal(d("40")) {
		t.Fatalf("recharge should absorb 40: %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_PureRatio_2to1(t *testing.T) {
	// ratio=30, ratio_recharge=2.0，充值池=70；扣 60
	// T 单位扣费分摊：gift=T·2/3, recharge=T/3
	// 上限 cap_by_gift = 30·3/2 = 45；cap_by_recharge = 70·3 = 210；T = min(60, 45, 210) = 45
	// 扣 45 后：gift_part=30, recharge_part=15；剩余 60-45=15 走 stage 3 → recharge 池
	// 最终：gift=30, recharge=15+15=30
	in := AllocateInput{
		TotalCost:    d("60"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("30"), RatioRecharge: d("2")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("30")) {
		t.Fatalf("ratio gift expected 30, got %s", res.GiftDeltas[1])
	}
	if !res.RechargeDelta.Equal(d("30")) {
		t.Fatalf("recharge expected 30, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_MultipleRatio_LowerFirst(t *testing.T) {
	// 两笔 ratio：A r=0.5（先消耗）, B r=2.0
	// remaining: A=10, B=20，充值池=70（balance=100-30），扣 30
	// stage 2 - A：cap_by_gift=10·1.5/0.5=30, T = min(30, 30, 70·1.5) = 30
	//   gift=30·0.5/1.5=10（A 全用尽）, recharge=20
	//   剩余 0 → stage 2 结束（B 不动）
	in := AllocateInput{
		TotalCost:    d("30"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("10"), RatioRecharge: d("0.5")},
			{ID: 2, Mode: DeductionModeRatio, Remaining: d("20"), RatioRecharge: d("2")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("10")) {
		t.Fatalf("low-ratio A expected 10, got %s", res.GiftDeltas[1])
	}
	if _, exists := res.GiftDeltas[2]; exists {
		t.Fatalf("high-ratio B should not be touched, got %s", res.GiftDeltas[2])
	}
	if !res.RechargeDelta.Equal(d("20")) {
		t.Fatalf("recharge expected 20, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_RatioNoRevoke_GiftExhausted(t *testing.T) {
	// When ratio gift is fully consumed during stage 2, no remaining to worry about.
	// balance = 40 (ratio gift remaining=3.33, rechargePool=36.67), deduct 50
	// stage 2: capByGift=3.33·3/2=5.0, T=min(50,5,36.67·3)=5
	//   gift≈3.33, recharge≈1.67
	// stage 3: 45 → rechargePool goes negative (OK, no revoke)
	in := AllocateInput{
		TotalCost:    d("50"),
		TotalBalance: d("40"),
		Gifts: []ActiveGift{
			{ID: 2, Mode: DeductionModeRatio, Remaining: d("3.33333333"), RatioRecharge: d("2")},
		},
	}
	res, _ := Allocate(in)
	assertConservation(t, in, res)
}

func TestAllocate_RatioNoRevoke_RechargeBottoms(t *testing.T) {
	// Previously this test asserted RevokeRatioGifts=true. Now ratio gifts
	// are NOT revoked — they remain active and dormant until user recharges.
	// balance=20, gifts: ratio A r=2 remaining=10, ratio B r=3 remaining=5
	// recharge_pool = 20 - 10 - 5 = 5
	// stage 2 A (r=2): capByGift=10·3/2=15, capByRecharge=5·3=15, T=min(50,15,15)=15
	//                  gift=10, recharge=5; A exhausted, rechargePool=0
	// stage 2 B (r=3): capByRecharge=0, T=0, skip; B remaining=5 stays active
	// stage 3: 35 all to rechargePool → goes negative
	// B is NOT revoked (remains active for when user recharges).
	in := AllocateInput{
		TotalCost:    d("50"),
		TotalBalance: d("20"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("10"), RatioRecharge: d("2")},
			{ID: 2, Mode: DeductionModeRatio, Remaining: d("5"), RatioRecharge: d("3")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("10")) {
		t.Fatalf("A should be fully consumed, got %s", res.GiftDeltas[1])
	}
	// B should NOT be touched (no revoke, no deduction)
	if _, exists := res.GiftDeltas[2]; exists {
		t.Fatalf("B should not be deducted, got %s", res.GiftDeltas[2])
	}
	assertConservation(t, in, res)
}

func TestAllocate_RatioSkippedWhenRechargePoolZero(t *testing.T) {
	// User 518 scenario: only ratio gift, rechargePool=0 from the start.
	// balance=60, ratio gift remaining=60 → rechargePool = 60-60 = 0
	// stage 2: capByRecharge=0, ratio gift NOT consumed
	// stage 3: full cost goes to recharge (overdraft)
	// ratio gift remains active (not revoked).
	in := AllocateInput{
		TotalCost:    d("0.53"),
		TotalBalance: d("60"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("60"), RatioRecharge: d("2")},
		},
	}
	res, _ := Allocate(in)
	// ratio gift should not be consumed
	if _, exists := res.GiftDeltas[1]; exists {
		t.Fatalf("ratio gift should not be consumed when rechargePool=0, got %s", res.GiftDeltas[1])
	}
	// full cost goes to recharge pool (overdraft)
	if !res.RechargeDelta.Equal(d("0.53")) {
		t.Fatalf("recharge expected 0.53, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_PriorityPlusRatioPlusRecharge(t *testing.T) {
	// 设计稿走查例 (扣 60)：A priority=20, B ratio r=2 remaining=30, recharge=50, balance=100
	// stage 1: A 扣 20 → remaining 40
	// stage 2 B: capByGift=30·3/2=45, capByRecharge=50·3=150, T=min(40,45,150)=40
	//   gift=40·2/3=26.6666..., recharge=40/3=13.3333...
	in := AllocateInput{
		TotalCost:    d("60"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("20")},
			{ID: 2, Mode: DeductionModeRatio, Remaining: d("30"), RatioRecharge: d("2")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("20")) {
		t.Fatalf("priority A expected 20, got %s", res.GiftDeltas[1])
	}
	// 由于 8 位舍入，gift_part 与 recharge_part 不会精确为分数
	// 只断言守恒
	assertConservation(t, in, res)
}

func TestAllocate_PriorityCoversWhenRechargePoolZero(t *testing.T) {
	// User has priority gift and rechargePool=0.
	// priority gift can independently support requests.
	// balance=50, priority gift remaining=50 → rechargePool=0
	// stage 1: priority absorbs full cost
	in := AllocateInput{
		TotalCost:    d("10"),
		TotalBalance: d("50"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("10")) {
		t.Fatalf("priority should absorb 10, got %s", res.GiftDeltas[1])
	}
	if !res.RechargeDelta.IsZero() {
		t.Fatalf("recharge should be zero, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_ZeroCost_NoOp(t *testing.T) {
	in := AllocateInput{
		TotalCost:    decimal.Zero,
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("20")},
		},
	}
	res, _ := Allocate(in)
	if len(res.GiftDeltas) != 0 || !res.RechargeDelta.IsZero() {
		t.Fatalf("zero cost should be no-op, got %+v", res)
	}
}

func TestAllocate_PrecisionTiny(t *testing.T) {
	// 极小值（1e-8）扣费验证 decimal 精度
	in := AllocateInput{
		TotalCost:    d("0.00000001"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModePriority, Remaining: d("0.00000005")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("0.00000001")) {
		t.Fatalf("tiny precision lost: %s", res.GiftDeltas[1])
	}
	assertConservation(t, in, res)
}

func TestAllocate_NegativeCostRejected(t *testing.T) {
	_, err := Allocate(AllocateInput{TotalCost: d("-1"), TotalBalance: d("100")})
	if err == nil {
		t.Fatal("expected error for negative cost")
	}
}
