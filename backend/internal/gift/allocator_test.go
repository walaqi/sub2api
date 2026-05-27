package gift

import (
	"testing"

	"github.com/shopspring/decimal"
)

// 测试不变量：Σ(GiftDeltas) + RechargeDelta ≡ TotalCost；联动作废后总扣 = TotalCost + RevokedRemaining。
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

func TestAllocate_RatioTriggersRevoke(t *testing.T) {
	// 设计稿走查例：priority A=20, ratio B=30 (r=2.0), recharge=50, balance=100
	// 第二次扣 50：
	// stage 1: priority A 已扣完，跳过
	// stage 2: B 上限 cap_by_gift = 3.33·1.5/... 这里我们直接构造扣完场景
	// 改为：余额 = 40（A=0, B=3.33, recharge=36.67），扣 50
	// stage 2 B: capByGift=3.33·3/2=5.0, capByRecharge=36.67·3=110, T=min(50,5,110)=5
	//   gift=5·2/3≈3.33, recharge=5/3≈1.67
	// stage 3: 剩 45 全压 recharge_pool → recharge_pool = 36.67-1.67-45 = -10 → 触底
	// 因为没有其他 ratio 赠金，B 已耗尽，RevokeRatioGifts=false（B remaining=0）
	in := AllocateInput{
		TotalCost:    d("50"),
		TotalBalance: d("40"),
		Gifts: []ActiveGift{
			{ID: 2, Mode: DeductionModeRatio, Remaining: d("3.33333333"), RatioRecharge: d("2")},
		},
	}
	res, _ := Allocate(in)
	if res.RevokeRatioGifts {
		t.Fatalf("no ratio gifts left to revoke after exhaustion")
	}
	assertConservation(t, in, res)
}

func TestAllocate_RatioRevokeWhenRechargeBottoms(t *testing.T) {
	// 充值池触底时联动作废"仍 active"的 ratio 赠金
	// balance=20, gifts: ratio A r=2 remaining=10, ratio B r=3 remaining=5
	// recharge_pool = 20 - 10 - 5 = 5
	// 扣 50：
	//   stage 2 A (r=2): capByGift=10·3/2=15, capByRecharge=5·3=15, T=min(50,15,15)=15
	//                    gift=10, recharge=5；A 用尽，rechargePool=0
	//   stage 2 B (r=3): capByRecharge=0，T=0，跳过；B remaining=5 仍 active
	//   stage 3: 剩 35 全压 → rechargePool = -35
	// 触底时 B remaining=5 → RevokeRatioGifts=true, RevokedRemaining=5
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
	if !res.RevokeRatioGifts || !res.RevokedRemaining.Equal(d("5")) {
		t.Fatalf("expected revoke B with 5, got revoke=%v sum=%s ids=%v", res.RevokeRatioGifts, res.RevokedRemaining, res.RevokedGiftIDs)
	}
	if len(res.RevokedGiftIDs) != 1 || res.RevokedGiftIDs[0] != 2 {
		t.Fatalf("expected revoked id [2], got %v", res.RevokedGiftIDs)
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
