package gift

import (
	"testing"

	"github.com/shopspring/decimal"
)

func i64(v int64) *int64 { return &v }

// ---------------------------------------------------------------------------
// partitionByGroup: 分组切分（eligible / ineligibleRemaining）
// ---------------------------------------------------------------------------

func TestPartitionByGroup_GlobalAlwaysEligible(t *testing.T) {
	gifts := []ActiveGift{
		{ID: 1, Remaining: d("10")},                  // 全局
		{ID: 2, Remaining: d("20"), GroupID: i64(5)}, // A 组
	}
	// 请求在 A 组：全局 + A 组 eligible。
	elig, ineligible := partitionByGroup(gifts, i64(5))
	if len(elig) != 2 {
		t.Fatalf("expected 2 eligible, got %d", len(elig))
	}
	if !ineligible.Equal(decimal.Zero) {
		t.Fatalf("expected 0 ineligible, got %s", ineligible)
	}
}

func TestPartitionByGroup_CrossGroupIneligible(t *testing.T) {
	gifts := []ActiveGift{
		{ID: 1, Remaining: d("10")},                  // 全局
		{ID: 2, Remaining: d("20"), GroupID: i64(5)}, // A 组
	}
	// 请求在 B 组(=7)：只有全局 eligible，A 组的 20 归 ineligible。
	elig, ineligible := partitionByGroup(gifts, i64(7))
	if len(elig) != 1 || elig[0].ID != 1 {
		t.Fatalf("expected only global eligible, got %+v", elig)
	}
	if !ineligible.Equal(d("20")) {
		t.Fatalf("expected 20 ineligible, got %s", ineligible)
	}
}

func TestPartitionByGroup_NilRequestGroupOnlyGlobal(t *testing.T) {
	gifts := []ActiveGift{
		{ID: 1, Remaining: d("10")},                  // 全局
		{ID: 2, Remaining: d("20"), GroupID: i64(5)}, // A 组
	}
	// 请求无分组：只有全局 eligible，带分组的全归 ineligible。
	elig, ineligible := partitionByGroup(gifts, nil)
	if len(elig) != 1 || elig[0].ID != 1 {
		t.Fatalf("expected only global eligible, got %+v", elig)
	}
	if !ineligible.Equal(d("20")) {
		t.Fatalf("expected 20 ineligible, got %s", ineligible)
	}
}

// ---------------------------------------------------------------------------
// IneligibleGiftRemaining: 全局充值池不变量（cx-s2 R1 #1 核心例）
// ---------------------------------------------------------------------------

func TestAllocate_IneligibleGiftNotSpentCrossGroup(t *testing.T) {
	// balance 100，A 组 priority 赠金 remaining 100，请求在 B 组。
	// eligible=[]，ineligibleRemaining=100 → rechargePool = 100−0−100 = 0（不是 100）。
	// 扣 30 → 全部落充值池（透支），A 组赠金分文不动。
	in := AllocateInput{
		TotalCost:               d("30"),
		TotalBalance:            d("100"),
		Gifts:                   nil, // eligible 子集为空
		IneligibleGiftRemaining: d("100"),
	}
	res, err := Allocate(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GiftDeltas) != 0 {
		t.Fatalf("ineligible gift must not be spent, got %+v", res.GiftDeltas)
	}
	if !res.RechargeDelta.Equal(d("30")) {
		t.Fatalf("expected 30 recharge (overdraft), got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_EligibleGlobalWithIneligibleSibling(t *testing.T) {
	// balance 100：全局 priority 20（eligible）+ 别组赠金 30（ineligible）。
	// rechargePool = 100 − 20 − 30 = 50。扣 40 → 全局 20 + 充值池 20。
	in := AllocateInput{
		TotalCost:               d("40"),
		TotalBalance:            d("100"),
		Gifts:                   []ActiveGift{{ID: 1, Mode: DeductionModePriority, Remaining: d("20")}},
		IneligibleGiftRemaining: d("30"),
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("20")) {
		t.Fatalf("eligible global priority expected 20, got %s", res.GiftDeltas[1])
	}
	if !res.RechargeDelta.Equal(d("20")) {
		t.Fatalf("recharge expected 20, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

// ---------------------------------------------------------------------------
// Stage 0: 置顶（绝对第一）
// ---------------------------------------------------------------------------

func TestAllocate_PinnedRatioBeforePriority(t *testing.T) {
	// 决策"绝对第一"：置顶的 ratio 赠金先于 priority 消费。
	// balance=100；置顶 ratio r=1 remaining=50，普通 priority remaining=50。
	// rechargePool = 100 − 50 − 50 = 0 → 置顶 ratio 无充值池配对（休眠），Stage 0 取 0；
	// 退回 Stage 1 由 priority 承担。扣 30 → priority 30。
	// （验证置顶 ratio 在 rechargePool≤0 时休眠、不抢占，且不 panic。）
	in := AllocateInput{
		TotalCost:    d("30"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("50"), RatioRecharge: d("1"), Pinned: true},
			{ID: 2, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, _ := Allocate(in)
	if _, ok := res.GiftDeltas[1]; ok {
		t.Fatalf("pinned ratio should be dormant at rechargePool=0, got %s", res.GiftDeltas[1])
	}
	if !res.GiftDeltas[2].Equal(d("30")) {
		t.Fatalf("priority should absorb 30, got %s", res.GiftDeltas[2])
	}
	assertConservation(t, in, res)
}

func TestAllocate_PinnedRatioDrainsBeforePriorityWhenPoolAvailable(t *testing.T) {
	// 置顶 ratio r=1 remaining=10；普通 priority remaining=50；balance=100。
	// rechargePool = 100 − 10 − 50 = 40 > 0 → 置顶 ratio 先消费（绝对第一）。
	// 扣 10：Stage 0 ratio r=1 → gift_part=T/2, recharge_part=T/2；
	//   capByGift=10·2/1=20, capByRecharge=40·2=80, T=min(10,20,80)=10 → gift=5, recharge=5。
	// 全部 10 由置顶 ratio 消化，priority 分文不动 —— 证明置顶 ratio 抢在 priority 之前。
	in := AllocateInput{
		TotalCost:    d("10"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 1, Mode: DeductionModeRatio, Remaining: d("10"), RatioRecharge: d("1"), Pinned: true},
			{ID: 2, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[1].Equal(d("5")) {
		t.Fatalf("pinned ratio gift_part should be 5, got %s", res.GiftDeltas[1])
	}
	if _, ok := res.GiftDeltas[2]; ok {
		t.Fatalf("priority must not be touched (pinned ratio drained first), got %s", res.GiftDeltas[2])
	}
	if !res.RechargeDelta.Equal(d("5")) {
		t.Fatalf("recharge expected 5, got %s", res.RechargeDelta)
	}
	assertConservation(t, in, res)
}

func TestAllocate_PinnedPriorityFirst(t *testing.T) {
	// 置顶 priority 赠金优先于其它 priority 消费（Stage 0）。
	// balance=100；置顶 priority id2 remaining=15，普通 priority id1 remaining=50。
	// 扣 10 → 全部由置顶 id2 承担（id1 不动）。
	in := AllocateInput{
		TotalCost:    d("10"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 2, Mode: DeductionModePriority, Remaining: d("15"), Pinned: true},
			{ID: 1, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[2].Equal(d("10")) {
		t.Fatalf("pinned priority should absorb 10, got %s", res.GiftDeltas[2])
	}
	if _, ok := res.GiftDeltas[1]; ok {
		t.Fatalf("non-pinned priority should not be touched, got %s", res.GiftDeltas[1])
	}
	assertConservation(t, in, res)
}

func TestAllocate_PinnedNotDoubleCounted(t *testing.T) {
	// 置顶 priority 用尽后，剩余由其它 priority 承担；置顶项不被 Stage 1 重复计数。
	// balance=100；置顶 priority id2 remaining=10，普通 priority id1 remaining=50。扣 30。
	// Stage 0: id2 全 10；Stage 1: id1 承担 20。
	in := AllocateInput{
		TotalCost:    d("30"),
		TotalBalance: d("100"),
		Gifts: []ActiveGift{
			{ID: 2, Mode: DeductionModePriority, Remaining: d("10"), Pinned: true},
			{ID: 1, Mode: DeductionModePriority, Remaining: d("50")},
		},
	}
	res, _ := Allocate(in)
	if !res.GiftDeltas[2].Equal(d("10")) {
		t.Fatalf("pinned should be 10, got %s", res.GiftDeltas[2])
	}
	if !res.GiftDeltas[1].Equal(d("20")) {
		t.Fatalf("non-pinned priority should absorb 20, got %s", res.GiftDeltas[1])
	}
	assertConservation(t, in, res)
}
