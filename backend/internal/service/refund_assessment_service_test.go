//go:build unit

package service

import (
	"testing"
)

func TestAllocateFIFO_Empty(t *testing.T) {
	var slots []PoolSlot
	AllocateFIFO(slots, 100)
	if len(slots) != 0 {
		t.Fatal("expected empty slots")
	}
}

func TestAllocateFIFO_ZeroUsed(t *testing.T) {
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.5},
		{Amount: 100, Ratio: 1.0},
	}
	AllocateFIFO(slots, 0)
	for i, s := range slots {
		if s.Consumed != 0 {
			t.Errorf("slot %d: expected consumed=0, got %f", i, s.Consumed)
		}
		if s.Remaining != s.Amount {
			t.Errorf("slot %d: expected remaining=%f, got %f", i, s.Amount, s.Remaining)
		}
	}
}

func TestAllocateFIFO_PartialFirstSlot(t *testing.T) {
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.5},  // pay=100, 1:2
		{Amount: 300, Ratio: 0.333},
	}
	AllocateFIFO(slots, 150)

	if slots[0].Consumed != 150 {
		t.Errorf("slot 0: expected consumed=150, got %f", slots[0].Consumed)
	}
	if slots[0].Remaining != 50 {
		t.Errorf("slot 0: expected remaining=50, got %f", slots[0].Remaining)
	}
	assertClose(t, "slot 0 consumed_money", slots[0].ConsumedMoney, 75.0)

	if slots[1].Consumed != 0 {
		t.Errorf("slot 1: expected consumed=0, got %f", slots[1].Consumed)
	}
	if slots[1].Remaining != 300 {
		t.Errorf("slot 1: expected remaining=300, got %f", slots[1].Remaining)
	}
}

func TestAllocateFIFO_SpansMultipleSlots(t *testing.T) {
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.5},   // 付费 1:2
		{Amount: 50, Ratio: 0},      // 免费 admin
		{Amount: 300, Ratio: 0.333}, // 付费 1:3
	}
	AllocateFIFO(slots, 280)

	// slot 0: 全消耗
	if slots[0].Consumed != 200 {
		t.Errorf("slot 0: expected consumed=200, got %f", slots[0].Consumed)
	}
	assertClose(t, "slot 0 consumed_money", slots[0].ConsumedMoney, 100.0)

	// slot 1: 全消耗（免费）
	if slots[1].Consumed != 50 {
		t.Errorf("slot 1: expected consumed=50, got %f", slots[1].Consumed)
	}
	if slots[1].ConsumedMoney != 0 {
		t.Errorf("slot 1: expected consumed_money=0, got %f", slots[1].ConsumedMoney)
	}

	// slot 2: 消耗 30
	if slots[2].Consumed != 30 {
		t.Errorf("slot 2: expected consumed=30, got %f", slots[2].Consumed)
	}
	assertClose(t, "slot 2 consumed_money", slots[2].ConsumedMoney, 9.99)
	if slots[2].Remaining != 270 {
		t.Errorf("slot 2: expected remaining=270, got %f", slots[2].Remaining)
	}
}

func TestAllocateFIFO_ExceedsTotal(t *testing.T) {
	slots := []PoolSlot{
		{Amount: 100, Ratio: 1.0},
		{Amount: 50, Ratio: 0},
	}
	// totalUsed > sum of all slots — should cap at slot amounts
	AllocateFIFO(slots, 200)

	if slots[0].Consumed != 100 {
		t.Errorf("slot 0: expected consumed=100, got %f", slots[0].Consumed)
	}
	if slots[1].Consumed != 50 {
		t.Errorf("slot 1: expected consumed=50, got %f", slots[1].Consumed)
	}
}

func TestAllocateFIFO_RefundScenario(t *testing.T) {
	// 模拟：用户充了200(1:2)，admin给50，充了300(1:3)
	// API消耗=250，退费扣减=50 → effective=300
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.5},
		{Amount: 50, Ratio: 0},
		{Amount: 300, Ratio: 0.333},
	}
	effectiveUsed := 300.0
	AllocateFIFO(slots, effectiveUsed)

	// slot 0: 200 全消耗
	if slots[0].Consumed != 200 {
		t.Errorf("slot 0: expected consumed=200, got %f", slots[0].Consumed)
	}
	// slot 1: 50 全消耗
	if slots[1].Consumed != 50 {
		t.Errorf("slot 1: expected consumed=50, got %f", slots[1].Consumed)
	}
	// slot 2: 50 消耗
	if slots[2].Consumed != 50 {
		t.Errorf("slot 2: expected consumed=50, got %f", slots[2].Consumed)
	}
	assertClose(t, "slot 2 consumed_money", slots[2].ConsumedMoney, 16.65)
	if slots[2].Remaining != 250 {
		t.Errorf("slot 2: expected remaining=250, got %f", slots[2].Remaining)
	}
}

func TestComputeSummary(t *testing.T) {
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.5, Consumed: 200, ConsumedMoney: 100},
		{Amount: 50, Ratio: 0, Consumed: 50, ConsumedMoney: 0},
		{Amount: 300, Ratio: 0.333, Consumed: 50, ConsumedMoney: 16.65},
	}
	s := computeSummary(slots)

	assertClose(t, "total_paid_credited", s.TotalPaidCredited, 500.0)
	assertClose(t, "total_free_credited", s.TotalFreeCredited, 50.0)
	assertClose(t, "total_paid_consumed", s.TotalPaidConsumed, 250.0)
	assertClose(t, "total_free_consumed", s.TotalFreeConsumed, 50.0)
	assertClose(t, "total_paid_money_spent", s.TotalPaidMoneySpent, 116.65)
}

func TestMaskCode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ABC", "ABC"},
		{"ABCDEF", "ABCDEF"},
		{"ABCDEFGHIJ", "ABC***HIJ"},
	}
	for _, tc := range cases {
		got := maskCode(tc.in)
		if got != tc.want {
			t.Errorf("maskCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- Gap compensation tests ---

// buildGapSlots 模拟 Assess 中 step 5.1 的 gap 补偿逻辑（纯函数提取，方便单测）。
// effectiveUsed = totalRechargeUsed + totalRefundDeducted
// rawPool = 用户当前真实充值池（允许负值）
func buildGapSlots(slots []PoolSlot, effectiveUsed, rawPool float64) []PoolSlot {
	totalEverCredited := effectiveUsed + rawPool
	slotSum := 0.0
	for _, sl := range slots {
		slotSum += sl.Amount
	}
	if gap := roundTo8(totalEverCredited - slotSum); gap > 0.01 {
		slots = append([]PoolSlot{{
			Source:    "signup_grant",
			SourceID:  0,
			Amount:    gap,
			PayAmount: 0,
			Ratio:     0,
			Note:      "注册赠送 / 未追踪入账",
		}}, slots...)
	}
	return slots
}

func TestGapCompensation_NoGap(t *testing.T) {
	// 用户消耗 400，余额 10，slots 总额正好 410 → 无 gap
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.1},
		{Amount: 200, Ratio: 0.1},
		{Amount: 10, Ratio: 0},
	}
	result := buildGapSlots(slots, 400, 10)
	if len(result) != 3 {
		t.Fatalf("expected 3 slots (no gap), got %d", len(result))
	}
}

func TestGapCompensation_HasGap(t *testing.T) {
	// 用户消耗 460，余额 0，slots 总额 410 → gap = 50
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.1},
		{Amount: 200, Ratio: 0.1},
		{Amount: 10, Ratio: 0},
	}
	result := buildGapSlots(slots, 460, 0)
	if len(result) != 4 {
		t.Fatalf("expected 4 slots (gap prepended), got %d", len(result))
	}
	gap := result[0]
	if gap.Source != "signup_grant" {
		t.Errorf("gap slot source = %q, want signup_grant", gap.Source)
	}
	assertClose(t, "gap amount", gap.Amount, 50.0)
	if gap.Ratio != 0 {
		t.Errorf("gap slot ratio = %f, want 0 (free)", gap.Ratio)
	}
}

func TestGapCompensation_NegativePool(t *testing.T) {
	// 用户透支: 消耗 460.57，余额 -0.57，slots 总额 410
	// rawPool = -0.57 → totalEverCredited = 460.57 + (-0.57) = 460 → gap = 50 (NOT 50.57)
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.1},
		{Amount: 200, Ratio: 0.1},
		{Amount: 10, Ratio: 0},
	}
	result := buildGapSlots(slots, 460.57, -0.57)
	if len(result) != 4 {
		t.Fatalf("expected 4 slots (gap prepended), got %d", len(result))
	}
	assertClose(t, "gap amount with negative pool", result[0].Amount, 50.0)
}

func TestGapCompensation_NegativePoolNoGap(t *testing.T) {
	// 用户透支但 slot 总额 >= totalEverCredited → 无 gap
	// 消耗 50，余额 -5，slots 总额 100 → totalEverCredited = 45 < 100
	slots := []PoolSlot{
		{Amount: 100, Ratio: 1.0},
	}
	result := buildGapSlots(slots, 50, -5)
	if len(result) != 1 {
		t.Fatalf("expected 1 slot (no gap), got %d", len(result))
	}
}

// --- Redeem slot ratio tests ---

func TestAllocateFIFO_RedeemWithRealRatio(t *testing.T) {
	// 模拟10倍充值兑换码: 付20到账200, ratio=0.1
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.1, PayAmount: 20},
		{Amount: 200, Ratio: 0.1, PayAmount: 20},
		{Amount: 10, Ratio: 0, PayAmount: 0}, // 推荐返佣 (免费)
	}
	AllocateFIFO(slots, 410)

	// slot 0: 200 全消耗, consumed_money = 200 * 0.1 = 20
	assertClose(t, "slot 0 consumed", slots[0].Consumed, 200.0)
	assertClose(t, "slot 0 consumed_money", slots[0].ConsumedMoney, 20.0)
	assertClose(t, "slot 0 remaining", slots[0].Remaining, 0.0)

	// slot 1: 200 全消耗, consumed_money = 200 * 0.1 = 20
	assertClose(t, "slot 1 consumed", slots[1].Consumed, 200.0)
	assertClose(t, "slot 1 consumed_money", slots[1].ConsumedMoney, 20.0)
	assertClose(t, "slot 1 remaining", slots[1].Remaining, 0.0)

	// slot 2: 10 全消耗, consumed_money = 0 (免费)
	assertClose(t, "slot 2 consumed", slots[2].Consumed, 10.0)
	assertClose(t, "slot 2 consumed_money", slots[2].ConsumedMoney, 0.0)
}

func TestAllocateFIFO_RedeemPartialConsumption(t *testing.T) {
	// 付20到账200(10x), 只消耗了100 → consumed_money = 100*0.1 = 10, 可退 = 20-10 = 10
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.1, PayAmount: 20},
	}
	AllocateFIFO(slots, 100)

	assertClose(t, "consumed", slots[0].Consumed, 100.0)
	assertClose(t, "consumed_money", slots[0].ConsumedMoney, 10.0)
	assertClose(t, "remaining", slots[0].Remaining, 100.0)

	// 可退实付 = pay_amount - consumed_money
	refundable := slots[0].PayAmount - slots[0].ConsumedMoney
	assertClose(t, "refundable", refundable, 10.0)
}

func TestComputeSummary_RedeemWithRatio(t *testing.T) {
	// redeem_balance 但有 ratio>0 应计入 paid 类
	slots := []PoolSlot{
		{Source: "redeem_balance", Amount: 200, Ratio: 0.1, Consumed: 200, ConsumedMoney: 20},
		{Source: "affiliate_transfer", Amount: 10, Ratio: 0, Consumed: 10, ConsumedMoney: 0},
	}
	s := computeSummary(slots)

	assertClose(t, "total_paid_credited", s.TotalPaidCredited, 200.0)
	assertClose(t, "total_free_credited", s.TotalFreeCredited, 10.0)
	assertClose(t, "total_paid_consumed", s.TotalPaidConsumed, 200.0)
	assertClose(t, "total_free_consumed", s.TotalFreeConsumed, 10.0)
	assertClose(t, "total_paid_money_spent", s.TotalPaidMoneySpent, 20.0)
}

func TestGapCompensation_ThenFIFO(t *testing.T) {
	// 端到端: gap补偿后执行FIFO，验证合成slot被正确消耗
	// 用户有50注册赠送(gap)、消耗460、余额0、slots=410
	slots := []PoolSlot{
		{Amount: 200, Ratio: 0.1, PayAmount: 20},
		{Amount: 200, Ratio: 0.1, PayAmount: 20},
		{Amount: 10, Ratio: 0, PayAmount: 0},
	}
	effectiveUsed := 460.0
	rawPool := 0.0

	slots = buildGapSlots(slots, effectiveUsed, rawPool)
	AllocateFIFO(slots, effectiveUsed)

	// slot 0 = gap (signup_grant), amount=50, ratio=0
	assertClose(t, "gap consumed", slots[0].Consumed, 50.0)
	assertClose(t, "gap consumed_money", slots[0].ConsumedMoney, 0.0) // free
	assertClose(t, "gap remaining", slots[0].Remaining, 0.0)

	// slot 1 = 200, ratio=0.1
	assertClose(t, "slot 1 consumed", slots[1].Consumed, 200.0)
	assertClose(t, "slot 1 consumed_money", slots[1].ConsumedMoney, 20.0)

	// slot 2 = 200, ratio=0.1
	assertClose(t, "slot 2 consumed", slots[2].Consumed, 200.0)
	assertClose(t, "slot 2 consumed_money", slots[2].ConsumedMoney, 20.0)

	// slot 3 = 10, ratio=0 (affiliate)
	assertClose(t, "slot 3 consumed", slots[3].Consumed, 10.0)
	assertClose(t, "slot 3 consumed_money", slots[3].ConsumedMoney, 0.0)

	// 汇总
	summary := computeSummary(slots)
	assertClose(t, "paid_credited", summary.TotalPaidCredited, 400.0)
	assertClose(t, "free_credited", summary.TotalFreeCredited, 60.0) // gap(50) + affiliate(10)
	assertClose(t, "paid_money_spent", summary.TotalPaidMoneySpent, 40.0)
}

// --- helpers ---

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()
	if diff := got - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("%s: got %f, want %f (diff %f)", name, got, want, diff)
	}
}
