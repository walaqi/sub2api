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

// --- helpers ---

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()
	if diff := got - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("%s: got %f, want %f (diff %f)", name, got, want, diff)
	}
}
