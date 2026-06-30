package domain

import "testing"

func TestNormalizeGiftDeduction(t *testing.T) {
	t.Parallel()

	ratio := func(v float64) *float64 { return &v }

	t.Run("empty mode normalizes to priority, ratio cleared", func(t *testing.T) {
		mode, r, err := NormalizeGiftDeduction("", ratio(0.5))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftDeductionModePriority {
			t.Errorf("mode = %q, want priority", mode)
		}
		if r != nil {
			t.Errorf("ratio = %v, want nil", r)
		}
	})

	t.Run("unknown mode normalizes to priority", func(t *testing.T) {
		mode, r, err := NormalizeGiftDeduction("bogus", ratio(0.5))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftDeductionModePriority || r != nil {
			t.Errorf("mode=%q ratio=%v, want priority/nil", mode, r)
		}
	})

	t.Run("priority forces ratio nil even if provided", func(t *testing.T) {
		mode, r, err := NormalizeGiftDeduction(GiftDeductionModePriority, ratio(2))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftDeductionModePriority || r != nil {
			t.Errorf("mode=%q ratio=%v, want priority/nil", mode, r)
		}
	})

	t.Run("ratio with valid value passes through", func(t *testing.T) {
		mode, r, err := NormalizeGiftDeduction(GiftDeductionModeRatio, ratio(0.5))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftDeductionModeRatio {
			t.Errorf("mode = %q, want ratio", mode)
		}
		if r == nil || *r != 0.5 {
			t.Errorf("ratio = %v, want 0.5", r)
		}
	})

	t.Run("ratio mode with nil ratio errors", func(t *testing.T) {
		if _, _, err := NormalizeGiftDeduction(GiftDeductionModeRatio, nil); err == nil {
			t.Error("expected error for ratio mode with nil ratio")
		}
	})

	t.Run("ratio mode with zero/negative ratio errors", func(t *testing.T) {
		if _, _, err := NormalizeGiftDeduction(GiftDeductionModeRatio, ratio(0)); err == nil {
			t.Error("expected error for ratio=0")
		}
		if _, _, err := NormalizeGiftDeduction(GiftDeductionModeRatio, ratio(-1)); err == nil {
			t.Error("expected error for ratio<0")
		}
	})

	t.Run("ratio above 10 errors", func(t *testing.T) {
		if _, _, err := NormalizeGiftDeduction(GiftDeductionModeRatio, ratio(10.1)); err == nil {
			t.Error("expected error for ratio>10")
		}
	})

	t.Run("ratio exactly 10 is allowed", func(t *testing.T) {
		mode, r, err := NormalizeGiftDeduction(GiftDeductionModeRatio, ratio(10))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftDeductionModeRatio || r == nil || *r != 10 {
			t.Errorf("mode=%q ratio=%v, want ratio/10", mode, r)
		}
	})
}

func TestNormalizeGiftExpiry(t *testing.T) {
	t.Parallel()

	days := func(v int) *int { return &v }

	t.Run("empty mode normalizes to discount_valid_until and clears days", func(t *testing.T) {
		mode, d, err := NormalizeGiftExpiry("", days(7))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftExpiryModeDiscountValidUntil || d != nil {
			t.Errorf("mode=%q days=%v, want discount_valid_until/nil", mode, d)
		}
	})

	t.Run("unknown mode normalizes to discount_valid_until", func(t *testing.T) {
		mode, d, err := NormalizeGiftExpiry("bogus", days(7))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftExpiryModeDiscountValidUntil || d != nil {
			t.Errorf("mode=%q days=%v, want discount_valid_until/nil", mode, d)
		}
	})

	t.Run("never clears days", func(t *testing.T) {
		mode, d, err := NormalizeGiftExpiry(GiftExpiryModeNever, days(7))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftExpiryModeNever || d != nil {
			t.Errorf("mode=%q days=%v, want never/nil", mode, d)
		}
	})

	t.Run("after_days requires positive days", func(t *testing.T) {
		if _, _, err := NormalizeGiftExpiry(GiftExpiryModeAfterDays, nil); err == nil {
			t.Error("expected error for after_days with nil days")
		}
		if _, _, err := NormalizeGiftExpiry(GiftExpiryModeAfterDays, days(0)); err == nil {
			t.Error("expected error for after_days with zero days")
		}
		if _, _, err := NormalizeGiftExpiry(GiftExpiryModeAfterDays, days(-1)); err == nil {
			t.Error("expected error for after_days with negative days")
		}
	})

	t.Run("after_days returns copied days", func(t *testing.T) {
		mode, d, err := NormalizeGiftExpiry(GiftExpiryModeAfterDays, days(15))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != GiftExpiryModeAfterDays || d == nil || *d != 15 {
			t.Errorf("mode=%q days=%v, want after_days/15", mode, d)
		}
	})
}
