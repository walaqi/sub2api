//go:build unit

package keybind

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_RechargeDiscount_Populated(t *testing.T) {
	client := newWindowTestClient(t)
	resolver := NewBindKeyGiftSettingResolver(client)

	// Write a setting with recharge discount config
	_, err := client.BindKeyGiftSetting.Create().
		SetAPIKeyID(100).
		SetDeductionMode("priority").
		SetConfig(&domain.BindKeyConfig{
			RechargeDiscount: &domain.BindKeyRechargeDiscount{
				Enabled:               true,
				DiscountRate:          0.15,
				MaxDiscountableAmount: 500,
				ValidDays:             30,
			},
		}).
		Save(context.Background())
	require.NoError(t, err)

	setting, err := resolver.Resolve(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, setting)
	require.NotNil(t, setting.RechargeDiscount)
	assert.True(t, setting.RechargeDiscount.Enabled)
	assert.Equal(t, 0.15, setting.RechargeDiscount.DiscountRate)
	assert.Equal(t, 500.0, setting.RechargeDiscount.MaxDiscountableAmount)
	assert.Equal(t, 30, setting.RechargeDiscount.ValidDays)
}

func TestResolver_RechargeDiscount_Nil_WhenNotSet(t *testing.T) {
	client := newWindowTestClient(t)
	resolver := NewBindKeyGiftSettingResolver(client)

	// Write a setting without recharge discount
	_, err := client.BindKeyGiftSetting.Create().
		SetAPIKeyID(101).
		SetDeductionMode("priority").
		Save(context.Background())
	require.NoError(t, err)

	setting, err := resolver.Resolve(context.Background(), 101)
	require.NoError(t, err)
	require.NotNil(t, setting)
	assert.Nil(t, setting.RechargeDiscount)
}

func TestResolver_RechargeDiscount_NotFound(t *testing.T) {
	client := newWindowTestClient(t)
	resolver := NewBindKeyGiftSettingResolver(client)

	setting, err := resolver.Resolve(context.Background(), 999)
	require.NoError(t, err)
	assert.Nil(t, setting)
}

func TestResolveRechargeDiscountConfig_Validates(t *testing.T) {
	svc := &Service{}

	tests := []struct {
		name    string
		setting *BindKeyGiftSetting
		wantNil bool
	}{
		{
			name:    "nil setting",
			setting: nil,
			wantNil: true,
		},
		{
			name:    "nil RechargeDiscount",
			setting: &BindKeyGiftSetting{},
			wantNil: true,
		},
		{
			name: "disabled",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               false,
					DiscountRate:          0.1,
					MaxDiscountableAmount: 100,
					ValidDays:             7,
				},
			},
			wantNil: true,
		},
		{
			name: "zero rate",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               true,
					DiscountRate:          0,
					MaxDiscountableAmount: 100,
					ValidDays:             7,
				},
			},
			wantNil: true,
		},
		{
			name: "rate over 10",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               true,
					DiscountRate:          10.5,
					MaxDiscountableAmount: 100,
					ValidDays:             7,
				},
			},
			wantNil: true,
		},
		{
			name: "zero max amount",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               true,
					DiscountRate:          0.1,
					MaxDiscountableAmount: 0,
					ValidDays:             7,
				},
			},
			wantNil: true,
		},
		{
			name: "zero valid days",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               true,
					DiscountRate:          0.1,
					MaxDiscountableAmount: 100,
					ValidDays:             0,
				},
			},
			wantNil: true,
		},
		{
			name: "valid config",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               true,
					DiscountRate:          0.2,
					MaxDiscountableAmount: 1000,
					ValidDays:             14,
				},
			},
			wantNil: false,
		},
		{
			name: "rate exactly 10 is valid",
			setting: &BindKeyGiftSetting{
				RechargeDiscount: &domain.BindKeyRechargeDiscount{
					Enabled:               true,
					DiscountRate:          10.0,
					MaxDiscountableAmount: 50,
					ValidDays:             1,
				},
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.resolveRechargeDiscountConfig(tt.setting)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}
