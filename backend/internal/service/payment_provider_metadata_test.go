package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseInstanceMetadata(t *testing.T) {
	t.Run("empty input returns zero", func(t *testing.T) {
		meta := ParseInstanceMetadata("")
		assert.Empty(t, meta.Channels)
		assert.Nil(t, meta.BalanceRechargeMultiplier)
		assert.Nil(t, meta.ProductNamePrefix)
		assert.Nil(t, meta.ProductNameSuffix)
	})

	t.Run("invalid json returns zero", func(t *testing.T) {
		meta := ParseInstanceMetadata("{not valid json")
		assert.Empty(t, meta.Channels)
	})

	t.Run("parses channels and overrides", func(t *testing.T) {
		raw := `{
			"channels": {
				"epay":  {"label": "聚合支付", "icon_url": "https://cdn.example/icons/epay.png"},
				"qqpay": {"label": "QQ 钱包"}
			},
			"balance_recharge_multiplier": 1.05,
			"product_name_prefix": "聚合-",
			"product_name_suffix": ""
		}`
		meta := ParseInstanceMetadata(raw)
		assert.Equal(t, "聚合支付", meta.ChannelFor("epay").Label)
		assert.Equal(t, "https://cdn.example/icons/epay.png", meta.ChannelFor("epay").IconURL)
		assert.Equal(t, "QQ 钱包", meta.ChannelFor("qqpay").Label)
		assert.Empty(t, meta.ChannelFor("usdt").Label)
		assert.Equal(t, 1.05, meta.EffectiveMultiplier(1.0))
		assert.Equal(t, "聚合-", meta.EffectiveProductNamePrefix("default"))
		// Empty string is explicitly set: takes precedence over fallback.
		assert.Equal(t, "", meta.EffectiveProductNameSuffix("default"))
	})

	t.Run("multiplier fallback for invalid values", func(t *testing.T) {
		raw := `{"balance_recharge_multiplier": -1}`
		meta := ParseInstanceMetadata(raw)
		assert.Equal(t, 2.0, meta.EffectiveMultiplier(2.0))
	})

	t.Run("missing affixes return fallback", func(t *testing.T) {
		meta := ParseInstanceMetadata(`{"channels": {}}`)
		assert.Equal(t, "global-prefix", meta.EffectiveProductNamePrefix("global-prefix"))
		assert.Equal(t, "global-suffix", meta.EffectiveProductNameSuffix("global-suffix"))
	})
}
