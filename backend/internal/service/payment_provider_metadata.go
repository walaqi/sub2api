package service

import (
	"encoding/json"
	"math"
	"strings"
)

// ProviderInstanceMetadata is the structured representation of
// PaymentProviderInstance.metadata (a free-form JSON text column).
//
// It is intentionally additive: every field is optional so a missing or
// blank metadata column always parses to a zero value, and the runtime
// falls back to global PaymentConfig values.
type ProviderInstanceMetadata struct {
	Channels                  map[string]ChannelMetadata `json:"channels,omitempty"`
	BalanceRechargeMultiplier *float64                   `json:"balance_recharge_multiplier,omitempty"`
	ProductNamePrefix         *string                    `json:"product_name_prefix,omitempty"`
	ProductNameSuffix         *string                    `json:"product_name_suffix,omitempty"`
}

// ChannelMetadata holds per-payment-type display overrides for a single
// instance (keyed by the literal supported_types string).
type ChannelMetadata struct {
	Label   string `json:"label,omitempty"`
	IconURL string `json:"icon_url,omitempty"`
}

// ParseInstanceMetadata decodes the raw metadata string. Empty/invalid
// input returns a zero value — callers must treat the result as a hint,
// not a contract.
func ParseInstanceMetadata(raw string) ProviderInstanceMetadata {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ProviderInstanceMetadata{}
	}
	var meta ProviderInstanceMetadata
	if err := json.Unmarshal([]byte(trimmed), &meta); err != nil {
		return ProviderInstanceMetadata{}
	}
	return meta
}

// ChannelFor returns the per-channel metadata for the given payment type,
// or a zero value when the channel is not configured.
func (m ProviderInstanceMetadata) ChannelFor(paymentType string) ChannelMetadata {
	if m.Channels == nil {
		return ChannelMetadata{}
	}
	return m.Channels[paymentType]
}

// EffectiveMultiplier returns the instance-level multiplier when set to a
// finite positive value; otherwise returns fallback.
func (m ProviderInstanceMetadata) EffectiveMultiplier(fallback float64) float64 {
	if m.BalanceRechargeMultiplier == nil {
		return fallback
	}
	v := *m.BalanceRechargeMultiplier
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return fallback
	}
	return v
}

// EffectiveProductNamePrefix returns the instance-level prefix when present,
// otherwise the fallback. A nil pointer means "not configured" (use fallback);
// an empty string means "explicitly cleared".
func (m ProviderInstanceMetadata) EffectiveProductNamePrefix(fallback string) string {
	if m.ProductNamePrefix == nil {
		return fallback
	}
	return *m.ProductNamePrefix
}

// EffectiveProductNameSuffix mirrors EffectiveProductNamePrefix.
func (m ProviderInstanceMetadata) EffectiveProductNameSuffix(fallback string) string {
	if m.ProductNameSuffix == nil {
		return fallback
	}
	return *m.ProductNameSuffix
}
