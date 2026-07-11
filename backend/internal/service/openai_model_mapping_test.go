package service

import "testing"

func TestResolveOpenAIForwardModel(t *testing.T) {
	tests := []struct {
		name               string
		account            *Account
		requestedModel     string
		defaultMappedModel string
		expectedModel      string
	}{
		{
			name: "uses messages dispatch default for claude model",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "claude-opus-4-6",
			defaultMappedModel: "gpt-4o-mini",
			expectedModel:      "gpt-4o-mini",
		},
		{
			name: "does not fall back to group default for invalid gpt model",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "gpt6",
			defaultMappedModel: "gpt-5.4",
			expectedModel:      "gpt6",
		},
		{
			name: "preserves explicit gpt-5.4 instead of group default",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "gpt-5.4",
			defaultMappedModel: "gpt-4o-mini",
			expectedModel:      "gpt-5.4",
		},
		{
			name: "preserves exact passthrough mapping instead of group default",
			account: &Account{
				Credentials: map[string]any{
					"model_mapping": map[string]any{
						"gpt-5.4": "gpt-5.4",
					},
				},
			},
			requestedModel:     "gpt-5.4",
			defaultMappedModel: "gpt-4o-mini",
			expectedModel:      "gpt-5.4",
		},
		{
			name: "preserves wildcard passthrough mapping instead of group default",
			account: &Account{
				Credentials: map[string]any{
					"model_mapping": map[string]any{
						"gpt-*": "gpt-5.4",
					},
				},
			},
			requestedModel:     "gpt-5.4",
			defaultMappedModel: "gpt-4o-mini",
			expectedModel:      "gpt-5.4",
		},
		{
			name: "uses account remap when explicit target differs",
			account: &Account{
				Credentials: map[string]any{
					"model_mapping": map[string]any{
						"gpt-5": "gpt-5.4",
					},
				},
			},
			requestedModel:     "gpt-5",
			defaultMappedModel: "gpt-4o-mini",
			expectedModel:      "gpt-5.4",
		},
		{
			name: "preserves codex spark instead of group default",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "gpt-5.3-codex-spark",
			defaultMappedModel: "gpt-5.4",
			expectedModel:      "gpt-5.3-codex-spark",
		},
		{
			name: "preserves gpt-5.5 instead of group default",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "gpt-5.5",
			defaultMappedModel: "gpt-5.4",
			expectedModel:      "gpt-5.5",
		},
		{
			name: "preserves compact-spelled gpt5.5 instead of group default",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "gpt5.5",
			defaultMappedModel: "gpt-5.4",
			expectedModel:      "gpt5.5",
		},
		{
			name: "preserves openai namespaced gpt-5.5 instead of group default",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "openai/gpt-5.5",
			defaultMappedModel: "gpt-5.4",
			expectedModel:      "openai/gpt-5.5",
		},
		{
			name: "preserves compact gpt-5.5 instead of group default",
			account: &Account{
				Credentials: map[string]any{},
			},
			requestedModel:     "gpt-5.5-openai-compact",
			defaultMappedModel: "gpt-5.4",
			expectedModel:      "gpt-5.5-openai-compact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveOpenAIForwardModel(tt.account, tt.requestedModel, tt.defaultMappedModel); got != tt.expectedModel {
				t.Fatalf("resolveOpenAIForwardModel(...) = %q, want %q", got, tt.expectedModel)
			}
		})
	}
}

func TestResolveOpenAIForwardModel_PreventsClaudeModelFromFallingBackToGpt54(t *testing.T) {
	account := &Account{
		Credentials: map[string]any{},
	}

	withoutDefault := resolveOpenAIForwardModel(account, "claude-opus-4-6", "")
	if withoutDefault != "claude-opus-4-6" {
		t.Fatalf("resolveOpenAIForwardModel(...) = %q, want %q", withoutDefault, "claude-opus-4-6")
	}

	withDefault := resolveOpenAIForwardModel(account, "claude-opus-4-6", "gpt-5.4")
	if withDefault != "gpt-5.4" {
		t.Fatalf("resolveOpenAIForwardModel(...) = %q, want %q", withDefault, "gpt-5.4")
	}
}

func TestResolveOpenAICompactForwardModel(t *testing.T) {
	tests := []struct {
		name          string
		account       *Account
		model         string
		expectedModel string
	}{
		{
			name:          "nil account keeps original model",
			account:       nil,
			model:         "gpt-5.4",
			expectedModel: "gpt-5.4",
		},
		{
			name: "missing compact mapping keeps original model",
			account: &Account{
				Credentials: map[string]any{},
			},
			model:         "gpt-5.4",
			expectedModel: "gpt-5.4",
		},
		{
			name: "exact compact mapping overrides model",
			account: &Account{
				Credentials: map[string]any{
					"compact_model_mapping": map[string]any{
						"gpt-5.4": "gpt-5.4-openai-compact",
					},
				},
			},
			model:         "gpt-5.4",
			expectedModel: "gpt-5.4-openai-compact",
		},
		{
			name: "wildcard compact mapping overrides model",
			account: &Account{
				Credentials: map[string]any{
					"compact_model_mapping": map[string]any{
						"gpt-5.*": "gpt-5-openai-compact",
					},
				},
			},
			model:         "gpt-5.4",
			expectedModel: "gpt-5-openai-compact",
		},
		{
			name: "passthrough compact mapping remains unchanged",
			account: &Account{
				Credentials: map[string]any{
					"compact_model_mapping": map[string]any{
						"gpt-5.4": "gpt-5.4",
					},
				},
			},
			model:         "gpt-5.4",
			expectedModel: "gpt-5.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveOpenAICompactForwardModel(tt.account, tt.model); got != tt.expectedModel {
				t.Fatalf("resolveOpenAICompactForwardModel(...) = %q, want %q", got, tt.expectedModel)
			}
		})
	}
}

func TestNormalizeCodexModel(t *testing.T) {
	cases := map[string]string{
		"gpt-5.3-codex-spark":       "gpt-5.3-codex-spark",
		"gpt-5.3-codex-spark-high":  "gpt-5.3-codex-spark",
		"gpt-5.3-codex-spark-xhigh": "gpt-5.3-codex-spark",
		"gpt-5.3":                   "gpt-5.3-codex",
		"gpt-image-2":               "gpt-image-2",
		"gpt-5.4-nano":              "gpt-5.4-nano",
		"gpt-5.4-nano-high":         "gpt-5.4-nano",
		"gpt6":                      "gpt6",
		"claude-opus-4-6":           "claude-opus-4-6",
		// GPT-5.6 系列（sol / terra / luna）与 GPT-5.5 Pro 作为已知型号透传，
		// 且带推理档位后缀的变体归一化到基础型号。
		"gpt-5.6-sol":         "gpt-5.6-sol",
		"gpt-5.6-sol-high":    "gpt-5.6-sol",
		"gpt-5.6-sol-low":     "gpt-5.6-sol",
		"gpt-5.6-sol-xhigh":   "gpt-5.6-sol",
		"gpt-5.6-terra":       "gpt-5.6-terra",
		"gpt-5.6-terra-high":  "gpt-5.6-terra",
		"gpt-5.6-luna":        "gpt-5.6-luna",
		"gpt-5.6-luna-medium": "gpt-5.6-luna",
		"gpt-5.5-pro":         "gpt-5.5-pro",
		"gpt-5.5-pro-high":    "gpt-5.5-pro",
	}

	for input, expected := range cases {
		if got := normalizeCodexModel(input); got != expected {
			t.Fatalf("normalizeCodexModel(%q) = %q, want %q", input, got, expected)
		}
	}
}

// TestNormalizeCodexModelPolicy verifies the collapse-policy variant: an unknown
// gpt-5* model collapses to gpt-5.4 under the default policy but passes through
// untouched when the model came from an explicit admin mapping (collapse=false).
// Known models and reasoning-effort suffix stripping behave identically.
func TestNormalizeCodexModelPolicy(t *testing.T) {
	tests := []struct {
		name            string
		model           string
		collapseUnknown bool
		want            string
	}{
		{
			name:            "unknown gpt-5 collapses under default policy",
			model:           "gpt-5.9-nova",
			collapseUnknown: true,
			want:            "gpt-5.4",
		},
		{
			name:            "unknown gpt-5 passes through when explicitly mapped",
			model:           "gpt-5.9-nova",
			collapseUnknown: false,
			want:            "gpt-5.9-nova",
		},
		{
			name:            "known model resolves identically regardless of policy (collapse)",
			model:           "gpt-5.6-sol",
			collapseUnknown: true,
			want:            "gpt-5.6-sol",
		},
		{
			name:            "known model resolves identically regardless of policy (no collapse)",
			model:           "gpt-5.6-sol",
			collapseUnknown: false,
			want:            "gpt-5.6-sol",
		},
		{
			name:            "effort suffix stripped even when not collapsing",
			model:           "gpt-5.4-high",
			collapseUnknown: false,
			want:            "gpt-5.4",
		},
		{
			// 发现 1 修复：未知 gpt-5* 显式映射目标不 collapse，但档位后缀仍须剥离。
			name:            "unknown gpt-5 strips effort suffix but does not collapse",
			model:           "gpt-5.9-nova-high",
			collapseUnknown: false,
			want:            "gpt-5.9-nova",
		},
		{
			name:            "unknown gpt-5 strips low suffix",
			model:           "gpt-5.9-nova-low",
			collapseUnknown: false,
			want:            "gpt-5.9-nova",
		},
		{
			// 未知 gpt-5* 无档位后缀：原样透传。
			name:            "unknown gpt-5 without effort suffix passes through",
			model:           "gpt-5.9-nova",
			collapseUnknown: false,
			want:            "gpt-5.9-nova",
		},
		{
			// 档位剥离仅限 gpt-5* 前缀，非 gpt-5 未知模型即使带 -high 也不动。
			name:            "non gpt-5 unknown model with high suffix untouched",
			model:           "foo-bar-high",
			collapseUnknown: false,
			want:            "foo-bar-high",
		},
		{
			name:            "non gpt-5 model unaffected by policy",
			model:           "gpt6",
			collapseUnknown: false,
			want:            "gpt6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCodexModelWithPolicy(tt.model, tt.collapseUnknown); got != tt.want {
				t.Fatalf("normalizeCodexModelWithPolicy(%q, %v) = %q, want %q", tt.model, tt.collapseUnknown, got, tt.want)
			}
		})
	}
}

func TestNormalizeOpenAIModelForUpstream(t *testing.T) {
	tests := []struct {
		name    string
		account *Account
		model   string
		want    string
	}{
		{
			name:    "oauth preserves unknown non codex model",
			account: &Account{Type: AccountTypeOAuth},
			model:   "gemini-3-flash-preview",
			want:    "gemini-3-flash-preview",
		},
		{
			name:    "oauth preserves invalid gpt model",
			account: &Account{Type: AccountTypeOAuth},
			model:   "gpt6",
			want:    "gpt6",
		},
		{
			name:    "oauth normalizes known codex alias",
			account: &Account{Type: AccountTypeOAuth},
			model:   "gpt-5.4-high",
			want:    "gpt-5.4",
		},
		{
			name:    "oauth preserves codex auto review model",
			account: &Account{Type: AccountTypeOAuth},
			model:   "codex-auto-review",
			want:    "codex-auto-review",
		},
		{
			name:    "apikey preserves custom compatible model",
			account: &Account{Type: AccountTypeAPIKey},
			model:   "gemini-3-flash-preview",
			want:    "gemini-3-flash-preview",
		},
		{
			name:    "apikey preserves official non codex model",
			account: &Account{Type: AccountTypeAPIKey},
			model:   "gpt-4.1",
			want:    "gpt-4.1",
		},
		{
			name:    "oauth passes through newly registered gpt-5.6-sol",
			account: &Account{Type: AccountTypeOAuth},
			model:   "gpt-5.6-sol",
			want:    "gpt-5.6-sol",
		},
		{
			name:    "oauth passes through gpt-5.5-pro",
			account: &Account{Type: AccountTypeOAuth},
			model:   "gpt-5.5-pro",
			want:    "gpt-5.5-pro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeOpenAIModelForUpstream(tt.account, tt.model); got != tt.want {
				t.Fatalf("normalizeOpenAIModelForUpstream(...) = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNormalizeOpenAIModelForUpstreamWithPolicy covers the explicit-mapping
// override: for OAuth (Codex) accounts, a model produced by an admin's explicit
// model_mapping must reach upstream verbatim rather than being collapsed to
// gpt-5.4 by the unknown-gpt-5* fallback. This is the core of the fix — before
// it, an admin could not express "forward this model as-is" because the wire
// normalization always ran last and overrode the mapping.
func TestNormalizeOpenAIModelForUpstreamWithPolicy(t *testing.T) {
	tests := []struct {
		name             string
		account          *Account
		model            string
		explicitlyMapped bool
		want             string
	}{
		{
			name:             "oauth unknown gpt-5 collapses when not explicitly mapped",
			account:          &Account{Type: AccountTypeOAuth},
			model:            "gpt-5.9-nova",
			explicitlyMapped: false,
			want:             "gpt-5.4",
		},
		{
			name:             "oauth unknown gpt-5 passes through when explicitly mapped",
			account:          &Account{Type: AccountTypeOAuth},
			model:            "gpt-5.9-nova",
			explicitlyMapped: true,
			want:             "gpt-5.9-nova",
		},
		{
			name:             "oauth still strips effort suffix even when explicitly mapped",
			account:          &Account{Type: AccountTypeOAuth},
			model:            "gpt-5.4-high",
			explicitlyMapped: true,
			want:             "gpt-5.4",
		},
		{
			// 发现 1 修复：未知 gpt-5* 显式映射目标不 collapse，但档位后缀仍剥离。
			name:             "oauth unknown gpt-5 explicitly mapped strips effort suffix without collapse",
			account:          &Account{Type: AccountTypeOAuth},
			model:            "gpt-5.9-nova-high",
			explicitlyMapped: true,
			want:             "gpt-5.9-nova",
		},
		{
			name:             "apikey account unaffected by explicit-mapped flag",
			account:          &Account{Type: AccountTypeAPIKey},
			model:            "gpt-5.9-nova",
			explicitlyMapped: false,
			want:             "gpt-5.9-nova",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeOpenAIModelForUpstreamWithPolicy(tt.account, tt.model, tt.explicitlyMapped); got != tt.want {
				t.Fatalf("normalizeOpenAIModelForUpstreamWithPolicy(...) = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestResolveOpenAIForwardModelDetailed_ExplicitMappedFlag verifies the
// explicitlyMapped return value that drives the collapse policy: it is true only
// when an account-level model_mapping rule (exact or wildcard) matched, and false
// for the Claude messages-dispatch default fallback or an unmapped model.
func TestResolveOpenAIForwardModelDetailed_ExplicitMappedFlag(t *testing.T) {
	tests := []struct {
		name               string
		account            *Account
		requestedModel     string
		defaultMappedModel string
		wantModel          string
		wantExplicit       bool
	}{
		{
			name: "exact mapping match sets explicit",
			account: &Account{Credentials: map[string]any{
				"model_mapping": map[string]any{"gpt-5.6-sol": "gpt-5.6-sol"},
			}},
			requestedModel: "gpt-5.6-sol",
			wantModel:      "gpt-5.6-sol",
			wantExplicit:   true,
		},
		{
			name: "wildcard mapping match sets explicit",
			account: &Account{Credentials: map[string]any{
				"model_mapping": map[string]any{"gpt-5.6-sol*": "gpt-5.6-sol"},
			}},
			requestedModel: "gpt-5.6-sol-high",
			wantModel:      "gpt-5.6-sol",
			wantExplicit:   true,
		},
		{
			name:           "no mapping leaves explicit false",
			account:        &Account{Credentials: map[string]any{}},
			requestedModel: "gpt-5.6-sol",
			wantModel:      "gpt-5.6-sol",
			wantExplicit:   false,
		},
		{
			name:               "claude dispatch default is not explicit",
			account:            &Account{Credentials: map[string]any{}},
			requestedModel:     "claude-opus-4-6",
			defaultMappedModel: "gpt-5.4",
			wantModel:          "gpt-5.4",
			wantExplicit:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotModel, gotExplicit := resolveOpenAIForwardModelDetailed(tt.account, tt.requestedModel, tt.defaultMappedModel)
			if gotModel != tt.wantModel || gotExplicit != tt.wantExplicit {
				t.Fatalf("resolveOpenAIForwardModelDetailed(...) = (%q, %v), want (%q, %v)", gotModel, gotExplicit, tt.wantModel, tt.wantExplicit)
			}
		})
	}
}

// TestNormalizeOpenAIModelForUpstream_ExplicitMappingEndToEnd reproduces the
// original bug scenario: an OAuth account with an explicit passthrough mapping
// for an unknown gpt-5* model. Before the fix the result collapsed to gpt-5.4;
// now the mapped model reaches upstream verbatim.
func TestNormalizeOpenAIModelForUpstream_ExplicitMappingEndToEnd(t *testing.T) {
	account := &Account{
		Type: AccountTypeOAuth,
		Credentials: map[string]any{
			"model_mapping": map[string]any{"gpt-5.9-nova*": "gpt-5.9-nova"},
		},
	}

	billingModel, explicitlyMapped := resolveOpenAIForwardModelDetailed(account, "gpt-5.9-nova-high", "")
	if !explicitlyMapped {
		t.Fatalf("expected explicitlyMapped=true for wildcard passthrough mapping")
	}
	if billingModel != "gpt-5.9-nova" {
		t.Fatalf("billingModel = %q, want %q", billingModel, "gpt-5.9-nova")
	}

	upstream := normalizeOpenAIModelForUpstreamWithPolicy(account, billingModel, explicitlyMapped)
	if upstream != "gpt-5.9-nova" {
		t.Fatalf("upstream = %q, want %q (explicit mapping must not collapse to gpt-5.4)", upstream, "gpt-5.9-nova")
	}
}

func TestUsageBillingModelCandidatesPreserveCodexAutoReviewModel(t *testing.T) {
	candidates := usageBillingModelCandidates("codex-auto-review")

	expected := []string{"codex-auto-review"}
	if len(candidates) != len(expected) {
		t.Fatalf("usageBillingModelCandidates(codex-auto-review) = %#v, want %#v", candidates, expected)
	}
	for i := range expected {
		if candidates[i] != expected[i] {
			t.Fatalf("usageBillingModelCandidates(codex-auto-review) = %#v, want %#v", candidates, expected)
		}
	}
}
