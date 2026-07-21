//go:build unit

package service

import "testing"

func TestGroupModel5hLimitFor(t *testing.T) {
	tests := []struct {
		name      string
		limits    map[string]float64
		model     string
		wantLimit float64
		wantOK    bool
	}{
		{
			name:      "configured model returns limit",
			limits:    map[string]float64{"claude-opus-4-8": 3.5},
			model:     "claude-opus-4-8",
			wantLimit: 3.5,
			wantOK:    true,
		},
		{
			name:   "unconfigured model returns not-ok",
			limits: map[string]float64{"claude-opus-4-8": 3.5},
			model:  "gpt-5.3-codex",
			wantOK: false,
		},
		{
			name:   "exact match only, no wildcard",
			limits: map[string]float64{"claude-opus-*": 3.5},
			model:  "claude-opus-4-8",
			wantOK: false,
		},
		{
			name:   "zero limit treated as unconfigured",
			limits: map[string]float64{"claude-opus-4-8": 0},
			model:  "claude-opus-4-8",
			wantOK: false,
		},
		{
			name:   "negative limit treated as unconfigured",
			limits: map[string]float64{"claude-opus-4-8": -1},
			model:  "claude-opus-4-8",
			wantOK: false,
		},
		{
			name:   "empty map returns not-ok",
			limits: map[string]float64{},
			model:  "claude-opus-4-8",
			wantOK: false,
		},
		{
			name:   "nil map returns not-ok",
			limits: nil,
			model:  "claude-opus-4-8",
			wantOK: false,
		},
		{
			name:   "empty model returns not-ok",
			limits: map[string]float64{"claude-opus-4-8": 3.5},
			model:  "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Group{Model5hLimits: tt.limits}
			limit, ok := g.Model5hLimitFor(tt.model)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && limit != tt.wantLimit {
				t.Errorf("limit = %v, want %v", limit, tt.wantLimit)
			}
		})
	}
}

func TestGroupModel5hLimitFor_NilGroup(t *testing.T) {
	var g *Group
	if _, ok := g.Model5hLimitFor("claude-opus-4-8"); ok {
		t.Error("nil group should return not-ok")
	}
}
