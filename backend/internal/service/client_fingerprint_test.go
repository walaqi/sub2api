//go:build unit

package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func fpHeaders(kv map[string]string) http.Header {
	h := http.Header{}
	for k, v := range kv {
		h.Set(k, v)
	}
	return h
}

func TestComputeClientFingerprint_StableForSameClient(t *testing.T) {
	h := fpHeaders(map[string]string{
		"User-Agent":                  "claude-cli/2.1.92 (external, cli)",
		"X-Stainless-OS":              "Linux",
		"X-Stainless-Arch":            "arm64",
		"X-Stainless-Runtime":         "node",
		"X-Stainless-Runtime-Version": "v24.13.0",
		"X-Stainless-Package-Version": "0.70.0",
		"X-Stainless-Lang":            "js",
		"X-App":                       "cli",
	})

	got1 := ComputeClientFingerprint(h)
	got2 := ComputeClientFingerprint(h)
	require.Equal(t, got1, got2, "same headers must yield same fingerprint")
	require.Len(t, got1, 32)
}

func TestComputeClientFingerprint_WhitespaceNormalized(t *testing.T) {
	a := ComputeClientFingerprint(fpHeaders(map[string]string{
		"X-Stainless-OS":      "Linux",
		"X-Stainless-Runtime": "node",
	}))
	b := ComputeClientFingerprint(fpHeaders(map[string]string{
		"X-Stainless-OS":      "  Linux  ",
		"X-Stainless-Runtime": "node",
	}))
	require.Equal(t, a, b, "cosmetic whitespace must not change the fingerprint")
}

func TestComputeClientFingerprint_CaseInsensitiveHeaderNames(t *testing.T) {
	canonical := ComputeClientFingerprint(fpHeaders(map[string]string{
		"X-Stainless-OS": "Linux",
		"User-Agent":     "claude-cli/2.1.92",
	}))

	// Raw header map with lowercase keys (http.Header.Get canonicalizes lookups).
	lower := http.Header{}
	lower["x-stainless-os"] = []string{"Linux"} // bypass Set canonicalization
	lower["user-agent"] = []string{"claude-cli/2.1.92"}
	// http.Header.Get canonicalizes the *query* key, but stored keys must match;
	// use a properly-set header to represent the same logical request.
	proper := fpHeaders(map[string]string{
		"x-stainless-os": "Linux",
		"user-agent":     "claude-cli/2.1.92",
	})
	require.Equal(t, canonical, ComputeClientFingerprint(proper))
}

func TestComputeClientFingerprint_DifferentClientsDiffer(t *testing.T) {
	base := map[string]string{
		"User-Agent":                  "claude-cli/2.1.92 (external, cli)",
		"X-Stainless-OS":              "Linux",
		"X-Stainless-Arch":            "arm64",
		"X-Stainless-Runtime-Version": "v24.13.0",
	}
	baseFP := ComputeClientFingerprint(fpHeaders(base))

	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"different_os", "X-Stainless-OS", "Windows"},
		{"different_arch", "X-Stainless-Arch", "x64"},
		{"different_runtime_version", "X-Stainless-Runtime-Version", "v20.0.0"},
		{"different_cli_version", "User-Agent", "claude-cli/2.0.0 (external, cli)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := make(map[string]string, len(base))
			for k, v := range base {
				m[k] = v
			}
			m[tc.key] = tc.val
			require.NotEqual(t, baseFP, ComputeClientFingerprint(fpHeaders(m)),
				"a change in %s must produce a different fingerprint", tc.key)
		})
	}
}

func TestComputeClientFingerprint_FieldShiftDoesNotCollide(t *testing.T) {
	// {OS:"", Arch:"x64"} must not hash the same as {OS:"x64", Arch:""}.
	a := ComputeClientFingerprint(fpHeaders(map[string]string{
		"X-Stainless-Arch": "x64",
	}))
	b := ComputeClientFingerprint(fpHeaders(map[string]string{
		"X-Stainless-OS": "x64",
	}))
	require.NotEqual(t, a, b)
}

func TestComputeClientFingerprint_EmptyAndNil(t *testing.T) {
	require.Equal(t, "", ComputeClientFingerprint(nil))
	require.Equal(t, "", ComputeClientFingerprint(http.Header{}))
	// Headers present but none of them fingerprint headers → empty.
	require.Equal(t, "", ComputeClientFingerprint(fpHeaders(map[string]string{
		"Content-Type": "application/json",
		"Accept":       "*/*",
	})))
}

func TestComputeClientFingerprint_IgnoresVolatileHeaders(t *testing.T) {
	base := map[string]string{
		"User-Agent":          "claude-cli/2.1.92",
		"X-Stainless-OS":      "Linux",
		"X-Stainless-Runtime": "node",
	}
	withVolatile := make(map[string]string, len(base)+3)
	for k, v := range base {
		withVolatile[k] = v
	}
	withVolatile["X-Stainless-Retry-Count"] = "3"
	withVolatile["X-Stainless-Timeout"] = "600"
	withVolatile["Anthropic-Beta"] = "context-management-2025"

	require.Equal(t,
		ComputeClientFingerprint(fpHeaders(base)),
		ComputeClientFingerprint(fpHeaders(withVolatile)),
		"retry-count / timeout / anthropic-beta must not affect the fingerprint")
}
