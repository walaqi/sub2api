package service

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// clientFingerprintHeaders is the ordered list of inbound request headers that
// make up the HTTP-layer client fingerprint. These are stable per client install
// (OS / arch / runtime / SDK & CLI versions) and are carried end-to-end by Claude
// Code clients — Cloudflare does not terminate HTTP headers, so they reach the
// origin intact even behind the CF → Nginx → origin chain.
//
// IMPORTANT: this is a spoofable signal (a client can send any header values), at
// the same trust level as device_id. Its value is in cross-referencing with
// device_id + IP, not on its own. Detection must stay one-directional: a
// fingerprint shared by MANY accounts is strong evidence of a farm; a unique or
// absent fingerprint is NOT proof of innocence.
//
// Deliberately excluded: per-request volatile headers (x-stainless-retry-count,
// x-stainless-timeout), secrets (authorization, x-api-key), and anthropic-beta
// (feature flags that vary per request and would destabilize the fingerprint).
var clientFingerprintHeaders = []string{
	"User-Agent", // includes claude-cli/<version>
	"X-Stainless-OS",
	"X-Stainless-Arch",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Package-Version",
	"X-Stainless-Lang",
	"X-App",
}

// ComputeClientFingerprint derives a stable HTTP-layer fingerprint from the
// inbound request headers. It returns a 32-char hex string (truncated SHA-256),
// or "" when none of the fingerprint headers are present (e.g. non-Claude-Code
// traffic) so callers can leave the column NULL rather than store a hash of
// emptiness.
//
// The hash is order-stable (headers are combined in clientFingerprintHeaders
// order) and whitespace-normalized so cosmetic differences don't fork the
// fingerprint. Header lookups are case-insensitive via http.Header.Get.
func ComputeClientFingerprint(header http.Header) string {
	if header == nil {
		return ""
	}

	parts := make([]string, 0, len(clientFingerprintHeaders))
	present := false
	for _, name := range clientFingerprintHeaders {
		// Normalize whitespace so " node " and "node" hash identically.
		v := strings.Join(strings.Fields(header.Get(name)), " ")
		if v != "" {
			present = true
		}
		// Always append (even empty) using a field separator so that a missing
		// header is distinguishable from an adjacent value shift, e.g.
		// {OS:"", Arch:"x64"} must not collide with {OS:"x64", Arch:""}.
		parts = append(parts, name+"="+v)
	}
	if !present {
		return ""
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])[:32]
}
