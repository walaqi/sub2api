package service

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var registrationEmailDomainPattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`,
)

const (
	// registrationEmailRegexPrefix marks a whitelist entry as a regular expression rule.
	registrationEmailRegexPrefix = "re:"
	// registrationEmailRegexLabelSep separates the regex body from its display label.
	// "#" is a literal in both Go's RE2 and JavaScript regex engines, so it never
	// conflicts with the pattern itself, and the label may freely contain "|".
	registrationEmailRegexLabelSep = "#"
)

// compiledRegistrationEmailRegexCache caches compiled regexes keyed by the raw
// regex body. RE2 matching is linear-time (ReDoS-safe); the cache only avoids
// recompiling on every registration attempt.
var compiledRegistrationEmailRegexCache sync.Map // map[string]*regexp.Regexp

// RegistrationEmailSuffix extracts normalized suffix in "@domain" form.
func RegistrationEmailSuffix(email string) string {
	_, domain, ok := splitEmailForPolicy(email)
	if !ok {
		return ""
	}
	return "@" + domain
}

// IsRegistrationEmailSuffixAllowed checks whether an email is allowed by suffix whitelist.
// Empty whitelist means allow all.
func IsRegistrationEmailSuffixAllowed(email string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	_, domain, ok := splitEmailForPolicy(email)
	if !ok {
		return false
	}
	suffix := "@" + domain
	for _, allowed := range whitelist {
		// Regex entries keep their original case (e.g. \D vs \d), so do not lowercase them.
		if strings.HasPrefix(allowed, registrationEmailRegexPrefix) {
			if registrationEmailRegexMatches(allowed, normalizedEmail) {
				return true
			}
			continue
		}
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if strings.HasPrefix(allowed, "@") && suffix == allowed {
			return true
		}
		if strings.HasPrefix(allowed, "*.") && registrationEmailDomainMatchesWildcard(domain, allowed) {
			return true
		}
	}
	return false
}

// NormalizeRegistrationEmailSuffixWhitelist normalizes and validates suffix whitelist items.
func NormalizeRegistrationEmailSuffixWhitelist(raw []string) ([]string, error) {
	return normalizeRegistrationEmailSuffixWhitelist(raw, true)
}

// ParseRegistrationEmailSuffixWhitelist parses persisted JSON into normalized suffixes.
// Invalid entries are ignored to keep old misconfigurations from breaking runtime reads.
func ParseRegistrationEmailSuffixWhitelist(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var items []string
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return []string{}
	}
	normalized, _ := normalizeRegistrationEmailSuffixWhitelist(items, false)
	if len(normalized) == 0 {
		return []string{}
	}
	return normalized
}

func normalizeRegistrationEmailSuffixWhitelist(raw []string, strict bool) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		normalized, err := normalizeRegistrationEmailSuffix(item)
		if err != nil {
			if strict {
				return nil, err
			}
			continue
		}
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func normalizeRegistrationEmailSuffix(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)

	// Regex entries are case-sensitive and must keep their original characters,
	// so they are handled before any lowercasing/character stripping below.
	if strings.HasPrefix(trimmed, registrationEmailRegexPrefix) {
		return normalizeRegistrationEmailRegex(trimmed)
	}

	value := strings.ToLower(trimmed)
	if value == "" {
		return "", nil
	}

	if strings.HasPrefix(value, "*.") {
		domain := strings.TrimPrefix(value, "*.")
		if !isValidRegistrationEmailDomain(domain) {
			return "", fmt.Errorf("invalid email suffix: %q", raw)
		}
		return "*." + domain, nil
	}

	domain := value
	if strings.Contains(value, "@") {
		if !strings.HasPrefix(value, "@") || strings.Count(value, "@") != 1 {
			return "", fmt.Errorf("invalid email suffix: %q", raw)
		}
		domain = strings.TrimPrefix(value, "@")
	}

	if !isValidRegistrationEmailDomain(domain) {
		return "", fmt.Errorf("invalid email suffix: %q", raw)
	}

	return "@" + domain, nil
}

// normalizeRegistrationEmailRegex validates a "re:<pattern>#<label>" entry.
// The pattern must be anchored (^...$), the label must be non-empty, and the
// pattern must compile. On success the entry is returned unchanged (whitespace
// around the whole entry is trimmed, but the pattern itself is preserved).
func normalizeRegistrationEmailRegex(entry string) (string, error) {
	body := strings.TrimPrefix(entry, registrationEmailRegexPrefix)
	pattern, label, found := strings.Cut(body, registrationEmailRegexLabelSep)
	if !found {
		return "", fmt.Errorf("invalid email regex rule, expected %q separator: %q", registrationEmailRegexLabelSep, entry)
	}
	if strings.TrimSpace(label) == "" {
		return "", fmt.Errorf("invalid email regex rule, missing display label: %q", entry)
	}
	if pattern == "" {
		return "", fmt.Errorf("invalid email regex rule, empty pattern: %q", entry)
	}
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		return "", fmt.Errorf("invalid email regex rule, pattern must be anchored with ^ and $: %q", entry)
	}
	if _, err := compileRegistrationEmailRegex(pattern); err != nil {
		return "", fmt.Errorf("invalid email regex rule: %q: %w", entry, err)
	}
	return entry, nil
}

// compileRegistrationEmailRegex compiles (and caches) a regex pattern body.
func compileRegistrationEmailRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := compiledRegistrationEmailRegexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil //nolint:errcheck // type assertion always succeeds
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	compiledRegistrationEmailRegexCache.Store(pattern, re)
	return re, nil
}

// registrationEmailRegexMatches reports whether a normalized email matches a
// "re:<pattern>#<label>" whitelist entry.
func registrationEmailRegexMatches(entry string, normalizedEmail string) bool {
	body := strings.TrimPrefix(entry, registrationEmailRegexPrefix)
	pattern, _, found := strings.Cut(body, registrationEmailRegexLabelSep)
	if !found || pattern == "" {
		return false
	}
	re, err := compileRegistrationEmailRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(normalizedEmail)
}

// RegistrationEmailSuffixDisplay returns the user-facing representation of a
// whitelist entry. Regex entries expose only their display label, never the
// raw pattern.
func RegistrationEmailSuffixDisplay(entry string) string {
	if !strings.HasPrefix(entry, registrationEmailRegexPrefix) {
		return entry
	}
	body := strings.TrimPrefix(entry, registrationEmailRegexPrefix)
	_, label, found := strings.Cut(body, registrationEmailRegexLabelSep)
	if !found {
		return ""
	}
	return strings.TrimSpace(label)
}

func isValidRegistrationEmailDomain(domain string) bool {
	return domain != "" &&
		!strings.Contains(domain, "@") &&
		registrationEmailDomainPattern.MatchString(domain)
}

func registrationEmailDomainMatchesWildcard(domain string, allowed string) bool {
	base := strings.TrimPrefix(allowed, "*.")
	if !isValidRegistrationEmailDomain(base) {
		return false
	}
	return domain == base || strings.HasSuffix(domain, "."+base)
}

func splitEmailForPolicy(raw string) (local string, domain string, ok bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", "", false
	}
	return local, domain, true
}
