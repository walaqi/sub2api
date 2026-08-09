//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeRegistrationEmailSuffixWhitelist(t *testing.T) {
	got, err := NormalizeRegistrationEmailSuffixWhitelist([]string{"example.com", "@EXAMPLE.COM", " @foo.bar ", "*.EDU.CN"})
	require.NoError(t, err)
	require.Equal(t, []string{"@example.com", "@foo.bar", "*.edu.cn"}, got)
}

func TestNormalizeRegistrationEmailSuffixWhitelist_Regex(t *testing.T) {
	got, err := NormalizeRegistrationEmailSuffixWhitelist([]string{`re:^\d+@qq\.com$#仅限纯数字QQ邮箱`, "@foo.bar"})
	require.NoError(t, err)
	require.Equal(t, []string{`re:^\d+@qq\.com$#仅限纯数字QQ邮箱`, "@foo.bar"}, got)
}

func TestNormalizeRegistrationEmailSuffixWhitelist_RegexInvalid(t *testing.T) {
	for name, item := range map[string]string{
		"missing separator": `re:^\d+@qq\.com$`,
		"empty label":       `re:^\d+@qq\.com$#`,
		"empty pattern":     `re:#label`,
		"not anchored head": `re:\d+@qq\.com$#label`,
		"not anchored tail": `re:^\d+@qq\.com#label`,
		"bad pattern":       `re:^[a-z$#label`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NormalizeRegistrationEmailSuffixWhitelist([]string{item})
			require.Error(t, err)
		})
	}
}

func TestNormalizeRegistrationEmailSuffixWhitelist_Invalid(t *testing.T) {
	for _, item := range []string{"@invalid_domain", "*.", "*", "*.@", "*.foo"} {
		t.Run(item, func(t *testing.T) {
			_, err := NormalizeRegistrationEmailSuffixWhitelist([]string{item})
			require.Error(t, err)
		})
	}
}

func TestParseRegistrationEmailSuffixWhitelist(t *testing.T) {
	got := ParseRegistrationEmailSuffixWhitelist(`["example.com","@foo.bar","*.EDU.CN","@invalid_domain","*.foo"]`)
	require.Equal(t, []string{"@example.com", "@foo.bar", "*.edu.cn"}, got)
}

func TestIsRegistrationEmailSuffixAllowed_Regex(t *testing.T) {
	rule := `re:^\d+@qq\.com$#仅限纯数字QQ邮箱`
	require.True(t, IsRegistrationEmailSuffixAllowed("12345@qq.com", []string{rule}))
	require.False(t, IsRegistrationEmailSuffixAllowed("abc1@qq.com", []string{rule}))
	require.False(t, IsRegistrationEmailSuffixAllowed("12345@163.com", []string{rule}))
	// Anchored pattern must not substring-match a longer local part.
	require.False(t, IsRegistrationEmailSuffixAllowed("x12345@qq.com", []string{rule}))
	// Email is lowercased before matching, so a lowercase pattern still matches mixed-case input.
	require.True(t, IsRegistrationEmailSuffixAllowed("12345@QQ.com", []string{rule}))
	// Regex entries coexist with plain suffix entries.
	mixed := []string{"@foo.bar", rule}
	require.True(t, IsRegistrationEmailSuffixAllowed("user@foo.bar", mixed))
	require.True(t, IsRegistrationEmailSuffixAllowed("999@qq.com", mixed))
	require.False(t, IsRegistrationEmailSuffixAllowed("user@other.com", mixed))
}

func TestRegistrationEmailSuffixDisplay(t *testing.T) {
	require.Equal(t, "@foo.bar", RegistrationEmailSuffixDisplay("@foo.bar"))
	require.Equal(t, "*.edu.cn", RegistrationEmailSuffixDisplay("*.edu.cn"))
	require.Equal(t, "仅限纯数字QQ邮箱", RegistrationEmailSuffixDisplay(`re:^\d+@qq\.com$#仅限纯数字QQ邮箱`))
	// Label may itself contain "|"; only the regex/label boundary uses "#".
	require.Equal(t, "a|b 提示", RegistrationEmailSuffixDisplay(`re:^x$#a|b 提示`))
}

func TestIsRegistrationEmailSuffixAllowed(t *testing.T) {
	require.True(t, IsRegistrationEmailSuffixAllowed("user@example.com", []string{"@example.com"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("user@example.com.", []string{"@example.com"}))
	require.False(t, IsRegistrationEmailSuffixAllowed("user@sub.example.com", []string{"@example.com"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("user@qq.com", []string{"@qq.com"}))
	require.False(t, IsRegistrationEmailSuffixAllowed("user@sub.qq.com", []string{"@qq.com"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("student@cs.edu.cn", []string{"*.edu.cn"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("student@edu.cn", []string{"*.edu.cn"}))
	require.False(t, IsRegistrationEmailSuffixAllowed("student@foo.cn", []string{"*.edu.cn"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("user@a.com", []string{"@a.com", "*.b.cn"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("user@school.b.cn", []string{"@a.com", "*.b.cn"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("user@b.cn", []string{"@a.com", "*.b.cn"}))
	require.False(t, IsRegistrationEmailSuffixAllowed("user@c.cn", []string{"@a.com", "*.b.cn"}))
	require.True(t, IsRegistrationEmailSuffixAllowed("user@any.com", []string{}))
}

func TestRegistrationEmailQuotaRejectsMalformedDomainWhenWhitelistConfigured(t *testing.T) {
	repo := &userRepoStub{}
	svc := newAuthService(repo, map[string]string{
		SettingKeyRegistrationEnabled:                 "true",
		SettingKeyRegistrationEmailSuffixWhitelist:    `["@example.com"]`,
		SettingKeyRegistrationEmailDomainQuotaEnabled: "true",
	}, nil, nil)

	_, _, err := svc.Register(context.Background(), "malformed-email", "password")

	require.ErrorIs(t, err, ErrEmailSuffixNotAllowed)
	require.Empty(t, repo.created)
}

func TestIsRegistrationEmailSuffixLimited(t *testing.T) {
	require.False(t, IsRegistrationEmailSuffixLimited("user@custom.example", nil))
	require.False(t, IsRegistrationEmailSuffixLimited("user@example.com", []string{"@example.com"}))
	require.True(t, IsRegistrationEmailSuffixLimited("user@custom.example", []string{"@example.com"}))
}

func TestRegistrationEmailDomainUsesRegistrableDomain(t *testing.T) {
	require.Equal(t, "abc.com", RegistrationEmailDomain("user@abc.com"))
	require.Equal(t, "abc.com", RegistrationEmailDomain("user@abcd.abc.com"))
	require.Equal(t, "example.co.uk", RegistrationEmailDomain("user@team.example.co.uk"))
	require.Equal(t, "example.com", RegistrationEmailDomain("user@example.com."))
	require.Equal(t, "example.com", RegistrationEmailDomain("user@team.example.com."))
}
