//go:build unit

// validateAPIKeyName 的单元测试。
// 该函数在创建/更新 API Key 时对名称做输入校验：去首尾空白、非空、
// 按 rune 限长、拒绝控制字符与尖括号（<、>）。
// 这些测试固化当前行为，防止后续改动无意间放宽校验、引入注入风险或破坏正常名称。

package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAPIKeyName_Valid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"普通英文名", "My Prod Key", "My Prod Key"},
		{"中文名", "生产环境密钥", "生产环境密钥"},
		{"含和号与引号", `A & B "x"`, `A & B "x"`},
		{"含表情符号", "key 🚀", "key 🚀"},
		{"去除首尾空白", "  trimmed  ", "trimmed"},
		{"恰好达到长度上限", strings.Repeat("a", apiKeyNameMaxLen), strings.Repeat("a", apiKeyNameMaxLen)},
		{"恰好达到长度上限的中文", strings.Repeat("中", apiKeyNameMaxLen), strings.Repeat("中", apiKeyNameMaxLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateAPIKeyName(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestValidateAPIKeyName_Empty(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"空字符串", ""},
		{"纯空格", "   "},
		{"纯制表符与换行", "\t\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateAPIKeyName(tc.in)
			require.ErrorIs(t, err, ErrAPIKeyNameEmpty)
		})
	}
}

func TestValidateAPIKeyName_TooLong(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"超出一个字符", strings.Repeat("a", apiKeyNameMaxLen+1)},
		{"超出一个中文字符", strings.Repeat("中", apiKeyNameMaxLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateAPIKeyName(tc.in)
			require.ErrorIs(t, err, ErrAPIKeyNameTooLong)
		})
	}
}

func TestValidateAPIKeyName_InvalidChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"script 标签", "<script>alert(1)</script>"},
		{"img onerror", `<img src=x onerror=alert(1)>`},
		{"仅左尖括号", "a<b"},
		{"仅右尖括号", "a>b"},
		{"NUL 字符", "a\x00b"},
		{"换行符", "line1\nline2"},
		{"回车符", "a\rb"},
		{"制表符夹在中间", "a\tb"},
		{"DEL 字符", "a\x7fb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateAPIKeyName(tc.in)
			require.ErrorIs(t, err, ErrAPIKeyNameInvalidChars)
		})
	}
}

// 确保非法名称不会返回任何被“清洗后”的字符串，避免调用方误用部分结果。
func TestValidateAPIKeyName_ReturnsEmptyOnError(t *testing.T) {
	got, err := validateAPIKeyName("<script>")
	require.Error(t, err)
	require.Empty(t, got)
	require.False(t, errors.Is(err, ErrAPIKeyNameEmpty))
}
