package repository

import (
	"testing"
	"github.com/stretchr/testify/require"
)

// 这个测试专门验证 stripSQLComments 函数是否能正确处理字符串字面量中的 --
func TestStripSQLComments_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "字符串中的 -- 不应被当作注释",
			input:    "INSERT INTO settings(value) VALUES ('a--b');",
			expected: "INSERT INTO settings(value) VALUES ('a--b');",
		},
		{
			name:     "真实注释中的 -- 应该被移除",
			input:    "-- 这是一个注释\nSELECT 1;",
			expected: "SELECT 1;",
		},
		{
			name:     "注释中的分号不应影响SQL分割",
			input:    "-- 这是一个包含;分号的注释\nCREATE INDEX idx_test ON table(col);",
			expected: "CREATE INDEX idx_test ON table(col);",
		},
		{
			name:     "生产环境的实际例子",
			input:    "-- AND inviter_reward_blocked_by_quota=true); this narrow partial index...\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rrt_inviter_blocked_pending ON referral_reward_tracker (inviter_id) WHERE inviter_reward_granted = FALSE AND inviter_reward_blocked_by_quota = TRUE;",
			expected: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rrt_inviter_blocked_pending ON referral_reward_tracker (inviter_id) WHERE inviter_reward_granted = FALSE AND inviter_reward_blocked_by_quota = TRUE;",
		},
		{
			name:     "引号内的注释标识符",
			input:    `INSERT INTO t(col1, col2) VALUES ('a--b', "c--d"); -- 真正的注释`,
			expected: `INSERT INTO t(col1, col2) VALUES ('a--b', "c--d");`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripSQLComments(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

// 这个测试验证 splitSQLStatements 函数的整体行为
func TestSplitSQLStatements_Regression(t *testing.T) {
	// 生产失败的迁移文件内容
	migrationContent := `-- 176_referral_tracker_blocked_by_quota_index_notx.sql
-- Partial index for the "quota exhausted" login popup targeting.
-- fillReferralTargeting runs EXISTS(... inviter_id=$1 AND inviter_reward_granted=false
-- AND inviter_reward_blocked_by_quota=true); this narrow partial index keeps that
-- probe cheap even for inviters with many invitee tracker rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rrt_inviter_blocked_pending
    ON referral_reward_tracker (inviter_id)
    WHERE inviter_reward_granted = FALSE AND inviter_reward_blocked_by_quota = TRUE;`

	statements := splitSQLStatements(migrationContent)
	
	// 应该只有1个语句（CREATE INDEX）
	require.Len(t, statements, 1)
	
	// 语句应该包含CREATE INDEX
	require.Contains(t, statements[0], "CREATE INDEX CONCURRENTLY IF NOT EXISTS")
	
	// 语句不应该包含注释文本
	require.NotContains(t, statements[0], "this narrow partial index")
	require.NotContains(t, statements[0], "fillReferralTargeting")
}

// 测试验证我们的修复不会破坏现有的行为
func TestSplitSQLStatements_BasicCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []string
	}{
		{
			name:     "简单语句",
			input:    "SELECT 1;",
			expected: []string{"SELECT 1"},
		},
		{
			name:     "多个语句",
			input:    "SELECT 1; SELECT 2;",
			expected: []string{"SELECT 1", "SELECT 2"},
		},
		{
			name:     "带空格的语句",
			input:    "  SELECT 1 ;  SELECT 2 ;  ",
			expected: []string{"SELECT 1", "SELECT 2"},
		},
		{
			name:     "无注释的复杂语句",
			input:    "CREATE INDEX idx_a ON t(a); CREATE INDEX idx_b ON t(b);",
			expected: []string{"CREATE INDEX idx_a ON t(a)", "CREATE INDEX idx_b ON t(b)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitSQLStatements(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
