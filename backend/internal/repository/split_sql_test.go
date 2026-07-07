package repository

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSplitSQLStatements_StringLiterals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "string literal with semicolon",
			input:    "CREATE TABLE t (id INT, expr TEXT DEFAULT 'test;value');",
			expected: []string{"CREATE TABLE t (id INT, expr TEXT DEFAULT 'test;value')"},
		},
		{
			name: "expression index with semicolon in string",
			input: `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_t_expr
ON t ((replace(name, ';', ',')));`,
			expected: []string{`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_t_expr
ON t ((replace(name, ';', ',')))`},
		},
		{
			name:     "multiple string literals with semicolons",
			input:    `INSERT INTO settings(key, value) VALUES ('key1', 'val;ue1'), ('key2', 'val;ue2');`,
			expected: []string{`INSERT INTO settings(key, value) VALUES ('key1', 'val;ue1'), ('key2', 'val;ue2')`},
		},
		{
			name:     "escaped single quotes with semicolon",
			input:    "UPDATE t SET col = 'don''t split; here' WHERE id = 1;",
			expected: []string{"UPDATE t SET col = 'don''t split; here' WHERE id = 1"},
		},
		{
			name:     "quoted identifiers with semicolon",
			input:    `CREATE TABLE "test;table" (id INT);`,
			expected: []string{`CREATE TABLE "test;table" (id INT)`},
		},
		{
			name:     "mixed quotes and semicolons",
			input:    `INSERT INTO t(col1, col2) VALUES ('a;b', "c;d");`,
			expected: []string{`INSERT INTO t(col1, col2) VALUES ('a;b', "c;d")`},
		},
		{
			name:     "comment with semicolon followed by statement",
			input:    "-- This is a comment; with semicolon\nSELECT * FROM t WHERE col = 'value;with;semicolon';",
			expected: []string{"SELECT * FROM t WHERE col = 'value;with;semicolon'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitSQLStatements(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitSQLStatements_MultipleStatements(t *testing.T) {
	input := `
-- First statement
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL
);

-- Second statement with string containing semicolon
INSERT INTO users (name, email) VALUES ('John;Doe', 'john@example.com');

-- Third statement
CREATE INDEX idx_users_email ON users(email);
`

	expected := []string{
		`CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL
)`,
		`INSERT INTO users (name, email) VALUES ('John;Doe', 'john@example.com')`,
		`CREATE INDEX idx_users_email ON users(email)`,
	}

	result := splitSQLStatements(input)
	require.Equal(t, expected, result)
}
