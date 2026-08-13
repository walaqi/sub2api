# Merge progress

- Baseline: `ec909bf6ff6b28b08b6f7fb4a1a1a3f1eaf4dbc2`
- Source snapshot tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- Raw snapshot total: 239
- Effective merge total: 224
- Already in baseline: 16
- Pending: 220
- Awaiting user: 0
- Merged: 3
- Skipped: 0
- Failed/blocked: 0
- Next index: 20
- Next commit: `3e5d4af411977b0b14860ac5796831c02b0fb1be`
- Last action: prerequisites `9f5b57fc9` and `44ab690a` merged as `eccfc09db` and `9c57d3da8`; gift-safe batch holds covered by `edaa4e7ff`; complete integration and frontend gates passed
- Active prerequisite: `65ff800362dc0c2b20c5f14ca78dbf3d02a1af23` (high risk; batch image billing, state-machine and queue hardening)

## High-risk verification notes

- `9f5b57fc9`: preserved the fork gift engine, proportional gift constraints, overdraft marker and balance cache synchronization.
- `44ab690a`: retained the complete batch image implementation instead of dropping unresolved endpoints; billing holds use recharge balance only and do not consume or freeze gifts.
- Added regression coverage in `edaa4e7ff` for rejecting a hold larger than recharge balance even when gift balance makes total balance sufficient.
- `make -C backend test-integration`: passed, including current migrations on an isolated PostgreSQL container and gift/referral service flows.
- Frontend ESLint, `vue-tsc`, and critical Vitest: passed (6 files, 97 tests).
- `make test`: Go tests pass; lint stops only on three baseline gosec G704 findings in unchanged `internal/pkg/servertiming/http.go` and `internal/server/middleware/openai_fast_policy_forwarding_test.go`.
- The fixed localhost service-test database predated the batch image migrations and lacked `users.frozen_balance`; the idempotent `160_add_user_frozen_balance.sql` was applied to that local test database before rerunning. The repository integration harness independently proved the full migration set from a clean database.
