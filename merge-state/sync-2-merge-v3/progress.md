# Merge progress

- Baseline: `ec909bf6ff6b28b08b6f7fb4a1a1a3f1eaf4dbc2`
- Source snapshot tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- Raw snapshot total: 239
- Effective merge total: 224
- Already in baseline: 16
- Pending: 212
- Awaiting user: 0
- Merged: 11
- Skipped: 0
- Failed/blocked: 0
- Next index: 28
- Next commit: `6f7bad3f2fa3a5727485848a1d0c4c132fcf4cb8`
- Last action: medium-risk simple-mode Grok image enablement `fbc88edf9` merged as `0e6bbd6f8`; upstream migration 186 was moved after main's outbox migration as 204; focused repository integration tests passed
- Active queue commit: none

## High-risk verification notes

- `9f5b57fc9`: preserved the fork gift engine, proportional gift constraints, overdraft marker and balance cache synchronization.
- `44ab690a`: retained the complete batch image implementation instead of dropping unresolved endpoints; billing holds use recharge balance only and do not consume or freeze gifts.
- Added regression coverage in `edaa4e7ff` for rejecting a hold larger than recharge balance even when gift balance makes total balance sufficient.
- `make -C backend test-integration`: passed, including current migrations on an isolated PostgreSQL container and gift/referral service flows.
- Frontend ESLint, `vue-tsc`, and critical Vitest: passed (6 files, 97 tests).
- `make test`: Go tests pass; lint stops only on three baseline gosec G704 findings in unchanged `internal/pkg/servertiming/http.go` and `internal/server/middleware/openai_fast_policy_forwarding_test.go`.
- The fixed localhost service-test database predated the batch image migrations and lacked `users.frozen_balance`; the idempotent `160_add_user_frozen_balance.sql` was applied to that local test database before rerunning. The repository integration harness independently proved the full migration set from a clean database.
- `65ff8003`: preserved recharge-only gift-safe holds while adding phantom-release protection, atomic queue/state transitions, settlement retry exhaustion, hold/discount validation, and image-only token-pricing fail-closed behavior. Its `admin_service.go` increment was mapped to main's split `admin_group.go` implementation.
- `09729ba5`: merged the final post-revert implementation from its three-commit second-parent chain (`1fb942dd`, `e5e94d1`, `0eb6e21`), including task persistence, polling routes and S3-compatible result offload. Existing batch image, gift/referral, Image Studio and risk-control wiring were retained. Default URL downloads now use resolved-IP validation and reject private hosts; focused service lint reports zero issues.
- `bfabfe60`: added reachable environment keys and admin-managed, immediately reloadable image-storage settings with backup-S3 reuse and step-up protection; focused backend and frontend gates passed.
- `3e5d4af4`: merged the complete composite-groups implementation, including migration, Ent model, resolver, admin API/UI, provider-aware routing and usage attribution. Main-specific gift deletion semantics, group-scoped gift billing, affiliate/notification dependencies, client-error throttling, batch/async image routes, Image Studio and websearch wiring were retained. Added a regression asserting that an OpenAI target account still bills gifts against the composite API-key group. `go test ./...` passed; integration packages passed (the service package passed on isolated rerun after one suite-level timing failure); frontend ESLint and typecheck passed. Full Vitest had 1253/1255 passing, with two unchanged baseline rollback-timeout argument assertions failing. `make test` stopped only on the same three baseline G704 findings.
- `ba88cc239`: user-approved high-risk billing correction merged as `130e06bfd`. Composite public aliases now use the concrete forwarded model unless explicitly channel-priced, preventing zero or family-fallback misbilling. The corrected ActualCost continues through main's gift/recharge allocator and super-invite spend tracker; focused regression confirms the composite API-key group remains the gift scope. Full Go and integration tests passed; frontend lint/typecheck passed; Vitest retained only the two confirmed rollback-timeout baseline failures; golangci-lint retained only the same three baseline G704 findings.
- `09b1309c9`: user-approved high-risk channel-pricing normalization merged as `e9e94e03e`. Claude dot/hyphen model spellings now resolve to the same custom channel price; corrected ActualCost continues through main's gift/recharge allocator and super-invite spend tracker without changing gift group scope. Focused pricing, composite billing and gift-scope tests passed; full Go and integration tests passed; frontend lint/typecheck passed; Vitest retained only the two confirmed rollback-timeout baseline failures; golangci-lint retained only the same three baseline G704 findings.
