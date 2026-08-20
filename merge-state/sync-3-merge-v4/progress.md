# Merge progress

- Target branch: `merge/sync-3-merge-v4`
- Baseline: `60e2d4e40f92e4cbe5032fe5222a83d75a907e01`
- Source ref: `origin/1-merge`
- Source tip: `32a0d9ba2d537875f605e0360c28c7f8d418a29a`
- Frozen compare entries: 164
- Pending: 0
- Merged: 164
- Empty/duplicate applications: 57
- Failed/blocked: 0
- Awaiting user: 0
- Last action: all 164 entries processed automatically; backend packages compile and frontend typecheck pass.
- Verification: `go test -run '^$' ./internal/service ./internal/handler ./internal/repository` passed; `pnpm run typecheck` passed. Full service/repository tests were attempted but the sandbox denies `httptest` listener creation (`operation not permitted`).
- Important adaptation: usage statistics commit `a9514a68d` was resolved using the complete upstream one-scan grouping-sets implementation, with current public settings and dependency wiring retained where they conflicted.
