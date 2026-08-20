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
- Last action: all 164 entries processed automatically; post-merge backend and frontend verification completed.
- Verification: `go test ./internal/repository` and `go test ./internal/service` passed outside the restricted sandbox; focused handler/repository compile checks and `pnpm run typecheck` passed. Full tests require allowing local `httptest` listeners outside the sandbox.
- Important adaptation: usage statistics commit `a9514a68d` was resolved using the complete upstream one-scan grouping-sets implementation, with current public settings and dependency wiring retained where they conflicted.
