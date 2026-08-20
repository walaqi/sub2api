# Upstream merge ledger: sync-3-merge-v4

## Fixed boundaries

- Target branch: `merge/sync-3-merge-v4`
- Baseline branch: `main`
- Baseline commit: `60e2d4e40f92e4cbe5032fe5222a83d75a907e01`
- Source ref: `origin/1-merge`
- Source tip: `32a0d9ba2d537875f605e0360c28c7f8d418a29a`
- Selection source: the supplied GitHub compare HTML, `walaqi/1-merge...Wei-Shaw/main`
- Raw selected commits: 164
- The frozen snapshot preserves the HTML compare order, including older May and July commits.

## Merge policy

1. Process all 164 frozen entries in snapshot order.
2. Automatically resolve and merge each item; do not pause for a user decision.
3. Merge commits are applied with first-parent semantics; an empty application is recorded as already represented by earlier applied parents.
4. Preserve main-specific gift, super-invite, registration-regex, usage-IP privacy, content moderation and prompt-audit behavior.
5. Record every result, conflict adaptation, skip/empty application and verification in `state.tsv` and `progress.md`.

## Files

- `snapshot.tsv`: immutable 164-entry source identity/order/parent/date/subject snapshot.
- `state.tsv`: live per-entry ledger.
- `progress.md`: aggregate progress and known test results.

