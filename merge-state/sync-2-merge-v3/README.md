# Upstream merge ledger: sync-2-merge-v3

## Fixed boundaries

- Baseline branch: `merge/sync-2-merge-v3`
- Baseline commit: `ec909bf6ff6b28b08b6f7fb4a1a1a3f1eaf4dbc2`
- Baseline equals `main`, `origin/main`, and `origin/merge/sync-2-merge-v3` at snapshot creation.
- Source ref: `origin/1-merge`
- Source tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- Selection: first-parent commits with committer date on or after `2026-07-22 00:00:00 +0800`.
- Raw selected count: 239.
- Already contained in baseline through historical aggregate commit `9fccb74ac6e98ac7dd9ee982cff221934d3fdaef`: 15.
- Effective merge count: 224.
- First selected commit: `c5971a6fcbd484b94c06177df95902a1b02c9f9e`.
- Last selected commit: `5935e674a84341c3536e27e6a968384f67d9062b`.

The snapshot is immutable for this run. A later fetch must not silently add, remove, or reorder commits in `snapshot.tsv`. The 15 historical matches remain in the raw snapshot for auditability but are excluded from the effective merge queue because `9fccb74ac` is an ancestor of the baseline.

## Merge policy

1. Evaluate each non-excluded selected commit in snapshot order.
2. Low and medium risk commits may be merged automatically.
3. Any risk above medium requires an explicit `merge` or `skip` decision from the user.
4. A skipped commit remains recorded and processing continues with the next snapshot entry.
5. After every above-medium-risk merge, run the complete test suite, including integration tests.
6. Update `state.tsv` and `progress.md` immediately after each decision, merge, skip, or test result.

## Protected fork behavior

Risk evaluation must pay particular attention to overlap with these main-branch differences:

- Gift balance subsystem: priority-consumed gift balance and proportional gift balance. Proportional gifts are usable only when cash balance satisfies the configured ratio.
- Super referral: recharge threshold activation, invitee gift, and inviter reward after invitee gift consumption; all amounts and thresholds are administrator-configurable.
- Smaller fork changes, including regex matching for registered email addresses in gateway email security.
- The fork intentionally may not contain every upstream behavior, including displaying IP addresses in usage records.

An overlap with these areas requires careful behavioral comparison; a clean Git application alone does not establish low risk.

## Files

- `snapshot.tsv`: immutable source commit identity, order, parents, date, subject, and historical-ledger match marker.
- `state.tsv`: live status for this run. The 15 commits already contained in the baseline are `already_in_baseline`; the other 224 entries start as `unassessed` and `pending`.
- `historical.tsv`: exact matches found in the previous merge ledger and the evidence used to exclude them from the effective queue.
- `prerequisites.tsv`: dependencies discovered outside the frozen date window but required to preserve a queued commit's complete feature surface.
- `progress.md`: current aggregate counts and next item.

Historical source: `/home/chris/.claude/projects/-home-chris-projects-sub2api/05670123-5840-438d-8aa9-339ba2116a6e/tool-results/bdqs57mmw.txt`.
