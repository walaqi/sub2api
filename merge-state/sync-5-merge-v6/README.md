# Upstream merge ledger: sync-5-merge-v6

## Fixed boundaries

- Target branch: `merge/sync-5-merge-v6`
- Baseline branch: `main`
- Baseline commit: `e13c5bf444e7efdce970dcb284b255434932ae5d` (main after PR #78 / sync-4-merge-v5)
- Source ref: `origin/1-merge`
- Source tip: `b5827cfd54d58c248a9480b800444d0b40f0c6ea`
- Selection method: upstream PR-number set difference, `origin/1-merge` minus `main`, restricted to PR numbers above the previous round's cutoff `#6208`
- Raw selected commits: 18 (`#6211`–`#6358`, upstream 2026-08-26 → 2026-08-29)
- Resulting PR: walaqi/sub2api#79

## Selection method (important)

`main` and `origin/1-merge` have **diverged lineages** — their merge-base is `63b0631a5`
(2026-05-23). Every prior round replayed upstream PRs as *new SHAs* via
`cherry-pick -m 1 -x`, so git ancestry cannot identify pending work: a naive
`git rev-list origin/main..origin/1-merge` reports 2765 commits / 916 PR merges,
which is badly inflated. Selection is therefore done by upstream PR number:

```bash
git log origin/main   --format=%s | grep -oE "Merge pull request #[0-9]+" | grep -oE "[0-9]+$" | sort -u > pr_main.txt
git log origin/1-merge --format=%s | grep -oE "Merge pull request #[0-9]+" | grep -oE "[0-9]+$" | sort -u > pr_1merge.txt
comm -13 pr_main.txt pr_1merge.txt   # NOTE: comm needs lexicographic sort, do not sort -n first
```

That difference yields **579** PR numbers. A **PR number missing from `main`'s log
does not mean the code is missing** — roughly 87% were absorbed by earlier rounds
without their PR number landing in `main`'s log (see the bucket B audit below).

The 579 split into two buckets:

- **Bucket A (18 PRs):** numbers above the previous cutoff `#6208`. Every one
  content-checked as genuinely absent. Unambiguously new upstream work.
- **Bucket B (561 PRs):** older-numbered stragglers scattered 2026-06 → 2026-08.

Both buckets were processed in this round (user decisions, 2026-08-31): bucket A
first, then bucket B after a full content audit.

### Bucket B audit (all 561 verified by content, not by number)

`bucketB_audit.tsv` records the per-PR verdict. Method: for each PR's merge commit
`M`, take `git diff M^1 M`, collect distinctive added lines, and look for them in a
worktree of the target branch. Round 1 checked code extensions only; round 2
re-checked every non-PRESENT candidate across **all** file types with a whole-tree
fallback so renames and moved files are not mistaken for missing code.

| Final | Count |
|---|---|
| PRESENT (already in `main`) | 487 |
| DEFERRED (partial / needs per-PR review) | 63 |
| MERGED this round | 4 |
| SUPERSEDED | 4 |
| SKIP (fork already solves it better) | 2 |
| NO_OP | 1 |

**Merged (4):** `#4581` `#5620` `#5926` `#6188` — the genuinely-absent core.

**Deliberately not merged, with reasons:**

- `#2960` **SKIP** — CWE-79 key-name XSS. Fork's `validateAPIKeyName` already
  rejects `<`/`>` at input plus control chars and length limits, and comments that
  the output layer still escapes. Upstream's `html.EscapeString` instead mutates
  stored data (`&lt;script&gt;` in the DB) and would drop fork's other checks.
  Fork's approach is strictly stronger.
- `#3405` **SKIP** — subscription order CNY conversion. Fork has its own
  `SubscriptionUSDToCNYRate` mechanism (explicit opt-in, `price × rate` only when
  the gateway currency is CNY); upstream's `BalanceRechargeMultiplier` path would
  regress the conversion behaviour that was already closed out separately.
- `#3001`, `#3846`, `#5690` **SUPERSEDED** — Go toolchain bumps to 1.26.4 / 1.26.5
  / Dockerfile pin. `main` is already on **go1.27.0**; merging these would
  *downgrade* the toolchain.
- `#3769` **SUPERSEDED** — xlsx audit exception renewal; already renewed on `main`.
- `#3747` **NO_OP** — a revert of `#3738`, which is not in `main` either.
- `#3195`, `#3335`, `#3718` **PRESENT** — low similarity scores, but the target
  symbols (`invalid_grant`, `resolveOpenAIUpstreamEndpoint`, BOM `﻿`) are
  already in `main` via reformulated implementations.
- `#3615` **DEFERRED** — usage IP geolocation. Collides with fork's deliberate
  usage-IP privacy divergence (fork exposes IP to admins only), so it needs a
  product decision rather than a mechanical merge.
- `#4125` **DEFERRED** — Apple container / `macos-15` CI support; infra scope.

The 63 DEFERRED entries are mostly PARTIAL matches, which usually means upstream's
change was absorbed in a reformulated shape. Each needs reading before any merge;
none is known to be a functional gap.

## Merge policy

1. Apply entries in source chronological order with `cherry-pick -m 1 -x`
   (first-parent semantics), matching how previous rounds recorded upstream PRs.
2. Resolve conflicts by preserving fork customizations and accepting upstream's
   additions; never take a whole upstream file that would silently revert fork code.
3. Verify by compiling and running tests — do not assume a marker-free file is correct.
4. Preserve fork-specific gift/super-invite/registration-regex/usage-IP privacy
   behavior and the fork-only `NewOpenAIGatewayService` gift-engine parameter.
5. Record every entry, conflict adaptation and verification result in
   `state.tsv` and `progress.md`.

### usage_logs column invariant (highest-risk area)

`#6188` adds a `usage_logs` column, and this fork carries 4 columns upstream does
not (`gift_cost`, `recharge_cost`, `device_id`, `client_fingerprint`). Taking either
side of such a conflict silently drops columns — this is the SELECT/Scan drift class
that previously caused a production bug (fixed in PR #72/#73). The union was verified
at every site the code requires to stay in sync
(see the comment block above `usageLogInsertArgTypes`):

| Site | Count | gift_cost / recharge_cost |
|---|---|---|
| INSERT column lists (4 paths, incl. 6× and 3× batch CTEs) | 64 / 384 / 192 / 64 | pos 28 / 29 |
| `usageLogInsertArgTypes` | 64 | `[27]`/`[28]` = `numeric` |
| `prepareUsageLogInsert().args` | 64 | `log.GiftCost` / `log.RechargeCost` |
| `usageLogSelectColumns` | 65 | pos 29 / 30 |
| `scanUsageLog` targets | 65 | `giftCost` / `rechargeCost` |

SELECT ↔ Scan was checked position-by-position: **0 mismatches across all 65**.
Note the fork offset — `requested_reasoning_effort` sits at 0-indexed **50** here,
not upstream's 48, because the two gift columns precede it. Any future usage_logs
column must update all five sites together.

## Files

- `snapshot.tsv`: immutable 18-entry bucket A source identity/order/parent/date/subject snapshot.
- `state.tsv`: per-entry ledger (22 rows: 18 bucket A + 4 bucket B), including the
  resulting commit on the target branch. Bucket B rows are prefixed `[bucketB]`.
- `bucketB_audit.tsv`: all 561 bucket B PRs with round-1/round-2 verdicts and final disposition.
- `progress.md`: aggregate progress, fork-side adaptations and test results.

## Baseline for the next round

The next round's cutoff is **`#6358`** — the highest upstream PR number merged here.

Bucket B is now audited, so the next round does **not** need to re-verify it: consult
`bucketB_audit.tsv` instead. Only the 63 `DEFERRED` entries remain open, and the
`SKIP`/`SUPERSEDED`/`NO_OP` verdicts should not be revisited without a new reason —
re-merging the toolchain PRs would downgrade Go, and re-merging `#2960`/`#3405` would
regress fork behaviour.

Note: the previous round (`sync-4-merge-v5`, PR #78) never wrote a ledger directory,
so `merge-state/` jumps from `sync-3-merge-v4` to `sync-5-merge-v6`. The 81 PRs of
that round are recoverable from `git log origin/main` subjects.
