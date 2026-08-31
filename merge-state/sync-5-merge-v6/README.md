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
does not mean the code is missing**: sampling 49 of the 579 (taking one distinctive
added code line per PR and grepping `origin/main`) found 39 already present, 9
genuinely absent, 1 indeterminate — roughly 80% were absorbed by earlier rounds
without their PR number landing in `main`'s log.

The 579 therefore split into two buckets, and **this round covers bucket A only**
(user decision, 2026-08-31):

- **Bucket A (this round, 18 PRs):** numbers above the previous cutoff `#6208`.
  Every one content-checked as genuinely absent. Unambiguously new upstream work.
- **Bucket B (deferred, ~90 PRs):** older-numbered stragglers scattered
  2026-06 → 2026-08 (e.g. `#2007`, `#3267`, `#3794`, `#4188`, `#4461`, `#4625`,
  `#5837`). Not merged. Needs per-PR verification because it mixes genuine
  misses, deliberate prior SKIP decisions (`#4485` prompt-audit, `#3812` split
  plan) and false-absents from the heuristic — if a PR's sampled line was later
  modified by another commit it reads ABSENT even though the PR did land.

## Merge policy

1. Apply all 18 entries in source chronological order with `cherry-pick -m 1 -x`
   (first-parent semantics), matching how previous rounds recorded upstream PRs.
2. Resolve conflicts by preserving fork customizations and accepting upstream's
   additions; never take a whole upstream file that would silently revert fork code.
3. Verify by compiling and running tests — do not assume a marker-free file is correct.
4. Preserve fork-specific gift/super-invite/registration-regex/usage-IP privacy
   behavior and the fork-only `NewOpenAIGatewayService` gift-engine parameter.
5. Record every entry, conflict adaptation and verification result in
   `state.tsv` and `progress.md`.

## Files

- `snapshot.tsv`: immutable 18-entry source identity/order/parent/date/subject snapshot.
- `state.tsv`: per-entry ledger, including the resulting commit on the target branch.
- `progress.md`: aggregate progress, fork-side adaptations and test results.

## Baseline for the next round

The next round's cutoff is **`#6358`** — the highest upstream PR number merged here.
Bucket B remains outstanding and is **not** covered by that cutoff; it must be
selected by PR number, not by "greater than `#6358`".

Note: the previous round (`sync-4-merge-v5`, PR #78) never wrote a ledger directory,
so `merge-state/` jumps from `sync-3-merge-v4` to `sync-5-merge-v6`. The 81 PRs of
that round are recoverable from `git log origin/main` subjects.
