# Incremental merge progress

- Previous source tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- Frozen source tip: `1d3b9665c8824d3b7f5a03a3f50419e812261e91`
- Raw incremental objects: 33
- Effective first-parent merge units: 9
- Pending: 5
- Merged: 4
- Skipped: 0
- Failed/blocked: 0
- Next index: 244
- Next commit: `e803e3851c0a7e222cfadeafad7b8636ab959d11`
- Last action: merged medium-risk #243 as `0d962635e`; Wire regeneration and focused cache invalidation tests passed.

## High-risk verification

- #240 `0fa577a19`: merged as `b90772c1e`. Restored the complete Grok JWT tier, Grok 4.6, per-model group pricing, x_search, realtime billing and quota behavior. Ent/Wire were regenerated from the combined graph and migration 221 became 236. Search endpoints retain composed prompt-audit/content moderation; accepted ActualCost still uses main's gift allocator and super-invite tracker. Ordinary Go passed. Frontend ESLint/typecheck and 1572/1572 tests passed. Independent integration had one cross-package shared-database keybind failure; the entire keybind integration package passed independently. Unit-tag retained known config/CheckerNil baselines and one unrelated Aliyun transport flake that passed independently. Lint retained only three known G704 findings.
