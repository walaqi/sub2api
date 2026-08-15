# Incremental merge progress

- Previous source tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- Frozen source tip: `1d3b9665c8824d3b7f5a03a3f50419e812261e91`
- Raw incremental objects: 33
- Effective first-parent merge units: 9
- Pending: 1
- Merged: 8
- Skipped: 0
- Failed/blocked: 0
- Next index: 248
- Next commit: `1d3b9665c8824d3b7f5a03a3f50419e812261e91`
- Last action: merged high-risk #247 as `d4a6a8ebb` with migration-number adaptation `7d14ffa5a`; complete gates passed with the documented shared-DB isolation and lint baseline exceptions.

## High-risk verification

- #240 `0fa577a19`: merged as `b90772c1e`. Restored the complete Grok JWT tier, Grok 4.6, per-model group pricing, x_search, realtime billing and quota behavior. Ent/Wire were regenerated from the combined graph and migration 221 became 236. Search endpoints retain composed prompt-audit/content moderation; accepted ActualCost still uses main's gift allocator and super-invite tracker. Ordinary Go passed. Frontend ESLint/typecheck and 1572/1572 tests passed. Independent integration had one cross-package shared-database keybind failure; the entire keybind integration package passed independently. Unit-tag retained known config/CheckerNil baselines and one unrelated Aliyun transport flake that passed independently. Lint retained only three known G704 findings.
- #246 `fbfdcef81`: merged as `4aa245dde` with adaptation `af6e37ba2`. Grok long-context pricing now follows only the group-level switch and unknown Grok text fallback excludes image/video/audio families. Corrected ActualCost still flows through main gift and super-invite accounting. Ordinary Go passed; frontend ESLint/typecheck and 1572/1572 tests passed. Unit retained only known config/CheckerNil baselines. Integration had the same cross-package shared-database keybind interference and isolated keybind passed. Lint retained only three known G704 findings.
- #247 `c204d33b0`: merged as `d4a6a8ebb` with adaptation `7d14ffa5a`. Group usage daily rollups provide server-timezone today/yesterday/retained totals and atomically invalidate historical buckets when usage rows are changed or cleaned. Conflicting upstream migrations 222/223 were renumbered to 237/238. The feature reads admin summary `actual_cost` only; main gift allocation, super-invite tracking and ordinary-user IP privacy remain unchanged. Focused unit and PostgreSQL trigger tests, ordinary Go, frontend tests/ESLint/typecheck and unit passed. Full integration had only the known cross-package keybind shared-database interference and the complete keybind package passed independently. Lint retained exactly the three known G704 findings.
