# Incremental merge progress

- Previous source tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- Frozen source tip: `1d3b9665c8824d3b7f5a03a3f50419e812261e91`
- Raw incremental objects: 33
- Effective first-parent merge units: 9
- Pending: 2
- Merged: 7
- Skipped: 0
- Failed/blocked: 0
- Next index: 247
- Next commit: `c204d33b09ebfefe96c1d4dcb16a88590992257e`
- Last action: merged high-risk #246 as `4aa245dde` with unit-only contract adaptation `af6e37ba2`; complete gates passed with documented baseline/shared-DB isolation exceptions.

## High-risk verification

- #240 `0fa577a19`: merged as `b90772c1e`. Restored the complete Grok JWT tier, Grok 4.6, per-model group pricing, x_search, realtime billing and quota behavior. Ent/Wire were regenerated from the combined graph and migration 221 became 236. Search endpoints retain composed prompt-audit/content moderation; accepted ActualCost still uses main's gift allocator and super-invite tracker. Ordinary Go passed. Frontend ESLint/typecheck and 1572/1572 tests passed. Independent integration had one cross-package shared-database keybind failure; the entire keybind integration package passed independently. Unit-tag retained known config/CheckerNil baselines and one unrelated Aliyun transport flake that passed independently. Lint retained only three known G704 findings.
- #246 `fbfdcef81`: merged as `4aa245dde` with adaptation `af6e37ba2`. Grok long-context pricing now follows only the group-level switch and unknown Grok text fallback excludes image/video/audio families. Corrected ActualCost still flows through main gift and super-invite accounting. Ordinary Go passed; frontend ESLint/typecheck and 1572/1572 tests passed. Unit retained only known config/CheckerNil baselines. Integration had the same cross-package shared-database keybind interference and isolated keybind passed. Lint retained only three known G704 findings.
