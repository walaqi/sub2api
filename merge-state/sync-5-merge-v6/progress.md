# Merge progress

- Target branch: `merge/sync-5-merge-v6`
- Baseline: `e13c5bf444e7efdce970dcb284b255434932ae5d` (main after PR #78)
- Source ref: `origin/1-merge`
- Source tip: `b5827cfd54d58c248a9480b800444d0b40f0c6ea`
- Branch tip at ledger time: `9896d82d378d32f0723a08cb5e142f6d5a561ae0`
- Resulting PR: walaqi/sub2api#79 (28 commits, 189 files)
- Selected entries: 22 (18 bucket A + 4 bucket B)
- Pending: 0
- Merged: 22
- Conflicted then resolved: 6 (`#6270`, `#6278`, `#6358`, `#4581`, `#5926`, `#6188`)
- Empty/duplicate applications: 0
- Failed/blocked: 0
- Awaiting user: 0
- Bucket B: all 561 audited by content — 487 already present, 63 deferred,
  4 merged, 4 superseded, 2 skipped, 1 no-op. See `README.md` and `bucketB_audit.tsv`.

## Merged PRs

**Bucket A (18)** — above the previous `#6208` cutoff:

`#6211` `#6227` `#6229` `#6246` `#6255` `#6260` `#6263` `#6270` `#6277` `#6278`
`#6291` `#6293` `#6299` `#6303` `#6309` `#6310` `#6312` `#6358`

**Bucket B (4)** — genuinely-absent older PRs recovered by the content audit:

`#4581` (GitHub release token), `#5620` (anthropic chat bridge reasoning passback),
`#5926` (routed codex model catalog, 49 files), `#6188` (usage requested reasoning
effort, 41 files).

Content is concentrated in the OpenAI/Grok gateway: Spark quota 429 scoped to model
level (`#6358`), image-tool cooldown no longer triggered by "model replied with text"
(`#6270`), ws-v2 passthrough and tool-id regressions (`#6211`/`#6293`/`#6312`),
non-streaming terminal-failure failover (`#6310`), Grok 4.6 xhigh tier (`#6278`),
per-user public-group access control (`#6303`), easypay relative pay URL / QR code
(`#6309`), register-page OAuth and promo code (`#6227`).

## Conflict adaptations

- **`#6270`** — `openai_images_responses.go`: all 4 hunks were empty-HEAD (pure
  additions). After clearing markers, `responseBody` was declared twice because
  upstream hoisted it to the top of the function; fork's duplicate was removed to
  match upstream structure. Separately, the forward-level test
  `TestOpenAIGatewayServiceForwardImages_TextFallbackDoesNotCoolImageCapability`
  asserted `result==nil` + 502 failover, which cannot hold in fork: fork's image
  SSE path never wires up `openAIImagesTextFallbackError` (fork lacks upstream's
  `len(results)==0` error-classification block), so a text-only reply returns a
  successful result instead. The assertion was rewritten to fork reality with a
  comment; the PR's actual invariant — never write an account-level cooldown from
  this signal — is still asserted, and 3 of the 4 new tests pass verbatim.
- **`#6278`** — `openai_codex_models_service.go` conflicted as a whole file.
  Took fork's version (785 lines), which contains no `configuredCodexGrokReasoningLevels`
  and no xhigh references, so upstream's one-line
  `grokSupportsXHighReasoningEffort` → `GrokSupportsXHighReasoningEffort` rename has
  no counterpart here. The exported name landed correctly through the other files
  in the PR, which staged cleanly.
- **`#6358`** — `ratelimit_service.go` had a single empty-HEAD hunk. Taking it
  produced `undefined: openAIImageCapabilityLossCooldown` / `...Reason`, because
  upstream added those two constants inside the same const block that fork's side
  of the conflict retained. Adding them made the file byte-identical to upstream.
- **`#4581`** (bucket B) — `deploy/docker-compose.yml`: both sides added an env var
  at the same spot. Kept both (fork's `ALIPAY_MOBILE_PRECREATE_DEEP_LINK` and
  upstream's `UPDATE_GITHUB_TOKEN`).
- **`#5926`** (bucket B) — `gateway_models_test.go` had one empty-HEAD hunk; the
  types and helpers the incoming block needs were already staged by the same pick, so
  it was taken wholesale. Two follow-ons: the new
  `configuredCodexGrokReasoningLevels` called the *pre-rename* lowercase
  `grokSupportsXHighReasoningEffort`, which `#6278` had already renamed to the
  exported form earlier in this round; and 5 test call sites (4 ×
  `NewOpenAIGatewayService`, 1 × `NewGatewayService`) needed the fork-only trailing
  `giftEngine` argument.
- **`#6188`** (bucket B) — the highest-risk conflict of the round; see the
  `usage_logs` column invariant table in `README.md`. Column lists auto-merged to the
  correct 64-column union, but the `$N` placeholder lines and capacity hints
  conflicted (fork 63 vs upstream 60) and were rewritten to `$1..$64`. Arg indices in
  `usage_log_session_id_unit_test.go` moved from upstream's 47/48 to fork's 49/50
  (+2 for the gift columns). One upstream test asserting a user-visible
  `IPAddress` on the user-facing DTO was dropped: fork's user DTO deliberately has no
  IP field (`// IPAddress 用户请求 IP（仅管理员可见）`), so the assertion contradicts
  fork's usage-IP privacy policy by design. On the frontend, upstream's markup
  referenced `currentToggleableColumns` / `isCurrentColumnVisible` /
  `toggleCurrentColumn`, none of which exist in fork (fork uses
  `toggleableColumns` / `isColumnVisible` / `toggleColumn`) — taking upstream's side
  would not compile, so fork's markup was kept and `hasReasoningEffortMapping` was
  re-added by hand. The IP-geolocation lines in the same hunk were intentionally
  omitted: they depend on `#3615`, which fork has not merged.

## Fork-side adaptation commits

- `4e148b0438e33565b1802235ba25120547a38c64` — `fix(test)`: `#6293`'s new test called
  `NewOpenAIGatewayService` with 22 arguments; fork's signature takes 23, ending in
  the fork-only `giftEngine *gift.Engine`. This broke typecheck for the whole
  `internal/handler` package.
- `d9cda81f572c33f823e026d0a8fef4bd0e7c9a8f` — `fix(lint)`: the 7 text-fallback
  helpers `#6270` brought in have no call sites in fork (see the `#6270` note above),
  so `unused` fired. Marked with the `//nolint:unused // WIP streaming images support`
  convention already used 8 times in that file.
- `c57f0f43e9779d8b7cb415f4984246be835b8c9c` — `fix(migrations)`: `#6303`'s
  `231_user_restrict_public_groups.sql` collided with fork's existing
  `231_channel_monitor_hide_throughput.sql`; renumbered to `242`, following
  `b32fee978`'s precedent. The filename has no code references.
- `adafdb06f` — `fix(migrations)`: same collision class for `#6188`'s
  `231_add_usage_log_requested_reasoning_effort.sql`; renumbered to `243`.
- `9896d82d3` — `test(usage)`: wired `#6188`'s new integration test to fork markup.
  Three failures, all fork/upstream UI divergence rather than functional defects:
  fork's `DataTable.vue` reads `window.matchMedia` during setup (upstream's does not,
  so the upstream test carried no stub — stubbed for desktop, matching
  `DataTable.spec.ts`); and the `data-testid` hooks the test needs
  (`usage-column-settings`, `usage-column-toggle-*`, `reasoning-effort-cell`) were
  absent from fork's markup, which the conflict resolution had preserved. Attributes
  only — no behaviour or styling changed.

## Verification

All green on `9896d82d3`:

- `go build ./...`
- `go test -tags=unit ./...`
- `go test -tags=integration ./...`
- `golangci-lint run ./...` — 0 issues
- `pnpm run typecheck`, `pnpm run lint`
- frontend unit tests: **249 files / 1805 cases**
- `usage_logs` column invariant re-audited after `#6188`: SELECT ↔ Scan aligned
  position-by-position across all 65 columns, 0 mismatches; `gift_cost` /
  `recharge_cost` confirmed present at every one of the five sync sites
- CI on PR #79 (bucket A state): test, golangci-lint, frontend, backend-security,
  frontend-security, shell all pass. Bucket B commits pushed after that run —
  re-check CI before merging.

### Local integration DB must be migrated first

The first integration run produced 14 gift/referral failures reporting
`pq: column "restrict_public_groups" does not exist`. Root cause was a **stale local
test database** (missing `239`/`240`/`241` from the previous round plus this round's
`242`), not a code defect — the ent client emits the new column in UPDATEs and
Postgres rejects it, so failures surface on shared paths like `add balance` and look
like a broken gift subsystem. Applying migrations with the project's own runner
(`repository.ApplyMigrations`, which records `schema_migrations` filename/checksum
rows correctly — do not hand-write DDL) made the whole suite green. Anyone running
integration tests should migrate the test DB first. This round adds `242` and `243`,
so the same step is required again.

## Known follow-ups

- `#6270`'s forward-level test is written against fork's current behavior. Once fork
  wires up the image SSE `len(results)==0` classification branch, restore upstream's
  original assertions (`result==nil` + 502 failover) and drop the 7
  `//nolint:unused` markers added in `d9cda81f5`.
- Recorded fork behavior, pre-existing and not introduced here: an image response
  with no image output is still counted as one image (`ImageCount:1`). Noted in the
  test comment.
- `#6188` frontend: fork kept its own column-settings markup, so upstream's
  IP-geolocation toolbar in the same hunk was omitted along with `#3615`. If `#3615`
  is ever merged, revisit `UsageTable.vue` to pick up `showIpGeoToolbar` /
  `ipGeoBatchLoading`.
- Bucket B: 63 `DEFERRED` entries remain open — mostly PARTIAL matches where
  upstream's change was likely absorbed in a reformulated shape. `#3615` (usage IP
  geolocation) needs a product decision because it collides with fork's admin-only IP
  policy; `#4125` (Apple container / macos-15 CI) is infra scope. See
  `bucketB_audit.tsv` for the per-PR verdicts.
