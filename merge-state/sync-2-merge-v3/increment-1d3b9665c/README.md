# Incremental upstream snapshot: 1d3b9665c

## Fixed boundaries

- Merge baseline branch: `merge/sync-2-merge-v3`
- Merge baseline commit: `d56879c06d6868abb9359b4c4ee0426e6d21eb2d`
- Source ref at fetch: `origin/1-merge`
- Previous source tip: `5935e674a84341c3536e27e6a968384f67d9062b`
- New source tip: `1d3b9665c8824d3b7f5a03a3f50419e812261e91`
- Reachable Git objects in the incremental range: 33
- First-parent merge units: 9

The 33-object range contains the internal second-parent histories of eight pull
request merges. Applying those internal commits and their merge commits would
duplicate each pull request. This snapshot therefore processes the nine
first-parent increments, while `objects.tsv` preserves all 33 object identities
for completeness and dependency auditing.

## Active policy

- Automatically merge every item regardless of risk level.
- Preserve main's gift, super-invite, registration-regex, usage-IP privacy and
  composed content-moderation/prompt-audit behavior.
- Resolve required second-parent dependencies rather than dropping features.
- Run complete ordinary, unit-tag, frontend, lint and independent integration
  tests after every high-risk merge.
- Update `state.tsv`, `progress.md` and the parent progress ledger after each
  resolved merge unit.

