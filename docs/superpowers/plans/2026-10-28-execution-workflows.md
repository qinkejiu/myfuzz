# Execution workflow implementation plan

**Goal:** Put static authentication at execution boundaries, keep live DUT checks in the hot loop, and separate search from full replay acceptance.

**Architecture:** Existing component/runtime adapters remain. A context-local static memo captures strict results and revalidates them with all memo/mtime shortcuts disabled before publication. Public search summaries remain provisional until that boundary succeeds. CLI execution policy is independent of original/fresh input identity.

## Agreed boundaries

- CLI `--execution-mode search` is the default. `develop` is a one-case smoke; `acceptance` requires actual complete replay.
- Python APIs default `execution_mode=None` to preserve existing strict behavior.
- Source, toolchain, immutable cache and producer reconstruction may be reused only within one explicit execution scope. Exit drift fails the public result; in-memory evidence does not grant a new baseline.
- Dynamic producer/code/artifact/root/cache, actual binary/process, input ownership, protocol, epochs and consumer relations remain checked.
- Search originals skip unconditional internal replay. Real new certified relations select replay; explicit fresh and acceptance always verify. Unknown feedback remains unknown.
- No fake replay success or fresh artifacts when no replay ran. Workflow totals include final boundary validation; subprocess totals include child verification work.
- One implementation agent owns static validation, one the native/generic/F6 replay paths, one GPIO/comparison. Root owns policy, CLI, descriptor integration and final native checks.

## Tasks

- [x] Add `execution_validation_scope` with deep-copied memo results, strict exit, exception/context restoration and no temporary build-stage entries.
- [x] Integrate static source/build/observer/producer checks and freeze issuer source digests; retain dynamic checks.
- [x] Add develop/search/acceptance policy; shared F1–F4, F5 and F6 support explicit no-replay originals.
- [x] Handle search single-execution → acceptance two-execution fresh binding without weakening build, nonce or exit checks.
- [x] Publish only boundary-verified normalized summaries; reject nested public publication, invalidate failed candidates and reject unverified originals for fresh.
- [x] GPIO acceptance uses a separate controller process; capture its output and account for verification time.
- [x] Compare verification facts, not generic replay booleans; distinguish not-requested from failure and incompatible execution modes.
- [x] Select full replay for actual new certified relations, and use compact native search records otherwise.
- [x] Finish integrated software and independent review gates, with no native tests hidden in fixtures.
- [x] Freeze source and run real search/acceptance/fresh checks across the existing flow backends. Measure actual per-case and command totals against saved baselines, not just shifted timing windows.
- [x] Complete verified failure export and a bounded separate-process failure reproducer using the existing backend replay paths. Static/source/cleanup failures are refused, not labelled DUT bugs. Never turn reproduced failure into successful search.
- [x] Update current usage/support matrix and evidence report with measured results and remaining limits.

## Verification evidence

Focused RED/GREEN already covers scope call counts and same-size/mtime-restored drift, published versus temporary cache, pending publication and exit invalidation, search→acceptance binding, skip-replay artifacts, GPIO separate controller policy and comparison validation.

The first integrated gate had 240 passed / 30 skipped plus one stale GPIO CLI fixture that did not write the newly required sidecar; the fixture has been updated. Subsequent search/comparison checks passed. Two implementation tests unintentionally entered native preparation before their mocks were corrected; both were stopped and are not acceptance evidence. Official native runs are owned by root after a source freeze.

Do not infer full workflow acceptance from these software gates alone. Failed-input export/replay requires complete, source-bound terminal material; incomplete records must be explicitly refused.

Final successful native scope: Timer/F1-F3/F5/F6 search→fresh, Timer selective discovery replay, GPIO v2 independent fresh with pinned direct elaboration. Failure reproducer is integrated and software-verified; no certified native DUT-failure specimen was available. Final failure-only factory ordering fix is covered by a RED/GREEN scope test and does not retroactively change frozen native evidence. Details: docs/reports/execution-workflows-20261028.md.
