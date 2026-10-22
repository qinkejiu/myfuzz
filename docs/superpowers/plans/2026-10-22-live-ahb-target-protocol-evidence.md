# Live AHB-Lite target protocol evidence implementation plan

> **For agentic workers:** Follow the referenced design. Preserve the shared
> dirty tree; do not stage, commit, reset, clean, or run remote commands.

**Goal:** Report generated singular AHB-Lite target traces through the existing
Runner protocol evidence and L1 coverage API.

**Architecture:** Extend the existing protocol trace observer with a
Runner-projection-owned singular mode while leaving plural CPU OBI projection
ownership unchanged. Clear coverage correlation on the Runner reset barrier;
do not promote reports into causal feedback.

**Tech Stack:** Python, ScenarioRunner event journal, AHB-Lite raw/projection
schemas, `IpProtocolEvidenceConsumer`, `IpBaseCoverageConsumer`.

## Global constraints

- Follow `../specs/2026-10-22-live-ahb-target-protocol-evidence-design.md`.
- Consume the existing complete Runner event journal without filtering or
  renumbering event IDs.
- Do not create duplicate target raw or protocol projection events.
- Preserve the current plural CPU OBI trace-set behavior and validation.
- Keep reports at `protocol_boundary_only`; no CPU/DMA causal or functional
  success, retirement, bug, or stage-completion claims.
- No RTL/profile/driver/protocol schemas or static F6 changes.
- The initial source slice was limited to static checks under the instruction
  then in force. The follow-up software gate below uses the later instruction
  to run appropriate verification; new native execution remains separate.

## Task 1: observer modes and reset lifecycle

**Files:** modify `src/myfuzz/scenario/protocol_trace_sets.py` and
`src/myfuzz/scenario/ip_base_coverage.py`.

- [x] Keep plural `base_protocol_traces` mode OBI-authenticated and
  projector-owning.
- [x] Add singular `base_protocol_trace` mode with a single endpoint,
  evidence/coverage consumers and an explicit flag stating Runner owns
  projection. Validate the exact `ip_protocol_trace.v1` shape through the
  existing normalizer/checker admission path; do not invoke the OBI verifier.
- [x] On `reset_barrier`, clear all pending coverage correlations while
  retaining feature counters and historical evidence.

## Task 2: Runner admission and report path

**Files:** modify `src/myfuzz/scenario/runner.py`.

- [x] Register singular mode only when the component has an admitted existing
  protocol normalizer/checker and a callable tick-sample drain.
- [x] Keep plural CPU mode gated by `_physical_tick_samples_enabled` and its
  authenticated OBI trace set.
- [x] In `_drain_tick_samples`, run observer-owned checker/normalizer projection
  only for plural producer-owned entries; singular target events remain solely
  Runner-produced.
- [x] Preserve full-journal report cursor semantics and idempotent repeated
  reports.

## Task 3: documentation and static acceptance

**Files:** update `docs/CURRENT_PROGRESS.md`, `docs/LOCAL_HARNESS_RUNTIME.md`,
`docs/reports/README.md`, and add a scoped report under `docs/reports/`.

- [x] Run AST/bytecode syntax checks on the changed production modules and
  inspect exact admission/event ownership paths; do not run tests under the
  current instruction.
- [x] Record that live AHB target reporting is source-integrated but not
  runtime-validated until a real Runner replay gate is requested/executed.
- [x] Keep P6/P7/P8 and generic same-protocol onboarding open.

Task 1 and Task 2 are source-integrated. Task 3 static checks ran on 2026-10-22:
`python3 -m py_compile` for the three production modules and scoped
`git diff --check` both exited 0. The independent source review and native
Runner replay remain separate gates; this plan does not mark runtime acceptance.

## Follow-up software acceptance (2026-10-22)

- [x] Preserve original archived Caliptra first/fresh/artifact bytes as pinned
  deterministic gzip inputs in a non-ignored evidence directory.
- [x] Use actual Runner singular projection and file-backed EventJournal to
  check 91 unique boundary certificates per historical input, exact raw sample
  equality, complete journal IDs/cursors and first/fresh software prefix.
- [x] Reject changed response values and wrong-phase POST raw references.
- [x] Verify synthetic coverage-barrier pending-clear/count retention without
  representing it as live hardware reset.
- [x] Retain failed integration attempt1 (70 passed/4 old OBI fixture errors);
  authenticate exact historical/current source provenance separately and
  preserve physical/SV/CPP equality in the OBI retrospective fixture.
- [x] Final five-module software gate:77 passed/67 subtests,exit0,selected
  before/after input hashes unchanged; independent reviews have no blocker.

See `docs/reports/live-ahb-target-protocol-evidence-20261022.md` and evidence
`software-attempt2/verification.json`. This is retrospective software proof,
not a new native run or a complete source closure freeze.

## Native completed-transfer acceptance (2026-10-22)

- [x] Real current generated target through Runner and file-backed journal.
- [x] First/fresh each eight unique raw-linked certificates, six reads/two writes, pending0.
- [x] Full action/journal/report/identity equality, no journal normalization.
- [x] Completed-transfer warm_all restart, cumulative ticks/epochs, four distinct reaped processes exit0.
- [x] Declared361 build inputs and3 verifier files frozen/archived; cache/binary pinned.
- [x] Failed native-attempt1 preserved; exact saved-input verifier correction and successful attempt2 retained.

Actual attempt2:1 passed/13.47s,exit0. This closes only normal completed
transfers, process restart and fresh reporting. See the scoped report.

## Remaining native branches

Use real AHB target pre/post sample receipts in a Runner-backed native
composition; verify complete journal identity, request/accept/response and
wait/error/cancel references, one fresh replay, reset-barrier pending clear,
and pending zero. Preserve AHB's no-native-ID gap. The completed-transfer/restart subset above is now executed. Positive wait,
error and in-flight cancellation cannot be inferred from it, the offline DMA
provider receipt or CPU AHB observation.

The current Caliptra wrapper ties hold and bus error low. It cannot supply
positive native wait/error cases; those require a genuine capable target or
stimulus. Its ordinary completed transfers also cannot prove in-flight reset
cancellation. These branches remain open rather than inferred from synthetic
coverage controls.
