# A2 generated APB storage startup: host consumption report

Date: 2026-10-17. Scope: source-only host admission and consumption of generated
`apb_storage_startup_capture.v1` pages, plus the C issuer startup-retrieval
phase. Basis: `apb-storage-a2-host-consumer-brief.md` (authoritative),
`apb-storage-a2-generation-implementation.md`, `apb-storage-a2-startup-design.md`,
`apb-storage-C-independent-source-review.md`, `apb-storage-version-integration-brief.md`.
No DUT, frontend, model, Verilator, remote, SSH, cache-eligibility or native build
was executed. No F4 or native authority is claimed.

Base implementation commit: `4c0a62c15e1f24404dc86fb1a2f83c5710be2db4` (`feat: consume generated APB
storage startup pages`). Final source-pin/fix and evidence commit: the commit
containing this report (its SHA is reported in the handoff message), which adds
the C pending operation/fields match tightening, explicit host process/case/
epoch assertions, refreshed `source-freeze.json` and this report. Exact final
source bytes are frozen in `.superpowers/apb-storage-a2-host/source-freeze.json`.

## Implemented interface

### `src/myfuzz/local_harness/session.py`

- `_expected_ready()` now has an exact A2 branch only when `kind ==
  apb3_register_observe` and `driver_schema_version ==
  local_driver_generation.apb_storage_startup.v2` with both
  `storage_startup_selection` and `storage_startup_capture` present. It rejects
  A2 markers on any other runtime kind, partial capture/selection, unknown
  capture keys, wrong schema, and wrong digests. It calls the canonical
  `apb_storage_startup.contract_from_document` and normalizes malformed
  `KeyError`/`TypeError` cases to `ValueError`.
- Ordinary v1 and AHB v2 branches keep their existing schema check and return
  tuple bytes. A2 release ticks may be zero (the generated contract permits it);
  v1 still requires at least one release tick. AHB branch unchanged.
- The private `_STORAGE_STARTUP_OPERATIONS = {'READ_APB_STORAGE_STARTUP':
  (63,)}` is merged in `_command_impl` only after `_expected_ready()` admitted
  the exact A2 document. `_OPERATIONS` and `registered_operations(kind)` are
  untouched; Standard/AHB callers never see the APB READ.
- The private operation table is pinned alongside `_OPERATIONS` in the existing
  native-reset producer guard; `_command_impl` retains the exact unparsed
  last reply (`_last_wire_reply`) so a host consumer can preserve raw wire
  context through parse/identity failures. The actual parser and callbacks are
  not wrapped or replaced.

### `src/myfuzz/local_harness/apb3_register_session.py`

- Private A2 state is initialized before use: admitted contract, exact probe
  port copies, required/retrieving/complete flags, page receipts, last receipt,
  failure record, cumulative receipt-storage bytes, and permanent-failure latch.
- The constructor requires the closed producer: empty setup writes, empty probe
  offsets, no dynamic inputs, no bound inputs. It revalidates the contract via
  `contract_from_document`.
- `begin_case` keeps the base lifecycle (identity, build issuance, fresh
  execution, READY), then clears ordinary state and, before returning and before
  any setup/STEP/ACCESS/SOURCE/BIND, retrieves every ordered page through
  `self.command('READ_APB_STORAGE_STARTUP', (page,))`. Each page must be a
  `result` with the current execution, expected wire sequence, zero tick
  before/after/new ticks, empty samples, `rdata=0`, `error=0`, exactly
  `observations.storage_startup`, and a canonical page matching the recomputed
  contract and the exact probe port widths. Parsed receipt and exact raw line
  are retained per page; cumulative page+receipt JSON storage is bounded by
  `receipt_storage_bound_bytes`.
- `_take`/`_samples` remain reserved for ordinary commands; pages never enter
  the ordinary samples queue and never advance command ticks.
- A missing, lost, partial, malformed, reordered, duplicated, foreign, or
  tampered page records
  `possible_effects=true`/`effect_certainty=unknown`, the original raw reply,
  retained parsed pages, last page/sequence, and all four authority flags false,
  then aborts and reaps the fixture process. The failure is permanent; a later
  `begin_case` is refused, so no automatic retry/new-sequence healing occurs.
- The `command` override allows READ only during the current retrieval and
  refuses all ordinary commands until every page is complete. It refuses READ
  on standard sessions and after retrieval completion.

### `src/myfuzz/local_harness/apb_storage_startup.py`

Added the pure `validate_startup_handoff()` namespace/continuity validator. It
requires an observed reset, exact probe shapes/widths, persistent
source-mapped storage value and reset equality between the last startup `post`
and first command `pre`, and joins changed APB request roles to the actual first
command fields. `prdata`/`pready`/`pslverr` are deliberately free to change
(readback is not storage); `grants_reset_prerequisite=False`. A startup with
release_ticks=0 ending asserted is preserved as asserted; no release edge is
synthesized. The generation contract remains canonical; no public authority
token or deserialization was added.

### `src/myfuzz/scenario/apb_storage_register_version.py` (C issuer)

The C issuer remains the owner of native authority, but now has the reviewed
startup-retrieval phase requested by the brief:

- `live` state carries a separate `startup` journal and `last_wire_sequence`.
  `startup` holds the recomputed contract/ports, next page, retained page
  receipts, records/bytes, complete/handoff phase, last startup post/raw
  reference, and reset-observed flag. Ordinary `state`/`scope` remain the
  command namespace.
- First page requires wire sequence 1, zero command ticks, initial scope with no
  prior ordinary state, no routed context, and no pending command. Later pages
  require exact next page, contiguous genuine wire sequence, the same
  process/execution/reset epoch/tick base, zero ticks, and no ordinary state.
- Page receipts are validated only after the real `_command_impl` frame check:
  result status, execution, sequence, zero ticks, empty samples, `rdata/error`
  zero, exactly `storage_startup`, and the canonical page contract. The pending
  operation/fields/sequence and actual receipt object are matched before a
  startup record is stored. `last_wire_sequence` advances independently of
  ticks.
- Pages never enter `reduce_storage_samples`. Ordinary command local tick
  indices remain 1.. at process start plus the existing `_tick_base`; page
  sequences are not added to command ticks and ordinary `state.sequence` is not
  reset after pages.
- The first ordinary command is accepted only after all pages, with no tick
  before it, and invokes `validate_startup_handoff` on its first `pre` sample
  before the ordinary reducer. Handoff facts plus startup/command raw references
  are retained; readback changes are explicitly legal. Startup `last_raw`
  references include namespace, page command sequence, startup edge index,
  sample phase, execution, target epoch and PID.
- `issue()`/`consume()` refuse while the pages/first-command handoff is
  incomplete. Every begin (including a page READ) clears outstanding tokens
  before validation. Unknown READ on a non-A2 artifact, page reorder/duplicate,
  tampered contract, scope/process/epoch/tick-base drift and missing initial
  pages poison the scope. Startup reset levels are explicitly not an F4 reset
  prerequisite; `grants_reset_prerequisite=False` is retained.
- All new helper/validator references are pinned; the canonical contract is
  reconstructed from the artifact on each validation. `_OPERATIONS` remains
  standard.

### `native_reset_producer_contract.py` / `native_reset_observation.py`

- `apb_storage_startup` is added to the closed storage dependency closure and
  to the observer's source-hash set.
- For an A2 artifact, `check_producer` reconstructs the canonical startup
  contract and requires the APB session's admitted contract/ports to match,
  with the exact A2 schema and host private-state shapes. Existing mechanical
  lifecycle/command facts and the no-reset-from-READY boundary are preserved.
  Existing APB/GPIO seals continue to pin every declared/resolved method,
  including the new private A2 methods.
- Failed startup retrieval does not make teardown unable to record its close
  fact; poison is owned by the host/C issuer, while B still validates the
  producer.

## RED evidence (observed before implementation)

- `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_apb_storage_startup_host.py`
  → `1 failed, 11 errors`: real A2 artifact was refused by the v1-only
  `_expected_ready`, and the host startup attributes did not exist.
- The new helper handoff tests initially failed with
  `AttributeError: validate_startup_handoff`; the C page-validator/handoff tests
  initially failed because `validate_storage_startup_receipt` was absent.
- C page-sequencing/host-contract refusal tests were initially red at the
  missing startup phase and then at the wrong refusal layer.
- The only test harness hang found during RED was in the new software pipe
  fixture: closing a `TextIOWrapper` from the main thread while the responder
  thread blocked in `readline` deadlocked. The fixture now wakes the responder
  with an `END` sentinel and closes only in the responder thread. This was a
  fixture defect, not a production defect; no fault parameter was removed,
  skipped, or relaxed. All 14 malformed/lost page parameters and the lost-ACK
  control execute.

## GREEN evidence (actual commands and counts)

All commands use `PYTHONPATH=src python3 -m pytest -q`.

| Command (tests) | Result | Log |
|---|---|---|
| A2 host/helper/C/B/probe/generic/source-contract focused suite (8 files) | `250 passed, 59 skipped` in 30.32s | `.superpowers/apb-storage-a2-host/a2-focused-green.log` |
| AHB startup/CPU contract/register identity, build identity, host-source reuse, generic APB trace | `147 passed` in 71.26s | `.superpowers/apb-storage-a2-host/ahb-build-regression.log` |
| session, driver protocol/renderer, generated session registration, GPIO session, generic APB real/bound | `41 passed, 3 skipped, 15 subtests passed` in 27.93s | `.superpowers/apb-storage-a2-host/session-gpio-regression.log` |
| GPIO register version/evidence + native reset evidence | `135 passed, 2 skipped` in 28.57s | `.superpowers/apb-storage-a2-host/gpio-native-reset-regression.log` |

The A2 focused suite includes:

- real production runtime/driver renderers with saved elaborated timer ports;
  real source-lock verification, session constructor and `_expected_ready`;
  real `build._prepare` with only `build._toolchain` replaced by software tool
  identities; assertion that `apb_storage_startup.py` and the shared header are
  in the host/build identity; no eligible build receipt is issued.
- canonical page RESULT bytes fed through the actual base `_command_impl` and
  `wire.parse_driver_receipt` with a software in-process pipe/process fixture;
  the parser and original callbacks are unmocked. The fixture is explicitly
  noneligible and cannot grant a native version.
- zero page command ticks, genuine page wire sequences 1..N, ACK-capacity
  consumption (513-tick/17-page control), first normal sample tick 1, and a
  first command that cannot precede the pages.
- same-sequence cached duplicate-line refusal, reordered page, page count,
  unknown field, boolean width, missing probe, invalid UTF-8, noncanonical
  JSON, lost reply, partial buffer, EPIPE, OSError, lost ACK, tampered
  contract/artifact, raw receipt retention, permanent poison, process close and
  no retry.
- measured `last_startup_post → first_command_pre` storage/reset continuity with
  a legal APB drive; readback/pready/pslverr changes remain legal; readback
  cannot substitute storage; missing initial pages and unobserved reset are
  refused; STEP-first handoff is idle and continuous.
- C pure page/handoff validators with wire-parsed receipts and the documentary
  completion test (no authority object, no registry/token entry); unknown READ,
  missing initial pages, page reorder, tampered host contract, noneligible
  native refusal, and zero-tick READ token clearing.
- unchanged default v1 path, storage-probe-without-A2, GPIO/B/C, AHB
  schema/CommandSet/constructor/_prepare/parser, and default driver CPP/READY
  byte controls from the existing suites.

## Authority and evidence boundaries retained

- `grants_reset_prerequisite=false`, `hierarchy_verified=false`,
  `native_verified=false`, `reset_authority=false`, `version_authority=false`,
  `source_authority=false` remain on the startup contract, host failure record,
  handoff facts and C witnesses.
- Startup levels are measured documentary data, not an F4 reset prerequisite.
  No reset assertion/release edge is synthesized from READY, page text, reset
  metadata or readback.
- No native build, model, frontend, remote action, or eligible build receipt was
  produced. The software fixture is not authority.
- No D/F4/Runner changes were made as a side effect.

## Conflict and coordination notes

- The brief records the C issuer as owner-frozen around `053ff9c`. This task
  explicitly assigns the C startup-retrieval path, so the minimal phase was
  added in `apb_storage_register_version.py`; it is source-only and requires
  C-owner re-review before any native use. The module source hash used by B is
  computed from the live file, not a stale constant. No C token/version is
  claimed positive.
- Brief item 36 is honored: continuity compares persistent storage/reset and
  the APB request roles actually driven by the first command; combinational
  readback/ack roles are allowed to change. No all-APB-bits equality is
  required.
- `tests/local_harness/test_build_identity.py::...` failed once during the run
  because another agent concurrently wrote files in the host-source closure
  (`src/myfuzz/integration/compiled_f4.py` /
  `src/myfuzz/integration/compiled_storage_producer.py`), changing the build
  identity between two calls in the same test. The focused test and the full
  147-test rerun passed after those files settled. This was an external
  workspace race, not an A2 source regression.

## Still open (not claimed)

- Actual native gate: new source closure/build identity, real elaborated
  hierarchy/probe/reset waveform, actual startup pages, first-command
  continuity, fresh prefixes, counters and negative controls. The C issuer
  native-positive startup pages → first command → issue/consume path is
  implemented but **not executable** on a noneligible software fixture and was
  therefore not run as a positive.
- Fresh-scope/reset-consumer semantics after C poisoning, F4 witness joins,
  reset prerequisite issuance, P7/new-IP completion.
- No claim of F4, native hierarchy, or reset verification.
