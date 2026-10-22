# Native Exact Source Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan task by task. Each task ends with a scoped review.

**Goal:** Issue a live, owner-bound `native_instruction_bus_completion.v1` fact only when an admitted four-byte host instruction is read from its exact RAM snapshot and completes on the native instruction bus.

**Architecture:** Preserve the existing host input binding and native bus observation as separate facts. Carry the actual `ReadSnapshot`, `TransactionKey`, service owner, source admission, and binding issuance through the observer's live pending transaction; issue a completion object only at the next PRE `valid && ready` after the existing response/tick checks pass. A versioned Runner consumer validates that object and publishes a detached completion fact. The feature is a separate strict opt-in and its fresh replay installs independent owners and nonces.

**Tech Stack:** Python 3.11+, existing `MemoryService`/`PersistentMemory`, `NativeBusObserver`, `NativePacketSession`, `ScenarioRunner`, and the repository's source identity and fresh replay gates. No new third-party runtime dependency.

## Global Constraints

- The new `native_source_completion` option defaults to `False` and requires both existing native completion observation and source binding.
- Only a real original `MemoryService.read` result associated with the current native accepted transaction can carry a snapshot into completion issuance; equality, JSON, hash, or an offline trace never creates a live receipt.
- Candidate policy is fixed: unrelated bootstrap, fixed support, or NOP fetches receive diagnostic-only observations and no eligible grant; once the source address resolves to a selected admitted candidate, any mismatch in owner, admission, case/path, snapshot, transaction, four bytes, writer kind, version, epoch, or native PRE completion poisons and refuses the source-completion producer.
- Completion requires native instruction marker `1`, read strobes `0`, aligned exact four-byte source address, backend full byte enable `15`, one exact `MemoryService.read`, and matching accepted/read/response/completion transaction identity. It is issued only on the next PRE sample satisfying `valid && ready`, after existing response-tick and `rdata` checks pass.
- Reset revokes the old epoch; abort poisons and cleans up once; finish revokes live tokens after actual quiescence. No path fabricates a completion, tick, service read, or extra request.
- `native_instruction_bus_completion.v1` has proof scope `native_instruction_bus_transfer_completed`; it does not claim decode, execution, architectural retirement, CPU semantic consumption, peripheral payload consumption, or feedback. `grants_source_authority` remains `false`.
- Do not change existing host binding event meaning, raw native sample schemas, or the meaning of `native_bus_observation.v1`. New schema fields require an explicit HARNESS V2 identity update; historical V1/V2 gate results are not evidence for the new source-completion path.
- Do not stage, commit, or clean unrelated user changes. Keep the implementation scoped to the files listed below.

## Files and Responsibilities

- Modify `src/myfuzz/scenario/memory.py` and `src/myfuzz/scenario/memory_service.py` only for actual read-result identity and owner-bound lookup needed by the native source-completion producer.
- Create `src/myfuzz/scenario/native_instruction_bus_completion.py` to own the frozen live completion fact, issuance registry, strict candidate validation, revocation, and detached document projection.
- Modify `src/myfuzz/scenario/native_instruction_source_binding.py` and `src/myfuzz/scenario/session_runtime.py` to expose a private exact-owner lookup of an already-issued, still-live `NativeInstructionSourceBinding`; serialized host events are never lookup authority.
- Modify `src/myfuzz/scenario/native_cpu_events.py` and `src/myfuzz/local_harness/native_session.py` to carry actual pending object references and issue completion only after the existing next-PRE handshake checks.
- Modify `src/myfuzz/scenario/native_packet_session.py`, `src/myfuzz/integration/picorv32_native_online.py`, `src/myfuzz/scenario/runner.py`, `src/myfuzz/scenario/host_identity.py`, and `src/myfuzz/scenario/native_replay_identity.py` to thread the strict opt-in, lifecycle, issued-object consumption, explicit source identity, and independent-owner fresh normalization.
- Extend `tests/scenario/test_memory_service.py`, `tests/local_harness/test_native_completion_adapter.py`, `tests/scenario/test_generated_evidence_host_identity.py`, and `tests/integration/test_scenario_picorv32_native_campaign.py`; create `tests/scenario/test_native_instruction_bus_completion.py` for object issuance, candidate policy, mismatch refusal, and lifecycle coverage.
- After code gates pass, add a separately pinned remote run recipe and evidence under `/root/fanzehui/myfuzz/operations/` and `/root/fanzehui/myfuzz/evidence/`; remote project/cache/source writes must stay under `/root/fanzehui/**` per `agent.md`.

## Implementation Tasks

### Task 1: Issue and retain actual native read snapshots

**Files:**
- Modify: `src/myfuzz/scenario/memory.py`
- Modify: `src/myfuzz/scenario/memory_service.py`
- Test: `tests/scenario/test_memory_service.py`
- Test: `tests/scenario/test_native_instruction_bus_completion.py`

**Interfaces:**
- Input: the existing `MemoryService.read(key, address, width_bytes=4)` result, the exact `TransactionKey`, the service/memory owner identities, and the currently accepted observer transaction.
- Output: a private issued-read handle whose live registry binds the original `ReadSnapshot` object, typed key object, exact service and memory objects, and actual successful service ledger entry. The handle cannot be minted by constructing an equal `ReadSnapshot` or detached journal document.

- [ ] Add tests for actual read issuance, replayed/equal snapshot refusal, owner mismatch, key mismatch, and event-append failure not becoming eligible source completion.
- [ ] Run `pytest -q tests/scenario/test_memory_service.py tests/scenario/test_native_instruction_bus_completion.py`; confirm the new issuance tests fail because the private issued-read handle is absent.
- [ ] Add the minimal private registry/validation seam while preserving `MemoryService.read` values, ledger behavior, and serialized events.
- [ ] Re-run the same command and confirm the issuance tests pass without changing existing read/write receipt wire formats.

### Task 2: Resolve only existing live source bindings and enforce the candidate rule

**Files:**
- Modify: `src/myfuzz/scenario/native_instruction_source_binding.py`
- Modify: `src/myfuzz/scenario/session_runtime.py`
- Test: `tests/scenario/test_native_instruction_bus_completion.py`

**Interfaces:**
- Input: exact native session owner, reset epoch, actual `ReadSnapshot` object, actual `TransactionKey` object, actual instruction address, and the existing active binding registry.
- Output: either the single original issued binding for the exact current source word or a diagnostic-only unrelated-fetch result. More than one candidate or any contradiction for a selected candidate poisons the producer and raises a stable refusal code.

- [ ] Add cases for matching source, unrelated bootstrap/NOP, aliased address, multiple binding candidates, wrong case/path/admission, mixed writer/version, stale epoch, substituted owner, and byte mismatch.
- [ ] Run `pytest -q tests/scenario/test_native_instruction_bus_completion.py`; confirm candidate and refusal cases fail before the private live lookup exists.
- [ ] Add a private registry lookup that returns the original issued binding only; validate exact four lane values, version IDs, writer IDs/kinds, source span, admission, action, case/path/direction, and live owner/session epoch.
- [ ] Re-run the same command and confirm unrelated startup fetches do not receive completion authority while contradictory selected candidates poison/refuse.

### Task 3: Issue completion at the actual next-PRE native handshake

**Files:**
- Create: `src/myfuzz/scenario/native_instruction_bus_completion.py`
- Modify: `src/myfuzz/scenario/native_cpu_events.py`
- Modify: `src/myfuzz/local_harness/native_session.py`
- Test: `tests/local_harness/test_native_completion_adapter.py`
- Test: `tests/scenario/test_native_instruction_bus_completion.py`

**Interfaces:**
- Producer input: the original pending transaction object, original accepted and response scopes, actual service-read handle, original snapshot and key objects, original source binding object, and the validated native PRE completion tuple.
- Producer output: a frozen owner-bound completion object with schema `native_instruction_bus_completion.v1`, proof scope `native_instruction_bus_transfer_completed`, and `grants_source_authority=False`.

- [ ] Add tests proving that backend response consumption alone, POST `ready`, marker changes, same-value replacement snapshots, wrong tick, response mismatch, non-full byte enable, data reads, and completion without a real service read issue no completion.
- [ ] Run `pytest -q tests/local_harness/test_native_completion_adapter.py tests/scenario/test_native_instruction_bus_completion.py`; confirm issuance is absent before implementation.
- [ ] Retain live snapshot/key/owner references beside the current pending projection. At the existing successful PRE `valid && ready` branch, after all current checks and before pending is cleared, invoke the producer exactly once.
- [ ] Keep raw events unchanged; reset/abort/finish revoke transient references and tokens. Re-run the command and confirm only the exact qualifying handshake produces a completion object.

### Task 4: Thread opt-in through session, identity, Runner consumer, and fresh replay

**Files:**
- Modify: `src/myfuzz/scenario/native_packet_session.py`
- Modify: `src/myfuzz/integration/picorv32_native_online.py`
- Modify: `src/myfuzz/scenario/runner.py`
- Modify: `src/myfuzz/scenario/host_identity.py`
- Modify: `src/myfuzz/scenario/native_replay_identity.py`
- Test: `tests/scenario/test_generated_evidence_host_identity.py`
- Test: `tests/integration/test_scenario_picorv32_native_campaign.py`

**Interfaces:**
- Configuration: strict boolean `native_source_completion=False`; `True` is valid only with `native_completion_observation=True` and `native_source_binding=True`. The exact saved configuration and bounds are frozen in an explicit new HARNESS V2 identity; V1 remains unchanged.
- Runner: consumes only the original issued completion object from the current session, validates its owner/admission/source references, then emits a detached V1 completion document. It never reconstructs authority from event IDs, hashes, or saved JSON.
- Fresh: replays the complete saved warmup, cases, and finish using independent session/memory/service/native owners and a new nonce; it shares no live binding or completion token with the original run.

- [ ] Add tests for strict bool/config refusal, dependency flags, changed saved bounds, missing identity paths, tampered schema/version, no old-owner token reuse, and exact full-fresh comparison with only explicitly owned nonce fields normalized.
- [ ] Run `pytest -q tests/scenario/test_generated_evidence_host_identity.py tests/integration/test_scenario_picorv32_native_campaign.py`; confirm new config/identity/fresh assertions fail before wiring.
- [ ] Thread the opt-in through factories, immutable policy/manifests, Runner registration/drain, fresh construction, and the explicit HARNESS V2 source path list. Do not modify V1.
- [ ] Re-run the command and confirm default-off sessions retain existing event shapes and enabled sessions publish only live issued completion facts.

### Task 5: Freeze, independently run, and audit the exact-source gate

**Files:**
- Modify: `scripts/verify_picorv32_native_online.py`
- Create/update: `docs/reports/native-exact-source-completion-20261018.md`
- Create: remote operation records only under `/root/fanzehui/myfuzz/operations/<new-operation>/`
- Create: evidence only under `/root/fanzehui/myfuzz/evidence/<new-evidence>/`
- Update: `docs/CURRENT_PROGRESS.md`, `docs/LOCAL_HARNESS_RUNTIME.md`, and `docs/reports/README.md`

**Interfaces:**
- Gate: opt into source completion explicitly, retain existing host binding and native observation gates, verify one positive selected-source completion, one non-candidate startup fetch without grant, and one selected-candidate contradiction that poisons/refuses. Each run has a full independent-owner fresh replay and independent raw/event audit.
- Evidence: tie the run to a source manifest, gate script identity, tool freeze, parent/gate/DUT terminal records, raw samples, typed receipt joins, and independent auditor output. The current auditor verifies listed manifest/tool rows individually but records `source_tree_closure_verified=false`, `external_tool_bytes_verified=false`, and `gate_executable_identity_verified=false`; those flags do not satisfy a claim of complete source/tool closure.
- Run identity: the one-shot controller supplies a fresh 64-character lowercase hex `gate_run_id` with required CLI `--gate-run-id`. Each of the three branch results records that ID, its fixed branch name, and the gate PID; `summary.json.gz` records the same ID/PID. Claim, launch, start, end, and post-run receipts must carry the same ID. The end receipt hashes all three branch results and the summary; the independent auditor checks these joins. Previous host-binding-only or native-observation-only gates are not evidence for this slice.

- [x] Extend the existing CLI with `--native-source-completion`; reject it unless both prerequisite opt-ins are present. Require a controller-supplied 64-character lowercase hex `--gate-run-id` and emit the shared identity on each branch and summary. Dependency and source-root refusal paths are covered without starting RTL.
- [x] Run local unit and integration gates from Tasks 1–4 before packaging. The current combined auditor/producer/D1 gate passes **63 tests, 3 skipped, 32 subtests**; the earlier source-completion/DMA integration suites are recorded above.
- [ ] Prepare a new remote operation without modifying the remote baseline project; verify the root and operation path are under `/root/fanzehui/myfuzz/` before each write.
- [ ] Run the frozen real gate, full fresh replay, and a separate independent audit; preserve failure attempts without weakening the gate.
- [ ] Update progress documentation with exact results and explicitly state the remaining boundary: bus transfer completion only, no decode/retirement/semantic consumption/IP feedback.

### Task 5 status note (2026-10-22)

The current independent auditor now requires `gate_run_id` to join the intent, plan, claim, launch, gate-start, gate-end, post-run receipt, all three branch results, and `summary.json.gz`. The gate-end receipt must pin all branch and summary gzip hashes. The auditor rejects noncanonical inventory paths and rechecks pinned bytes on every read. Its output explicitly records that complete source-tree closure, external tool bytes, and actual gate executable identity are not verified.

The existing r10 remote package has not been started, and its controller/runner/auditor bytes are not available in the local workspace. Do not alter or reuse r10. A new reviewed r11 sibling package is required to make the controller generate/pass the run identity and write the new terminal hashes. No remote or real-process gate has run as part of this status update.

The r11 controller work is tracked in [the dedicated plan](2026-10-22-native-completion-r11-controller.md). It separates the pre-run static package seal from the post-run audit identity, preserves the auditor's exact argv/identity keys and tool-freeze format, requires the Stage 1 and Stage 2 gate-script bytes to match, and obtains the final identity SHA independently. It also binds the exact four-field `CLAIMS`, seven-row `ACCEPTANCE_MATRIX`, protected-baseline/submodule/output postflight facts, and post-wait process-group observation. Plan review is checking the latest amendments; the target host remains unreachable, and no controller code or remote package exists.
