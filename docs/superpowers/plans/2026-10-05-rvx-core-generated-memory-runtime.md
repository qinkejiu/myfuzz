# RVX Core Generated Memory Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a source-verified, generated independent harness and persistent RAM runtime for the real RVX `rvx_core` RTL, with no `rvx.v` SoC wrapper, while preserving its synchronous completion and back-to-back request behavior.

**Architecture:** Add a declarative protocol/profile for RVX's shared-address read/write request interface. Generate a local runtime that exposes the core's physical request/response pins and a stateful CPU session that services each accepted RAM access exactly once through `PersistentMemory` and `TransactionLedger`. Keep local clocks and reset from the generated harness, and keep all interrupt inputs inactive for this first CPU bring-up. The first acceptance executes a seeded RV32I program on real `rvx_core` RTL, checks full-word and byte-enable memory effects, saves/replays the execution in a fresh RTL process, and compares state and transaction evidence.

**Tech Stack:** Python 3, JSON component/protocol declarations, generated SystemVerilog, generated C++/Verilator driver, `PersistentMemory`, `TransactionLedger`, pytest/unittest.

## Global Constraints

- Use only `external_designs/rvx/hardware/rvx_core.v` as the CPU DUT; do not instantiate `rvx.v`, `rvx_bus`, `rvx_ram`, UART, timer, GPIO, or SPI.
- Preserve `rvx_core`'s active-high synchronous reset and its own clocked request/response behavior; do not add a global SoC clock model.
- Treat `read_request` and `write_request` as transaction requests, not randomizable CPU inputs; transaction payloads and results come from the actual RTL and persistent memory service.
- A held request while awaiting its matching response is one transaction; a request on a response edge may be the next transaction even if all payload values equal the prior request.
- Commit writes once per accepted transaction, honor all four byte-enable lanes, and return a read value frozen from the accepted memory snapshot.
- Do not route out-of-region accesses to fabricated zero data. Until a real IP target is connected in a later task, out-of-region MMIO must terminate with an environment error.
- Preserve all pre-existing worktree changes; do not stage or commit files.

---

## File Map

- Create `src/myfuzz/protocols/plugins/pipelined_completion_memory.json` for the component-neutral single-outstanding, shared-address completion interface.
- Modify `src/myfuzz/protocols/catalog.py` only if the protocol needs a new relation/rule kind; add catalog tests in `tests/protocols/test_pipelined_completion_memory_catalog.py`.
- Create `configs/cpus/rvx_core/component_profile.json`; add the pinned `rvx_core` record in `configs/soc/sources.lock.json` with `elaboration_status=elaboration_unverified` until durable closure evidence can be tracked.
- Add profile/source-lock coverage in `tests/composition/test_rvx_core_component_profile.py`.
- Modify `src/myfuzz/local_harness/runtime_renderer.py`, `driver_renderer.py`, `session.py`, `build.py`, `__init__.py`, and `src/myfuzz/scenario/contracts.py` to register runtime kind `rvx_memory_cpu` and its session identity.
- Create `src/myfuzz/local_harness/rvx_memory_session.py` implementing `GeneratedRvxMemorySession`.
- Add unit coverage in `tests/local_harness/test_rvx_memory_runtime.py` and `tests/local_harness/test_rvx_memory_session.py`.
- Add the real RTL acceptance in `tests/integration/test_scenario_rvx_core_persistent_memory_real.py` and update `docs/LOCAL_HARNESS_RUNTIME.md` only after its evidence has passed.
- Write the measured result to `docs/reports/generated-rvx-core-persistent-memory-20261005.md`.

## Interfaces

The profile endpoint `processor.memory` uses protocol `pipelined-completion-memory@1` with physical roles `addr`, `read_request`, `read_response`, `read_data`, `write_request`, `write_response`, `write_data`, and `write_strobe`. `read_data`, `read_response`, and `write_response` are environment-to-core roles; all other roles are core outputs. The profile marks `halt`, all IRQ inputs, and `real_time_clock` constant zero, leaving clock/reset to generated local controls.

`GeneratedRvxMemorySession` accepts a `PersistentMemory` and an authenticated `rvx_memory_cpu` artifact. `step_local({})` advances exactly one CPU-local tick, services one physical request using a monotonically increasing `TransactionKey`, and returns the observed CPU outputs plus `data_req_*` / `data_rsp_*` trace fields. It has no external randomized CPU response inputs. Registered response latency is configurable within the generated local wait bound and included in session identity; the acceptance uses one local tick. While the response is pending, the core's held request must not repeat its backend effect. When the previous response is presented, the request sampled for the same edge may start the next transaction. Before backend service, the session checks that the command's final observation and that tick's post-edge sample agree.

The accepted boot program stores `0x12345678` at `0x100`, overwrites byte lane 1 with `0x55`, loads the word back, stores that result at `0x104`, writes completion marker `1` at `0x108`, then loops. The expected values are RAM[`0x100`] = `0x12345578`, RAM[`0x104`] = `0x12345578`, and RAM[`0x108`] = `1`; the byte store must have `write_strobe=0b0010` and lane-aligned `write_data=0x00005500`.

## Tasks

### Task 1: Define and test the pipelined completion protocol

**Files:**
- Create: `src/myfuzz/protocols/plugins/pipelined_completion_memory.json`
- Modify: `src/myfuzz/protocols/catalog.py` only for required declarative relation/rule enums
- Test: `tests/protocols/test_pipelined_completion_memory_catalog.py`

- [x] Add a failing catalog test that loads `pipelined-completion-memory@1`, checks every field direction and width, and rejects a malformed channel relation or unsupported temporal rule.
- [x] Run `pytest tests/protocols/test_pipelined_completion_memory_catalog.py -q`; confirm it fails because the protocol plugin is absent.
- [x] Add the protocol declaration with separate read/write request/completion fields, a shared byte address/data bus, 4-bit byte strobe, one request in flight, no request-ready pin, and documented completion-edge next-request acceptance.
- [x] Add only relation/rule kinds that are needed to express the read and write completion contracts; keep independent runtime assertions responsible for request mutual exclusion and exact-once service.
- [x] Re-run the focused catalog test and the protocol catalog tests; expect all to pass.

### Task 2: Pin and verify the RVX CPU profile

**Files:**
- Create: `configs/cpus/rvx_core/component_profile.json`
- Modify: `configs/soc/sources.lock.json`
- Test: `tests/composition/test_rvx_core_component_profile.py`

- [x] Add failing profile tests requiring top module `rvx_core`, source revision equal to the checked-out RVX submodule commit, the eight memory endpoint roles, reset/clock declarations, fixed inactive `halt`/IRQ/RTC inputs, RV32I facts, and no `instruction_identity` claim.
- [x] Run the focused profile test and confirm it fails because the profile is absent.
- [x] Declare only `rvx_core.v` as the selected source; use source-derived port aliases/directions/widths and an explicit clock/reset action. Do not include the full `rvx` top or inferred IP/bus endpoints.
- [x] Add a source-verified lock row with no elaboration evidence block. This checkout's source verifier rejects untracked elaboration evidence, and Git tracking operations are outside the current authorization.
- [x] Run the profile test and source-lock verification; expect the profile to source-verify, and allow `plan_local_harness` to freshly elaborate the physical top. Record the formal elaboration-evidence status as unverified until the evidence file can be tracked later.

### Task 3: Generate the physical runtime and CPU-step driver

**Files:**
- Modify: `src/myfuzz/local_harness/runtime_renderer.py`
- Modify: `src/myfuzz/local_harness/driver_renderer.py`
- Modify: `src/myfuzz/local_harness/session.py`
- Test: `tests/local_harness/test_rvx_memory_runtime.py`

- [x] Add failing renderer tests for runtime kind `rvx_memory_cpu`, direct physical request/response pin exposure, zero IRQ/halt inputs, one sample per command, and rejection of a wrong endpoint shape or an unsupported CPU input.
- [x] Run the focused tests and confirm they fail because no RVX runtime branch exists.
- [x] Add protocol-selected runtime rendering that directly exposes the RVX physical bus roles; do not reuse `native_completion_memory_adapter` because RVX may change request payload on the response edge.
- [x] Add `STEP_RVX_MEMORY` with inputs `(read_response, write_response, read_data)` and one local tick. The driver must capture the request after applying those response inputs and before the rising edge, then return pre-edge request/data plus physical observations and post-edge outputs.
- [x] Register the bounded operation in the shared wire parser as well as the Python session API; reject malformed field shapes before dispatch.
- [x] Enforce maximum widths and only accept the empty external-input mapping from the Python CPU session.
- [x] Re-run runtime renderer and driver tests; expect exactly one tick/sample per step and no fabricated backend response.

### Task 4: Add persistent exact-once RVX memory service

**Files:**
- Create: `src/myfuzz/local_harness/rvx_memory_session.py`
- Modify: `src/myfuzz/local_harness/__init__.py`
- Modify: `src/myfuzz/scenario/contracts.py`
- Modify: `schemas/scenario_runtime_manifest.v1.json`
- Test: `tests/local_harness/test_rvx_memory_session.py`

- [x] Add failing session tests for first request service, held request during wait, one write commit, completion-edge acceptance of a second request with identical payload, response-to-request type matching, unaligned/unmapped access rejection, and reset cancellation without memory rollback.
- [x] Run the focused session tests and confirm the class/identity contract is missing.
- [x] Implement `GeneratedRvxMemorySession` with one pending completion record; service reads/writes through `MemoryService` and `TransactionLedger`, call `PersistentMemory.advance_step()` once per local step, and emit measured transaction source epoch/sequence.
- [x] While response is withheld, never re-execute the held transaction. On the response step, use the old pending record to identify the completion, then classify the request from `samples[0].pre` as a new beat even when address/data equal the prior beat. Never classify the response edge from the post-edge sample.
- [x] Reject inconsistent driver post-edge snapshots before servicing a backend request; a regression test checks that the rejected receipt creates no memory events or initialized bytes.
- [x] Register the exact session identity in scenario preflight and JSON schema; enforce replay identity, source component, service schema, and `ram_only` memory policy.
- [x] Re-run focused session and scenario identity tests; expect duplicate/missing/wrong-type completions to fail before being accepted as valid execution evidence.

### Task 5: Execute and replay the seeded program on real RVX RTL

**Files:**
- Create: `tests/integration/test_scenario_rvx_core_persistent_memory_real.py`
- Create: `docs/reports/generated-rvx-core-persistent-memory-20261005.md`
- Modify: `docs/LOCAL_HARNESS_RUNTIME.md`

- [x] Add an integration test that builds the generated runtime, writes the exact RV32I instruction words into `PersistentMemory`, starts one fresh real RVX session, releases reset once, and executes exactly 128 CPU-local ticks (the scenario runner is fixed-step and records this schedule).
- [x] Run the test before implementation and confirm it fails at the missing runtime/session, not from a test-construction error.
- [x] Run the completed test and require: boot fetch at address zero; the completion marker first appears within the 128-tick schedule; each transaction has one ledger acceptance/completion; no held store repeats; the `sb` request uses strobe `0010` and data lane `0x00005500`; the three expected RAM words match; and all accesses remain inside the declared RAM region.
- [x] Replay the same program and memory seed in a fresh RTL process. Require the ordered transaction list, response data, byte enables, final memory digest, and completion marker to match the first run exactly.
- [x] Record actual commands, elapsed time, Verilator version, source/profile digests, tick counts, replay results, and limits in the report. State explicitly that durable elaboration evidence remains unverified while Git tracking is deferred, and that MMIO/IP routing, IRQ delivery, RVX bus decode, and cross-component integration remain for later work.
- [x] Update the runtime matrix with only the evidence actually produced; keep broad coverage-guided fuzzing status `runtime_unverified` unless a separate coverage-guided campaign was run.

## Completion Criteria

- The source-pinned profile selects only standalone `rvx_core`, classifies all physical ports, and is freshly elaborated by the generated runtime. The durable source-lock elaboration evidence remains unverified while Git tracking is deferred.
- Generated RTL and driver identity are deterministic and fresh-replay identity checks pass.
- A real CPU request held across response delay creates one backend transaction and one memory side effect; a subsequent identical request on the completion edge creates a distinct transaction.
- The byte-lane store and all final RAM values match the seeded program's architectural expectations.
- Fresh replay matches the entire memory and transaction evolution, not only the final marker.
- The implementation and documentation make no claim that the CPU can already access a real IP, that `rvx_bus` is tested, or that this directed acceptance found a DUT bug.
