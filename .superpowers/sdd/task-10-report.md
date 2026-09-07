# Task 10 Report: Generic Processor Memory Backend Arbitration and Routing

## Status

Complete. Task 10 was implemented directly on `feature/ibex-protocol-longrun` from base commit `975756785a1fbfe52bc1bd03918cc75d16956631`.

Implementation commit: `28e63ef6dba0b94698a9a373162d2ca4f722bb13`

## Files Changed

- `src/myfuzz/composition/processor_backend.py` (new): validates and canonicalizes Task 9 execution routes and allocated address regions into `processor_backend.v1`.
- `src/myfuzz/protocols/rtl/processor_memory_arbiter.sv` (new): fair two-initiator, single-outstanding processor-memory-beat arbiter.
- `src/myfuzz/composition/protocol_composer.py`: builds and publishes the backend contract, emits `processor_backend.v1.json`, and conditionally includes the arbiter RTL for split routes.
- `src/myfuzz/composition/__init__.py`: exports the backend planner API.
- `tests/composition/test_processor_backend.py` (new): focused deterministic backend-plan tests.
- `tests/protocols/test_processor_memory_arbiter_rtl.py` (new): real Icarus RTL simulation covering the required transaction behavior.

Pre-existing changes to `.superpowers/sdd/task-2-report.md` and the untracked `third_party/` directory were not staged or modified by Task 10.

## Behavior

- A single `memory_master` or `processor_memory_master` route produces a direct backend plan and adds no arbiter RTL source.
- Split `data_memory_master` and `instruction_memory_master` routes produce a deterministic round-robin plan and add `processor_memory_arbiter.sv` to the published source list.
- Initiator ordering is canonical by function and route ID, independent of input ordering or source naming.
- Task 9 `processor-memory-beat@1` mode, width, max-outstanding, and timeout capabilities are validated before a backend plan is accepted.
- Composition-assigned regions are sorted and validated for bounds, width agreement, malformed ends, and overlap.
- Unmapped requests are specified to complete with one error, zero read data, and no side effect.
- Read-only instruction routes are recorded with `error_without_backend_request`; writable split instruction routes fail composition with `instruction-write-policy`.
- The arbiter captures owner, address, write data, and byte enable at initiator acceptance and holds the backend request stable through backpressure.
- Simultaneous requests use round-robin priority; ownership remains fixed through completion.
- Backend responses are latched and held stable until the owning initiator accepts them; the non-owner never observes the completion.
- Partial-write byte enables pass unchanged.
- Unmapped accesses and read-only writes complete locally with one error and do not create backend requests.
- Timeout creates exactly one error completion. If the backend request was accepted, the arbiter requests cancellation and reuses the untagged response channel only after draining the response or receiving the backend's acknowledgment that no response can follow.
- Reset aborts active requests without completion, requests cancellation of all pre-reset accepted requests, and restores arbitration only after the backend acknowledges the stale-response barrier.
- Generic wrapper rendering is unchanged; Task 10 publishes routing artifacts but does not implement Task 11 top-level wiring.

## TDD Evidence

### RED

An initial environment probe used `python`, which is not installed:

```text
python -m unittest tests.composition.test_processor_backend tests.protocols.test_processor_memory_arbiter_rtl -v
```

Result: exit 127, `/bin/bash: python: command not found`. This was not accepted as the feature RED.

Authoritative RED command:

```text
PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend tests.protocols.test_processor_memory_arbiter_rtl -v
```

Result: exit 1. The Python test failed to import `myfuzz.composition.processor_backend`; Icarus failed because `processor_memory_arbiter.sv` did not exist. Two tests ran with one import error and one simulation compile failure, both for the expected missing Task 10 implementation.

### GREEN

Focused Task 10 command:

```text
PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend tests.protocols.test_processor_memory_arbiter_rtl -v
```

Result: exit 0, 5 tests ran in 0.013 seconds, all passed.

Relevant processor/composition regression command:

```text
PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend tests.composition.test_processor_boundary tests.composition.test_processor_adapters tests.composition.test_processor_execution tests.composition.test_protocol_composer tests.protocols.test_processor_memory_backend tests.protocols.test_processor_memory_arbiter_rtl tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl -v
```

Result: exit 0, 41 tests ran in 6.315 seconds, all passed. Icarus compiled and executed the new arbiter and all three processor adapter simulations. The run emitted three existing `ResourceWarning` messages from implicit `TemporaryDirectory` cleanup in `test_processor_execution`; they did not affect test status.

Additional pre-commit check:

```text
git diff --check
```

Result: exit 0 with no whitespace errors.

## Self-Review

- Requirement coverage: direct route, split route, simultaneous arrival/fairness, request payload stability, response ownership/backpressure, unmapped completion, partial writes, timeout, late-response quarantine, reset abort/recovery, and read-only instruction rejection are covered.
- Determinism: initiators and regions are canonically sorted; the backend hash excludes itself and is derived from the complete path-free backend document.
- Compatibility: legacy generic composition plans without processor execution do not build or emit a backend plan. Existing generic renderer behavior remains unchanged.
- Scope: no processor adapter behavior was changed and no Task 11 generated top-level wiring was added.
- Safety: only the six Task 10 implementation/test files were staged in the implementation commit. Unrelated worktree changes were preserved.
- Review tooling: the requested independent review workflow was checked, but this environment exposes no reviewer/subagent tool. Review was therefore performed inline against the brief and focused test evidence.

## Concerns

- Task 11 must consume `processor_backend.v1.json`, generate address-decode signals for each region, connect each route adapter to direct or arbiter ports, and connect the selected backend target. Task 10 intentionally does not perform that wiring.
- Task 11 must wire `cancel_valid_o`/`cancel_ready_i` to a backend that honors the documented acknowledgment guarantee. A backend that neither responds nor acknowledges cancellation is non-conforming and cannot be reused safely.
- No independent subagent code review was possible because no reviewer-agent capability is available in this session.

## Review Fix TDD Evidence

### RED: cancellation and reset contract

```text
PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend tests.protocols.test_processor_memory_arbiter_rtl -v
```

Result: exit 1, 5 tests ran, 2 failed. The composition assertion failed because `processor_backend.v1` still declared `quarantine_and_discard` and `abort_without_completion`; the real RTL simulation failed at `reset requests backend flush` because the arbiter had no cancel/flush interface.

### RED: Task 9 temporary-directory warning

```text
PYTHONPATH=src python3 -W always::ResourceWarning -m unittest tests.composition.test_processor_execution.ProcessorExecutionTests.test_processor_classification_fails_closed_on_missing_or_ambiguous_timing -v
```

Result: exit 0, 1 test passed but emitted 3 `ResourceWarning: Implicitly cleaning up <TemporaryDirectory ...>` warnings, one for each expected exception path.

### GREEN: focused Task 10

```text
PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend tests.protocols.test_processor_memory_arbiter_rtl -v
```

Result: exit 0, 5 tests ran in 0.013 seconds, all passed. The RTL test proves a timed-out accepted request completes exactly once, cancellation acknowledgment permits a later request to complete when no late response arrives, stale response pulses are rejected after acknowledgment, and reset during `WAIT_RSP` flushes before post-reset recovery.

### GREEN: warning reproducer

```text
PYTHONPATH=src python3 -W always::ResourceWarning -m unittest tests.composition.test_processor_execution.ProcessorExecutionTests.test_processor_classification_fails_closed_on_missing_or_ambiguous_timing -v
```

Result: exit 0, 1 test ran in 0.014 seconds, passed with no warnings.

### GREEN: scoped processor/composition/RTL regression

```text
PYTHONPATH=src python3 -W always::ResourceWarning -m unittest tests.composition.test_processor_backend tests.composition.test_processor_boundary tests.composition.test_processor_adapters tests.composition.test_processor_execution tests.composition.test_protocol_composer tests.protocols.test_processor_memory_backend tests.protocols.test_processor_memory_arbiter_rtl tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl -v
```

Result: exit 0, 41 tests ran in 6.370 seconds, all passed with no warnings.
