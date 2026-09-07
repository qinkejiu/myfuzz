# Task 9 Report

## Status

DONE

## Files Changed

- Added `src/myfuzz/composition/processor_execution.py`
- Modified `src/myfuzz/composition/auto.py`
- Modified `src/myfuzz/composition/__init__.py`
- Added `tests/composition/test_processor_execution.py`
- Updated `.superpowers/sdd/task-9-report.md` after the implementation commit; this report path is ignored and is not part of the commit.

Existing unrelated user changes in `.superpowers/sdd/task-2-report.md` and `third_party/` were preserved and excluded from the commit.

## Behavior Implemented

- Added immutable `ProcessorExecutionPlan` and `ProcessorExecutionRoute` records with a canonical `processor_execution.v1` audit document and deterministic execution hash.
- Resolves each processor memory binding through `resolve_processor_adapter` and records endpoint/function, source and target protocols, adapter ID, RTL module/source, derived parameters, extension policies, physical field connections, and backend contract.
- Derives address, data, AXI ID/user, and TL-UL source widths exclusively from validated endpoint fields. It rejects missing facts and inconsistent widths instead of using CPU profiles, CPU names, module names, or fallback widths.
- Generates stable route IDs from memory function and protocol facts, independent of endpoint and CPU/module names.
- Supports exactly one unified `memory_master` route or one instruction plus one data route. Ambiguous, duplicate, and incomplete memory topologies fail closed.
- Records scalar ports directly and packed members as container port, member path, compiler-proven coordinates, and SystemVerilog part-select.
- Validates complete packed processor input coverage and rejects overlapping, missing, inconsistent, or stale packed-container facts.
- Rejects overlapping adapter-driven processor inputs and RFuzz layout fields, preventing double driving of the same whole port or packed slice.
- Records the explicit `processor-memory-beat@1` backend field widths, capabilities, direction, and exact adapter RTL ports.
- Generic planning activates processor execution only when memory plus separate processor `clock` and `reset` endpoint functions form a complete processor-boundary signature. Existing generic MMIO `memory_master` routes without that signature retain prior behavior.
- Generic planning removes adapter/backend-driven processor response inputs from the RFuzz input layout before ownership validation.
- Generic composition IR includes the processor execution document. Exact adapter paths remain in the audit record, while path-independent composition IR stores deterministic source IDs under `adapter_source_ids` and `rtl_source_id`.
- Adapter RTL sources are added to generic source files and source evidence, so adapter selection/source changes affect composition IR/source hashes and serialized generic output.
- Public processor execution APIs are exported from `myfuzz.composition`.

## RED Command and Output Summary

Environment-only runner attempts, not accepted as RED:

- `python -m pytest tests/composition/test_processor_execution.py -q`: exit 127 because `python` is unavailable.
- `python3 -m pytest tests/composition/test_processor_execution.py -q`: collection failed because `PYTHONPATH=src` was absent.

Accepted initial RED:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Result: exit 2 during collection with `ModuleNotFoundError: No module named 'myfuzz.composition.processor_execution'` and `1 error in 0.13s`.

Integration RED discovered by the focused test:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Result: `1 failed, 2 passed, 6 subtests passed`; canonical IR rejected the exact adapter path with `ValueError: composition_ir.metadata:host-specific`. Production code was changed to retain exact paths in the audit document and encode deterministic source IDs in composition IR.

Backend-port-map RED added during self-review:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Result: `1 failed, 2 passed, 6 subtests passed`; the assertion showed semantic `write`, `addr`, `wdata`, `be`, `rdata`, and `error` fields had suffix-derived names instead of the actual `req_*`/`rsp_*` adapter ports. Production code was changed to use the explicit backend port contract.

## GREEN Commands and Output Summaries

Final focused GREEN:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Result: exit 0, `3 passed, 6 subtests passed in 0.09s`.

Final processor regression GREEN:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py tests/composition/test_processor_boundary.py -q
```

Result: exit 0, `21 passed, 20 subtests passed in 6.20s`.

Final generic planning/writing regression GREEN:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_generic_auto.py tests/composition/test_generic_lint_diagnostics.py -q
```

Result: exit 0, `17 passed in 1.27s`.

No broad full-suite test was run, per user instruction.

## Commit Hash

`0d24deb` (`feat(composition): plan processor execution routes`)

The commit contains exactly:

- `src/myfuzz/composition/__init__.py`
- `src/myfuzz/composition/auto.py`
- `src/myfuzz/composition/processor_execution.py`
- `tests/composition/test_processor_execution.py`

## Self-Review

- Confirmed every Task 9 record is derived from protocol and source-backed endpoint facts, with no CPU/profile/module-name selection branches.
- Confirmed route identity excludes endpoint and module names but includes function and protocol facts.
- Confirmed source-side and backend-side adapter ports are explicit and directionally correct.
- Confirmed scalar and packed physical ownership checks account for whole-port/member overlap and RFuzz overlap.
- Confirmed processor execution source paths are represented path-independently inside canonical composition IR while remaining auditable in `processor_execution.v1`.
- Confirmed legacy generic composition behavior is preserved for non-processor memory routes.
- `git diff --cached --check` passed before commit.
- Reviewer subagent capability was unavailable; self-review plus focused and scoped regression evidence was used instead.

## Concerns

- No implementation concern remains within Task 9 scope.
- A broad full-suite test was intentionally not run. Verification was limited to the focused and task-relevant regression suites requested by the user.
- SystemVerilog instantiation from these records remains Task 11 by the approved plan; Task 9 only plans, hashes, source-registers, and publishes the deterministic execution records.

## Task 9 Review Fix Wave

### RED

Command:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Output:

```text
FFF.                                                              [100%]
FAILED tests/composition/test_processor_execution.py::ProcessorExecutionTests::test_clocked_mmio_without_processor_timing_association_keeps_legacy_path
FAILED tests/composition/test_processor_execution.py::ProcessorExecutionTests::test_generic_plan_embeds_execution_and_adapter_source_name_independently
FAILED tests/composition/test_processor_execution.py::ProcessorExecutionTests::test_records_protocol_selected_routes_widths_ports_and_backend_contract
SUBFAILED(reason='unsupported-extension') tests/composition/test_processor_execution.py::ProcessorExecutionTests::test_rejects_invalid_or_ambiguous_execution_facts
4 failed, 1 passed, 6 subtests passed in 0.26s
```

The failures were respectively `generic:source-path:missing` after false processor activation,
missing `processor_execution.v1.json`, missing `ProcessorAdapterDefinition.source_ports`,
and no exception for an undeclared field omitted from `extension_fields`.

After the first implementation pass, the complete generic IR comparison remained RED:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

```text
.F..                                                              [100%]
FAILED tests/composition/test_processor_execution.py::ProcessorExecutionTests::test_generic_plan_embeds_execution_and_adapter_source_name_independently
1 failed, 3 passed, 7 subtests passed in 0.23s
```

The differing value was the endpoint-derived input-layout `field_id`/`owner` evidence and its
layout hash. Processor-mode IR now normalizes those identifiers while preserving the runtime
layout for rendering and audit.

The first scoped regression run exposed established diagnostic precedence:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py tests/composition/test_processor_boundary.py tests/composition/test_generic_auto.py tests/composition/test_generic_lint_diagnostics.py -q
```

```text
...........F...........................             [100%]
FAILED tests/composition/test_processor_adapters.py::ProcessorAdapterTests::test_unknown_extension_and_wrong_direction_fail_closed
1 failed, 38 passed, 21 subtests passed in 7.39s
```

The new RTL-port direction check initially preceded the existing extension-policy direction
check. Extension policy diagnostics now retain precedence.

### GREEN

Focused command:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Output:

```text
....                                                              [100%]
4 passed, 7 subtests passed in 0.22s
```

Scoped processor and generic regressions:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py tests/composition/test_processor_boundary.py tests/composition/test_generic_auto.py tests/composition/test_generic_lint_diagnostics.py -q
```

Output:

```text
.......................................             [100%]
39 passed, 21 subtests passed in 7.34s
```

No broad full-suite test was run.

## Task 9 Second Review Fix Wave

### RED

Focused command:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Output:

```text
FF.F..                                                         [100%]
6 failed, 3 passed, 7 subtests passed in 0.20s
```

The failures proved that a realistically timing-associated ordinary MMIO endpoint was still
misclassified, explicit processor candidates silently fell through on valid and ambiguous or
missing timing, and source evidence IDs remained insensitive to processor source-content changes.

The first scoped regression run exposed two processor-boundary fixtures with explicit split
processor functions but no clock/reset associations:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py tests/composition/test_processor_boundary.py tests/composition/test_generic_auto.py tests/composition/test_generic_lint_diagnostics.py -q
```

```text
..............F...F......................        [100%]
2 failed, 39 passed, 24 subtests passed in 7.54s
```

Both failures were `ProcessorBoundaryError: memory-clock`; the processor fixtures were updated
to carry the now-required explicit timing associations.

### GREEN

Focused command:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py -q
```

Output:

```text
......                                                         [100%]
6 passed, 10 subtests passed in 0.27s
```

Scoped processor and generic regressions:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py tests/composition/test_processor_boundary.py tests/composition/test_generic_auto.py tests/composition/test_generic_lint_diagnostics.py -q
```

Output:

```text
.........................................        [100%]
41 passed, 24 subtests passed in 7.40s
```

No broad full-suite test was run.
