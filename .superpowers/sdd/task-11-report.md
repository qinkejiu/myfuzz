# Task 11 Report: Generated Processor SystemVerilog Wiring

## Status

Complete from base `04c4ce32308e037da12aaa8d54aa3003f00a82d2`.

Implementation commit: `f023be1` (`feat(composition): generate processor wiring`)

## Changed Files

- `src/myfuzz/composition/auto.py`
- `src/myfuzz/composition/protocol_composer.py`
- `tests/composition/test_processor_execution.py`
- `tests/integration/test_processor_auto_wiring.py`
- `.superpowers/sdd/task-11-report.md`

Pre-existing changes in `.superpowers/sdd/task-2-report.md` and the untracked `third_party/` directory were preserved and excluded from the implementation commit.

## Behavior

- Processor composition is selected only by the semantic `processor_execution` plan produced from processor endpoint functions; rendering contains no CPU, module, endpoint, or fixture-name dispatch.
- The planner verifies processor reset polarity and synchrony against the selected source module and persists the explicit control fact used by rendering.
- A virtual `processor-memory-beat@1` initiator derived from the validated execution contract allows RAM and peripheral profiles to bind independently of the CPU-facing OBI, AXI4, or TL-UL protocol.
- The generated top declares and instantiates the source CPU, validated protocol adapter, direct backend or Task 10 round-robin arbiter, generated cancellation-safe backend bridge, and source-verified backend-native components.
- Scalar CPU fields connect directly. Packed fields use only the compiler-proven `part_select`; each physical container is declared and connected to the CPU once.
- Adapter-driven CPU input ranges are checked for unique ownership before any SystemVerilog is emitted.
- Clock and reset are selected from processor boundary facts. Active-high reset is explicitly normalized for adapter/backend RTL; polarity and synchrony must both be present in verified evidence.
- Split arbitration connects `cancel_valid_o` to the generated backend's `cancel_valid_i` and `cancel_ready_o` back to `cancel_ready_i`. Cancellation acknowledgment is withheld until an accepted target response has been drained or no response remains.
- `processor_execution.v1.json` contains the Task 9 route records, complete Task 10 backend route, deterministic external/generated RTL SHA-256 records, and a publication hash.
- Source hashes are checked before staging publication and again after atomic publication. A changed post-publication source removes the newly created output instead of retaining invalid evidence.
- Non-processor rendering remains on the existing generic path.

## TDD Evidence

### RED: missing processor instances

Command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_processor_auto_wiring -v
```

Output after correcting fixture-only elaboration metadata:

```text
test_renamed_protocol_fixtures_publish_complete_wiring_and_compile ...
  (protocol=('obi', '1')) ... FAIL
  (protocol=('axi4', '1')) ... FAIL
  (protocol=('tl-ul', '1')) ... FAIL
AssertionError: '<protocol>_processor_memory_adapter #(' not found in generated top
Ran 1 test in 2.234s
FAILED (failures=3)
```

The source-only renderer instantiated the renamed CPU but no Task 9 adapter or Task 10 backend.

### RED: backend-native component routing

Command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_processor_backend_instantiates_semantic_memory_target -v
```

Output:

```text
ERROR: test_processor_backend_instantiates_semantic_memory_target
myfuzz.composition.auto.AutoCompositionError: generic:component:storage:no-compatible-endpoint
Ran 1 test in 0.356s
FAILED (errors=1)
```

This proved component selection had no semantic processor-backend initiator.

### RED: generated RTL source evidence

Command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_renamed_protocol_fixtures_publish_complete_wiring_and_compile -v
```

Output:

```text
(protocol=('obi', '1')) ... FAIL
(protocol=('axi4', '1')) ... FAIL
(protocol=('tl-ul', '1')) ... FAIL
AssertionError: 'generic_composition_top.sv' not found in source_hashes
Ran 1 test in 2.216s
FAILED (failures=3)
```

### GREEN: focused Task 11 integration

Command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_processor_auto_wiring -v
```

Output:

```text
test_processor_backend_instantiates_semantic_memory_target ... ok
test_renamed_protocol_fixtures_publish_complete_wiring_and_compile ... ok
Ran 2 tests in 3.086s
OK
```

The renamed OBI, AXI4, and TL-UL subtests compiled the generated source lists with strict Icarus and Verilator when installed.

### GREEN: final Task 9/10/composition regression

Command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.composition.test_processor_execution tests.composition.test_processor_backend tests.composition.test_processor_adapters tests.composition.test_processor_boundary tests.composition.test_protocol_composer tests.composition.test_generic_auto tests.composition.test_generic_lint_diagnostics tests.protocols.test_processor_memory_backend tests.protocols.test_processor_memory_arbiter_rtl tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl tests.integration.test_generic_composition tests.integration.test_processor_auto_wiring -v
```

Output:

```text
Ran 96 tests in 12.372s
OK
```

Focused source checks:

```text
git diff --check -- src/myfuzz/composition/auto.py src/myfuzz/composition/protocol_composer.py tests/composition/test_processor_execution.py tests/integration/test_processor_auto_wiring.py
```

Result: exit 0, no output.

## Self-Review

- Checked the implementation against each Task 11 brief item and the Task 9/10 binding decisions.
- Confirmed processor selection uses endpoint functions, protocols, execution records, backend records, field roles, and compiler physical mappings only.
- Confirmed packed containers are instantiated once and adapter connections consume exact recorded slices.
- Confirmed unique CPU input drivers are rejected before rendering.
- Confirmed the generated backend's cancel handshake is connected in the split path and closes the same-cycle cancel/response drain edge case.
- Confirmed source-backed backend components require all ten `processor-memory-beat@1` fields, verified clock/reset compatibility, source-proven module ports, and validated integer parameters.
- Confirmed non-processor generic integration tests remain green.
- Confirmed only Task 11 files were staged in the implementation commit.

## Concerns

- No independent reviewer/subagent tool was available, so review was performed inline.
- The requested focused suites were run; the full repository suite was intentionally not run.
- Generated split-top compilation is exercised through the same renderer branch and the Task 10 arbiter is covered by RTL simulation, but the new Task 11 integration fixture set compiles unified/direct processor routes rather than an additional split CPU fixture.

## Review Fix RED/GREEN Evidence

### RED: complete Task 11 review regression set

Command:

    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.composition.test_processor_backend.ProcessorBackendTests.test_split_routes_use_fair_arbiter_and_reject_instruction_writes tests.composition.test_processor_execution.ProcessorExecutionTests.test_generic_plan_embeds_execution_and_adapter_source_name_independently tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_direct_backend_flushes_an_accepted_nonresponding_target_before_reuse tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_direct_target_without_explicit_flush_contract_is_rejected tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_synchronous_cpu_reset_is_rejected_by_asynchronous_fixed_adapter tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_split_renamed_fixture_compiles_and_recovers_after_timeout tests.integration.test_processor_auto_wiring.ProcessorAutoWiringIntegrationTests.test_split_routing_evidence_tampering_is_rejected -v

Output after correcting fixture-only timing associations:

    KeyError: 'rtl_source'
    KeyError: 'audit'
    TypeError: _render_processor_backend_module() takes 2 positional arguments but 4 were given
    AssertionError: ValueError not raised (missing recovery-contract rejection)
    AssertionError: "adapter-reset-synchrony" does not match "memory-reset:execution.route.4"
    ProcessorBoundaryError: memory-clock:route.data
    Ran 7 tests in 1.415s
    FAILED (failures=2, errors=5)

These failures independently exposed missing Task 10 routing source/reset facts, publication audit evidence, bounded direct recovery generation, target recovery rejection, reset-synchrony compatibility, and split endpoint integration.

### GREEN: focused Task 11 and contract tests

Command:

    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.composition.test_processor_backend tests.composition.test_processor_execution tests.integration.test_processor_auto_wiring -v

Output:

    Ran 17 tests in 5.083s
    OK

This includes Icarus behavioral coverage for an accepted nonresponding direct target followed by safe reset-flush reuse, and a renamed split instruction/data fixture covering two adapters, ordering, timeout, cancellation/flush, reset, and post-recovery progress. Installed Icarus and Verilator compile the published strict source list; absence raises an explicit SkipTest.

### GREEN: Task 9/10/composition/RTL regression gate

Command:

    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.composition.test_processor_execution tests.composition.test_processor_backend tests.composition.test_processor_adapters tests.composition.test_processor_boundary tests.composition.test_protocol_composer tests.composition.test_generic_auto tests.composition.test_generic_lint_diagnostics tests.protocols.test_processor_memory_backend tests.protocols.test_processor_memory_arbiter_rtl tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl tests.integration.test_generic_composition tests.integration.test_processor_auto_wiring -v

Output:

    Ran 101 tests in 14.346s
    OK
