# Task 12 Report: Connected Generic Processor Simulation Fixture

## Status

Complete from base commit `4e74de267f2faf845f0bdabfc99df1bab48e17de`, including all findings from the review of `4e74de2..826b79c`.

Implementation commit: `826b79c` (`test(integration): execute connected processor fixtures`)

Review-fix commit: the commit containing this report update.

## Files

- Added `tests/fixtures/rtl/generic_processor/generic_processor_fixture.sv`.
- Added `tests/fixtures/rtl/generic_processor/generic_processor_ram.sv`.
- Added `tests/integration/test_connected_processor_fixture.py`.
- Modified `src/myfuzz/integration/rfuzz_simulator.py` only to project processor execution routes and their separate source-proven clock/reset controls.

The pre-existing `.superpowers/sdd/task-2-report.md` modification and untracked `third_party/` directory were preserved and excluded from the commit.

## Behavior

- A single source-backed RTL sequencer autonomously waits for the generated adapter reset-release contract, then fetches an instruction at address `0`, reads data at address `4`, writes bytes `0` and `1` with byte enable `4'b0011`, reads address `4` back, and raises `done_o`.
- The sequencer exposes OBI, AXI4, and TL-UL protocol pins simultaneously. Each test variant changes only the selected protocol endpoint facts and adapter source; processor behavior, backend route, RAM, scoreboard, assertions, addresses, and data are shared.
- The RAM initializes `0x13579bdf` and `0xaabbccdd`, implements one outstanding request/response path, honors byte enables, and produces final readback `0xaabb3344`.
- The integration test executes `plan_generic_composition -> write_generic_composition -> iverilog compile -> vvp simulate` for every protocol.
- Requests originate only from the RTL sequencer. The Python testbench drives clock, reset, and an unrelated changing random input; it never drives protocol requests.
- Both RTL source counters and backend-to-RAM handshake counters must report exactly four accepted requests and four completions. Any loss, duplicate, protocol/backend error, wrong fetch/data/readback, stall, or 160-cycle timeout fails simulation.
- RFuzz runtime projection now understands processor execution routes. The test proves the random external input is the only projected runtime input and every adapter-driven source response port is excluded, preventing double driving.
- Non-processor plans retain the original `_generic_routes` RFuzz path.

## RED Evidence

Environment-only attempts, not accepted as feature RED:

```text
python -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `127`, `/bin/bash: line 1: python: command not found`.

```text
python3 -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `2`, collection error `ModuleNotFoundError: No module named 'myfuzz'` because `PYTHONPATH=src` was absent.

Authoritative initial RED:

```text
PYTHONPATH=src python3 -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `1`; all three OBI/AXI4/TL-UL subtests failed with `FileNotFoundError` for `tests/fixtures/rtl/generic_processor/generic_processor_fixture.sv`. Summary: `3 failed, 1 passed in 0.16s`.

RFuzz processor-projection RED after adding the RTL fixture:

```text
PYTHONPATH=src python3 -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `1`; all three subtests failed at `rfuzz_simulator._runtime_boundary` with `ValueError: generic composition adapter binding is invalid`. Summary: `3 failed, 1 passed in 1.33s`.

Separate-control RED after processor route ownership was added:

```text
PYTHONPATH=src python3 -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `1`; all three subtests failed with `ValueError: runtime requires one verified clock/reset domain`. Summary: `3 failed, 1 passed in 1.24s`.

AXI reset-release RED after RFuzz projection was fixed:

```text
PYTHONPATH=src python3 -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `1`; OBI and TL-UL passed, while AXI timed out with `accepted=0 completions=0 readback=00000000 errors=0 cycles=160 exit=timeout`. Summary: `1 failed, 1 passed, 2 subtests passed in 2.67s`.

Temporary boundary tracing showed AXI `arvalid=1`, `arready=1`, and source acceptance on cycle 0 while the generated synchronous adapter reset remained asserted. A shared three-cycle source startup guard fixed the fixture's reset-contract race.

## GREEN Evidence

Focused Task 12 GREEN:

```text
PYTHONPATH=src python3 -m pytest -q tests/integration/test_connected_processor_fixture.py -vv
```

Output: exit `0`, `1 passed, 3 subtests passed in 2.60s`.

Final Task 9-12/composition/RTL/RFuzz regression command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.composition.test_processor_execution tests.composition.test_processor_backend tests.composition.test_processor_adapters tests.composition.test_processor_boundary tests.composition.test_protocol_composer tests.composition.test_generic_auto tests.composition.test_generic_lint_diagnostics tests.protocols.test_processor_memory_backend tests.protocols.test_processor_memory_arbiter_rtl tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl tests.integration.test_generic_composition tests.integration.test_processor_auto_wiring tests.integration.test_rfuzz_simulator tests.integration.test_connected_processor_fixture -v
```

Output: exit `0`, `Ran 120 tests in 24.844s`, `OK`.

Pre-commit staged whitespace/scope check:

```text
git diff --cached --check
git diff --cached --name-only
```

Output: exit `0`, no whitespace diagnostics; exactly the four Task 12 implementation/test files were staged.

## Metrics

| Protocol | Accepted | Completions | Readback | Errors | Cycles | Exit reason |
|---|---:|---:|---:|---:|---:|---|
| OBI | 4 | 4 | `0xaabb3344` | 0 | 24 | `done` |
| AXI4 | 4 | 4 | `0xaabb3344` | 0 | 28 | `done` |
| TL-UL | 4 | 4 | `0xaabb3344` | 0 | 28 | `done` |

## Self-Review

- Checked every Task 12 brief item against the fixture, generated-flow test, RFuzz ownership assertions, metrics, and timeout/error paths.
- Confirmed the processor fixture contains no CPU/module/endpoint-name dispatch and the production simulator branch selects only from `processor_execution` facts.
- Confirmed all request handshakes and responses are generated/consumed in RTL and Python supplies no bus transaction values.
- Confirmed OBI, AXI4, and TL-UL share one sequencer, one backend contract, one RAM, one testbench scoreboard, and identical expected operations.
- Confirmed RFuzz removes whole scalar or packed processor route ports before constructing the external random layout.
- Confirmed the non-processor branch is unchanged and all prior RFuzz simulator tests pass.
- Confirmed source publication still covers adapter, RAM, processor, and generated-top hashes through the existing Task 11 audit path.
- Independent reviewer/subagent capability was unavailable; review was performed inline.

## Review-Fix RED/GREEN Evidence

Authoritative RED after removing the three-cycle source guard, retaining requests until true protocol acceptance, adding reset-time readiness assertions, independently tracking AXI AW/W, and adding packed-container projection coverage, but before production RTL changes:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl tests.integration.test_rfuzz_simulator.RfuzzSimulatorTests.test_processor_projection_excludes_packed_response_container_only tests.integration.test_connected_processor_fixture -v
```

Output: exit `1`, `Ran 6 tests in 2.712s`, `FAILED (failures=2)`. The AXI adapter test failed with `FAIL: reset blocks all source-facing acceptance`. The connected AXI simulation failed with `METRICS accepted=0 completions=0 readback=00000000 errors=0 cycles=160 exit=timeout`. OBI, TL-UL, and the packed physical response-container RFuzz projection case passed.

GREEN after gating AXI AW/W/AR readiness with the adapter's explicit active-low synchronous reset:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl tests.integration.test_rfuzz_simulator.RfuzzSimulatorTests.test_processor_projection_excludes_packed_response_container_only tests.integration.test_connected_processor_fixture -v
```

Output: exit `0`, `Ran 6 tests in 2.659s`, `OK`.

Focused Task 9-12/composition/adapter/RFuzz regression:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.composition.test_processor_execution tests.composition.test_processor_backend tests.composition.test_processor_adapters tests.composition.test_processor_boundary tests.composition.test_protocol_composer tests.composition.test_generic_auto tests.composition.test_generic_lint_diagnostics tests.protocols.test_processor_memory_backend tests.protocols.test_processor_memory_arbiter_rtl tests.protocols.test_obi_processor_memory_adapter_rtl tests.protocols.test_axi4_processor_memory_adapter_rtl tests.protocols.test_tl_ul_processor_memory_adapter_rtl tests.integration.test_generic_composition tests.integration.test_processor_auto_wiring tests.integration.test_rfuzz_simulator tests.integration.test_connected_processor_fixture -v
```

Output: exit `0`, `Ran 121 tests in 26.255s`, `OK`.

Fresh connected metrics after the review fixes:

| Protocol | Accepted | Completions | Readback | Errors | Cycles | Exit reason |
|---|---:|---:|---:|---:|---:|---|
| OBI | 4 | 4 | `0xaabb3344` | 0 | 23 | `done` |
| AXI4 | 4 | 4 | `0xaabb3344` | 0 | 28 | `done` |
| TL-UL | 4 | 4 | `0xaabb3344` | 0 | 27 | `done` |

## Concerns

- The focused suites requested by the task passed; the full repository suite was intentionally not run.
- The source fixture now issues immediately after its own reset release. OBI and TL-UL already suppressed source acceptance during adapter reset; AXI AW/W/AR readiness now follows the same explicit contract while preserving Task 11's generated reset synchronizer.
- No remaining Task 12 implementation concern was found.
