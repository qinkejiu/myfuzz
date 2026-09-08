# Contract transducer Task 7 report

Status: COMPLETE.

Implementation commit: `c9e9cadf8f3bf1a8e6ea91c3401248e795335558`.

## Scope and interfaces

Changed only the six Task 7 production/test files. This report is committed
separately to record the implementation hash. User changes to
`.superpowers/sdd/task-2-report.md` and all `third_party` files were preserved.

`build_simulator(..., contract_transducer=plan, test_header=header)` publishes
the complete cycle layout, transport, `contract_transducer.json`,
`contract_transducer.sv`, and `test_header.json`. The header is optional: the
default uses the supplied fixed boot/hart controls, two reset cycles, and the
existing 65536-cycle execution limit. A supplied header is validated against
the contract and cycle layout, including instruction alignment; reset and
execution counts must be positive and bounded. Execution cycles are an upper
bound on the number of complete records admitted for a test. Conflicting
boot/hart defaults, randomized boot/hart controls, and fixed boot-image plusargs
are rejected before publication.

`write_generic_composition(..., contract_transducer=plan)` adds the four generic
top ports `rfuzz_cycle_bits`, `test_begin`, `test_boot_address`, and
`test_illegal_instruction`. It instantiates the renderer at `backend_target_*`
after the existing processor adapters, arbiter, and backend wrapper. In this
mode every address reaches the contract store, and the fixed address-decoded
memory/peripheral target instances and their response drivers are omitted.
The original component/address IR remains planning evidence; it is not the
constrained runtime's active target map. No-transducer rendering retains the
legacy behavior.

For split instruction/data routes, publicly visible route request handshakes
capture the selected semantic function. The backend request handshake then
latches that flag alongside the held target request. No CPU identifier,
hierarchical owner signal, or force is used. Unified memory routes currently
lack an explicit per-request instruction classification and are rejected.
Protocol, widths, and both memory-function bindings must match the plan.

The outer arbiter/backend watchdog is at least `2 * max_wait_cycles + 16`,
covering both bounded transducer stall phases plus wrapper overhead. Its
effective value is also recorded in backend metadata and backend hashes.
The existing wrapper limit of 65535 remains enforced. The transducer's reset
combines normalized DUT reset with target flush, preserving memory through
protocol cancellation; only test begin clears the store.

The host `CycleIdentityProjector` returns the complete raw record unchanged,
with `constraint_hash` equal to the complete transducer contract hash. Existing
physical-binding validation proves external input slices, including packed
compiler offsets. Only `external.<field_id>` slices drive CPU external inputs;
backend entropy fields never become additional CPU protocol-input drivers.
External declarations, cycle-field widths, and physical bindings must agree.
The existing `RfuzzInputTransport` encodes the full cycle width in its unchanged
equal-width, eight-byte-aligned wire format. The old InputLayout-specific
transport factory is not used for CycleInputLayout.

Each persistent RFuzz test pulses `test_begin` once before its configured DUT
reset sequence, then consumes one whole record per execution tick. Test begin
also latches the fixed boot/illegal controls. Boot/hart values reach their
source-proven physical CPU ports when those bindings exist.

Replay identity includes `transducer_hash` and `header_hash` when present,
alongside raw payload, layout, constraint, binary, physical-control, and simulator
input identities. The artifact provenance records the exact generated RTL byte
SHA-256. Both corpus checks reject differing saved identities before executing
the test records. Artifacts without the new metadata, or with it set to None,
keep their previous replay identity and key.

## RED evidence

The checkout has no `python` command; effective commands use
`PYTHONPATH=src python3 -m pytest`.

Initial simulator publication/lifecycle tests:

```sh
PYTHONPATH=src python3 -m pytest tests/integration/test_rfuzz_simulator.py::ContractSimulatorTests -q --tb=short
```

RED: **3 failed**, each because `build_simulator` did not support the
`contract_transducer` keyword. After composition and simulator integration,
the expanded first group passed **6 tests and 10 subtests** in 11.64 seconds.

The independently implemented replay tests initially produced **9 failures**
for absent transducer/header identity binding and non-rejected replay changes.
The focused replay group then passed **5 tests and 8 subtests**.

Composition tests initially produced **6 failures** for unsupported transducer
render/publication keywords. The watchdog publication regression subsequently
failed with recorded `16` versus emitted `56`; the backend metadata/hash now
uses the effective bound.

Self-review added a byte-hash assertion before correcting a JSON-string hash
used for the RTL file: **1 failed, 6 passed, 10 subtests passed**. Another
regression exposed acceptance of an external cycle slice with a width different
from its physical binding: **2 failures** (the failed subtest and the unexpected
publication assertion). Validation now rejects changed external widths and
additional unbound external cycle fields before creating an output directory.

## Final GREEN evidence

```sh
PYTHONPATH=src python3 -m pytest tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py tests/composition/test_protocol_composer.py -q --tb=short
```

Result: **50 passed, 3 skipped, 40 subtests passed in 26.13 seconds**, exit 0.
The three skips are existing official RFuzz/real CPU opt-in tests; the new
constrained tests execute actual Icarus RTL and Verilator publication lint.

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/composition/test_coherent_memory.py tests/isa/test_instruction_transducer.py tests/integration/test_processor_auto_wiring.py -q --tb=short
```

Result: **226 passed, 3 subtests passed in 35.18 seconds**, exit 0, no skips.
This includes the prior Python/RTL equivalence and synthesis checks plus
processor wiring regressions. Icarus, Verilator, and Yosys resolve from
`/home/qinkejiu/.local/bin`. `git diff --check` and
`git diff --cached --check` both passed before the implementation commit.

## Self-review and limitations

Actual generated RTL checks cover instruction-versus-data entropy selection,
legal and illegal header modes against Python instruction repair, boot/hart
physical pins, raw external input bits, response-data variation, repeat-test
determinism, memory clearing between tests, bounded record counts, and full
20-cycle acceptance/response stalls without premature outer cancellation.
The latter completes all eight contending instruction/data requests using
all-zero entropy. Existing packed binding, reset, process cleanup, and legacy
projection tests remain green.

The replay/composer subtask was reviewed against the final diff, including
public handshake timing, flush wiring, disabled legacy drivers, actual watchdog
metadata, and new corpus checks. No unresolved Task 7 correctness issue was
identified by this self-review.

Supported constrained topology is currently two split instruction/data routes.
Unified interfaces require a future explicit classification contract. External
inputs currently require plain bit encoding with at most `randomizable`
metadata; numeric/enum/gating projection is rejected rather than silently
applied outside the transducer plan. Large standalone transducer wait bounds
that exceed the wrapper watchdog limit cannot use this integration. This task
does not claim an official-mutator long campaign or full real-CPU execution;
those opt-in checks and later task work remain separate from the listed RTL
integration evidence.
