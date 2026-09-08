# Contract transducer Task 6 report

Status: COMPLETE

Implementation commit: `dd3a2156432b7f8367b59e00282a0008e9e26212`.

## Scope and interface

Created only `src/myfuzz/composition/transducer_rtl.py`,
`tests/composition/test_transducer_rtl.py`, and
`tests/integration/test_constrained_backend_rtl.py`, plus this report. No Task 5
interface correction was necessary. Existing user `task-2-report.md` changes and
all third-party files were left untouched.

`render_transducer_rtl(plan, module_name="myfuzz_contract_transducer")` emits a
SystemVerilog module with these generic ports:

- `clock_i`, active-low `reset_i`, synchronous `test_begin_i`;
- `test_boot_address_i`, `test_illegal_instruction_i`, latched at test begin;
- `rfuzz_cycle_bits`, with width and consumed slices from `plan.cycle_layout`;
- `req_valid_i`, `req_instruction_i`, `req_addr_i`, `req_write_i`,
  `req_wdata_i`, `req_be_i`, and `req_ready_o`;
- `rsp_valid_o`, `rsp_data_o`, `rsp_error_o`.

The caller supplies valid normalized requests and validates the full TestHeader
before test begin, as documented in the renderer. `req_instruction_i=1` denotes
instruction and zero denotes data; the renderer derives each function's domain
from the plan. There is no CPU-name or hierarchy inspection, numeric domain input,
or consumption of external cycle fields. An absent reference byte-enable maps to
all enabled RTL lanes. Unbound functions and invalid instruction writes are
outside the valid normalized-request input contract.

**Cycle convention:** outputs describe the current cycle immediately before its
rising edge; that edge commits the corresponding `ContractRuntime.step` effects.
Both request acceptance and response outputs are combinational from the pending
state/current entropy, with state and memory committed by `always_ff`. This is a
deliberate clarification of the brief's illustrative registered-response snippet:
the equivalence harness samples all four outputs at the same pre-edge boundary,
preserving the Python response-cycle entropy semantics without adding latency.
Entropy must remain stable through that edge. There is no response backpressure,
matching `ProcessorBeatTransducer`.

## Implementation

The store uses bounded valid/tag/domain/data/byte-valid/provenance arrays and a
full-tag associative lookup with first-free allocation. The default capacity is
256 arbitrary `(domain, aligned beat base)` entries. There is no hashing, eviction,
or replacement; capacity errors return zero without mutation regardless of random
error enablement. Widths, capacity, wait limits, domains, and entropy offsets all
come from the plan. The generated source includes its contract hash.

The FSM bounds acceptance and response waits, holds exactly one request, and
does not accept a replacement during a response. Random error responses return
that response cycle's raw data, exactly as the reference does; structural capacity
and provenance errors return zero. Errors never allocate or change bytes.

The store distinguishes instruction-generated, data-generated, and CPU-written
beats. Fetching data-generated content errors; successful CPU writes permit exact
later fetches. Per-byte validity preserves partial writes to absent beats and
initializes only missing bytes on the first later read. Empty-byte-enable writes
do not allocate or change provenance, including when full. DUT reset clears only
protocol state. Test begin invalidates all entries, cancels protocol state, and
latches header controls even while DUT reset is asserted.

Instruction functions use the plan ISA's public `RiscvInstructionTransducer`
templates and repair methods. Every 32-bit or compressed 16-bit slot has its own
selector and payload slice. For compressed templates, rendering enumerates each
template's free-bit subspace and reduces any nonlinear reference repairs to
Boolean expressions. This avoids duplicating operation-specific legality rules
or emitting a full instruction ROM. Illegal masks/values are likewise derived
from the reference's explicit illegal selection. A halfword request or a saved
halfword boot entry in the matching beat forces compressed slots. Cached beats
remain byte-identical, including after DUT reset.

## RED evidence

The brief's `python` executable is absent in this checkout. The effective command
was:

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py -q
```

Before production code existed: exit 2, two expected missing-module collection
errors for `myfuzz.composition.transducer_rtl`. The initial tests already included
source shape and cycle-for-cycle Icarus equivalence for protocol, memory,
provenance, reset, domains, independent slots, every selector, and illegal mode.
After implementation: **33 passed in 6.11s**.

Self-review then added exhaustive compressed operand coverage and an optional
Yosys synthesis-structure check. They passed without further production changes:
**3 passed, 24 deselected in 10.68s**.

Independent review reproduced a truncation bug for valid wait configurations
larger than 32 bits. Two short trace regressions were added before fixing it:

```sh
PYTHONPATH=src python3 -m pytest tests/integration/test_constrained_backend_rtl.py -k large_wait -q --tb=short
```

RED: **2 failed, 27 deselected** for `(1 << 32) + 1` and `(1 << 63) + 1`.
The former `integer MAX_WAIT` truncated each value to 1 and caused immediate
acceptance/response. The renderer now emits a counter-width `MAX_WAIT_MINUS_ONE`
literal for both comparisons. Focused GREEN: **6 passed, 32 deselected in 0.26s**,
including normal bounds and source-configuration checks. No shared compiler or
runtime bounds were changed.

## GREEN evidence

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/composition/test_coherent_memory.py tests/isa/test_instruction_transducer.py -q
```

Final result after the review fix: **176 passed in 16.47s**, exit 0. This includes
all 138 Task 5 regression cases and 38 Task 6 cases. No Icarus or Yosys test was
skipped. The earlier candidate, before the two large-wait regressions, passed
174 cases in 16.52s. `git diff --check` and `git diff --cached --check` exited 0
before committing; the implementation commit contains only the three Task 6
production/test files.

Icarus executable: `/home/qinkejiu/.local/bin/iverilog`.
Exact version: **Icarus Verilog version 14.0 (devel) (f493076)**; preprocessor,
parser/elaborator, and VVP code-generator version agree.

The harness writes each generated module and testbench into pytest's temporary
directory and executes these argument vectors (paths vary per case):

```sh
/home/qinkejiu/.local/bin/iverilog -g2012 -s tb -o <tmp>/simulation.vvp <tmp>/backend.sv <tmp>/tb.sv
/home/qinkejiu/.local/bin/vvp <tmp>/simulation.vvp
```

Each cycle compares `(req_ready, rsp_valid, rsp_data, rsp_error)` with Python.
Coverage includes:

- Wait bounds 1/2/5 and nontruncating 33/64-bit wait limits, idle ready suppression, changing requests while pending,
  response without replacement, cancelled requests, and acceptance-age reset.
- Repeat fetch/read coherence; aligned low bits; full/partial/empty writes;
  instruction/data sharing and isolated domains; 64-bit address boundaries.
- Random errors enabled/disabled; raw error data; no error allocation; data-fetch
  provenance conflicts; CPU-write exceptions; partial initialization; reset and
  test-begin lifetime separation, including test begin during reset/pending.
- Capacities 1/3/256 with adversarial same-low-bit addresses; overflow reads and
  writes, empty writes when full, old contents retained, reset preserving full
  capacity, and test begin reclaiming capacity.
- 32/64-bit data beats, RV32/RV64 ISA contracts, base/compressed slot modes,
  independent slot selectors, all 256 selector values, zero/all-one/random
  payloads, and both illegal header modes.
- Request offset +2, architectural boot +2 with an aligned request, saved header
  survival through reset, unrelated beats, and replacement headers. Header pins
  deliberately vary outside test begin to verify that controls are latched.
- Every free-bit combination of every compressed template: 28,801 RV32C plus
  38,913 RV64C combinations (**67,714 total**), packed into independent RTL slots.
- Reordered cycle fields with external fields before backend fields, and two
  seeded mixed traces of 1,200 cycles each.

Yosys executable: `/home/qinkejiu/.local/bin/yosys`.
Exact version: **Yosys 0.68+ (git sha1 b8959e70b, Release,
GNU /usr/bin/c++ 13.3.0)**. The default 256-entry, 64-bit module passed:

```sh
yosys -Q -T -p 'read_verilog -sv <tmp>/backend.sv; hierarchy -check -top myfuzz_contract_transducer; proc; opt; memory_collect; check -assert; select -assert-none t:$dlatch'
```

## Self-review and concerns

Reviewed allocation order, byte-valid merging, no writes on error, provenance
transitions, stored boot/illegal lifetime, counter off-by-one behavior, domain
mapping, and entropy slice ownership against the final Task 5 implementation.
All declared capacity is usable without collision-driven behavior changes.

Independent review initially found one important wait-constant truncation issue;
the preceding RED/GREEN regression addresses it. The reviewer rechecked the fix
and independently passed five timing/boundary tests plus all nine renderer tests,
with a final ready-to-merge assessment. No other critical/important
protocol, memory, synthesis, or timing issue was identified. The reviewer also
independently reran the original 36 Task 6 cases successfully in 16.18s.

Minor interface limitation: custom `module_name` values must be non-keyword
SystemVerilog identifiers. The current lexical validation rejects malformed
identifiers but does not reject reserved words such as `module`.

The associative lookup and write selection scale with configured capacity. Yosys
validated synthesizable structure and absence of latches; this task does not claim
technology mapping, timing closure, or measured PPA. No full formal equivalence
claim is made beyond the listed trace and exhaustive compressed-repair coverage.
Future wiring must respect the documented pre-edge convention and the reference's
no-backpressure response contract. Header schema/hash validation remains the host's
responsibility; this module receives only the validated fixed controls it uses.
