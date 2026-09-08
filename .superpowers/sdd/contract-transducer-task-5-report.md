# Contract transducer Task 5 report

Status: COMPLETE

Implementation commit: `0c4c5e19b520ce20ae92b8a8d1e35cbd21aeb0ab`

## Scope and interface

Implemented only the two Task 5 production modules, public composition exports,
and two Task 5 test modules. This report is committed separately so it can record
the implementation commit. No third-party files or existing task reports changed.

`ProcessorBeatRequest` carries explicit `address`, `function`, `domain`, `write`,
`write_data`, and optional `byte_enable`. `ProcessorBeatTransducer` has one pending
request, separates acceptance from response, and bounds both acceptance wait and
response wait. Choice bits 0, 1, and 2 select acceptance, response, and injected
response error. The response cycle cannot also accept a new request.

`compile_contract_transducer` accepts `processor-memory-beat@1`, an ISA contract,
address/data widths, memory-domain declarations, optional external-input widths,
wait bound, injected-error control, and `memory_capacity_entries` (default 256).
Plans contain no CPU profile identifier. Semantic sets and field declarations
are canonically sorted. All configuration, the complete cycle layout, addressing
policy, and capacity/error policy enter `contract_hash` and `document()`.

Cycle fields are `instruction_selector` (8), `instruction_payload` (32),
`response_choice` (3), `response_data` (data width), followed by independently
allocated `external.<id>` fields in identifier order.

`ContractRuntime.step(raw_cycle, dut_outputs)` accepts a request, None, or a mapping
with `request` and active-high boolean `reset`. The result exposes `req_ready`,
`rsp_valid`, `rsp_data`, `rsp_error`, `response_request`, `response_data_source`,
`external_inputs`, and a `response_data` alias. `begin_test(header)` validates
hashes and boot address before clearing protocol, memory, and capacity state.
`reset_dut()` / `reset=True` only clear protocol state.

On successful response, first instruction reads repair that response cycle's
instruction payload using its independent selector; first data reads retain raw
response data. Reads return coherent stored bytes; successful writes update only
enabled byte lanes. Error responses do not allocate or mutate memory. The actual
memory address is the aligned beat base, with low address bits ignored and write
lanes determined by byte enables. Capacity keys are `(domain, aligned_base)`.
Full capacity returns `rsp_error=True`, `rsp_data=0`, source `capacity_error`, with
no eviction. This structural error is independent of random-error enablement.

## RED evidence

The brief's `python` executable is absent; `python3` requires `PYTHONPATH=src` in
this checkout. The effective focused command throughout was:

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py -q
```

Before production files existed: exit 2, two expected missing-module collection
errors (`myfuzz.composition.protocol_transducer` and
`myfuzz.composition.contract_transducer`). Initial implementation: 40 passed.

Capacity/alignment tests were then added before those behaviors: exit 1,
8 failed and 40 passed. Failures were unsupported `memory_capacity_entries`
and non-aligned 64-bit reads. After implementation: 48 passed.

## GREEN evidence

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/composition/test_coherent_memory.py tests/isa/test_instruction_transducer.py -q
git diff --check
git diff --cached --check
```

Final regression: **106 passed in 0.31s**, exit 0. Both diff checks exited 0.

## Self-review and concerns

- Checked no response precedes acceptance, pending requests cannot be replaced,
  both stall phases terminate within the configured bound, and reset cancels
  protocol state without clearing in-test memory.
- Checked response-cycle provenance, instruction/data domain sharing and
  isolation, byte writes, errors without mutation, replay determinism,
  selector independence, canonical hashes, and bounded memory without eviction.
- Imports are lazy at the ISA/composition boundary to avoid circular public
  package initialization. No source-name matching or CPU-specific branches exist.
- Current beat widths are explicitly 32 or 64 bits. Instruction initialization
  emits a 32-bit repaired instruction; for a 64-bit beat, upper bytes preserve
  raw response data. Compressed instruction selection is not exposed by this
  cycle layout, although the ISA contract can permit C.
- The caller schedules fixed header reset/execution cycles; the reference step
  does not autonomously count or inject resets. RTL rendering and Python/RTL
  equivalence are Task 6 work, not claimed by these Python tests.

## Approved review fixes: provenance, complete beats, and header versions

Status: COMPLETE

Fix implementation commit: `b124c1445f5a2d1d25eeca32dc0f12ce33e05063`

This section supersedes the initial report's data-to-instruction cache behavior,
instruction-slot limitation, and cycle-field descriptions. Changes were limited
to `contract_transducer.py`, `cycle_input.py`, their two test modules, and this
report. Existing user changes to `task-2-report.md` were preserved untouched.

Each allocated beat now tracks read-only exposed provenance:
`instruction_generated`, `data_generated`, or `cpu_written`. A fetch of a
data-generated beat completes with protocol error and zero data, regardless of
random-error injection settings. It does not alter cached memory. Successful
CPU byte writes mark the beat CPU-written; subsequent fetches preserve the CPU's
actual bytes, including self-modifying code. Existing instruction-generated
beats remain coherent across instruction/data reads. Test begin clears provenance;
DUT reset preserves it. Writes with no enabled bytes do not change provenance
or consume capacity. Partial CPU writes to absent beats preserve written lanes;
the first subsequent read initializes only missing bytes from raw response data.

Generated instruction beats are now complete: base mode independently repairs
every 32-bit slot; compressed mode independently repairs every 16-bit slot.
There is no mixed-slot mode or instruction crossing the end of a generated beat.
With C and alignment 2, `instruction_compressed` is a dedicated RFuzz mode bit.
A first fetch at address modulo 4 equal to 2 forces compressed mode, so a
halfword-aligned boot such as `0x82` starts at an instruction boundary. Cached
beats remain byte-identical on repeated fetches. Without compressed capability,
the mode bit is absent and all slots are 32 bits. Explicit illegal-instruction
test mode remains supported through the existing header flag.

`instruction_payload` now spans the full data width. `instruction_selector`
selects slot zero; `instruction_selector_1` through the required final index
select subsequent slots independently. Selector count is data width divided by
16 when compressed operation is supported, otherwise data width divided by 32.
Each selector is eight independent bits. Payload bits are partitioned into
nonoverlapping slots of the selected width. All fields, addressing/slot/provenance
policies, and the supported header version enter the canonical plan/hash.
External fields remain separate and sorted.

`cycle_input.TEST_HEADER_SCHEMA_VERSION` is the single supported value,
`cycle_test.v1`. Both `TestHeader` construction and `ContractRuntime.begin_test`
enforce it. The latter rechecks even a manually tampered frozen header before
clearing any test state.

### Additional RED evidence

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_cycle_input.py -q
```

Before implementation: **26 failed, 58 passed**. Failures showed unguarded
data-generated instruction fetches, illegal upper 64-bit instruction slots,
missing independent slot selectors/compressed mode, and unsupported header
versions being accepted. After the fixes: **84 passed**.

Self-review added a zero-byte-enable write regression before changing allocation:

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_contract_transducer.py -q --tb=short
```

RED: **1 failed, 56 passed**; an empty write incorrectly exhausted a one-entry
store. The fix makes empty writes complete without allocation or mutation.

### Final GREEN evidence and self-review

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/composition/test_coherent_memory.py tests/isa/test_instruction_transducer.py -q
git diff --check
git diff --cached --check
```

Final result: **135 passed in 0.30s**, including the original 106 regression cases
with approved changed assertions and 29 additional cases. Both diff checks passed.

Self-review checked every generated 16/32-bit slot with the ISA provider across
32/64-bit beats, C/non-C contracts, independent selectors and payload slices,
both raw compressed mode values at boot `0x82`, cache repetition, data conflict
without mutation, CPU full/partial writes, reset/begin-test provenance lifetime,
and header rejection without clearing prior contents. Existing protocol timing,
bounded waiting, capacity, domain, and error regressions remain green.

Remaining boundary: a cached beat is returned verbatim; the model does not
reinterpret arbitrary later CPU control flow into the middle of an existing
32-bit instruction. CPU-written contents and explicitly requested illegal
instruction tests intentionally bypass the generated-legal-content guarantee.
RTL rendering/equivalence remains Task 6 work. No unresolved Task 5 review issue.

## Follow-up: architectural halfword boot with aligned bus requests

Status: COMPLETE

Implementation commit: `5d7adbad5896f82f8dab0e080a36ed547c080fcf`

The previous halfword check used the normalized request address alone. A DUT
can clear its low address bits before issuing the fetch, losing the architectural
boot offset. The runtime now also uses its saved test header: on first instruction
generation, if the aligned requested beat contains `header.boot_address` and
that boot address is 2 modulo 4, the entire beat uses compressed slots. Thus
boot `0x82` and bus request `0x80` are handled correctly with raw mode bit zero.
The plan's hash-bound addressing policy explicitly names both request and boot
entry offsets.

`begin_test` already saves the validated header, and DUT reset retains it. The
new tests verify that lifetime and verify a later test with boot `0x80` returns
to raw-selected base mode. Beats not containing the boot address still obey the
raw mode selector. Cached repeated reads are unchanged.

RED command:

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_contract_transducer.py -q --tb=short
```

Before the fix: **2 failed, 58 passed**. Both 32-bit and 64-bit beats failed
per-halfword ISA validation for boot `0x82`, request `0x80`, raw mode zero.

GREEN command:

```sh
PYTHONPATH=src python3 -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/composition/test_coherent_memory.py tests/isa/test_instruction_transducer.py -q
git diff --check
git diff --cached --check
```

Result: **138 passed in 0.30s**, including the original 135 cases and three new
cases. Both diff checks passed. Self-review confirms the saved boot offset is
used only during first instruction generation, preserved through DUT reset,
replaced at test begin, and scoped to the matching aligned beat. No CPU-name
conditionals were introduced. Only the Task 5 runtime/test and this report changed;
user task-2-report and third-party files were untouched. No unresolved follow-up
issue; RTL equivalence remains separate Task 6 work.
