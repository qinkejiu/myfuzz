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
