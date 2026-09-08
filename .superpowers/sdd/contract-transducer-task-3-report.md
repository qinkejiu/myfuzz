# Task 3 Report: ISA Operation Selection and Minimal Repair

## Status

Complete. The fixed architectural-NOP fallback is replaced by deterministic,
ISA-capability-filtered operation selection followed by minimal fixed-bit and
reserved-combination repair.

## Commit

- Commit subject: `feat: minimally repair RFuzz instructions by ISA`
- This report is included in the same Task 3 commit.

## Scope

- Added immutable `InstructionTemplate` and `InstructionChoice` records.
- Added `RiscvInstructionTransducer` with balanced 8-bit operation selection,
  explicit opt-in illegal output, and `repair_for_operation`.
- Covered every RV32 I/M/C operation form accepted by the existing provider;
  the table also follows the provider's existing RV64 I/M/C capability surface.
- Replaced `RuntimeProjector`'s illegal-to-NOP convergence with high-byte
  selector plus full-field payload repair.
- Exported the new ISA API from `myfuzz.isa`.
- Preserved raw-only operation for contracts containing unimplemented ISA
  extensions.

## RED evidence

The requested `python` executable is absent in this environment, so all valid
test evidence uses `PYTHONPATH=src python3`.

1. Initial API test:

   `PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py -q`

   Collection failed with `ImportError: cannot import name
   'RiscvInstructionTransducer' from 'myfuzz.isa'`, confirming the API did not
   exist.

2. Raw-only compatibility regression:

   `PYTHONPATH=src python3 -m pytest tests/composition/test_runtime_projection.py::RuntimeProjectionTests::test_raw_instruction_mode_accepts_an_unimplemented_isa_contract -q`

   Failed because eager transducer construction rejected the raw-only `I+A`
   contract. Construction is now conditional on implemented legal validation.

3. Compressed reserved-combination regression:

   `PYTHONPATH=src python3 -m pytest 'tests/isa/test_instruction_transducer.py::test_compressed_reserved_encodings_are_minimally_repaired[C.ANDI-65535]' -q`

   Failed with `instruction template produced an illegal word: C.ANDI`. In the
   initial Task 3 commit, bit 12 was fixed for both XLENs to satisfy the existing
   provider. That initial state is superseded below: final RV64 generation
   preserves legal bit 12, while RV32 remains restricted by the current provider.

## GREEN evidence

- Focused Task 3 and legacy legality suite:

  `PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py tests/isa/test_instruction_constraints.py tests/composition/test_runtime_projection.py -q`

  Result: `46 passed, 43 subtests passed`.

- Independent template-matrix audit exercised payloads `0`, all ones, and
  `0xA5A55A5A` for every template, checked provider legality, and checked every
  reported free bit against its raw payload:

  - RV32IMC: 82 templates (56 base, 26 compressed).
  - RV64IMC: 105 templates (73 base, 32 compressed).

- `git diff --check` completed without whitespace errors.

## Self-review

- Capability filtering excludes M and C forms unless their contract capability
  and compressed alignment requirements are present.
- Selector enumeration covers all 256 selector values and produces diverse,
  legal operations by default.
- `free_mask` removes both statically fixed bits and the exact conditional bit
  used to escape a reserved encoding; tests confirm all reported free bits are
  unchanged.
- The explicit illegal category is absent from default choices and is reachable
  only when `illegal=True`.
- Existing dirty files under `third_party/` and
  `.superpowers/sdd/task-2-report.md` were not modified.

## Concerns

- In the initial Task 3 commit, the transducer conservatively fixed `C.ANDI`
  bit 12 for both XLENs because of the provider's accepted subset. The Fix Review
  below records the final behavior: RV64 preserves legal bit 12; only RV32 keeps
  the provider-required restriction.
- `RuntimeProjector` has no dedicated selector field in its legacy layout, so it
  derives the selector from the instruction field's high eight bits. The later
  whole-contract transducer should consume the dedicated selector field defined
  by the cycle layout instead of reusing payload bits.

## Fix Review

### Status and commit

- All review Important findings are fixed.
- Code/test fix commit:
  `3115f8d3a35db8058e9f0d2a0e75ac2f6b89e3ce`
  (`fix: preserve compressed entropy and illegal width`).

### RED evidence

After adding the reviewer-provided RV64C examples, a complete compressed
same-operation fixed-point audit, and the C-aware illegal-category regression:

`PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py -q`

failed as expected with `6 failed, 21 passed`:

- `C.SRLI` changed `0x9001` to `0x8005`;
- `C.SRAI` changed `0x9401` to `0x8405`;
- `C.ANDI` changed `0x9805` to `0x8805`;
- the RV64 full-space fixed-point audit failed at `C.SRLI`;
- both I-only and IC illegal-category cases had low bits `00`, not `11`.

### GREEN evidence

Required review suite:

`PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py tests/isa/test_instruction_constraints.py tests/composition/test_runtime_projection.py -q`

Result: `53 passed, 43 subtests passed in 0.28s`.

An additional exhaustive audit enumerated all 65,536 payloads for every
compressed template and checked provider legality plus reported-free-bit
preservation:

- RV32: all 26 compressed templates passed;
- RV64: all 32 compressed templates passed.

### Self-review

- RV64 `C.SRLI`, `C.SRAI`, and `C.ANDI` now leave bit 12 free. RV32 keeps the
  provider-required bit-12 restrictions. `C.ANDI` applies a one-bit conditional
  repair only when the provider would otherwise reject the generated RV64 word.
- Every provider-accepted compressed word that independently decodes to a
  selected operation is now a fixed point of `repair_for_operation`, for both
  RV32 and RV64 and for every exposed compressed template.
- The explicit illegal category always emits a 32-bit-length word using reserved
  major opcode `0x4B`; `InstructionChoice.legal` is computed by the same provider
  and is false with both I-only and IC contracts.
- Runtime projection now has an explicit repeat-evaluation assertion proving the
  same input produces the same result.
- `git diff --check` passed, and no Task 2 report or `third_party/` content was
  changed.

### Remaining concerns

- The existing provider still rejects RV32 `C.ANDI` with bit 12 set, so RV32
  generation remains conservatively restricted to its accepted subset. RV64
  legal bit-12 inputs are preserved as required.
- RuntimeProjector still derives its legacy selector from the payload high byte;
  the future whole-contract transducer should use the dedicated cycle selector.

## Fix Review: Width-Preserving Illegal Category

### Status and commit

- The remaining review Important is fixed.
- Code/test fix commit:
  `bedcbf008fa337af53482b89c82ff6e076c1bf0d`
  (`fix: preserve explicit illegal instruction width`).

### RED evidence

After adding RV32IC cases for payloads `0xffff` and `0x1234ffff`:

`PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py -q`

failed as expected with `2 failed, 27 passed`. Both failures reported
`InstructionChoice.width == 32` where the requested width was 16, proving the
illegal branch silently widened compressed requests.

### GREEN evidence

Focused transducer suite:

`PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py -q`

Result: `29 passed in 0.24s`.

Required complete review suite:

`PYTHONPATH=src python3 -m pytest tests/isa/test_instruction_transducer.py tests/isa/test_instruction_constraints.py tests/composition/test_runtime_projection.py -q`

Result: `55 passed, 43 subtests passed in 0.26s`.

### Self-review

- A selected 16-bit illegal category now returns a 16-bit choice and truncates
  oversized payloads before construction.
- Its encoding fixes compressed funct3/quadrant and all `C.ADDI4SPN` nzuimm bits
  to zero, retains only `rd'` bits `[4:2]`, and is therefore deterministically
  rejected by the compressed provider for every retained value.
- The 32-bit illegal path is unchanged: it keeps 32-bit instruction length and
  reserved major opcode `0x4B`.
- Both illegal widths compute `choice.legal` through the corresponding provider
  path, and tests assert the result is false.
- The earlier `C.ANDI` narrative now explicitly distinguishes the initial
  conservative state from the final XLEN-specific behavior.
- `git diff --check` passed; the Task 2 report and `third_party/` remain untouched.

### Remaining concerns

- The existing provider continues to restrict RV32 `C.ANDI` bit 12; RV64 legal
  bit-12 inputs remain preserved.
- RuntimeProjector still derives its legacy selector from the payload high byte;
  a later whole-contract transducer should consume the dedicated selector field.
