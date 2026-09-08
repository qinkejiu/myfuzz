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

   Failed with `instruction template produced an illegal word: C.ANDI`; bit 12
   is now fixed because the existing provider treats that combination as
   reserved.

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

- The current provider rejects the negative-immediate (`bit 12 = 1`) C.ANDI
  space, so the transducer conservatively fixes that bit to zero. Correcting the
  provider later would recover one additional RFuzz payload bit.
- `RuntimeProjector` has no dedicated selector field in its legacy layout, so it
  derives the selector from the instruction field's high eight bits. The later
  whole-contract transducer should consume the dedicated selector field defined
  by the cycle layout instead of reusing payload bits.
