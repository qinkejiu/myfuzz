# Task 4 third-review fix report

## Scope

This fix resolves the remaining Task 4 OP-32 RV64M review finding only. It
changes `src/myfuzz/isa/constraints.py` and
`tests/isa/test_instruction_constraints.py`, plus this report. No Task 5 path
or pre-existing user change is included.

## Root cause and RED evidence

The dedicated OP-32 branch correctly separated RV64 from RV32 and whitelisted
the five RV64I word operations, but its `funct7 == 1` condition recognized
only `funct3 == 0` (MULW). It omitted DIVW, DIVUW, REMW, and REMUW.

Added a new regression matrix before changing production code. It covers
ADDW/SUBW/SLLW/SRLW/SRAW, MULW/DIVW/DIVUW/REMW/REMUW, reserved `funct3` values
1/2/3 for `funct7 == 1`, non-M rejection, and RV32 rejection of OP-32.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.isa.test_instruction_constraints.InstructionConstraintsTest.test_rv64m_op_32_accepts_all_word_arithmetic_encodings_and_rejects_reserved -v
```

Result: exit 1, with the expected four failures for DIVW, DIVUW, REMW, and
REMUW. MULW, retained RV64I cases, reserved encodings, and RV32 behavior did
not fail.

## Fix

For opcode `0x3b` and `funct7 == 1`, the RV64M whitelist now accepts exactly
`funct3` 0, 4, 5, 6, and 7 when M is present. Values 1, 2, and 3 remain
illegal. Existing raw-only unknown-extension fallback and all prior tests are
unchanged.

## GREEN and required verification

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.isa.test_instruction_constraints.InstructionConstraintsTest.test_rv64m_op_32_accepts_all_word_arithmetic_encodings_and_rejects_reserved -v
```

Result: exit 0, 1 test passed.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints -v
```

Result: exit 0, 18 tests passed.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints tests.harness.test_compiler tests.harness.test_projection -v
```

Result: exit 0, 44 tests passed.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_source_crawler tests.contracts.test_interface_contracts -v
```

Result: exit 0, 45 tests passed.

`git diff --check` completed with exit 0 and no output.
