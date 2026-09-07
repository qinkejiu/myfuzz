# Task 4 independent-review fix report

## Scope

This commit resolves the Task 4 Critical/Important review findings only.  It
does not modify the pre-existing `.superpowers/sdd/task-2-report.md` edit or
the untracked `third_party/` tree.  No Task 5 path is changed.

## RED evidence

After adding the regression coverage for real `interface_annotations.v1`
endpoints, constraint closure, raw-ABI geometry, unknown ISA extensions, and
I/M/C reserved encodings, ran:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints -v
```

Result: exit 1.  The new layout API-export test failed because
`myfuzz.composition` did not export `InputLayoutError`; `IsaContract` rejected
`Zba`; RV32 accepted `LWU`; and compressed `0x0000` was accepted merely from
its low two bits.  This demonstrated the reported gaps before implementation.

## GREEN evidence

Implemented source-bound layout fields and normalization, including the exact
`port`, `direction`, and `signed` binding facts.  Layout documents retain
source provenance, while the canonical layout hash deliberately omits source
file/line/column values.  A consistent APB protocol candidate supplies the
default four-byte address alignment.  Byte-enable width is checked against the
same endpoint's data width.

Component constraints now accept only `owner`/`endpoint_id`, `role`, `range`,
`alignment`, `dependency_group`, and `gated_by`.  They reject unknown keys,
unknown target fields, unbounded/non-integral/out-of-width ranges, unaligned
range boundaries, dangling dependency groups, invalid gate references, and
self-gated `valid`.  `ready` is gated by its endpoint's `valid` when both are
present.  The legacy `owner`/`role` record shape remains accepted.

The ISA provider now accepts unknown or unimplemented extension names as
raw-only contracts; it validates only I/M/C-only contracts.  It decodes
XLEN-specific loads/stores, OP/OP-IMM forms, SYSTEM/CSR, FENCE, and compressed
quadrants/reserved register and immediate combinations.  Compressed validation
requires `instruction_alignment == 2`.

GREEN command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints -v
```

Result: exit 0, 15 tests passed.

## Final Task 4 focused/harness/regression verification

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints tests.harness.test_compiler tests.harness.test_projection -v
```

Result: exit 0, 41 tests passed.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_source_crawler tests.contracts.test_interface_contracts -v
```

Result: exit 0, 45 tests passed.

```text
git diff --check
```

Result: exit 0 with no output.

An exploratory full composition/ISA discovery run was not used as a Task 4
gate: five pre-existing catalog/auto tests assert that the Ibex upstream source
is absent, but the user-owned untracked `third_party/` tree makes it present.
Those failures are outside this fix and no files there were changed.

## Changed files

- `src/myfuzz/composition/input_layout.py`
- `src/myfuzz/composition/__init__.py`
- `src/myfuzz/isa/constraints.py`
- `tests/composition/test_input_layout.py`
- `tests/isa/test_instruction_constraints.py`
- `.superpowers/sdd/task-4-fix-report.md`

## Commit

`fix: close Task 4 independent review findings`
