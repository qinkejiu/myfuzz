# Task 4 second-review fix report

## Scope

This change resolves only the two Task 4 Important findings from the second
review.  It does not modify any Task 5 path, the pre-existing
`.superpowers/sdd/task-2-report.md` edit, or the untracked `third_party/`
tree.

## RED

Added regression coverage before production changes for:

- RV64 OP-32 legal ADDW/SUBW/SLLW/SRLW/SRAW/MULW encodings and the reviewer
  reproductions `(2 << 12) | 0x3b` and `(1 << 25) | (1 << 12) | 0x3b`.
- Retaining a field's `evidence` in the layout document and making a change
  to evidence kinds change the canonical layout hash.  The existing
  path/line/column provenance regression remains and verifies that source
  relocation does not change that hash.

Command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout.InputLayoutTest.test_real_annotation_endpoint_preserves_binding_and_path_independent_hash tests.composition.test_input_layout.InputLayoutTest.test_field_evidence_is_preserved_and_changes_canonical_layout_hash tests.isa.test_instruction_constraints.InstructionConstraintsTest.test_rv64_op_32_accepts_only_rv64i_m_word_operation_encodings -v
```

Result: exit 1, three expected assertion failures: missing document evidence,
unchanged hash after evidence changed, and acceptance of `(2 << 12) | 0x3b`.

## GREEN

OP-32 now has a dedicated RV64I/M whitelist: ADDW, SUBW, SLLW, SRLW, SRAW,
and M-gated MULW only.  Generic OP validation and the provider's I/M/C,
XLEN, and raw-only extension behavior remain unchanged.

`LayoutField` retains its existing public fields and adds a trailing,
tuple-normalized `evidence` field.  The field evidence kinds are parsed from
real `interface_annotations.v1` records, retained by
`input_layout_document`, and included in the canonical hash document.
Provenance remains document-only, so source file, line, and column do not
affect the path-independent layout hash.

Focused GREEN command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout.InputLayoutTest.test_real_annotation_endpoint_preserves_binding_and_path_independent_hash tests.composition.test_input_layout.InputLayoutTest.test_field_evidence_is_preserved_and_changes_canonical_layout_hash tests.isa.test_instruction_constraints.InstructionConstraintsTest.test_rv64_op_32_accepts_only_rv64i_m_word_operation_encodings -v
```

Result: exit 0, 3 tests passed.

## Final verification

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints -v
```

Result: exit 0, 17 tests passed.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints tests.harness.test_compiler tests.harness.test_projection -v
```

Result: exit 0, 43 tests passed.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_source_crawler tests.contracts.test_interface_contracts -v
```

Result: exit 0, 45 tests passed.
