from __future__ import annotations

import pytest

from myfuzz.composition.constraint_ir import (
    ConstraintIrError,
    ConstraintProgram,
    Expr,
    bit_and,
    bit_not,
    bit_or,
    concat,
    const,
    equal,
    evaluate,
    mux,
    ref,
    select_balanced,
    slice_bits,
)


def test_mux_and_boolean_nodes_preserve_width() -> None:
    expr = mux(ref("s", 1), ref("a", 4), ref("b", 4))
    assert evaluate(expr, {"s": 1, "a": 0xA, "b": 0x3}) == 0xA
    assert evaluate(expr, {"s": 0, "a": 0xA, "b": 0x3}) == 0x3
    assert bit_and(ref("a", 4), const(4, 0xF)).width == 4
    assert bit_or(ref("a", 4), const(4, 0)).width == 4
    assert bit_not(ref("a", 4)).width == 4


def test_balanced_selection_differs_by_at_most_one_preimage() -> None:
    counts = [0] * 5
    for raw in range(256):
        counts[select_balanced(raw, 8, tuple(range(5)))] += 1
    assert max(counts) - min(counts) <= 1


def test_balanced_selection_allows_more_choices_than_raw_domain() -> None:
    choices = (0, 1, 2)
    counts = [0] * len(choices)
    for raw in range(1 << 1):
        counts[select_balanced(raw, 1, choices)] += 1
    assert max(counts) - min(counts) <= 1
    assert [select_balanced(raw, 1, choices) for raw in range(2)] == [0, 1]


def test_width_mismatch_and_cycle_fail_closed() -> None:
    with pytest.raises(ConstraintIrError, match="width"):
        bit_and(ref("a", 2), ref("b", 3))
    with pytest.raises(ConstraintIrError, match="width"):
        mux(ref("s", 2), ref("a", 4), ref("b", 4))
    cyclic = Expr("mux", 1, (ref("s", 1), const(1, 0), const(1, 0)))
    object.__setattr__(cyclic, "args", (ref("s", 1), cyclic, const(1, 0)))
    with pytest.raises(ConstraintIrError, match="cycle"):
        evaluate(cyclic, {"s": 1})


def test_nodes_validate_widths_and_values() -> None:
    with pytest.raises(ConstraintIrError, match="width"):
        const(0, 0)
    with pytest.raises(ConstraintIrError, match="value"):
        const(3, 8)
    with pytest.raises(ConstraintIrError, match="width"):
        equal(ref("a", 2), ref("b", 3))
    with pytest.raises(ConstraintIrError, match="slice"):
        slice_bits(ref("a", 4), 2, 3)
    with pytest.raises(ConstraintIrError, match="concat"):
        concat(())


def test_slice_concat_equal_and_masking_are_deterministic() -> None:
    source = ref("source", 8)
    expr = concat((slice_bits(source, 7, 4), slice_bits(source, 3, 0)))
    assert expr.width == 8
    assert evaluate(expr, {"source": 0x1AB}) == 0xAB
    assert evaluate(bit_not(ref("source", 4)), {"source": 0x1F}) == 0
    assert evaluate(equal(ref("left", 4), ref("right", 4)), {"left": 0xF, "right": 0x1F}) == 1


def test_program_validates_dag_and_emits_canonical_document() -> None:
    output = bit_and(ref("a", 4), const(4, 0xF))
    program = ConstraintProgram((
        ("result", output),
        ("same", equal(output, output)),
    ))
    assert program.validate() is None
    document = program.document()
    assert document == {
        "schema_version": "constraint_ir.v1",
        "outputs": [{"name": "result", "expr": 0}, {"name": "same", "expr": 3}],
        "nodes": [
            {"id": 0, "op": "and", "width": 4, "args": [1, 2]},
            {"id": 1, "op": "ref", "width": 4, "name": "a"},
            {"id": 2, "op": "const", "width": 4, "value": 15},
            {"id": 3, "op": "eq", "width": 1, "args": [0, 0]},
        ],
    }
    assert program.canonical_document() == document


def test_program_rejects_duplicate_outputs_and_unknown_inputs() -> None:
    with pytest.raises(ConstraintIrError, match="output"):
        ConstraintProgram((("x", ref("a", 1)), ("x", ref("b", 1)))).validate()
    with pytest.raises(ConstraintIrError, match="input"):
        evaluate(ref("a", 2), {})
    assert evaluate(ref("a", 2), {"a": 4}) == 0


def test_program_rejects_same_ref_name_with_different_width_within_expression() -> None:
    expression = concat((ref("shared", 1), ref("shared", 2)))
    with pytest.raises(ConstraintIrError, match="ref.*width"):
        ConstraintProgram((("result", expression),)).validate()


def test_program_rejects_same_ref_name_with_different_width_across_outputs() -> None:
    program = ConstraintProgram((("one", ref("shared", 1)), ("two", ref("shared", 2))))
    with pytest.raises(ConstraintIrError, match="ref.*width"):
        program.validate()


def test_selection_rejects_invalid_domain_and_preserves_choice_identity() -> None:
    with pytest.raises(ConstraintIrError, match="selection"):
        select_balanced(0, 0, (1,))
    with pytest.raises(ConstraintIrError, match="selection"):
        select_balanced(-1, 8, (1,))
    with pytest.raises(ConstraintIrError, match="selection"):
        select_balanced(0, 8, ())
    assert select_balanced(255, 8, ("a", "b", "c")) == "c"
