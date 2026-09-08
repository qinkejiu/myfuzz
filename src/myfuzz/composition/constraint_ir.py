"""Small, typed expression language for contract-derived input constraints.

The constructors in this module are deliberately strict.  An :class:`Expr`
is a bit-vector node, and every operation has one unambiguous result width.
Programs are immutable DAGs; validation is repeated at the serialization and
evaluation boundaries so malformed hand-built nodes fail closed as well.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class ConstraintIrError(ValueError):
    """Raised when a constraint expression or program is not well formed."""


@dataclass(frozen=True, slots=True)
class Expr:
    """An immutable bit-vector expression node.

    ``args`` contains child :class:`Expr` objects for normal operators.  The
    leaf payload for ``const`` and ``ref`` is kept in the same tuple to retain
    one compact immutable representation (and is represented explicitly in
    the canonical document).
    """

    op: str
    width: int
    args: tuple[object, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.op, str) or not self.op:
            raise ConstraintIrError("invalid expression op")
        if type(self.width) is not int or self.width <= 0:
            raise ConstraintIrError("invalid expression width")
        if not isinstance(self.args, tuple):
            object.__setattr__(self, "args", tuple(self.args))


@dataclass(frozen=True, slots=True)
class ConstraintProgram:
    """Named output expressions forming one validated immutable DAG."""

    outputs: tuple[tuple[str, Expr], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", tuple(self.outputs))

    def validate(self) -> None:
        """Validate output names, operators, widths, and acyclicity."""
        names: set[str] = set()
        visiting: set[int] = set()
        visited: set[int] = set()
        for output in self.outputs:
            if not isinstance(output, tuple) or len(output) != 2:
                raise ConstraintIrError("invalid output")
            name, expression = output
            if not isinstance(name, str) or not name:
                raise ConstraintIrError("invalid output name")
            if name in names:
                raise ConstraintIrError("duplicate output name")
            names.add(name)
            _validate_expr(expression, visiting, visited)

    def document(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible document for this program."""
        self.validate()
        node_ids: dict[int, int] = {}
        nodes: list[dict[str, object]] = []

        def encode(expression: Expr) -> int:
            identity = id(expression)
            existing = node_ids.get(identity)
            if existing is not None:
                return existing
            node_id = len(nodes)
            node_ids[identity] = node_id
            # Reserve the id before descending; validation above guarantees
            # this cannot encounter a cycle.
            nodes.append({})
            record: dict[str, object] = {"id": node_id, "op": expression.op, "width": expression.width}
            if expression.op == "const":
                record["value"] = expression.args[0]
            elif expression.op == "ref":
                record["name"] = expression.args[0]
            elif expression.op == "slice":
                record["args"] = [encode(expression.args[0]), expression.args[1], expression.args[2]]
            else:
                record["args"] = [encode(argument) for argument in expression.args]
            nodes[node_id] = record
            return node_id

        outputs = [{"name": name, "expr": encode(expression)} for name, expression in self.outputs]
        return {"schema_version": "constraint_ir.v1", "outputs": outputs, "nodes": nodes}

    def canonical_document(self) -> dict[str, object]:
        """Alias for :meth:`document` used by canonicalization callers."""
        return self.document()


def _validate_expr(expression: object, visiting: set[int], visited: set[int]) -> None:
    if not isinstance(expression, Expr):
        raise ConstraintIrError("invalid expression")
    identity = id(expression)
    if identity in visiting:
        raise ConstraintIrError("expression cycle")
    if identity in visited:
        return
    visiting.add(identity)
    op = expression.op
    width = expression.width
    args = expression.args
    if op == "const":
        if len(args) != 1 or type(args[0]) is not int or not 0 <= args[0] < (1 << width):
            raise ConstraintIrError("invalid const value")
    elif op == "ref":
        if len(args) != 1 or not isinstance(args[0], str) or not args[0]:
            raise ConstraintIrError("invalid ref name")
    elif op in ("and", "or"):
        if len(args) != 2 or not all(isinstance(item, Expr) for item in args):
            raise ConstraintIrError(f"{op} width mismatch")
        left, right = args
        if left.width != right.width or left.width != width:
            raise ConstraintIrError(f"{op} width mismatch")
        _validate_expr(left, visiting, visited)
        _validate_expr(right, visiting, visited)
    elif op == "not":
        if len(args) != 1 or not isinstance(args[0], Expr) or args[0].width != width:
            raise ConstraintIrError("not width mismatch")
        _validate_expr(args[0], visiting, visited)
    elif op == "eq":
        if len(args) != 2 or not all(isinstance(item, Expr) for item in args):
            raise ConstraintIrError("equal width mismatch")
        left, right = args
        if width != 1 or left.width != right.width:
            raise ConstraintIrError("equal width mismatch")
        _validate_expr(left, visiting, visited)
        _validate_expr(right, visiting, visited)
    elif op == "mux":
        if len(args) != 3 or not all(isinstance(item, Expr) for item in args):
            raise ConstraintIrError("mux width mismatch")
        select, when_true, when_false = args
        if select.width != 1 or when_true.width != when_false.width or when_true.width != width:
            raise ConstraintIrError("mux width mismatch")
        _validate_expr(select, visiting, visited)
        _validate_expr(when_true, visiting, visited)
        _validate_expr(when_false, visiting, visited)
    elif op == "slice":
        if len(args) != 3 or not isinstance(args[0], Expr):
            raise ConstraintIrError("slice width mismatch")
        source, hi, lo = args
        if type(lo) is not int or type(hi) is not int or lo < 0 or lo > hi or hi >= source.width:
            raise ConstraintIrError("slice bounds")
        if width != hi - lo + 1:
            raise ConstraintIrError("slice width mismatch")
        _validate_expr(source, visiting, visited)
    elif op == "concat":
        if not args or not all(isinstance(item, Expr) for item in args):
            raise ConstraintIrError("concat width mismatch")
        if width != sum(item.width for item in args):
            raise ConstraintIrError("concat width mismatch")
        for item in args:
            _validate_expr(item, visiting, visited)
    else:
        raise ConstraintIrError(f"unknown expression op: {op}")
    visiting.remove(identity)
    visited.add(identity)


def _expression(value: object, label: str = "expression") -> Expr:
    if not isinstance(value, Expr):
        raise ConstraintIrError(f"{label} required")
    return value


def _width(width: object) -> int:
    if type(width) is not int or width <= 0:
        raise ConstraintIrError("invalid width")
    return width


def const(width: int, value: int) -> Expr:
    width = _width(width)
    if type(value) is not int or not 0 <= value < (1 << width):
        raise ConstraintIrError("invalid const value")
    return Expr("const", width, (value,))


def ref(name: str, width: int) -> Expr:
    width = _width(width)
    if not isinstance(name, str) or not name:
        raise ConstraintIrError("invalid ref name")
    return Expr("ref", width, (name,))


def _binary(op: str, left: Expr, right: Expr) -> Expr:
    left = _expression(left, "left expression")
    right = _expression(right, "right expression")
    if left.width != right.width:
        raise ConstraintIrError(f"{op} width mismatch")
    return Expr(op, left.width, (left, right))


def bit_and(left: Expr, right: Expr) -> Expr:
    return _binary("and", left, right)


def bit_or(left: Expr, right: Expr) -> Expr:
    return _binary("or", left, right)


def bit_not(expression: Expr) -> Expr:
    expression = _expression(expression)
    return Expr("not", expression.width, (expression,))


def equal(left: Expr, right: Expr) -> Expr:
    left = _expression(left, "left expression")
    right = _expression(right, "right expression")
    if left.width != right.width:
        raise ConstraintIrError("equal width mismatch")
    return Expr("eq", 1, (left, right))


def mux(select: Expr, when_true: Expr, when_false: Expr) -> Expr:
    select = _expression(select, "select expression")
    when_true = _expression(when_true, "true expression")
    when_false = _expression(when_false, "false expression")
    if select.width != 1 or when_true.width != when_false.width:
        raise ConstraintIrError("mux width mismatch")
    return Expr("mux", when_true.width, (select, when_true, when_false))


def slice_bits(expression: Expr, hi: int, lo: int) -> Expr:
    expression = _expression(expression)
    if type(lo) is not int or type(hi) is not int or lo < 0 or lo > hi or hi >= expression.width:
        raise ConstraintIrError("slice bounds")
    return Expr("slice", hi - lo + 1, (expression, hi, lo))


def concat(*expressions: Expr | Sequence[Expr]) -> Expr:
    # Accept both concat(a, b) and concat((a, b)); the latter is convenient
    # for dynamically assembled templates.
    if len(expressions) == 1 and isinstance(expressions[0], Sequence) and not isinstance(expressions[0], Expr):
        values = tuple(expressions[0])
    else:
        values = tuple(expressions)
    if not values or not all(isinstance(item, Expr) for item in values):
        raise ConstraintIrError("concat width mismatch")
    return Expr("concat", sum(item.width for item in values), values)


def select_balanced(raw: int, raw_width: int, choices: Sequence[Any]) -> Any:
    """Select a choice with preimage sizes differing by at most one."""
    if (type(raw) is not int or type(raw_width) is not int or raw_width <= 0
            or not 0 <= raw < (1 << raw_width) or not isinstance(choices, Sequence)
            or isinstance(choices, (str, bytes)) or not choices):
        raise ConstraintIrError("invalid selection")
    domain = 1 << raw_width
    if len(choices) > domain:
        raise ConstraintIrError("invalid selection")
    return choices[min(len(choices) - 1, raw * len(choices) // domain)]


def evaluate(expr: Expr | ConstraintProgram, inputs: Mapping[str, int]) -> int | dict[str, int]:
    """Evaluate an expression (or all outputs) with width masking at each node."""
    if not isinstance(inputs, Mapping):
        raise ConstraintIrError("inputs must be a mapping")
    if isinstance(expr, ConstraintProgram):
        expr.validate()
        return {name: _evaluate(expression, inputs, {}, set()) for name, expression in expr.outputs}
    expression = _expression(expr)
    _validate_expr(expression, set(), set())
    return _evaluate(expression, inputs, {}, set())


def _evaluate(expression: Expr, inputs: Mapping[str, int], memo: dict[int, int], visiting: set[int]) -> int:
    identity = id(expression)
    if identity in visiting:
        raise ConstraintIrError("expression cycle")
    if identity in memo:
        return memo[identity]
    visiting.add(identity)
    mask = (1 << expression.width) - 1
    op = expression.op
    args = expression.args
    if op == "const":
        value = args[0]
    elif op == "ref":
        name = args[0]
        if name not in inputs:
            raise ConstraintIrError(f"missing input: {name}")
        value = inputs[name]
        if type(value) is not int:
            raise ConstraintIrError(f"invalid input: {name}")
    elif op == "and":
        value = _evaluate(args[0], inputs, memo, visiting) & _evaluate(args[1], inputs, memo, visiting)
    elif op == "or":
        value = _evaluate(args[0], inputs, memo, visiting) | _evaluate(args[1], inputs, memo, visiting)
    elif op == "not":
        value = ~_evaluate(args[0], inputs, memo, visiting)
    elif op == "eq":
        value = int(_evaluate(args[0], inputs, memo, visiting) == _evaluate(args[1], inputs, memo, visiting))
    elif op == "mux":
        select = _evaluate(args[0], inputs, memo, visiting)
        value = _evaluate(args[1] if select else args[2], inputs, memo, visiting)
    elif op == "slice":
        source = _evaluate(args[0], inputs, memo, visiting)
        value = source >> args[2]
    elif op == "concat":
        value = 0
        for item in args:
            value = (value << item.width) | _evaluate(item, inputs, memo, visiting)
    else:
        raise ConstraintIrError(f"unknown expression op: {op}")
    visiting.remove(identity)
    result = value & mask
    memo[identity] = result
    return result


def constraint_program_document(program: ConstraintProgram) -> dict[str, object]:
    """Return the canonical JSON-compatible document for a program."""
    if not isinstance(program, ConstraintProgram):
        raise ConstraintIrError("program required")
    return program.document()


canonical_document = constraint_program_document


__all__ = [
    "ConstraintIrError", "Expr", "ConstraintProgram", "const", "ref", "bit_and", "bit_or",
    "bit_not", "equal", "mux", "slice_bits", "concat", "select_balanced", "evaluate",
    "constraint_program_document", "canonical_document",
]
