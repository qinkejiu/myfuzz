"""Shared protocol width-expression compilation semantics."""

from __future__ import annotations

import ast
from collections.abc import Mapping


class ProtocolWidthError(ValueError):
    """Raised when a protocol width expression cannot be compiled."""


def width_parameters(parameters: Mapping[str, object]) -> dict[str, int]:
    """Require the positive integer parameter domain used by protocol widths."""
    names: dict[str, int] = {}
    for name, value in parameters.items():
        if (
            not isinstance(name, str)
            or not name
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
        ):
            raise ProtocolWidthError(
                "width parameters must be positive integer declarations"
            )
        names[name] = value
    return names


def compile_width_expression(
    expression: str,
    parameters: Mapping[str, object],
) -> int:
    """Evaluate one bounded arithmetic width expression deterministically."""
    if not isinstance(expression, str) or not expression:
        raise ProtocolWidthError("width expression must be a non-empty string")
    names = width_parameters(parameters)
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError as error:
        raise ProtocolWidthError(f"invalid width expression: {expression}") from error

    def evaluate(current: ast.AST) -> int:
        if (
            isinstance(current, ast.Constant)
            and isinstance(current.value, int)
            and not isinstance(current.value, bool)
        ):
            return current.value
        if isinstance(current, ast.Name) and current.id in names:
            return names[current.id]
        if isinstance(current, ast.BinOp) and isinstance(
            current.op,
            (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Div),
        ):
            left, right = evaluate(current.left), evaluate(current.right)
            if isinstance(current.op, ast.Add):
                return left + right
            if isinstance(current.op, ast.Sub):
                return left - right
            if isinstance(current.op, ast.Mult):
                return left * right
            if right == 0 or left % right:
                raise ProtocolWidthError(
                    f"non-integral width expression: {expression}"
                )
            return left // right
        raise ProtocolWidthError(f"unsupported width expression: {expression}")

    result = evaluate(node)
    if result <= 0:
        raise ProtocolWidthError(
            f"width expression is not positive: {expression}"
        )
    return result


__all__ = [
    "ProtocolWidthError",
    "compile_width_expression",
    "width_parameters",
]
