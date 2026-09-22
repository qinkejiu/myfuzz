"""Shared protocol width-expression compilation semantics."""

from __future__ import annotations

import ast
from collections.abc import Mapping


#: Width names a bundled plugin may use that are not the two the composition
#: layer passes in (``address_width``/``data_width``).  They are the TL-UL
#: parameter set of the pinned OpenTitan top package and of the bundled adapter,
#: which declare the same values: top_pkg.sv fixes TL_SZW=2, TL_AIW=8, TL_DIW=1
#: and TL_AUW=23, tlul_pkg's tl_d2h_t carries a 14-bit user field, and
#: src/myfuzz/protocols/rtl/beat_to_tlul.sv defaults SIZE_WIDTH=2,
#: SOURCE_WIDTH=8, SINK_WIDTH=1, USER_WIDTH=23 and DUSER_WIDTH=14.  A caller's
#: own parameters always win over these defaults.
PROTOCOL_WIDTH_PARAMETER_DEFAULTS: dict[str, int] = {
    "size_width": 2,
    "source_width": 8,
    "sink_width": 1,
    "user_width": 23,
    "d_user_width": 14,
}


class ProtocolWidthError(ValueError):
    """Raised when a protocol width expression cannot be compiled."""


def width_parameters(parameters: Mapping[str, object], *,
                     defaults: Mapping[str, int] | None = None) -> dict[str, int]:
    """Require the positive integer parameter domain used by protocol widths.

    ``defaults`` are the plugin-declared width names a binding need not repeat;
    a name supplied by the caller always overrides its default.
    """
    names: dict[str, int] = dict(PROTOCOL_WIDTH_PARAMETER_DEFAULTS
                                 if defaults is None else defaults)
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
    *,
    defaults: Mapping[str, int] | None = None,
) -> int:
    """Evaluate one bounded arithmetic width expression deterministically."""
    if not isinstance(expression, str) or not expression:
        raise ProtocolWidthError("width expression must be a non-empty string")
    names = width_parameters(parameters, defaults=defaults)
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
    "PROTOCOL_WIDTH_PARAMETER_DEFAULTS",
    "ProtocolWidthError",
    "compile_width_expression",
    "width_parameters",
]
