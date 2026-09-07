"""Compile explicit endpoint bindings against declared protocol plugins."""

from __future__ import annotations

import ast
from collections.abc import Mapping

from .catalog import ProtocolCatalog
from .model import CompiledField, CompiledProtocol, ProtocolDefinitionError


class ProtocolCompilationError(ProtocolDefinitionError):
    """Raised when a binding cannot satisfy a declared protocol plugin."""


def _width(expression: str, parameters: Mapping[str, object]) -> int:
    names: dict[str, int] = {}
    for name, value in parameters.items():
        if not isinstance(name, str) or isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ProtocolCompilationError("width parameters must be positive integer declarations")
        names[name] = value
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError as error:
        raise ProtocolCompilationError(f"invalid width expression: {expression}") from error

    def evaluate(current: ast.AST) -> int:
        if isinstance(current, ast.Constant) and isinstance(current.value, int) and not isinstance(current.value, bool):
            return current.value
        if isinstance(current, ast.Name) and current.id in names:
            return names[current.id]
        if isinstance(current, ast.BinOp) and isinstance(current.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Div)):
            left, right = evaluate(current.left), evaluate(current.right)
            if isinstance(current.op, ast.Add):
                return left + right
            if isinstance(current.op, ast.Sub):
                return left - right
            if isinstance(current.op, ast.Mult):
                return left * right
            if right == 0 or left % right:
                raise ProtocolCompilationError(f"non-integral width expression: {expression}")
            return left // right
        raise ProtocolCompilationError(f"unsupported width expression: {expression}")

    result = evaluate(node)
    if result <= 0:
        raise ProtocolCompilationError(f"width expression is not positive: {expression}")
    return result


def compile_protocol(
    binding: object,
    facts: object,
    catalog: ProtocolCatalog,
    *,
    require_runtime: bool = False,
) -> CompiledProtocol:
    if not isinstance(binding, Mapping):
        raise ProtocolCompilationError("binding must be an object")
    binding_id = binding.get("binding_id")
    protocol_id, version = binding.get("protocol_id"), binding.get("version")
    ports, parameters = binding.get("ports"), binding.get("parameters", {})
    if not isinstance(binding_id, str) or not binding_id:
        raise ProtocolCompilationError("binding_id must be a non-empty string")
    if not isinstance(protocol_id, str) or not isinstance(version, str):
        raise ProtocolCompilationError("protocol_id and version must be strings")
    if not isinstance(ports, Mapping) or not isinstance(parameters, Mapping):
        raise ProtocolCompilationError("ports and parameters must be objects")
    try:
        plugin = catalog.require(protocol_id, version)
    except ProtocolDefinitionError as error:
        raise ProtocolCompilationError(str(error)) from error
    for field in plugin.fields:
        required = field.required or (require_runtime and field.runtime_required)
        if required and (not isinstance(ports.get(field.field_id), str) or not ports[field.field_id]):
            raise ProtocolCompilationError(f"missing declared port binding for field: {field.field_id}")
    if not isinstance(facts, Mapping) or not isinstance(facts.get("port_widths"), Mapping):
        raise ProtocolCompilationError("facts.port_widths must be an object")
    compiled: list[CompiledField] = []
    widths = facts["port_widths"]
    for field in plugin.fields:
        port_id = ports.get(field.field_id)
        if not isinstance(port_id, str) or not port_id:
            continue
        actual_width = widths.get(port_id)
        if isinstance(actual_width, bool) or not isinstance(actual_width, int) or actual_width <= 0:
            raise ProtocolCompilationError(f"missing positive width fact for port ID: {port_id}")
        expected_width = _width(field.width_expression, parameters)
        if expected_width != actual_width:
            raise ProtocolCompilationError(f"width mismatch for field {field.field_id}: declared {expected_width}, fact {actual_width}")
        role = field.semantic_role
        # Compatibility for existing declarative plugins: recognize the arithmetic
        # byte-lane expression structurally, never an arbitrary same-width signal.
        expression = ast.parse(field.width_expression, mode="eval").body
        if role is None and isinstance(expression, ast.BinOp) and isinstance(expression.op, (ast.Div, ast.FloorDiv)):
            if isinstance(expression.left, ast.Name) and expression.left.id == "data_width" and isinstance(expression.right, ast.Constant) and expression.right.value == 8:
                role = "byte_enable"
        if role == "byte_enable":
            data_width = parameters.get("data_width")
            if not isinstance(data_width, int) or data_width % 8 or actual_width != data_width // 8:
                raise ProtocolCompilationError("byte-enable semantic role requires data_width / 8 lanes")
        compiled.append(CompiledField(field.field_id, field.direction, actual_width, port_id, field.reset_value, role))
    return CompiledProtocol(binding_id, protocol_id, version, tuple(compiled), plugin.channel_relations, plugin.capability_limits)


def compile_runtime_protocol(
    binding: object,
    facts: object,
    catalog: ProtocolCatalog,
) -> CompiledProtocol:
    return compile_protocol(binding, facts, catalog, require_runtime=True)


def protocol_input_fields(compiled: CompiledProtocol) -> tuple[CompiledField, ...]:
    return tuple(field for field in compiled.fields if field.direction == "host_to_device")
