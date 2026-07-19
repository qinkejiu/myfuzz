"""Compose-v5 scheme-A flat top emission."""

from __future__ import annotations

import re
from typing import Mapping

from .flat_shell import EmittedFlatShell
from .input_model import InputValidationError, PortDirection
from .rtl_analysis import EvidenceState, RTLModule, RTLPort


_SV_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SAFE_PARAMETER_LITERAL = re.compile(
    r"-?(?:"
    r"\d[\d_]*"
    r"|"
    r"(?:\d[\d_]*)?'[sS]?[bBoOdDhH][0-9a-fA-F_xXzZ?]+"
    r"|"
    r"'[01xXzZ]"
    r")\Z"
)


def emit_compose_v5_scheme_a_flat_shell(
    component_modules: Mapping[str, RTLModule],
    *,
    module_name: str = "compose_v5_scheme_a_flat_top",
) -> EmittedFlatShell:
    """Instantiate declared components side-by-side and expose every child port.

    This is the scheme-A baseline shape: no planner-generated child-to-child
    nets, no protocol assumptions, and every top-level port is a direct
    qualified mirror of a real RTL child port.
    """

    _identifier(module_name, "compose-v5 scheme-A flat top module name")
    if not isinstance(component_modules, Mapping) or not component_modules:
        raise InputValidationError("compose-v5 scheme-A flat top requires component modules")

    modules = tuple(
        _module(component_id, module)
        for component_id, module in sorted(component_modules.items())
    )
    instances = [module["instance"] for module in modules]
    if len(instances) != len(set(instances)):
        raise InputValidationError("compose-v5 scheme-A flat top instance names must be unique")

    external: list[dict[str, object]] = []
    seen_ports: set[str] = set()
    for module in modules:
        for port in module["ports"]:
            top_port = f"{module['instance']}__{port['name']}"
            if top_port in seen_ports:
                raise InputValidationError(f"duplicate compose-v5 scheme-A top port {top_port}")
            seen_ports.add(top_port)
            direction = port["direction"]
            external.append({
                "name": top_port,
                "instance": module["instance"],
                "child_port": port["name"],
                "direction": direction.value,
                "width": port["width"],
                "fuzz_control": direction is PortDirection.INPUT,
            })

    if not external:
        raise InputValidationError("compose-v5 scheme-A flat top found no ports")

    lines = [
        f"module {module_name} (",
        ",\n".join(
            f" {_direction(PortDirection(port['direction']))} logic "
            f"{_range(int(port['width']))}{port['name']}"
            for port in external
        ),
        ");",
    ]
    for module in modules:
        parameters = module["parameters"]
        if parameters:
            lines.extend((
                f" {module['module_type']} #(",
                ",\n".join(f"  .{name}({value})" for name, value in parameters),
                f" ) {module['instance']} (",
            ))
        else:
            lines.append(f" {module['module_type']} {module['instance']} (")
        lines.append(",\n".join(
            f"  .{port['name']}({module['instance']}__{port['name']})"
            for port in module["ports"]
        ))
        lines.append(" );")
    lines.append("endmodule")

    return EmittedFlatShell(
        module_name=module_name,
        rtl="\n".join(lines) + "\n",
        external_ports=tuple(external),
        instances=tuple(instances),
    )


def _module(component_id: str, module: RTLModule) -> dict[str, object]:
    _identifier(component_id, "compose-v5 scheme-A component id")
    if not isinstance(module, RTLModule):
        raise InputValidationError("compose-v5 scheme-A flat top requires RTLModule values")
    _identifier(module.original_name, f"compose-v5 component {component_id} original module name")
    _identifier(module.name, f"compose-v5 component {component_id} analysis module name")
    if module.evidence.state is not EvidenceState.KNOWN:
        raise InputValidationError(f"compose-v5 component {component_id} module is not fully provable")
    ports = tuple(_port(component_id, port) for port in sorted(module.ports, key=lambda item: item.name))
    if not ports:
        raise InputValidationError(f"compose-v5 component {component_id} has no ports")
    if len({port["name"] for port in ports}) != len(ports):
        raise InputValidationError(f"duplicate port in compose-v5 component {component_id}")
    parameters = tuple(
        (_identifier(name, f"compose-v5 component {component_id} parameter name"),
         _parameter_literal(value, f"compose-v5 component {component_id} parameter {name}"))
        for name, value in sorted(module.parameters)
    )
    return {
        "module_type": module.original_name,
        "instance": component_id,
        "ports": ports,
        "parameters": parameters,
    }


def _port(component_id: str, port: RTLPort) -> dict[str, object]:
    _identifier(port.name, f"compose-v5 component {component_id} port name")
    if port.direction is PortDirection.INOUT:
        raise InputValidationError(
            f"compose-v5 scheme-A flat top rejects inout port {component_id}.{port.name}"
        )
    if port.direction not in {PortDirection.INPUT, PortDirection.OUTPUT}:
        raise InputValidationError(f"invalid direction for compose-v5 port {component_id}.{port.name}")
    if isinstance(port.width, bool) or not isinstance(port.width, int) or port.width <= 0:
        raise InputValidationError(
            f"compose-v5 port {component_id}.{port.name} has invalid width"
        )
    if port.evidence.state is not EvidenceState.KNOWN:
        raise InputValidationError(
            f"compose-v5 port {component_id}.{port.name} is not fully provable"
        )
    return {"name": port.name, "direction": port.direction, "width": port.width}


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not _SV_IDENTIFIER.fullmatch(value):
        raise InputValidationError(f"{path}: expected a simple Verilog identifier")
    return value


def _parameter_literal(value: object, path: str) -> str:
    if not isinstance(value, str) or not _SAFE_PARAMETER_LITERAL.fullmatch(value):
        raise InputValidationError(f"{path}: expected a safe numeric Verilog parameter literal")
    return value


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def _direction(value: PortDirection) -> str:
    return "input" if value is PortDirection.INPUT else "output"
