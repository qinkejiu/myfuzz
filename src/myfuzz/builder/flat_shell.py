"""Emit the disconnected Flat Random baseline without invoking connection planning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import SystemIR
from .input_model import InputValidationError, PortDirection


@dataclass(frozen=True)
class EmittedFlatShell:
    module_name: str
    rtl: str
    external_ports: tuple[Mapping[str, object], ...]
    instances: tuple[str, ...]


def emit_flat_shell(ir: SystemIR, module_name: str = "flat_random_top") -> EmittedFlatShell:
    """Instantiate modules with no child-to-child nets and qualify every port name."""
    if not module_name.isidentifier():
        raise InputValidationError("Flat shell module name must be a Verilog identifier")
    modules = tuple(_module(value, index) for index, value in enumerate(ir.modules))
    instances = [module["instance"] for module in modules]
    if len(instances) != len(set(instances)):
        raise InputValidationError("Flat shell instance names must be unique")
    external = []
    for module in sorted(modules, key=lambda value: value["instance"]):
        for port in module["ports"]:
            external.append({
                "name": f"{module['instance']}__{port['name']}",
                "instance": module["instance"], "child_port": port["name"],
                "direction": port["direction"].value, "width": port["width"],
                "fuzz_control": port["direction"] is PortDirection.INPUT,
            })
    lines = [f"module {module_name} (", ",\n".join(
        f" {_direction(PortDirection(port['direction']))} logic {_range(int(port['width']))}{port['name']}"
        for port in external), ");"]
    for module in sorted(modules, key=lambda value: value["instance"]):
        parameters = module["parameters"]
        if parameters:
            lines.extend((f" {module['module_type']} #(", ",\n".join(
                f"  .{name}({_literal(value)})" for name, value in parameters),
                f" ) {module['instance']} ("))
        else:
            lines.append(f" {module['module_type']} {module['instance']} (")
        lines.append(",\n".join(
            f"  .{port['name']}({module['instance']}__{port['name']})" for port in module["ports"]))
        lines.append(" );")
    lines.append("endmodule")
    return EmittedFlatShell(module_name, "\n".join(lines) + "\n", tuple(external),
                            tuple(sorted(instances)))


def _module(value: Mapping[str, Any], index: int) -> dict[str, object]:
    allowed = {"name", "module_type", "instance", "ports", "parameters"}
    unknown = set(value) - allowed
    if unknown: raise InputValidationError(f"modules[{index}]: unknown field(s): {', '.join(sorted(unknown))}")
    module_type = _identifier(value.get("module_type"), f"modules[{index}].module_type")
    instance = _identifier(value.get("instance"), f"modules[{index}].instance")
    raw_ports = value.get("ports")
    if not isinstance(raw_ports, (tuple, list)) or not raw_ports:
        raise InputValidationError(f"modules[{index}].ports: expected non-empty array")
    ports = []
    for port_index, raw in enumerate(raw_ports):
        if not isinstance(raw, Mapping): raise InputValidationError("Flat shell port must be an object")
        name = _identifier(raw.get("name"), f"modules[{index}].ports[{port_index}].name")
        try: direction = PortDirection(raw.get("direction"))
        except ValueError as exc: raise InputValidationError(f"invalid direction for {instance}.{name}") from exc
        if direction is PortDirection.INOUT:
            raise InputValidationError(f"Flat shell rejects unsupported inout port {instance}.{name}")
        width = raw.get("width")
        if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
            raise InputValidationError(f"invalid width for {instance}.{name}")
        ports.append({"name": name, "direction": direction, "width": width})
    if len({port["name"] for port in ports}) != len(ports):
        raise InputValidationError(f"duplicate port in flat instance {instance}")
    raw_parameters = value.get("parameters", {})
    if not isinstance(raw_parameters, Mapping): raise InputValidationError("parameters must be an object")
    parameters = tuple(sorted((_identifier(k, "parameter"), v) for k, v in raw_parameters.items()))
    if any(not isinstance(v, (int, bool)) for _, v in parameters):
        raise InputValidationError("Flat shell parameters must be integer or boolean")
    return {"module_type": module_type, "instance": instance, "ports": tuple(ports),
            "parameters": parameters}


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.isidentifier():
        raise InputValidationError(f"{path}: expected a Verilog identifier")
    return value


def _range(width: int) -> str: return "" if width == 1 else f"[{width - 1}:0] "
def _direction(value: PortDirection) -> str: return "input" if value is PortDirection.INPUT else "output"
def _literal(value: int | bool) -> str: return ("1'b1" if value else "1'b0") if isinstance(value, bool) else str(value)
