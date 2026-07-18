"""Deterministic synthesizable SoC top emission from explicit SystemIR facts."""

from __future__ import annotations

from dataclasses import dataclass
import shlex
from typing import Any, Mapping

from .contracts import ElaborationManifest, SystemIR
from .input_model import InputValidationError, PortDirection


@dataclass(frozen=True)
class EmittedSoc:
    module_name: str
    rtl: str
    external_ports: tuple[str, ...]
    instances: tuple[str, ...]


def emit_soc_filelist(manifest: ElaborationManifest) -> str:
    """Serialize one validated manifest without rediscovering or reordering its inputs."""
    tokens = [f"+incdir+{path}" for path in manifest.include_dirs]
    tokens.extend(f"+define+{definition}" for definition in manifest.defines)
    tokens.extend(f"-G{name}={value}" for name, value in manifest.parameters)
    tokens.extend(source.path for source in manifest.sources)
    return "".join(f"{shlex.quote(token)}\n" for token in tokens)


def emit_generated_soc_top(ir: SystemIR, module_name: str = "generated_soc_top") -> EmittedSoc:
    if not module_name.isidentifier():
        raise InputValidationError("SoC top module name must be a Verilog identifier")
    modules = [_module(value, index) for index, value in enumerate(ir.modules)]
    if len({module["name"] for module in modules}) != len(modules):
        raise InputValidationError("SoC modules must have unique logical names")
    if len({module["instance"] for module in modules}) != len(modules):
        raise InputValidationError("SoC modules must have unique instance names")
    endpoints = {
        f"{module['name']}.{port['name']}": (module, port)
        for module in modules for port in module["ports"]
    }
    signals: dict[str, str] = {}
    driven_targets: set[str] = set()
    declarations: list[str] = []
    for index, connection in enumerate(ir.connections):
        source = _text(connection.get("source"), f"connections[{index}].source")
        target = _text(connection.get("target"), f"connections[{index}].target")
        if source not in endpoints or target not in endpoints:
            raise InputValidationError(f"connection references unknown endpoint: {source}->{target}")
        source_port = endpoints[source][1]
        target_port = endpoints[target][1]
        if source_port["direction"] is not PortDirection.OUTPUT or target_port["direction"] is not PortDirection.INPUT:
            raise InputValidationError(f"connection direction mismatch: {source}->{target}")
        if source_port["width"] != target_port["width"]:
            raise InputValidationError(f"connection width mismatch: {source}->{target}")
        if target in driven_targets:
            raise InputValidationError(f"multiple drivers for {target}")
        driven_targets.add(target)
        signal = signals.get(source)
        if signal is None:
            signal = f"__edge_{index:04d}"
            declarations.append(_logic(signal, source_port["width"]))
            signals[source] = signal
        signals[target] = signal

    external: list[tuple[str, PortDirection, int]] = []
    for label, (_module_value, port) in sorted(endpoints.items()):
        if label in signals:
            continue
        if not port["external"]:
            if port["direction"] is PortDirection.INPUT:
                raise InputValidationError(f"unconnected required input {label}")
            raise InputValidationError(f"unconnected output {label} must be explicitly observed")
        external_name = label.replace(".", "__")
        signals[label] = external_name
        external.append((external_name, port["direction"], port["width"]))

    port_lines = [
        f" {_direction(direction)} logic {_range(width)}{name}"
        for name, direction, width in external
    ]
    lines = [f"module {module_name} ("]
    lines.append(",\n".join(port_lines))
    lines.append(");")
    lines.extend(f" {value}" for value in declarations)
    for module in sorted(modules, key=lambda item: (item["instance"], item["name"])):
        bindings = []
        for port in module["ports"]:
            label = f"{module['name']}.{port['name']}"
            bindings.append(f"  .{port['name']}({signals[label]})")
        parameter_values = module["parameters"]
        if parameter_values:
            parameters = ",\n".join(
                f"  .{name}({_parameter_literal(value)})"
                for name, value in parameter_values
            )
            lines.append(f" {module['module_type']} #(")
            lines.append(parameters)
            lines.append(f" ) {module['instance']} (")
        else:
            lines.append(f" {module['module_type']} {module['instance']} (")
        lines.append(",\n".join(bindings))
        lines.append(" );")
    lines.append("endmodule")
    return EmittedSoc(
        module_name, "\n".join(lines) + "\n",
        tuple(name for name, _direction_value, _width in external),
        tuple(module["instance"] for module in sorted(modules, key=lambda item: item["instance"])),
    )


def _module(value: Mapping[str, Any], index: int) -> dict[str, Any]:
    name = _identifier(value.get("name"), f"modules[{index}].name")
    module_type = _identifier(value.get("module_type"), f"modules[{index}].module_type")
    instance = _identifier(value.get("instance"), f"modules[{index}].instance")
    raw_ports = value.get("ports")
    if not isinstance(raw_ports, (list, tuple)) or not raw_ports:
        raise InputValidationError(f"modules[{index}].ports: expected a non-empty array")
    ports = tuple(_port(item, index, port_index) for port_index, item in enumerate(raw_ports))
    if len({port["name"] for port in ports}) != len(ports):
        raise InputValidationError(f"modules[{index}].ports: duplicate port name")
    raw_parameters = value.get("parameters", {})
    if not isinstance(raw_parameters, Mapping):
        raise InputValidationError(f"modules[{index}].parameters: expected an object")
    parameters: list[tuple[str, int | bool]] = []
    for parameter_name, parameter_value in raw_parameters.items():
        identifier = _identifier(parameter_name, f"modules[{index}].parameters key")
        if not isinstance(parameter_value, (int, bool)):
            raise InputValidationError(
                f"modules[{index}].parameters.{identifier}: expected an integer or boolean"
            )
        parameters.append((identifier, parameter_value))
    return {
        "name": name,
        "module_type": module_type,
        "instance": instance,
        "ports": ports,
        "parameters": tuple(sorted(parameters)),
    }


def _port(value: object, module_index: int, port_index: int) -> dict[str, Any]:
    path = f"modules[{module_index}].ports[{port_index}]"
    if not isinstance(value, Mapping):
        raise InputValidationError(f"{path}: expected an object")
    name = _identifier(value.get("name"), f"{path}.name")
    try:
        direction = PortDirection(value.get("direction"))
    except ValueError as exc:
        raise InputValidationError(f"{path}.direction: invalid direction") from exc
    width = value.get("width")
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise InputValidationError(f"{path}.width: expected a positive integer")
    external = value.get("external", False)
    if not isinstance(external, bool):
        raise InputValidationError(f"{path}.external: expected a boolean")
    return {"name": name, "direction": direction, "width": width, "external": external}


def _logic(name: str, width: int) -> str:
    return f"logic {_range(width)}{name};"


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def _direction(direction: PortDirection) -> str:
    return {PortDirection.INPUT: "input", PortDirection.OUTPUT: "output", PortDirection.INOUT: "inout"}[direction]


def _parameter_literal(value: int | bool) -> str:
    if isinstance(value, bool):
        return "1'b1" if value else "1'b0"
    return str(value)


def _identifier(value: object, path: str) -> str:
    text = _text(value, path)
    if not text.isidentifier():
        raise InputValidationError(f"{path}: expected a Verilog identifier")
    return text


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value
