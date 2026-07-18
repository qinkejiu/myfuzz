"""Structured artifact and optional structural-wrapper emission."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .discovery import DiscoveryResult
from .input_model import InputValidationError, PortDirection, SystemSpec
from .planner import SystemPlan
from .unknown_ports import UnknownPortAction


def emit_system(
    plan: SystemPlan,
    spec: SystemSpec,
    discovery: DiscoveryResult,
    output_dir: str | Path,
    *,
    generate_wrapper: bool = False,
) -> dict[str, Any]:
    if not plan.valid:
        raise InputValidationError(
            "cannot emit invalid system plan: " + "; ".join(plan.validation_issues)
        )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, Any] = {
        "system_ir.json": _system_ir(plan, spec, discovery),
        "port_bindings.json": {"port_bindings": [_binding(item) for item in plan.port_bindings]},
        "address_map.json": {"address_width": plan.address_plan.address_width, "windows": [
            {
                "module": entry.window.module,
                "base": entry.window.base,
                "size": entry.window.size,
                "upper": entry.window.upper,
                "request_mode": entry.intent.request.mode.value,
                "requested_base": entry.intent.request.base,
                "requested_alignment": entry.intent.request.alignment,
                "source": entry.window.source,
                "reason": entry.window.reason,
                "confidence": entry.window.confidence,
            }
            for entry in plan.address_plan.entries
        ]},
        "connection_graph.json": {"connections": [
            {
                "order": edge.order,
                "source": edge.source.label(),
                "target": edge.target.label(),
                "width": edge.width,
                "semantic": edge.semantic,
                "kind": edge.kind.value,
                "source_of_evidence": edge.evidence_source,
                "reason": edge.reason,
                "confidence": edge.confidence,
            }
            for edge in plan.graph.connections
        ], "virtual_modules": list(plan.virtual_modules)},
        "signal_constraints.json": {"constraints": [
            {
                "target": constraint.target.label(),
                "kind": constraint.kind.value,
                "expression": constraint.expression,
                "source": constraint.evidence_source,
                "reason": constraint.reason,
                "confidence": constraint.confidence,
            }
            for constraint in plan.graph.constraints
        ]},
        "unknown_ports.json": {"unknown_ports": [item.to_report_dict() for item in plan.unknown_ports]},
    }
    generated_files = list(artifacts)
    wrapper_status: dict[str, Any] = {"requested": generate_wrapper, "generated": False}
    if generate_wrapper:
        if any(name.startswith("__fabric_") for name in plan.virtual_modules):
            wrapper_status["reason"] = "virtual multi-endpoint fabric requires a protocol backend"
        else:
            wrapper_name = f"{_identifier(plan.name)}_wrapper.sv"
            (out / wrapper_name).write_text(_emit_wrapper(plan, spec, discovery), encoding="utf-8")
            generated_files.append(wrapper_name)
            wrapper_status.update({"generated": True, "file": wrapper_name})

    report = {
        "schema_version": 1,
        "system": plan.name,
        "status": "generated",
        "inputs": {
            "sources": [asdict(source) for source in spec.sources],
            "declared_modules": [module.name for module in spec.modules],
            "discovered_files": list(discovery.files),
        },
        "summary": {
            "modules": len(discovery.modules),
            "interfaces": len(plan.interfaces),
            "bindings": len(plan.port_bindings),
            "address_windows": len(plan.address_plan.entries),
            "connections": len(plan.graph.connections),
            "constraints": len(plan.graph.constraints),
            "unknown_port_decisions": len(plan.unknown_ports),
        },
        "classifications": [
            {
                "module": item.module, "kind": item.kind.value, "source": item.source,
                "reason": item.reason, "confidence": item.confidence,
            }
            for item in plan.classifications
        ],
        "interfaces": [
            {
                "module": item.module, "name": item.name, "protocol": item.protocol,
                "role": item.role.value, "profile": item.profile,
            }
            for item in plan.interfaces
        ],
        "inference_evidence": [_binding(item) for item in plan.port_bindings],
        "unknown_ports": [item.to_report_dict() for item in plan.unknown_ports],
        "wrapper": wrapper_status,
        "validation_issues": [],
        "generated_files": generated_files + ["generation_report.json"],
    }
    artifacts["generation_report.json"] = report
    for name, value in artifacts.items():
        (out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def _system_ir(plan: SystemPlan, spec: SystemSpec, discovery: DiscoveryResult) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "name": plan.name,
        "clock_domains": [asdict(domain) for domain in spec.clock_domains],
        "reset_domains": [asdict(domain) for domain in spec.reset_domains],
        "modules": [
            {
                "name": module.name,
                "source_file": module.source_file,
                "source_set": module.source_set,
                "parameters": module.parameters,
                "top_candidate": module.top_candidate,
                "instances": [asdict(instance) for instance in module.instances],
                "ports": [
                    {
                        "name": port.name, "direction": port.direction.value, "width": port.width,
                        "width_expression": port.width_expression,
                    }
                    for port in module.ports
                ],
            }
            for module in discovery.modules
        ],
        "virtual_modules": list(plan.virtual_modules),
    }


def _binding(item: Any) -> dict[str, Any]:
    return {
        "module": item.module, "port": item.port, "direction": item.direction.value,
        "width": item.width, "semantic": item.semantic, "interface": item.interface,
        "source": item.source, "reason": item.reason, "confidence": item.confidence,
    }


def _emit_wrapper(plan: SystemPlan, spec: SystemSpec, discovery: DiscoveryResult) -> str:
    connected_targets = {edge.target for edge in plan.graph.connections}
    net_by_source = {edge.source: f"net_{_identifier(edge.source.module)}_{_identifier(edge.source.port)}" for edge in plan.graph.connections}
    unknown = {(item.module, item.port): item for item in plan.unknown_ports}
    constraints = {item.target: item for item in plan.graph.constraints}
    top_ports: list[tuple[str, int, str]] = []
    virtual_sources = {edge.source for edge in plan.graph.connections if edge.source.module.startswith("__")}
    for source in sorted(virtual_sources):
        width = next(edge.width for edge in plan.graph.connections if edge.source == source)
        top_ports.append((f"ext_{_identifier(source.module)}", width, "input"))
    for decision in plan.unknown_ports:
        if decision.action in (UnknownPortAction.EXTERNAL_INPUT, UnknownPortAction.RFUZZ_DRIVE):
            top_ports.append((f"ext_{_identifier(decision.module)}_{_identifier(decision.port)}", decision.width, "input"))
        elif decision.action is UnknownPortAction.OBSERVE:
            top_ports.append((f"obs_{_identifier(decision.module)}_{_identifier(decision.port)}", decision.width, "output"))

    lines = [f"module {_identifier(plan.name)}_wrapper ("]
    declarations = [f"  {direction} logic {_range(width)}{name}" for name, width, direction in top_ports]
    lines.append(",\n".join(declarations))
    lines.append(");")
    for source, net in sorted(net_by_source.items(), key=lambda item: item[1]):
        width = next(edge.width for edge in plan.graph.connections if edge.source == source)
        lines.append(f"  logic {_range(width)}{net};")
        if source.module.startswith("__"):
            lines.append(f"  assign {net} = ext_{_identifier(source.module)};")

    module_specs = {module.name: module for module in spec.modules}
    for module in discovery.modules:
        parameters = module_specs.get(module.name).parameters if module.name in module_specs else {}
        parameter_text = ""
        if parameters:
            assignments = ", ".join(f".{name}({value})" for name, value in sorted(parameters.items()))
            parameter_text = f" #({assignments})"
        port_connections: list[str] = []
        for port in module.ports:
            ref = _ref(module.name, port.name)
            expression = None
            if ref in net_by_source:
                expression = net_by_source[ref]
            elif ref in connected_targets:
                edge = next(edge for edge in plan.graph.connections if edge.target == ref)
                expression = net_by_source[edge.source]
            elif ref in constraints:
                expression = _constant_expression(constraints[ref].expression, port.width or 1)
            else:
                decision = unknown.get((module.name, port.name))
                if decision and decision.action in (UnknownPortAction.EXTERNAL_INPUT, UnknownPortAction.RFUZZ_DRIVE):
                    expression = f"ext_{_identifier(module.name)}_{_identifier(port.name)}"
                elif decision and decision.action is UnknownPortAction.OBSERVE:
                    expression = f"obs_{_identifier(module.name)}_{_identifier(port.name)}"
            if expression is None:
                expression = ""
            port_connections.append(f"    .{port.name}({expression})")
        lines.append(f"  {module.name}{parameter_text} u_{_identifier(module.name)} (")
        lines.append(",\n".join(port_connections))
        lines.append("  );")
    lines.append("endmodule")
    return "\n".join(lines) + "\n"


def _constant_expression(expression: str, width: int) -> str:
    match = re.fullmatch(r"value\s*==\s*([01])", expression.strip())
    if not match:
        raise InputValidationError(f"wrapper cannot directly emit constraint {expression!r}")
    return f"{width}'d{match.group(1)}"


def _range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def _identifier(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_$]", "_", value)


def _ref(module: str, port: str):
    from .graph import EndpointRef
    return EndpointRef(module, port)
