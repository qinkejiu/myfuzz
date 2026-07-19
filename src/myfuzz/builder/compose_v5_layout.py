"""Compose-v5 rawbits layout synthesis."""

from __future__ import annotations

from typing import Mapping

from .input_model import InputValidationError, PortDirection
from .rawbits_v5 import RawBitsV5Layout, build_rawbits_v5_layout
from .rtl_analysis import EvidenceState, RTLModule, RTLPort
from .system_contract_discovery_v5 import ContractV5SystemDiscoveryReport


def build_compose_v5_scheme_a_rawbits_layout(
    component_modules: Mapping[str, RTLModule],
    *,
    discovery: ContractV5SystemDiscoveryReport | None = None,
) -> RawBitsV5Layout:
    """Build the flat-random scheme-A bit layout from real RTL input ports.

    Every declared component input becomes fuzz-owned rawbits.  Clock/reset
    kinds come only from behavior-discovered signal roles; without a unique
    discovery role, an input remains a normal external_input field.
    """

    if not isinstance(component_modules, Mapping) or not component_modules:
        raise InputValidationError("compose-v5 scheme-A layout requires component modules")
    role_by_module_port = _discovered_roles(discovery)
    fields: list[dict[str, object]] = []
    for component_id, module in sorted(component_modules.items()):
        if not isinstance(component_id, str) or not component_id:
            raise InputValidationError("compose-v5 scheme-A component id must be non-empty")
        if not isinstance(module, RTLModule):
            raise InputValidationError("compose-v5 scheme-A layout requires RTLModule values")
        for port in sorted(module.ports, key=lambda item: item.name):
            if port.direction is PortDirection.INOUT:
                raise InputValidationError(
                    f"compose-v5 scheme-A layout rejects inout port {component_id}.{port.name}"
                )
            if port.direction is not PortDirection.INPUT:
                continue
            _validate_input_port(component_id, port)
            role = (
                role_by_module_port.get((module.name, port.name))
                or role_by_module_port.get((module.original_name, port.name))
            )
            fields.append({
                "name": port.name,
                "component": component_id,
                "owner": f"{component_id}.{port.name}",
                "kind": _field_kind(role),
                "width": port.width,
                "initial_value": 0,
            })
    if not fields:
        raise InputValidationError("compose-v5 scheme-A layout found no input ports")
    return build_rawbits_v5_layout(tuple(fields))


def _discovered_roles(
    discovery: ContractV5SystemDiscoveryReport | None,
) -> dict[tuple[str, str], str]:
    if discovery is None:
        return {}
    if not isinstance(discovery, ContractV5SystemDiscoveryReport):
        raise InputValidationError("compose-v5 scheme-A discovery must be a system report")
    result: dict[tuple[str, str], str] = {}
    for report in discovery.module_reports:
        if report.ambiguity.status != "unique" or len(report.hypotheses) != 1:
            continue
        hypothesis = report.hypotheses[0]
        for signal in hypothesis.signals:
            if signal.direction != "input":
                continue
            if signal.role not in {"clock", "reset"}:
                continue
            result[(report.module, signal.port)] = signal.role
            result[(report.original_module, signal.port)] = signal.role
            result[(signal.module, signal.port)] = signal.role
    return result


def _field_kind(role: str | None) -> str:
    if role == "clock":
        return "clock"
    if role == "reset":
        return "reset"
    return "external_input"


def _validate_input_port(component_id: str, port: RTLPort) -> None:
    if not isinstance(port.name, str) or not port.name:
        raise InputValidationError(f"compose-v5 scheme-A has unnamed input port on {component_id}")
    if isinstance(port.width, bool) or not isinstance(port.width, int) or port.width <= 0:
        raise InputValidationError(
            f"compose-v5 scheme-A port {component_id}.{port.name} has invalid width"
        )
    if port.evidence.state is not EvidenceState.KNOWN:
        raise InputValidationError(
            f"compose-v5 scheme-A port {component_id}.{port.name} is not fully provable"
        )
