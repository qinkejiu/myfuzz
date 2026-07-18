"""Functional module classification with authoritative user declarations."""

from __future__ import annotations

from dataclasses import dataclass

from .discovery import DiscoveryResult
from .input_model import ModuleKind, SystemSpec


@dataclass(frozen=True)
class ModuleClassification:
    module: str
    kind: ModuleKind
    source: str
    reason: str
    confidence: str


def classify_modules(spec: SystemSpec, discovery: DiscoveryResult) -> tuple[ModuleClassification, ...]:
    declared = {module.name: module for module in spec.modules}
    results: list[ModuleClassification] = []
    for module in discovery.modules:
        user = declared.get(module.name)
        if user is not None:
            results.append(ModuleClassification(
                module.name, user.kind, "user",
                "module kind was supplied by the user and is authoritative", "declared",
            ))
            continue
        results.append(_infer(module.name, module.ports, module.instances))
    return tuple(sorted(results, key=lambda item: item.module))


def _infer(module: str, ports: tuple, instances: tuple) -> ModuleClassification:
    names = {port.name.lower() for port in ports}
    output_names = {port.name.lower() for port in ports if port.direction.value == "output"}
    input_names = names - output_names
    master_markers = {"data_req_o", "req_o", "m_req_o"}
    target_markers = {"req_i", "s_req_i"}
    has_master = bool(output_names & master_markers)
    has_target = bool(input_names & target_markers)
    if has_master and has_target:
        kind, reason, confidence = ModuleKind.BRIDGE, "both initiator and target request ports were discovered", "heuristic"
    elif has_master:
        kind, reason, confidence = ModuleKind.BUS_MASTER, "an initiator request output was discovered", "heuristic"
    elif has_target:
        kind, reason, confidence = ModuleKind.BUS_SLAVE, "a target request input was discovered", "heuristic"
    elif instances:
        kind, reason, confidence = ModuleKind.INTERCONNECT, "module structurally contains other discovered modules", "low"
    elif names and names <= {"clk", "clk_i", "clk_o", "rst", "rst_n", "rst_ni", "reset", "reset_n"}:
        kind, reason, confidence = ModuleKind.CLOCK_RESET, "only clock/reset shaped ports were discovered", "heuristic"
    else:
        kind, reason, confidence = ModuleKind.UNKNOWN, "no reusable functional signature was sufficient", "unknown"
    return ModuleClassification(module, kind, "discovery", reason, confidence)
