"""Compose-v5 connection planning from declared roles and discovered contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import content_digest
from .input_model import InputValidationError
from .rtl_analysis import RTLModule
from .system_contract_discovery_v5 import ContractV5SystemDiscoveryReport


COMPOSE_V5_CONNECTION_PLAN_SCHEMA = "myfuzz.compose-v5-connection-plan/v1"
_WINDOW_SIZE = 0x1000
_RAM_BASE = 0x0000_0000
_IP_BASE = 0x4000_0000


@dataclass(frozen=True)
class ComposeV5ConnectionPlan:
    manifest_digest: str
    discovery_digest: str
    master_component: str
    components: tuple[Mapping[str, object], ...]
    interfaces: tuple[Mapping[str, object], ...]
    edges: tuple[Mapping[str, object], ...]
    address_map: tuple[Mapping[str, object], ...]
    bridge_requirements: tuple[Mapping[str, object], ...]
    incomplete_reasons: tuple[str, ...]
    digest: str
    schema: str = COMPOSE_V5_CONNECTION_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != COMPOSE_V5_CONNECTION_PLAN_SCHEMA:
            raise InputValidationError("compose-v5 connection plan schema mismatch")
        _digest(self.manifest_digest, "connection plan manifest_digest")
        _digest(self.discovery_digest, "connection plan discovery_digest")
        if not isinstance(self.master_component, str) or not self.master_component:
            raise InputValidationError("connection plan master_component must be non-empty")
        if not isinstance(self.components, tuple) or not self.components:
            raise InputValidationError("connection plan components must be a non-empty tuple")
        if not isinstance(self.interfaces, tuple):
            raise InputValidationError("connection plan interfaces must be a tuple")
        if not isinstance(self.edges, tuple):
            raise InputValidationError("connection plan edges must be a tuple")
        if not isinstance(self.address_map, tuple):
            raise InputValidationError("connection plan address_map must be a tuple")
        if not isinstance(self.bridge_requirements, tuple):
            raise InputValidationError("connection plan bridge_requirements must be a tuple")
        if not isinstance(self.incomplete_reasons, tuple):
            raise InputValidationError("connection plan incomplete_reasons must be a tuple")
        if self.digest and self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("compose-v5 connection plan digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "manifest_digest": self.manifest_digest,
            "discovery_digest": self.discovery_digest,
            "master_component": self.master_component,
            "components": [dict(item) for item in self.components],
            "interfaces": [dict(item) for item in self.interfaces],
            "edges": [dict(item) for item in self.edges],
            "address_map": [dict(item) for item in self.address_map],
            "bridge_requirements": [dict(item) for item in self.bridge_requirements],
            "incomplete_reasons": list(self.incomplete_reasons),
        }

    def to_dict(self) -> dict[str, object]:
        value = self.payload_dict()
        value["digest"] = self.digest
        return value


def build_compose_v5_connection_plan(
    manifest: Any,
    component_modules: Mapping[str, RTLModule],
    discovery: ContractV5SystemDiscoveryReport,
) -> ComposeV5ConnectionPlan:
    """Plan CPU-only-master component connections from discovered bit-level contracts."""

    if not hasattr(manifest, "components") or not hasattr(manifest, "digest"):
        raise InputValidationError("connection plan requires a compose-v5 manifest-like object")
    if not isinstance(discovery, ContractV5SystemDiscoveryReport):
        raise InputValidationError("connection plan requires a system discovery report")
    if not isinstance(component_modules, Mapping) or not component_modules:
        raise InputValidationError("connection plan requires component modules")

    by_component = {component.id: component for component in manifest.components}
    if set(by_component) != set(component_modules):
        raise InputValidationError("connection plan component modules do not match manifest components")
    cpu_components = tuple(
        component.id for component in manifest.components
        if _role(component) == "cpu"
    )
    if len(cpu_components) != 1:
        raise InputValidationError("connection plan requires exactly one CPU component")
    master = cpu_components[0]

    module_to_component = _module_to_component(component_modules)
    components = tuple(
        {
            "id": component.id,
            "role": _role(component),
            "module": component.module,
            "source_set": component.source_set,
        }
        for component in sorted(manifest.components, key=lambda item: item.id)
    )
    interfaces, incomplete = _interfaces(discovery, module_to_component)
    interface_by_component = {
        str(item["component"]): item
        for item in interfaces
        if item["status"] == "unique"
    }

    master_interface = interface_by_component.get(master)
    if master_interface is None:
        incomplete.append(f"master component {master} has no unique discovered interface")
    elif master_interface["interface_role"] != "initiator":
        incomplete.append(f"master component {master} interface is not an initiator")

    address_map = _address_map(manifest.components)
    edges: list[dict[str, object]] = []
    bridges: list[dict[str, object]] = []
    for component in sorted(manifest.components, key=lambda item: item.id):
        if component.id == master or _role(component) == "bridge":
            continue
        target_interface = interface_by_component.get(component.id)
        edge_id = f"{master}->{component.id}"
        if master_interface is None or target_interface is None:
            reason = (
                f"{edge_id}: missing discovered interface"
                if target_interface is None
                else f"{edge_id}: missing master interface"
            )
            incomplete.append(reason)
            edges.append(_edge(edge_id, master, component.id, "incomplete", reason))
            continue
        if target_interface["interface_role"] != "target":
            reason = f"{edge_id}: destination interface is not a target"
            incomplete.append(reason)
            edges.append(_edge(edge_id, master, component.id, "incomplete", reason))
            continue
        source_kind = str(master_interface["interface_kind"])
        target_kind = str(target_interface["interface_kind"])
        bridge_id = f"bridge_{master}_{component.id}"
        bridge_status = "direct" if source_kind == target_kind else "generate_required"
        bridges.append({
            "id": bridge_id,
            "source_component": master,
            "target_component": component.id,
            "source_interface_kind": source_kind,
            "target_interface_kind": target_kind,
            "status": bridge_status,
            "rtl_generation": "not_required" if bridge_status == "direct" else "required",
            "evidence": "interface kinds came from behavior-backed contract discovery",
        })
        edges.append({
            "id": edge_id,
            "source_component": master,
            "target_component": component.id,
            "status": "planned",
            "kind": "protocol",
            "source_interface": master_interface["id"],
            "target_interface": target_interface["id"],
            "bridge_requirement": bridge_id,
            "address_window": component.id if _role(component) in {"ram", "ip"} else "",
            "reason": "CPU-only master policy plus behavior-discovered initiator/target interfaces",
        })

    payload = {
        "schema": COMPOSE_V5_CONNECTION_PLAN_SCHEMA,
        "manifest_digest": manifest.digest,
        "discovery_digest": discovery.digest,
        "master_component": master,
        "components": [dict(item) for item in components],
        "interfaces": [dict(item) for item in interfaces],
        "edges": [dict(item) for item in tuple(edges)],
        "address_map": [dict(item) for item in address_map],
        "bridge_requirements": [dict(item) for item in tuple(bridges)],
        "incomplete_reasons": list(tuple(sorted(set(incomplete)))),
    }
    return ComposeV5ConnectionPlan(
        manifest.digest,
        discovery.digest,
        master,
        components,
        interfaces,
        tuple(edges),
        address_map,
        tuple(bridges),
        tuple(sorted(set(incomplete))),
        content_digest(payload),
    )


def _interfaces(
    discovery: ContractV5SystemDiscoveryReport,
    module_to_component: Mapping[str, str],
) -> tuple[tuple[Mapping[str, object], ...], list[str]]:
    interfaces: list[dict[str, object]] = []
    incomplete: list[str] = []
    for report in discovery.module_reports:
        component = module_to_component.get(report.module) or module_to_component.get(report.original_module)
        if component is None:
            raise InputValidationError(f"discovery report module {report.module!r} is not a manifest component")
        if report.ambiguity.status != "unique" or len(report.hypotheses) != 1:
            reason = f"{component}: interface discovery status is {report.ambiguity.status}"
            incomplete.append(reason)
            interfaces.append({
                "id": f"{component}.unresolved",
                "component": component,
                "status": "incomplete",
                "interface_kind": "",
                "interface_role": "",
                "signals": [],
                "reason": reason,
            })
            continue
        hypothesis = report.hypotheses[0]
        interfaces.append({
            "id": f"{component}.if0",
            "component": component,
            "status": "unique",
            "interface_kind": hypothesis.interface_kind,
            "interface_role": hypothesis.interface_role,
            "signals": [
                {
                    "owner": f"{component}.{signal.port}",
                    "port": signal.port,
                    "direction": signal.direction,
                    "role": signal.role,
                    "width": signal.width,
                    "polarity": signal.polarity,
                }
                for signal in hypothesis.signals
            ],
            "reason": "unique behavior-backed contract hypothesis",
        })
    return tuple(sorted(interfaces, key=lambda item: str(item["id"]))), incomplete


def _address_map(components: tuple[Any, ...]) -> tuple[Mapping[str, object], ...]:
    windows: list[dict[str, object]] = []
    ram_index = 0
    ip_index = 0
    for component in sorted(components, key=lambda item: item.id):
        role = _role(component)
        if role == "ram":
            base = _RAM_BASE + ram_index * _WINDOW_SIZE
            ram_index += 1
        elif role == "ip":
            base = _IP_BASE + ip_index * _WINDOW_SIZE
            ip_index += 1
        else:
            continue
        windows.append({
            "component": component.id,
            "base": base,
            "size": _WINDOW_SIZE,
            "source": "compose_v5_default_sequential",
            "reason": "manifest provided component role but no explicit address map field in v1",
        })
    return tuple(windows)


def _edge(
    edge_id: str,
    source: str,
    target: str,
    status: str,
    reason: str,
) -> dict[str, object]:
    return {
        "id": edge_id,
        "source_component": source,
        "target_component": target,
        "status": status,
        "kind": "protocol",
        "source_interface": "",
        "target_interface": "",
        "bridge_requirement": "",
        "address_window": "",
        "reason": reason,
    }


def _module_to_component(component_modules: Mapping[str, RTLModule]) -> dict[str, str]:
    result: dict[str, str] = {}
    for component_id, module in component_modules.items():
        if not isinstance(component_id, str) or not component_id:
            raise InputValidationError("connection plan component id must be non-empty")
        if not isinstance(module, RTLModule):
            raise InputValidationError("connection plan requires RTLModule values")
        for name in {module.name, module.original_name}:
            if name in result and result[name] != component_id:
                raise InputValidationError(f"RTL module name {name!r} maps to multiple components")
            result[name] = component_id
    return result


def _role(component: object) -> str:
    role = getattr(component, "role", None)
    value = getattr(role, "value", role)
    if not isinstance(value, str) or not value:
        raise InputValidationError("compose-v5 component role must be a non-empty string")
    return value


def _digest(value: object, path: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
