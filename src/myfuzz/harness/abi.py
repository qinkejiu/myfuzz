"""Deterministic raw-bit ABI records and manifest validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from myfuzz.dependency.graph import DependencyNode


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def content_hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class RawDestination:
    destination_id: int
    component_id: int | None
    port_id: int
    width: int


@dataclass(frozen=True, slots=True)
class RawBitUse:
    raw_lo: int
    raw_hi: int
    destination_id: int
    destination_lo: int
    action: str
    category: str


@dataclass(frozen=True, slots=True)
class RawBitAbi:
    raw_width: int
    destinations: tuple[RawDestination, ...]
    uses: tuple[RawBitUse, ...]
    abi_hash: str

    def validate_total_use(self) -> None:
        if isinstance(self.raw_width, bool) or not isinstance(self.raw_width, int) or self.raw_width <= 0:
            raise ValueError("raw_width must be positive")
        cursor = 0
        seen: set[int] = set()
        destination_widths = {item.destination_id: item.width for item in self.destinations}
        for use in sorted(self.uses, key=lambda item: item.raw_lo):
            if use.raw_lo != cursor or use.raw_hi < use.raw_lo:
                raise ValueError("raw-bit mapping must be contiguous and nonempty")
            width = destination_widths.get(use.destination_id)
            if width is None or use.destination_lo < 0 or use.raw_hi - use.raw_lo + 1 > width - use.destination_lo:
                raise ValueError("raw-bit mapping references an invalid destination slice")
            if use.raw_lo in seen:
                raise ValueError("raw-bit mapping overlaps")
            seen.add(use.raw_lo)
            cursor = use.raw_hi + 1
        if cursor != self.raw_width:
            raise ValueError("raw-bit mapping does not cover raw_width")


def _int(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (value <= 0 if positive else value < 0):
        qualifier = "positive " if positive else "non-negative "
        raise ValueError(f"{label} must be a {qualifier}integer")
    return value


def _group(value: object) -> DependencyNode:
    if isinstance(value, DependencyNode):
        return value
    if not isinstance(value, Mapping) or not isinstance(value.get("kind"), str) or not isinstance(value.get("components"), Sequence):
        raise ValueError("dependency groups must be structured kind/components records")
    components = tuple(value["components"])
    if any(not isinstance(item, str) or not item for item in components):
        raise ValueError("dependency group components must be non-empty strings")
    return DependencyNode(value["kind"], components)


def _ports(manifest: Mapping[str, object]) -> tuple[dict[str, Any], ...]:
    top = manifest.get("top")
    if not isinstance(top, Mapping) or not isinstance(top.get("module"), str) or not top["module"]:
        raise ValueError("manifest.top.module is required for generated port mapping")
    raw = manifest.get("top_port_abi")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("manifest.top_port_abi must be an array")
    ports: list[dict[str, Any]] = []
    seen: set[int] = set()
    emitted_seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"top_port_abi[{index}] must be an object")
        port_id = _int(item.get("port_id"), f"top_port_abi[{index}].port_id")
        width = _int(item.get("width"), f"top_port_abi[{index}].width", positive=True)
        direction = item.get("direction")
        if direction not in {"input", "output", "inout"}:
            raise ValueError(f"top_port_abi[{index}].direction is invalid")
        emitted_name = item.get("emitted_name")
        if not isinstance(emitted_name, str) or not emitted_name:
            raise ValueError(f"top_port_abi[{index}].emitted_name is required")
        if emitted_name in emitted_seen:
            raise ValueError(f"duplicate emitted port name: {emitted_name}")
        emitted_seen.add(emitted_name)
        if port_id in seen:
            raise ValueError("duplicate top port ID")
        seen.add(port_id)
        component_id = item.get("component_id")
        if component_id is not None:
            _int(component_id, f"top_port_abi[{index}].component_id")
        driver_count = item.get("driver_count", item.get("drivers", 1))
        if isinstance(driver_count, Sequence) and not isinstance(driver_count, (str, bytes)):
            driver_count = len(driver_count)
        if isinstance(driver_count, bool) or not isinstance(driver_count, int) or driver_count != 1:
            raise ValueError(f"multiple drivers for port ID: {port_id}")
        reset_value = item.get("reset_value")
        if reset_value is not None and (isinstance(reset_value, bool) or not isinstance(reset_value, int) or not 0 <= reset_value < 1 << width):
            raise ValueError(f"invalid reset value for port ID: {port_id}")
        constant_value = item.get("constant_value")
        if constant_value is not None and (isinstance(constant_value, bool) or not isinstance(constant_value, int) or not 0 <= constant_value < 1 << width):
            raise ValueError(f"invalid constant value for port ID: {port_id}")
        if item.get("semantic_role") in {"clock", "reset"} and width != 1:
            raise ValueError(f"clock/reset port must be one bit: {port_id}")
        role = item.get("semantic_role")
        if not isinstance(role, str) or not role:
            raise ValueError(f"top_port_abi[{index}].semantic_role is required")
        record = dict(item)
        record.update(port_id=port_id, width=width, direction=direction)
        ports.append(record)
    return tuple(ports)


def _control_declarations(manifest: Mapping[str, object], ports: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    """Validate explicit control semantics and return role-to-port declarations."""
    combinational = manifest.get("combinational_design", False)
    if not isinstance(combinational, bool):
        raise ValueError("manifest.combinational_design must be an explicit boolean")
    by_role = {
        role: tuple(port for port in ports if port.get("semantic_role") == role)
        for role in ("clock", "reset")
    }
    if combinational:
        if by_role["clock"] or by_role["reset"]:
            raise ValueError("combinational designs cannot declare clock/reset ports")
        return {}
    declarations: dict[str, dict[str, Any]] = {}
    for role in ("clock", "reset"):
        matches = by_role[role]
        if len(matches) != 1:
            raise ValueError(f"exactly one explicit {role} semantic declaration is required")
        declaration = matches[0]
        active_level = declaration.get("active_level")
        if isinstance(active_level, bool) or active_level not in (0, 1):
            raise ValueError(f"{role} declaration requires active_level 0 or 1")
        if role == "reset":
            synchronous = declaration.get("synchronous")
            if not isinstance(synchronous, bool):
                raise ValueError("reset declaration requires explicit synchronous boolean")
            reset_value = declaration.get("reset_value")
            if reset_value != active_level:
                raise ValueError("reset_value must match the declared reset active_level")
            io_meta_reset = declaration.get("io_meta_reset")
            if io_meta_reset is not None and not isinstance(io_meta_reset, bool):
                raise ValueError("reset io_meta_reset declaration must be boolean")
        declarations[role] = declaration
    return declarations


def _validate_fields(manifest: Mapping[str, object], ports: tuple[dict[str, Any], ...]) -> None:
    fields = manifest.get("fields", ())
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)):
        raise ValueError("manifest.fields must be an array")
    by_port = {item["port_id"]: item for item in ports}
    for index, field in enumerate(fields):
        if not isinstance(field, Mapping):
            raise ValueError(f"fields[{index}] must be an object")
        port_id = _int(field.get("port_id"), f"fields[{index}].port_id")
        if port_id not in by_port:
            raise ValueError(f"unbound field port ID: {port_id}")
        width = field.get("width")
        if width is not None and _int(width, f"fields[{index}].width", positive=True) != by_port[port_id]["width"]:
            raise ValueError(f"width mismatch for field port ID: {port_id}")
        reset_value = field.get("reset_value")
        field_width = by_port[port_id]["width"]
        if reset_value is not None and (
            isinstance(reset_value, bool)
            or not isinstance(reset_value, int)
            or not 0 <= reset_value < 1 << field_width
        ):
            raise ValueError(f"invalid reset value for field port ID: {port_id}")


def _validate_protocol_bindings(manifest: Mapping[str, object]) -> None:
    bindings = manifest.get("protocol_bindings", manifest.get("endpoint_bindings"))
    if bindings is None:
        return
    if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
        raise ValueError("protocol bindings must be an array")
    for index, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            raise ValueError(f"protocol_bindings[{index}] must be an object")
        protocol_id = binding.get("protocol_id")
        version = binding.get("version")
        if not isinstance(protocol_id, str) or not protocol_id or not isinstance(version, str) or not version:
            raise ValueError(f"protocol_bindings[{index}] requires explicit protocol_id and version")


def _validate_external(manifest: Mapping[str, object], ports: tuple[dict[str, Any], ...]) -> None:
    external = manifest.get("external_ports")
    if external is None:
        return
    if not isinstance(external, Sequence) or isinstance(external, (str, bytes)):
        raise ValueError("manifest.external_ports must be an array")
    by_port = {item["port_id"]: item for item in ports}
    seen: set[int] = set()
    for index, item in enumerate(external):
        if not isinstance(item, Mapping):
            raise ValueError(f"external_ports[{index}] must be an object")
        port_id = _int(item.get("port_id"), f"external_ports[{index}].port_id")
        if port_id in seen:
            raise ValueError("duplicate external port ID")
        seen.add(port_id)
        if port_id not in by_port:
            raise ValueError(f"unbound external port ID: {port_id}")
        if _int(item.get("width"), f"external_ports[{index}].width", positive=True) != by_port[port_id]["width"]:
            raise ValueError(f"width mismatch for external port ID: {port_id}")
        direction = item.get("direction")
        if direction is not None and direction != by_port[port_id]["direction"]:
            raise ValueError(f"direction mismatch for external port ID: {port_id}")


def _group_records(manifest: Mapping[str, object], ports: tuple[dict[str, Any], ...]) -> tuple[DependencyNode, ...]:
    declared = tuple(_group(item) for item in manifest.get("dependency_groups", ()))
    if len(declared) > 64:
        raise ValueError("dependency-aware projection supports at most 64 groups")
    if len(set(declared)) != len(declared):
        raise ValueError("duplicate dependency group")
    known = set(declared)
    for port in ports:
        group = port.get("dependency_group")
        if group is not None and _group(group) not in known:
            raise ValueError("port references an undeclared dependency group")
    return tuple(sorted(declared))


def _select_ports(manifest: Mapping[str, object]) -> tuple[dict[str, Any], ...]:
    ports = _ports(manifest)
    _control_declarations(manifest, ports)
    _validate_fields(manifest, ports)
    _validate_protocol_bindings(manifest)
    _validate_external(manifest, ports)
    _group_records(manifest, ports)
    selected: list[dict[str, Any]] = []
    for port in ports:
        role = port.get("semantic_role")
        missing = object()
        fuzzable = port.get("fuzzable", port.get("fuzz_disposition", port.get("disposition", missing)))
        if fuzzable is missing and port["direction"] in {"input", "inout"}:
            raise ValueError(f"fuzz disposition must be explicit for port ID: {port['port_id']}")
        if isinstance(fuzzable, str):
            if fuzzable not in {"fuzz", "fuzzable", "enabled", "input", "constant", "disabled", "output"}:
                raise ValueError(f"invalid fuzz disposition for port ID: {port['port_id']}")
            fuzzable = fuzzable in {"fuzz", "fuzzable", "enabled", "input"}
        if not isinstance(fuzzable, bool):
            raise ValueError(f"fuzz disposition must be explicit for port ID: {port['port_id']}")
        if (
            not fuzzable
            and port["direction"] in {"input", "inout"}
            and role not in {"clock", "reset"}
            and port.get("constant_value", port.get("reset_value")) is None
        ):
            raise ValueError(f"unbound non-fuzzable input port ID: {port['port_id']}")
        if fuzzable and port["direction"] in {"input", "inout"} and role not in {"clock", "reset"}:
            selected.append(port)
    return tuple(sorted(selected, key=lambda item: item["port_id"]))


def build_raw_abi(manifest: object) -> RawBitAbi:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    selected = _select_ports(manifest)
    if not selected:
        raise ValueError("manifest declares no fuzzable input ports")
    destinations: list[RawDestination] = []
    uses: list[RawBitUse] = []
    cursor = 0
    for destination_id, port in enumerate(selected):
        width = port["width"]
        destinations.append(RawDestination(destination_id, port.get("component_id"), port["port_id"], width))
        uses.append(RawBitUse(cursor, cursor + width - 1, destination_id, 0, "direct", "direct"))
        cursor += width
    declared_width = manifest.get("raw_width")
    if declared_width is not None and _int(declared_width, "manifest.raw_width", positive=True) != cursor:
        raise ValueError(f"declared raw width does not match packed width: {declared_width} != {cursor}")
    document = {
        "raw_width": cursor,
        "destinations": [
            {
                "destination_id": item.destination_id,
                "component_id": item.component_id,
                "port_id": item.port_id,
                "width": item.width,
            }
            for item in destinations
        ],
        "uses": [
            {
                "raw_lo": item.raw_lo,
                "raw_hi": item.raw_hi,
                "destination_id": item.destination_id,
                "destination_lo": item.destination_lo,
                "action": item.action,
                "category": item.category,
            }
            for item in uses
        ],
    }
    abi = RawBitAbi(cursor, tuple(destinations), tuple(uses), content_hash(document))
    abi.validate_total_use()
    return abi


def selected_ports(manifest: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    return _select_ports(manifest)


def manifest_ports(manifest: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    ports = _ports(manifest)
    _control_declarations(manifest, ports)
    _validate_fields(manifest, ports)
    _validate_protocol_bindings(manifest)
    _validate_external(manifest, ports)
    _group_records(manifest, ports)
    return tuple(sorted(ports, key=lambda item: item["port_id"]))


def control_declarations(manifest: object) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    ports = _ports(manifest)
    return _control_declarations(manifest, ports)


def dependency_groups(manifest: object) -> tuple[DependencyNode, ...]:
    ports = manifest_ports(manifest)
    assert isinstance(manifest, Mapping)
    return _group_records(manifest, ports)


def dependency_group_for_port(port: Mapping[str, Any]) -> DependencyNode | None:
    value = port.get("dependency_group")
    return None if value is None else _group(value)
