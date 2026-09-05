"""Strict, deterministic manifest parsing for protocol composition."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import ProtocolDefinitionError

from .registry import ComponentRegistry


class ProtocolCompositionError(ValueError):
    """Raised when a protocol-composition input is outside the closed contract."""


@dataclass(frozen=True, slots=True)
class CompositionComponent:
    component_id: str
    component_type: str
    protocol_id: str
    protocol_version: str
    base: int
    size: int
    irq: int | None
    parameters: Mapping[str, int]
    external_input: bool
    _source_index: int = field(default=0, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ProtocolCompositionManifest:
    target_kind: str
    base_config: str
    address_width: int
    data_width: int
    components: tuple[CompositionComponent, ...]
    seed: int
    duration_seconds: int
    checkpoint_seconds: int


def _error(label: str, kind: str) -> ProtocolCompositionError:
    return ProtocolCompositionError(f"{label}:{kind}")


def _object(value: object, label: str, *, required: set[str], allowed: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _error(label, "type")
    missing = sorted(required - set(value))
    if missing:
        raise _error(label, f"missing-field:{missing[0]}")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise _error(label, f"unknown-field:{unknown[0]}")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise _error(label, "type")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(label, "type")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise _error(label, "type")
    return value


def _component(value: object, index: int) -> CompositionComponent:
    label = f"components[{index}]"
    document = _object(
        value,
        label,
        required={"component_id", "component_type", "protocol", "base", "size", "parameters", "external_input"},
        allowed={"component_id", "component_type", "protocol", "base", "size", "irq", "parameters", "external_input"},
    )
    protocol = _object(
        document["protocol"],
        f"{label}.protocol",
        required={"id", "version"},
        allowed={"id", "version"},
    )
    parameters_raw = _object(
        document["parameters"],
        f"{label}.parameters",
        required=set(),
        allowed=set(document["parameters"]) if isinstance(document["parameters"], Mapping) else set(),
    )
    parameters: dict[str, int] = {}
    for name, parameter in parameters_raw.items():
        if not isinstance(name, str) or not name:
            raise _error(f"{label}.parameters", "invalid-name")
        parameters[name] = _integer(parameter, f"{label}.parameters.{name}")
    irq_value = document.get("irq")
    irq = None if irq_value is None else _integer(irq_value, f"{label}.irq")
    return CompositionComponent(
        component_id=_string(document["component_id"], f"{label}.component_id"),
        component_type=_string(document["component_type"], f"{label}.component_type"),
        protocol_id=_string(protocol["id"], f"{label}.protocol.id"),
        protocol_version=_string(protocol["version"], f"{label}.protocol.version"),
        base=_integer(document["base"], f"{label}.base"),
        size=_integer(document["size"], f"{label}.size"),
        irq=irq,
        parameters=MappingProxyType(parameters),
        external_input=_boolean(document["external_input"], f"{label}.external_input"),
        _source_index=index,
    )


def load_protocol_composition(path: Path) -> ProtocolCompositionManifest:
    """Load a closed `protocol_composition.v1` document without side effects."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProtocolCompositionError(f"manifest:read:{error}") from error
    document = _object(
        raw,
        "manifest",
        required={"schema_version", "target", "components", "runtime"},
        allowed={"schema_version", "target", "components", "runtime"},
    )
    if document["schema_version"] != "protocol_composition.v1":
        raise _error("manifest.schema_version", "unsupported")
    target = _object(
        document["target"],
        "target",
        required={"kind", "base_config", "address_width", "data_width"},
        allowed={"kind", "base_config", "address_width", "data_width"},
    )
    target_kind = _string(target["kind"], "target.kind")
    base_config = _string(target["base_config"], "target.base_config")
    address_width = _integer(target["address_width"], "target.address_width")
    data_width = _integer(target["data_width"], "target.data_width")
    if target_kind != "ibex_core":
        raise _error("target.kind", "unsupported")
    if base_config != "ibex_multicomponent_ip":
        raise _error("target.base_config", "unsupported")
    if address_width != 32:
        raise _error("target.address_width", "unsupported")
    if data_width != 32:
        raise _error("target.data_width", "unsupported")
    components_raw = document["components"]
    if not isinstance(components_raw, list) or not components_raw:
        raise _error("components", "type")
    components = tuple(_component(item, index) for index, item in enumerate(components_raw))
    runtime = _object(
        document["runtime"],
        "runtime",
        required={"seed", "duration_seconds", "checkpoint_seconds"},
        allowed={"seed", "duration_seconds", "checkpoint_seconds"},
    )
    seed = _integer(runtime["seed"], "runtime.seed")
    duration_seconds = _integer(runtime["duration_seconds"], "runtime.duration_seconds")
    checkpoint_seconds = _integer(runtime["checkpoint_seconds"], "runtime.checkpoint_seconds")
    if not 0 <= seed <= 0xFFFF_FFFF:
        raise _error("runtime.seed", "out-of-range")
    if duration_seconds <= 0:
        raise _error("runtime.duration_seconds", "not-positive")
    if checkpoint_seconds <= 0 or checkpoint_seconds > duration_seconds:
        raise _error("runtime.checkpoint_seconds", "out-of-range")
    return ProtocolCompositionManifest(
        target_kind=target_kind,
        base_config=base_config,
        address_width=address_width,
        data_width=data_width,
        components=tuple(sorted(components, key=lambda item: item.component_id)),
        seed=seed,
        duration_seconds=duration_seconds,
        checkpoint_seconds=checkpoint_seconds,
    )


def validate_protocol_composition(
    manifest: ProtocolCompositionManifest,
    catalog: ProtocolCatalog,
    registry: ComponentRegistry,
) -> None:
    """Reject every unregistered or structurally unsafe composition before generation."""
    component_ids: set[str] = set()
    irqs: set[int] = set()
    regions: list[tuple[int, int, CompositionComponent]] = []
    address_limit = 1 << manifest.address_width
    for component in sorted(manifest.components, key=lambda item: item._source_index):
        label = f"components[{component._source_index}]"
        if component.component_id in component_ids:
            raise _error(f"{label}.component_id", f"duplicate-id:{component.component_id}")
        component_ids.add(component.component_id)
        try:
            registration = registry.require(component.component_type)
        except KeyError as error:
            raise _error(f"{label}.component_type", f"unknown:{component.component_type}") from error
        missing_source = registry.missing_source(registration)
        if missing_source is not None:
            raise _error(f"registry.{registration.component_type}", f"missing-source:{missing_source}")
        try:
            catalog.require(component.protocol_id, component.protocol_version)
        except ProtocolDefinitionError as error:
            raise _error(f"{label}.protocol", f"unknown:{component.protocol_id}@{component.protocol_version}") from error
        if (component.protocol_id, component.protocol_version) not in registration.supported_protocols:
            raise _error(f"{label}.protocol", f"unsupported:{component.protocol_id}@{component.protocol_version}")
        if component.base < 0 or component.base % 0x1000:
            raise _error(f"{label}.base", "not-4k-aligned")
        required_size = 0x10000 if component.component_type == "ram" else 0x1000
        if component.size != required_size:
            raise _error(f"{label}.size", f"invalid-for:{component.component_type}")
        if component.base + component.size > address_limit:
            raise _error(f"{label}.base", "outside-address-width")
        if component.irq is not None:
            if not registration.irq_capable:
                raise _error(f"{label}.irq", "unsupported")
            if not 0 <= component.irq < 15:
                raise _error(f"{label}.irq", "out-of-range")
            if component.irq in irqs:
                raise _error(f"{label}.irq", f"duplicate:{component.irq}")
            irqs.add(component.irq)
        for parameter_name, parameter_value in component.parameters.items():
            if parameter_name not in registration.parameter_limits:
                raise _error(f"{label}.parameters.{parameter_name}", "unknown")
            lower, upper = registration.parameter_limits[parameter_name]
            if not lower <= parameter_value <= upper:
                raise _error(f"{label}.parameters.{parameter_name}", "out-of-range")
        for parameter_name in registration.parameter_defaults:
            if parameter_name not in component.parameters:
                continue
        for start, end, existing in regions:
            if component.base < end and start < component.base + component.size:
                raise _error(f"{label}.base", f"overlaps:{existing.component_id}")
        regions.append((component.base, component.base + component.size, component))


__all__ = [
    "CompositionComponent",
    "ProtocolCompositionError",
    "ProtocolCompositionManifest",
    "load_protocol_composition",
    "validate_protocol_composition",
]
