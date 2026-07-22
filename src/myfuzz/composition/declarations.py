"""Validation for explicit, name-independent composition declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .facts import HdlFacts
from .ids import canonical_id


class DeclarationError(ValueError):
    """Stable validation error formatted as ``path:reason``."""


@dataclass(frozen=True)
class PortDecl:
    port_id: int
    role: str
    required: bool


@dataclass(frozen=True)
class ProtocolFieldBinding:
    field_role: str
    port_id: int


@dataclass(frozen=True)
class ProtocolBinding:
    id: int
    protocol_id: str
    side: str
    fields: tuple[ProtocolFieldBinding, ...]


@dataclass(frozen=True)
class ClockResetDecl:
    port_id: int
    kind: str
    domain_id: int
    active_level: str
    synchronous: bool


@dataclass(frozen=True)
class ComponentDecl:
    id: int
    module_id: int
    role: str
    ports: tuple[PortDecl, ...]
    protocol_bindings: tuple[ProtocolBinding, ...]
    clock_reset: tuple[ClockResetDecl, ...]


@dataclass(frozen=True)
class DeclarationSet:
    components: tuple[ComponentDecl, ...]

    def validate_against(self, facts: HdlFacts) -> None:
        """Check every declared component endpoint against structural facts."""
        known_modules = {module.id for module in facts.modules}
        seen_modules: set[int] = set()
        for component_index, component in enumerate(self.components):
            component_path = f"components[{component_index}]"
            if component.module_id not in known_modules:
                _fail(f"{component_path}.module_id:unresolved-reference")
            if component.module_id in seen_modules:
                _fail(f"{component_path}.module_id:duplicate-module")
            seen_modules.add(component.module_id)

            fact_ports = {port.id: port for port in facts.ports_for_module(component.module_id)}
            declared_ports = {port.port_id: port for port in component.ports}
            for port_id in sorted(fact_ports.keys() - declared_ports.keys()):
                _fail(f"{component_path}.ports:missing-fact-port:{port_id}")
            for port_id in sorted(declared_ports.keys() - fact_ports.keys()):
                _fail(f"{component_path}.ports:unresolved-reference:{port_id}")
            for port_id, port in declared_ports.items():
                fact_port = fact_ports[port_id]
                if port.role != fact_port.declared_role:
                    _fail(f"{component_path}.ports:{port_id}:role-conflict")

            for binding_index, binding in enumerate(component.protocol_bindings):
                for field_index, field in enumerate(binding.fields):
                    if field.port_id not in declared_ports:
                        _fail(
                            f"{component_path}.protocol_bindings[{binding_index}]"
                            f".fields[{field_index}].port_id:unresolved-reference"
                        )

            clock_reset_ports: set[int] = set()
            for declaration_index, declaration in enumerate(component.clock_reset):
                path = f"{component_path}.clock_reset[{declaration_index}]"
                if declaration.port_id not in declared_ports:
                    _fail(f"{path}.port_id:unresolved-reference")
                if declaration.port_id in clock_reset_ports:
                    _fail(f"{path}.port_id:duplicate-id")
                clock_reset_ports.add(declaration.port_id)
                if declared_ports[declaration.port_id].role != declaration.kind:
                    _fail(f"{path}.kind:role-conflict")
            for port in component.ports:
                if port.role in ("clock", "reset") and port.port_id not in clock_reset_ports:
                    _fail(f"{component_path}.clock_reset:missing-port:{port.port_id}")


def _fail(message: str) -> None:
    raise DeclarationError(message)


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(f"{path}:type")
    return value


def _array(value: object, path: str) -> Sequence[object]:
    if not isinstance(value, list):
        _fail(f"{path}:type")
    return value


def _string(record: Mapping[str, object], key: str, path: str) -> str:
    if key not in record:
        _fail(f"{path}.{key}:missing")
    value = record[key]
    if not isinstance(value, str) or not value:
        _fail(f"{path}.{key}:type")
    return value


def _positive_int(record: Mapping[str, object], key: str, path: str) -> int:
    if key not in record:
        _fail(f"{path}.{key}:missing")
    value = record[key]
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _fail(f"{path}.{key}:invalid-id")
    return value


def _boolean(record: Mapping[str, object], key: str, path: str) -> bool:
    if key not in record:
        _fail(f"{path}.{key}:missing")
    value = record[key]
    if not isinstance(value, bool):
        _fail(f"{path}.{key}:type")
    return value


def _opaque_id(record: Mapping[str, object], key: str, kind: str, path: str) -> int:
    return canonical_id(kind, _string(record, key, path))


def _unique(values: Sequence[int], path: str) -> None:
    if len(values) != len(set(values)):
        for index, value in enumerate(values):
            if value in values[:index]:
                _fail(f"{path}[{index}].id:duplicate-id")


def _parse_ports(value: object, path: str) -> tuple[PortDecl, ...]:
    ports: list[PortDecl] = []
    ids: set[int] = set()
    for index, item in enumerate(_array(value, f"{path}.ports")):
        item_path = f"{path}.ports[{index}]"
        record = _mapping(item, item_path)
        port_id = _positive_int(record, "port_id", item_path)
        if port_id in ids:
            _fail(f"{item_path}.port_id:duplicate-id")
        ids.add(port_id)
        ports.append(PortDecl(port_id, _string(record, "role", item_path), _boolean(record, "required", item_path)))
    return tuple(sorted(ports, key=lambda port: port.port_id))


def _parse_protocols(value: object, path: str) -> tuple[ProtocolBinding, ...]:
    bindings: list[ProtocolBinding] = []
    ids: list[int] = []
    for index, item in enumerate(_array(value, f"{path}.protocol_bindings")):
        item_path = f"{path}.protocol_bindings[{index}]"
        record = _mapping(item, item_path)
        binding_id = _opaque_id(record, "id", "protocol_binding", item_path)
        ids.append(binding_id)
        fields: list[ProtocolFieldBinding] = []
        roles: set[str] = set()
        for field_index, field_value in enumerate(_array(record.get("fields"), f"{item_path}.fields")):
            field_path = f"{item_path}.fields[{field_index}]"
            field = _mapping(field_value, field_path)
            field_role = _string(field, "field_role", field_path)
            if field_role in roles:
                _fail(f"{field_path}.field_role:duplicate-role")
            roles.add(field_role)
            fields.append(ProtocolFieldBinding(field_role, _positive_int(field, "port_id", field_path)))
        bindings.append(
            ProtocolBinding(
                id=binding_id,
                protocol_id=_string(record, "protocol_id", item_path),
                side=_string(record, "side", item_path),
                fields=tuple(sorted(fields, key=lambda field: (field.field_role, field.port_id))),
            )
        )
    _unique(ids, f"{path}.protocol_bindings")
    return tuple(sorted(bindings, key=lambda binding: binding.id))


def _parse_clock_reset(value: object, path: str) -> tuple[ClockResetDecl, ...]:
    declarations: list[ClockResetDecl] = []
    for index, item in enumerate(_array(value, f"{path}.clock_reset")):
        item_path = f"{path}.clock_reset[{index}]"
        record = _mapping(item, item_path)
        kind = _string(record, "kind", item_path)
        if kind not in ("clock", "reset"):
            _fail(f"{item_path}.kind:invalid")
        active_level = _string(record, "active_level", item_path)
        if active_level not in ("high", "low"):
            _fail(f"{item_path}.active_level:invalid")
        declarations.append(
            ClockResetDecl(
                port_id=_positive_int(record, "port_id", item_path),
                kind=kind,
                domain_id=_opaque_id(record, "domain_id", "clock_reset_domain", item_path),
                active_level=active_level,
                synchronous=_boolean(record, "synchronous", item_path),
            )
        )
    return tuple(sorted(declarations, key=lambda declaration: declaration.port_id))


def load_declarations(path: Path) -> DeclarationSet:
    """Load a declaration document, retaining only semantic data and numeric IDs."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise DeclarationError(f"document:read:{error.strerror}") from error
    except json.JSONDecodeError as error:
        raise DeclarationError(f"document:json:{error.msg}") from error
    root = _mapping(document, "document")
    if root.get("schema_version") != "composition_declarations.v1":
        _fail("schema_version:unsupported")

    components: list[ComponentDecl] = []
    component_ids: list[int] = []
    for index, item in enumerate(_array(root.get("components"), "components")):
        component_path = f"components[{index}]"
        record = _mapping(item, component_path)
        component_id = _opaque_id(record, "id", "component", component_path)
        component_ids.append(component_id)
        components.append(
            ComponentDecl(
                id=component_id,
                module_id=_positive_int(record, "module_id", component_path),
                role=_string(record, "role", component_path),
                ports=_parse_ports(record.get("ports"), component_path),
                protocol_bindings=_parse_protocols(record.get("protocol_bindings", []), component_path),
                clock_reset=_parse_clock_reset(record.get("clock_reset", []), component_path),
            )
        )
    _unique(component_ids, "components")
    return DeclarationSet(tuple(sorted(components, key=lambda component: component.id)))
