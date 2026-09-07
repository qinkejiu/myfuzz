"""Typed, deterministic connection constraints for composition search."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

from myfuzz.contracts import canonical_bytes
from myfuzz.protocols.widths import (
    ProtocolWidthError,
    compile_width_expression,
    width_parameters,
)
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import CompiledProtocol

from .declarations import DeclarationSet, ProtocolBinding
from .endpoint_capabilities import (
    AdapterCapability,
    EndpointCapability,
    match_endpoint_pair,
    normalize_annotations,
)
from .facts import HdlFacts, canonical_structural_value


class ConstraintGraphError(ValueError):
    """Raised when semantic declarations needed by the graph are absent."""


@dataclass(frozen=True, slots=True)
class CapabilityConstraintGraph:
    """Source-backed alternatives kept separate from legacy declaration graphs."""

    endpoints: tuple[EndpointCapability, ...]
    alternatives: tuple[Mapping[str, object], ...]


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    ordinal: int
    record: object


@dataclass(frozen=True, slots=True)
class ProtocolField:
    role: str
    direction: str
    minimum_width: int
    maximum_width: int | None
    required: bool
    width_expression: str | None = None


@dataclass(frozen=True, slots=True)
class AdapterRule:
    kind: str
    source_protocol_id: str
    target_protocol_id: str
    allows_width_mismatch: bool


@dataclass(frozen=True, slots=True)
class ProtocolDefinition:
    protocol_id: str
    endpoint_roles: tuple[str, ...]
    fields: tuple[ProtocolField, ...]
    legal_adapters: tuple[AdapterRule, ...]
    version: str = "1"


@dataclass(frozen=True, slots=True)
class PortNode:
    id: int
    component_id: int
    direction: str
    width: int
    signed: bool
    role: str
    required: bool


@dataclass(frozen=True, slots=True)
class EndpointField:
    role: str
    port_id: int
    protocol_direction: str
    width: int


@dataclass(frozen=True, slots=True)
class EndpointNode:
    id: int
    component_id: int
    protocol_id: str
    side: str
    fields: tuple[EndpointField, ...]
    required: bool
    clock_domain_ids: tuple[int, ...]
    reset_domain_ids: tuple[int, ...]
    version: str = "1"
    parameters: tuple[tuple[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class ForbiddenEdge:
    source_endpoint_id: int
    target_endpoint_id: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Conflict:
    kind: str
    endpoint_ids: tuple[int, ...]
    port_ids: tuple[int, ...]
    detail: str
    provenance: tuple[Evidence, ...] = ()

    @property
    def reason(self) -> str:
        return self.kind

    @property
    def endpoints(self) -> tuple[int, ...]:
        return self.endpoint_ids


@dataclass(frozen=True, slots=True)
class FieldConnection:
    role: str
    source_port_id: int
    target_port_id: int
    source_width: int
    target_width: int


@dataclass(frozen=True, slots=True)
class EdgeCandidate:
    id: int
    kind: str
    source_endpoint_id: int
    target_endpoint_id: int | None
    fields: tuple[FieldConnection, ...]
    adapter: str | None
    evidence: tuple[Evidence, ...]

    @property
    def from_endpoint_id(self) -> int:
        return self.source_endpoint_id

    @property
    def to_endpoint_id(self) -> int | None:
        return self.target_endpoint_id

    @property
    def adapter_id(self) -> str | None:
        return self.adapter

    @property
    def provenance(self) -> tuple[Evidence, ...]:
        return self.evidence


@dataclass(frozen=True, slots=True)
class ConstraintGraph:
    ports: tuple[PortNode, ...]
    endpoints: tuple[EndpointNode, ...]
    protocols: tuple[ProtocolDefinition, ...]
    forbidden_edges: tuple[ForbiddenEdge, ...]
    evidence: tuple[Evidence, ...]
    input_conflicts: tuple[Conflict, ...]

    @property
    def conflicts(self) -> tuple[Conflict, ...]:
        return self.input_conflicts

    @property
    def forbidden(self) -> tuple[ForbiddenEdge, ...]:
        return self.forbidden_edges


_INITIATOR_TO_TARGET = frozenset(("initiator_to_target", "host_to_device"))
_TARGET_TO_INITIATOR = frozenset(("target_to_initiator", "device_to_host"))
_EXTERNAL_ROLES = frozenset(("clock", "reset", "uninterpreted_external"))
_EVIDENCE_SECTION_ORDER = {"dataflow_edges": 0, "control_edges": 1}


def _fail(path: str, reason: str) -> None:
    raise ConstraintGraphError(f"{path}:{reason}")


def _freeze(value: object) -> object:
    return canonical_structural_value(value)


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(path, "missing-explicit-value")
    return value


def _positive_width(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _fail(path, "invalid-width")
    return value


def _field_width(value: object, path: str) -> tuple[int, int | None, str | None]:
    if isinstance(value, int) and not isinstance(value, bool):
        width = _positive_width(value, path)
        return width, width, None
    if isinstance(value, Mapping):
        minimum = _positive_width(value.get("min"), f"{path}.min")
        maximum = _positive_width(value.get("max"), f"{path}.max")
        if minimum > maximum:
            _fail(path, "invalid-range")
        return minimum, maximum, None
    if isinstance(value, str) and value:
        return 1, None, value
    _fail(path, "missing-explicit-width")


def _adapter_rule(value: object, protocol_id: str, index: int) -> AdapterRule:
    path = f"protocols.{protocol_id}.legal_adapters[{index}]"
    if isinstance(value, str) and value:
        return AdapterRule(value, protocol_id, protocol_id, True)
    if isinstance(value, Mapping):
        kind = _string(value.get("kind", value.get("id")), f"{path}.kind")
        source = _string(value.get("source_protocol_id", value.get("from_protocol_id", protocol_id)), f"{path}.source_protocol_id")
        target = _string(value.get("target_protocol_id", value.get("to_protocol_id", protocol_id)), f"{path}.target_protocol_id")
        allows_width = value.get("allows_width_mismatch", value.get("safe", False))
    elif isinstance(value, AdapterRule):
        kind = _string(value.kind, f"{path}.kind")
        source = _string(value.source_protocol_id, f"{path}.source_protocol_id")
        target = _string(value.target_protocol_id, f"{path}.target_protocol_id")
        allows_width = value.allows_width_mismatch
    else:
        _fail(path, "type")
    if not isinstance(allows_width, bool):
        _fail(f"{path}.allows_width_mismatch", "type")
    return AdapterRule(kind, source, target, allows_width)


def _protocol_definition(value: object, path: str) -> ProtocolDefinition:
    if isinstance(value, Mapping):
        protocol_id = _string(value.get("protocol_id"), f"{path}.protocol_id")
        version = _string(
            value.get("plugin_version", value.get("version", "1")),
            f"{path}.plugin_version",
        )
        endpoint_roles_raw = value.get("endpoint_roles", ("initiator", "target"))
        channels = value.get("channels")
        if not isinstance(endpoint_roles_raw, Sequence) or isinstance(endpoint_roles_raw, (str, bytes)):
            _fail(f"{path}.endpoint_roles", "type")
        endpoint_roles = tuple(_string(role, f"{path}.endpoint_roles") for role in endpoint_roles_raw)
        if not isinstance(channels, Sequence) or isinstance(channels, (str, bytes)):
            _fail(f"{path}.channels", "missing")
        raw_fields: list[object] = []
        for channel_index, channel in enumerate(channels):
            if not isinstance(channel, Mapping) or not isinstance(channel.get("fields"), Sequence):
                _fail(f"{path}.channels[{channel_index}].fields", "missing")
            raw_fields.extend(channel["fields"])
        adapters_raw = value.get("legal_adapters", ())
    elif isinstance(value, ProtocolDefinition):
        protocol_id = _string(value.protocol_id, f"{path}.protocol_id")
        version = _string(value.version, f"{path}.version")
        endpoint_roles_raw = value.endpoint_roles
        raw_fields = list(value.fields)
        adapters_raw = value.legal_adapters
    else:
        protocol_id = _string(getattr(value, "protocol_id", None), f"{path}.protocol_id")
        version = _string(
            getattr(value, "version", getattr(value, "plugin_version", "1")),
            f"{path}.version",
        )
        endpoint_roles_raw = getattr(value, "endpoint_roles", ("initiator", "target"))
        raw_fields = list(getattr(value, "fields", ()))
        adapters_raw = getattr(value, "legal_adapters", ())

    if not isinstance(endpoint_roles_raw, Sequence) or isinstance(endpoint_roles_raw, (str, bytes)):
        _fail(f"{path}.endpoint_roles", "type")
    endpoint_roles = tuple(_string(role, f"{path}.endpoint_roles") for role in endpoint_roles_raw)
    if not endpoint_roles:
        _fail(f"{path}.endpoint_roles", "missing")
    if len(endpoint_roles) != len(set(endpoint_roles)):
        _fail(f"{path}.endpoint_roles", "duplicate")
    if not isinstance(adapters_raw, Sequence) or isinstance(adapters_raw, (str, bytes)):
        _fail(f"{path}.legal_adapters", "type")
    fields: list[ProtocolField] = []
    seen_roles: set[str] = set()
    for index, raw_field in enumerate(raw_fields):
        field_path = f"{path}.fields[{index}]"
        if isinstance(raw_field, Mapping):
            role = _string(raw_field.get("role", raw_field.get("field_id")), f"{field_path}.role")
            direction = _string(raw_field.get("direction"), f"{field_path}.direction")
            minimum, maximum, width_expression = _field_width(
                raw_field.get("width", raw_field.get("width_expression")),
                f"{field_path}.width",
            )
            required = raw_field.get("required")
        elif isinstance(raw_field, ProtocolField):
            role = _string(raw_field.role, f"{field_path}.role")
            direction = _string(raw_field.direction, f"{field_path}.direction")
            minimum = _positive_width(raw_field.minimum_width, f"{field_path}.width.min")
            maximum = raw_field.maximum_width
            if maximum is not None:
                maximum = _positive_width(maximum, f"{field_path}.width.max")
                if minimum > maximum:
                    _fail(f"{field_path}.width", "invalid-range")
            required = raw_field.required
            width_expression = raw_field.width_expression
        else:
            role = _string(getattr(raw_field, "role", getattr(raw_field, "field_id", None)), f"{field_path}.role")
            direction = _string(getattr(raw_field, "direction", None), f"{field_path}.direction")
            minimum, maximum, width_expression = _field_width(
                getattr(raw_field, "width", getattr(raw_field, "width_expression", None)),
                f"{field_path}.width",
            )
            required = getattr(raw_field, "required", True)
        if direction not in _INITIATOR_TO_TARGET and direction not in _TARGET_TO_INITIATOR:
            _fail(f"{field_path}.direction", "invalid")
        if not isinstance(required, bool):
            _fail(f"{field_path}.required", "missing")
        if role in seen_roles:
            _fail(f"{field_path}.role", "duplicate")
        seen_roles.add(role)
        fields.append(
            ProtocolField(
                role,
                direction,
                minimum,
                maximum,
                required,
                width_expression,
            )
        )
    if not fields:
        _fail(f"{path}.fields", "missing")
    adapters_list: list[AdapterRule] = []
    seen_adapters: dict[tuple[str, str, str], AdapterRule] = {}
    for index, item in enumerate(adapters_raw):
        adapter = _adapter_rule(item, protocol_id, index)
        identity = (adapter.source_protocol_id, adapter.target_protocol_id, adapter.kind)
        previous = seen_adapters.get(identity)
        if previous is not None:
            reason = "duplicate-identity" if previous == adapter else "conflicting-identity"
            _fail(f"{path}.legal_adapters[{index}]", reason)
        seen_adapters[identity] = adapter
        adapters_list.append(adapter)
    adapters = tuple(sorted(adapters_list, key=lambda item: (item.source_protocol_id, item.target_protocol_id, item.kind, item.allows_width_mismatch)))
    return ProtocolDefinition(
        protocol_id,
        tuple(sorted(endpoint_roles)),
        tuple(sorted(fields, key=lambda item: item.role)),
        adapters,
        version,
    )


def _normalize_protocols(protocols: object) -> tuple[ProtocolDefinition, ...]:
    if isinstance(protocols, Mapping):
        if "protocol_id" in protocols:
            values = (protocols,)
        else:
            canonical_keys = [str(key) for key in protocols]
            if len(canonical_keys) != len(set(canonical_keys)):
                _fail("protocols", "duplicate-key")
            values = tuple(protocols[key] for key in sorted(protocols, key=str))
    elif hasattr(protocols, "plugins"):
        values = tuple(getattr(protocols, "plugins"))
    elif isinstance(protocols, Sequence) and not isinstance(protocols, (str, bytes)):
        values = tuple(protocols)
    else:
        _fail("protocols", "type")
    definitions = tuple(
        sorted(
            (
                _protocol_definition(value, f"protocols[{index}]")
                for index, value in enumerate(values)
            ),
            key=lambda item: (item.protocol_id, item.version),
        )
    )
    keys = [(item.protocol_id, item.version) for item in definitions]
    if len(keys) != len(set(keys)):
        _fail("protocols", "duplicate-protocol-version")
    adapter_identities: dict[tuple[str, str, str, str], AdapterRule] = {}
    for definition in definitions:
        for adapter in definition.legal_adapters:
            identity = (
                definition.version,
                adapter.source_protocol_id,
                adapter.target_protocol_id,
                adapter.kind,
            )
            previous = adapter_identities.get(identity)
            if previous is not None:
                reason = "duplicate-adapter-identity" if previous == adapter else "conflicting-adapter-identity"
                _fail("protocols", reason)
            adapter_identities[identity] = adapter
    return definitions


def _expected_direction(protocol_direction: str, side: str) -> str:
    if protocol_direction in _INITIATOR_TO_TARGET:
        return "output" if side == "initiator" else "input"
    return "input" if side == "initiator" else "output"


def _collect_evidence(facts: HdlFacts) -> tuple[Evidence, ...]:
    result: list[Evidence] = []
    for section, records in facts.structural_sections:
        if section not in ("dataflow_edges", "control_edges"):
            continue
        frozen_records = sorted((_freeze(record) for record in records), key=canonical_bytes)
        for ordinal, record in enumerate(frozen_records):
            result.append(Evidence(section, ordinal, record))
    return tuple(
        sorted(
            result,
            key=lambda item: (_EVIDENCE_SECTION_ORDER[item.kind], item.ordinal, canonical_bytes(item.record)),
        )
    )


def _make_endpoint(
    binding: ProtocolBinding,
    component: object,
    port_nodes: Mapping[int, PortNode],
    protocol: ProtocolDefinition,
    evidence: tuple[Evidence, ...],
) -> tuple[EndpointNode, tuple[Conflict, ...]]:
    component_id = int(getattr(component, "id"))
    if binding.version is not None and binding.version != protocol.version:
        _fail(
            f"components.{component_id}.protocol_bindings.{binding.id}.version",
            "protocol-version-mismatch",
        )
    if binding.side not in protocol.endpoint_roles or binding.side not in ("initiator", "target"):
        _fail(f"components.{component_id}.protocol_bindings.{binding.id}.side", "invalid")
    field_specs = {field.role: field for field in protocol.fields}
    parameters = dict(binding.parameters)
    try:
        width_parameters(parameters)
    except ProtocolWidthError as error:
        _fail(
            f"components.{component_id}.protocol_bindings.{binding.id}.parameters",
            str(error),
        )
    bound_roles = {field.field_role for field in binding.fields}
    missing = tuple(field.role for field in protocol.fields if field.required and field.role not in bound_roles)
    if missing:
        _fail(f"components.{component_id}.protocol_bindings.{binding.id}.fields", f"missing-required:{','.join(missing)}")
    endpoint_fields: list[EndpointField] = []
    conflicts: list[Conflict] = []
    for field in binding.fields:
        if field.field_role not in field_specs:
            _fail(f"components.{component_id}.protocol_bindings.{binding.id}.fields", f"unknown-role:{field.field_role}")
        port = port_nodes[field.port_id]
        if port.role != field.field_role:
            _fail(f"components.{component_id}.protocol_bindings.{binding.id}.fields", f"role-conflict:{field.port_id}")
        spec = field_specs[field.field_role]
        expected = _expected_direction(spec.direction, binding.side)
        if port.direction not in (expected, "inout"):
            conflicts.append(Conflict("direction", (binding.id,), (port.id,), f"expected {expected}, found {port.direction}", evidence))
        expected_width: int | None = None
        if spec.width_expression is not None:
            try:
                expected_width = compile_width_expression(
                    spec.width_expression,
                    parameters,
                )
            except ProtocolWidthError as error:
                _fail(
                    f"components.{component_id}.protocol_bindings.{binding.id}.parameters",
                    str(error),
                )
        if expected_width is not None and port.width != expected_width:
            conflicts.append(
                Conflict(
                    "width",
                    (binding.id,),
                    (port.id,),
                    f"expected compiled width {expected_width}, found {port.width}",
                    evidence,
                )
            )
        elif port.width < spec.minimum_width or (spec.maximum_width is not None and port.width > spec.maximum_width):
            conflicts.append(Conflict("width", (binding.id,), (port.id,), "port width is outside the declared protocol range", evidence))
        endpoint_fields.append(EndpointField(field.field_role, port.id, spec.direction, port.width))
    clock_domains = tuple(sorted(item.domain_id for item in getattr(component, "clock_reset") if item.kind == "clock"))
    reset_domains = tuple(sorted(item.domain_id for item in getattr(component, "clock_reset") if item.kind == "reset"))
    return (
        EndpointNode(
            binding.id,
            component_id,
            binding.protocol_id,
            binding.side,
            tuple(sorted(endpoint_fields, key=lambda item: (item.role, item.port_id))),
            any(port_nodes[field.port_id].required for field in binding.fields),
            clock_domains,
            reset_domains,
            binding.version or protocol.version,
            binding.parameters,
        ),
        tuple(conflicts),
    )


def _cross_adapter(
    protocols: Mapping[tuple[str, str], ProtocolDefinition],
    source: EndpointNode,
    target: EndpointNode,
) -> AdapterRule | None:
    source_key = (source.protocol_id, source.version)
    target_key = (target.protocol_id, target.version)
    rules = protocols[source_key].legal_adapters + protocols[target_key].legal_adapters
    matches = [
        rule
        for rule in rules
        if (rule.source_protocol_id, rule.target_protocol_id)
        == (source.protocol_id, target.protocol_id)
    ]
    return min(matches, key=lambda item: item.kind) if matches else None


def _same_protocol_width_adapter(protocol: ProtocolDefinition) -> AdapterRule | None:
    matches = [rule for rule in protocol.legal_adapters if rule.source_protocol_id == protocol.protocol_id and rule.target_protocol_id == protocol.protocol_id and rule.allows_width_mismatch]
    return min(matches, key=lambda item: item.kind) if matches else None


def _pair_constraints(
    source: EndpointNode,
    target: EndpointNode,
    protocols: Mapping[tuple[str, str], ProtocolDefinition],
) -> tuple[tuple[str, ...], str | None]:
    reasons: list[str] = []
    adapter: AdapterRule | None = None
    if source.component_id == target.component_id:
        reasons.append("self_connection")
    if source.side != "initiator" or target.side != "target":
        reasons.append("side")
    source_protocol_key = (source.protocol_id, source.version)
    target_protocol_key = (target.protocol_id, target.version)
    if source_protocol_key != target_protocol_key:
        if source.protocol_id != target.protocol_id:
            adapter = _cross_adapter(protocols, source, target)
        if adapter is None:
            reasons.append("protocol")
    if bool(source.clock_domain_ids) != bool(target.clock_domain_ids) or (source.clock_domain_ids and target.clock_domain_ids and source.clock_domain_ids != target.clock_domain_ids):
        reasons.append("domain")
    if bool(source.reset_domain_ids) != bool(target.reset_domain_ids) or (source.reset_domain_ids and target.reset_domain_ids and source.reset_domain_ids != target.reset_domain_ids):
        reasons.append("domain")
    source_fields = {field.role: field for field in source.fields}
    target_fields = {field.role: field for field in target.fields}
    if source_fields.keys() != target_fields.keys():
        reasons.append("protocol_field")
    for role in sorted(source_fields.keys() & target_fields.keys()):
        left, right = source_fields[role], target_fields[role]
        expected_left = _expected_direction(left.protocol_direction, source.side)
        expected_right = _expected_direction(right.protocol_direction, target.side)
        if expected_left == expected_right:
            reasons.append("direction")
        if left.width != right.width:
            width_adapter = (
                adapter
                if adapter is not None and adapter.allows_width_mismatch
                else _same_protocol_width_adapter(protocols[source_protocol_key])
                if source_protocol_key == target_protocol_key
                else None
            )
            if width_adapter is None:
                reasons.append("width")
            elif adapter is None:
                adapter = width_adapter
    return tuple(dict.fromkeys(reasons)), adapter.kind if adapter is not None else None


def build_constraint_graph(facts: HdlFacts, declarations: DeclarationSet, protocols: object) -> ConstraintGraph:
    """Build a normalized graph using only typed facts and explicit declarations."""
    declarations.validate_against(facts)
    definitions = _normalize_protocols(protocols)
    protocol_by_key = {
        (item.protocol_id, item.version): item
        for item in definitions
    }
    protocols_by_id: dict[str, tuple[ProtocolDefinition, ...]] = {}
    for definition in definitions:
        protocols_by_id[definition.protocol_id] = (
            *protocols_by_id.get(definition.protocol_id, ()),
            definition,
        )
    fact_ports = {port.id: port for port in facts.ports}
    port_nodes: list[PortNode] = []
    for component in declarations.components:
        for declaration in component.ports:
            fact = fact_ports[declaration.port_id]
            port_nodes.append(PortNode(fact.id, component.id, fact.direction, fact.width, fact.signed, declaration.role, declaration.required))
    port_nodes.sort(key=lambda item: item.id)
    port_by_id = {port.id: port for port in port_nodes}
    evidence = _collect_evidence(facts)
    endpoints: list[EndpointNode] = []
    input_conflicts: list[Conflict] = []
    bound_ports: set[int] = set()
    for component in declarations.components:
        for binding in component.protocol_bindings:
            matching_protocols = protocols_by_id.get(binding.protocol_id, ())
            if not matching_protocols:
                _fail(f"components.{component.id}.protocol_bindings.{binding.id}.protocol_id", "unsupported")
            if binding.version is None:
                if len(matching_protocols) != 1:
                    _fail(
                        f"components.{component.id}.protocol_bindings.{binding.id}.version",
                        "protocol-version-ambiguous",
                    )
                protocol = matching_protocols[0]
            else:
                protocol = protocol_by_key.get((binding.protocol_id, binding.version))
                if protocol is None:
                    _fail(
                        f"components.{component.id}.protocol_bindings.{binding.id}.version",
                        "protocol-version-unsupported",
                    )
            for field in binding.fields:
                if field.port_id in bound_ports:
                    _fail(f"components.{component.id}.protocol_bindings.{binding.id}.fields", f"duplicate-port:{field.port_id}")
                bound_ports.add(field.port_id)
            endpoint, conflicts = _make_endpoint(
                binding,
                component,
                port_by_id,
                protocol,
                evidence,
            )
            endpoints.append(endpoint)
            input_conflicts.extend(conflicts)
    for port in port_nodes:
        if port.role not in _EXTERNAL_ROLES and port.id not in bound_ports:
            _fail(f"ports.{port.id}.protocol_binding", "missing")
    endpoints.sort(key=lambda item: item.id)
    forbidden: list[ForbiddenEdge] = []
    for first_index, first in enumerate(endpoints):
        for second in endpoints[first_index + 1 :]:
            source, target = (first, second)
            if second.side == "initiator" and first.side == "target":
                source, target = second, first
            reasons, _ = _pair_constraints(source, target, protocol_by_key)
            if reasons:
                forbidden.append(ForbiddenEdge(source.id, target.id, reasons))
    return ConstraintGraph(
        tuple(port_nodes),
        tuple(endpoints),
        definitions,
        tuple(sorted(forbidden, key=lambda item: (item.source_endpoint_id, item.target_endpoint_id))),
        evidence,
        tuple(sorted(input_conflicts, key=lambda item: (item.kind, item.endpoint_ids, item.port_ids))),
    )


def build_capability_constraint_graph(
    annotations: Mapping[str, object], adapters: Sequence[AdapterCapability], *,
    protocol_catalog: ProtocolCatalog | None = None,
    compiled_protocols: Mapping[str, CompiledProtocol] | None = None,
) -> CapabilityConstraintGraph:
    """Build generic source-backed alternatives without changing legacy callers."""
    endpoints = normalize_annotations(annotations)
    alternatives = tuple(
        alternative
        for source in endpoints
        for target in endpoints
        if source.endpoint_id != target.endpoint_id
        for alternative in match_endpoint_pair(
            source, target, adapters,
            protocol_catalog=protocol_catalog,
            compiled_protocols=compiled_protocols,
        )
    )
    return CapabilityConstraintGraph(endpoints, alternatives)


def _forbidden(graph: ConstraintGraph, source_id: int, target_id: int) -> ForbiddenEdge | None:
    # ``forbidden_edges`` is sorted by endpoint IDs; binary search keeps
    # enumeration bounded without materializing a second lookup table.
    low, high = 0, len(graph.forbidden_edges)
    while low < high:
        middle = (low + high) // 2
        edge = graph.forbidden_edges[middle]
        key = (edge.source_endpoint_id, edge.target_endpoint_id)
        if key < (source_id, target_id):
            low = middle + 1
        else:
            high = middle
    if low < len(graph.forbidden_edges):
        edge = graph.forbidden_edges[low]
        if (edge.source_endpoint_id, edge.target_endpoint_id) == (source_id, target_id):
            return edge
    return None


def _relevant_evidence(evidence: tuple[Evidence, ...], port_ids: set[int]) -> tuple[Evidence, ...]:
    def includes(value: object) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return value in port_ids
        if isinstance(value, tuple):
            return any(includes(item) for item in value)
        return False

    return tuple(item for item in evidence if includes(item.record))


def _edge_id(kind: str, source_id: int, target_id: int | None) -> int:
    payload = f"{kind}:{source_id}:{target_id if target_id is not None else 0}".encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _candidate(source: EndpointNode, target: EndpointNode, graph: ConstraintGraph) -> EdgeCandidate:
    protocols = {(item.protocol_id, item.version): item for item in graph.protocols}
    _, adapter = _pair_constraints(source, target, protocols)
    target_fields = {field.role: field for field in target.fields}
    fields: list[FieldConnection] = []
    port_ids: set[int] = set()
    for left in source.fields:
        right = target_fields[left.role]
        if left.protocol_direction in _INITIATOR_TO_TARGET:
            producer, consumer = left, right
        else:
            producer, consumer = right, left
        fields.append(FieldConnection(left.role, producer.port_id, consumer.port_id, producer.width, consumer.width))
        port_ids.update((left.port_id, right.port_id))
    return EdgeCandidate(
        _edge_id("connection", source.id, target.id),
        "connection",
        source.id,
        target.id,
        tuple(sorted(fields, key=lambda item: (item.role, item.source_port_id, item.target_port_id))),
        adapter,
        _relevant_evidence(graph.evidence, port_ids),
    )


def _endpoint_has_input_conflict(graph: ConstraintGraph, endpoint_id: int) -> bool:
    return any(endpoint_id in conflict.endpoint_ids for conflict in graph.input_conflicts)


def candidate_edges(graph: ConstraintGraph) -> Iterator[EdgeCandidate]:
    """Yield internal connections, then orphan optional externals, in ID order."""
    connected: set[int] = set()
    for first_index, first in enumerate(graph.endpoints):
        for second in graph.endpoints[first_index + 1 :]:
            source, target = first, second
            if second.side == "initiator" and first.side == "target":
                source, target = second, first
            if _endpoint_has_input_conflict(graph, source.id) or _endpoint_has_input_conflict(graph, target.id):
                continue
            if _forbidden(graph, source.id, target.id) is not None:
                continue
            connected.update((source.id, target.id))
            yield _candidate(source, target, graph)
    for endpoint in graph.endpoints:
        if not endpoint.required and endpoint.id not in connected:
            yield EdgeCandidate(_edge_id("external", endpoint.id, None), "external", endpoint.id, None, (), None, ())


def _matched_endpoint_ids(graph: ConstraintGraph, edges: Sequence[EdgeCandidate]) -> set[int]:
    """Return endpoints covered by a deterministic maximum bipartite matching."""
    endpoint_by_id = {endpoint.id: endpoint for endpoint in graph.endpoints}
    adjacency: dict[int, tuple[int, ...]] = {}
    for edge in edges:
        if edge.kind != "connection" or edge.target_endpoint_id is None:
            continue
        adjacency.setdefault(edge.source_endpoint_id, tuple())
        adjacency[edge.source_endpoint_id] = tuple(sorted((*adjacency[edge.source_endpoint_id], edge.target_endpoint_id)))

    source_ids = tuple(endpoint.id for endpoint in graph.endpoints if endpoint.side == "initiator")
    target_ids = tuple(endpoint.id for endpoint in graph.endpoints if endpoint.side == "target")
    dummy_target_nodes = tuple(("dummy_target", source_id) for source_id in source_ids)
    augmented_adjacency: dict[tuple[str, int], tuple[tuple[str, int], ...]] = {}
    for source_id in source_ids:
        targets = tuple(("target", target_id) for target_id in adjacency.get(source_id, ()))
        if not endpoint_by_id[source_id].required:
            targets += dummy_target_nodes
        augmented_adjacency[("source", source_id)] = targets
    optional_targets = tuple(("target", target_id) for target_id in target_ids if not endpoint_by_id[target_id].required)
    for target_id in target_ids:
        augmented_adjacency[("dummy_source", target_id)] = optional_targets + dummy_target_nodes

    augmented_match: dict[tuple[str, int], tuple[str, int]] = {}

    def augment_required(left: tuple[str, int], visited: set[tuple[str, int]]) -> bool:
        for right in augmented_adjacency[left]:
            if right in visited:
                continue
            visited.add(right)
            previous_left = augmented_match.get(right)
            if previous_left is None or augment_required(previous_left, visited):
                augmented_match[right] = left
                return True
        return False

    augmented_left = tuple(("source", source_id) for source_id in source_ids) + tuple(("dummy_source", target_id) for target_id in target_ids)
    if all(augment_required(left, set()) for left in augmented_left):
        return {endpoint.id for endpoint in graph.endpoints if endpoint.required}

    matched_target_to_source: dict[int, int] = {}

    def augment(source_id: int, visited_targets: set[int]) -> bool:
        for target_id in adjacency.get(source_id, ()):
            if target_id in visited_targets:
                continue
            visited_targets.add(target_id)
            previous_source = matched_target_to_source.get(target_id)
            if previous_source is None or augment(previous_source, visited_targets):
                matched_target_to_source[target_id] = source_id
                return True
        return False

    sources = sorted(
        (endpoint for endpoint in graph.endpoints if endpoint.side == "initiator"),
        key=lambda endpoint: (not endpoint.required, endpoint.id),
    )
    adjacency = {
        source_id: tuple(sorted(target_ids, key=lambda target_id: (not endpoint_by_id[target_id].required, target_id)))
        for source_id, target_ids in adjacency.items()
    }
    for source in sources:
        augment(source.id, set())

    matched_source_ids = set(matched_target_to_source.values())
    return matched_source_ids | set(matched_target_to_source)


def reject_hard_conflicts(graph: ConstraintGraph) -> list[Conflict]:
    """Return deterministic conflicts that prevent required endpoint coverage."""
    conflicts = list(graph.input_conflicts)
    edges = list(candidate_edges(graph))
    connected = _matched_endpoint_ids(graph, edges)
    endpoint_by_id = {endpoint.id: endpoint for endpoint in graph.endpoints}
    seen = {(item.kind, item.endpoint_ids, item.port_ids) for item in conflicts}
    for endpoint in graph.endpoints:
        if not endpoint.required or endpoint.id in connected:
            continue
        related = [edge for edge in graph.forbidden_edges if endpoint.id in (edge.source_endpoint_id, edge.target_endpoint_id)]
        for edge in related:
            pair = (edge.source_endpoint_id, edge.target_endpoint_id)
            port_ids = tuple(sorted(field.port_id for endpoint_id in pair for field in endpoint_by_id[endpoint_id].fields))
            for reason in edge.reasons:
                key = (reason, pair, port_ids)
                if key not in seen:
                    conflicts.append(Conflict(reason, pair, port_ids, "candidate edge is forbidden", _relevant_evidence(graph.evidence, set(port_ids))))
                    seen.add(key)
        port_ids = tuple(field.port_id for field in endpoint.fields)
        key = ("required_cardinality", (endpoint.id,), port_ids)
        if key not in seen:
            conflicts.append(Conflict("required_cardinality", (endpoint.id,), port_ids, "required endpoint has no legal connection"))
            seen.add(key)
    return sorted(conflicts, key=lambda item: (item.kind, item.endpoint_ids, item.port_ids, item.detail))


__all__ = [
    "Adapter",
    "CapabilityConstraintGraph",
    "AdapterRule",
    "Conflict",
    "ConstraintGraph",
    "ConstraintGraphError",
    "EdgeCandidate",
    "EndpointField",
    "EndpointNode",
    "Evidence",
    "FieldConnection",
    "FieldSpec",
    "ForbiddenEdge",
    "PortNode",
    "ProtocolDefinition",
    "ProtocolField",
    "ProtocolSpec",
    "build_constraint_graph",
    "build_capability_constraint_graph",
    "candidate_edges",
    "reject_hard_conflicts",
]

# Friendly aliases for callers that use the more generic specification names.
Adapter = AdapterRule
FieldSpec = ProtocolField
ProtocolSpec = ProtocolDefinition
