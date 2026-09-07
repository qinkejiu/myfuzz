"""Generic, source-backed endpoint capabilities and protocol matching.

This module deliberately operates on semantic field roles and HDL facts.  HDL
port spelling is retained only in the source annotation and is never used to
select or rank a composition candidate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import CompiledProtocol, ProtocolDefinitionError


class EndpointCapabilityError(ValueError):
    """Raised when source-backed endpoint annotations are structurally invalid."""


@dataclass(frozen=True, slots=True)
class EndpointFieldFact:
    role: str
    port: str
    direction: str
    width: int
    signed: bool
    source: "SourceReference | None" = None
    evidence: tuple[str, ...] = ()
    member_path: tuple[str, ...] = ()
    raw_lo: int | None = None
    raw_hi: int | None = None
    container_width: int | None = None


@dataclass(frozen=True, slots=True)
class SourceReference:
    """Path-independent location inside the pinned source tree."""

    file: str
    line: int
    column: int | None = None


@dataclass(frozen=True, slots=True)
class TimingFact:
    kind: str
    fields: tuple[str, ...]
    clock: str | None
    max_latency: int | None = None
    source: SourceReference | None = None
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EndpointCapability:
    endpoint_id: str
    function: str
    side: str | None
    protocol: tuple[str, str] | None
    fields: tuple[EndpointFieldFact, ...]
    clock: str | None
    reset: str | None
    timing: tuple[TimingFact, ...]
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AdapterCapability:
    adapter_id: str
    source_protocol: tuple[str, str]
    target_protocol: tuple[str, str]
    features: tuple[str, ...]
    max_latency: int | None = None
    allows_width_projection: bool = False
    width_projection_fields: tuple[str, ...] = ()


_DIRECTIONS = frozenset(("input", "output", "inout"))
_SIDES = frozenset(("initiator", "target"))


def _error(path: str, reason: str) -> None:
    raise EndpointCapabilityError(f"{path}:{reason}")


def _name(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        _error(path, "missing")
    return value


def _nullable_name(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _name(value, path)


def _protocol(value: object, path: str) -> tuple[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 2:
        _error(path, "invalid")
    return (_name(value[0], f"{path}.id"), _name(value[1], f"{path}.version"))


def _candidate_protocol(endpoint: Mapping[str, object], path: str) -> tuple[tuple[str, str] | None, str | None]:
    direct = _protocol(endpoint.get("protocol"), f"{path}.protocol")
    direct_side = endpoint.get("side")
    if direct_side is not None and direct_side not in _SIDES:
        _error(f"{path}.side", "invalid")
    if direct is not None:
        return direct, direct_side if isinstance(direct_side, str) else None
    candidates = endpoint.get("protocol_candidates", ())
    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)):
        _error(f"{path}.protocol_candidates", "invalid")
    consistent = [item for item in candidates if isinstance(item, Mapping) and item.get("status") == "consistent"]
    if not consistent:
        return None, direct_side if isinstance(direct_side, str) else None
    identities = {(item.get("id"), item.get("version")) for item in consistent}
    orientations = {item.get("orientation") for item in consistent}
    result = None
    if len(identities) == 1:
        protocol_id, version = next(iter(identities))
        result = (_name(protocol_id, f"{path}.protocol_candidates.id"), _name(version, f"{path}.protocol_candidates.version"))
    inferred_sides = {
        {"host": "initiator", "device": "target"}.get(orientation)
        for orientation in orientations
    }
    inferred_sides.discard(None)
    inferred_side = next(iter(inferred_sides)) if len(inferred_sides) == 1 else None
    if direct_side is not None and inferred_side is not None and direct_side != inferred_side:
        _error(f"{path}.side", "conflicts-with-protocol-orientation")
    return result, inferred_side


def _source_reference(value: object, path: str) -> SourceReference | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        _error(path, "invalid")
    file = _name(value.get("file"), f"{path}.file")
    if (
        file.startswith("/") or "\\" in file or ".." in file.split("/")
        or ":" in file.split("/", 1)[0] or not file.strip(".")
    ):
        _error(f"{path}.file", "not-relative")
    line = value.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
        _error(f"{path}.line", "invalid")
    column = value.get("column")
    if column is not None and (isinstance(column, bool) or not isinstance(column, int) or column <= 0):
        _error(f"{path}.column", "invalid")
    return SourceReference(file, line, column)


def _evidence(value: object, path: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _error(path, "invalid")
    return tuple(sorted({_name(item, path) for item in value}))


def _field(value: object, path: str) -> EndpointFieldFact:
    if not isinstance(value, Mapping):
        _error(path, "invalid")
    direction = _name(value.get("direction"), f"{path}.direction")
    if direction not in _DIRECTIONS:
        _error(f"{path}.direction", "invalid")
    width = value.get("width")
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        _error(f"{path}.width", "invalid")
    signed = value.get("signed")
    if not isinstance(signed, bool):
        _error(f"{path}.signed", "invalid")
    member_value = value.get("member_path", ())
    if not isinstance(member_value, Sequence) or isinstance(member_value, (str, bytes)):
        _error(f"{path}.member_path", "invalid")
    member_path = tuple(_name(item, f"{path}.member_path") for item in member_value)
    member_keys = ("member_path", "raw_lo", "raw_hi", "container_width")
    present_member_keys = tuple(key for key in member_keys if key in value)
    if present_member_keys and len(present_member_keys) != len(member_keys):
        _error(path, "incomplete-member-range")
    if present_member_keys and not member_path:
        _error(path, "invalid-member-range")
    offsets = tuple(value.get(key) for key in member_keys[1:])
    if present_member_keys and any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in offsets):
        _error(path, "invalid-member-range")
    if present_member_keys and (offsets[1] < offsets[0] or offsets[1] - offsets[0] + 1 != width
                        or offsets[1] >= offsets[2]):
        _error(path, "invalid-member-range")
    normalized_evidence = _evidence(value.get("evidence"), f"{path}.evidence")
    if member_path and not {"explicit_member", "compiler_elaboration"}.issubset(normalized_evidence):
        _error(f"{path}.evidence", "missing-member-evidence")
    return EndpointFieldFact(
        _name(value.get("role"), f"{path}.role"),
        _name(value.get("port"), f"{path}.port"),
        direction,
        width,
        signed,
        _source_reference(value.get("source"), f"{path}.source"),
        normalized_evidence,
        member_path,
        offsets[0], offsets[1], offsets[2],
    )


def _timing(value: object, path: str, roles: frozenset[str]) -> TimingFact:
    if not isinstance(value, Mapping):
        _error(path, "invalid")
    kind = _name(value.get("kind"), f"{path}.kind")
    fields = value.get("fields")
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)):
        _error(f"{path}.fields", "invalid")
    normalized_fields = tuple(_name(field, f"{path}.fields") for field in fields)
    if not set(normalized_fields).issubset(roles):
        _error(f"{path}.fields", "unknown-role")
    clock = _nullable_name(value.get("clock"), f"{path}.clock")
    max_latency = value.get("max_latency")
    if max_latency is not None and (isinstance(max_latency, bool) or not isinstance(max_latency, int) or max_latency < 0):
        _error(f"{path}.max_latency", "invalid")
    return TimingFact(
        kind, normalized_fields, clock, max_latency,
        _source_reference(value.get("source"), f"{path}.source"),
        _evidence(value.get("evidence"), f"{path}.evidence"),
    )


def normalize_annotations(
    document: Mapping[str, object], *, protocol_catalog: ProtocolCatalog | None = None
) -> tuple[EndpointCapability, ...]:
    """Convert source annotations into immutable semantic capabilities."""
    endpoints = document.get("endpoints")
    if not isinstance(endpoints, Sequence) or isinstance(endpoints, (str, bytes)):
        _error("endpoints", "missing")
    result: list[EndpointCapability] = []
    seen: set[str] = set()
    for index, raw in enumerate(endpoints):
        path = f"endpoints[{index}]"
        if not isinstance(raw, Mapping):
            _error(path, "invalid")
        endpoint_id = _name(raw.get("endpoint_id"), f"{path}.endpoint_id")
        if endpoint_id in seen:
            _error(f"{path}.endpoint_id", "duplicate")
        seen.add(endpoint_id)
        protocol, inferred_side = _candidate_protocol(raw, path)
        side = raw.get("side", inferred_side)
        if side is not None and side not in _SIDES:
            _error(f"{path}.side", "invalid")
        # Protocol expectations are matching constraints.  Do not reject an
        # endpoint here: the graph must retain unsupported/ambiguous paths
        # with their generation-time rejection evidence.
        fields_raw = raw.get("fields")
        if not isinstance(fields_raw, Sequence) or isinstance(fields_raw, (str, bytes)) or not fields_raw:
            _error(f"{path}.fields", "missing")
        fields = tuple(_field(item, f"{path}.fields[{field_index}]") for field_index, item in enumerate(fields_raw))
        roles = tuple(field.role for field in fields)
        if len(roles) != len(set(roles)):
            _error(f"{path}.fields", "duplicate-role")
        physical_keys = tuple((field.port, field.member_path) for field in fields)
        if len(physical_keys) != len(set(physical_keys)):
            _error(f"{path}.fields", "duplicate-physical")
        timing_raw = raw.get("timing", ())
        if not isinstance(timing_raw, Sequence) or isinstance(timing_raw, (str, bytes)):
            _error(f"{path}.timing", "invalid")
        timing = tuple(_timing(item, f"{path}.timing[{timing_index}]", frozenset(roles)) for timing_index, item in enumerate(timing_raw))
        result.append(EndpointCapability(
            endpoint_id,
            _name(raw.get("function"), f"{path}.function"),
            side,
            protocol,
            tuple(sorted(fields, key=lambda field: field.role)),
            _nullable_name(raw.get("clock"), f"{path}.clock"),
            _nullable_name(raw.get("reset"), f"{path}.reset"),
            tuple(sorted(timing, key=lambda item: (item.kind, item.fields, item.clock or ""))),
            _evidence(raw.get("evidence"), f"{path}.evidence"),
        ))
    return tuple(sorted(result, key=lambda endpoint: endpoint.endpoint_id))


def _expected_direction(protocol_direction: str, side: str) -> str:
    if protocol_direction == "host_to_device":
        return "output" if side == "initiator" else "input"
    if protocol_direction == "device_to_host":
        return "input" if side == "initiator" else "output"
    raise EndpointCapabilityError(f"protocol.direction:{protocol_direction}:invalid")


def validate_protocol_fingerprint(
    endpoint: EndpointCapability,
    protocol: CompiledProtocol,
    allowed_roles: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    """Return deterministic protocol-fingerprint conflicts for an endpoint."""
    reasons: list[str] = []
    if endpoint.side is None:
        reasons.append("side-ambiguous")
    if endpoint.protocol is not None and endpoint.protocol != (protocol.protocol_id, protocol.version):
        reasons.append("protocol-version")
    fields = {field.role: field for field in endpoint.fields}
    declared_roles = {field.field_id for field in protocol.fields}
    reasons.extend(
        f"undeclared-role:{role}"
        for role in sorted(fields.keys() - declared_roles - allowed_roles)
    )
    for expected in protocol.fields:
        actual = fields.get(expected.field_id)
        if actual is None:
            reasons.append(f"required-field:{expected.field_id}")
            continue
        if endpoint.side is not None and actual.direction != _expected_direction(expected.direction, endpoint.side):
            reasons.append(f"direction:{expected.field_id}")
        if actual.width != expected.width:
            reasons.append(f"width:{expected.field_id}")
    return tuple(dict.fromkeys(reasons))


def _source_document(value: SourceReference | None) -> dict[str, object] | None:
    if value is None:
        return None
    document: dict[str, object] = {"file": value.file, "line": value.line}
    if value.column is not None:
        document["column"] = value.column
    return document


def _evidence_key(item: Mapping[str, object]) -> tuple[object, ...]:
    source = item.get("source")
    source_key = () if not isinstance(source, Mapping) else (source.get("file"), source.get("line"), source.get("column"))
    return (
        item.get("kind"), item.get("endpoint"), item.get("role", item.get("relation", "")),
        tuple(item.get("fields", ())), item.get("direction", ""), item.get("width", -1),
        item.get("signed", False), item.get("max_latency", -1), source_key, tuple(item.get("evidence", ())),
    )


def _match_evidence(source: EndpointCapability, target: EndpointCapability) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for endpoint, endpoint_side in ((source, "source"), (target, "target")):
        for field in endpoint.fields:
            record: dict[str, object] = {"kind": "field", "endpoint": endpoint_side, "role": field.role,
                                         "direction": field.direction, "width": field.width, "signed": field.signed}
            if field.source is not None:
                record["source"] = _source_document(field.source)
            if field.evidence:
                record["evidence"] = list(field.evidence)
            records.append(record)
        for timing in endpoint.timing:
            record = {"kind": "timing", "endpoint": endpoint_side, "relation": timing.kind,
                      "fields": list(timing.fields), "clocked": timing.clock is not None,
                      "max_latency": timing.max_latency}
            if timing.source is not None:
                record["source"] = _source_document(timing.source)
            if timing.evidence:
                record["evidence"] = list(timing.evidence)
            records.append(record)
        domain = {"kind": "domain", "endpoint": endpoint_side, "clocked": endpoint.clock is not None,
                  "reset": endpoint.reset is not None}
        if endpoint.evidence:
            domain["evidence"] = list(endpoint.evidence)
        records.append(domain)
    return tuple(sorted(records, key=_evidence_key))


def _temporal_relations(
    endpoint: EndpointCapability,
) -> dict[tuple[str, tuple[str, ...]], tuple[str, tuple[str, ...], str | None, int | None]]:
    return {
        (item.kind, item.fields): (item.kind, item.fields, item.clock, item.max_latency)
        for item in endpoint.timing
    }


def _validation_reasons(
    endpoint: EndpointCapability,
    protocol_catalog: ProtocolCatalog | None,
    compiled_protocols: Mapping[str, CompiledProtocol] | None,
    adapter_roles: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    if endpoint.protocol is None:
        return ()
    reasons: list[str] = []
    if protocol_catalog is not None:
        try:
            plugin = protocol_catalog.require(*endpoint.protocol)
        except ProtocolDefinitionError:
            return (f"unsupported-protocol:{endpoint.protocol[0]}@{endpoint.protocol[1]}",)
        fields = {field.role: field for field in endpoint.fields}
        declared_roles = {field.field_id for field in plugin.fields}
        for expected in plugin.fields:
            actual = fields.get(expected.field_id)
            if actual is None:
                if expected.required:
                    reasons.append(f"required-field:{expected.field_id}")
                continue
            if endpoint.side is not None and actual.direction != _expected_direction(expected.direction, endpoint.side):
                reasons.append(f"direction:{expected.field_id}")
        reasons.extend(
            f"undeclared-role:{role}"
            for role in sorted(fields.keys() - declared_roles - adapter_roles)
        )
    compiled = None if compiled_protocols is None else compiled_protocols.get(endpoint.endpoint_id)
    if compiled is None:
        reasons.append("protocol-validation-required")
    else:
        reasons.extend(validate_protocol_fingerprint(endpoint, compiled, adapter_roles))
    return tuple(dict.fromkeys(reasons))


def _allows_width_projection(adapter: AdapterCapability | None, role: str) -> bool:
    return bool(
        adapter is not None
        and adapter.allows_width_projection is True
        and isinstance(adapter.width_projection_fields, tuple)
        and all(isinstance(item, str) and item for item in adapter.width_projection_fields)
        and role in adapter.width_projection_fields
    )


def _match_reasons(
    source: EndpointCapability, target: EndpointCapability, adapter: AdapterCapability | None,
    protocol_catalog: ProtocolCatalog | None, compiled_protocols: Mapping[str, CompiledProtocol] | None,
) -> tuple[str, ...]:
    reasons: list[str] = []
    adapter_roles = frozenset() if adapter is None else frozenset((*adapter.features, *adapter.width_projection_fields))
    reasons.extend(_validation_reasons(source, protocol_catalog, compiled_protocols, adapter_roles))
    reasons.extend(_validation_reasons(target, protocol_catalog, compiled_protocols, adapter_roles))
    if source.side != "initiator" or target.side != "target":
        reasons.append("side-ambiguous" if source.side is None or target.side is None else "side")
    if adapter is None:
        if source.protocol is None or target.protocol is None:
            reasons.append("protocol-ambiguous")
        elif source.protocol != target.protocol:
            if (
                source.protocol is not None
                and target.protocol is not None
                and source.protocol[0] == target.protocol[0]
            ):
                reasons.append("protocol-version")
            else:
                reasons.append("protocol")
    elif source.protocol is None or target.protocol is None:
        reasons.append("protocol-ambiguous")
    elif (source.protocol, target.protocol) != (adapter.source_protocol, adapter.target_protocol):
        reasons.append("protocol")
    if source.clock != target.clock:
        reasons.append("clock-domain")
    if source.reset != target.reset:
        reasons.append("reset-domain")
    source_fields = {field.role: field for field in source.fields}
    target_fields = {field.role: field for field in target.fields}
    for role in sorted(source_fields.keys() - target_fields.keys()):
        if adapter is None:
            reasons.append(f"required-field:{role}")
        elif role not in adapter.features:
            reasons.append(f"unsupported-feature:{role}")
    for role in sorted(target_fields.keys() - source_fields.keys()):
        reasons.append(f"required-field:{role}")
    for role in sorted(source_fields.keys() & target_fields.keys()):
        left, right = source_fields[role], target_fields[role]
        if left.direction == right.direction or "inout" in (left.direction, right.direction):
            reasons.append(f"direction:{role}")
        if left.signed != right.signed:
            reasons.append(f"signed:{role}")
        if left.width != right.width and not _allows_width_projection(adapter, role):
            reasons.append(f"width-projection:{role}")
    source_relations, target_relations = _temporal_relations(source), _temporal_relations(target)
    if source_relations != target_relations:
        reasons.append("temporal-relation")
    elif adapter is not None and adapter.max_latency is not None:
        if isinstance(adapter.max_latency, bool) or not isinstance(adapter.max_latency, int) or adapter.max_latency < 0:
            reasons.append("adapter-latency-invalid")
        else:
            for relation in source_relations:
                bounds = tuple(item[3] for item in (source_relations[relation], target_relations[relation]) if item[3] is not None)
                if bounds and adapter.max_latency > min(bounds):
                    reasons.append("temporal-latency")
    return tuple(dict.fromkeys(reasons))


def _score(source: EndpointCapability, target: EndpointCapability, adapter: AdapterCapability | None) -> tuple[int, int, int, int, int]:
    source_widths = {field.role: field.width for field in source.fields}
    target_widths = {field.role: field.width for field in target.fields}
    width_projections = sum(source_widths[role] != target_widths[role] for role in source_widths.keys() & target_widths.keys())
    uncertainty = sum(value is None for value in (source.protocol, target.protocol, source.clock, target.clock, source.reset, target.reset))
    return (0 if source.protocol == target.protocol and adapter is None else 1, -len(_match_evidence(source, target)), 0 if adapter is None else 1, width_projections, uncertainty)


def match_endpoint_pair(
    source: EndpointCapability, target: EndpointCapability, adapters: Sequence[AdapterCapability], *,
    protocol_catalog: ProtocolCatalog | None = None,
    compiled_protocols: Mapping[str, CompiledProtocol] | None = None,
) -> tuple[dict[str, object], ...]:
    """Return accepted and rejected generic match alternatives with evidence."""
    choices: list[AdapterCapability | None] = [None, *sorted(adapters, key=lambda adapter: adapter.adapter_id)]
    evidence = _match_evidence(source, target)
    matches = []
    for adapter in choices:
        reasons = _match_reasons(source, target, adapter, protocol_catalog, compiled_protocols)
        matches.append({"source_endpoint_id": source.endpoint_id, "target_endpoint_id": target.endpoint_id,
                        "accepted": not reasons, "adapter_id": adapter.adapter_id if adapter is not None else None,
                        "reasons": reasons, "evidence": evidence, "score_vector": _score(source, target, adapter)})
    return tuple(sorted(matches, key=lambda item: (not bool(item["accepted"]), item["score_vector"], str(item["adapter_id"]))))


__all__ = ["AdapterCapability", "EndpointCapability", "EndpointCapabilityError", "EndpointFieldFact", "SourceReference", "TimingFact", "match_endpoint_pair", "normalize_annotations", "validate_protocol_fingerprint"]
