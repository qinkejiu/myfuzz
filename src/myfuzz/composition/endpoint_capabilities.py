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


@dataclass(frozen=True, slots=True)
class EndpointCapability:
    endpoint_id: str
    function: str
    side: str
    protocol: tuple[str, str] | None
    fields: tuple[EndpointFieldFact, ...]
    clock: str | None
    reset: str | None
    timing: tuple[Mapping[str, object], ...]


@dataclass(frozen=True, slots=True)
class AdapterCapability:
    adapter_id: str
    source_protocol: tuple[str, str]
    target_protocol: tuple[str, str]
    features: tuple[str, ...]
    max_latency: int | None
    allows_width_projection: bool


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
    keys = {(item.get("id"), item.get("version"), item.get("orientation")) for item in consistent}
    if len(keys) != 1:
        _error(f"{path}.protocol_candidates", "ambiguous")
    protocol_id, version, orientation = next(iter(keys))
    result = (_name(protocol_id, f"{path}.protocol_candidates.id"), _name(version, f"{path}.protocol_candidates.version"))
    inferred_side = {"host": "initiator", "device": "target"}.get(orientation)
    if inferred_side is None:
        _error(f"{path}.protocol_candidates.orientation", "invalid")
    if direct_side is not None and direct_side != inferred_side:
        _error(f"{path}.side", "conflicts-with-protocol-orientation")
    return result, inferred_side


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
    return EndpointFieldFact(
        _name(value.get("role"), f"{path}.role"),
        _name(value.get("port"), f"{path}.port"),
        direction,
        width,
        signed,
    )


def _timing(value: object, path: str, roles: frozenset[str]) -> Mapping[str, object]:
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
    return {"kind": kind, "fields": normalized_fields, "clock": clock}


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
        if side not in _SIDES:
            _error(f"{path}.side", "missing-or-invalid")
        if protocol_catalog is not None and protocol is not None:
            try:
                protocol_catalog.require(*protocol)
            except ProtocolDefinitionError as error:
                _error(f"{path}.protocol", str(error))
        fields_raw = raw.get("fields")
        if not isinstance(fields_raw, Sequence) or isinstance(fields_raw, (str, bytes)) or not fields_raw:
            _error(f"{path}.fields", "missing")
        fields = tuple(_field(item, f"{path}.fields[{field_index}]") for field_index, item in enumerate(fields_raw))
        roles = tuple(field.role for field in fields)
        if len(roles) != len(set(roles)):
            _error(f"{path}.fields", "duplicate-role")
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
            tuple(sorted(timing, key=lambda item: (str(item["kind"]), tuple(item["fields"])))),
        ))
    return tuple(sorted(result, key=lambda endpoint: endpoint.endpoint_id))


def _expected_direction(protocol_direction: str, side: str) -> str:
    if protocol_direction == "host_to_device":
        return "output" if side == "initiator" else "input"
    if protocol_direction == "device_to_host":
        return "input" if side == "initiator" else "output"
    raise EndpointCapabilityError(f"protocol.direction:{protocol_direction}:invalid")


def validate_protocol_fingerprint(endpoint: EndpointCapability, protocol: CompiledProtocol) -> tuple[str, ...]:
    """Return deterministic protocol-fingerprint conflicts for an endpoint."""
    reasons: list[str] = []
    if endpoint.protocol is not None and endpoint.protocol != (protocol.protocol_id, protocol.version):
        reasons.append("protocol-version")
    fields = {field.role: field for field in endpoint.fields}
    for expected in protocol.fields:
        actual = fields.get(expected.field_id)
        if actual is None:
            reasons.append(f"required-field:{expected.field_id}")
            continue
        if actual.direction != _expected_direction(expected.direction, endpoint.side):
            reasons.append(f"direction:{expected.field_id}")
        if actual.width != expected.width:
            reasons.append(f"width:{expected.field_id}")
    return tuple(dict.fromkeys(reasons))


def _evidence(source: EndpointCapability, target: EndpointCapability) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for endpoint, endpoint_side in ((source, "source"), (target, "target")):
        for field in endpoint.fields:
            records.append({"kind": "field", "endpoint": endpoint_side, "role": field.role,
                            "direction": field.direction, "width": field.width, "signed": field.signed})
        for timing in endpoint.timing:
            records.append({"kind": "timing", "endpoint": endpoint_side, "relation": timing["kind"],
                            "fields": list(timing["fields"]), "clocked": timing["clock"] is not None})
        records.append({"kind": "domain", "endpoint": endpoint_side, "clocked": endpoint.clock is not None,
                        "reset": endpoint.reset is not None})
    return tuple(sorted(records, key=repr))


def _temporal_relations(endpoint: EndpointCapability) -> frozenset[tuple[str, tuple[str, ...]]]:
    return frozenset((str(item["kind"]), tuple(item["fields"])) for item in endpoint.timing)


def _match_reasons(source: EndpointCapability, target: EndpointCapability, adapter: AdapterCapability | None) -> tuple[str, ...]:
    reasons: list[str] = []
    if source.side != "initiator" or target.side != "target":
        reasons.append("side")
    if adapter is None:
        if source.protocol != target.protocol:
            if (
                source.protocol is not None
                and target.protocol is not None
                and source.protocol[0] == target.protocol[0]
            ):
                reasons.append("protocol-version")
            else:
                reasons.append("protocol")
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
        if left.width != right.width and (adapter is None or not adapter.allows_width_projection):
            reasons.append(f"width-projection:{role}")
    source_relations, target_relations = _temporal_relations(source), _temporal_relations(target)
    if source_relations and target_relations and source_relations != target_relations:
        reasons.append("temporal-relation")
    return tuple(dict.fromkeys(reasons))


def _score(source: EndpointCapability, target: EndpointCapability, adapter: AdapterCapability | None) -> tuple[int, int, int, int, int]:
    source_widths = {field.role: field.width for field in source.fields}
    target_widths = {field.role: field.width for field in target.fields}
    width_projections = sum(source_widths[role] != target_widths[role] for role in source_widths.keys() & target_widths.keys())
    uncertainty = sum(value is None for value in (source.protocol, target.protocol, source.clock, target.clock, source.reset, target.reset))
    return (0 if source.protocol == target.protocol and adapter is None else 1, -len(_evidence(source, target)), 0 if adapter is None else 1, width_projections, uncertainty)


def match_endpoint_pair(source: EndpointCapability, target: EndpointCapability, adapters: Sequence[AdapterCapability]) -> tuple[dict[str, object], ...]:
    """Return accepted and rejected generic match alternatives with evidence."""
    choices: list[AdapterCapability | None] = [None]
    choices.extend(sorted((adapter for adapter in adapters if (adapter.source_protocol, adapter.target_protocol) == (source.protocol, target.protocol)), key=lambda adapter: adapter.adapter_id))
    evidence = _evidence(source, target)
    matches = []
    for adapter in choices:
        reasons = _match_reasons(source, target, adapter)
        matches.append({"source_endpoint_id": source.endpoint_id, "target_endpoint_id": target.endpoint_id,
                        "accepted": not reasons, "adapter_id": adapter.adapter_id if adapter is not None else None,
                        "reasons": reasons, "evidence": evidence, "score_vector": _score(source, target, adapter)})
    return tuple(sorted(matches, key=lambda item: (not bool(item["accepted"]), item["score_vector"], str(item["adapter_id"]))))


__all__ = ["AdapterCapability", "EndpointCapability", "EndpointCapabilityError", "EndpointFieldFact", "match_endpoint_pair", "normalize_annotations", "validate_protocol_fingerprint"]
