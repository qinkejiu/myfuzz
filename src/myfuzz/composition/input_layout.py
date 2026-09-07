"""Deterministic, source-bound RFuzz input layouts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from myfuzz.contracts import canonical_bytes
from myfuzz.isa.constraints import IsaContract


class InputLayoutError(ValueError):
    """Raised when annotations cannot become a finite, safe input layout."""


@dataclass(frozen=True, slots=True)
class LayoutField:
    field_id: str
    owner: str
    role: str
    width: int
    raw_lo: int
    raw_hi: int
    encoding: str
    constraint: Mapping[str, object]
    dependency_group: str | None = None
    port: str = ""
    signed: bool = False
    direction: str = "input"
    provenance: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "constraint", MappingProxyType(dict(self.constraint)))
        if self.provenance is not None:
            object.__setattr__(self, "provenance", MappingProxyType(dict(self.provenance)))


@dataclass(frozen=True, slots=True)
class InputLayout:
    schema_version: str
    raw_width: int
    fields: tuple[LayoutField, ...]
    layout_hash: str

    def to_raw_abi(self):
        """Return an ABI whose identity includes every generated bit mapping."""
        from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash

        destinations = tuple(RawDestination(index, None, index, field.width) for index, field in enumerate(self.fields))
        uses = tuple(RawBitUse(field.raw_lo, field.raw_hi, index, 0, "direct", "generated") for index, field in enumerate(self.fields))
        document = {
            "schema_version": "raw_bit_abi.v1",
            "layout_schema_version": self.schema_version,
            "layout_hash": self.layout_hash,
            "raw_width": self.raw_width,
            "destinations": [{"destination_id": item.destination_id, "component_id": item.component_id,
                              "port_id": item.port_id, "width": item.width} for item in destinations],
            "uses": [{"raw_lo": item.raw_lo, "raw_hi": item.raw_hi, "destination_id": item.destination_id,
                      "destination_lo": item.destination_lo, "action": item.action, "category": item.category} for item in uses],
        }
        result = RawBitAbi(self.raw_width, destinations, uses, content_hash(document))
        result.validate_total_use()
        return result


_ROLE_ORDER = {"address": 0, "byte_enable": 1, "ready": 2, "valid": 3, "data": 4, "instruction": 5}
_CONSTRAINT_KEYS = frozenset(("owner", "endpoint_id", "role", "range", "alignment", "dependency_group", "gated_by"))


def _error(message: str) -> None:
    raise InputLayoutError(message)


def _name(value: object, message: str) -> str:
    if not isinstance(value, str) or not value:
        _error(message)
    return value


def _width(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _error(f"{label}: invalid width")
    return value


def _provenance(value: object) -> Mapping[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        _error("invalid provenance")
    file_name = _name(value.get("file"), "invalid provenance")
    line = value.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
        _error("invalid provenance")
    result: dict[str, object] = {"file": file_name, "line": line}
    if "column" in value:
        column = value["column"]
        if isinstance(column, bool) or not isinstance(column, int) or column <= 0:
            _error("invalid provenance")
        result["column"] = column
    return result


def _protocol_is_apb(endpoint: Mapping[str, object]) -> bool:
    candidates = endpoint.get("protocol_candidates")
    if candidates is not None:
        if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)):
            _error("invalid protocol_candidates")
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                _error("invalid protocol candidate")
            if candidate.get("id") == "apb" and candidate.get("status") == "consistent":
                return True
        return False
    # Compatibility with the early Task 4 simplified annotation shape.
    protocol = endpoint.get("protocol")
    return (isinstance(protocol, Sequence) and not isinstance(protocol, (str, bytes))
            and bool(protocol) and protocol[0] == "apb")


def _normalize_records(records: Sequence[Mapping[str, object]], available: set[tuple[str, str]]) -> dict[tuple[str, str], dict[str, object]]:
    normalized: dict[tuple[str, str], dict[str, object]] = {}
    groups: dict[str, set[tuple[str, str]]] = {}
    for record in records:
        unknown = set(record) - _CONSTRAINT_KEYS
        if unknown:
            _error("unknown constraint key")
        owner = record.get("owner", record.get("endpoint_id"))
        if "owner" in record and "endpoint_id" in record and record["owner"] != record["endpoint_id"]:
            _error("contradictory constraint owner")
        key = (_name(owner, "constraint owner missing"), _name(record.get("role"), "constraint role missing"))
        if key not in available:
            _error("constraint references unknown field")
        target = normalized.setdefault(key, {})
        for name, value in record.items():
            if name in ("owner", "endpoint_id", "role"):
                continue
            if name in target and target[name] != value:
                _error(f"contradictory {name}")
            target[name] = value
        group = record.get("dependency_group")
        if group is not None:
            group_name = _name(group, "invalid dependency_group")
            groups.setdefault(group_name, set()).add(key)
    if any(len(members) < 2 for members in groups.values()):
        _error("dependency_group requires multiple field members")
    return normalized


def _range(value: object, *, width: int, signed: bool) -> list[int]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 2:
        _error("invalid range")
    lo, hi = value
    if any(isinstance(item, bool) or not isinstance(item, int) for item in (lo, hi)):
        _error("unbounded range")
    if hi < lo:
        _error("invalid range")
    minimum = -(1 << (width - 1)) if signed else 0
    maximum = (1 << (width - 1)) - 1 if signed else (1 << width) - 1
    if lo < minimum or hi > maximum:
        _error("range outside field width")
    return [lo, hi]


def _alignment(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value & (value - 1):
        _error("invalid alignment")
    return value


def _instruction_encoding(isa: IsaContract | None) -> str:
    if isa is None or not isa.supports_legal_instruction_validation:
        return "raw_instruction"
    return "riscv_imc"


def _field_document(field: LayoutField, *, include_provenance: bool) -> dict[str, object]:
    document: dict[str, object] = {
        "field_id": field.field_id, "owner": field.owner, "role": field.role, "width": field.width,
        "raw_lo": field.raw_lo, "raw_hi": field.raw_hi, "encoding": field.encoding,
        "constraint": dict(field.constraint), "dependency_group": field.dependency_group,
        "binding": {"port": field.port, "direction": field.direction, "signed": field.signed},
    }
    if include_provenance and field.provenance is not None:
        document["provenance"] = dict(field.provenance)
    return document


def build_input_layout(annotations: Mapping[str, object], *, component_constraints: Sequence[Mapping[str, object]] = (), isa: IsaContract | None = None) -> InputLayout:
    if not isinstance(annotations, Mapping):
        _error("annotations must be an object")
    if isa is not None and not isinstance(isa, IsaContract):
        _error("isa must be an IsaContract")
    if not isinstance(component_constraints, Sequence) or isinstance(component_constraints, (str, bytes)):
        _error("component_constraints must be a sequence")
    if any(not isinstance(record, Mapping) for record in component_constraints):
        _error("component constraint must be an object")
    endpoints = annotations.get("endpoints")
    if not isinstance(endpoints, Sequence) or isinstance(endpoints, (str, bytes)):
        _error("annotations.endpoints must be a sequence")

    candidates: list[tuple[str, str, int, bool, bool, bool, str, str, Mapping[str, object] | None]] = []
    seen: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            _error("invalid endpoint")
        owner = _name(endpoint.get("endpoint_id"), "endpoint_id missing")
        is_apb = _protocol_is_apb(endpoint)
        fields = endpoint.get("fields")
        if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)):
            _error("endpoint fields missing")
        for source in fields:
            if not isinstance(source, Mapping):
                _error("invalid endpoint field")
            direction = source.get("direction")
            if direction not in ("input", "output", "inout"):
                _error("invalid field direction")
            if direction not in ("input", "inout"):
                continue
            role = _name(source.get("role"), "field role missing")
            key = (owner, role)
            if key in seen:
                _error("duplicate input field")
            seen.add(key)
            signed = source.get("signed", False)
            if not isinstance(signed, bool):
                _error("invalid field signedness")
            optional = source.get("optional", False)
            if not isinstance(optional, bool):
                _error("invalid optional flag")
            candidates.append((owner, role, _width(source.get("width"), f"{owner}:{role}"), signed, optional, is_apb,
                               _name(source.get("port"), "field port missing"), direction, _provenance(source.get("source"))))
    if not candidates:
        _error("empty input layout")
    candidates.sort(key=lambda item: (item[0], item[4], _ROLE_ORDER.get(item[1], 100), item[1], item[6]))
    available = {(owner, role) for owner, role, *_ in candidates}
    records = _normalize_records(tuple(component_constraints), available)
    by_key = {(owner, role): item for owner, role, *item in candidates}

    fields: list[LayoutField] = []
    cursor = 0
    for owner, role, width, signed, _optional, is_apb, port, direction, provenance in candidates:
        constraint = dict(records.get((owner, role), {}))
        group = constraint.pop("dependency_group", None)
        if group is not None:
            group = _name(group, "invalid dependency_group")
        if "range" in constraint:
            constraint["range"] = _range(constraint["range"], width=width, signed=signed)
        default_alignment = 4 if is_apb and role == "address" else None
        alignment_value = constraint.get("alignment", default_alignment)
        if alignment_value is not None:
            alignment = _alignment(alignment_value)
            constraint["alignment"] = alignment
            if "range" in constraint and (constraint["range"][0] % alignment or constraint["range"][1] % alignment):
                _error("contradictory address range/alignment")
        if role == "byte_enable":
            data = by_key.get((owner, "data"))
            if data is None or data[0] % 8 or width != data[0] // 8:
                _error("invalid byte_enable width")
            constraint["byte_enable_width"] = width
        explicit_gate = constraint.get("gated_by")
        if explicit_gate is None and role == "ready" and (owner, "valid") in available:
            constraint["gated_by"] = f"{owner}:valid"
        elif explicit_gate is not None:
            gate = _name(explicit_gate, "invalid gated_by")
            if ":" not in gate:
                _error("invalid gated_by")
            gate_owner, gate_role = gate.rsplit(":", 1)
            if (gate_owner, gate_role) not in available:
                _error("unknown gated_by")
            if role == "valid":
                _error("valid cannot gate itself")
            if gate_owner != owner or gate_role != "valid":
                _error("gated_by must reference owner valid")
        encoding = _instruction_encoding(isa) if role == "instruction" else "bits"
        fields.append(LayoutField(f"{owner}:{role}", owner, role, width, cursor, cursor + width - 1, encoding,
                                  constraint, group, port, signed, direction, provenance))
        cursor += width
    document = {"schema_version": "input_layout.v1", "raw_width": cursor,
                "fields": [_field_document(field, include_provenance=False) for field in fields]}
    return InputLayout("input_layout.v1", cursor, tuple(fields), hashlib.sha256(canonical_bytes(document)).hexdigest())


def input_layout_document(layout: InputLayout) -> dict[str, object]:
    if not isinstance(layout, InputLayout):
        raise TypeError("layout must be an InputLayout")
    return {"schema_version": layout.schema_version, "raw_width": layout.raw_width,
            "fields": [_field_document(field, include_provenance=True) for field in layout.fields], "layout_hash": layout.layout_hash}
