"""Deterministic, semantic RFuzz input layouts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from myfuzz.contracts import canonical_bytes
from myfuzz.isa.constraints import IsaContract


class InputLayoutError(ValueError):
    """Raised when an annotation cannot become a finite input layout."""


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

    def __post_init__(self) -> None:
        object.__setattr__(self, "constraint", MappingProxyType(dict(self.constraint)))


@dataclass(frozen=True, slots=True)
class InputLayout:
    schema_version: str
    raw_width: int
    fields: tuple[LayoutField, ...]
    layout_hash: str

    def to_raw_abi(self):
        """Return an equivalent existing RawBitAbi without coupling generation to it."""
        from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash

        destinations = tuple(RawDestination(index, None, index, field.width) for index, field in enumerate(self.fields))
        uses = tuple(RawBitUse(field.raw_lo, field.raw_hi, index, 0, "direct", "generated") for index, field in enumerate(self.fields))
        document = {"layout_hash": self.layout_hash, "raw_width": self.raw_width}
        result = RawBitAbi(self.raw_width, destinations, uses, content_hash(document))
        result.validate_total_use()
        return result


_ROLE_ORDER = {"address": 0, "byte_enable": 1, "ready": 2, "valid": 3, "data": 4, "instruction": 5}


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


def _constraints(records: Sequence[Mapping[str, object]], owner: str, role: str) -> tuple[dict[str, object], str | None]:
    result: dict[str, object] = {}
    group: str | None = None
    for record in records:
        if record.get("owner", record.get("endpoint_id")) != owner or record.get("role") != role:
            continue
        for key, value in record.items():
            if key in ("owner", "endpoint_id", "role"):
                continue
            if key == "dependency_group":
                if not isinstance(value, str) or not value:
                    _error("invalid dependency_group")
                if group is not None and group != value:
                    _error("contradictory dependency_group")
                group = value
                continue
            if key in result and result[key] != value:
                _error(f"contradictory {key}")
            result[key] = value
    return result, group


def _range(value: object) -> list[int]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 2:
        _error("invalid range")
    lo, hi = value
    if any(isinstance(item, bool) or not isinstance(item, int) for item in (lo, hi)):
        _error("unbounded range")
    if lo < 0 or hi < lo:
        _error("invalid range")
    return [lo, hi]


def _instruction_encoding(isa: IsaContract | None) -> str:
    if isa is None or any(item not in {"I", "M", "C"} for item in isa.extensions):
        return "raw_instruction"
    return "riscv_imc"


def build_input_layout(annotations: Mapping[str, object], *, component_constraints: Sequence[Mapping[str, object]] = (), isa: IsaContract | None = None) -> InputLayout:
    if not isinstance(annotations, Mapping):
        _error("annotations must be an object")
    if isa is not None and not isinstance(isa, IsaContract):
        _error("isa must be an IsaContract")
    if not isinstance(component_constraints, Sequence) or isinstance(component_constraints, (str, bytes)):
        _error("component_constraints must be a sequence")
    records = tuple(record for record in component_constraints if isinstance(record, Mapping))
    if len(records) != len(component_constraints):
        _error("component constraint must be an object")
    endpoints = annotations.get("endpoints")
    if not isinstance(endpoints, Sequence) or isinstance(endpoints, (str, bytes)):
        _error("annotations.endpoints must be a sequence")
    candidates: list[tuple[str, str, int, bool, str, Mapping[str, object]]] = []
    seen: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            _error("invalid endpoint")
        owner = _name(endpoint.get("endpoint_id"), "endpoint_id missing")
        protocol = endpoint.get("protocol")
        is_apb = isinstance(protocol, Sequence) and not isinstance(protocol, (str, bytes)) and bool(protocol) and protocol[0] == "apb"
        fields = endpoint.get("fields")
        if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)):
            _error("endpoint fields missing")
        for field in fields:
            if not isinstance(field, Mapping) or field.get("direction") not in ("input", "inout"):
                continue
            role = _name(field.get("role"), "field role missing")
            key = (owner, role)
            if key in seen:
                _error("duplicate input field")
            seen.add(key)
            candidates.append((owner, role, _width(field.get("width"), f"{owner}:{role}"), bool(field.get("optional", False)), "apb" if is_apb else "generic", field))
    candidates.sort(key=lambda item: (item[0], item[3], _ROLE_ORDER.get(item[1], 100), item[1]))
    fields: list[LayoutField] = []
    cursor = 0
    available = {(owner, role) for owner, role, *_ in candidates}
    for owner, role, width, _optional, protocol, _source in candidates:
        constraint, group = _constraints(records, owner, role)
        if "range" in constraint:
            constraint["range"] = _range(constraint["range"])
        alignment = constraint.get("alignment", 4 if protocol == "apb" and role == "address" else None)
        if alignment is not None:
            if isinstance(alignment, bool) or not isinstance(alignment, int) or alignment <= 0 or alignment & (alignment - 1):
                _error("invalid alignment")
            constraint["alignment"] = alignment
            if "range" in constraint and constraint["range"][0] % alignment:
                _error("contradictory address range/alignment")
        if role == "byte_enable":
            address = next((item for item in candidates if item[0] == owner and item[1] == "address"), None)
            if address is None or address[2] % 8 or width != address[2] // 8:
                _error("invalid byte_enable width")
            constraint["byte_enable_width"] = width
        if role in ("valid", "ready") and (owner, "valid") in available and (owner, "ready") in available:
            constraint["gated_by"] = f"{owner}:valid"
        encoding = _instruction_encoding(isa) if role == "instruction" else "bits"
        fields.append(LayoutField(f"{owner}:{role}", owner, role, width, cursor, cursor + width - 1, encoding, constraint, group))
        cursor += width
    document = {
        "schema_version": "input_layout.v1",
        "raw_width": cursor,
        "fields": [_field_document(field) for field in fields],
    }
    return InputLayout("input_layout.v1", cursor, tuple(fields), hashlib.sha256(canonical_bytes(document)).hexdigest())


def _field_document(field: LayoutField) -> dict[str, object]:
    return {"field_id": field.field_id, "owner": field.owner, "role": field.role, "width": field.width, "raw_lo": field.raw_lo, "raw_hi": field.raw_hi, "encoding": field.encoding, "constraint": dict(field.constraint), "dependency_group": field.dependency_group}


def input_layout_document(layout: InputLayout) -> dict[str, object]:
    if not isinstance(layout, InputLayout):
        raise TypeError("layout must be an InputLayout")
    return {"schema_version": layout.schema_version, "raw_width": layout.raw_width, "fields": [_field_document(field) for field in layout.fields], "layout_hash": layout.layout_hash}
