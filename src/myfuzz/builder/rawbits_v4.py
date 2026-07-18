"""Lossless RawBits v4 layouts and checked testcase transport framing."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, replace
from enum import IntEnum
import hashlib
import json
import struct
from typing import Iterable, Mapping
import zlib

from .contracts.experiment import content_digest
from .input_model import InputValidationError


RAWBITS_V4_LAYOUT_SCHEMA = "myfuzz.rawbits-layout/v4"
RAWBITS_V4_TRANSPORT_SCHEMA = "myfuzz.rawbits-transport/v4"
RAWBITS_V4_OPAQUE_SCHEMA = "myfuzz.rawbits-opaque-envelope/v4"
RAWBITS_V4_MAGIC = b"MYFZV4\x00\x00"
RAWBITS_V4_VERSION = 4
RAWBITS_V4_HEADER_BYTES = 64
RAWBITS_V4_FLAG_FINAL = 1 << 0
RAWBITS_V4_FLAG_CONTINUATION = 1 << 1
_HEADER = struct.Struct("<8sHHBBHQIIIII8s8sI")

if _HEADER.size != RAWBITS_V4_HEADER_BYTES:
    raise RuntimeError("RawBits v4 header layout must be exactly 64 bytes")


class RawBitsV4Lane(IntEnum):
    RAW_ESCAPE = 1
    PROTOCOL_WAVEFORM = 2
    ADVERSARIAL_MUTATION = 3
    CPU_SEMANTIC = 4


class RawBitsV4Submode(IntEnum):
    RAW_LITERAL = 1
    GUARDED_INTENT = 2
    LITERAL_TRACE = 3
    MUTATION = 4
    SEMANTIC_OPS = 5
    PROGRAM_FRAGMENT = 6


@dataclass(frozen=True)
class RawBitsV4Limits:
    max_chunks: int = 1024
    max_logical_records: int = 1_048_576
    max_chunk_payload_bytes: int = 64 * 1024 * 1024
    max_testcase_bytes: int = 512 * 1024 * 1024
    schema: str = "myfuzz.rawbits-limits/v4"

    def __post_init__(self) -> None:
        for name in (
            "max_chunks", "max_logical_records", "max_chunk_payload_bytes",
            "max_testcase_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise InputValidationError(f"RawBits v4 {name} must be a positive integer")
        if self.max_chunks > 1 << 32:
            raise InputValidationError("RawBits v4 max_chunks exceeds the 32-bit chunk index domain")


@dataclass(frozen=True)
class RawBitsV4Field:
    name: str
    offset: int
    width: int
    source: str
    consumer: str
    used: bool
    submodes: tuple[str, ...]
    default_interpretation: str
    provenance: Mapping[str, object]


@dataclass(frozen=True)
class RawBitsV4LaneLayout:
    lane: str
    fields: tuple[RawBitsV4Field, ...]
    width: int
    used_mask: int
    submode_used_masks: tuple[tuple[str, int], ...]

    def used_mask_for(self, submode: RawBitsV4Submode | int) -> int:
        name = RawBitsV4Submode(_submode(submode)).name
        match = next((mask for mode, mask in self.submode_used_masks if mode == name), None)
        if match is None:
            raise InputValidationError(
                f"RawBits v4 lane {self.lane} does not define submode {name}"
            )
        return match


@dataclass(frozen=True)
class RawBitsV4Layout:
    lanes: tuple[RawBitsV4LaneLayout, ...]
    record_width_bits: int
    record_width_bytes: int
    digest: str
    schema: str = RAWBITS_V4_LAYOUT_SCHEMA
    byte_order: str = "little"
    bit_order: str = "lsb0"
    record_order: str = "forward"

    def __post_init__(self) -> None:
        if self.schema != RAWBITS_V4_LAYOUT_SCHEMA:
            raise InputValidationError("RawBits v4 layout schema version mismatch")
        if self.byte_order != "little" or self.bit_order != "lsb0" or self.record_order != "forward":
            raise InputValidationError("RawBits v4 layout ordering contract mismatch")
        if self.record_width_bits <= 0 or self.record_width_bytes <= 0:
            raise InputValidationError("RawBits v4 record width must be positive")
        if self.record_width_bytes % 8:
            raise InputValidationError("RawBits v4 records must be aligned to 8 bytes")
        if self.record_width_bytes * 8 < self.record_width_bits:
            raise InputValidationError("RawBits v4 record bytes do not contain all record bits")
        lane_names = [lane.lane for lane in self.lanes]
        expected = sorted(lane_names, key=lambda name: RawBitsV4Lane[name].value)
        if not lane_names or lane_names != expected or len(lane_names) != len(set(lane_names)):
            raise InputValidationError("RawBits v4 lanes must be unique and canonically ordered")
        if self.digest:
            _sha256(self.digest, "RawBitsV4Layout.digest")
            if self.digest != content_digest(self.payload_dict()):
                raise InputValidationError("RawBits v4 layout digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def lane_layout(self, lane: RawBitsV4Lane | str) -> RawBitsV4LaneLayout:
        name = _lane(lane).name
        match = next((item for item in self.lanes if item.lane == name), None)
        if match is None:
            raise InputValidationError(f"RawBits v4 layout does not enable lane {name}")
        return match


@dataclass(frozen=True)
class RawBitsV4Header:
    lane: RawBitsV4Lane
    submode: int
    flags: int
    logical_testcase_id: int
    chunk_index: int
    record_width_bits: int
    record_width_bytes: int
    record_count: int
    payload_bytes: int
    layout_digest_prefix: bytes

    def pack(self) -> bytes:
        _validate_header_values(self)
        prefix = _HEADER.pack(
            RAWBITS_V4_MAGIC, RAWBITS_V4_VERSION, RAWBITS_V4_HEADER_BYTES,
            self.lane.value, self.submode, self.flags, self.logical_testcase_id,
            self.chunk_index, self.record_width_bits, self.record_width_bytes,
            self.record_count, self.payload_bytes, self.layout_digest_prefix,
            b"\x00" * 8, 0,
        )
        crc = zlib.crc32(prefix[:-4]) & 0xFFFFFFFF
        return prefix[:-4] + struct.pack("<I", crc)

    @classmethod
    def unpack(cls, data: bytes) -> "RawBitsV4Header":
        if len(data) != RAWBITS_V4_HEADER_BYTES:
            raise InputValidationError("RawBits v4 header must be exactly 64 bytes")
        values = _HEADER.unpack(data)
        (magic, version, header_bytes, lane, submode, flags, testcase_id,
         chunk_index, width_bits, width_bytes, record_count, payload_bytes,
         digest_prefix, reserved, expected_crc) = values
        if magic != RAWBITS_V4_MAGIC or version != RAWBITS_V4_VERSION:
            raise InputValidationError("RawBits v4 transport magic/version mismatch")
        if header_bytes != RAWBITS_V4_HEADER_BYTES:
            raise InputValidationError("RawBits v4 header length mismatch")
        if reserved != b"\x00" * 8:
            raise InputValidationError("RawBits v4 reserved header bytes must be zero")
        actual_crc = zlib.crc32(data[:-4]) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise InputValidationError("RawBits v4 header CRC mismatch")
        try:
            lane_value = RawBitsV4Lane(lane)
        except ValueError as exc:
            raise InputValidationError(f"RawBits v4 lane {lane} is unsupported") from exc
        header = cls(
            lane_value, submode, flags, testcase_id, chunk_index, width_bits,
            width_bytes, record_count, payload_bytes, digest_prefix,
        )
        _validate_header_values(header)
        return header


@dataclass(frozen=True)
class RawBitsV4Testcase:
    layout_digest: str
    lane: str
    submode: int
    logical_testcase_id: int
    records: tuple[int, ...]
    chunk_count: int
    transport_sha256: str
    schema: str = RAWBITS_V4_TRANSPORT_SCHEMA


@dataclass(frozen=True)
class OpaqueRawBitsV4Envelope:
    legacy_schema: str
    legacy_sha256: str
    payload_encoding: str
    payload: str
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = RAWBITS_V4_OPAQUE_SCHEMA

    def __post_init__(self) -> None:
        if self.legacy_schema not in {"myfuzz.rawbits/v2", "myfuzz.rawbits-layout/v3"}:
            raise InputValidationError("opaque v4 envelope only accepts RawBits v2 or v3")
        _sha256(self.legacy_sha256, "OpaqueRawBitsV4Envelope.legacy_sha256")
        if self.payload_encoding != "base64":
            raise InputValidationError("opaque v4 payload encoding must be base64")
        if not isinstance(self.provenance, Mapping) or not self.provenance:
            raise InputValidationError("opaque v4 provenance must be a non-empty object")
        try:
            decoded = base64.b64decode(self.payload, validate=True)
        except (TypeError, ValueError) as exc:
            raise InputValidationError("opaque v4 payload is not canonical base64") from exc
        if base64.b64encode(decoded).decode("ascii") != self.payload:
            raise InputValidationError("opaque v4 payload is not canonical base64")
        if hashlib.sha256(decoded).hexdigest() != self.legacy_sha256:
            raise InputValidationError("opaque v4 legacy digest mismatch")
        if self.digest and self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("opaque v4 content digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_rawbits_v4_layout(
    lanes: Mapping[RawBitsV4Lane | str, Iterable[Mapping[str, object]]],
) -> RawBitsV4Layout:
    if not isinstance(lanes, Mapping) or not lanes:
        raise InputValidationError("RawBits v4 layout requires at least one lane")
    built: list[RawBitsV4LaneLayout] = []
    seen: set[RawBitsV4Lane] = set()
    for lane_key, fields in lanes.items():
        lane = _lane(lane_key)
        if lane in seen:
            raise InputValidationError(f"RawBits v4 lane {lane.name} is duplicated")
        seen.add(lane)
        values = sorted((dict(field) for field in fields), key=lambda item: str(item.get("name", "")))
        if not values:
            raise InputValidationError(f"RawBits v4 lane {lane.name} must contain fields")
        offset = 0
        used_mask = 0
        result: list[RawBitsV4Field] = []
        names: set[str] = set()
        allowed = {
            "name", "width", "source", "consumer", "used",
            "submodes", "default_interpretation", "provenance",
        }
        submode_masks = {submode.name: 0 for submode in _allowed_submodes(lane)}
        for index, value in enumerate(values):
            required = allowed - {"submodes"}
            missing, unknown = required - set(value), set(value) - allowed
            if missing or unknown:
                detail = sorted(missing or unknown)
                kind = "missing" if missing else "unknown"
                raise InputValidationError(
                    f"RawBits v4 {lane.name} field {index}: {kind} field(s): {', '.join(detail)}"
                )
            name = _text(value["name"], f"{lane.name}.field[{index}].name")
            if name in names:
                raise InputValidationError(f"RawBits v4 {lane.name} field names must be unique")
            names.add(name)
            width = _positive(value["width"], f"{lane.name}.{name}.width")
            used = value["used"]
            if not isinstance(used, bool):
                raise InputValidationError(f"RawBits v4 {lane.name}.{name}.used must be boolean")
            raw_submodes = value.get("submodes", [item.name for item in _allowed_submodes(lane)])
            if not isinstance(raw_submodes, (tuple, list)) or not raw_submodes:
                raise InputValidationError(
                    f"RawBits v4 {lane.name}.{name}.submodes must be a non-empty array"
                )
            submodes = tuple(sorted(
                {_submode_name(item, lane) for item in raw_submodes},
                key=lambda item: RawBitsV4Submode[item].value,
            ))
            provenance = value["provenance"]
            if not isinstance(provenance, Mapping) or not provenance:
                raise InputValidationError(f"RawBits v4 {lane.name}.{name}.provenance must be non-empty")
            result.append(RawBitsV4Field(
                name, offset, width,
                _text(value["source"], f"{lane.name}.{name}.source"),
                _text(value["consumer"], f"{lane.name}.{name}.consumer"),
                used,
                submodes,
                _text(value["default_interpretation"], f"{lane.name}.{name}.default_interpretation"),
                dict(provenance),
            ))
            if used:
                field_mask = ((1 << width) - 1) << offset
                used_mask |= field_mask
                for submode in submodes:
                    submode_masks[submode] |= field_mask
            offset += width
        if used_mask == 0:
            raise InputValidationError(f"RawBits v4 lane {lane.name} must consume at least one bit")
        empty_submodes = [name for name, mask in submode_masks.items() if mask == 0]
        if empty_submodes:
            raise InputValidationError(
                f"RawBits v4 lane {lane.name} has no used fields for submode(s): "
                + ", ".join(empty_submodes)
            )
        built.append(RawBitsV4LaneLayout(
            lane.name, tuple(result), offset, used_mask,
            tuple(sorted(submode_masks.items(), key=lambda item: RawBitsV4Submode[item[0]].value)),
        ))
    built.sort(key=lambda item: RawBitsV4Lane[item.lane].value)
    record_width_bits = max(item.width for item in built)
    natural_bytes = (record_width_bits + 7) // 8
    record_width_bytes = ((natural_bytes + 7) // 8) * 8
    unsigned = RawBitsV4Layout(tuple(built), record_width_bits, record_width_bytes, "")
    return replace(unsigned, digest=content_digest(unsigned.payload_dict()))


def rawbits_v4_layout_from_dict(value: Mapping[str, object]) -> RawBitsV4Layout:
    if not isinstance(value, Mapping):
        raise InputValidationError("RawBits v4 serialized layout must be an object")
    expected = set(RawBitsV4Layout.__dataclass_fields__)
    if set(value) != expected:
        detail = sorted((expected - set(value)) or (set(value) - expected))
        kind = "missing" if expected - set(value) else "unknown"
        raise InputValidationError(
            f"RawBits v4 serialized layout has {kind} field(s): {', '.join(detail)}"
        )
    raw_lanes = value.get("lanes")
    if not isinstance(raw_lanes, (tuple, list)) or not raw_lanes:
        raise InputValidationError("RawBits v4 serialized lanes must be a non-empty array")
    lane_specs: dict[str, tuple[Mapping[str, object], ...]] = {}
    try:
        for raw_lane in raw_lanes:
            if not isinstance(raw_lane, Mapping) or set(raw_lane) != set(RawBitsV4LaneLayout.__dataclass_fields__):
                raise InputValidationError("RawBits v4 serialized lane fields mismatch")
            lane_name = str(raw_lane["lane"])
            raw_fields = raw_lane["fields"]
            if not isinstance(raw_fields, (tuple, list)) or not raw_fields:
                raise InputValidationError("RawBits v4 serialized lane fields are empty")
            fields = []
            for raw_field in raw_fields:
                if not isinstance(raw_field, Mapping) or set(raw_field) != set(RawBitsV4Field.__dataclass_fields__):
                    raise InputValidationError("RawBits v4 serialized field shape mismatch")
                fields.append({key: item for key, item in raw_field.items() if key != "offset"})
            if lane_name in lane_specs:
                raise InputValidationError("RawBits v4 serialized lane is duplicated")
            lane_specs[lane_name] = tuple(fields)
        rebuilt = build_rawbits_v4_layout(lane_specs)
    except (KeyError, TypeError, ValueError) as exc:
        raise InputValidationError("RawBits v4 serialized layout is malformed") from exc
    canonical_rebuilt = json.dumps(
        rebuilt.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    try:
        canonical_input = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("RawBits v4 serialized layout is not canonical JSON") from exc
    if canonical_input != canonical_rebuilt:
        raise InputValidationError("RawBits v4 serialized layout differs from its reconstructed form")
    return rebuilt


def encode_rawbits_v4_testcase(
    layout: RawBitsV4Layout,
    *,
    lane: RawBitsV4Lane | str,
    submode: RawBitsV4Submode | int,
    logical_testcase_id: int,
    records: Iterable[int],
    limits: RawBitsV4Limits = RawBitsV4Limits(),
    records_per_chunk: int = 65535,
) -> bytes:
    layout.__post_init__()
    lane_value = _lane(lane)
    lane_layout = layout.lane_layout(lane_value)
    submode_value = _submode(submode)
    _validate_lane_submode(lane_value, submode_value)
    if isinstance(logical_testcase_id, bool) or not 0 <= logical_testcase_id < 1 << 64:
        raise InputValidationError("RawBits v4 logical_testcase_id must be an unsigned 64-bit integer")
    if isinstance(records_per_chunk, bool) or not 1 <= records_per_chunk <= 65535:
        raise InputValidationError("RawBits v4 records_per_chunk must be 1..65535")
    max_by_payload = limits.max_chunk_payload_bytes // layout.record_width_bytes
    chunk_records = min(records_per_chunk, max_by_payload)
    if chunk_records <= 0:
        raise InputValidationError("RawBits v4 chunk payload limit cannot hold one record")
    values = tuple(records)
    if not values or len(values) > limits.max_logical_records:
        raise InputValidationError("RawBits v4 logical record count is outside manifest limits")
    for index, value in enumerate(values):
        _validate_record(value, lane_layout, submode_value, layout, f"record[{index}]")
    chunks = [values[index:index + chunk_records] for index in range(0, len(values), chunk_records)]
    if len(chunks) > limits.max_chunks:
        raise InputValidationError("RawBits v4 chunk count exceeds manifest limits")
    prefix = bytes.fromhex(layout.digest[:16])
    output = bytearray()
    for index, chunk in enumerate(chunks):
        payload = b"".join(value.to_bytes(layout.record_width_bytes, "little") for value in chunk)
        flags = RAWBITS_V4_FLAG_FINAL if index == len(chunks) - 1 else RAWBITS_V4_FLAG_CONTINUATION
        header = RawBitsV4Header(
            lane_value, submode_value, flags, logical_testcase_id, index,
            layout.record_width_bits, layout.record_width_bytes, len(chunk),
            len(payload), prefix,
        )
        output.extend(header.pack())
        output.extend(payload)
    if len(output) > limits.max_testcase_bytes:
        raise InputValidationError("RawBits v4 testcase bytes exceed manifest limits")
    return bytes(output)


def decode_rawbits_v4_testcase(
    layout: RawBitsV4Layout,
    transport: bytes,
    *,
    limits: RawBitsV4Limits = RawBitsV4Limits(),
) -> RawBitsV4Testcase:
    layout.__post_init__()
    if not isinstance(transport, bytes) or not transport:
        raise InputValidationError("RawBits v4 transport must be non-empty bytes")
    if len(transport) > limits.max_testcase_bytes:
        raise InputValidationError("RawBits v4 testcase bytes exceed manifest limits")
    cursor = 0
    headers: list[RawBitsV4Header] = []
    records: list[int] = []
    expected_prefix = bytes.fromhex(layout.digest[:16])
    while cursor < len(transport):
        if len(headers) >= limits.max_chunks:
            raise InputValidationError("RawBits v4 chunk count exceeds manifest limits")
        end_header = cursor + RAWBITS_V4_HEADER_BYTES
        if end_header > len(transport):
            raise InputValidationError("RawBits v4 transport has a truncated header")
        header = RawBitsV4Header.unpack(transport[cursor:end_header])
        if header.layout_digest_prefix != expected_prefix:
            raise InputValidationError("RawBits v4 layout digest prefix mismatch")
        if header.record_width_bits != layout.record_width_bits or header.record_width_bytes != layout.record_width_bytes:
            raise InputValidationError("RawBits v4 record width does not match target layout")
        expected_payload = header.record_count * header.record_width_bytes
        if expected_payload != header.payload_bytes:
            raise InputValidationError("RawBits v4 payload length does not match record geometry")
        if header.payload_bytes > limits.max_chunk_payload_bytes:
            raise InputValidationError("RawBits v4 chunk payload exceeds manifest limits")
        end_payload = end_header + header.payload_bytes
        if end_payload > len(transport):
            raise InputValidationError("RawBits v4 transport has a truncated payload")
        if headers:
            first = headers[0]
            if (header.logical_testcase_id, header.lane, header.submode) != (
                first.logical_testcase_id, first.lane, first.submode,
            ):
                raise InputValidationError("RawBits v4 continuation identity/lane/submode mismatch")
        if header.chunk_index != len(headers):
            raise InputValidationError("RawBits v4 chunk indexes must be zero-based and contiguous")
        if header.flags == RAWBITS_V4_FLAG_FINAL and end_payload != len(transport):
            raise InputValidationError("RawBits v4 final chunk must terminate the logical testcase")
        if header.flags == RAWBITS_V4_FLAG_CONTINUATION and end_payload == len(transport):
            raise InputValidationError("RawBits v4 logical testcase is missing a final chunk")
        lane_layout = layout.lane_layout(header.lane)
        payload = transport[end_header:end_payload]
        for offset in range(0, len(payload), layout.record_width_bytes):
            value = int.from_bytes(payload[offset:offset + layout.record_width_bytes], "little")
            _validate_record(
                value, lane_layout, header.submode, layout,
                f"chunk[{len(headers)}].record",
            )
            records.append(value)
            if len(records) > limits.max_logical_records:
                raise InputValidationError("RawBits v4 logical record count exceeds manifest limits")
        headers.append(header)
        cursor = end_payload
    if not headers or headers[-1].flags != RAWBITS_V4_FLAG_FINAL:
        raise InputValidationError("RawBits v4 logical testcase has no final chunk")
    first = headers[0]
    return RawBitsV4Testcase(
        layout.digest, first.lane.name, first.submode, first.logical_testcase_id,
        tuple(records), len(headers), hashlib.sha256(transport).hexdigest(),
    )


def envelope_legacy_rawbits_v4(
    data: bytes,
    *,
    legacy_schema: str,
    provenance: Mapping[str, object],
) -> OpaqueRawBitsV4Envelope:
    if not isinstance(data, bytes):
        raise InputValidationError("legacy RawBits payload must be bytes")
    value = OpaqueRawBitsV4Envelope(
        legacy_schema, hashlib.sha256(data).hexdigest(), "base64",
        base64.b64encode(data).decode("ascii"), dict(provenance),
    )
    return replace(value, digest=content_digest(value.payload_dict()))


def unwrap_legacy_rawbits_v4(envelope: OpaqueRawBitsV4Envelope) -> bytes:
    envelope.__post_init__()
    return base64.b64decode(envelope.payload, validate=True)


def opaque_v4_envelope_from_dict(value: Mapping[str, object]) -> OpaqueRawBitsV4Envelope:
    required = {
        "schema", "legacy_schema", "legacy_sha256", "payload_encoding",
        "payload", "provenance", "digest",
    }
    missing, unknown = required - set(value), set(value) - required
    if missing or unknown:
        detail = sorted(missing or unknown)
        kind = "missing" if missing else "unknown"
        raise InputValidationError(f"opaque v4 envelope: {kind} field(s): {', '.join(detail)}")
    if value["schema"] != RAWBITS_V4_OPAQUE_SCHEMA:
        raise InputValidationError("opaque v4 envelope schema version mismatch")
    return OpaqueRawBitsV4Envelope(**{key: item for key, item in value.items() if key != "schema"})


def rawbits_v4_header_schema() -> dict[str, object]:
    """Return the exact machine-readable fixed header layout."""
    fields = (
        ("magic", 0, 8), ("version", 8, 2), ("header_bytes", 10, 2),
        ("lane", 12, 1), ("submode", 13, 1), ("flags", 14, 2),
        ("logical_testcase_id", 16, 8), ("chunk_index", 24, 4),
        ("record_width_bits", 28, 4), ("record_width_bytes", 32, 4),
        ("record_count", 36, 4), ("payload_bytes", 40, 4),
        ("layout_digest_prefix", 44, 8), ("reserved_zero", 52, 8),
        ("header_crc32", 60, 4),
    )
    return {
        "schema": "myfuzz.rawbits-transport-header/v4",
        "byte_order": "little",
        "header_bytes": RAWBITS_V4_HEADER_BYTES,
        "crc_coverage": {"offset": 0, "bytes": 60},
        "fields": [
            {"name": name, "offset_bytes": offset, "size_bytes": size}
            for name, offset, size in fields
        ],
    }


def _validate_header_values(header: RawBitsV4Header) -> None:
    if not isinstance(header.lane, RawBitsV4Lane):
        raise InputValidationError("RawBits v4 header lane must be a RawBitsV4Lane")
    if isinstance(header.submode, bool) or not 0 <= header.submode <= 0xFF:
        raise InputValidationError("RawBits v4 submode must be an unsigned byte")
    if header.flags not in {RAWBITS_V4_FLAG_FINAL, RAWBITS_V4_FLAG_CONTINUATION}:
        raise InputValidationError("RawBits v4 flags must select exactly final or continuation")
    bounds = (
        ("logical_testcase_id", header.logical_testcase_id, (1 << 64) - 1),
        ("chunk_index", header.chunk_index, (1 << 32) - 1),
        ("record_width_bits", header.record_width_bits, (1 << 32) - 1),
        ("record_width_bytes", header.record_width_bytes, (1 << 32) - 1),
        ("record_count", header.record_count, 65535),
        ("payload_bytes", header.payload_bytes, (1 << 32) - 1),
    )
    for name, value, maximum in bounds:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise InputValidationError(f"RawBits v4 {name} is out of range")
    if header.record_width_bits <= 0 or header.record_width_bytes <= 0 or header.record_count <= 0:
        raise InputValidationError("RawBits v4 record dimensions must be positive")
    if header.record_width_bytes % 8:
        raise InputValidationError("RawBits v4 record width bytes must be 8-byte aligned")
    if header.record_width_bytes * 8 < header.record_width_bits:
        raise InputValidationError("RawBits v4 record bytes do not contain record bits")
    if not isinstance(header.layout_digest_prefix, bytes) or len(header.layout_digest_prefix) != 8:
        raise InputValidationError("RawBits v4 layout digest prefix must be 8 bytes")


def _validate_record(
    value: object,
    lane: RawBitsV4LaneLayout,
    submode: int,
    layout: RawBitsV4Layout,
    path: str,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InputValidationError(f"RawBits v4 {path} must be a non-negative integer")
    if value >= 1 << (layout.record_width_bytes * 8):
        raise InputValidationError(f"RawBits v4 {path} does not fit the record bytes")
    if value & ~lane.used_mask_for(submode):
        raise InputValidationError(f"RawBits v4 {path} has nonzero unused or padding bits")


def _validate_lane_submode(lane: RawBitsV4Lane, submode: int) -> None:
    if submode not in {item.value for item in _allowed_submodes(lane)}:
        raise InputValidationError(f"RawBits v4 submode {submode} is invalid for lane {lane.name}")


def _allowed_submodes(lane: RawBitsV4Lane) -> tuple[RawBitsV4Submode, ...]:
    allowed = {
        RawBitsV4Lane.RAW_ESCAPE: {RawBitsV4Submode.RAW_LITERAL},
        RawBitsV4Lane.PROTOCOL_WAVEFORM: {
            RawBitsV4Submode.GUARDED_INTENT, RawBitsV4Submode.LITERAL_TRACE,
        },
        RawBitsV4Lane.ADVERSARIAL_MUTATION: {RawBitsV4Submode.MUTATION},
        RawBitsV4Lane.CPU_SEMANTIC: {
            RawBitsV4Submode.SEMANTIC_OPS, RawBitsV4Submode.PROGRAM_FRAGMENT,
        },
    }
    return tuple(sorted(allowed[lane], key=lambda item: item.value))


def _submode_name(value: object, lane: RawBitsV4Lane) -> str:
    if isinstance(value, RawBitsV4Submode):
        submode = value
    elif isinstance(value, str):
        try:
            submode = RawBitsV4Submode[value]
        except KeyError as exc:
            raise InputValidationError(f"unsupported RawBits v4 submode {value!r}") from exc
    elif isinstance(value, int) and not isinstance(value, bool):
        try:
            submode = RawBitsV4Submode(value)
        except ValueError as exc:
            raise InputValidationError(f"unsupported RawBits v4 submode {value!r}") from exc
    else:
        raise InputValidationError("RawBits v4 submode must be an enum, integer, or canonical name")
    _validate_lane_submode(lane, submode.value)
    return submode.name


def _lane(value: RawBitsV4Lane | str) -> RawBitsV4Lane:
    if isinstance(value, RawBitsV4Lane):
        return value
    if isinstance(value, str):
        try:
            return RawBitsV4Lane[value]
        except KeyError as exc:
            raise InputValidationError(f"unsupported RawBits v4 lane {value!r}") from exc
    raise InputValidationError("RawBits v4 lane must be an enum or canonical name")


def _submode(value: RawBitsV4Submode | int) -> int:
    if isinstance(value, RawBitsV4Submode):
        return value.value
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise InputValidationError("RawBits v4 submode must be an unsigned byte")
    return value


def _sha256(value: object, path: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _positive(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InputValidationError(f"{path}: expected a positive integer")
    return value
