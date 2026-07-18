"""Native RawBits v3 layouts and lossless envelopes for historical v2 bytes."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, replace
import hashlib
from typing import Iterable, Mapping

from .contracts.experiment import canonical_json, content_digest
from .input_model import InputValidationError


@dataclass(frozen=True)
class RawBitsV3Field:
    name: str
    offset: int
    width: int
    source: str
    consumer: str
    minimum: int
    maximum: int
    default: int
    provenance: Mapping[str, object]


@dataclass(frozen=True)
class RawBitsV3Layout:
    fields: tuple[RawBitsV3Field, ...]
    cycle_width: int
    bytes_per_cycle: int
    digest: str
    schema: str = "myfuzz.rawbits-layout/v3"
    byte_order: str = "little"
    bit_order: str = "lsb0"
    cycle_order: str = "forward"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class OpaqueRawBitsV3Envelope:
    legacy_schema: str
    legacy_sha256: str
    payload_encoding: str
    payload: str
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.rawbits-opaque-envelope/v3"

    def __post_init__(self) -> None:
        if self.legacy_schema != "myfuzz.rawbits/v2":
            raise InputValidationError("opaque v3 envelope only accepts myfuzz.rawbits/v2")
        _sha256(self.legacy_sha256, "legacy_sha256")
        if self.payload_encoding != "base64":
            raise InputValidationError("opaque v3 envelope payload_encoding must be base64")
        if not isinstance(self.provenance, Mapping) or not self.provenance:
            raise InputValidationError("opaque v3 envelope provenance must be a non-empty object")
        try:
            payload = base64.b64decode(self.payload, validate=True)
        except (ValueError, TypeError) as exc:
            raise InputValidationError("opaque v3 envelope payload is not canonical base64") from exc
        if base64.b64encode(payload).decode("ascii") != self.payload:
            raise InputValidationError("opaque v3 envelope payload is not canonical base64")
        if hashlib.sha256(payload).hexdigest() != self.legacy_sha256:
            raise InputValidationError("opaque v3 envelope legacy digest mismatch")
        if self.digest and self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("opaque v3 envelope content digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_rawbits_v3_layout(fields: Iterable[Mapping[str, object]]) -> RawBitsV3Layout:
    values = sorted((dict(field) for field in fields), key=lambda item: str(item.get("name", "")))
    if not values:
        raise InputValidationError("RawBits v3 layout must contain at least one field")
    result: list[RawBitsV3Field] = []
    offset = 0
    for index, value in enumerate(values):
        allowed = {"name", "width", "source", "consumer", "minimum", "maximum", "default", "provenance"}
        missing, unknown = allowed - set(value), set(value) - allowed
        if missing or unknown:
            detail = sorted(missing) if missing else sorted(unknown)
            kind = "missing" if missing else "unknown"
            raise InputValidationError(f"RawBits v3 field {index}: {kind} field(s): {', '.join(detail)}")
        name, source, consumer = (_text(value[key], f"field[{index}].{key}") for key in ("name", "source", "consumer"))
        width = _positive(value["width"], f"field[{index}].width")
        minimum = _integer(value["minimum"], f"field[{index}].minimum")
        maximum = _integer(value["maximum"], f"field[{index}].maximum")
        default = _integer(value["default"], f"field[{index}].default")
        if minimum < 0 or maximum < minimum or maximum >= 1 << width or not minimum <= default <= maximum:
            raise InputValidationError(f"field[{index}]: range/default does not fit width")
        provenance = value["provenance"]
        if not isinstance(provenance, Mapping) or not provenance:
            raise InputValidationError(f"field[{index}].provenance: expected a non-empty object")
        result.append(RawBitsV3Field(name, offset, width, source, consumer, minimum, maximum, default, dict(provenance)))
        offset += width
    names = [field.name for field in result]
    if len(names) != len(set(names)):
        raise InputValidationError("RawBits v3 field names must be unique")
    payload = {
        "schema": "myfuzz.rawbits-layout/v3", "byte_order": "little", "bit_order": "lsb0",
        "cycle_order": "forward", "cycle_width": offset, "fields": [asdict(field) for field in result],
    }
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    return RawBitsV3Layout(tuple(result), offset, (offset + 7) // 8, digest)


def envelope_rawbits_v2(data: bytes, *, provenance: Mapping[str, object]) -> OpaqueRawBitsV3Envelope:
    if not isinstance(data, bytes):
        raise InputValidationError("legacy RawBits payload must be bytes")
    value = OpaqueRawBitsV3Envelope(
        legacy_schema="myfuzz.rawbits/v2",
        legacy_sha256=hashlib.sha256(data).hexdigest(),
        payload_encoding="base64",
        payload=base64.b64encode(data).decode("ascii"),
        provenance=dict(provenance),
    )
    return replace(value, digest=content_digest(value.payload_dict()))


def unwrap_rawbits_v2(envelope: OpaqueRawBitsV3Envelope) -> bytes:
    envelope.__post_init__()
    return base64.b64decode(envelope.payload, validate=True)


def opaque_envelope_from_dict(value: Mapping[str, object]) -> OpaqueRawBitsV3Envelope:
    required = {
        "schema", "legacy_schema", "legacy_sha256", "payload_encoding", "payload",
        "provenance", "digest",
    }
    missing, unknown = required - set(value), set(value) - required
    if missing or unknown:
        detail = sorted(missing) if missing else sorted(unknown)
        kind = "missing" if missing else "unknown"
        raise InputValidationError(f"opaque v3 envelope: {kind} field(s): {', '.join(detail)}")
    if value["schema"] != "myfuzz.rawbits-opaque-envelope/v3":
        raise InputValidationError("opaque v3 envelope schema version mismatch")
    return OpaqueRawBitsV3Envelope(**{key: item for key, item in value.items() if key != "schema"})


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


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError(f"{path}: expected an integer")
    return value
