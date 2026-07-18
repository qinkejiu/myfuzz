"""Compose-v5 flat bitstream layout and time-step reference execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
from typing import Callable, Mapping, Protocol

from .contracts.experiment import content_digest
from .input_model import InputValidationError


RAWBITS_V5_LAYOUT_SCHEMA = "myfuzz.rawbits-layout/v5"
RAWBITS_V5_MAX_TESTCASE_BYTES = 1 << 20
RAWBITS_V5_MAX_STEPS = 65_536
RAWBITS_V5_FIELD_KINDS = frozenset({"clock", "reset", "external_input", "selector"})


@dataclass(frozen=True)
class RawBitsV5Field:
    name: str
    component: str
    owner: str
    kind: str
    width: int
    offset: int
    initial_value: int = 0
    direction: str = "input"

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (
            self.name, self.component, self.owner, self.kind, self.direction,
        )):
            raise InputValidationError("RawBits v5 field strings must be non-empty")
        if self.kind not in RAWBITS_V5_FIELD_KINDS:
            raise InputValidationError(f"RawBits v5 field kind {self.kind!r} is unsupported")
        if self.direction != "input":
            raise InputValidationError("RawBits v5 only lays out fuzz-owned input fields")
        if isinstance(self.width, bool) or not isinstance(self.width, int) or self.width <= 0:
            raise InputValidationError("RawBits v5 field width must be a positive integer")
        if isinstance(self.offset, bool) or not isinstance(self.offset, int) or self.offset < 0:
            raise InputValidationError("RawBits v5 field offset must be a non-negative integer")
        if (isinstance(self.initial_value, bool)
                or not isinstance(self.initial_value, int)
                or not 0 <= self.initial_value < (1 << self.width)):
            raise InputValidationError("RawBits v5 initial value does not fit its field width")
        if self.kind == "clock" and self.width != 1:
            raise InputValidationError("RawBits v5 clocks must be one bit wide")


@dataclass(frozen=True)
class RawBitsV5Layout:
    fields: tuple[RawBitsV5Field, ...]
    record_width_bits: int
    record_width_bytes: int
    max_testcase_bytes: int
    max_steps: int
    digest: str
    schema: str = RAWBITS_V5_LAYOUT_SCHEMA
    byte_order: str = "little"
    bit_order: str = "lsb0"
    step_order: str = "forward"
    partial_record: str = "zero_pad"

    def __post_init__(self) -> None:
        if self.schema != RAWBITS_V5_LAYOUT_SCHEMA:
            raise InputValidationError("RawBits v5 layout schema version mismatch")
        if (self.byte_order, self.bit_order, self.step_order, self.partial_record) != (
            "little", "lsb0", "forward", "zero_pad",
        ):
            raise InputValidationError("RawBits v5 ordering or padding contract mismatch")
        if not self.fields:
            raise InputValidationError("RawBits v5 layout requires at least one field")
        if self.record_width_bits <= 0:
            raise InputValidationError("RawBits v5 record width must be positive")
        if self.record_width_bytes != (self.record_width_bits + 7) // 8:
            raise InputValidationError("RawBits v5 records use minimal byte packing")
        if self.max_testcase_bytes != RAWBITS_V5_MAX_TESTCASE_BYTES:
            raise InputValidationError("RawBits v5 testcase byte limit is frozen at 1 MiB")
        expected_steps = min(
            RAWBITS_V5_MAX_STEPS, self.max_testcase_bytes // self.record_width_bytes,
        )
        if self.max_steps != expected_steps or self.max_steps <= 0:
            raise InputValidationError("RawBits v5 maximum step count is inconsistent")
        cursor = 0
        identities: set[tuple[str, str]] = set()
        owners: set[str] = set()
        for field in self.fields:
            if field.offset != cursor:
                raise InputValidationError("RawBits v5 fields must be densely packed")
            identity = (field.component, field.name)
            if identity in identities:
                raise InputValidationError("RawBits v5 component field names must be unique")
            identities.add(identity)
            if field.owner in owners:
                raise InputValidationError("RawBits v5 field owners must be globally unique")
            owners.add(field.owner)
            cursor += field.width
        if cursor != self.record_width_bits:
            raise InputValidationError("RawBits v5 field widths do not match record width")
        if self.digest:
            _digest(self.digest, "RawBitsV5Layout.digest")
            if self.digest != content_digest(self.payload_dict()):
                raise InputValidationError("RawBits v5 layout digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RawBitsV5Testcase:
    raw_bytes: bytes
    records: tuple[int, ...]
    padded_final_bytes: int


@dataclass(frozen=True)
class RawBitsV5Run:
    steps: int
    eval_count: int
    rising_edges: Mapping[str, int]
    falling_edges: Mapping[str, int]
    wire_digest: str
    coverage_digest: str
    settled: bool
    failure: str | None = None


class RawBitsV5Model(Protocol):
    def drive_inputs(self, values: Mapping[str, int]) -> None: ...
    def eval(self) -> None: ...
    def wire_state(self) -> bytes: ...
    def coverage_state(self) -> bytes: ...


def build_rawbits_v5_layout(fields: tuple[Mapping[str, object], ...]) -> RawBitsV5Layout:
    if not isinstance(fields, tuple) or not fields:
        raise InputValidationError("RawBits v5 layout fields must be a non-empty tuple")
    allowed = {"name", "component", "owner", "kind", "width", "initial_value", "direction"}
    normalized: list[dict[str, object]] = []
    for index, raw in enumerate(fields):
        if not isinstance(raw, Mapping):
            raise InputValidationError(f"RawBits v5 fields[{index}] must be an object")
        unknown = set(raw) - allowed
        required = {"name", "component", "owner", "kind", "width"} - set(raw)
        if unknown or required:
            detail = sorted(unknown or required)
            word = "unknown" if unknown else "missing"
            raise InputValidationError(f"RawBits v5 fields[{index}] {word}: {', '.join(detail)}")
        normalized.append(dict(raw))
    normalized.sort(key=lambda item: (
        str(item["component"]), str(item["owner"]), str(item["name"]), str(item["kind"]),
    ))
    offset = 0
    built: list[RawBitsV5Field] = []
    for item in normalized:
        field = RawBitsV5Field(
            name=item["name"], component=item["component"], owner=item["owner"],
            kind=item["kind"], width=item["width"], offset=offset,
            initial_value=item.get("initial_value", 0), direction=item.get("direction", "input"),
        )
        built.append(field)
        offset += field.width
        if offset > RAWBITS_V5_MAX_TESTCASE_BYTES * 8:
            raise InputValidationError("RawBits v5 one-step record exceeds 1 MiB")
    record_bytes = (offset + 7) // 8
    layout = RawBitsV5Layout(
        tuple(built), offset, record_bytes, RAWBITS_V5_MAX_TESTCASE_BYTES,
        min(RAWBITS_V5_MAX_STEPS, RAWBITS_V5_MAX_TESTCASE_BYTES // record_bytes), "",
    )
    return replace(layout, digest=content_digest(layout.payload_dict()))


def rawbits_v5_layout_from_dict(value: Mapping[str, object]) -> RawBitsV5Layout:
    if not isinstance(value, Mapping):
        raise InputValidationError("RawBits v5 layout must be an object")
    expected = {
        "schema", "fields", "record_width_bits", "record_width_bytes",
        "max_testcase_bytes", "max_steps", "digest", "byte_order", "bit_order",
        "step_order", "partial_record",
    }
    if set(value) != expected:
        raise InputValidationError("RawBits v5 serialized layout fields are invalid")
    raw_fields = value["fields"]
    if not isinstance(raw_fields, (list, tuple)):
        raise InputValidationError("RawBits v5 serialized fields must be an array")
    fields = tuple(RawBitsV5Field(**dict(item)) for item in raw_fields)
    return RawBitsV5Layout(
        fields=fields,
        record_width_bits=value["record_width_bits"],
        record_width_bytes=value["record_width_bytes"],
        max_testcase_bytes=value["max_testcase_bytes"],
        max_steps=value["max_steps"],
        digest=value["digest"], schema=value["schema"], byte_order=value["byte_order"],
        bit_order=value["bit_order"], step_order=value["step_order"],
        partial_record=value["partial_record"],
    )


def decode_rawbits_v5_testcase(layout: RawBitsV5Layout, data: bytes) -> RawBitsV5Testcase:
    if not isinstance(data, bytes):
        raise InputValidationError("RawBits v5 testcase must be bytes")
    if len(data) > layout.max_testcase_bytes:
        raise InputValidationError("RawBits v5 testcase exceeds 1 MiB")
    if not data:
        return RawBitsV5Testcase(data, (), 0)
    count = _checked_ceil_div(len(data), layout.record_width_bytes)
    if count > layout.max_steps:
        raise InputValidationError("RawBits v5 testcase exceeds the maximum step count")
    padded = count * layout.record_width_bytes - len(data)
    payload = data + b"\x00" * padded
    mask = (1 << layout.record_width_bits) - 1
    records = tuple(
        int.from_bytes(payload[offset:offset + layout.record_width_bytes], "little") & mask
        for offset in range(0, len(payload), layout.record_width_bytes)
    )
    return RawBitsV5Testcase(data, records, padded)


def encode_rawbits_v5_records(layout: RawBitsV5Layout, records: tuple[int, ...]) -> bytes:
    if not isinstance(records, tuple):
        raise InputValidationError("RawBits v5 records must be a tuple")
    if len(records) > layout.max_steps:
        raise InputValidationError("RawBits v5 record count exceeds the maximum step count")
    mask = (1 << layout.record_width_bits) - 1
    result = bytearray()
    for record in records:
        if isinstance(record, bool) or not isinstance(record, int) or not 0 <= record <= mask:
            raise InputValidationError("RawBits v5 record does not fit the layout")
        result.extend(record.to_bytes(layout.record_width_bytes, "little"))
    if len(result) > layout.max_testcase_bytes:
        raise InputValidationError("RawBits v5 encoded testcase exceeds 1 MiB")
    return bytes(result)


def decode_rawbits_v5_record(layout: RawBitsV5Layout, record: int) -> dict[str, int]:
    return {
        field.owner: (record >> field.offset) & ((1 << field.width) - 1)
        for field in layout.fields
    }


def run_rawbits_v5_reference(
    layout: RawBitsV5Layout,
    data: bytes,
    model_factory: Callable[[], RawBitsV5Model],
    *,
    max_settle_evals: int = 32,
) -> RawBitsV5Run:
    if isinstance(max_settle_evals, bool) or not isinstance(max_settle_evals, int) \
            or max_settle_evals < 2:
        raise InputValidationError("RawBits v5 settle limit must be at least two evals")
    testcase = decode_rawbits_v5_testcase(layout, data)
    model = model_factory()
    prior = {field.owner: field.initial_value for field in layout.fields}
    rising = {field.owner: 0 for field in layout.fields if field.kind == "clock"}
    falling = dict(rising)
    wire_trace = bytearray()
    coverage_trace = bytearray()
    eval_count = 0
    for step_index, record in enumerate(testcase.records):
        values = decode_rawbits_v5_record(layout, record)
        for owner in rising:
            if prior[owner] == 0 and values[owner] == 1:
                rising[owner] += 1
            elif prior[owner] == 1 and values[owner] == 0:
                falling[owner] += 1
        model.drive_inputs(values)
        previous: bytes | None = None
        settled = False
        for _ in range(max_settle_evals):
            model.eval()
            eval_count += 1
            current = bytes(model.wire_state())
            if previous == current:
                settled = True
                break
            previous = current
        if not settled:
            return RawBitsV5Run(
                step_index + 1, eval_count, rising, falling,
                hashlib.sha256(wire_trace).hexdigest(),
                hashlib.sha256(coverage_trace).hexdigest(), False, "settle_limit",
            )
        wire_trace.extend(len(previous).to_bytes(8, "little"))
        wire_trace.extend(previous)
        coverage = bytes(model.coverage_state())
        coverage_trace.extend(len(coverage).to_bytes(8, "little"))
        coverage_trace.extend(coverage)
        prior = values
    return RawBitsV5Run(
        len(testcase.records), eval_count, rising, falling,
        hashlib.sha256(wire_trace).hexdigest(), hashlib.sha256(coverage_trace).hexdigest(), True,
    )


def _checked_ceil_div(value: int, divisor: int) -> int:
    if value < 0 or divisor <= 0:
        raise InputValidationError("RawBits v5 checked length arithmetic received invalid values")
    return value // divisor + (1 if value % divisor else 0)


def _digest(value: str, path: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
