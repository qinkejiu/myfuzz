"""RFUZZ RawBits v2 layout, packing, and strict compatibility gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .input_model import InputValidationError


RAWBITS_SCHEMA = "myfuzz.rawbits/v2"
RAWBITS_LAYOUT_SCHEMA = "myfuzz.rawbits-layout/v2"


@dataclass(frozen=True)
class RawBitsLayoutEntry:
    target: str
    offset: int
    raw_width: int
    value_width: int
    purpose: str
    provenance: str


@dataclass(frozen=True)
class RawBitsLayout:
    entries: tuple[RawBitsLayoutEntry, ...]
    cycle_width: int
    bytes_per_cycle: int
    digest: str
    schema: str = RAWBITS_LAYOUT_SCHEMA
    byte_order: str = "little"
    bit_order: str = "lsb0"
    cycle_order: str = "forward"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RawBitsTestcase:
    cycles: tuple[int, ...]
    metadata: Mapping[str, object]


def build_rawbits_layout(entries: Iterable[Mapping[str, object]]) -> RawBitsLayout:
    normalized: list[tuple[str, int, int, str, str]] = []
    for index, value in enumerate(entries):
        target = _text(value.get("target"), f"layout[{index}].target")
        raw_width = _positive(value.get("raw_width", value.get("width")), f"layout[{index}].raw_width")
        value_width = _positive(value.get("value_width", value.get("width")), f"layout[{index}].value_width")
        purpose = _text(value.get("purpose"), f"layout[{index}].purpose")
        provenance = _text(value.get("provenance"), f"layout[{index}].provenance")
        normalized.append((target, raw_width, value_width, purpose, provenance))
    normalized.sort()
    if len({item[0] for item in normalized}) != len(normalized):
        raise InputValidationError("RawBits layout targets must be unique")
    offset = 0
    layout_entries: list[RawBitsLayoutEntry] = []
    for target, raw_width, value_width, purpose, provenance in normalized:
        layout_entries.append(RawBitsLayoutEntry(
            target, offset, raw_width, value_width, purpose, provenance,
        ))
        offset += raw_width
    if offset <= 0:
        raise InputValidationError("RawBits layout must contain at least one bit")
    payload = {
        "schema": RAWBITS_LAYOUT_SCHEMA,
        "byte_order": "little",
        "bit_order": "lsb0",
        "cycle_order": "forward",
        "cycle_width": offset,
        "entries": [asdict(item) for item in layout_entries],
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return RawBitsLayout(tuple(layout_entries), offset, (offset + 7) // 8, digest)


def pack_rawbits_cycles(layout: RawBitsLayout, cycles: Iterable[int]) -> tuple[bytes, dict[str, object]]:
    values = tuple(cycles)
    limit = 1 << layout.cycle_width
    encoded = bytearray()
    for index, value in enumerate(values):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= limit:
            raise InputValidationError(f"RawBits cycle {index}: value does not fit cycle_width")
        encoded.extend(value.to_bytes(layout.bytes_per_cycle, layout.byte_order))
    metadata = {
        "schema": RAWBITS_SCHEMA,
        "layout_digest": layout.digest,
        "cycle_width": layout.cycle_width,
        "bytes_per_cycle": layout.bytes_per_cycle,
        "cycles": len(values),
        "byte_order": layout.byte_order,
        "bit_order": layout.bit_order,
        "cycle_order": layout.cycle_order,
    }
    return bytes(encoded), metadata


def decode_rawbits_testcase(
    layout: RawBitsLayout, data: bytes, metadata: Mapping[str, object],
) -> RawBitsTestcase:
    expected = {
        "schema": RAWBITS_SCHEMA,
        "layout_digest": layout.digest,
        "cycle_width": layout.cycle_width,
        "bytes_per_cycle": layout.bytes_per_cycle,
        "byte_order": layout.byte_order,
        "bit_order": layout.bit_order,
        "cycle_order": layout.cycle_order,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise InputValidationError(
                f"RawBits metadata mismatch for {key}: expected {value!r}, got {metadata.get(key)!r}"
            )
    cycle_count = metadata.get("cycles")
    if isinstance(cycle_count, bool) or not isinstance(cycle_count, int) or cycle_count < 0:
        raise InputValidationError("RawBits metadata cycles must be a non-negative integer")
    expected_size = cycle_count * layout.bytes_per_cycle
    if len(data) != expected_size:
        raise InputValidationError(
            f"RawBits byte length mismatch: expected {expected_size}, got {len(data)}"
        )
    limit = 1 << layout.cycle_width
    cycles = tuple(
        int.from_bytes(data[index:index + layout.bytes_per_cycle], layout.byte_order)
        for index in range(0, len(data), layout.bytes_per_cycle)
    )
    if any(value >= limit for value in cycles):
        raise InputValidationError("RawBits unused high bits must be zero")
    return RawBitsTestcase(cycles, dict(metadata))


def write_rawbits_testcase(
    layout: RawBitsLayout,
    cycles: Iterable[int],
    output_dir: str | Path,
    *,
    name: str,
) -> dict[str, str]:
    if not name.isidentifier():
        raise InputValidationError("RawBits testcase name must be an identifier")
    data, metadata = pack_rawbits_cycles(layout, cycles)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    binary_path = output / f"{name}.rawbits"
    metadata_path = output / f"{name}.json"
    binary_path.write_bytes(data)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return {"rawbits": str(binary_path), "metadata": str(metadata_path)}


def load_rawbits_testcase(
    layout: RawBitsLayout, data_path: str | Path, metadata_path: str | Path,
) -> RawBitsTestcase:
    metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    if not isinstance(metadata, Mapping):
        raise InputValidationError("RawBits metadata must be an object")
    return decode_rawbits_testcase(layout, Path(data_path).read_bytes(), metadata)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _positive(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InputValidationError(f"{path}: expected a positive integer")
    return value
