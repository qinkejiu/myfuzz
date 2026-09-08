"""Fixed test headers and equal-width RFuzz cycle input records."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from myfuzz.contracts import content_hash

from .rfuzz_transport import RfuzzInputTransport


class CycleInputError(ValueError):
    """Raised when a cycle input layout, header, or payload is invalid."""


_LAYOUT_SCHEMA_VERSION = "cycle_input_layout.v1"
TEST_HEADER_SCHEMA_VERSION = "cycle_test.v1"


def _layout_document(
    schema_version: str,
    raw_width: int,
    fields: Sequence[CycleField],
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "raw_width": raw_width,
        "fields": [
            {
                "name": item.name,
                "width": item.width,
                "raw_lo": item.raw_lo,
                "raw_hi": item.raw_hi,
            }
            for item in fields
        ],
    }


def _validate_layout(
    schema_version: object,
    raw_width: object,
    fields: object,
    layout_hash: object,
) -> None:
    if schema_version != _LAYOUT_SCHEMA_VERSION:
        raise CycleInputError("invalid cycle layout schema version")
    if type(raw_width) is not int or raw_width <= 0:
        raise CycleInputError("cycle layout raw width is invalid")
    if not isinstance(fields, tuple) or not fields:
        raise CycleInputError("cycle layout fields are invalid")
    names: set[str] = set()
    cursor = 0
    for item in fields:
        if not isinstance(item, CycleField):
            raise CycleInputError("cycle layout fields are invalid")
        if item.name in names:
            raise CycleInputError("duplicate cycle field name")
        names.add(item.name)
        if item.raw_lo != cursor:
            raise CycleInputError("cycle field offsets are not contiguous")
        if item.raw_hi != item.raw_lo + item.width - 1:
            raise CycleInputError("cycle field width does not match offsets")
        cursor = item.raw_hi + 1
    if cursor != raw_width:
        raise CycleInputError("cycle layout raw width does not cover fields")
    if not isinstance(layout_hash, str) or not layout_hash:
        raise CycleInputError("cycle layout hash is required")
    expected_hash = content_hash(_layout_document(schema_version, raw_width, fields))
    if layout_hash != expected_hash:
        raise CycleInputError("cycle layout hash does not match canonical layout")


@dataclass(frozen=True, slots=True)
class TestHeader:
    __test__ = False

    schema_version: str
    layout_hash: str
    contract_hash: str
    reset_cycles: int
    execution_cycles: int
    boot_address: int
    hart_id: int
    illegal_instruction: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != TEST_HEADER_SCHEMA_VERSION:
            raise CycleInputError("unsupported header schema version")
        if not isinstance(self.layout_hash, str) or not self.layout_hash:
            raise CycleInputError("header layout hash is required")
        if not isinstance(self.contract_hash, str) or not self.contract_hash:
            raise CycleInputError("header contract hash is required")
        for name in ("reset_cycles", "execution_cycles", "boot_address", "hart_id"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise CycleInputError(f"header {name.replace('_', ' ')} is invalid")
        if not isinstance(self.illegal_instruction, bool):
            raise CycleInputError("header illegal instruction flag is invalid")


@dataclass(frozen=True, slots=True)
class CycleField:
    """One declared slice of a raw cycle record.

    ``raw_lo`` and ``raw_hi`` are assigned by :meth:`CycleInputLayout.build`;
    callers declare only a stable name and width.
    """

    field_id: str
    width: int
    raw_lo: int = field(default=-1, init=False)
    raw_hi: int = field(default=-1, init=False)

    @property
    def name(self) -> str:
        """Compatibility alias for the declared field identifier."""
        return self.field_id

    def __post_init__(self) -> None:
        if not isinstance(self.field_id, str) or not self.field_id:
            raise CycleInputError("cycle field name is required")
        if type(self.width) is not int or self.width <= 0:
            raise CycleInputError("cycle field width must be positive")


@dataclass(frozen=True, slots=True)
class CycleInputLayout:
    schema_version: str
    raw_width: int
    fields: tuple[CycleField, ...]
    layout_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.fields, tuple):
            try:
                object.__setattr__(self, "fields", tuple(self.fields))
            except TypeError as exc:
                raise CycleInputError("cycle layout fields are invalid") from exc
        _validate_layout(self.schema_version, self.raw_width, self.fields, self.layout_hash)

    def validate(self) -> None:
        """Revalidate mutable escape hatches such as ``object.__setattr__``."""
        _validate_layout(self.schema_version, self.raw_width, self.fields, self.layout_hash)

    @classmethod
    def build(cls, fields: Sequence[CycleField]) -> "CycleInputLayout":
        if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)):
            raise CycleInputError("cycle fields must be a sequence")
        declared = tuple(fields)
        if not declared:
            raise CycleInputError("cycle layout requires fields")
        if any(not isinstance(item, CycleField) for item in declared):
            raise CycleInputError("cycle layout fields are invalid")
        names = [item.name for item in declared]
        if len(set(names)) != len(names):
            raise CycleInputError("duplicate cycle field name")

        offset = 0
        positioned: list[CycleField] = []
        for item in declared:
            positioned_item = CycleField(item.name, item.width)
            object.__setattr__(positioned_item, "raw_lo", offset)
            object.__setattr__(positioned_item, "raw_hi", offset + item.width - 1)
            positioned.append(positioned_item)
            offset += item.width

        document = _layout_document(_LAYOUT_SCHEMA_VERSION, offset, tuple(positioned))
        return cls(_LAYOUT_SCHEMA_VERSION, offset, tuple(positioned), content_hash(document))

    def document(self) -> dict[str, object]:
        """Return the canonical, hash-bound layout document."""
        self.validate()
        document = _layout_document(self.schema_version, self.raw_width, self.fields)
        return {**document, "layout_hash": self.layout_hash}


@dataclass(frozen=True, slots=True)
class CycleTestCase:
    header: TestHeader
    raw_cycles: tuple[int, ...]
    truncated_bytes: int


def parse_cycle_payload(
    payload: bytes,
    layout: CycleInputLayout,
    header: TestHeader,
) -> CycleTestCase:
    """Decode complete equal-width records and stop at the execution limit."""
    if not isinstance(payload, bytes):
        raise CycleInputError("cycle payload must be bytes")
    if not isinstance(layout, CycleInputLayout):
        raise CycleInputError("cycle layout is required")
    if not isinstance(header, TestHeader):
        raise CycleInputError("cycle header is required")
    layout.validate()
    if header.layout_hash != layout.layout_hash:
        raise CycleInputError("header layout hash does not match cycle layout")

    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)
    raw_cycles, truncated_bytes = transport.unpack_records(
        payload, max_records=header.execution_cycles
    )
    return CycleTestCase(header, raw_cycles, truncated_bytes)


__all__ = [
    "CycleField",
    "CycleInputError",
    "CycleInputLayout",
    "CycleTestCase",
    "TestHeader",
    "TEST_HEADER_SCHEMA_VERSION",
    "parse_cycle_payload",
]
