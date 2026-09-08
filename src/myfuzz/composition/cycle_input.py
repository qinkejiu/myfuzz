"""Fixed test headers and equal-width RFuzz cycle input records."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from myfuzz.contracts import content_hash

from .rfuzz_transport import RfuzzInputTransport


class CycleInputError(ValueError):
    """Raised when a cycle input layout, header, or payload is invalid."""


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
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise CycleInputError("header schema version is required")
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

    name: str
    width: int
    raw_lo: int = field(default=-1, init=False)
    raw_hi: int = field(default=-1, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise CycleInputError("cycle field name is required")
        if type(self.width) is not int or self.width <= 0:
            raise CycleInputError("cycle field width must be positive")


@dataclass(frozen=True, slots=True)
class CycleInputLayout:
    schema_version: str
    raw_width: int
    fields: tuple[CycleField, ...]
    layout_hash: str

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

        document = {
            "schema_version": "cycle_input_layout.v1",
            "raw_width": offset,
            "fields": [
                {
                    "name": item.name,
                    "width": item.width,
                    "raw_lo": item.raw_lo,
                    "raw_hi": item.raw_hi,
                }
                for item in positioned
            ],
        }
        return cls("cycle_input_layout.v1", offset, tuple(positioned), content_hash(document))

    def document(self) -> dict[str, object]:
        """Return the canonical, hash-bound layout document."""
        return {
            "schema_version": self.schema_version,
            "raw_width": self.raw_width,
            "fields": [
                {
                    "name": item.name,
                    "width": item.width,
                    "raw_lo": item.raw_lo,
                    "raw_hi": item.raw_hi,
                }
                for item in self.fields
            ],
            "layout_hash": self.layout_hash,
        }


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
    "parse_cycle_payload",
]
