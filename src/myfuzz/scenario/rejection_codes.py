"""Versioned, machine-readable rejection codes for decoded candidates.

A refusal is only evidence when it can be recomputed: every rejection carries a
stable code from :class:`RejectionCode`, the path of the field that failed, and
a JSON-safe summary of the offending value. The natural-language message stays
for humans and is never the contract.

``candidate_rejection.v1`` covers candidate-time validation: instruction and
MMIO field checks, mutation entropy, ownership of the targeted input bits, the
online instruction reservation, the initialized-byte budget, and path/source
identity. Construction-time configuration errors of ``OnlineCaseDecoder`` still
raise plain :class:`ValueError`, because no candidate exists yet.

Raising is fail-closed: a caller that cannot classify a refusal must keep the
original error, not invent a code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import re
from types import MappingProxyType
from typing import NoReturn


REJECTION_SCHEMA_VERSION = "candidate_rejection.v1"
REJECTION_CATALOG_SCHEMA_VERSION = "candidate_rejection_catalog.v1"
REJECTION_DOCUMENT_KEYS = frozenset(
    {"schema_version", "code", "pointer", "detail"})
#: A pointer names a field path such as ``instruction.rd`` or ``fragment[4].funct3``.
POINTER_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\[[0-9]+\])?(\.[A-Za-z_][A-Za-z0-9_]*(\[[0-9]+\])?)*$")


class RejectionCode(StrEnum):
    """Stable rejection identities; the string value is the contract."""

    ISA_DISALLOWED_OPERATION = "isa.disallowed_operation"
    ISA_UNEXPECTED_OPERAND = "isa.unexpected_operand"
    ISA_RESERVED_IMM_BIT = "isa.reserved_imm_bit"
    FIELD_BAD_REGISTER = "field.bad_register"
    FIELD_REGISTER_CONFLICT = "field.register_conflict"
    FIELD_BAD_IMMEDIATE = "field.bad_immediate"
    FIELD_BAD_SHAMT = "field.bad_shamt"
    FIELD_BAD_ALIGNMENT = "field.bad_alignment"
    FIELD_BAD_ADDRESS = "field.bad_address"
    FRAGMENT_INVALID_SEQUENCE = "fragment.invalid_sequence"
    FRAGMENT_EXCEEDS_ADDRESS_SPACE = "fragment.exceeds_address_space"
    MMIO_BAD_WINDOW = "mmio.bad_window"
    MMIO_BAD_PERMISSION = "mmio.bad_permission"
    MMIO_BAD_WIDTH = "mmio.bad_width"
    MMIO_NO_WINDOW = "mmio.no_window"
    MMIO_OUT_OF_WINDOW = "mmio.out_of_window"
    MMIO_READ_ONLY = "mmio.read_only"
    MMIO_WRITE_ONLY = "mmio.write_only"
    MMIO_WINDOW_DENIED = "mmio.window_denied"
    MMIO_NO_ALIGNED_ADDRESS = "mmio.no_aligned_address"
    DECODE_MALFORMED_RECORD = "decode.malformed_record"
    DECODE_MALFORMED_ENTROPY = "decode.malformed_entropy"
    DECODE_MALFORMED_SEED = "decode.malformed_seed"
    DECODE_UNBOUNDED_INPUT = "decode.unbounded_input"
    DECODE_BAD_COVERAGE_HINT = "decode.bad_coverage_hint"
    OWNERSHIP_BOUND_INPUT = "ownership.bound_input"
    OWNERSHIP_FIXED_INPUT = "ownership.fixed_input"
    OWNERSHIP_UNDECLARED_FIELD = "ownership.undeclared_field"
    OWNERSHIP_RANGE_EXCEEDS_FIELD = "ownership.range_exceeds_field"
    OWNERSHIP_AMBIGUOUS_PRODUCER = "ownership.ambiguous_producer"
    SLOT_OUT_OF_RESERVATION = "slot.out_of_reservation"
    SLOT_MATERIALIZED = "slot.materialized"
    SLOT_ALREADY_CONSUMED = "slot.already_consumed"
    SLOT_PROPOSAL_MISMATCH = "slot.proposal_mismatch"
    BUDGET_EXHAUSTED = "budget.exhausted"
    PATH_UNDECLARED = "path.undeclared"
    PATH_SOURCE_MISMATCH = "path.source_mismatch"


_DESCRIPTIONS = MappingProxyType({
    RejectionCode.ISA_DISALLOWED_OPERATION:
        "Operation is outside the admitted first-stage RV32I subset.",
    RejectionCode.ISA_UNEXPECTED_OPERAND:
        "Instruction encodes an operand its operation does not use.",
    RejectionCode.ISA_RESERVED_IMM_BIT:
        "Shift immediate sets bits that RV32I reserves in the OP-IMM format.",
    RejectionCode.FIELD_BAD_REGISTER:
        "Register operand is not an RV32I register number 0..31.",
    RejectionCode.FIELD_REGISTER_CONFLICT:
        "Base and data registers are equal or name x0.",
    RejectionCode.FIELD_BAD_IMMEDIATE:
        "Immediate or stored value does not fit its declared field.",
    RejectionCode.FIELD_BAD_SHAMT:
        "Shift amount is not an RV32I shamt value 0..31.",
    RejectionCode.FIELD_BAD_ALIGNMENT:
        "Address or offset is not aligned to the access width.",
    RejectionCode.FIELD_BAD_ADDRESS:
        "Address is not a 32-bit RV32 byte address.",
    RejectionCode.FRAGMENT_INVALID_SEQUENCE:
        "Fragment is not a nonempty tuple of RV32I instructions.",
    RejectionCode.FRAGMENT_EXCEEDS_ADDRESS_SPACE:
        "Fragment image runs past the end of the RV32 address space.",
    RejectionCode.MMIO_BAD_WINDOW:
        "MMIO window does not describe a nonempty RV32 range.",
    RejectionCode.MMIO_BAD_PERMISSION:
        "MMIO window permissions are not boolean or deny both directions.",
    RejectionCode.MMIO_BAD_WIDTH:
        "Access width is not declared by the target window.",
    RejectionCode.MMIO_NO_WINDOW:
        "No usable MMIO window was declared for this access.",
    RejectionCode.MMIO_OUT_OF_WINDOW:
        "MMIO address lies outside every declared window.",
    RejectionCode.MMIO_READ_ONLY:
        "Store targets a window that is not writable.",
    RejectionCode.MMIO_WRITE_ONLY:
        "Load targets a window that is not readable.",
    RejectionCode.MMIO_WINDOW_DENIED:
        "No declared window permits the requested operation.",
    RejectionCode.MMIO_NO_ALIGNED_ADDRESS:
        "Permitted window has no aligned address for this width.",
    RejectionCode.DECODE_MALFORMED_RECORD:
        "Candidate record or instruction bytes are not complete words.",
    RejectionCode.DECODE_MALFORMED_ENTROPY:
        "Mutation entropy is missing or shorter than four bytes.",
    RejectionCode.DECODE_MALFORMED_SEED:
        "Mutation seed is not a supported RV32I instruction.",
    RejectionCode.DECODE_UNBOUNDED_INPUT:
        "Online input is empty or exceeds the declared byte bound.",
    RejectionCode.DECODE_BAD_COVERAGE_HINT:
        "Coverage hints name unknown sources or nonpositive weights.",
    RejectionCode.OWNERSHIP_BOUND_INPUT:
        "Mutation targets bits owned by a bound producer.",
    RejectionCode.OWNERSHIP_FIXED_INPUT:
        "Mutation targets bits owned by a fixed producer.",
    RejectionCode.OWNERSHIP_UNDECLARED_FIELD:
        "Mutation targets an input field absent from the ownership map.",
    RejectionCode.OWNERSHIP_RANGE_EXCEEDS_FIELD:
        "Mutation span exceeds the declared input field width.",
    RejectionCode.OWNERSHIP_AMBIGUOUS_PRODUCER:
        "Mutation spans more than one fuzzable producer.",
    RejectionCode.SLOT_OUT_OF_RESERVATION:
        "Fragment does not fit its declared online instruction reservation.",
    RejectionCode.SLOT_MATERIALIZED:
        "Instruction bytes were already determined by a real read or Store.",
    RejectionCode.SLOT_ALREADY_CONSUMED:
        "Reserved instruction word was already filled by an admitted candidate.",
    RejectionCode.SLOT_PROPOSAL_MISMATCH:
        "Commit was called with a case that is not the current proposal.",
    RejectionCode.BUDGET_EXHAUSTED:
        "Online instruction reservation or initialized-byte budget is exhausted.",
    RejectionCode.PATH_UNDECLARED:
        "Case path is not declared by this decoder.",
    RejectionCode.PATH_SOURCE_MISMATCH:
        "Case source is not declared on the selected path.",
})
assert set(_DESCRIPTIONS) == set(RejectionCode), "every rejection code needs a description"

#: Message-keyed bridge for refusals raised by modules that do not yet carry a
#: :class:`Rejection`. It never replaces a real code; it only classifies one.
_LEGACY_MESSAGES = MappingProxyType({
    "instruction bytes are outside declared online slots":
        (RejectionCode.SLOT_OUT_OF_RESERVATION, "memory.address"),
    "instruction slots contain determined bytes":
        (RejectionCode.SLOT_MATERIALIZED, "memory.address"),
    "initialized byte budget exceeded":
        (RejectionCode.BUDGET_EXHAUSTED, "memory.max_initialized_bytes"),
})
_OVERWRITE_MESSAGE = "instruction admission would overwrite determined bytes"
#: Writer kind of a byte that an earlier admitted candidate already filled.
_CONSUMED_WRITER_KIND = "INSTRUCTION_SOURCE"


def description_of(code: RejectionCode | str) -> str:
    """Return the short English description of one rejection code."""
    return _DESCRIPTIONS[RejectionCode(code)]


def rejection_code_catalog() -> dict:
    """Stable catalog of every defined code, for digest pinning."""
    return {
        "schema_version": REJECTION_CATALOG_SCHEMA_VERSION,
        "rejection_schema_version": REJECTION_SCHEMA_VERSION,
        "codes": [{"code": code.value, "description": _DESCRIPTIONS[code]}
                  for code in sorted(RejectionCode, key=lambda item: item.value)],
    }


def rejection_code_catalog_sha256() -> str:
    """Canonical digest of the catalog; a rename changes this value."""
    encoded = json.dumps(rejection_code_catalog(), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def value_summary(value: object, *, limit: int = 64) -> object:
    """Summarize one rejected value as JSON-safe data without floats.

    Anything that is not a JSON scalar, bytes or a sequence is reduced to a
    bounded ``repr`` so a rejection can always be serialized.
    """
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, (tuple, list)):
        return [value_summary(item, limit=limit) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _freeze_value(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, float):
        raise ValueError("rejection detail must not contain floats")
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_value(item) for item in value)
    raise ValueError("rejection detail must be JSON serializable")


def _freeze_detail(detail: object) -> Mapping[str, object] | None:
    if detail is None:
        return None
    if not isinstance(detail, Mapping):
        raise ValueError("rejection detail must be a mapping or None")
    frozen: dict[str, object] = {}
    for key, value in detail.items():
        if not isinstance(key, str) or not key:
            raise ValueError("rejection detail keys must be nonempty strings")
        frozen[key] = _freeze_value(value)
    return MappingProxyType(dict(sorted(frozen.items())))


def _thaw_value(value: object) -> object:
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    return value


def _thaw_detail(detail: Mapping[str, object] | None) -> dict | None:
    if detail is None:
        return None
    return {key: _thaw_value(value) for key, value in detail.items()}


def _coerce_code(code: object) -> RejectionCode:
    if isinstance(code, RejectionCode):
        return code
    if isinstance(code, str):
        try:
            return RejectionCode(code)
        except ValueError:
            pass
    raise ValueError(f"unknown rejection code: {code!r}")


@dataclass(frozen=True)
class Rejection:
    """One immutable, recomputable refusal of a candidate input."""

    code: RejectionCode
    pointer: str
    detail: Mapping[str, object] | None = None
    schema_version: str = REJECTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _coerce_code(self.code))
        if self.schema_version != REJECTION_SCHEMA_VERSION:
            raise ValueError(
                f"unknown rejection schema version: {self.schema_version!r}")
        if (not isinstance(self.pointer, str)
                or not POINTER_PATTERN.match(self.pointer)):
            raise ValueError(
                f"rejection pointer must be a dotted field path: {self.pointer!r}")
        object.__setattr__(self, "detail", _freeze_detail(self.detail))

    def document(self) -> dict:
        """Stable JSON-serializable record of this rejection."""
        return {"schema_version": self.schema_version,
                "code": str(self.code),
                "pointer": self.pointer,
                "detail": _thaw_detail(self.detail)}

    @classmethod
    def from_document(cls, document: Mapping) -> "Rejection":
        """Rebuild a rejection from its document, refusing foreign shapes."""
        if not isinstance(document, Mapping) or set(document) != REJECTION_DOCUMENT_KEYS:
            raise ValueError("rejection document keys are fixed by the schema")
        return cls(document["code"], document["pointer"], document["detail"],
                   document["schema_version"])

    def __hash__(self) -> int:
        detail = json.dumps(self.document()["detail"], sort_keys=True,
                            separators=(",", ":"), ensure_ascii=False,
                            allow_nan=False)
        return hash((self.schema_version, str(self.code), self.pointer, detail))

    def __str__(self) -> str:
        return f"{self.code}@{self.pointer}"


class RejectionError(ValueError):
    """A ValueError that carries the versioned rejection it was raised for."""

    def __init__(self, message: str, rejection: Rejection) -> None:
        if not isinstance(rejection, Rejection):
            raise ValueError("rejection error requires a Rejection value")
        super().__init__(message)
        self.rejection = rejection


def reject(code: RejectionCode | str, message: str, pointer: str,
           **detail: object) -> NoReturn:
    """Raise a fail-closed ValueError carrying a versioned rejection."""
    summarized = {key: value_summary(value) for key, value in detail.items()}
    raise RejectionError(message, Rejection(code, pointer, summarized or None))


def rejection_of(error: BaseException, *,
                 occupant_writer_kinds: tuple[str, ...] = ()) -> Rejection | None:
    """Return the rejection carried by an error, or classify a legacy message.

    ``occupant_writer_kinds`` are the real writer kinds of the bytes that
    blocked an instruction admission, for example ``ReadSnapshot.writer_kinds``.
    They separate a reservation already consumed by an admitted candidate from
    bytes materialized by a real read or Store. Without them the shared
    overwrite message is classified as ``slot.materialized``, the general case.
    """
    if isinstance(error, RejectionError):
        return error.rejection
    if not isinstance(error, BaseException) or not error.args:
        return None
    message = error.args[0]
    if not isinstance(message, str):
        return None
    if message == _OVERWRITE_MESSAGE:
        kinds = tuple(kind for kind in occupant_writer_kinds if isinstance(kind, str))
        if kinds and all(kind == _CONSUMED_WRITER_KIND for kind in kinds):
            return Rejection(RejectionCode.SLOT_ALREADY_CONSUMED, "memory.address",
                             {"occupant": _CONSUMED_WRITER_KIND})
        detail = ({"occupant": "|".join(sorted(set(kinds)))} if kinds else None)
        return Rejection(RejectionCode.SLOT_MATERIALIZED, "memory.address", detail)
    entry = _LEGACY_MESSAGES.get(message)
    if entry is None:
        return None
    code, pointer = entry
    return Rejection(code, pointer)
