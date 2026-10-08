"""Opt-in initial RAM data operator: declared bytes, decided before launch.

The plan's P4/A2 item requires a legal initial-data operator and states its rule:
"初始数据在会话启动前变异；会话内仅未知数据字节的首次读取可物化一次" -- initial
data is mutated **before** the session starts, and inside the session only the
first read of an unknown data byte may materialize it, once.  A live/continuous
session keeps its preloaded images immutable (``scenario_rfuzz`` refuses an
in-session ``memory_image`` mutation for exactly that reason), so this module is
the pre-session half: it decides one declared initial RAM data byte and the
session installs it as one more declared image before ``begin()``.  From then on
the byte is an ordinary initial image byte: the first read returns it, a real
Store may overwrite it, and ``scenario/slot_immutability.py`` reports it as an
``initial_image`` materialization.

Nothing here is invented:

* the byte address is drawn inside a :class:`TrustedInitialRamDataDeclaration`
  (a component, a declared memory region, a bounded window and a declared value
  mask), never from the raw record alone;
* the value is drawn inside that declared mask from
  ``sha256(b"myfuzz.online.initial_ram_data.v1\\0" + raw)`` -- the same
  domain-separated rule style as the shipped live path switch
  (:func:`myfuzz.integration.scenario_rfuzz._apply_path_switch`), so a replay of
  the same record proposes the same byte and no search state takes part;
* the raw record itself is a declared input of the run, not a clock reading: the
  live entry points pass the same eight-byte record the RFuzz client receives as
  its seed, which the run stores verbatim in ``seed.bin``, so the proposal is
  recomputable from the run's own artifacts.

Refusals reuse the shipped ``candidate_rejection.v1`` codes that apply; no new
code is required, and the operator's own stable ``reason`` token carries the
precise semantics exactly like ``online_path_switch_refusal.v1`` does.  The
mapping is explicit so a reviewer can audit every one of them:

===============================================  ==============================
operator reason                                    shipped code
===============================================  ==============================
``malformed_raw``                                 ``decode.malformed_record``
``undeclared_byte``                               ``mmio.out_of_window``
``fixed_image_byte``                              ``ownership.fixed_input``
``bound_slot_byte``                               ``ownership.bound_input``
``materialized_byte``                             ``slot.materialized``
``already_adopted``                               ``slot.already_consumed``
``budget_exhausted``                              ``budget.exhausted``
``operator_disabled`` / ``adopted``               (no refusal; ``rejection=null``)
===============================================  ==============================

``undeclared_byte`` is "the declaration names a byte this session's memory does
not declare": the address lies outside every declared RAM window of that
component, which is what ``mmio.out_of_window`` already means for a host memory
access.  ``fixed_image_byte`` is a byte a declared session image already fixes
(``ownership.fixed_input``: a constant producer), ``bound_slot_byte`` is a byte a
real CPU fetch will produce from a reserved online instruction slot
(``ownership.bound_input``: a real producer owns it), and ``materialized_byte`` is
a byte a real read or Store already determined (``slot.materialized``).  A byte
this operator already decided is refused as ``already_adopted``
(``slot.already_consumed``): an unknown-once materialization is never redone.

Default OFF: nothing in this module runs unless a caller asks for it, and the
session records no state at all when the operator was never declared, so the
shipped decoder manifest, session manifest, plan and candidate identities are
untouched.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn

from .rejection_codes import Rejection, RejectionCode


INITIAL_RAM_DATA_DECLARATION_SCHEMA_VERSION = "initial_ram_data_declaration.v1"
INITIAL_RAM_DATA_DECISION_SCHEMA_VERSION = "initial_ram_data_decision.v1"
INITIAL_RAM_DATA_STATE_SCHEMA_VERSION = "initial_ram_data_state.v1"
#: Domain separator of the raw-derived declared-byte draw.  It is disjoint from
#: the shipped decode and path-switch domains, so an initial-data choice can
#: never alias another operator's draw, and a replay draws the same byte.
INITIAL_RAM_DATA_DOMAIN = b"myfuzz.online.initial_ram_data.v1\0"
#: Opt-in environment bridge, only consulted on the online path.  The
#: constructor argument always wins, and any other value is refused instead of
#: guessed, exactly like ``MYFUZZ_PATH_SWITCH``.
INITIAL_RAM_DATA_ENV = "MYFUZZ_INITIAL_RAM_DATA"
#: Base identity of the one initial image a decision installs.  The session
#: appends the declared memory and byte offset, so the image identity states
#: which declared byte it materializes.
INITIAL_RAM_DATA_IMAGE_ID = "initial-ram-data"
#: Root of the repository, used to name the operator source in run state.
_ROOT = Path(__file__).resolve().parents[3]
_ENV_TRUE = ("1", "true", "yes", "on")
_ENV_FALSE = ("0", "false", "no", "off", "")


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a nonempty stripped string")
    return value


def _uint(value: object, name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} exceeds its declared bound")
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TrustedInitialRamDataDeclaration:
    """The only initial RAM bytes and values this operator may decide.

    Declared by the trusted profile/template side (never by a fuzzable case),
    bounded by construction and content-addressed, so a reviewer recomputes
    which window a decision was taken under.  ``scope`` names where the window
    came from, ``component``/``memory_id`` name the declared memory, ``base``
    and ``byte_count`` bound the byte addresses, and ``value_mask``/``value_base``
    bound the byte values exactly like the mask/value fields the shipped
    feedback and ownership declarations use.  The window is never widened by a
    request: a drawn address outside it cannot exist, and an address this
    session does not map is refused.
    """

    scope: str
    component: str
    memory_id: str
    base: int
    byte_count: int
    value_mask: int = 0xFF
    value_base: int = 0
    image_id: str = INITIAL_RAM_DATA_IMAGE_ID
    declaration_id: str = ""

    def __post_init__(self) -> None:
        _text(self.scope, "declaration scope")
        _text(self.component, "declaration component")
        _text(self.memory_id, "declaration memory_id")
        _uint(self.base, "declaration base", maximum=(1 << 64) - 1)
        if isinstance(self.byte_count, bool) or not isinstance(self.byte_count, int):
            raise ValueError("declaration byte_count must be a positive integer")
        if not 1 <= self.byte_count:
            raise ValueError("declaration byte_count must be a positive integer")
        if self.base > (1 << 64) - self.byte_count:
            raise ValueError("declaration window exceeds address bounds")
        if (isinstance(self.value_mask, bool) or not isinstance(self.value_mask, int)
                or not 1 <= self.value_mask <= 0xFF):
            # A zero mask would declare a constant, not a mutable byte: the
            # operator would report an adoption for a value nobody chose.
            raise ValueError("declaration value_mask must be within 0x01..0xFF")
        _uint(self.value_base, "declaration value_base", maximum=0xFF)
        _text(self.image_id, "declaration image_id")
        expected = _digest(self._material())
        if self.declaration_id and self.declaration_id != expected:
            raise ValueError(
                "declaration_id does not match canonical declaration material")
        object.__setattr__(self, "declaration_id", expected)

    @property
    def end(self) -> int:
        """First address after the declared window; never inside it."""
        return self.base + self.byte_count

    def allows_address(self, address: int) -> bool:
        """Whether one exact byte address is inside the declared window."""
        return (type(address) is int and not isinstance(address, bool)
                and self.base <= address < self.end)

    def allows_value(self, value: int) -> bool:
        """Whether one byte value is inside the declared masked domain."""
        if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 0xFF:
            return False
        return value & ~self.value_mask == self.value_base & ~self.value_mask

    def _material(self) -> dict:
        return {"schema_version": INITIAL_RAM_DATA_DECLARATION_SCHEMA_VERSION,
                "scope": self.scope, "component": self.component,
                "memory_id": self.memory_id, "base": self.base,
                "byte_count": self.byte_count,
                "value_base": self.value_base, "value_mask": self.value_mask,
                "image_id": self.image_id}

    def document(self) -> dict:
        return {**self._material(), "declaration_id": self.declaration_id}

    @classmethod
    def from_document(cls, document: object) -> "TrustedInitialRamDataDeclaration":
        fields = {"schema_version", "scope", "component", "memory_id", "base",
                  "byte_count", "value_base", "value_mask", "image_id",
                  "declaration_id"}
        if type(document) is not dict or set(document) != fields:
            raise ValueError("declaration has unknown or missing fields")
        if document["schema_version"] != INITIAL_RAM_DATA_DECLARATION_SCHEMA_VERSION:
            raise ValueError("unsupported declaration schema_version")
        return cls(scope=document["scope"], component=document["component"],
                   memory_id=document["memory_id"], base=document["base"],
                   byte_count=document["byte_count"],
                   value_mask=document["value_mask"],
                   value_base=document["value_base"],
                   image_id=document["image_id"],
                   declaration_id=document["declaration_id"])


@dataclass(frozen=True)
class InitialRamDataProposal:
    """One drawn declared byte: the address and value a raw record proposes.

    ``byte_offset`` is the offset inside the declared memory region, which only
    a caller that declares that region can state: the pure draw leaves it
    ``None`` rather than guessing a base, and the evaluator fills it from the
    session's own declared window.
    """

    declaration_id: str
    component: str
    memory_id: str
    address: int
    value: int
    draw_sha256: str
    image_id: str
    byte_offset: int | None = None
    proposal_id: str = ""

    def __post_init__(self) -> None:
        for name in ("declaration_id", "component", "memory_id", "image_id"):
            _text(getattr(self, name), f"proposal {name}")
        _uint(self.address, "proposal address", maximum=(1 << 64) - 1)
        if self.byte_offset is not None:
            _uint(self.byte_offset, "proposal byte_offset", maximum=(1 << 64) - 1)
        _uint(self.value, "proposal value", maximum=0xFF)
        _text(self.draw_sha256, "proposal draw_sha256")
        expected = _digest(self._material())
        if self.proposal_id and self.proposal_id != expected:
            raise ValueError("proposal_id does not match canonical proposal material")
        object.__setattr__(self, "proposal_id", expected)

    def _material(self) -> dict:
        return {"schema_version": INITIAL_RAM_DATA_DECISION_SCHEMA_VERSION,
                "declaration_id": self.declaration_id,
                "component": self.component, "memory_id": self.memory_id,
                "address": self.address, "byte_offset": self.byte_offset,
                "value": self.value, "draw_sha256": self.draw_sha256,
                "image_id": self.image_id}

    def document(self) -> dict:
        return {**self._material(), "proposal_id": self.proposal_id}


@dataclass(frozen=True)
class InitialRamDataState:
    """The declared facts the evaluator may consult; none of them is guessed.

    ``regions`` are the session memory's own declared windows,
    ``fixed_images`` the images the session template already declares,
    ``determined`` every byte a real read/Store/image already determined,
    ``reserved`` the instruction slots a real fetch still has to fill, and
    ``adopted`` the bytes this operator already decided.  A caller that cannot
    state one of them passes an empty tuple, and the corresponding check then
    refuses rather than assumes.
    """

    regions: tuple[tuple[str, int, int], ...] = ()
    determined: tuple[tuple[str, int, int, str], ...] = ()
    reserved: tuple[tuple[str, int], ...] = ()
    fixed_images: tuple[tuple[str, int, int, str], ...] = ()
    adopted: tuple[tuple[str, int, int], ...] = ()


class InitialRamDataReason:
    """Stable operator reason tokens; the string value is the contract."""

    ADOPTED = "adopted"
    OPERATOR_DISABLED = "operator_disabled"
    MALFORMED_RAW = "malformed_raw"
    UNDECLARED_BYTE = "undeclared_byte"
    FIXED_IMAGE_BYTE = "fixed_image_byte"
    BOUND_SLOT_BYTE = "bound_slot_byte"
    MATERIALIZED_BYTE = "materialized_byte"
    ALREADY_ADOPTED = "already_adopted"
    BUDGET_EXHAUSTED = "budget_exhausted"


#: Every reason the operator can report, in evaluation order where it matters.
INITIAL_RAM_DATA_REASONS = (
    InitialRamDataReason.ADOPTED, InitialRamDataReason.OPERATOR_DISABLED,
    InitialRamDataReason.MALFORMED_RAW, InitialRamDataReason.UNDECLARED_BYTE,
    InitialRamDataReason.FIXED_IMAGE_BYTE, InitialRamDataReason.BOUND_SLOT_BYTE,
    InitialRamDataReason.MATERIALIZED_BYTE, InitialRamDataReason.ALREADY_ADOPTED,
    InitialRamDataReason.BUDGET_EXHAUSTED)

#: The shipped rejection code and pointer every refusing reason is reported
#: under.  ``adopted`` and ``operator_disabled`` are not refusals of a byte.
_REASON_REJECTIONS = MappingProxyType({
    InitialRamDataReason.MALFORMED_RAW:
        (RejectionCode.DECODE_MALFORMED_RECORD, "initial_ram.raw"),
    InitialRamDataReason.UNDECLARED_BYTE:
        (RejectionCode.MMIO_OUT_OF_WINDOW, "initial_ram.address"),
    InitialRamDataReason.FIXED_IMAGE_BYTE:
        (RejectionCode.OWNERSHIP_FIXED_INPUT, "initial_ram.address"),
    InitialRamDataReason.BOUND_SLOT_BYTE:
        (RejectionCode.OWNERSHIP_BOUND_INPUT, "initial_ram.byte_offset"),
    InitialRamDataReason.MATERIALIZED_BYTE:
        (RejectionCode.SLOT_MATERIALIZED, "initial_ram.byte_offset"),
    InitialRamDataReason.ALREADY_ADOPTED:
        (RejectionCode.SLOT_ALREADY_CONSUMED, "initial_ram.byte_offset"),
    InitialRamDataReason.BUDGET_EXHAUSTED:
        (RejectionCode.BUDGET_EXHAUSTED, "initial_ram.max_bytes"),
})


def _rejection(reason: str, detail: Mapping | None = None) -> dict:
    """The shipped rejection document of one refusing reason."""
    code, pointer = _REASON_REJECTIONS[reason]
    return Rejection(code, pointer, detail).document()


def propose_initial_ram_byte(declaration: TrustedInitialRamDataDeclaration,
                             raw: bytes) -> InitialRamDataProposal:
    """Draw one declared byte and value from the raw record alone.

    The rule mirrors the shipped live path switch: the first eight digest bytes
    select the declared byte address in declaration order, the second eight
    select the value inside the declared mask.  It reads no clock, no counter and
    no search state, so the same record proposes the same byte forever.  The
    region byte offset is left ``None``: only a caller holding the declared
    memory window can state it, and a guessed base would be an invented fact.
    """
    if not isinstance(declaration, TrustedInitialRamDataDeclaration):
        raise ValueError("a TrustedInitialRamDataDeclaration is required")
    if not isinstance(raw, bytes) or not raw:
        raise ValueError("a nonempty raw record is required")
    digest = hashlib.sha256(INITIAL_RAM_DATA_DOMAIN + raw).digest()
    window_offset = int.from_bytes(digest[:8], "little") % declaration.byte_count
    address = declaration.base + window_offset
    value = ((declaration.value_base & ~declaration.value_mask)
             | (int.from_bytes(digest[8:16], "little") & declaration.value_mask))
    return InitialRamDataProposal(
        declaration_id=declaration.declaration_id,
        component=declaration.component, memory_id=declaration.memory_id,
        address=address, value=value, draw_sha256=digest.hex(),
        image_id=f"{declaration.image_id}.{declaration.memory_id}.{window_offset}")


def _refuse(reason: str, *, proposal: InitialRamDataProposal | None,
            detail: Mapping | None = None) -> tuple[str, dict | None]:
    return reason, _rejection(reason, detail)


def _classify(proposal: InitialRamDataProposal,
              declaration: TrustedInitialRamDataDeclaration,
              state: InitialRamDataState, *, max_bytes: int,
              region: tuple[str, int, int] | None
              ) -> tuple[str, dict | None]:
    """Decide one drawn byte against the declared state, fail closed."""
    memory_id, offset = proposal.memory_id, proposal.byte_offset
    if region is None or offset is None:
        return _refuse(InitialRamDataReason.UNDECLARED_BYTE, proposal=proposal,
                       detail={"memory_id": memory_id, "byte_offset": offset,
                               "address": proposal.address,
                               "declared_scope": declaration.scope})
    previous = next((row[2] for row in state.adopted
                     if row[0] == memory_id and row[1] == offset), None)
    if previous is not None:
        # An unknown-once materialization is decided once; re-deciding the same
        # byte is refused whether or not the proposed value agrees.
        return _refuse(InitialRamDataReason.ALREADY_ADOPTED, proposal=proposal,
                       detail={"value": previous, "proposed": proposal.value})
    occupant = next((row[3] for row in state.fixed_images
                     if row[0] == proposal.component
                     and row[1] <= proposal.address < row[2]), None)
    if occupant is not None:
        return _refuse(InitialRamDataReason.FIXED_IMAGE_BYTE, proposal=proposal,
                       detail={"occupant": occupant})
    if any(row[0] == memory_id and row[1] == offset for row in state.reserved):
        return _refuse(InitialRamDataReason.BOUND_SLOT_BYTE, proposal=proposal,
                       detail={"occupant": "online_instruction_slot"})
    determined = next((row for row in state.determined
                       if row[0] == memory_id and row[1] == offset), None)
    if determined is not None:
        return _refuse(InitialRamDataReason.MATERIALIZED_BYTE, proposal=proposal,
                       detail={"occupant": determined[3]})
    if len(state.adopted) >= max_bytes:
        return _refuse(InitialRamDataReason.BUDGET_EXHAUSTED, proposal=proposal,
                       detail={"max_bytes": max_bytes,
                               "adopted_bytes": len(state.adopted)})
    return InitialRamDataReason.ADOPTED, None


def evaluate_initial_ram_data(declaration: TrustedInitialRamDataDeclaration,
                              raw: object, state: InitialRamDataState, *,
                              enabled: bool = True,
                              max_bytes: int = 1) -> dict:
    """Decide one declared initial RAM byte, recording why it was taken or not.

    The returned ``initial_ram_data_decision.v1`` document always states the
    declaration, the bounds and the operator's own reason.  ``proposal`` is the
    drawn byte (``null`` when the operator was off or the record was malformed),
    ``adopted`` is the byte a session must install (``null`` for every refusal),
    and ``rejection`` is the shipped refusal code when one applies -- never a
    guessed value, and never a guessed zero.
    """
    if not isinstance(declaration, TrustedInitialRamDataDeclaration):
        raise ValueError("a TrustedInitialRamDataDeclaration is required")
    if not isinstance(state, InitialRamDataState):
        raise ValueError("an InitialRamDataState is required")
    if type(enabled) is not bool:
        raise ValueError("initial RAM data enabled must be boolean")
    if type(max_bytes) is not int or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("initial RAM data max_bytes must be a positive integer")
    proposal = None
    adopted = None
    rejection = None
    if not enabled:
        reason = InitialRamDataReason.OPERATOR_DISABLED
    elif not isinstance(raw, bytes) or not raw:
        reason, rejection = _refuse(
            InitialRamDataReason.MALFORMED_RAW, proposal=None,
            detail={"raw_type": type(raw).__name__,
                    "raw_length": len(raw) if isinstance(raw, bytes) else None})
    else:
        proposal = propose_initial_ram_byte(declaration, raw)
        region = next((row for row in state.regions
                       if row[0] == declaration.memory_id
                       and row[1] <= proposal.address < row[2]), None)
        if region is not None:
            # The session, not the draw, states which declared byte offset the
            # address names; without one the proposal keeps ``byte_offset=None``
            # and the refusal below says so.  ``proposal_id`` is recomputed from
            # the completed material, so it covers the offset too.
            proposal = replace(proposal, byte_offset=proposal.address - region[1],
                               proposal_id="")
        reason, rejection = _classify(proposal, declaration, state,
                                      max_bytes=max_bytes, region=region)
        if reason == InitialRamDataReason.ADOPTED:
            adopted = {"memory_id": proposal.memory_id,
                       "byte_offset": proposal.byte_offset,
                       "address": proposal.address, "value": proposal.value,
                       "image_id": proposal.image_id,
                       "proposal_id": proposal.proposal_id}
    return {"schema_version": INITIAL_RAM_DATA_DECISION_SCHEMA_VERSION,
            "reason": reason,
            "enabled": enabled,
            "declaration": declaration.document(),
            "proposal": None if proposal is None else proposal.document(),
            "adopted": adopted,
            "rejection": rejection,
            "bounds": {"max_bytes": max_bytes,
                       "adopted_bytes": len(state.adopted),
                       "window_bytes": declaration.byte_count,
                       "value_mask": declaration.value_mask}}


def resolve_initial_ram_data_switch(requested: bool | None, *, online: bool,
                                    environ: Mapping | None = None
                                    ) -> tuple[bool, str]:
    """Resolve the opt-in operator and name the source of the decision.

    Mirrors :func:`myfuzz.integration.scenario_rfuzz._path_switch_switch`:
    ``None`` defers to :data:`INITIAL_RAM_DATA_ENV`, the environment is only
    consulted on the online decoder path, and any other value is refused
    instead of guessed.
    """
    if requested is not None:
        if type(requested) is not bool:
            raise ValueError("initial_ram_data must be boolean or None")
        return requested, "constructor"
    if not online:
        return False, "default"
    source = os.environ if environ is None else environ
    value = source.get(INITIAL_RAM_DATA_ENV)
    if value is None:
        return False, "default"
    text = value.strip().lower()
    if text in _ENV_TRUE:
        return True, "environment"
    if text in _ENV_FALSE:
        return False, "environment"
    raise ValueError(
        f"{INITIAL_RAM_DATA_ENV} must be one of "
        f"{', '.join(sorted(_ENV_TRUE + _ENV_FALSE))}, got {value!r}")


def operator_source_identity() -> dict:
    """The operator source identity, stated as ``null`` plus a reason if absent.

    It is reported in run state rather than added to the shipped session
    manifest: adding a source file to ``_ONLINE_SOURCE_PATHS`` would change the
    manifest of every run, including an operator-off one.
    """
    path = Path(__file__).resolve()
    try:
        resolved = path.relative_to(_ROOT).as_posix()
    except ValueError:
        resolved = path.as_posix()
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        return {"path": resolved, "sha256": None,
                "reason": f"operator source is unavailable: {type(error).__name__}"}
    return {"path": resolved, "sha256": digest}


__all__ = [
    "INITIAL_RAM_DATA_DECLARATION_SCHEMA_VERSION",
    "INITIAL_RAM_DATA_DECISION_SCHEMA_VERSION",
    "INITIAL_RAM_DATA_DOMAIN",
    "INITIAL_RAM_DATA_ENV",
    "INITIAL_RAM_DATA_IMAGE_ID",
    "INITIAL_RAM_DATA_REASONS",
    "INITIAL_RAM_DATA_STATE_SCHEMA_VERSION",
    "InitialRamDataProposal",
    "InitialRamDataReason",
    "InitialRamDataState",
    "TrustedInitialRamDataDeclaration",
    "evaluate_initial_ram_data",
    "operator_source_identity",
    "propose_initial_ram_byte",
    "resolve_initial_ram_data_switch",
]
