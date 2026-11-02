"""One shared F1 program-space gate for the unified in-process entry.

The fixed trampoline slot can execute four opt-in program shapes on top of the
historical straight-line ALU/LW/SW program: computed-base address forms,
strictly-forward branches, packed compressed parcels, and the natural-width
subword forms.  Their static rules and their reference semantics already live
in :mod:`myfuzz.fuzz.rv32_program`, :mod:`myfuzz.fuzz.rv32_compressed` and
:mod:`myfuzz.fuzz.rv32_subword`; this module is the one place that turns a
scenario declaration (``f1_program_words``/``f1_subword``/``f1_allow_*``) into
the right validator call, and the one place that produces the per-case F1
criteria the C++ host must meet.

Two entry points matter to the integration:

``validate_f1_program_record(record, *, isa, window_bytes, flags)``
    The Python authority for what an F1 record may contain.  It dispatches to
    the existing validator for the declared shape and never re-implements an
    instruction rule.  The historical program gate's refusal text is preserved
    for legacy shapes, so the entry can replace its private
    ``_validate_f1_program`` without changing any existing expectation.

``f1_reference_expectation(record, *, isa, window_bytes, flags, ...)``
    The Python authority for what a legal record must *do*.  It delegates to
    :func:`myfuzz.fuzz.rv32_program.reference_run` or
    :func:`myfuzz.fuzz.rv32_compressed.reference_run_compressed`; this module
    never executes an instruction itself.  The result carries the retirement
    count, the PC order, the ``(pc, insn, rd, wdata)`` trace, the final
    register/memory delta and a canonical trace hash.

``host_mirror_spec()``
    A JSON-ready description of the exact C++ host changes (branch targets,
    computed-base provenance, two-parcel fetch, PC step 2/4, trace hash).  It is
    documentation data, not a second implementation, and the same table is in
    ``docs/patches/f1-program-gate-integration.md``.

The module is intentionally isolated: it edits no existing file and imports no
``scripts`` module.  It performs no I/O and claims no RTL result.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..riscv.profile import RiscvProfile
from .rv32_compressed import (
    ALU_ONLY,
    CompressedPolicy,
    image_instructions,
    reference_run_compressed,
    validate_compressed_program,
)
from .rv32_program import (
    DEFAULT_RESERVED_REGISTERS,
    reference_run,
    validate_program_words,
)

#: The entry's ``MAX_F1_PROGRAM_WORDS``.  A scenario declares a record of at
#: most this many 32-bit words in the trampoline slot; a compressed record word
#: still counts as one word and holds up to two parcels.
MAX_F1_PROGRAM_WORDS = 16
#: The entry's ``PROGRAM_DATA_WORDS * 4`` default.  Callers pass the declared
#: window explicitly; this is only the documentation default.
DEFAULT_WINDOW_BYTES = 64

_MASK32 = 0xFFFFFFFF
_ALU_OPCODES = frozenset((0x37, 0x17, 0x13, 0x33))
_MEMORY_OPCODES = frozenset((0x03, 0x23))
#: FNV-1a constants, the same pair the C++ host already uses for its data-window
#: hash (``scripts/inprocess_obi_apb_f1f4_spike.cpp`` ``window_hash``).
_FNV_OFFSET = 2166136261
_FNV_PRIME = 16777619
_TRACE_HASH_FIELDS = ("pc", "insn_word", "rd", "wdata")
_SCENARIO_KEYS = {
    "program_words": "f1_program_words",
    "subword": "f1_subword",
    "allow_branches": "f1_allow_branches",
    "allow_address_forms": "f1_allow_address_forms",
    "allow_compressed": "f1_allow_compressed",
    "allow_jumps": "f1_allow_jumps",
    "allow_loops": "f1_allow_loops",
    "allow_compressed_control": "f1_allow_compressed_control",
    "allow_compressed_memory": "f1_allow_compressed_memory",
}


# ---------------------------------------------------------------------------
# Scenario declaration -> flags
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class F1GateFlags:
    """The F1 program-shape declaration of one scenario.

    ``program_words`` is the record-word capacity (``f1_program_words``); the
    booleans are the opt-in shapes.  ``1`` keeps the legacy single-word gate;
    values above one select the program gate.  Every opt-in requires program
    mode (``program_words > 1``) so the record keeps its declared length
    semantics.

    ``allow_jumps`` admits ``JAL``/``JALR`` with a statically proven, strictly
    forward target; ``allow_loops`` admits the canonical bounded loop (and
    requires ``allow_branches``, because its back edge is a B-type branch);
    ``allow_compressed_control``/``allow_compressed_memory`` widen the
    compressed parcel subset and require ``allow_compressed``.  A jump or loop
    is not combined with the compressed or computed-base shapes, and the
    subword validator keeps its own straight-line rule.
    """

    program_words: int = 1
    subword: bool = False
    allow_branches: bool = False
    allow_address_forms: bool = False
    allow_compressed: bool = False
    allow_jumps: bool = False
    allow_loops: bool = False
    allow_compressed_control: bool = False
    allow_compressed_memory: bool = False

    def __post_init__(self) -> None:
        if type(self.program_words) is not int:
            raise ValueError("f1_program_words must be an integer")
        if not 1 <= self.program_words <= MAX_F1_PROGRAM_WORDS:
            raise ValueError(
                f"f1_program_words {self.program_words} must be in 1.."
                f"{MAX_F1_PROGRAM_WORDS}")
        for field in ("subword", "allow_branches", "allow_address_forms",
                      "allow_compressed", "allow_jumps", "allow_loops",
                      "allow_compressed_control", "allow_compressed_memory"):
            if type(getattr(self, field)) is not bool:
                raise ValueError(f"f1_{field} must be a boolean")
        if self._program_mode_required() and self.program_words < 2:
            raise ValueError(
                "the opt-in F1 program shapes require f1_program_words > 1")
        if self.allow_compressed and self.allow_address_forms:
            raise ValueError(
                "f1_allow_compressed and f1_allow_address_forms are "
                "incompatible: compressed records admit only the x18 memory "
                "forms")
        if self.allow_compressed and self.allow_jumps:
            raise ValueError(
                "f1_allow_compressed and f1_allow_jumps are incompatible: a "
                "jump in a compressed image is refused; use "
                "f1_allow_compressed_control")
        if self.allow_compressed and self.allow_loops:
            raise ValueError(
                "f1_allow_compressed and f1_allow_loops are incompatible: "
                "compressed loops are refused; the bounded loop is a 32-bit "
                "form")
        if self.allow_loops and not self.allow_branches:
            raise ValueError(
                "f1_allow_loops requires f1_allow_branches: a bounded loop's "
                "back edge is a B-type branch")
        if self.allow_compressed_control and not self.allow_compressed:
            raise ValueError(
                "f1_allow_compressed_control requires f1_allow_compressed: it "
                "widens the compressed parcel subset")
        if self.allow_compressed_memory and not self.allow_compressed:
            raise ValueError(
                "f1_allow_compressed_memory requires f1_allow_compressed: it "
                "widens the compressed parcel subset")
        if self.allow_address_forms and (self.allow_jumps or self.allow_loops):
            raise ValueError(
                "f1_allow_address_forms is not combined with f1_allow_jumps or "
                "f1_allow_loops in this increment: the computed-base proof "
                "runs over the straight-line/forward-branch image")
        if self.subword and (self.allow_branches or self.allow_address_forms
                             or self.allow_compressed or self.allow_jumps
                             or self.allow_loops):
            raise ValueError(
                "f1_subword is incompatible with f1_allow_branches, "
                "f1_allow_address_forms, f1_allow_compressed, f1_allow_jumps "
                "and f1_allow_loops: the subword validator has its own "
                "straight-line memory rule")

    def _program_mode_required(self) -> bool:
        return (self.subword or self.allow_branches or self.allow_address_forms
                or self.allow_compressed or self.allow_jumps
                or self.allow_loops or self.allow_compressed_control
                or self.allow_compressed_memory)

    @property
    def mode(self) -> str:
        """The dispatch name, used in the expectation document and the tests."""
        if self.program_words == 1:
            return "single"
        if self.allow_compressed:
            control = self.allow_compressed_control
            memory = self.allow_compressed_memory
            if control and memory:
                return "compressed-control-memory"
            if control:
                return "compressed-control"
            if memory:
                return "compressed-memory"
            return "compressed"
        if self.subword:
            return "subword"
        parts = [name for name, flag in (
            ("address", self.allow_address_forms),
            ("branch", self.allow_branches),
            ("jump", self.allow_jumps),
            ("loop", self.allow_loops)) if flag]
        if not parts:
            return "legacy"
        if parts == ["address"]:
            return "address"
        if parts == ["branch"]:
            return "branch"
        if parts == ["address", "branch"]:
            return "extended"
        return "-".join(parts)

    @property
    def compressed(self) -> bool:
        """Whether the record words are compressed (two-parcel) images."""
        return self.allow_compressed

    @property
    def traced(self) -> bool:
        """Whether the case evidence is the full reference retirement trace.

        A straight-line program's evidence is "every installed word retired";
        every opt-in control shape (branches, jumps, loops, compressed parcels)
        retires a sequence the reference trace decides, so the host's RVFI trace
        is compared with it instead.
        """
        return (self.allow_branches or self.allow_jumps or self.allow_loops
                or self.allow_compressed)

    def as_dict(self) -> dict[str, Any]:
        """The flags in scenario spelling, ready for JSON."""
        return {key: getattr(self, field)
                for field, key in _SCENARIO_KEYS.items()}


def f1_gate_flags_from_scenario(config: Mapping[str, Any]) -> F1GateFlags:
    """Read the F1 program-shape flags from one scenario declaration.

    Only the five keys named below are read; every other scenario key is
    ignored.  Missing keys take their historical default (``1``/``False``).
    A declaration that names an impossible combination is refused here, before
    any record is validated.
    """
    if not isinstance(config, Mapping):
        raise ValueError("scenario config must be a mapping")
    values: dict[str, Any] = {}
    for field, key in _SCENARIO_KEYS.items():
        values[field] = config.get(key, 1 if field == "program_words" else False)
    return F1GateFlags(**values)


def normalize_f1_gate_flags(flags: object) -> F1GateFlags:
    """Accept a :class:`F1GateFlags`, a scenario/config mapping, or ``None``."""
    if flags is None:
        return F1GateFlags()
    if isinstance(flags, F1GateFlags):
        return flags
    if not isinstance(flags, Mapping):
        raise ValueError(
            "flags must be F1GateFlags, a scenario mapping or None")
    if any(key in flags for key in _SCENARIO_KEYS.values()):
        return f1_gate_flags_from_scenario(flags)
    unknown = set(flags) - set(_SCENARIO_KEYS)
    if unknown:
        raise ValueError(
            "unknown F1 gate flag(s): " + ", ".join(sorted(map(str, unknown))))
    return F1GateFlags(**dict(flags))


# ---------------------------------------------------------------------------
# Record and ISA plumbing
# ---------------------------------------------------------------------------


def _record_words(record: object) -> tuple[int, ...]:
    """The record's instruction words, from an entry record or a sequence."""
    if isinstance(record, Mapping):
        flow = record.get("flow")
        if flow is not None and flow != "F1":
            raise ValueError(f"record flow {flow!r} is not F1")
        for key in ("fields", "words"):
            if key in record:
                value = record[key]
                break
        else:
            raise ValueError("F1 record has neither fields nor words")
    else:
        value = getattr(record, "words", record)
    if isinstance(value, (str, bytes, bytearray)):
        raise ValueError(
            "F1 words must be a sequence of 32-bit instruction words")
    try:
        words = tuple(value)  # type: ignore[arg-type]
    except TypeError:
        raise ValueError(
            "F1 words must be a sequence of 32-bit instruction words") from None
    if not words:
        raise ValueError("F1 program has no instruction")
    for index, word in enumerate(words):
        if type(word) is not int or not 0 <= word <= _MASK32:
            raise ValueError(
                f"F1 instruction {index} is not one 32-bit word")
    return words


def _profile_from_isa(isa: object) -> RiscvProfile:
    """Build the program profile from an ``IsaContract`` or ``RiscvProfile``."""
    if isinstance(isa, RiscvProfile):
        profile = isa
    else:
        xlen = getattr(isa, "xlen", None)
        extensions = getattr(isa, "extensions", None)
        alignment = getattr(isa, "instruction_alignment", 4)
        if type(xlen) is not int or xlen not in (32, 64):
            raise ValueError("F1 program gate needs a declared RISC-V xlen")
        if isinstance(extensions, str) or extensions is None:
            raise ValueError(
                "F1 program gate needs a sequence of ISA extensions")
        try:
            normalized = frozenset(str(item).upper() for item in extensions)
        except TypeError:
            raise ValueError(
                "F1 program gate needs a sequence of ISA extensions") from None
        if not normalized:
            raise ValueError("the declared ISA has no extension")
        if type(alignment) is not int or alignment not in (2, 4):
            raise ValueError(
                "instruction_alignment must be 2 or 4")
        if xlen != 32:
            raise ValueError(
                "the F1 trampoline program gate is RV32-only; the declared "
                f"xlen is {xlen}")
        profile = RiscvProfile(xlen, normalized, alignment,
                               16 if "E" in normalized else 32, 0)
    if profile.xlen != 32:
        raise ValueError(
            "the F1 trampoline program gate is RV32-only; the declared xlen "
            f"is {profile.xlen}")
    return profile


def _require_window(window_bytes: object) -> int:
    if type(window_bytes) is not int:
        raise ValueError("F1 program gate window_bytes must be an integer")
    if window_bytes < 4:
        raise ValueError(
            f"F1 program gate window {window_bytes} must be at least 4 bytes")
    if window_bytes % 4:
        raise ValueError(
            f"F1 program gate window {window_bytes} must be 4-byte aligned")
    return window_bytes


def _program_message(message: str) -> str:
    """Prefix a shared-validator message with the entry's F1 namespace."""
    if message.startswith("F1 "):
        return message
    if message.startswith("program "):
        return "F1 " + message
    return "F1 program " + message


# ---------------------------------------------------------------------------
# Legacy (pre-program-space) adapters
# ---------------------------------------------------------------------------


def _legacy_offset(word: int) -> int:
    """The signed 12-bit memory immediate, decoded by opcode shape."""
    if word & 0x7F == 0x23:
        raw = (((word >> 25) & 0x7F) << 5) | ((word >> 7) & 0x1F)
    else:
        raw = (word >> 20) & 0xFFF
    return raw - 0x1000 if raw & 0x800 else raw


def _legacy_precheck(words: Sequence[int], window_bytes: int) -> None:
    """The historical ``_validate_f1_program`` refusals, in its exact order.

    The shared validator remains the authority for encodings, registers and
    extensions; this pass only keeps the entry-facing ordering and text of the
    historical program gate, which existing entry tests pin.
    """
    for index, word in enumerate(words):
        if word & 3 != 3:
            raise ValueError(
                f"F1 instruction {index} is not one 32-bit word")
        opcode = word & 0x7F
        if opcode not in _ALU_OPCODES and opcode not in _MEMORY_OPCODES:
            raise ValueError(
                f"F1 program instruction {index} is a control-flow or system "
                "word; the trampoline program is straight-line")
        if opcode not in _MEMORY_OPCODES:
            destination = (word >> 7) & 31
            if destination in DEFAULT_RESERVED_REGISTERS:
                label = {8: "mailbox", 9: "slot base",
                         18: "data-window base"}[destination]
                raise ValueError(
                    f"F1 program instruction {index} writes the reserved "
                    f"{label} register x{destination}")
            continue
        funct3 = (word >> 12) & 7
        if funct3 != 2:
            raise ValueError(
                f"F1 program memory word {index} is not LW or SW")
        base = (word >> 15) & 31
        if base != 18:
            raise ValueError(
                f"F1 program memory word {index} must use x18 as its base")
        offset = _legacy_offset(word)
        if offset % 4 or not 0 <= offset <= window_bytes - 4:
            raise ValueError(
                f"F1 program memory word {index} memory access leaves the "
                f"declared data window (offset {offset})")
        destination = (word >> 7) & 31
        if opcode == 0x03 and destination in DEFAULT_RESERVED_REGISTERS:
            raise ValueError(
                f"F1 program load {index} may not overwrite x8, x9 or x18")


def _legacy_shared_message(message: str) -> str:
    """Translate a shared-validator error into the historical gate's text."""
    match = re.match(r"instruction (\d+) (.*)", message, re.S)
    if match is None:
        return _program_message(message)
    index, rest = match.group(1), match.group(2)
    if rest.startswith("is compressed"):
        return f"F1 instruction {index} is not one 32-bit word"
    if rest.startswith("is a control-flow or system"):
        return (f"F1 program instruction {index} is a control-flow or system "
                "word; the trampoline program is straight-line")
    if rest.startswith("writes the reserved"):
        return f"F1 program instruction {index} {rest}"
    if rest.startswith("memory access must use x18"):
        return f"F1 program memory word {index} must use x18 as its base"
    if rest.startswith("memory access"):
        offset = _legacy_offset_message(rest)
        return (f"F1 program memory word {index} memory access leaves the "
                f"declared data window (offset {offset})")
    if rest.startswith(("is not a legal trampoline instruction",
                        "is not legal for this profile")):
        detail = rest.split(": ", 1)[1] if ": " in rest else rest
        return f"F1 instruction {index} is not legal for this profile: {detail}"
    return f"F1 program instruction {index} {rest}"


def _legacy_offset_message(rest: str) -> str:
    match = re.search(r"offset (-?\d+)", rest)
    return match.group(1) if match is not None else "unknown"


def _isa_contract_from(isa: object, profile: RiscvProfile) -> object:
    """The ``IsaContract`` the fixed one-word gate expects."""
    from ..isa.constraints import IsaContract

    if isinstance(isa, IsaContract):
        return isa
    return IsaContract(profile.xlen, tuple(sorted(profile.extensions)),
                       instruction_alignment=profile.instruction_alignment)


def _validate_single_word(profile: RiscvProfile, words: Sequence[int],
                          isa: object) -> None:
    """The fixed one-word trampoline gate (``f1_program_words == 1``).

    This keeps the historical f1f4 contract exactly: the word must pass
    ``validate_instruction_bytes`` first (which is why AUIPC is not admitted in
    single-word mode), then belong to the ALU opcode subset, then not write the
    mailbox pointer x8.  Only the reserved x8 rule applies; the program-mode
    x9/x18 reservations are a different contract.
    """
    from ..scenario.rv32i_sources import validate_instruction_bytes

    word = words[0]
    if word & 3 != 3:
        raise ValueError(
            "F1 requires one 32-bit instruction; compressed input is "
            "unsupported")
    # The historical gate lets ``validate_instruction_bytes`` raise its own
    # rejection text; wrapping it would change the single-word refusal.
    validate_instruction_bytes(
        word.to_bytes(4, "little"), isa=_isa_contract_from(isa, profile))
    opcode = word & 0x7F
    if opcode not in _ALU_OPCODES:
        raise ValueError(
            "F1 opcode 0x%02x is outside the executed ALU subset (no memory, "
            "control-flow or CSR word in the trampoline)" % opcode)
    if (word >> 7) & 31 == 8:
        raise ValueError(
            "F1 instruction may not overwrite the fixed mailbox register x8")


def _validate_legacy_program(profile: RiscvProfile, words: Sequence[int],
                             window_bytes: int) -> None:
    """The historical straight-line program gate, with its exact refusals."""
    _legacy_precheck(words, window_bytes)
    try:
        validate_program_words(profile, words, window_size=window_bytes)
    except ValueError as error:
        raise ValueError(_legacy_shared_message(str(error))) from None


# ---------------------------------------------------------------------------
# The shared validation entry point
# ---------------------------------------------------------------------------


def validate_f1_program_record(record: object, *, isa: object,
                               window_bytes: int,
                               flags: F1GateFlags | Mapping[str, Any] | None,
                               image_base: int | None = None,
                               ) -> None:
    """Raise :class:`ValueError` unless ``record`` is legal for the scenario.

    ``record`` is an entry record (``{"flow": "F1", "fields": (...)}``), a
    short program (anything with ``words``) or a plain word sequence.  ``isa``
    is the scenario's ``IsaContract`` (or an equivalent object with ``xlen``,
    ``extensions`` and ``instruction_alignment``).  ``window_bytes`` is the
    declared F1 data window.  ``image_base`` is the absolute address of the
    first installed word; a ``JALR`` and a ``C.JR``/``C.JALR`` are absolute
    transfers and are refused without it.

    ``flags`` selects exactly one validator:

    ============================  ============================================
    mode                          validator
    ============================  ============================================
    ``single``                    the fixed one-word ALU gate
    ``legacy``                    :func:`rv32_program.validate_program_words`
    ``address``                   same, ``allow_address_forms=True``
    ``branch``                    same, ``allow_branches=True``
    ``extended``                  same, both flags
    ``branch-jump``/``branch-loop``/...  same, the declared control flags
    ``subword``                   :func:`rv32_subword.validate_subword_program`
    ``compressed``                :func:`rv32_compressed.validate_compressed_program`
    ``compressed-control``/``-memory``/``-control-memory``
                                  same, with the opt-in parcel groups
    ============================  ============================================

    The legacy program mode keeps the historical entry text and ordering
    (``F1 program memory word <i> ...``); the opt-in modes prefix the shared
    validator's own message with ``F1 program`` and otherwise leave it intact.
    """
    gate_flags = normalize_f1_gate_flags(flags)
    profile = _profile_from_isa(isa)
    window = _require_window(window_bytes)
    words = _record_words(record)
    if len(words) > gate_flags.program_words:
        raise ValueError(
            f"F1 program has {len(words)} words; the scenario declares at "
            f"most {gate_flags.program_words}")
    if image_base is not None and (type(image_base) is not int
                                   or not 0 <= image_base <= _MASK32):
        raise ValueError(
            "F1 program image_base must be a 32-bit unsigned integer or None")
    mode = gate_flags.mode
    if mode == "single":
        _validate_single_word(profile, words, isa)
        return
    if gate_flags.compressed:
        if not profile.has("C"):
            raise ValueError(
                "F1 program compressed mode requires the C extension in the "
                f"declared ISA, not {sorted(profile.extensions)}")
        try:
            validate_compressed_program(
                profile, words, window_size=window,
                allow_branches=gate_flags.allow_branches,
                allow_compressed_control=gate_flags.allow_compressed_control,
                allow_compressed_memory=gate_flags.allow_compressed_memory,
                image_base=image_base)
        except ValueError as error:
            raise ValueError(_program_message(str(error))) from None
        return
    if mode == "subword":
        from .rv32_subword import validate_subword_program

        try:
            validate_subword_program(profile, words, window_size=window)
        except ValueError as error:
            raise ValueError(_program_message(str(error))) from None
        return
    if mode == "legacy":
        _validate_legacy_program(profile, words, window)
        return
    try:
        validate_program_words(
            profile, words, window_size=window,
            allow_branches=gate_flags.allow_branches,
            allow_address_forms=gate_flags.allow_address_forms,
            allow_jumps=gate_flags.allow_jumps,
            allow_loops=gate_flags.allow_loops,
            image_base=image_base)
    except ValueError as error:
        raise ValueError(_program_message(str(error))) from None


# ---------------------------------------------------------------------------
# Reference expectation and canonical trace hash
# ---------------------------------------------------------------------------


def _instruction_word_table(words: Sequence[int], *,
                            compressed: bool,
                            policy: object | None = None) -> dict[int, int]:
    """The encoded instruction at each image-relative PC offset."""
    if compressed:
        return {
            entry.pc_offset: (entry.parcel if entry.width == 2 else entry.word)
            for entry in image_instructions(
                words, policy if policy is not None else ALU_ONLY)
        }
    return {4 * index: word for index, word in enumerate(words)}


def _trace_entry(pc: int, insn: str, insn_word: int, rd: int,
                 wdata: int) -> dict[str, Any]:
    return {"pc": pc, "insn": insn, "insn_word": insn_word, "rd": rd,
            "wdata": wdata}


def _expectation_trace(result: Mapping[str, Any], words: Sequence[int], *,
                       pc_base: int, compressed: bool,
                       policy: object | None = None) -> list[dict[str, Any]]:
    table = _instruction_word_table(words, compressed=compressed,
                                    policy=policy)
    trace: list[dict[str, Any]] = []
    for entry in result["trace"]:
        offset = (entry.pc - pc_base) & _MASK32
        insn_word = table.get(offset)
        if insn_word is None:
            raise ValueError(
                f"reference trace pc {entry.pc:#010x} is not an instruction "
                "start of the installed image")
        trace.append(_trace_entry(entry.pc, entry.insn, insn_word, entry.rd,
                                  entry.wdata))
    return trace


def canonical_trace(trace: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate and copy one trace into its canonical JSON-ready shape.

    Each entry must carry ``pc``, ``insn``, ``insn_word``, ``rd`` and
    ``wdata``; the four integer fields must be 32-bit unsigned values.  The
    order is the retirement order and is preserved.
    """
    canonical: list[dict[str, Any]] = []
    for position, entry in enumerate(trace):
        if not isinstance(entry, Mapping):
            raise ValueError(
                f"trace entry {position} is not a mapping")
        missing = {"pc", "insn", "insn_word", "rd", "wdata"} - set(entry)
        if missing:
            raise ValueError(
                f"trace entry {position} is missing "
                + ", ".join(sorted(missing)))
        for field in _TRACE_HASH_FIELDS:
            if type(entry[field]) is not int or not 0 <= entry[field] <= _MASK32:
                raise ValueError(
                    f"trace entry {position} field {field} is not a 32-bit "
                    f"unsigned integer: {entry[field]!r}")
        if not isinstance(entry["insn"], str):
            raise ValueError(
                f"trace entry {position} insn is not a string")
        canonical.append({
            "pc": entry["pc"],
            "insn": entry["insn"],
            "insn_word": entry["insn_word"],
            "rd": entry["rd"],
            "wdata": entry["wdata"],
        })
    return canonical


def trace_hash(trace: Sequence[Mapping[str, Any]]) -> str:
    """The canonical FNV-1a 32 hash of one retirement trace.

    The payload is, for every retirement in order, the four 32-bit fields
    ``pc``, ``insn_word``, ``rd`` and ``wdata`` as little-endian bytes.  The
    instruction *name* is deliberately not hashed: the host has the encoded
    instruction word, not the Python mnemonic.  The same FNV-1a constants as
    the host's ``window_hash`` are used, so the host can reproduce the value
    with a five-line loop.
    """
    digest = _FNV_OFFSET
    for entry in canonical_trace(trace):
        for field in _TRACE_HASH_FIELDS:
            for byte in entry[field].to_bytes(4, "little"):
                digest ^= byte
                digest = (digest * _FNV_PRIME) & _MASK32
    return f"fnv1a32:{digest:08x}"


def f1_reference_expectation(record: object, *, isa: object,
                             window_bytes: int,
                             flags: F1GateFlags | Mapping[str, Any] | None,
                             registers: Mapping[int, int] | None = None,
                             memory: Mapping[int, int] | None = None,
                             data_base: int | None = 0,
                             trace: bool = False,
                             max_steps: int | None = None,
                             image_base: int | None = None,
                             ) -> dict[str, Any]:
    """The per-case F1 criteria for one legal record.

    The record is validated by :func:`validate_f1_program_record` against the
    scenario profile first, then executed by the module's reference model:
    :func:`~myfuzz.fuzz.rv32_program.reference_run` for the 32-bit shapes and
    :func:`~myfuzz.fuzz.rv32_compressed.reference_run_compressed` for packed
    parcels.  This function never interprets an instruction itself.

    ``registers``/``memory`` are the host's initial state, in absolute
    addresses: pass ``{18: data_window_base}`` and the data-window words when
    the expectation is to be compared with a host run.  ``data_base`` is the
    address of the first installed word (the slot base in the host), so the
    trace PCs and the final memory delta are directly comparable.  Both
    default to a zero-based image with zeroed state.

    The result is JSON-ready::

        {
          "schema_version": "f1_reference_expectation.v1",
          "mode": ...,
          "flags": {...},
          "pc_base": ..., "program_end": ...,
          "retired_count": ..., "pc_order": [...],
          "trace": [{"pc", "insn", "insn_word", "rd", "wdata"}, ...],
          "trace_hash": "fnv1a32:........",
          "register_writes": [...],
          "final_registers": {...},
          "memory_changes": {...},
        }

    ``steps`` is added when ``trace=True`` is passed to the underlying model.
    A subword record is refused here: :mod:`myfuzz.fuzz.rv32_subword` has a
    reference model but no retirement trace, and this function does not invent
    one.

    ``image_base`` is the absolute address of the first installed word.  It is
    the address a ``JALR``/``C.JR``/``C.JALR`` target is resolved against; when
    it is ``None`` the image starts at ``data_base`` (the default zero-based
    image).  A loop legitimately repeats PCs, so ``pc_order`` is the observed
    retirement order and is not strictly increasing.
    """
    gate_flags = normalize_f1_gate_flags(flags)
    if image_base is None:
        image_base = data_base if data_base is not None else 0
    validate_f1_program_record(record, isa=isa, window_bytes=window_bytes,
                               flags=gate_flags, image_base=image_base)
    words = _record_words(record)
    if gate_flags.mode == "subword":
        raise ValueError(
            "f1_reference_expectation has no subword retirement trace; "
            "myfuzz.fuzz.rv32_subword.reference_run_subword is the authority "
            "for f1_subword records")
    if data_base is None:
        data_base = 0
    if type(data_base) is not int or not 0 <= data_base <= _MASK32:
        raise ValueError("data_base must be a 32-bit unsigned integer or None")
    profile = _profile_from_isa(isa)
    window = _require_window(window_bytes)
    registers = {} if registers is None else registers
    memory = {} if memory is None else memory
    compressed = gate_flags.compressed
    policy = CompressedPolicy(gate_flags.allow_compressed_control,
                              gate_flags.allow_compressed_memory)
    if compressed:
        result = reference_run_compressed(
            words, registers=dict(registers), memory=dict(memory),
            data_base=data_base, window_size=window, trace=trace,
            allow_branches=gate_flags.allow_branches,
            allow_compressed_control=gate_flags.allow_compressed_control,
            allow_compressed_memory=gate_flags.allow_compressed_memory,
            image_base=image_base, max_steps=max_steps)
    else:
        result = reference_run(
            words, registers=dict(registers), memory=dict(memory),
            data_base=data_base, window_size=window, trace=trace,
            allow_branches=gate_flags.allow_branches,
            allow_address_forms=gate_flags.allow_address_forms,
            allow_jumps=gate_flags.allow_jumps,
            allow_loops=gate_flags.allow_loops,
            max_steps=max_steps)
    trace_entries = _expectation_trace(
        result, words, pc_base=data_base, compressed=compressed,
        policy=policy if compressed else None)
    expectation: dict[str, Any] = {
        "schema_version": "f1_reference_expectation.v1",
        "mode": gate_flags.mode,
        "flags": gate_flags.as_dict(),
        "isa": {"xlen": profile.xlen,
                "extensions": sorted(profile.extensions)},
        "pc_base": data_base,
        "program_end": (data_base + 4 * len(words)) & _MASK32,
        "retired_count": result["retired_count"],
        "retires": result["retires"],
        "pc_order": list(result["pc_order"]),
        "trace": trace_entries,
        "trace_hash": trace_hash(trace_entries),
        "trace_hash_algorithm": "fnv1a32",
        "register_writes": list(result["register_writes"]),
        "final_registers": dict(result["final_registers"]),
        "memory_changes": dict(result["memory_changes"]),
    }
    if "steps" in result:
        expectation["steps"] = list(result["steps"])
    return expectation


# ---------------------------------------------------------------------------
# The C++ host mirror specification (documentation data)
# ---------------------------------------------------------------------------


def host_mirror_spec() -> dict[str, Any]:
    """The exact C++ host changes the Python gate and expectation imply.

    This is the machine-readable twin of the table in
    ``docs/patches/f1-program-gate-integration.md``.  It deliberately contains
    no executable C++: the host file is not edited by this module's author.
    """
    return {
        "schema_version": "f1_host_mirror.v1",
        "authority": "src/myfuzz/fuzz/f1_program_gate.py",
        "host_file": "scripts/inprocess_obi_apb_f1f4_spike.cpp",
        "trace_hash": {
            "algorithm": "fnv1a32",
            "offset_basis": _FNV_OFFSET,
            "prime": _FNV_PRIME,
            "payload": "per retirement: pc, insn_word, rd, wdata as four "
                       "little-endian uint32 values",
            "python": "f1_reference_expectation(...)['trace_hash']",
        },
        "requirements": [
            {
                "id": "record_flags",
                "python": "f1_gate_flags_from_scenario",
                "cpp_anchor": "scripts/inprocess_obi_apb_f1f4_spike.cpp:280-288 "
                              "(F1_MAX_WORDS / F1_ALLOW_SUBWORD macros)",
                "change": "add F1_ALLOW_BRANCHES, F1_ALLOW_ADDRESS_FORMS and "
                          "F1_ALLOW_COMPRESSED, all defaulting to 0; the entry "
                          "must emit them from the scenario declaration next "
                          "to the existing F1_ALLOW_SUBWORD define",
            },
            {
                "id": "branch_targets",
                "python": "validate_program_words(..., allow_branches=True)",
                "cpp_anchor": "scripts/inprocess_obi_apb_f1f4_spike.cpp:755-831 "
                              "(make_record kF1 gate)",
                "change": "when F1_ALLOW_BRANCHES, admit opcode 0x63 with "
                          "funct3 in {0,1,4,5,6,7}; decode the B-type "
                          "displacement, require it 4-byte aligned, strictly "
                          "positive, and target index <= count (the appended "
                          "return jump at index count). Refuse every other "
                          "control transfer and every loop. Replace "
                          "prog_pc_ordered's +4 assumption with the expected "
                          "trace comparison.",
            },
            {
                "id": "address_provenance",
                "python": "validate_program_words(..., "
                          "allow_address_forms=True) / validate_address_program",
                "cpp_anchor": "scripts/inprocess_obi_apb_f1f4_spike.cpp:791-824 "
                              "(memory branch of the kF1 gate)",
                "change": "when F1_ALLOW_ADDRESS_FORMS, a memory word whose "
                          "rs1 is not x18 must carry immediate 0 and a base "
                          "register statically proven to be data_base + d. "
                          "Mirror the forward may-dataflow from "
                          "rv32_program._provenance_states: x18 is window[0,0], "
                          "LUI/ADDI/ADD propagate constants and window ranges, "
                          "ANDI folds only constants, every other write is "
                          "unknown, a merge unions two window ranges, and the "
                          "proven [low, high] plus the word's own immediate "
                          "must be 4-byte aligned and inside the declared "
                          "window. The x18 fast path keeps its existing rule.",
            },
            {
                "id": "compressed_fetch",
                "python": "validate_compressed_program(..., "
                          "allow_branches=...) / image_instructions",
                "cpp_anchor": "scripts/inprocess_obi_apb_f1f4_spike.cpp:768-831 "
                              "and the slot install at 1252-1265",
                "change": "when F1_ALLOW_COMPRESSED, a record word with bits "
                          "[1:0] != 3 is two 16-bit parcels, low half at pc and "
                          "high half at pc+2; a 32-bit word still occupies a "
                          "whole record word and may not straddle one. Decode "
                          "both halves with the admitted ALU subset (x12..x15 "
                          "destinations, nonzero immediate/shamt) and refuse "
                          "compressed control/memory parcels. The slot still "
                          "installs 4-byte record words and program_end stays "
                          "kSlot + 4*record.words. Expected retirement count is "
                          "the image instruction count (2 per packed record), "
                          "not record.words; insn comparison must use the "
                          "parcel (16-bit) or full word (32-bit) per PC.",
            },
            {
                "id": "pc_step",
                "python": "f1_reference_expectation(...)['pc_order']",
                "cpp_anchor": "scripts/inprocess_obi_apb_f1f4_spike.cpp:1780-1792 "
                              "(retirement attribution) and 2461-2482 (kF1 pass)",
                "change": "never derive the next retirement PC as last+4. A "
                          "compressed parcel steps 2 and a 32-bit word steps 4; "
                          "a taken branch jumps forward. Compare the observed "
                          "retirement PC sequence with the reference pc_order "
                          "(or its hash) instead of prog_pc_ordered.",
            },
            {
                "id": "trace_hash",
                "python": "f1_reference_expectation(...)['trace_hash']",
                "cpp_anchor": "scripts/inprocess_obi_apb_f1f4_spike.cpp:1774-1845 "
                              "(RVFI retirement block) and 2679-2700 (case line)",
                "change": "for every RVFI-valid retirement with "
                          "kSlot <= pc < program_end, feed the four little-"
                          "endian uint32 fields (pc, insn, rd_addr, rd_wdata) "
                          "to the same FNV-1a loop as window_hash. Emit "
                          "prog_trace_hash and prog_trace_count on the case "
                          "line; Python correspondence compares them with "
                          "f1_reference_expectation. Do not have the host "
                          "re-simulate the program to guess the trace.",
            },
        ],
        "protocol_note": (
            "The host cannot know a branch program's taken path before it "
            "runs. Either (a) let Python correspondence check the emitted "
            "prog_trace_hash/prog_pc_order after the case, or (b) extend the "
            "NEED_RECORD reply with one EXPECT_F1 <count> <hash> <pc_csv> line "
            "that the host stores and compares at case end. The reference "
            "trace remains the Python authority either way."
        ),
        "observation_keys": [
            "prog_retires", "prog_insns_match", "prog_rd_mask",
            "prog_last_wdata", "prog_traps", "prog_trace_hash",
            "prog_trace_count", "prog_pc_order", "data_hash_before",
            "data_hash_after", "data_changed",
        ],
    }
