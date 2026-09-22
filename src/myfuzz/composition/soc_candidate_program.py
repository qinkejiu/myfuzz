"""Roadmap item 3: declared candidate programs and input dependency repair.

The image plan (:mod:`myfuzz.composition.soc_image`) says *where* a fuzz
candidate may be written.  This module says *what a test does with it*: it
declares one candidate program per plan -- a generated register prologue plus N
independently fuzzable instruction slots at declared addresses and M data slots
in the declared writable region -- repairs every raw candidate into that program,
and refuses, by name, anything the declared facts cannot support.

What is declared, and where it comes from
-----------------------------------------

* the entry is the CPU profile's ``reset_vector``; the body starts at the pinned
  fetch convention ``{vector[31:8], 8'h80}`` and a one-word jump at the declared
  vector forwards a CPU that fetches at the vector itself (the convention
  :mod:`myfuzz.composition.soc_boot_program` uses, so no CPU is selected by
  name);
* the prologue registers come from the plan's own memory regions and windows:
  ``x2`` (sp) = top of the writable region, ``x3`` (the data base) = base of the
  writable region, and, when the plan declares an MMIO window, ``x4`` = the
  lowest declared MMIO window base.  Every binding is recorded in the program
  document; a candidate that uses a base register the prologue does not
  establish is refused, never entered with an unset base;
* instruction slot ``k`` sits at ``program_base + 4*k`` and data slot ``k`` at
  ``data_base + data_slot_offset + 4*k``; the declared addresses are handed to
  :func:`myfuzz.composition.soc_image.build_image_plan`, so the plan document and
  the transport layout expose exactly the slots the program places.

ISA scope (declared, not guessed)
---------------------------------

The generator emits and places **32-bit** encodings of the base integer ISA plus
``M``; it accepts a candidate that decodes as a legal 32-bit RV32I/RV32M word.  A
profile that also declares ``C`` is accepted as composition input, but this
generator implements no 16-bit placement, so a compressed candidate is refused
(``candidate-instruction-width-unsupported:16``) and the program document
records ``compressed_placement: false``.  An extension outside ``{I, M, C}`` is
refused at program-build time (``candidate-isa-extension-unsupported:<ext>``).

Control flow
------------

A branch or jump target is checked against the declared executable region first:
a target outside it is **refused**, never clamped.  A target inside the region
but outside the declared program window is projected with the same function the
address policy uses for data addresses (:func:`project_address`), the
instruction is re-encoded with the projected displacement, and the repair is
recorded and counted.  A projected displacement that does not fit the
instruction's encoding range is refused
(``candidate-target-immediate-unencodable:<kind>:<displacement>``).  The
``strict`` target policy refuses instead of projecting.

Dependencies
------------

The program's declared order is what satisfies a dependency: a store in slot
``i`` followed by a load from the same bytes in slot ``j > i`` is *repaired by
construction*, and the satisfied edge is recorded.  The composer also derives
and checks the byte-enable/permission of every access (the plan's declared fabric
decode permissions), MMIO read-before-write when the policy requires a preceding
write, a load whose response is used as the next address (resolved from the
frozen image or a preceding store; refused when unresolvable), and a load that
precedes the only store to its address when the load's value is not frozen.

Unknown values
--------------

A value the composer cannot derive is either resolved from the frozen image (the
image bytes, or the memory model's declared zero fill of an uninitialised memory
byte, cited from ``src/myfuzz/integration/rtl/riscv_boot_memory.sv``) or recorded
as an explicitly bounded unknown: it may be observed and stored, but it may never
determine an address.  A fact that cannot be bounded at all -- an undeclared base
register, an unsupported encoding, an unmapped access -- is refused with a named
error.

Committed inputs
----------------

A repair may only touch a word the test has not committed yet.  One repairer is
the lifetime of one test: the first word that offers a slot commits that slot's
repaired (offer, address, word, byte enable); a later word of the same test that
would change it is refused with
``repair-would-rewrite-committed-word:<slot>:<address>``, a directed seed that
would overwrite the frozen entry/prologue bytes is refused the same way, and a
repairer that already committed a test refuses a second one
(``candidate-repairer-already-committed``).
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType

from myfuzz.integration.soc_matrix_smoke import (
    ENTRY_OFFSET,
    _Assembler,
    _enc_b,
    _enc_i,
    _enc_j,
)

from .soc_composition import CompositionPlan
from .soc_image import (
    MAX_CANDIDATE_SLOTS,
    CandidateLayout,
    CandidateSlot,
    ImagePlan,
    ImageResult,
    SocImageError,
    build_image_plan,
)

CANDIDATE_PROGRAM_SCHEMA = "soc_candidate_program.v1"
CANDIDATE_TEST_SCHEMA = "soc_candidate_test.v1"

#: The ISA scope this generator really implements.  Emitted and accepted
#: instruction width is 32 bits; ``C`` is understood as a profile declaration
#: but 16-bit placement is not implemented.
SUPPORTED_XLEN = (32, 64)
SUPPORTED_EXTENSIONS = ("I", "M")
UNDERSTOOD_EXTENSIONS = ("I", "M", "C")
SUPPORTED_INSTRUCTION_WIDTHS = (32,)
CANDIDATE_ALIGNMENT = 4
WORD_BYTES = 4

#: Signed displacement bounds of the two PC-relative encodings and of the
#: I-immediate a JALR uses.
BRANCH_DISPLACEMENT_BOUND = 1 << 12
JAL_DISPLACEMENT_BOUND = 1 << 20
JALR_IMMEDIATE_BOUND = 1 << 11

#: Declared ABI register bindings the generated prologue establishes.
STACK_POINTER_REGISTER = 2
DATA_BASE_REGISTER = 3
MMIO_BASE_REGISTER = 4
REGISTER_ABI_NAMES = {0: "zero", 2: "sp", 3: "gp", 4: "tp"}

#: The generator's own ceiling on one generated program image.
MAX_PROGRAM_BYTES = 0x4000
#: A bounded fixpoint: a slot is re-analysed at most this many times, so a
#: candidate program with a loop terminates instead of growing forever.
MAX_SLOT_VISITS = 4


class CandidateProgramError(ValueError):
    """The declared candidate program cannot be built or repaired safely."""


def _error(reason: str) -> None:
    raise CandidateProgramError(reason)


def project_address(address: int, base: int, size: int) -> int:
    """Project one address into a declared window, four-byte aligned.

    This is the single address-window projection of the image path: the campaign
    projector repairs a candidate's raw address with
    ``first + ((address // 4) % slots) * 4``, and branch/jump targets are
    projected with exactly the same function rather than a second policy.
    """
    first = (int(base) + 3) & ~3
    slots = (int(base) + int(size) - first) // 4
    if slots < 1:
        _error(f"candidate-window-without-a-word:0x{int(base):x}:0x{int(size):x}")
    return first + ((int(address) // 4) % slots) * 4


# ---------------------------------------------------------------------------
# declared policy and program
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CandidateProgramPolicy:
    """How strictly the declared program is enforced.

    ``address_policy``: ``repair`` projects a raw candidate address onto the
    slot's declared address and records the repair; ``strict`` refuses a
    candidate that does not already carry the declared address.

    ``target_policy``: the same choice for branch/jump targets inside the
    declared executable region -- ``repair`` projects the target onto the
    declared program window and re-encodes the instruction, ``strict`` refuses.

    ``mmio_read_requires_write``: declare that a candidate program must write an
    MMIO address before reading it; a read with no covering preceding write is
    then refused by name instead of being recorded as an unknown value.

    ``allow_unmapped_access``: a load/store outside every declared window is
    refused by default; with this declared, it is recorded as an unknown-value
    access (the fabric answers with an error response, and the response value is
    never used as an address).

    ``data_slot_offset``: the declared offset of data slot 0 from the writable
    region base, so a program's own stores and the frozen data candidates do not
    have to share the first words.

    ``require_all_slots``: a declared program has one instruction word per slot,
    so a test that leaves a slot unoffered leaves a hole the CPU would execute
    as the memory model's zero fill (not a legal instruction).  By default that
    is refused (``candidate-slot-not-offered:<slot>``); with this declared False
    the hole is recorded as a bounded unknown and the slots after it are
    analysed as unreachable.
    """

    address_policy: str = "repair"
    target_policy: str = "repair"
    mmio_read_requires_write: bool = False
    allow_unmapped_access: bool = False
    require_all_slots: bool = True
    data_slot_offset: int = 0

    def __post_init__(self) -> None:
        for name in ("address_policy", "target_policy"):
            if getattr(self, name) not in ("repair", "strict"):
                _error(f"candidate-program-policy-invalid:{name}")
        for name in ("mmio_read_requires_write", "allow_unmapped_access",
                     "require_all_slots"):
            if not isinstance(getattr(self, name), bool):
                _error(f"candidate-program-policy-invalid:{name}")
        if isinstance(self.data_slot_offset, bool) \
                or not isinstance(self.data_slot_offset, int) or self.data_slot_offset < 0 \
                or self.data_slot_offset % CANDIDATE_ALIGNMENT:
            _error("candidate-program-policy-invalid:data_slot_offset")

    def document(self) -> dict[str, object]:
        return {
            "address_policy": self.address_policy,
            "target_policy": self.target_policy,
            "mmio_read_requires_write": self.mmio_read_requires_write,
            "allow_unmapped_access": self.allow_unmapped_access,
            "require_all_slots": self.require_all_slots,
            "data_slot_offset": self.data_slot_offset,
        }


@dataclass(frozen=True, slots=True)
class CandidateProgram:
    """One declared candidate program over one image plan."""

    plan_hash: str
    image: ImagePlan
    entry_address: int
    hardware_entry: int
    prologue_address: int
    prologue_words: tuple[int, ...]
    prologue_listing: tuple[str, ...]
    program_base: int
    program_size: int
    register_bindings: Mapping[str, object]
    policy: CandidateProgramPolicy
    isa: Mapping[str, object]
    #: The plan's declared fabric decode windows, joined with each target's
    #: declared port and read/write capability.  These are the permissions a
    #: candidate access is checked against.
    decode_windows: tuple[Mapping[str, object], ...]
    #: Memory region id -> the region base the frozen region image is anchored at.
    region_bases: Mapping[str, int]
    steps: tuple[str, ...]
    diagnostics: tuple[str, ...]
    #: The width of the raw record this program is projected from.  It is the
    #: *combined* ABI width when the composition appends environment-owned
    #: regions after the image segment (an attached peer's request fields, a
    #: synthetic master's stimulus), and the image width otherwise.  The program
    #: owns only its own image bits; bounding the record by the image width would
    #: refuse a legal record that also carries a peer request.
    raw_width: int = 0

    @property
    def record_width(self) -> int:
        """The width a raw word may really have for this program."""
        return int(self.raw_width) if int(self.raw_width) > 0 else int(self.image.raw_width)

    @property
    def slots(self) -> CandidateLayout:
        return self.image.candidates

    def window(self) -> tuple[int, int]:
        """The declared program window: every instruction slot address."""
        return (self.program_base, self.program_size)

    def region_base(self, region_id: str) -> int:
        try:
            return int(self.region_bases[region_id])
        except KeyError as error:
            raise CandidateProgramError(f"candidate-unknown-region:{region_id}") from error

    def entry_bytes(self) -> bytes:
        """The trampoline word plus the padding to the hardware entry."""
        pad = self.hardware_entry - self.entry_address
        trampoline = _enc_j(pad, 0, 0x6F)
        return trampoline.to_bytes(WORD_BYTES, "little") + bytes(pad - WORD_BYTES)

    def prologue_bytes(self) -> bytes:
        return b"".join(word.to_bytes(WORD_BYTES, "little")
                        for word in self.prologue_words)

    def static_image(self) -> bytes:
        """The region-anchored image the plan freezes for every test.

        Byte 0 is the first byte of the executable region: the entry trampoline,
        the generated prologue, then zeroes up to the end of the declared
        program window.  A campaign's fixed boot image is exactly this, and a
        test's candidate slots are overlaid on top of it (by ``initial_memory``
        in the RFuzz campaign path, or by the repairer's own ``request`` words).
        """
        base = self.image.base
        end = self.program_base + self.program_size
        image = bytearray(end - base)
        for payload, address in ((self.entry_bytes(), self.entry_address),
                                 (self.prologue_bytes(), self.prologue_address)):
            offset = address - base
            image[offset:offset + len(payload)] = payload
        return bytes(image)

    def repairer(self) -> "CandidateRepairer":
        """A fresh repairer: one repairer is the lifetime of one test."""
        return CandidateRepairer(self)

    def document(self) -> dict[str, object]:
        return {
            "schema_version": CANDIDATE_PROGRAM_SCHEMA,
            "plan_hash": self.plan_hash,
            "image_plan_hash": self.image.image_hash,
            # The raw record this program projects from: the image segment's own
            # width, or the wider combined ABI when environment-owned regions
            # (peer requests, synthetic stimulus) follow the image.
            "raw_width": int(self.record_width),
            "image_raw_width": int(self.image.raw_width),
            "entry_address": self.entry_address,
            "hardware_entry": self.hardware_entry,
            "trampoline": "jal x0, +0x%x at the declared reset vector"
                          % (self.hardware_entry - self.entry_address),
            "prologue": {
                "address": self.prologue_address,
                "words": len(self.prologue_words),
                "image_hash": "sha256:" + hashlib.sha256(
                    self.prologue_bytes()).hexdigest(),
                "listing": list(self.prologue_listing),
                "register_bindings": {
                    name: {key: value for key, value in dict(binding).items()}
                    for name, binding in sorted(self.register_bindings.items())},
            },
            "program": {
                "base": self.program_base,
                "size": self.program_size,
                "words": self.program_size // WORD_BYTES,
                "placement": "instruction slot k is at base + 4*k; the CPU enters the "
                             "declared reset vector, runs the trampoline, the prologue and "
                             "then the slots in declared order",
                "target_projection": "a branch/jump target outside the declared executable "
                                     "region is refused; a target inside it but outside this "
                                     "window is projected onto the window with "
                                     "project_address() and the instruction is re-encoded",
            },
            "candidates": self.image.candidates.document(),
            "static_image": {
                "base": self.image.base,
                "bytes": len(self.static_image()),
                "content_hash": "sha256:" + hashlib.sha256(
                    self.static_image()).hexdigest(),
                "content": "entry trampoline + generated prologue; the declared program "
                           "window is zero until a test overlays its candidates",
            },
            "isa": dict(self.isa),
            "policy": self.policy.document(),
            "permissions": [dict(row) for row in self.decode_windows],
            "steps": list(self.steps),
            "diagnostics": list(self.diagnostics),
        }


# ---------------------------------------------------------------------------
# plan facts
# ---------------------------------------------------------------------------


def _cpu(plan: CompositionPlan):
    instance = next((item for item in plan.instances if item.kind == "cpu"), None)
    if instance is None:
        _error("candidate-program-requires-a-cpu-instance")
    contract = instance.profile.cpu
    if contract is None:
        _error("candidate-program-requires-a-cpu-contract")
    return instance, contract


def _memory_regions(plan: CompositionPlan) -> list[dict]:
    return [dict(item) for item in plan.plan["address_map"]["memory_regions"]]


def _executable_region(plan: CompositionPlan, entry: int) -> dict:
    for region in _memory_regions(plan):
        permissions = region.get("permissions") or {}
        base = int(region["base"])
        if permissions.get("execute") and base <= entry < base + int(region["size"]):
            return region
    _error(f"candidate-program-entry-outside-executable-region:0x{entry:x}")


def _writable_region(plan: CompositionPlan) -> dict:
    candidates = [region for region in _memory_regions(plan)
                  if (region.get("permissions") or {}).get("write")]
    if not candidates:
        _error("candidate-program-without-a-writable-region")
    return min(candidates, key=lambda item: (int(item["base"]), str(item["region_id"])))


def _decode_windows(plan: CompositionPlan) -> tuple[Mapping[str, object], ...]:
    """The plan's own decode windows joined with each target's declared facts."""
    records = []
    for row in plan.plan["fabric"]["decode"]["windows"]:
        target_id = str(row.get("target_id", ""))
        target = next((item for item in plan.target_records
                       if str(item.get("target_id")) == target_id), None)
        capabilities = dict((target or {}).get("capabilities") or {})
        permissions = dict(row.get("permissions") or {})
        records.append({
            "window_id": str(row.get("window_id", target_id)),
            "target_id": target_id,
            "port": str((target or {}).get("port", "mem")),
            "base": int(row["base"]),
            "size": int(row["size"]),
            "read": bool(permissions.get("read", capabilities.get("read", False))),
            "write": bool(permissions.get("write", capabilities.get("write", False))),
            "execute": bool(permissions.get("execute", False)),
        })
    records.sort(key=lambda item: (int(item["base"]), str(item["window_id"])))
    return tuple(records)


def _isa_scope(contract) -> dict[str, object]:
    """The declared ISA range this generator implements, checked against the plan."""
    if str(contract.family) != "riscv":
        _error(f"candidate-isa-family-unsupported:{contract.family}")
    xlen = int(contract.xlen)
    if xlen not in SUPPORTED_XLEN:
        _error(f"candidate-xlen-unsupported:{xlen}")
    extensions = tuple(sorted({str(item).upper() for item in contract.extensions}))
    unsupported = [item for item in extensions if item not in UNDERSTOOD_EXTENSIONS]
    if unsupported:
        _error(f"candidate-isa-extension-unsupported:{unsupported[0].lower()}")
    if "I" not in extensions:
        _error(f"candidate-isa-without-base-integer:{list(extensions)}")
    return {
        "family": "riscv",
        "xlen": xlen,
        "extensions": list(extensions),
        "accepted_instruction_widths": list(SUPPORTED_INSTRUCTION_WIDTHS),
        "emitted_instruction_widths": list(SUPPORTED_INSTRUCTION_WIDTHS),
        "compressed_declared": "C" in extensions,
        "compressed_placement": False,
        "generator": "myfuzz.composition.soc_candidate_program",
    }


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------


def build_candidate_program(plan: CompositionPlan, *,
                            instruction_candidates: int = 2,
                            data_candidates: int = 1,
                            policy: CandidateProgramPolicy = CandidateProgramPolicy(),
                            isa_repair: bool = True,
                            raw_width: int = 0) -> CandidateProgram:
    """Declare one candidate program over the plan's own memory facts.

    ``raw_width`` is the width of the record the program will be projected from.
    The default (zero) means "the image segment's own width", which is right for a
    composition whose ABI ends at the image.  A composition that appends
    environment-owned regions -- an attached peer's request fields, a synthetic
    master's stimulus -- declares the combined width here, because the program
    owns only its own image bits and must not refuse a record that legally carries
    a peer request after them.
    """
    if not isinstance(plan, CompositionPlan):
        _error("composition-plan-required")
    if not isinstance(policy, CandidateProgramPolicy):
        _error("candidate-program-policy-required")
    if not isinstance(isa_repair, bool):
        _error("candidate-program-isa-repair-invalid")
    if type(raw_width) is not int or isinstance(raw_width, bool) or raw_width < 0:
        _error("candidate-program-raw-width-invalid")
    for value, label in ((instruction_candidates, "instruction_candidates"),
                         (data_candidates, "data_candidates")):
        if isinstance(value, bool) or not isinstance(value, int) \
                or not 1 <= value <= MAX_CANDIDATE_SLOTS:
            _error(f"candidate-count-invalid:{label}:{value!r}")
    instance, contract = _cpu(plan)
    isa = _isa_scope(contract)
    xlen = int(contract.xlen)
    entry = int(contract.reset_vector)
    rom = _executable_region(plan, entry)
    ram = _writable_region(plan)
    rom_base = int(rom["base"])
    rom_size = int(rom["size"])
    ram_base = int(ram["base"])
    ram_size = int(ram["size"])

    hardware_entry = (entry & ~0xFF) | ENTRY_OFFSET
    if hardware_entry < entry:
        _error(f"candidate-entry-vector-convention-unsupported:0x{entry:x}")

    # -- the prologue: every register binding comes from a declared fact ----
    stack_pointer = (ram_base + ram_size) & ~0xF
    data_base = ram_base
    mmio_base = _lowest_mmio_window(plan)
    asm = _Assembler(xlen)
    asm.label("_start")
    asm.comment("prologue: register bindings derived from the plan's memory regions")
    asm.li32(STACK_POINTER_REGISTER, stack_pointer)
    asm.li32(DATA_BASE_REGISTER, data_base)
    if mmio_base is not None:
        asm.li32(MMIO_BASE_REGISTER, mmio_base)
    prologue_words = tuple(asm.assemble())
    prologue_address = hardware_entry
    program_base = hardware_entry + WORD_BYTES * len(prologue_words)

    bindings: dict[str, object] = {
        "stack_pointer": {"register": STACK_POINTER_REGISTER,
                          "abi_name": REGISTER_ABI_NAMES[STACK_POINTER_REGISTER],
                          "value": stack_pointer, "value_hex": f"0x{stack_pointer:08x}",
                          "basis": f"top of the declared writable region "
                                   f"{ram['region_id']}, 16-byte aligned"},
        "data_base": {"register": DATA_BASE_REGISTER,
                      "abi_name": REGISTER_ABI_NAMES[DATA_BASE_REGISTER],
                      "value": data_base, "value_hex": f"0x{data_base:08x}",
                      "basis": f"base of the declared writable region {ram['region_id']}"},
    }
    if mmio_base is not None:
        bindings["mmio_base"] = {"register": MMIO_BASE_REGISTER,
                                 "abi_name": REGISTER_ABI_NAMES[MMIO_BASE_REGISTER],
                                 "value": mmio_base, "value_hex": f"0x{mmio_base:08x}",
                                 "basis": "lowest declared MMIO window base"}

    # -- declared slot addresses ------------------------------------------
    slot_addresses: dict[str, int] = {}
    for index in range(instruction_candidates):
        slot_addresses["init" if index == 0 else f"init{index}"] = \
            program_base + WORD_BYTES * index
    for index in range(data_candidates):
        slot_addresses["data" if index == 0 else f"data{index}"] = \
            data_base + policy.data_slot_offset + WORD_BYTES * index

    program_size = WORD_BYTES * instruction_candidates
    if program_base + program_size > rom_base + rom_size:
        _error(f"candidate-program-exceeds-region:0x{program_base + program_size:x}"
               f">0x{rom_base + rom_size:x}")
    if program_base + program_size - rom_base > MAX_PROGRAM_BYTES:
        _error(f"candidate-program-exceeds-bound:"
               f"0x{program_base + program_size - rom_base:x}>{MAX_PROGRAM_BYTES}")
    data_end = data_base + policy.data_slot_offset + WORD_BYTES * data_candidates
    if data_end > ram_base + ram_size:
        _error(f"candidate-data-slots-exceed-region:0x{data_end:x}"
               f">0x{ram_base + ram_size:x}")

    image = build_image_plan(plan, isa_repair=isa_repair,
                             instruction_candidates=instruction_candidates,
                             data_candidates=data_candidates,
                             slot_addresses=slot_addresses)
    steps = [
        f"entry: the CPU profile declares reset vector 0x{entry:08x}; a one-word jump at "
        f"the vector forwards a CPU that fetches there, and the body is at "
        f"0x{hardware_entry:08x} (the pinned {{vector[31:8], 8'h80}} convention)",
        f"prologue at 0x{prologue_address:08x}: {len(prologue_words)} words establish "
        + ", ".join(f"x{int(dict(item)['register'])}={dict(item)['value_hex']}"
                    for _, item in sorted(bindings.items())),
        f"program: {instruction_candidates} instruction slot(s) from 0x{program_base:08x} "
        f"to 0x{program_base + program_size:08x}, four bytes apart, executed in declared "
        f"order after the prologue",
        f"data: {data_candidates} data slot(s) from "
        f"0x{data_base + policy.data_slot_offset:08x}, frozen into the writable region "
        f"{ram['region_id']} before the CPU is released",
        "the entry trampoline, the prologue and the repaired candidate words are frozen "
        "before the CPU is released; no byte is rewritten after the freeze",
    ]
    diagnostics = [
        "the ISA scope is declared: 32-bit RV32I/RV32M encodings are emitted and "
        "accepted; compressed (16-bit) placement is not implemented and a 16-bit "
        "candidate is refused by name",
        "a branch or jump target outside the declared executable region is refused, "
        "never clamped; a target inside the region but outside the program window is "
        "projected with the same address-window projection the data policy uses",
        "a register a candidate uses as an address base must be established by the "
        "recorded prologue or by an earlier slot whose definition reaches it; otherwise "
        "the candidate is refused",
        "a value the composer cannot derive is recorded with its declared bound (the "
        "frozen image, or the memory model's zero fill of a memory byte) and may never "
        "determine an address",
    ]
    program = CandidateProgram(
        plan_hash=plan.plan_hash, image=image, entry_address=entry,
        hardware_entry=hardware_entry, prologue_address=prologue_address,
        prologue_words=prologue_words, prologue_listing=tuple(asm.listing(prologue_address)),
        program_base=program_base, program_size=program_size,
        register_bindings=MappingProxyType(bindings), policy=policy,
        isa=MappingProxyType(isa), decode_windows=_decode_windows(plan),
        region_bases=MappingProxyType({str(item["region_id"]): int(item["base"])
                                       for item in _memory_regions(plan)}),
        steps=tuple(steps), diagnostics=tuple(diagnostics),
        raw_width=int(raw_width))
    return replace(program, image=replace(image, program=program.document()))


def _lowest_mmio_window(plan: CompositionPlan) -> int | None:
    """The lowest declared MMIO window base, or None when the plan declares none."""
    bases = []
    for row in plan.plan["address_map"]["windows"]:
        target_id = str(row.get("target_id", ""))
        record = next((item for item in plan.target_records
                       if str(item.get("target_id")) == target_id), None)
        if record is not None and str(record.get("port")) == "mem":
            continue
        bases.append(int(row["base"]))
    return min(bases) if bases else None


# ---------------------------------------------------------------------------
# RV32I/RV32M decoding
# ---------------------------------------------------------------------------

_OP_LUI, _OP_AUIPC, _OP_JAL, _OP_JALR = 0x37, 0x17, 0x6F, 0x67
_OP_BRANCH, _OP_LOAD, _OP_STORE = 0x63, 0x03, 0x23
_OP_IMM, _OP_REG, _OP_MISC, _OP_SYSTEM = 0x13, 0x33, 0x0F, 0x73
_OP_IMM32, _OP_REG32 = 0x1B, 0x3B

_LOADS = {"LB": (0, 1), "LH": (1, 2), "LW": (2, 4), "LD": (3, 8),
          "LBU": (4, 1), "LHU": (5, 2), "LWU": (6, 4)}
_STORES = {"SB": (0, 1), "SH": (1, 2), "SW": (2, 4), "SD": (3, 8)}
_BRANCHES = {"BEQ": 0, "BNE": 1, "BLT": 4, "BGE": 5, "BLTU": 6, "BGEU": 7}
_IMM_OPS = {"ADDI": 0, "SLTI": 2, "SLTIU": 3, "XORI": 4, "ORI": 6, "ANDI": 7}
_REG_OPS = {"ADD": (0, 0x00), "SUB": (0, 0x20), "SLL": (1, 0x00), "SLT": (2, 0x00),
            "SLTU": (3, 0x00), "XOR": (4, 0x00), "SRL": (5, 0x00), "SRA": (5, 0x20),
            "OR": (6, 0x00), "AND": (7, 0x00)}
_M_OPS = {"MUL": 0, "MULH": 1, "MULHSU": 2, "MULHU": 3, "DIV": 4, "DIVU": 5,
          "REM": 6, "REMU": 7}
#: Instructions whose flow leaves the declared program: a trap, a return, or a
#: wait state.  They are accepted but recorded as a declared unknown bound.
_FLOW_LEAVES = {"ECALL": 0x00000073, "EBREAK": 0x00100073, "MRET": 0x30200073,
                "SRET": 0x10200073, "WFI": 0x10500073, "URET": 0x00200073}


class DecodedInstruction:
    """One decoded 32-bit RV32I/RV32M instruction."""

    __slots__ = ("name", "kind", "word", "rd", "rs1", "rs2", "imm", "size", "funct3")

    def __init__(self, name: str, kind: str, word: int, *, rd: int = 0, rs1: int = 0,
                 rs2: int = 0, imm: int = 0, size: int = 0, funct3: int = 0) -> None:
        self.name = name
        self.kind = kind
        self.word = word
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2
        self.imm = imm
        self.size = size
        self.funct3 = funct3

    def document(self) -> dict[str, object]:
        return {"name": self.name, "kind": self.kind, "word": f"0x{self.word:08x}",
                "rd": self.rd, "rs1": self.rs1, "rs2": self.rs2, "imm": self.imm,
                "size": self.size}


def _sign(value: int, bits: int) -> int:
    limit = 1 << (bits - 1)
    return (value & (limit - 1)) - (value & limit)


def _decode_i(word: int) -> int:
    return _sign(word >> 20, 12)


def _decode_s(word: int) -> int:
    return _sign(((word >> 25) << 5) | ((word >> 7) & 0x1F), 12)


def _decode_b(word: int) -> int:
    value = (((word >> 31) & 1) << 12) | (((word >> 7) & 1) << 11) \
        | (((word >> 25) & 0x3F) << 5) | (((word >> 8) & 0xF) << 1)
    return _sign(value, 13)


def _decode_j(word: int) -> int:
    value = (((word >> 31) & 1) << 20) | (((word >> 12) & 0xFF) << 12) \
        | (((word >> 20) & 1) << 11) | (((word >> 21) & 0x3FF) << 1)
    return _sign(value, 21)


def decode_word(word: int, xlen: int = 32) -> DecodedInstruction:
    """Decode one 32-bit RV32I/RV32M word, or refuse it by name.

    A 16-bit encoding is refused (``candidate-instruction-width-unsupported:16``)
    because this generator places 32-bit words only, and an encoding outside the
    declared scope is refused with ``candidate-encoding-unsupported:<word>``.
    """
    if isinstance(word, bool) or not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        _error(f"candidate-word-invalid:{word!r}")
    if (word & 0x3) != 0x3:
        _error("candidate-instruction-width-unsupported:16")
    opcode = word & 0x7F
    rd = (word >> 7) & 0x1F
    funct3 = (word >> 12) & 7
    rs1 = (word >> 15) & 0x1F
    rs2 = (word >> 20) & 0x1F
    funct7 = (word >> 25) & 0x7F
    if opcode == _OP_LUI:
        return DecodedInstruction("LUI", "lui", word, rd=rd, imm=word & 0xFFFFF000)
    if opcode == _OP_AUIPC:
        return DecodedInstruction("AUIPC", "auipc", word, rd=rd, imm=word & 0xFFFFF000)
    if opcode == _OP_JAL:
        return DecodedInstruction("JAL", "jal", word, rd=rd, imm=_decode_j(word))
    if opcode == _OP_JALR and funct3 == 0:
        return DecodedInstruction("JALR", "jalr", word, rd=rd, rs1=rs1, imm=_decode_i(word))
    if opcode == _OP_BRANCH:
        name = next((key for key, value in _BRANCHES.items() if value == funct3), None)
        if name is None:
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        return DecodedInstruction(name, "branch", word, rs1=rs1, rs2=rs2,
                                  imm=_decode_b(word), funct3=funct3)
    if opcode == _OP_LOAD:
        name = next((key for key, value in _LOADS.items() if value[0] == funct3), None)
        if name is None or (xlen == 32 and name in ("LD", "LWU")):
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        return DecodedInstruction(name, "load", word, rd=rd, rs1=rs1, imm=_decode_i(word),
                                  size=_LOADS[name][1], funct3=funct3)
    if opcode == _OP_STORE:
        name = next((key for key, value in _STORES.items() if value[0] == funct3), None)
        if name is None or (xlen == 32 and name == "SD"):
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        return DecodedInstruction(name, "store", word, rs1=rs1, rs2=rs2,
                                  imm=_decode_s(word), size=_STORES[name][1],
                                  funct3=funct3)
    if opcode == _OP_IMM:
        if funct3 in _IMM_OPS.values():
            name = next(key for key, value in _IMM_OPS.items() if value == funct3)
            return DecodedInstruction(name, "op_imm", word, rd=rd, rs1=rs1,
                                      imm=_decode_i(word))
        if funct3 == 1 and funct7 == 0:
            return DecodedInstruction("SLLI", "op_imm", word, rd=rd, rs1=rs1,
                                      imm=(word >> 20) & (0x1F if xlen == 32 else 0x3F))
        if funct3 == 5 and funct7 in (0x00, 0x20):
            return DecodedInstruction("SRLI" if funct7 == 0 else "SRAI", "op_imm", word,
                                      rd=rd, rs1=rs1,
                                      imm=(word >> 20) & (0x1F if xlen == 32 else 0x3F))
        _error(f"candidate-encoding-unsupported:0x{word:08x}")
    if opcode == _OP_REG:
        if funct7 == 1 and funct3 in _M_OPS.values():
            name = next(key for key, value in _M_OPS.items() if value == funct3)
            return DecodedInstruction(name, "m", word, rd=rd, rs1=rs1, rs2=rs2)
        name = next((key for key, value in _REG_OPS.items()
                     if value == (funct3, funct7)), None)
        if name is None:
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        return DecodedInstruction(name, "op", word, rd=rd, rs1=rs1, rs2=rs2)
    if opcode in (_OP_IMM32, _OP_REG32):
        if xlen != 64:
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        return DecodedInstruction("W-OP", "unmodelled", word, rd=rd, rs1=rs1, rs2=rs2)
    if opcode == _OP_MISC:
        if funct3 not in (0, 1):
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        return DecodedInstruction("FENCE", "fence", word)
    if opcode == _OP_SYSTEM:
        for name, value in _FLOW_LEAVES.items():
            if word == value:
                return DecodedInstruction(name, "leaves", word)
        if funct3 == 0:
            _error(f"candidate-encoding-unsupported:0x{word:08x}")
        # A CSR access is a legal encoding the composer models conservatively:
        # the read value is DUT state and the write changes CPU state.
        return DecodedInstruction("CSR", "csr", word, rd=rd, rs1=rs1)
    _error(f"candidate-encoding-unsupported:0x{word:08x}")


# ---------------------------------------------------------------------------
# directed-program encoders
# ---------------------------------------------------------------------------
#
# A directed program (a hand-written slot word, or the real-RTL acceptance run)
# needs the same encodings the generator emits.  These helpers are the public
# face of the pinned encoders in ``myfuzz.integration.soc_matrix_smoke``; a
# directed word is *validated* by :func:`decode_word` rather than replaced by the
# reference ISA repair, so what the composer analyses is what the RTL places.


def encode_u_type(imm20: int, rd: int, opcode: int) -> int:
    from myfuzz.integration.soc_matrix_smoke import _enc_u
    return _enc_u(imm20, rd, opcode)


def encode_i_type(imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    from myfuzz.integration.soc_matrix_smoke import _enc_i
    return _enc_i(imm, rs1, funct3, rd, opcode)


def encode_s_type(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    from myfuzz.integration.soc_matrix_smoke import _enc_s
    return _enc_s(imm, rs2, rs1, funct3, opcode)


def encode_b_type(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    from myfuzz.integration.soc_matrix_smoke import _enc_b
    return _enc_b(imm, rs2, rs1, funct3, opcode)


def encode_j_type(imm: int, rd: int, opcode: int) -> int:
    from myfuzz.integration.soc_matrix_smoke import _enc_j
    return _enc_j(imm, rd, opcode)


def encode_lui(rd: int, imm20: int) -> int:
    return encode_u_type(imm20, rd, 0x37)


def encode_addi(rd: int, rs1: int, imm: int) -> int:
    return encode_i_type(imm, rs1, 0b000, rd, 0x13)


def encode_lw(rd: int, rs1: int, imm: int) -> int:
    return encode_i_type(imm, rs1, 0b010, rd, 0x03)


def encode_sw(rs2: int, rs1: int, imm: int) -> int:
    return encode_s_type(imm, rs2, rs1, 0b010, 0x23)


def encode_jal(rd: int, displacement: int) -> int:
    return encode_j_type(displacement, rd, 0x6F)


def encode_jalr(rd: int, rs1: int, imm: int) -> int:
    return encode_i_type(imm, rs1, 0b000, rd, 0x67)


def encode_beq(rs1: int, rs2: int, displacement: int) -> int:
    return encode_b_type(displacement, rs2, rs1, 0b000, 0x63)


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RepairRecord:
    """One recorded change to an uncommitted input."""

    kind: str
    slot: str
    field: str
    before: int
    after: int
    rule: str

    def document(self) -> dict[str, object]:
        return {"kind": self.kind, "slot": self.slot, "field": self.field,
                "before": self.before, "after": self.after,
                "before_hex": f"0x{self.before:08x}", "after_hex": f"0x{self.after:08x}",
                "rule": self.rule}


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    """One declared dependency the program satisfies, resolves or bounds."""

    kind: str
    status: str
    slot: str
    address: int
    detail: str
    value: int | None = None

    def document(self) -> dict[str, object]:
        return {"kind": self.kind, "status": self.status, "slot": self.slot,
                "address": self.address, "address_hex": f"0x{self.address:08x}",
                "detail": self.detail, "value": self.value}


@dataclass(frozen=True, slots=True)
class UnknownRecord:
    """One value the composer could not derive, with its declared bound."""

    kind: str
    slot: str
    address: int
    bound: str
    detail: str

    def document(self) -> dict[str, object]:
        return {"kind": self.kind, "slot": self.slot, "address": self.address,
                "address_hex": f"0x{self.address:08x}", "bound": self.bound,
                "detail": self.detail}


@dataclass(frozen=True, slots=True)
class RepairedTest:
    """One repaired test: the raw words the RTL must apply and the record."""

    request: tuple[int, ...]
    image: ImageResult
    placements: tuple[Mapping[str, object], ...]
    records: tuple[RepairRecord, ...]
    dependencies: tuple[DependencyRecord, ...]
    unknowns: tuple[UnknownRecord, ...]
    counters: Mapping[str, int]
    artifacts: Mapping[str, object] = field(default_factory=dict)

    def document(self) -> dict[str, object]:
        return {
            "schema_version": CANDIDATE_TEST_SCHEMA,
            "request": list(self.request),
            "image": self.image.document(),
            "placements": [dict(item) for item in self.placements],
            "repairs": [item.document() for item in self.records],
            "dependencies": [item.document() for item in self.dependencies],
            "unknowns": [item.document() for item in self.unknowns],
            "counters": dict(sorted(self.counters.items())),
            "artifacts": {name: value for name, value in sorted(self.artifacts.items())},
        }


# ---------------------------------------------------------------------------
# the abstract machine
# ---------------------------------------------------------------------------


@dataclass
class _State:
    """The abstract machine state at one slot entry."""

    registers: dict[int, int | None]
    defined_by: dict[int, str]
    store_bytes: dict[int, int | None]
    mmio_writes: dict[int, int | None]
    pending_loads: dict[int, str]
    #: Register -> the slot whose load produced it.  Using such a register as an
    #: address base is the "response feeds the next address" dependency.
    load_sources: dict[int, str]


def _merge(left: _State, right: _State) -> _State:
    """Merge two incoming states: a differing or missing value becomes unknown."""
    registers: dict[int, int | None] = {}
    defined_by = dict(left.defined_by)
    for register in set(left.registers) | set(right.registers):
        first = left.registers.get(register)
        second = right.registers.get(register)
        registers[register] = first if first == second else None
        defined_by.setdefault(register, right.defined_by.get(register, ""))
    store_bytes: dict[int, int | None] = {}
    for address in set(left.store_bytes) | set(right.store_bytes):
        first = left.store_bytes.get(address)
        second = right.store_bytes.get(address)
        store_bytes[address] = first if first is not None and first == second else None
    mmio_writes: dict[int, int | None] = {}
    for address in set(left.mmio_writes) | set(right.mmio_writes):
        first = left.mmio_writes.get(address)
        second = right.mmio_writes.get(address)
        mmio_writes[address] = first if first is not None and first == second else None
    pending: dict[int, str] = {}
    for address in set(left.pending_loads) | set(right.pending_loads):
        first = left.pending_loads.get(address)
        second = right.pending_loads.get(address)
        if first == second and first is not None:
            pending[address] = first
    load_sources: dict[int, str] = {}
    for register in set(left.load_sources) | set(right.load_sources):
        first = left.load_sources.get(register)
        second = right.load_sources.get(register)
        if first == second and first is not None:
            load_sources[register] = first
    return _State(registers=registers, defined_by=defined_by, store_bytes=store_bytes,
                  mmio_writes=mmio_writes, pending_loads=pending,
                  load_sources=load_sources)


class _AccessMap:
    """The declared decode windows: mapping, permission and frozen values."""

    def __init__(self, program: CandidateProgram, image: ImageResult) -> None:
        self.windows = [dict(row) for row in program.decode_windows]
        self._frozen: dict[int, int] = {}
        for region_id, payload in image.region_images.items():
            base = program.region_base(region_id)
            for offset, byte in enumerate(payload):
                self._frozen[base + offset] = byte
        # Uninitialised bytes of a *memory-model* window read as the memory
        # model's declared zero fill (riscv_boot_memory.sv zeroes
        # initial_memory before $readmemh).  MMIO bytes never are.
        self._memory_windows = [row for row in self.windows if row["port"] == "mem"]

    def lookup(self, address: int, size: int) -> dict | None:
        for row in self.windows:
            if row["base"] <= address and address + size <= row["base"] + row["size"]:
                return row
        return None

    def executable(self, address: int) -> bool:
        for row in self.windows:
            if row["base"] <= address < row["base"] + row["size"]:
                return bool(row["execute"])
        return False

    def frozen(self, address: int, size: int) -> tuple[int, str] | None:
        value = 0
        source = "frozen image"
        for offset in range(size):
            current = address + offset
            if current in self._frozen:
                value |= self._frozen[current] << (8 * offset)
                continue
            if any(row["base"] <= current < row["base"] + row["size"]
                   for row in self._memory_windows):
                source = "frozen image + memory-model zero fill"
                continue
            return None
        return (value, source)


class _Analyzer:
    """Walk the declared program, repair targets and check every dependency."""

    def __init__(self, program: CandidateProgram, words: dict[str, int],
                 counter: dict[str, int], image: ImageResult,
                 directed: Sequence[str] = ()) -> None:
        self.program = program
        self.words = words
        self.counter = counter
        self.directed = frozenset(directed)
        self.regions = _AccessMap(program, image)
        self.base, self.size = program.window()
        self.records: list[RepairRecord] = []
        self.dependencies: list[DependencyRecord] = []
        self.unknowns: list[UnknownRecord] = []
        self.visits: dict[int, int] = {}
        self.xlen = int(program.isa["xlen"])

    # -- driver ------------------------------------------------------------

    def run(self) -> dict[str, object]:
        slots = self.program.slots.instruction
        if not slots:
            return self._result()
        for slot in slots:
            if slot.prefix in self.words:
                continue
            if self.program.policy.require_all_slots:
                _error(f"candidate-slot-not-offered:{slot.prefix}")
            self.unknowns.append(UnknownRecord(
                kind="unoffered-slot", slot=slot.prefix,
                address=slot.declared_address,
                bound="the memory model's zero fill (0x00000000) is not a legal "
                      "instruction; the CPU traps and the slots after this one are "
                      "analysed as unreachable",
                detail="the test offers no candidate for this declared slot"))
        initial = _State(registers={0: 0}, defined_by={0: "zero"}, store_bytes={},
                         mmio_writes={}, pending_loads={}, load_sources={})
        for name, binding in self.program.register_bindings.items():
            register = int(dict(binding)["register"])
            initial.registers[register] = int(dict(binding)["value"])
            initial.defined_by[register] = "prologue"
        states: dict[int, _State] = {0: initial}
        worklist = [0]
        while worklist:
            index = worklist.pop(0)
            if index >= len(slots) or self.visits.get(index, 0) >= MAX_SLOT_VISITS:
                continue
            if slots[index].prefix not in self.words:
                # A hole: the zero fill is not a legal instruction, so control
                # does not continue past it.
                continue
            self.visits[index] = self.visits.get(index, 0) + 1
            state = states[index]
            for successor, successor_state in self.step(index, state):
                if successor is None or successor >= len(slots):
                    continue
                if successor in states:
                    merged = _merge(states[successor], successor_state)
                    if merged.registers != states[successor].registers \
                            or merged.store_bytes != states[successor].store_bytes \
                            or merged.mmio_writes != states[successor].mmio_writes \
                            or merged.pending_loads != states[successor].pending_loads \
                            or merged.load_sources != states[successor].load_sources:
                        states[successor] = merged
                        worklist.append(successor)
                else:
                    states[successor] = successor_state
                    worklist.append(successor)
            worklist = sorted(set(worklist))
        for index in range(len(slots)):
            if slots[index].prefix not in self.words:
                continue
            if index not in self.visits:
                # An unreachable slot is not modelled, but the word it places is
                # still validated: an encoding the declared ISA does not support
                # is refused wherever it sits in the program.
                try:
                    decode_word(self.words[slots[index].prefix], self.xlen)
                except CandidateProgramError as error:
                    raise CandidateProgramError(
                        f"{error}:slot={slots[index].prefix}") from error
                self.unknowns.append(UnknownRecord(
                    kind="unreachable-slot", slot=slots[index].prefix,
                    address=slots[index].declared_address,
                    bound="the declared control flow does not reach this slot; its bytes "
                          "are still frozen, observable and encoding-checked",
                    detail="no declared path reaches this slot"))
        return self._result()

    def _result(self) -> dict[str, object]:
        return {"words": self.words, "records": self.records,
                "dependencies": self.dependencies, "unknowns": self.unknowns,
                "visits": self.visits}

    # -- one slot ----------------------------------------------------------

    def step(self, index: int, state: _State):
        slot = self.program.slots.instruction[index]
        address = slot.declared_address
        word = self.words[slot.prefix]
        try:
            decoded = decode_word(word, self.xlen)
        except CandidateProgramError as error:
            raise CandidateProgramError(f"{error}:slot={slot.prefix}") from error
        machine = _Machine(self, slot, decoded, address, state,
                           directed=slot.prefix in self.directed)
        machine.execute()
        self.words[slot.prefix] = machine.word
        return [(item, machine.state()) for item in machine.successors]


class _Machine:
    """One slot's abstract execution over one incoming state."""

    def __init__(self, analyzer: _Analyzer, slot: CandidateSlot,
                 decoded: DecodedInstruction, address: int, state: _State,
                 directed: bool) -> None:
        self.analyzer = analyzer
        self.program = analyzer.program
        self.slot = slot
        self.decoded = decoded
        self.address = address
        self.directed = directed
        self.word = decoded.word
        self.registers = dict(state.registers)
        self.defined_by = dict(state.defined_by)
        self.store_bytes = dict(state.store_bytes)
        self.mmio_writes = dict(state.mmio_writes)
        self.pending_loads = dict(state.pending_loads)
        self.load_sources = dict(state.load_sources)
        self.successors: list[int | None] = []
        self.registers[0] = 0

    # -- state helpers -----------------------------------------------------

    def state(self) -> _State:
        return _State(registers=dict(self.registers), defined_by=dict(self.defined_by),
                      store_bytes=dict(self.store_bytes),
                      mmio_writes=dict(self.mmio_writes),
                      pending_loads=dict(self.pending_loads),
                      load_sources=dict(self.load_sources))

    def write(self, register: int, value: int | None) -> None:
        if register == 0:
            return
        self.registers[register] = None if value is None else int(value) & 0xFFFFFFFF
        self.defined_by[register] = self.slot.prefix
        # Any later definition replaces the load response this register held.
        self.load_sources.pop(register, None)

    def read(self, register: int) -> int | None:
        if register == 0:
            return 0
        value = self.registers.get(register)
        if register not in self.defined_by:
            if not any(item.kind == "unset-register-read" and item.slot == self.slot.prefix
                       and item.detail.endswith(f"x{register}")
                       for item in self.analyzer.unknowns):
                self.analyzer.unknowns.append(UnknownRecord(
                    kind="unset-register-read", slot=self.slot.prefix,
                    address=self.address,
                    bound="the register is not established by the prologue or any earlier "
                          "slot; the profile declares no architectural reset value, so the "
                          "value is bounded only as unknown and never used as an address",
                    detail=f"reads x{register}"))
            self.counter_unknown()
            return None
        return None if value is None else int(value)

    def base(self, register: int, kind: str, imm: int) -> int:
        """An address base: established and derivable, repaired, or refused.

        A directed word is the test's own instruction, so an address base it
        does not establish is refused by name.  A fuzz word is *repaired*: the
        reference ISA repair already chose the operation, so the composer
        projects the base register field onto a declared base register (the
        writable-region base or the MMIO base) whose declared value makes the
        access land inside a mapped, permitted window, and records the repair.
        An indirect jump has no declared code-address register to project onto,
        so an unset JALR base is always refused.
        """
        if register == 0:
            return 0
        if register in self.defined_by:
            value = self.registers.get(register)
            if value is None:
                _error(f"dependency-response-address-unresolved:x{register}"
                       f":{self.defined_by.get(register) or 'unknown'}")
            if register in self.load_sources:
                self.analyzer.dependencies.append(DependencyRecord(
                    kind="response-feeds-address", status="resolved",
                    slot=self.slot.prefix, address=int(value) & 0xFFFFFFFF,
                    value=int(value) & 0xFFFFFFFF,
                    detail=f"x{register} is the response of the load in "
                           f"{self.load_sources[register]}; the value is derivable, so the "
                           f"address it feeds is resolved"))
                self.analyzer.counter["dependencies_resolved"] += 1
            return int(value) & 0xFFFFFFFF
        if self.directed or kind == "jalr":
            _error(f"candidate-base-register-unset:x{register}")
        return self.repair_base(register, kind, imm)

    def repair_base(self, register: int, kind: str, imm: int) -> int:
        """Project an unset base register onto a declared base register."""
        declared = [name for name in ("data_base", "mmio_base")
                    if name in self.program.register_bindings]
        if not declared:
            _error(f"candidate-base-register-unset:x{register}")
        size = self.decoded.size if kind in ("load", "store") else WORD_BYTES
        access = "read" if kind == "load" else "write"
        chosen = None
        for name in declared:
            binding = dict(self.program.register_bindings[name])
            candidate = (int(binding["value"]) + imm) & 0xFFFFFFFF
            window = self.analyzer.regions.lookup(candidate, size)
            if window is not None and window[access]:
                chosen = (name, binding, candidate)
                break
        if chosen is None:
            name = declared[0]
            binding = dict(self.program.register_bindings[name])
            return (int(binding["value"]) + imm) & 0xFFFFFFFF
        name, binding, candidate = chosen
        base_register = int(binding["register"])
        self.word = _set_field(self.word, _Field(15, 5), base_register)
        self.decoded.rs1 = base_register
        self.analyzer.records.append(RepairRecord(
            kind="register", slot=self.slot.prefix, field="rs1", before=register,
            after=base_register,
            rule=f"base register projected onto the declared {name} register "
                 f"x{base_register}; the access address becomes that register's declared "
                 f"value plus the instruction's own immediate"))
        self.analyzer.counter["register_repair"] += 1
        return candidate

    def counter_unknown(self) -> None:
        self.analyzer.counter["unknown_values"] += 1

    # -- execution ---------------------------------------------------------

    def execute(self) -> None:
        decoded = self.decoded
        kind = decoded.kind
        if kind == "lui":
            self.write(decoded.rd, decoded.imm & 0xFFFFFFFF)
        elif kind == "auipc":
            self.write(decoded.rd, (self.address + decoded.imm) & 0xFFFFFFFF)
        elif kind == "jal":
            self.write(decoded.rd, (self.address + WORD_BYTES) & 0xFFFFFFFF)
            target = (self.address + decoded.imm) & 0xFFFFFFFF
            rd = (self.word >> 7) & 0x1F
            self.successors.append(self.target(
                "jal", target,
                lambda value: _encode_jal(self.word, rd, value - self.address)))
        elif kind == "jalr":
            source = self.base(decoded.rs1, "jalr", decoded.imm)
            self.write(decoded.rd, (self.address + WORD_BYTES) & 0xFFFFFFFF)
            target = (source + decoded.imm) & 0xFFFFFFFF
            rd = (self.word >> 7) & 0x1F
            rs1 = decoded.rs1
            self.successors.append(self.target(
                "jalr", target,
                lambda value: _encode_jalr(self.word, rd, rs1, value - source)))
        elif kind == "branch":
            target = (self.address + decoded.imm) & 0xFFFFFFFF
            self.successors.extend(self.branch(target))
        elif kind == "load":
            source = self.base(decoded.rs1, "load", decoded.imm)
            self.write(decoded.rd, self.load((source + decoded.imm) & 0xFFFFFFFF))
            if decoded.rd != 0:
                self.load_sources[decoded.rd] = self.slot.prefix
        elif kind == "store":
            source = self.base(decoded.rs1, "store", decoded.imm)
            self.store((source + decoded.imm) & 0xFFFFFFFF)
        elif kind == "op_imm":
            self.write(decoded.rd, _compute_imm(decoded, self))
        elif kind in ("op", "m"):
            self.write(decoded.rd, _compute_reg(decoded, self))
        elif kind == "csr":
            if decoded.rs1 != 0:
                self.registers.pop(decoded.rs1, None)
                self.defined_by.pop(decoded.rs1, None)
            self.write(decoded.rd, None)
            self.analyzer.dependencies.append(DependencyRecord(
                kind="csr-effect", status="bounded", slot=self.slot.prefix,
                address=self.address,
                detail="a CSR access changes CPU state the composer does not model; the "
                       "read value is recorded as an unknown value"))
        elif kind == "fence":
            self.analyzer.dependencies.append(DependencyRecord(
                kind="unmodelled-instruction", status="bounded", slot=self.slot.prefix,
                address=self.address,
                detail="FENCE is legal but its ordering effect is not modelled; it does "
                       "not change a register or a byte"))
        elif kind == "unmodelled":
            self.analyzer.dependencies.append(DependencyRecord(
                kind="unmodelled-instruction", status="bounded", slot=self.slot.prefix,
                address=self.address,
                detail=f"{decoded.name} is legal but its effects are not modelled; every "
                       f"register it writes is unknown"))
            self.write(decoded.rd, None)
        elif kind == "leaves":
            self.analyzer.unknowns.append(UnknownRecord(
                kind="control-flow-leaves-program", slot=self.slot.prefix,
                address=self.address,
                bound="the slots after this one are not reached by the declared linear "
                      "flow and are analysed as unreachable",
                detail=f"{decoded.name} transfers control outside the candidate program"))
            return
        if not self.successors and kind not in ("jal", "jalr", "branch", "leaves"):
            self.successors.append(self.next_index())

    # -- control flow ------------------------------------------------------

    def next_index(self) -> int | None:
        current = self.program.slots.instruction.index(self.slot)
        follower = current + 1
        return follower if follower < len(self.program.slots.instruction) else None

    def target(self, kind: str, target: int, encode) -> int | None:
        """Check (and, in repair mode, project) one control-flow target."""
        if not self.analyzer.regions.executable(target):
            _error(f"candidate-target-outside-executable-region:0x{target:08x}")
        base, size = self.analyzer.base, self.analyzer.size
        if base <= target < base + size and (target - base) % WORD_BYTES == 0:
            return (target - base) // WORD_BYTES
        if self.program.policy.target_policy == "strict":
            _error(f"candidate-target-outside-declared-program:0x{target:08x}")
        projected = project_address(target, base, size)
        encoded = encode(projected)
        if encoded is None:
            _error(f"candidate-target-immediate-unencodable:{kind}:"
                   f"{projected - self.address}")
        self.analyzer.records.append(RepairRecord(
            kind="target", slot=self.slot.prefix, field=kind, before=target,
            after=projected,
            rule="target projected onto the declared program window (project_address) and "
                 "the instruction re-encoded"))
        self.analyzer.counter["target_repair"] += 1
        self.word = encoded
        return (projected - base) // WORD_BYTES

    def branch(self, target: int) -> list[int | None]:
        decoded = self.decoded
        rs1, rs2, funct3 = decoded.rs1, decoded.rs2, decoded.funct3
        successor = self.target(
            "branch", target,
            lambda value: _encode_branch(self.word, rs1, rs2, funct3,
                                         value - self.address))
        left = self.read(decoded.rs1)
        right = self.read(decoded.rs2)
        taken = None if left is None or right is None \
            else _branch_taken(decoded.name, left, right)
        if taken is False:
            return [self.next_index()]
        if taken is True:
            return [successor]
        self.analyzer.unknowns.append(UnknownRecord(
            kind="branch-direction", slot=self.slot.prefix, address=self.address,
            bound="either successor is possible; the values are merged at the join and "
                  "every value that differs becomes unknown",
            detail=f"{decoded.name} operands are not both derivable"))
        self.counter_unknown()
        return [self.next_index(), successor]

    # -- memory ------------------------------------------------------------

    def load(self, address: int) -> int | None:
        decoded = self.decoded
        window = self.analyzer.regions.lookup(address, decoded.size)
        if window is None:
            if not self.program.policy.allow_unmapped_access:
                _error(f"candidate-access-address-unmapped:0x{address:08x}")
            self.analyzer.unknowns.append(UnknownRecord(
                kind="unmapped-access", slot=self.slot.prefix, address=address,
                bound="the fabric answers with an error response; the response value is "
                      "unknown and is never used as an address",
                detail="the declared policy allows an unmapped access"))
            self.counter_unknown()
            self.mark_pending(address, decoded.size)
            return None
        if not window["read"]:
            _error(f"candidate-access-permission-denied:read:0x{address:08x}")
        if window["port"] != "mem":
            # MMIO: the declared read-after-write dependency is satisfied only by
            # an earlier MMIO write of exactly these bytes in this program.
            covered = all(address + offset in self.mmio_writes
                          for offset in range(decoded.size))
            if covered:
                known = all(self.mmio_writes.get(address + offset) is not None
                            for offset in range(decoded.size))
                value = _assemble(self.mmio_writes, address, decoded.size) if known else None
                self.analyzer.dependencies.append(DependencyRecord(
                    kind="mmio-write-before-read",
                    status="satisfied" if known else "bounded", slot=self.slot.prefix,
                    address=address, value=value,
                    detail="an earlier slot wrote exactly these MMIO bytes, so the declared "
                           "order repairs the read-after-write dependency by construction"
                           + ("" if known else "; the written value itself is unknown")))
                self.analyzer.counter["dependencies_satisfied"] += 1
                if not known:
                    self.counter_unknown()
                    self.mark_pending(address, decoded.size)
                return value
            if self.program.policy.mmio_read_requires_write:
                _error(f"dependency-mmio-read-before-write:0x{address:08x}")
        if all(self.store_bytes.get(address + offset) is not None
               for offset in range(decoded.size)):
            value = _assemble(self.store_bytes, address, decoded.size)
            self.analyzer.dependencies.append(DependencyRecord(
                kind="store-before-load", status="satisfied", slot=self.slot.prefix,
                address=address, value=value,
                detail="an earlier slot stored exactly these bytes; the declared order "
                       "repairs the dependency by construction"))
            self.analyzer.counter["dependencies_satisfied"] += 1
            return value
        if any(address + offset in self.store_bytes for offset in range(decoded.size)):
            self.analyzer.unknowns.append(UnknownRecord(
                kind="partial-store-coverage", slot=self.slot.prefix, address=address,
                bound="at least one byte is written on only one path; the merged value is "
                      "unknown and is never used as an address",
                detail="a store covers only part of the load"))
            self.counter_unknown()
            self.mark_pending(address, decoded.size)
            return None
        frozen = self.analyzer.regions.frozen(address, decoded.size)
        if frozen is not None:
            value, source = frozen
            self.analyzer.dependencies.append(DependencyRecord(
                kind="load-from-frozen-image", status="resolved", slot=self.slot.prefix,
                address=address, value=value,
                detail=f"the bytes are frozen before the CPU is released ({source})"))
            return value
        self.analyzer.unknowns.append(UnknownRecord(
            kind="mmio-read" if window["port"] != "mem" else "memory-read",
            slot=self.slot.prefix, address=address,
            bound="the value is DUT or unfrozen memory state; it may be stored and "
                  "compared but never used to derive an address",
            detail=f"{decoded.name} from {window['window_id']}"))
        self.counter_unknown()
        self.mark_pending(address, decoded.size)
        return None

    def store(self, address: int) -> None:
        decoded = self.decoded
        window = self.analyzer.regions.lookup(address, decoded.size)
        if window is None:
            if not self.program.policy.allow_unmapped_access:
                _error(f"candidate-access-address-unmapped:0x{address:08x}")
            self.analyzer.unknowns.append(UnknownRecord(
                kind="unmapped-access", slot=self.slot.prefix, address=address,
                bound="the fabric answers with an error response; no byte is written",
                detail="the declared policy allows an unmapped access"))
            self.counter_unknown()
            return
        if not window["write"]:
            _error(f"candidate-access-permission-denied:write:0x{address:08x}")
        for offset in range(decoded.size):
            if address + offset in self.pending_loads:
                _error(f"dependency-load-before-store:0x{address:08x}")
        value = self.read(decoded.rs2)
        if value is None:
            self.analyzer.unknowns.append(UnknownRecord(
                kind="store-value", slot=self.slot.prefix, address=address,
                bound="the stored value is not derivable; it is frozen as unknown and is "
                      "never used to derive an address",
                detail=f"{decoded.name} stores a register the composer cannot derive"))
            self.counter_unknown()
        for offset in range(decoded.size):
            byte = None if value is None else (value >> (8 * offset)) & 0xFF
            self.store_bytes[address + offset] = byte
            if window["port"] != "mem":
                self.mmio_writes[address + offset] = byte
        if window["port"] != "mem":
            self.analyzer.dependencies.append(DependencyRecord(
                kind="mmio-write", status="declared", slot=self.slot.prefix,
                address=address, value=value,
                detail=f"{decoded.name} writes {window['window_id']}"))

    def mark_pending(self, address: int, size: int) -> None:
        for offset in range(size):
            self.pending_loads[address + offset] = self.slot.prefix


# ---------------------------------------------------------------------------
# the repairer
# ---------------------------------------------------------------------------


class CandidateRepairer:
    """Repair one test's raw words into the declared candidate program.

    One repairer instance is the lifetime of one test: the first word that offers
    a slot commits that slot's repaired (address, word, byte enable), and a later
    change is refused.  :meth:`CandidateProgram.repairer` returns a fresh
    instance per test.
    """

    def __init__(self, program: CandidateProgram) -> None:
        if not isinstance(program, CandidateProgram):
            _error("candidate-repairer-requires-a-program")
        self.program = program
        self._committed = False
        self._committed_slots: dict[str, int] = {}
        self._frozen: dict[int, int] = {}
        self._frozen.update(_bytes_map(program.entry_bytes(), program.entry_address))
        self._frozen.update(_bytes_map(program.prologue_bytes(), program.prologue_address))

    # -- public ------------------------------------------------------------

    def repair_test(self, raw_values: Sequence[int], *,
                    directed: Mapping[str, int] | None = None,
                    seeds: Mapping[int, bytes] | None = None) -> RepairedTest:
        """Place, repair and check one test; returns the words the RTL applies.

        ``directed`` places an exact instruction word for a declared slot
        instead of the fuzzer's word (used for directed programs and for the
        real-RTL acceptance run).  ``seeds`` are bytes the caller has already
        committed to the image (a directed seed); a seed that would overwrite a
        byte the plan froze, or a declared slot, is refused.
        """
        if self._committed:
            _error("candidate-repairer-already-committed")
        if isinstance(raw_values, (str, bytes)) or not isinstance(raw_values, Sequence):
            _error("invalid-raw-sample-sequence")
        words = [int(item) for item in raw_values]
        if not words and not directed:
            _error("candidate-empty-test")
        directed = dict(directed or {})
        seeds = {int(address): bytes(payload) for address, payload in (seeds or {}).items()}
        for word in words:
            if word < 0 or word >> self.program.record_width:
                _error(f"candidate-raw-word-outside-layout:0x{word:x}")
        for prefix in directed:
            slot = self._slot(prefix)
            if slot.kind != "instruction":
                _error(f"candidate-directed-slot-not-an-instruction-slot:{prefix}")
        counter = {"address_repair": 0, "target_repair": 0, "register_repair": 0,
                   "isa_repair": 0, "slots_offered": 0, "slots_placed": 0,
                   "unknown_values": 0, "dependencies_satisfied": 0,
                   "dependencies_resolved": 0}
        records: list[RepairRecord] = []
        self._check_seeds(seeds)
        # -- 1. declared placement of every offered slot --------------------
        offers = self._offers(words)
        for prefix, index in sorted(offers.items(), key=lambda item: item[1]):
            slot = self._slot(prefix)
            counter["slots_offered"] += 1
            if prefix in directed:
                _error(f"candidate-slot-directed-and-offered:{prefix}")
            word = words[index]
            byte_enable = slot.segment("be").extract(word)
            if byte_enable != 0xF:
                _error(f"candidate-offer-not-full-word:{prefix}:0x{byte_enable:x}")
            given = slot.segment("address").extract(word)
            placed = self._place(slot, given, records, counter)
            words[index] = _set_field(words[index], slot.segment("address"), placed)
        for prefix in sorted(directed):
            counter["slots_offered"] += 1
        # -- 2. materialise once: the reference ISA repair ------------------
        # The image layer owns only its own segment: when the record is the wider
        # combined ABI (a peer request or synthetic stimulus follows the image
        # bits) the image is materialised from the image slice alone, and the bits
        # the program does not own are passed through untouched.
        static = self._static_images()
        probe = self.program.image.materialize_many(
            self._image_slice(words) or [0], directed={**static, **seeds} or None)
        corrected = self._corrected_words(probe, offers, directed, words, counter)
        # -- 3. analyse the declared program and repair its targets ---------
        # The first pass fixes the words (a projected target is re-encoded) and
        # records the repairs; it is deliberately discarded apart from those
        # records, because the image it analysed still holds the pre-repair
        # words.
        probe_counter: dict[str, int] = {name: 0 for name in counter}
        probe_analysis = _Analyzer(self.program, corrected, probe_counter, probe,
                                   directed=sorted(directed)).run()
        final = probe_analysis["words"]
        records.extend(probe_analysis["records"])
        for name in ("target_repair", "register_repair"):
            counter[name] = probe_counter.get(name, 0)
        # -- 4. commit: freeze the final words and rebuild the image --------
        final_words = list(words)
        code_directed: dict[int, bytes] = dict(static)
        code_directed.update(seeds)
        placements: list[dict[str, object]] = []
        for slot in self.program.slots.instruction:
            word = final.get(slot.prefix)
            if word is None:
                continue
            code_directed[slot.declared_address] = word.to_bytes(WORD_BYTES, "little")
            if slot.prefix in offers:
                index = offers[slot.prefix]
                final_words[index] = _set_field(final_words[index], slot.segment("data"),
                                                word)
                final_words[index] = _set_field(final_words[index], slot.segment("offer"), 1)
            placements.append({
                "slot": slot.prefix, "kind": "instruction",
                "declared_address": slot.declared_address,
                "address_hex": f"0x{slot.declared_address:08x}",
                "word": f"0x{word:08x}", "word_value": word,
                "source": "directed" if slot.prefix in directed else "fuzz",
            })
            self._committed_slots[slot.prefix] = word
            counter["slots_placed"] += 1
        for slot in self.program.slots.data:
            if slot.prefix not in offers:
                continue
            index = offers[slot.prefix]
            final_words[index] = _set_field(final_words[index], slot.segment("offer"), 1)
            value = slot.segment("value").extract(final_words[index])
            address = slot.segment("address").extract(final_words[index])
            placements.append({
                "slot": slot.prefix, "kind": "data",
                "declared_address": slot.declared_address,
                "address_hex": f"0x{address:08x}", "address_value": address,
                "word": f"0x{value:08x}", "word_value": value, "source": "fuzz",
            })
            self._committed_slots[slot.prefix] = value
            counter["slots_placed"] += 1
        validation = [self._without_instruction_offers(word) for word in final_words]
        result = self.program.image.materialize_many(
            self._image_slice(validation) or [0], directed=code_directed)
        # The dependency and unknown-value record is produced against the image
        # that is really frozen (the repaired words), so a load from a frozen
        # byte reports the value the memory model will hold.
        analysis = _Analyzer(self.program, final, counter, result,
                             directed=sorted(directed)).run()
        counters = dict(sorted(counter.items()))
        counters["instruction_slots_placed"] = sum(
            1 for item in placements if item["kind"] == "instruction")
        counters["data_slots_placed"] = sum(1 for item in placements
                                            if item["kind"] == "data")
        self._committed = True
        artifacts = {
            "static_image_hash": "sha256:" + hashlib.sha256(
                self.program.static_image()).hexdigest(),
            "entry_image_hash": "sha256:" + hashlib.sha256(
                self.program.entry_bytes()).hexdigest(),
            "prologue_image_hash": "sha256:" + hashlib.sha256(
                self.program.prologue_bytes()).hexdigest(),
            "program_window": {"base": self.program.program_base,
                               "base_hex": f"0x{self.program.program_base:08x}",
                               "size": self.program.program_size},
            "placed_words": placements,
        }
        return RepairedTest(request=tuple(final_words), image=result,
                            placements=tuple(placements), records=tuple(records),
                            dependencies=tuple(analysis["dependencies"]),
                            unknowns=tuple(analysis["unknowns"]),
                            counters=MappingProxyType(counters),
                            artifacts=MappingProxyType(artifacts))

    # -- placement ---------------------------------------------------------

    def _image_slice(self, words: Sequence[int]) -> list[int]:
        """The image segment's own bits of each record word.

        A record may be wider than the image (the combined ABI appends a peer's
        request fields, or a synthetic master's stimulus, after it).  Those bits
        belong to the environment, so the image layer is given the image slice and
        the caller's word is left otherwise untouched.
        """
        width = int(self.program.image.raw_width)
        mask = (1 << width) - 1
        return [int(word) & mask for word in words]

    def _slot(self, prefix: str) -> CandidateSlot:
        try:
            return self.program.slots.slot(prefix)
        except SocImageError as error:
            raise CandidateProgramError(str(error)) from error

    def _offers(self, words: Sequence[int]) -> dict[str, int]:
        offers: dict[str, int] = {}
        for index, word in enumerate(words):
            for slot in self.program.slots.slots():
                if not slot.segment("offer").extract(word):
                    continue
                if slot.prefix in offers:
                    _error(f"repair-would-rewrite-committed-word:{slot.prefix}"
                           f":0x{slot.declared_address:08x}")
                offers[slot.prefix] = index
        return offers

    def _static_images(self) -> dict[int, bytes]:
        """The bytes the *plan* freezes in the executable region.

        The entry trampoline and the generated prologue are not fuzz candidates:
        no test may change them, they are part of every test's image, and the
        campaign path must publish them as the fixed boot image a per-test
        overlay is applied on top of.
        """
        images = {
            self.program.entry_address: self.program.entry_bytes(),
            self.program.prologue_address: self.program.prologue_bytes(),
        }
        return {address: payload for address, payload in images.items() if payload}

    def _check_seeds(self, seeds: Mapping[int, bytes]) -> None:
        slots = {slot.declared_address: slot.prefix
                 for slot in self.program.slots.slots()}
        for address in sorted(seeds):
            payload = seeds[address]
            for offset in range(len(payload)):
                current = address + offset
                if current in self._frozen and self._frozen[current] != payload[offset]:
                    _error(f"repair-would-rewrite-committed-word:seed:0x{current:08x}")
            for slot_address, prefix in sorted(slots.items()):
                if address < slot_address + WORD_BYTES and slot_address < address + len(payload):
                    _error(f"candidate-seed-overlaps-slot:{prefix}:0x{slot_address:08x}")

    def _place(self, slot: CandidateSlot, given: int, records: list[RepairRecord],
               counter: dict[str, int]) -> int:
        declared = slot.declared_address
        if given == declared:
            return declared
        if self.program.policy.address_policy == "strict":
            _error(f"candidate-slot-address-misplaced:{slot.prefix}:0x{given:08x}"
                   f":expected-0x{declared:08x}")
        records.append(RepairRecord(
            kind="address", slot=slot.prefix, field="address", before=given,
            after=declared,
            rule="declared slot address (address policy: repair)"))
        counter["address_repair"] += 1
        return declared

    def _corrected_words(self, probe: ImageResult, offers: Mapping[str, int],
                         directed: Mapping[str, int], words: Sequence[int],
                         counter: dict[str, int]) -> dict[str, int]:
        """The word each slot really receives: the reference ISA repair, or directed."""
        placed = {str(item["slot"]): item for item in probe.slots}
        corrected: dict[str, int] = {}
        for slot in self.program.slots.instruction:
            if slot.prefix in directed:
                corrected[slot.prefix] = int(directed[slot.prefix]) & 0xFFFFFFFF
                continue
            if slot.prefix not in offers:
                continue
            record = placed.get(slot.prefix)
            if record is None or not record.get("accepted"):
                _error(f"candidate-slot-not-materialized:{slot.prefix}")
            address = int(record["address"])
            found = None
            for item in probe.initialization_records:
                candidate = item.get("raw_candidate") or {}
                if int(candidate.get("init_address", -1)) == address:
                    found = item
                    break
            if found is None:
                _error(f"candidate-slot-without-a-materialized-word:{slot.prefix}")
            corrected_word = int((found["corrected_candidate"] or {})["data"])
            given = slot.segment("data").extract(words[offers[slot.prefix]])
            if corrected_word != given:
                counter["isa_repair"] += 1
            corrected[slot.prefix] = corrected_word
        return corrected

    def _without_instruction_offers(self, word: int) -> int:
        for slot in self.program.slots.instruction:
            word = _set_field(word, slot.segment("offer"), 0)
        return word


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _bytes_map(payload: bytes, address: int) -> dict[int, int]:
    return {address + offset: byte for offset, byte in enumerate(payload)}


class _Field:
    """A raw bit range of an instruction word (used to repair one field)."""

    __slots__ = ("raw_lo", "width")

    def __init__(self, raw_lo: int, width: int) -> None:
        self.raw_lo = raw_lo
        self.width = width


def _set_field(word: int, segment, value: int) -> int:
    mask = ((1 << segment.width) - 1) << segment.raw_lo
    return (word & ~mask) | ((int(value) & ((1 << segment.width) - 1)) << segment.raw_lo)


def _encode_jal(word: int, rd: int, displacement: int) -> int | None:
    if not -JAL_DISPLACEMENT_BOUND <= displacement < JAL_DISPLACEMENT_BOUND:
        return None
    return _enc_j(displacement, rd, 0x6F)


def _encode_branch(word: int, rs1: int, rs2: int, funct3: int,
                   displacement: int) -> int | None:
    if not -BRANCH_DISPLACEMENT_BOUND <= displacement < BRANCH_DISPLACEMENT_BOUND:
        return None
    return _enc_b(displacement, rs2, rs1, funct3, 0x63)


def _encode_jalr(word: int, rd: int, rs1: int, displacement: int) -> int | None:
    if not -JALR_IMMEDIATE_BOUND <= displacement < JALR_IMMEDIATE_BOUND:
        return None
    return _enc_i(displacement, rs1, 0, rd, 0x67)


def _branch_taken(name: str, left: int, right: int) -> bool | None:
    left &= 0xFFFFFFFF
    right &= 0xFFFFFFFF
    if name == "BEQ":
        return left == right
    if name == "BNE":
        return left != right
    if name == "BLT":
        return _sign(left, 32) < _sign(right, 32)
    if name == "BGE":
        return _sign(left, 32) >= _sign(right, 32)
    if name == "BLTU":
        return left < right
    if name == "BGEU":
        return left >= right
    return None


def _assemble(store_bytes: Mapping[int, int], address: int, size: int) -> int:
    return sum(int(store_bytes[address + offset]) << (8 * offset)
               for offset in range(size))


def _compute_imm(decoded: DecodedInstruction, machine: _Machine) -> int | None:
    source = machine.read(decoded.rs1)
    if source is None:
        return None
    value = int(source) & 0xFFFFFFFF
    name, imm = decoded.name, decoded.imm
    if name == "ADDI":
        return (value + imm) & 0xFFFFFFFF
    if name == "SLTI":
        return 1 if _sign(value, 32) < imm else 0
    if name == "SLTIU":
        return 1 if value < (imm & 0xFFFFFFFF) else 0
    if name == "XORI":
        return value ^ (imm & 0xFFFFFFFF)
    if name == "ORI":
        return value | (imm & 0xFFFFFFFF)
    if name == "ANDI":
        return value & (imm & 0xFFFFFFFF)
    if name == "SLLI":
        return (value << (imm & 0x1F)) & 0xFFFFFFFF
    if name == "SRLI":
        return value >> (imm & 0x1F)
    if name == "SRAI":
        return (_sign(value, 32) >> (imm & 0x1F)) & 0xFFFFFFFF
    return None


def _compute_reg(decoded: DecodedInstruction, machine: _Machine) -> int | None:
    left = machine.read(decoded.rs1)
    if left is None:
        return None
    left = int(left) & 0xFFFFFFFF
    right = machine.read(decoded.rs2)
    if right is None:
        return None
    right = int(right) & 0xFFFFFFFF
    name = decoded.name
    if decoded.kind == "m":
        signed_left, signed_right = _sign(left, 32), _sign(right, 32)
        if name == "MUL":
            return (left * right) & 0xFFFFFFFF
        if name == "MULHU":
            return ((left * right) >> 32) & 0xFFFFFFFF
        if name == "MULHSU":
            return ((signed_left * right) >> 32) & 0xFFFFFFFF
        if name == "MULH":
            return ((signed_left * signed_right) >> 32) & 0xFFFFFFFF
        if name == "DIV":
            if signed_right == 0:
                return 0xFFFFFFFF
            result = abs(signed_left) // abs(signed_right)
            return (-result if (signed_left < 0) != (signed_right < 0) else result) \
                & 0xFFFFFFFF
        if name == "DIVU":
            return 0xFFFFFFFF if right == 0 else left // right
        if name == "REM":
            if signed_right == 0:
                return left
            result = abs(signed_left) % abs(signed_right)
            return (-result if signed_left < 0 else result) & 0xFFFFFFFF
        if name == "REMU":
            return left if right == 0 else left % right
        return None
    if name == "ADD":
        return (left + right) & 0xFFFFFFFF
    if name == "SUB":
        return (left - right) & 0xFFFFFFFF
    if name == "SLL":
        return (left << (right & 0x1F)) & 0xFFFFFFFF
    if name == "SRL":
        return left >> (right & 0x1F)
    if name == "SRA":
        return (_sign(left, 32) >> (right & 0x1F)) & 0xFFFFFFFF
    if name == "SLT":
        return 1 if _sign(left, 32) < _sign(right, 32) else 0
    if name == "SLTU":
        return 1 if left < right else 0
    if name == "XOR":
        return left ^ right
    if name == "OR":
        return left | right
    if name == "AND":
        return left & right
    return None


__all__ = [
    "BRANCH_DISPLACEMENT_BOUND",
    "CANDIDATE_ALIGNMENT",
    "CANDIDATE_PROGRAM_SCHEMA",
    "CANDIDATE_TEST_SCHEMA",
    "CandidateProgram",
    "CandidateProgramError",
    "CandidateProgramPolicy",
    "CandidateRepairer",
    "DATA_BASE_REGISTER",
    "DecodedInstruction",
    "DependencyRecord",
    "JAL_DISPLACEMENT_BOUND",
    "JALR_IMMEDIATE_BOUND",
    "MAX_PROGRAM_BYTES",
    "MMIO_BASE_REGISTER",
    "REGISTER_ABI_NAMES",
    "RepairRecord",
    "RepairedTest",
    "STACK_POINTER_REGISTER",
    "SUPPORTED_EXTENSIONS",
    "SUPPORTED_INSTRUCTION_WIDTHS",
    "SUPPORTED_XLEN",
    "UNDERSTOOD_EXTENSIONS",
    "UnknownRecord",
    "WORD_BYTES",
    "build_candidate_program",
    "decode_word",
    "encode_addi",
    "encode_beq",
    "encode_b_type",
    "encode_i_type",
    "encode_j_type",
    "encode_jal",
    "encode_jalr",
    "encode_lui",
    "encode_lw",
    "encode_s_type",
    "encode_sw",
    "encode_u_type",
    "project_address",
]
