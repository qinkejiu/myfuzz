"""Step 8: the boot / ISR program a composed SoC actually executes.

The program is generated from the plan, never from a component name:

* the entry, the ISA and the register width come from the CPU profile's
  ``reset_vector`` / ``xlen`` / ``extensions`` (``plan.request.cpu.profile``);
* every MMIO base address comes from the plan's own address map and target
  records, cross-checked against each other;
* the controller window and its register offsets come from
  ``plan.interrupt_document["controller"]``;
* the peripheral interrupt-enable operand, the cause/status operand and the
  clear operation come from the peripheral profile's declared register map
  (``profile.address.registers``: offset, access, side effect) together with the
  declared ``hold`` / ``clear`` conditions of the interrupt source;
* which source is claimed, and which peripheral that source belongs to, comes
  from ``plan.interrupt_document["sources"]``.

The image is a region-anchored ``$readmemh`` byte image: byte 0 is the first
byte of the executable region that contains the declared reset vector, exactly
as ``riscv_boot_memory_32/64`` loads it (``+riscv_boot_image``).  Two reset
conventions exist in the pinned CPUs and neither is selected by name: one
fetches at the declared vector, the other at ``{vector[31:8], 8'h80}`` (the
Ibex ``PC_BOOT`` formula documented at ``ibex_if_stage.sv:243``).  A jump at the
declared vector and the body at ``vector + 0x80`` therefore enter the same
program on both, which is the same trampoline contract the matrix boot program
already uses (``soc_matrix_smoke._build_program``, lines 1272-1280).

Declared-fact limits this module refuses to guess around
--------------------------------------------------------

* The peripheral profiles declare *what* holds an interrupt (``hold``) and *how*
  it is cleared (``clear``), but not how the condition is *raised*.  This
  generator therefore reads the raise path from the declared data it does have:
  the interrupt is triggered through the component's declared **external input
  pins** (``external_pins`` endpoint, input fields), driven by the runtime's
  external event plan.  A source whose component declares no such pin and no
  declared cause register is a capability gap and is rejected
  (``trigger-cause-undeclared``), never guessed.
* The enable operand is the one register reference in the declared ``hold``
  condition that the profile declares read-write; the status/cause operand is
  the first remaining declared-readable reference.  Zero or several candidates
  is a gap, not a coin flip.
* The clear operation is the first declared ``write_1_to_clear`` register
  reference in the declared ``clear`` text, else the first declared
  ``read_clears`` reference, clause by clause.  An unresolvable clear text is a
  gap.
* The controller's ``ENABLE`` word is written once with the source's id bit, as
  the controller contract requires (no claim splitting, no automatic
  read-modify-write of enable/complete).  The *peripheral* interrupt-enable bit
  is set with a read-modify-write so that no undeclared register bit changes.

Declared-register software phase
--------------------------------

``ProgramRequest.verify_peripherals`` (on by default) adds a phase that is aimed
entirely by each bound profile's own register table: a declared initialisation
write per declared reset value, a read of every declared readable register (with
the CPU's own exception count as the "did it trap" evidence), an offset-derived
write and read-back for every declared plain read/write register, the declared
clear access and its declared probe for every ``read_clears`` /
``write_1_to_clear`` register that names one, and a re-read of each declared
status register.  Every step writes its result into the report record, whose new
fields are appended so no existing offset moves.

It only ever acts on declared facts, so the remaining cases are refusals and
coverage notes rather than guesses: a peripheral with no declared register table
contributes a note in ``program.document["software"]["skipped"]`` and no
accessor; a clearing side effect with no declared probe register is a note, not a
fabricated check; a read-clears declaration on a write-only register, an
``clears_register`` naming nothing, or a register offset outside the immediate
range are errors (``read-clears-on-a-write-only-register``,
``unknown-clears-register:...``, ``register-offset-out-of-imm12-range:...``).

The faulting half of the same idea - a store into the plan's read-only region,
and a write to every declared read-only / read of every declared write-only
register - is ``ProgramRequest.probe_permissions`` (off by default, like
``expect_error_access``), because those probes deliberately take access faults
and need the generated trap handler.

Handler context
---------------

The handler is asynchronous, so it saves every register it uses (x5-x7 and
x28-x31) on the stack the program sets up and restores them before ``mret``;
only the stack pointer and the report-base register are shared with the main
flow.  Without that, returning from an interrupt would corrupt the interrupted
loop, which is exactly what an interrupt-lifecycle run detects.

Instruction order inside the generated program
----------------------------------------------

``mtvec`` is installed **before the first bus access**, while ``mie.MEIE`` and
``mstatus.MIE`` are set after the source setup.  The pinned cores reset
``mtvec`` to their boot address, so a fault taken before software installs
``mtvec`` sends the CPU back to the reset vector and silently restarts the
program; installing it first turns such a fault into a recorded exception
(``mcause`` in the report record) that a run can diagnose.  Everything else -
stack, peripheral enables, controller ``ENABLE``, global enable, bounded wait,
handler - follows the order the step-8 requirements list.

The module never names a CPU or a peripheral: the entry, the ISA, every base
address, every register offset and every source id come from the plan objects.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.integration.soc_matrix_smoke import (
    ENTRY_OFFSET,
    FLAG_OK,
    _Assembler,
    _enc_b,
    _enc_i,
    _enc_j,
    _enc_s,
    _enc_u,
)

from .soc_composition import CompositionPlan

PROGRAM_SCHEMA = "soc_boot_program.v1"
#: Schema of the ``program.document["software"]`` section: the declared-register
#: phase the generated program performs.
SOFTWARE_SCHEMA = "soc_boot_program_software.v1"

#: The completion magic the program writes into RAM.  It is the same constant
#: the matrix boot program records (``soc_matrix_smoke.FLAG_OK``), so one
#: testbench convention reads both.
COMPLETION_FLAG = FLAG_OK

#: Byte offsets inside the writable RAM region.  Both the flag and the whole
#: report block live in the first 256 bytes because the profile runtime reads
#: back exactly ``MAX_OBSERVED_WORDS * 8 == 256`` bytes through the memory
#: model's hierarchical array (``soc_runtime.render_profile_testbench``).
FLAG_OFFSET = 0x00
REPORT_OFFSET = 0x10
RAM_READBACK_BYTES = 0x100

#: Report block layout: name -> byte offset from ``report_address``.
REPORT_FIELDS: tuple[tuple[str, int], ...] = (
    ("claim_id", 0x00),
    ("handler_entries", 0x04),
    ("complete_accepted", 0x08),
    ("final_in_service", 0x0C),
    ("source_count", 0x10),
    ("pending_before_claim", 0x14),
    ("cause_before_clear", 0x18),
    ("cause_after_clear", 0x1C),
    ("status_raw_before_clear", 0x20),
    ("status_raw_after_clear", 0x24),
    # One slot per controller bitmap word, sampled before the claim: the
    # controller numbers bitmap bit k as source id 32*j+k (bit 0 is the reserved
    # id 0), so a source's enable/pending bit is bit (id % 32) of word (id // 32).
    ("pending_word_0_before_claim", 0x28),
    ("pending_word_1_before_claim", 0x2C),
    ("pending_word_after_complete", 0x30),
    ("prologue_cycle", 0x34),
    ("status_latched_by_poll", 0x38),
    ("pending_seen_by_main", 0x3C),
    ("error_access_requested", 0x40),
    ("error_cause", 0x44),
    ("unknown_claim", 0x48),
    ("loop_closed", 0x4C),
    ("main_completed", 0x50),
    # ---- the declared-register software phase -----------------------------
    # Appended after every field above so an existing offset never moves.  The
    # whole report block still fits the runtime's 256-byte readback window
    # (``REPORT_OFFSET + REPORT_BYTES <= RAM_READBACK_BYTES``), which the unit
    # tests and the generated run both assert.
    ("exception_count", 0x54),
    ("software_phase", 0x58),
    ("software_registers", 0x5C),
    ("software_skipped", 0x60),
    ("software_init_writes", 0x64),
    ("software_reads", 0x68),
    ("software_read_traps", 0x6C),
    ("software_traps", 0x70),
    ("software_writeback_checks", 0x74),
    ("software_writeback_matches", 0x78),
    ("software_writeback_mask", 0x7C),
    ("software_writeback_last_expected", 0x80),
    ("software_writeback_last_observed", 0x84),
    ("software_side_effects", 0x88),
    ("software_side_effects_confirmed", 0x8C),
    ("software_side_effect_mask", 0x90),
    ("software_side_effect_last_before", 0x94),
    ("software_side_effect_last_after", 0x98),
    ("software_status_checks", 0x9C),
    ("status_0", 0xA0),
    ("status_1", 0xA4),
    ("status_2", 0xA8),
    ("status_3", 0xAC),
    ("status_overflow", 0xB0),
    ("permission_probes", 0xB4),
    ("permission_errors", 0xB8),
    ("permission_error_mask", 0xBC),
    ("permission_last_mcause", 0xC0),
    ("permission_last_offset", 0xC4),
    ("rom_write_requested", 0xC8),
    ("rom_write_cause", 0xCC),
    ("rom_value_before", 0xD0),
    ("rom_value_after", 0xD4),
    ("rom_unchanged", 0xD8),
    ("unmapped_store_cause", 0xDC),
    # Registers/probes beyond the width of the per-check result masks are still
    # exercised; these count the ones the masks cannot name individually.
    ("software_unchecked", 0xE0),
    ("permission_unchecked", 0xE4),
    # The default lifecycle reports one source.  The opt-in multi-source
    # request keeps the first claim in ``claim_id`` for compatibility and
    # appends an aggregate ledger so repeated claim/complete service can be
    # audited without moving any pre-existing field.
    ("interrupt_completions", 0xE8),
    ("all_sources_closed", 0xEC),
)
#: Registers the shared handler saves on the stack and restores before mret.
#: x2 (stack pointer) and x8 (report base) are never modified by the handler.
HANDLER_SAVED_REGISTERS = (5, 6, 7, 28, 29, 30, 31)

#: One diagnostic report slot per controller bitmap word (ids 1..40 are verified).
PENDING_WORD_SLOTS = tuple(name for name, _ in REPORT_FIELDS
                           if name.startswith("pending_word_") and "before_claim" in name)
REPORT_BYTES = max(offset for _, offset in REPORT_FIELDS) + 4

#: Report slots for the declared status register of the first peripherals, and
#: the width of the per-check result masks (one bit per register, probe or
#: side-effect access, in the order the generated program performs them).
SOFTWARE_STATUS_SLOTS = 4
SOFTWARE_MASK_BITS = 32

#: Is the program bounded?  The ROM region bound is checked as well; this is the
#: generator's own ceiling so an oversized composition fails early.
MAX_PROGRAM_BYTES = 0x4000

#: The trap vector table: a 256-byte-aligned block of one-word jumps to the
#: shared handler.  64 entries cover every cause index a pinned core can encode
#: in the low byte of mtvec, so the same program works whether the core jumps to
#: the base (direct mode), to base + 4*cause (the pinned Ibex), or to a
#: capability trap vector.
VECTOR_ALIGNMENT = 0x100
VECTOR_ENTRIES = VECTOR_ALIGNMENT // 4

#: Bounded poll: the main flow waits for the peripheral's declared cause bit
#: before it records the completion flag.  The loop is bounded so an event that
#: never arrives is a recorded timeout, never an unbounded wait.
POLL_ITERATIONS = 4096

#: External trigger schedule, in post-reset cycles.  The default lifecycle's
#: first trigger source has its declared external input pins driven low first
#: and all-ones afterwards: a level-active request line latches on the first
#: transition, a change-latched input latches on the last one, and neither
#: re-latches while the level is held.  ``exercise_all_sources`` joins the
#: corresponding plans; ``stagger_sources`` shifts each source pair by the
#: bounded spacing below.  All events are recorded in the program document so
#: the runtime applies exactly them.
TRIGGER_LOW_CYCLE = 2048
TRIGGER_HIGH_CYCLE = 3072
# A peer event is a protocol payload rather than a pin level.  The value is
# deliberately a fixed, non-zero byte/pin pattern: the event plan records it,
# and the peripheral's own status/IRQ condition remains the oracle for whether
# the component accepted the protocol transaction.
PEER_TRIGGER_PAYLOAD = 0x5A
# A peer must latch its payload before software starts a component-owned
# transaction.  Both schedules use post-reset clock cycles; the extra cycles
# cover the peer's registered arm state and the CPU's next MMIO instruction.
PEER_ARM_SETTLE_CYCLES = 16
# When the caller asks for a staggered multi-source run, each source's
# low/high pair is shifted by this bounded amount.  The shift keeps the first
# source within the existing poll window and remains below MAX_CYCLES for the
# controller's verified 40-source capacity.
TRIGGER_SOURCE_SPACING = 1024

MSTATUS = 0x300
MIE = 0x304
MTVEC = 0x305
MCAUSE = 0x342
MEPC = 0x341
MCYCLE = 0xB00
MSTATUS_MIE = 1 << 3
MIE_MEIE = 1 << 11

_REFERENCE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WRITE_ONE = re.compile(r"write\s*[-_ ]?\s*1\b", re.IGNORECASE)


class BootProgramError(ValueError):
    """The declared composition cannot be booted as required."""


def _error(reason: str) -> None:
    raise BootProgramError(reason)


@dataclass(frozen=True, slots=True)
class ProgramRequest:
    """What the caller wants the generated program to do."""

    #: Enable interrupt delivery to the CPU: write the controller's ENABLE bits
    #: and set ``mie.MEIE`` + ``mstatus.MIE``.  The peripheral's own
    #: interrupt-enable bit belongs to peripheral initialisation and is written
    #: whenever an interrupt program is generated.  With ``False`` the
    #: controller's ENABLE stays at its reset value 0 and the CPU stays masked
    #: while everything else (handler, mtvec, peripheral setup, trigger) is
    #: unchanged: the source is sampled and pends, but it can neither notify nor
    #: be claimed.  That is the state the interrupt-lifecycle test uses to show
    #: the claim comes from the real notification path.
    enable_interrupts: bool = True
    #: Apply the recorded trigger (the external event plan).  With ``False`` the
    #: program performs no trigger MMIO write and the document states that the
    #: environment must not drive the recorded events either.
    trigger_event: bool = True
    #: Additionally access one unmapped address and record that the fabric
    #: answered with an error.
    expect_error_access: bool = False
    #: Emit the declared-register software phase.  Every step of it is derived
    #: from the bound profiles' own register declarations (offset, width,
    #: access, side effect, and the optional declared reset value, writable-bit
    #: mask and clearing probe) - never from a component name:
    #:
    #: * ``init``: write the declared reset value of every writable register
    #:   that declares one;
    #: * ``read``: read every declared readable register and record that the CPU
    #:   took no trap doing it;
    #: * ``write + read-back``: for every declared read/write register with side
    #:   effect ``none``, write a pattern derived from the register offset,
    #:   read it back and record the comparison;
    #: * ``clear / side effect``: for every register declared ``read_clears`` or
    #:   ``write_1_to_clear`` that also declares the register whose value proves
    #:   the clear, perform the declared access and re-read the probe;
    #: * ``status``: re-read each peripheral's declared status register.
    #:
    #: The phase runs after the main flow's wait, so its accesses cannot perturb
    #: the interrupt-source state the loop depends on.
    verify_peripherals: bool = True
    #: Additionally probe the *declared permissions* and record what the target
    #: answered, like ``expect_error_access`` does for the address map:
    #:
    #: * a store into the plan's executable, non-writable region (the plan says
    #:   the fabric must answer with an error and the image must survive);
    #: * a write to every declared read-only register and a read of every
    #:   declared write-only register, with the exception cause the CPU observed
    #:   recorded per probe.
    #:
    #: These probes are deliberate access faults, so they are opt-in: they need
    #: the generated trap handler, and they leave the CPU's own exception state
    #: (mcause/mepc/mtval) holding the last probe.  Off by default, exactly like
    #: ``expect_error_access``.
    probe_permissions: bool = False
    #: Exercise every declared, externally triggerable source in one run.  The
    #: default remains the historical first-source lifecycle so existing runs
    #: retain their exact report semantics.  With this opt-in mode the
    #: controller ENABLE bitmap contains all source bits, the trigger plan
    #: drives the union of all declared external pins, and the shared handler
    #: services each claimed id until the aggregate ledger closes.  Appended at
    #: the end of the dataclass to preserve callers that used older positional
    #: request arguments.
    exercise_all_sources: bool = False
    #: Stagger the per-source external trigger pairs in multi-source mode.  A
    #: false value deliberately drives all selected sources in the same cycle;
    #: a true value exercises the controller with distinct arrival windows.
    stagger_sources: bool = False


@dataclass(frozen=True, slots=True)
class BootProgram:
    """One generated boot/ISR program."""

    entry_address: int
    image: bytes
    flag_address: int
    report_address: int
    observations: Mapping[str, int]
    steps: tuple[str, ...]
    document: Mapping[str, object]


# ---------------------------------------------------------------------------
# plan facts
# ---------------------------------------------------------------------------


def _cpu(plan: CompositionPlan):
    instance = next((item for item in plan.instances if item.kind == "cpu"), None)
    if instance is None:
        _error("boot-program-requires-a-cpu-instance")
    contract = instance.profile.cpu
    if contract is None:
        _error("boot-program-requires-a-cpu-contract")
    return instance, contract


def _check_isa(contract) -> dict:
    """Check the declared ISA, and refuse only what cannot run this code.

    The generated image is deliberately uncompressed: every instruction is a
    32-bit encoding, which is legal on a core that also implements the C
    extension, and it is what makes the exception handler's ``mepc + 4`` skip
    exactly one instruction.  RV32E is refused because the program uses
    registers above x15 (the trap handler's scratch registers).

    The trap-vector shape (direct, vectored or capability table) is *not* read
    from here: the profile declares no such field, so the generated program
    installs a table every convention lands in (see ``_emit``).
    """
    if contract.family != "riscv":
        _error(f"unsupported-isa-family:{contract.family}")
    if int(contract.xlen) not in (32, 64):
        _error(f"unsupported-xlen:{contract.xlen}")
    extensions = {str(item).lower() for item in contract.extensions}
    if "i" not in extensions:
        _error(f"isa-without-base-integer:{sorted(extensions)}")
    if "e" in extensions:
        _error("isa-embedded-register-file-unsupported:x16-x31-are-used")
    return {"extensions": sorted(extensions), "compressed_supported": "c" in extensions}


def _memory_regions(plan: CompositionPlan) -> list[dict]:
    regions = plan.plan["address_map"]["memory_regions"]
    return [dict(item) for item in regions]


def _executable_region(plan: CompositionPlan, entry: int) -> dict:
    for region in _memory_regions(plan):
        permissions = region.get("permissions") or {}
        base = int(region["base"])
        if permissions.get("execute") and base <= entry < base + int(region["size"]):
            return region
    _error(f"entry-address-outside-executable-region:0x{entry:x}")


def _writable_region(plan: CompositionPlan) -> dict:
    candidates = [region for region in _memory_regions(plan)
                  if (region.get("permissions") or {}).get("write")]
    if not candidates:
        _error("no-writable-region-for-the-report-record")
    region = min(candidates, key=lambda item: (int(item["base"]), str(item["region_id"])))
    if int(region["size"]) < RAM_READBACK_BYTES:
        _error(f"writable-region-too-small-for-readback:{region['region_id']}:"
               f"0x{int(region['size']):x}<0x{RAM_READBACK_BYTES:x}")
    return region


def _windows(plan: CompositionPlan) -> dict[str, tuple[int, int]]:
    """``target_id`` -> (base, size) from the plan's own address map."""
    windows: dict[str, tuple[int, int]] = {}
    for window in plan.plan["address_map"]["windows"]:
        windows[str(window["target_id"])] = (int(window["base"]), int(window["size"]))
    return windows


def _peripheral_window(plan: CompositionPlan, instance_id: str) -> tuple[str, int, int]:
    """The MMIO window of one instance, from target records cross-checked with
    the address map.  Never from the component name."""
    windows = _windows(plan)
    for record in plan.target_records:
        if record.get("instance_id") != instance_id:
            continue
        window = record.get("window")
        base = int(window["base"]) if isinstance(window, Mapping) else None
        size = int(window["size"]) if isinstance(window, Mapping) else None
        adapter = record.get("resolved_adapter")
        if isinstance(adapter, Mapping) and isinstance(adapter.get("window"), Mapping):
            adapter_base = int(adapter["window"]["base"])
            adapter_size = int(adapter["window"]["size"])
            if (base, size) != (adapter_base, adapter_size):
                _error(f"peripheral-window-disagrees-with-adapter:{instance_id}")
        target_id = str(record["target_id"])
        if target_id not in windows:
            _error(f"peripheral-window-missing-from-address-map:{instance_id}:{target_id}")
        if windows[target_id] != (base, size):
            _error(f"peripheral-window-disagrees-with-address-map:{instance_id}:{target_id}")
        return target_id, base, size
    _error(f"no-mmio-window-for-interrupt-source-instance:{instance_id}")


def _controller(plan: CompositionPlan) -> dict | None:
    document = plan.interrupt_document.get("controller")
    if not isinstance(document, Mapping) or not document.get("present"):
        return None
    window = document.get("window")
    if not isinstance(window, Mapping):
        _error("controller-window-undeclared")
    base = int(window["base"])
    size = int(window["size"])
    offsets: dict[str, int] = {}
    for register in document.get("register_map", ()):
        if not isinstance(register, Mapping):
            continue
        offsets[str(register["name"])] = int(register["offset"])
    for name in ("CLAIM", "COMPLETE", "IN_SERVICE", "SOURCE_COUNT", "PENDING0", "ENABLE0"):
        if name not in offsets:
            _error(f"controller-register-missing:{name}")
    mapped = _windows(plan).get(f"{document['instance_id']}_win")
    if mapped is not None and mapped != (base, size):
        _error("controller-window-disagrees-with-address-map")
    return {
        "instance_id": str(document["instance_id"]),
        "base": base,
        "size": size,
        "offsets": offsets,
        "num_sources": int(document["num_sources"]),
        "bitmap_words": int(document["bitmap_words"]),
    }


def _registers(profile) -> dict[str, object]:
    if profile.address is None:
        _error(f"peripheral-without-a-declared-address-map:{profile.component_id}")
    return {item.name: item for item in profile.address.registers}


def _mentions(text: str, registers: Mapping[str, object]) -> list[tuple[str, int | None]]:
    """Declared register names mentioned in a declared condition, in order."""
    tokens = _TOKEN.findall(text)
    for case_sensitive in (True, False):
        found: list[tuple[str, int | None]] = []
        bits = {name: int(bit) for name, bit in _REFERENCE.findall(text)}
        for token in tokens:
            for name in registers:
                if (token == name) if case_sensitive else (token.lower() == name.lower()):
                    if (name, bits.get(name)) not in found:
                        found.append((name, bits.get(name)))
                    break
        if found:
            return found
    return []


def _condition_operands(profile, source_document: Mapping[str, object],
                        clear: Mapping[str, object]) -> dict:
    """The declared enable and cause/status operands of one interrupt source.

    The declared ``hold`` condition names both operands, for example
    ``IRQ_STATUS[0] is set and IRQ_EN[0] is set`` or ``IRQ_STATUS[0] is set and
    CTRL[1] enables the interrupt``.  Which one *enables* is a declared fact, not
    a name: the enable operand is the read-write reference with no declared side
    effect, and the cause/status operand is a remaining readable reference
    (preferring one with a declared clear-type side effect).  Zero or several
    candidates on either side is a gap, never a guess.
    """
    registers = _registers(profile)
    hold = str(source_document.get("hold", ""))
    if not hold:
        _error(f"interrupt-hold-condition-undeclared:{source_document.get('instance_id')}")
    references = [(name, int(bit)) for name, bit in _REFERENCE.findall(hold)]
    ordered: list[tuple[str, int]] = []
    for name, bit in references:
        if name not in registers:
            _error(f"hold-names-an-undeclared-register:{name}")
        if (name, bit) not in ordered:
            ordered.append((name, bit))

    def access(name: str) -> str:
        return str(getattr(registers[name], "access", ""))

    def side_effect(name: str) -> str:
        return str(getattr(registers[name], "side_effect", "none"))

    plain = [(name, bit) for name, bit in ordered
             if access(name) == "rw" and side_effect(name) == "none"]
    if len(plain) == 1:
        enable_name, enable_bit = plain[0]
    else:
        writable = [(name, bit) for name, bit in ordered if access(name) == "rw"]
        if len(writable) != 1:
            _error(f"interrupt-enable-operand-ambiguous:"
                   f"{source_document.get('instance_id')}:"
                   f"{','.join(name for name, _ in writable) or 'none'}")
        enable_name, enable_bit = writable[0]
    remaining = [(name, bit) for name, bit in ordered if name != enable_name
                 and access(name) in ("ro", "rw")]
    clearing = [(name, bit) for name, bit in remaining
                if side_effect(name) in ("read_clears", "write_1_to_clear")
                or name == clear.get("register")]
    status = clearing or remaining
    if not status:
        _error(f"interrupt-status-operand-undeclared:{source_document.get('instance_id')}")
    status_name, status_bit = status[0]
    for name, bit in ((enable_name, enable_bit), (status_name, status_bit)):
        register = registers[name]
        if bit >= int(getattr(register, "width", 32)):
            _error(f"declared-bit-outside-register:{name}[{bit}]")
        if int(getattr(register, "offset", 0)) < 0 or int(register.offset) > 0x7FF:
            _error(f"register-offset-out-of-imm12-range:{name}:{register.offset}")
    if str(getattr(registers[enable_name], "side_effect", "none")) != "none":
        _error(f"interrupt-enable-register-has-a-side-effect:{enable_name}:"
               f"{getattr(registers[enable_name], 'side_effect', 'none')}")
    return {
        "enable_register": enable_name,
        "enable_offset": int(registers[enable_name].offset),
        "enable_bit": enable_bit,
        "status_register": status_name,
        "status_offset": int(registers[status_name].offset),
        "cause_bit": status_bit,
        "register_map": sorted(registers),
    }


def _clear_operation(profile, source_document: Mapping[str, object]) -> dict:
    """The declared clear operation of one interrupt source."""
    registers = _registers(profile)
    text = str(source_document.get("clear", ""))
    if not text:
        _error(f"interrupt-clear-condition-undeclared:{source_document.get('instance_id')}")
    for clause in re.split(r"[;.]", text):
        if not clause.strip():
            continue
        mentioned = _mentions(clause, registers)
        if _WRITE_ONE.search(clause):
            for name, bit in mentioned:
                register = registers[name]
                if str(getattr(register, "side_effect", "")) == "write_1_to_clear":
                    if bit is None:
                        bit = _clear_default_bit(registers, name, source_document)
                    return {"kind": "write_1_to_clear", "register": name,
                            "offset": int(register.offset), "bit": int(bit)}
        for name, bit in mentioned:
            register = registers[name]
            if str(getattr(register, "side_effect", "")) == "read_clears":
                return {"kind": "read_clears", "register": name,
                        "offset": int(register.offset), "bit": bit}
    _error(f"interrupt-clear-operation-undeclared:{source_document.get('instance_id')}")


def _clear_default_bit(registers: Mapping[str, object], name: str,
                       source_document: Mapping[str, object]) -> int:
    hold = _REFERENCE.findall(str(source_document.get("hold", "")))
    for register_name, bit in hold:
        if register_name == name:
            return int(bit)
    return 0


def _event_slots(plan: CompositionPlan) -> dict[tuple[str, str], dict]:
    """The external input pins the profile runtime exposes as event slots.

    This mirrors ``soc_runtime._external_inputs`` exactly (external disposition,
    input direction, same generated name, sorted by name so the tuple index is
    the slot number the runtime applies); a unit test cross-checks the two.
    """
    records: list[dict] = []
    for instance in plan.instances:
        for entry in instance.dispositions:
            if entry.disposition != "external" or entry.direction != "input":
                continue
            span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
                f"_{entry.bit_hi}_{entry.bit_lo}"
            records.append({
                "name": f"{entry.instance_id}__{entry.port}{span}",
                "instance_id": entry.instance_id,
                "port": entry.port,
                "width": entry.bit_hi - entry.bit_lo + 1,
            })
    records.sort(key=lambda item: str(item["name"]))
    for index, item in enumerate(records):
        item["slot"] = index
    return {(str(item["instance_id"]), str(item["port"])): item for item in records}


def _external_input_pins(instance) -> list[dict]:
    """The component's declared external *input* pins, as elaborated ports."""
    pins: list[dict] = []
    for endpoint in instance.binding.endpoints:
        if endpoint.function != "external_pins":
            continue
        for field in endpoint.fields:
            if field.direction not in (None, "input"):
                continue
            pins.append({"endpoint_id": endpoint.endpoint_id, "role": field.role,
                         "port": field.port})
    return pins


def _peer_event_slots(plan: CompositionPlan) -> dict[tuple[str, str], dict]:
    """Return peer stimulus slots in the same order as ``soc_runtime``.

    The runtime addresses peer slots by a numeric index.  The boot generator
    therefore derives the table from the plan, sorts it by instance/slot and
    records the resulting index instead of guessing a top-level signal name.
    """
    records: list[dict] = []
    for peer in plan.peers:
        for slot in peer.slots:
            records.append({
                "instance_id": peer.instance_id,
                "peer_id": peer.peer_id,
                "slot": slot.slot,
                "width": slot.width,
                "signals": tuple(signal.top_port for signal in slot.signals),
            })
    records.sort(key=lambda item: (str(item["instance_id"]), str(item["slot"])))
    return {(str(item["instance_id"]), str(item["slot"])): dict(item, index=index)
            for index, item in enumerate(records)}


def _peer_trigger_for(plan: CompositionPlan, instance, source_id: int,
                      raise_actions: Sequence[Mapping[str, object]]) -> dict | None:
    """Build a trigger for an attached UART/SPI/GPIO peer when one exists.

    Attaching a peer removes the component's protocol input pin from the raw
    external boundary.  A trigger for that source must consequently use the
    peer's declared payload slot.  The three generic peer contracts expose one
    schedulable slot each; a missing slot is a capability gap rather than a
    fallback to an unconnected random bit.
    """
    peer = plan.peer(instance.instance_id)
    if peer is None:
        return None
    slots = _peer_event_slots(plan)
    preferred = {
        "uart": "uart.tx_byte",
        "spi": "spi.arm_byte",
        "gpio": "gpio.drive",
    }.get(str(peer.peer_id))
    if preferred is None:
        return None
    slot = slots.get((instance.instance_id, preferred))
    if slot is None:
        return None
    width = int(slot["width"])
    if peer.peer_id == "gpio":
        pins = max(1, width // 2)
        all_pins = (1 << pins) - 1
        payloads = (all_pins << pins, (all_pins << pins) | all_pins)
        cycles = (TRIGGER_LOW_CYCLE, TRIGGER_HIGH_CYCLE)
    else:
        payloads = (PEER_TRIGGER_PAYLOAD & ((1 << width) - 1),)
        cycles = (TRIGGER_LOW_CYCLE,)
    events = [{
        "slot": int(slot["index"]),
        "name": f"{instance.instance_id}:{preferred}",
        "instance_id": instance.instance_id,
        "peer_id": peer.peer_id,
        "slot_name": preferred,
        "width": width,
        "cycle": int(cycle),
        "payload": int(payload),
    } for cycle, payload in zip(cycles, payloads)]
    mmio_writes = [{**dict(action), "instance_id": instance.instance_id,
                    "source_id": source_id,
                    "after_cycle": max(cycles) + PEER_ARM_SETTLE_CYCLES}
                   for action in raise_actions]
    return {
        "kind": "peer_event_plan",
        "source_id": source_id,
        "instance_id": instance.instance_id,
        "peer_id": peer.peer_id,
        "pins": list(slot["signals"]),
        "events": [],
        "peer_events": events,
        "mmio_writes": mmio_writes,
        "basis": ("the interface is owned by the declared " + str(peer.peer_id) +
                  " peer, so the source is raised with its payload-carrying "
                  f"{preferred} slot; the peripheral status, controller pending, "
                  "claim and COMPLETE evidence decide whether the protocol event "
                  "was accepted"),
    }


def _trigger_for(plan: CompositionPlan, instance, source_id: int,
                 raise_actions: Sequence[Mapping[str, object]] = ()) -> dict | None:
    """The trigger the plan can actually apply for one source.

    A source may be raised by declared external input pin(s), by profile-owned
    MMIO writes, or by both.  Neither action is inferred from a component name.
    A source with neither kind of declared action is a capability gap.
    """
    peer_trigger = _peer_trigger_for(plan, instance, source_id, raise_actions)
    if peer_trigger is not None:
        return peer_trigger
    pins = _external_input_pins(instance)
    slots = _event_slots(plan)
    matched = [(pin, slots[(instance.instance_id, pin["port"])]) for pin in pins
               if (instance.instance_id, pin["port"]) in slots]
    if not matched and not raise_actions:
        return None
    matched.sort(key=lambda item: str(item[1]["name"]))
    events: list[dict] = []
    slot_names: list[str] = []
    for pin, slot in matched:
        width = int(slot["width"])
        full = (1 << width) - 1
        slot_names.append(str(slot["name"]))
        events.append({"slot": int(slot["slot"]), "name": str(slot["name"]),
                       "port": str(slot["port"]), "width": width,
                       "cycle": TRIGGER_LOW_CYCLE, "value": 0})
        events.append({"slot": int(slot["slot"]), "name": str(slot["name"]),
                       "port": str(slot["port"]), "width": width,
                       "cycle": TRIGGER_HIGH_CYCLE, "value": full})
    mmio_writes = [{**dict(action), "instance_id": instance.instance_id,
                    "source_id": source_id,
                    "after_cycle": TRIGGER_LOW_CYCLE + PEER_ARM_SETTLE_CYCLES}
                   for action in raise_actions]
    return {
        "kind": "external_event_plan" if events else "mmio_trigger_plan",
        "source_id": source_id,
        "instance_id": instance.instance_id,
        "pins": slot_names,
        "events": events,
        "peer_events": [],
        "mmio_writes": mmio_writes,
        "basis": ("the profile declares external pin events and/or ordered MMIO raise "
                  "actions; runtime drives the declared pins, CPU executes only the "
                  "declared register stores, and observed status/pending/claim decides "
                  "whether the source was triggered"),
    }


def _combine_triggers(triggers: Sequence[Mapping[str, object]], *,
                      stagger: bool = False) -> dict:
    """Join per-source external trigger plans into one deterministic plan.

    A physical input pin may be shared by several logical interrupt sources
    (for example a GPIO vector), so duplicate slot/cycle/value writes are
    removed.  The source list remains explicit: replay and the generated
    document can distinguish ``all sources were requested`` from ``one source
    happened to own the same pin``.
    """
    if not triggers:
        _error("multi-source-trigger-empty")
    first = triggers[0]
    events: list[dict] = []
    peer_events: list[dict] = []
    mmio_writes: list[dict] = []
    seen: set[tuple[int, int, int]] = set()
    peer_seen: set[tuple[int, int, int]] = set()
    pins: list[str] = []
    for trigger_index, trigger in enumerate(triggers):
        for pin in trigger.get("pins", ()):
            if str(pin) not in pins:
                pins.append(str(pin))
        shift = trigger_index * TRIGGER_SOURCE_SPACING if stagger else 0
        for event in trigger.get("events", ()):
            row = dict(event)
            row["cycle"] = int(row["cycle"]) + shift
            key = (int(row["slot"]), int(row["cycle"]), int(row["value"]))
            if key in seen:
                continue
            seen.add(key)
            events.append(row)
        for event in trigger.get("peer_events", ()):
            row = dict(event)
            row["cycle"] = int(row["cycle"]) + shift
            key = (int(row["slot"]), int(row["cycle"]), int(row["payload"]))
            if key in peer_seen:
                continue
            peer_seen.add(key)
            peer_events.append(row)
        for action in trigger.get("mmio_writes", ()):
            row = dict(action)
            row["after_cycle"] = int(row["after_cycle"]) + shift
            mmio_writes.append(row)
    events.sort(key=lambda item: (int(item["cycle"]), int(item["slot"]),
                                  int(item["value"])))
    peer_events.sort(key=lambda item: (int(item["cycle"]), int(item["slot"]),
                                       int(item["payload"])))
    mmio_writes.sort(key=lambda item: (int(item["after_cycle"]),
                                      int(item["source_id"])))
    source_ids = [int(trigger["source_id"]) for trigger in triggers]
    source_instances = [str(trigger["instance_id"]) for trigger in triggers]
    kinds = {str(trigger.get("kind", "external_event_plan")) for trigger in triggers}
    if events and peer_events:
        kind = "combined_event_plan"
    elif peer_events:
        kind = "peer_event_plan"
    elif events:
        kind = "external_event_plan"
    else:
        kind = "mmio_trigger_plan"
    return {
        "kind": kind,
        "source_id": source_ids[0],
        "source_ids": source_ids,
        "instance_id": str(first["instance_id"]),
        "instance_ids": source_instances,
        "staggered": bool(stagger),
        "pins": pins,
        "events": events,
        "peer_events": peer_events,
        "mmio_writes": mmio_writes,
        "source_kinds": sorted(kinds),
        "basis": ("the plan declares pin, peer and/or MMIO actions for each requested "
                  "source; runtime and CPU apply their deterministic union, while "
                  "controller claim/complete evidence identifies every source "
                  "that was actually serviced"),
    }


def _source_setups(plan: CompositionPlan, controller: dict | None) -> tuple[list[dict], list[str]]:
    """One setup record per declared interrupt source, plus gap notes."""
    gaps: list[str] = []
    setups: list[dict] = []
    for source in plan.interrupt_document.get("sources", ()):
        if not isinstance(source, Mapping):
            continue
        source_id = int(source["source_id"])
        instance_id = str(source["instance_id"])
        instance = plan.instance(instance_id)
        target_id, base, size = _peripheral_window(plan, instance_id)
        clear = _clear_operation(instance.profile, source)
        operands = _condition_operands(instance.profile, source, clear)
        prerequisites: list[dict[str, object]] = []
        raise_actions: list[dict[str, object]] = []
        registers = _registers(instance.profile)
        for item in source.get("prerequisites", ()) or ():
            if not isinstance(item, Mapping):
                _error(f"interrupt-prerequisite-invalid:{instance_id}")
            name = str(item.get("register", ""))
            register = registers.get(name)
            if register is None:
                _error(f"interrupt-prerequisite-register-unknown:{instance_id}:{name}")
            offset = int(item.get("offset", -1))
            mask = int(item.get("mask", 0))
            operation = str(item.get("operation", "set_bits"))
            if operation != "set_bits":
                _error(f"unsupported-interrupt-prerequisite-operation:{operation}")
            if str(getattr(register, "access", "")) != "rw":
                _error(f"interrupt-prerequisite-register-not-writable:{instance_id}:{name}")
            if offset != int(register.offset):
                _error(f"interrupt-prerequisite-offset-mismatch:{instance_id}:{name}:"
                       f"{offset}!={register.offset}")
            if mask <= 0 or mask >= (1 << int(register.width)):
                _error(f"interrupt-prerequisite-mask-outside-register:{instance_id}:{name}")
            prerequisites.append({"register": name, "offset": offset, "mask": mask,
                                  "reason": str(item.get("reason", "")),
                                  "operation": operation})
        for item in source.get("raise_actions", ()) or ():
            if not isinstance(item, Mapping):
                _error(f"interrupt-raise-action-invalid:{instance_id}")
            name = str(item.get("register", ""))
            register = registers.get(name)
            if register is None:
                _error(f"interrupt-raise-register-unknown:{instance_id}:{name}")
            offset = int(item.get("offset", -1))
            value = int(item.get("value", -1))
            operation = str(item.get("operation", "write_value"))
            if operation != "write_value":
                _error(f"unsupported-interrupt-raise-operation:{operation}")
            if str(getattr(register, "access", "")) not in ("rw", "wo"):
                _error(f"interrupt-raise-register-not-writable:{instance_id}:{name}")
            if offset != int(register.offset):
                _error(f"interrupt-raise-offset-mismatch:{instance_id}:{name}")
            if value < 0 or value >= (1 << int(register.width)):
                _error(f"interrupt-raise-value-outside-register:{instance_id}:{name}")
            raise_actions.append({"register": name, "offset": offset, "value": value,
                                  "reason": str(item.get("reason", "")),
                                  "operation": operation, "base": base})
        enable_word = None
        enable_shift = None
        if controller is not None:
            # The controller numbers bitmap bit k as source id 32*j+k and bit 0
            # of every word is the reserved id 0 (soc_irq_controller.sv lines
            # 4-5 and 172-178), so a source's own bit is id % 32, not id - 1.
            index = source_id // 32
            enable_word = controller["offsets"].get(f"ENABLE{index}")
            if enable_word is None:
                _error(f"controller-enable-word-missing:{index}")
            enable_shift = source_id % 32
            pending_word = controller["offsets"].get(f"PENDING{index}")
            if pending_word is None:
                _error(f"controller-pending-word-missing:{index}")
        else:
            pending_word = None
        setups.append({
            "source_id": source_id,
            "instance_id": instance_id,
            "component_id": str(source.get("component_id", instance.component_id)),
            "role": str(source.get("role", "")),
            "endpoint_id": str(source.get("endpoint_id", "")),
            "target_id": target_id,
            "base": base,
            "size": size,
            "enable_register": operands["enable_register"],
            "enable_offset": operands["enable_offset"],
            "enable_bit": operands["enable_bit"],
            "status_register": operands["status_register"],
            "status_offset": operands["status_offset"],
            "cause_bit": operands["cause_bit"],
            "cause_mask": 1 << operands["cause_bit"],
            "clear": clear,
            "clear_kind": clear["kind"],
            "clear_register": clear["register"],
            "clear_offset": clear["offset"],
            "clear_bit": int(clear.get("bit") or 0),
            "clear_mask": 1 << int(clear.get("bit") or 0),
            "controller_enable_offset": enable_word,
            "controller_enable_shift": enable_shift,
            "controller_enable_mask": (1 << enable_shift) if enable_shift is not None else 0,
            "controller_pending_offset": pending_word,
            "hold": str(source.get("hold", "")),
            "clear_text": str(source.get("clear", "")),
            "prerequisites": prerequisites,
            "raise_actions": raise_actions,
        })
    return setups, gaps


def _unmapped_address(plan: CompositionPlan) -> int:
    """One deterministic address the fabric decodes as an error."""
    windows = plan.plan["fabric"]["decode"]["windows"]
    spans = sorted((int(row["base"]), int(row["base"]) + int(row["size"]))
                   for row in windows)
    policy = plan.request.address_policy
    candidates: list[int] = []
    cursor = int(policy.mmio_base) + int(policy.mmio_limit) - 4
    while cursor >= int(policy.mmio_base) and len(candidates) < 4096:
        candidates.append(cursor & ~0x3)
        cursor -= 4
    cursor = (1 << 32) - 4
    while cursor > 0 and len(candidates) < 8192:
        candidates.append(cursor & ~0x3)
        cursor -= 4
    for address in candidates:
        if any(base <= address < end for base, end in spans):
            continue
        return address
    _error("no-unmapped-address-found")


# ---------------------------------------------------------------------------
# the declared-register software phase
# ---------------------------------------------------------------------------


def _writeback_pattern(offset: int, mask: int) -> int:
    """The deterministic probe value the generated program writes.

    It is a pure function of the register's declared offset, so two runs of the
    same plan write the same value, and masked to the declared writable bits so
    the comparison can only fail for a reason the profile really declares.  A
    value that masks to zero would make the read-back vacuous, so it falls back
    to the declared mask itself.
    """
    mask &= 0xFFFF_FFFF
    value = (0x5A5A_5A5A ^ ((int(offset) & 0xFF) * 0x0001_0101)) & 0xFFFF_FFFF
    value &= mask
    return value or mask


def _readable(register) -> bool:
    return str(getattr(register, "access", "")) in ("ro", "rw")


def _software_plan(plan: CompositionPlan, *, faulting_checks: bool) -> dict:
    """What the generated program will do to each bound peripheral's registers.

    Every fact comes from the plan (window base, target id) and the bound
    profile's own declared register table.  A peripheral that declares no
    registers contributes a coverage note and no accessor at all: the generator
    never invents one.  ``faulting_checks`` is False for a boot-only program,
    where no trap handler exists to record an access fault.
    """
    peripherals: list[dict] = []
    skipped: list[dict] = []
    notes: list[str] = []
    writeback_index = 0
    side_effect_index = 0
    probe_index = 0
    totals = {"registers": 0, "init_writes": 0, "reads": 0, "writebacks": 0,
              "side_effects": 0, "status_checks": 0, "probes": 0, "unchecked": 0,
              "probe_unchecked": 0}
    status_slots = 0
    status_overflow = 0

    # The status register the plan's own interrupt document names for an
    # instance, if it is an interrupt source: that is the declared status
    # operand of the source, and the one the ISR already reads.
    declared_status: dict[str, str] = {}
    for source in plan.interrupt_document.get("sources", ()):
        if not isinstance(source, Mapping):
            continue
        instance_id = str(source.get("instance_id", ""))
        hold = str(source.get("hold", ""))
        registers = {}
        try:
            instance = plan.instance(instance_id)
            registers = {item.name: item for item in instance.profile.address.registers}
        except (KeyError, AttributeError):
            continue
        mentioned = [name for name, _ in _mentions(hold, registers) if _readable(registers[name])]
        if mentioned:
            declared_status.setdefault(instance_id, mentioned[0])

    for instance in plan.instances:
        if instance.kind != "peripheral":
            continue
        profile = instance.profile
        if profile.address is None or not profile.address.registers:
            skipped.append({
                "instance_id": instance.instance_id,
                "component_id": str(profile.component_id),
                "reason": "no-registers-declared",
                "note": ("the bound profile declares no register table, so the generated "
                         "program emits no accessor for this peripheral and claims nothing "
                         "about it"),
            })
            continue
        try:
            target_id, base, size = _peripheral_window(plan, instance.instance_id)
        except BootProgramError:
            skipped.append({
                "instance_id": instance.instance_id,
                "component_id": str(profile.component_id),
                "reason": "no-mmio-window",
                "note": ("the instance has no declared MMIO window in the plan's address "
                         "map, so no register access is generated for it"),
            })
            continue
        by_name = {item.name: item for item in profile.address.registers}
        registers: list[dict] = []
        for register in profile.address.registers:
            offset = int(register.offset)
            if offset < 0 or offset > 0x7FF:
                _error(f"register-offset-out-of-imm12-range:{register.name}:{offset}")
            width = int(register.width)
            declared_mask = (1 << width) - 1
            writable = register.writable_bits
            writable_mask = declared_mask if writable is None else int(writable)
            record = {
                "instance_id": instance.instance_id,
                "component_id": str(profile.component_id),
                "target_id": target_id,
                "base": base,
                "name": register.name,
                "offset": offset,
                "width": width,
                "access": str(register.access),
                "side_effect": str(register.side_effect),
                "reset_value": (None if register.reset_value is None
                                else int(register.reset_value)),
                "writable_bits": (None if writable is None else int(writable)),
                "writable_mask": writable_mask,
                "clears_register": register.clears_register,
                "init": False,
                "read": False,
                "writeback": False,
                "write_value": None,
                "side_effect_check": None,
                "side_effect_probe": None,
                "side_effect_probe_offset": None,
                "side_effect_mask_value": None,
                "check_index": None,
                "side_effect_index": None,
                "probe_index": None,
                "probe_direction": None,
            }
            # 1. declared initialisation write.  Only a plain read/write register
            #    is initialised: writing a register whose profile declares a side
            #    effect would perform that effect, which is not initialisation.
            if (str(register.access) == "rw" and str(register.side_effect) == "none"
                    and register.reset_value is not None):
                record["init"] = True
                totals["init_writes"] += 1
            # 2. read every declared readable register.
            if _readable(register):
                record["read"] = True
                totals["reads"] += 1
            # 3. write + read-back for the plain read/write registers.
            if str(register.access) == "rw" and str(register.side_effect) == "none":
                record["writeback"] = True
                record["write_value"] = _writeback_pattern(offset, writable_mask)
                if writeback_index < SOFTWARE_MASK_BITS:
                    record["check_index"] = writeback_index
                else:
                    totals["unchecked"] += 1
                writeback_index += 1
                totals["writebacks"] += 1
            # 4. the declared clear / side effect, when a probe is declared.
            if str(register.side_effect) in ("read_clears", "write_1_to_clear"):
                if str(register.side_effect) == "read_clears" and not _readable(register):
                    _error(f"read-clears-on-a-write-only-register:{register.name}")
                probe_name = register.clears_register
                if probe_name is None:
                    skipped.append({
                        "instance_id": instance.instance_id,
                        "component_id": str(profile.component_id),
                        "register": register.name,
                        "reason": "clearing-side-effect-not-observable",
                        "note": (f"{register.name} declares {register.side_effect} but no "
                                 f"register of the map that proves it, so the generated "
                                 f"program emits no clear check for it instead of "
                                 f"guessing a probe"),
                    })
                elif probe_name not in by_name:
                    _error(f"unknown-clears-register:{register.name}:{probe_name}")
                else:
                    probe = by_name[probe_name]
                    record["side_effect_check"] = str(register.side_effect)
                    record["side_effect_probe"] = probe_name
                    record["side_effect_probe_offset"] = int(probe.offset)
                    if str(register.side_effect) == "write_1_to_clear":
                        record["side_effect_mask_value"] = writable_mask
                    if side_effect_index < SOFTWARE_MASK_BITS:
                        record["side_effect_index"] = side_effect_index
                    side_effect_index += 1
                    totals["side_effects"] += 1
            # 5. a direction probe: a write to a declared read-only register and
            #    a read of a declared write-only register.
            if str(register.access) == "ro":
                record["probe_direction"] = "write"
            elif str(register.access) == "wo":
                record["probe_direction"] = "read"
            if record["probe_direction"] is not None:
                if faulting_checks:
                    if probe_index < SOFTWARE_MASK_BITS:
                        record["probe_index"] = probe_index
                    else:
                        totals["probe_unchecked"] += 1
                    probe_index += 1
                    totals["probes"] += 1
            registers.append(record)
        totals["registers"] += len(registers)
        status_name = declared_status.get(instance.instance_id)
        if status_name is None:
            status_name = next((record["name"] for record in registers
                                if record["access"] == "ro"), None)
            if status_name is not None:
                notes.append(
                    f"{instance.instance_id}: no interrupt source declares a status operand, "
                    f"so the first declared read-only register ({status_name}) is re-read as "
                    f"the peripheral's status")
        status_offset = None
        if status_name is not None:
            status_offset = int(by_name[status_name].offset)
        status_slot = None
        if status_name is not None:
            if status_slots < SOFTWARE_STATUS_SLOTS:
                status_slot = status_slots
            else:
                status_overflow += 1
            status_slots += 1
            totals["status_checks"] += 1
        peripherals.append({
            "instance_id": instance.instance_id,
            "component_id": str(profile.component_id),
            "target_id": target_id,
            "window": {"base": base, "size": size},
            "register_map_source": f"component_profile:{profile.component_id}",
            "registers": registers,
            "status": (None if status_name is None else {
                "register": status_name, "offset": status_offset, "slot": status_slot,
                "source": ("the plan's declared interrupt status operand"
                           if instance.instance_id in declared_status
                           else "the first declared read-only register"),
            }),
        })
    if not faulting_checks and any(
            record["probe_direction"] is not None
            for peripheral in peripherals for record in peripheral["registers"]):
        notes.append(
            "the declared direction probes (a write to every read-only register and a read "
            "of every write-only register) are not emitted: they are deliberate access "
            "faults, so they are generated only when the request asks for them "
            "(probe_permissions=True) and a trap handler exists (isr=True)")
    return {
        "peripherals": peripherals,
        "skipped": skipped,
        "notes": notes,
        "totals": totals,
        "status_overflow": status_overflow,
        "probes_enabled": bool(faulting_checks),
        "permission_probes": [
            {"index": record["probe_index"], "instance_id": peripheral["instance_id"],
             "register": record["name"], "offset": record["offset"],
             "declared_access": record["access"], "probe": record["probe_direction"],
             "note": (f"{record['name']} is declared {record['access']}, so the probe "
                      f"{'writes' if record['probe_direction'] == 'write' else 'reads'} it "
                      f"and records the exception cause the CPU observed")}
            for peripheral in peripherals for record in peripheral["registers"]
            if record["probe_index"] is not None
        ],
    }


#: The x-registers the software phase uses.  Every one of them is saved and
#: restored by the shared handler, so an interrupt taken in the middle of the
#: phase cannot corrupt it.  ``_SW_AUX`` holds the CPU's exception count as it
#: was when the phase started, so the phase can report its *own* traps instead
#: of everything the composition did before it.
_SW_BASE = 5        # peripheral window base
_SW_TMP = 6
_SW_VAL = 7
_SW_AUX = 28        # exception count at phase entry
_SW_COUNTER = 29    # the counter-bump scratch (free wherever a bump is emitted)
_SW_BEFORE = 29
_SW_AFTER = 30
_SW_CAUSE = 31      # the composition's earlier recorded exception cause


def _emit_software_phase(asm: _ProgramAssembler, plan: CompositionPlan, software: dict, *,
                         rom_region: Mapping[str, object] | None, isr: bool) -> None:
    """Emit the declared-register phase into ``asm``.

    The emitter only ever uses the declared register facts the software plan
    carries and the plan's own addresses; it never names a component.  Labels are
    numbered per register so one phase can repeat the same shape many times.
    """
    add = asm.comment
    report = _RAM

    def bump(field: str) -> None:
        asm.lw(_SW_COUNTER, report, _report_offset(field))
        asm.addi(_SW_COUNTER, _SW_COUNTER, 1)
        asm.sw(_SW_COUNTER, report, _report_offset(field))

    def constant(field: str, value: int) -> None:
        asm.li32(_SW_TMP, int(value))
        asm.sw(_SW_TMP, report, _report_offset(field))

    add("declared-register software phase: every access below is aimed by the bound "
        "profile's own register declaration (offset, access, side effect) and the plan's "
        "own window base; no component name is used")
    asm.li32(_SW_TMP, 1)
    asm.sw(_SW_TMP, report, _report_offset("software_phase"))
    # The plan-derived counts are written up front: a run that never reaches the
    # phase then reads zero there, which is what an unfinished program means.
    constant("software_registers", int(software["totals"]["registers"]))
    constant("software_skipped", len(software["skipped"]))
    constant("software_unchecked", int(software["totals"]["unchecked"]))
    constant("permission_unchecked", int(software["totals"]["probe_unchecked"]))
    add("preserve the exception cause an earlier scenario recorded: the phase performs "
        "deliberately faulting accesses of its own, and the report field keeps its "
        "existing meaning")
    asm.lw(_SW_CAUSE, report, _report_offset("error_cause"))
    add("the CPU's exception counter as the phase starts: the phase's own trap counts are "
        "differences against it, so an earlier faulting scenario cannot be mistaken for a "
        "declared register access that trapped")
    asm.lw(_SW_AUX, report, _report_offset("exception_count"))

    # -- 1. declared initialisation writes and 2. the read pass ---------------
    for peripheral in software["peripherals"]:
        base = int(peripheral["window"]["base"])
        registers = peripheral["registers"]
        asm.li32(_SW_BASE, base)
        add(f"{peripheral['instance_id']} ({peripheral['component_id']}) at 0x{base:08x}: "
            f"{len(registers)} declared register(s) from "
            f"{peripheral['register_map_source']}")
        for record in registers:
            if not record["init"]:
                continue
            add(f"init: write the declared reset value 0x{record['reset_value']:08x} to "
                f"{record['name']} (offset 0x{record['offset']:02x})")
            asm.li32(_SW_VAL, int(record["reset_value"]))
            asm.sw(_SW_VAL, _SW_BASE, int(record["offset"]))
            bump("software_init_writes")
        for record in registers:
            if not record["read"]:
                continue
            add(f"read: {record['name']} (offset 0x{record['offset']:02x}, declared "
                f"{record['access']})")
            asm.lw(_SW_TMP, _SW_BASE, int(record["offset"]))
            bump("software_reads")
    add("the read pass is over: the CPU's own exception counter says whether any declared "
        "readable register trapped the access")
    asm.lw(_SW_TMP, report, _report_offset("exception_count"))
    asm.sub(_SW_TMP, _SW_TMP, _SW_AUX)
    asm.sw(_SW_TMP, report, _report_offset("software_read_traps"))

    # -- 3. write + read-back -------------------------------------------------
    for peripheral in software["peripherals"]:
        base = int(peripheral["window"]["base"])
        asm.li32(_SW_BASE, base)
        for record in peripheral["registers"]:
            if not record["writeback"]:
                continue
            index = record["check_index"]
            value = int(record["write_value"])
            mask = int(record["writable_mask"])
            add(f"write+read-back: {record['name']} (offset 0x{record['offset']:02x}) "
                f"<- 0x{value:08x} (offset-derived pattern masked to the declared writable "
                f"bits 0x{mask:08x})")
            asm.li32(_SW_VAL, value)
            # A named step: the listing marks the exact store a test can disable
            # to show that this comparison really can fail.
            asm.label(f"_sw_wb_store_{record['instance_id']}_{int(record['offset']):x}")
            asm.sw(_SW_VAL, _SW_BASE, int(record["offset"]))
            asm.lw(_SW_TMP, _SW_BASE, int(record["offset"]))
            asm.sw(_SW_VAL, report, _report_offset("software_writeback_last_expected"))
            asm.sw(_SW_TMP, report, _report_offset("software_writeback_last_observed"))
            bump("software_writeback_checks")
            if index is None:
                add("the result mask is full, so this register's individual outcome is not "
                    "recorded (it is still written and read back)")
                continue
            label_ok = f"_sw_wb_ok_{index}"
            label_done = f"_sw_wb_done_{index}"
            asm.beq(_SW_TMP, _SW_VAL, label_ok)
            add(f"the read-back differs from the value written: record it in the mask "
                f"as a failing check (bit {index})")
            asm.jal(0, label_done)
            asm.label(label_ok)
            bump("software_writeback_matches")
            asm.lw(_SW_TMP, report, _report_offset("software_writeback_mask"))
            asm.li32(_SW_VAL, 1 << index)
            asm.or_(_SW_TMP, _SW_TMP, _SW_VAL)
            asm.sw(_SW_TMP, report, _report_offset("software_writeback_mask"))
            asm.label(label_done)

    # -- 4. the declared clear / side effect ---------------------------------
    for peripheral in software["peripherals"]:
        base = int(peripheral["window"]["base"])
        asm.li32(_SW_BASE, base)
        for record in peripheral["registers"]:
            kind = record["side_effect_check"]
            if kind is None:
                continue
            index = record["side_effect_index"]
            probe_offset = int(record["side_effect_probe_offset"])
            label_fail = f"_sw_se_fail_{index}"
            # The wording deliberately avoids the ``clear:`` prefix the interrupt
            # path's own listing comment uses: a reader (or a test) that picks the
            # program's declared clear operation out of the listing must keep
            # finding the ISR's step and not this register-level re-check.
            add(f"declared {kind} side effect on {record['name']} "
                f"(offset 0x{record['offset']:02x}); the probe "
                f"{record['side_effect_probe']} (offset 0x{probe_offset:02x}) is the "
                f"register the profile declares proves it")
            asm.lw(_SW_BEFORE, _SW_BASE, probe_offset)
            if kind == "write_1_to_clear":
                mask = int(record["side_effect_mask_value"])
                add(f"perform the declared access: write 1s (0x{mask:08x}) and re-read")
                asm.li32(_SW_VAL, mask)
                # The named step: the listing marks the exact store a test can
                # disable to show that this check really can fail.
                asm.label(f"_sw_se_access_{record['instance_id']}_{int(record['offset']):x}")
                asm.sw(_SW_VAL, _SW_BASE, int(record["offset"]))
                asm.lw(_SW_AFTER, _SW_BASE, probe_offset)
                asm.sw(_SW_BEFORE, report, _report_offset("software_side_effect_last_before"))
                asm.sw(_SW_AFTER, report, _report_offset("software_side_effect_last_after"))
                bump("software_side_effects")
                if index is None:
                    continue
                asm.li32(_SW_VAL, mask)
                asm.and_(_SW_TMP, _SW_AFTER, _SW_VAL)
                asm.bne(_SW_TMP, 0, label_fail)
            else:
                add("perform the declared access: read the register and re-read the probe")
                asm.label(f"_sw_se_access_{record['instance_id']}_{int(record['offset']):x}")
                asm.lw(_SW_TMP, _SW_BASE, int(record["offset"]))
                asm.lw(_SW_AFTER, _SW_BASE, probe_offset)
                asm.sw(_SW_BEFORE, report, _report_offset("software_side_effect_last_before"))
                asm.sw(_SW_AFTER, report, _report_offset("software_side_effect_last_after"))
                bump("software_side_effects")
                if index is None:
                    continue
                asm.bne(_SW_AFTER, 0, label_fail)
            bump("software_side_effects_confirmed")
            asm.lw(_SW_TMP, report, _report_offset("software_side_effect_mask"))
            asm.li32(_SW_VAL, 1 << index)
            asm.or_(_SW_TMP, _SW_TMP, _SW_VAL)
            asm.sw(_SW_TMP, report, _report_offset("software_side_effect_mask"))
            asm.label(label_fail)

    # -- 5. the declared status register -------------------------------------
    for peripheral in software["peripherals"]:
        status = peripheral["status"]
        if status is None:
            add(f"{peripheral['instance_id']}: no declared status register to re-read")
            continue
        base = int(peripheral["window"]["base"])
        asm.li32(_SW_BASE, base)
        add(f"status: re-read {peripheral['instance_id']} {status['register']} "
            f"(offset 0x{int(status['offset']):02x}) - {status['source']}")
        asm.lw(_SW_TMP, _SW_BASE, int(status["offset"]))
        bump("software_status_checks")
        if status["slot"] is None:
            bump("status_overflow")
        else:
            asm.sw(_SW_TMP, report, _report_offset(f"status_{int(status['slot'])}"))

    add("every declared register access is done: the CPU's exception counter says whether "
        "any of them trapped.  The deliberately faulting ROM-write and direction probes are "
        "counted separately, below, so this field keeps its meaning")
    asm.lw(_SW_TMP, report, _report_offset("exception_count"))
    asm.sub(_SW_TMP, _SW_TMP, _SW_AUX)
    asm.sw(_SW_TMP, report, _report_offset("software_traps"))

    # -- ROM write -----------------------------------------------------------
    if rom_region is not None:
        base = int(rom_region["base"])
        pattern = _writeback_pattern(0x04, 0xFFFF_FFFF)
        add(f"ROM write: store 0x{pattern:08x} into the plan's executable, non-writable "
            f"region {rom_region['region_id']} at 0x{base:08x}; the plan declares that "
            f"window read-only, so the fabric must answer with an error and the image must "
            f"survive")
        asm.li32(_SW_TMP, 1)
        asm.sw(_SW_TMP, report, _report_offset("rom_write_requested"))
        asm.sw(0, report, _report_offset("error_cause"))
        asm.li32(_SW_BASE, base)
        asm.lw(_SW_BEFORE, _SW_BASE, 0)
        asm.li32(_SW_VAL, pattern)
        asm.label("_sw_rom_store")
        asm.sw(_SW_VAL, _SW_BASE, 0)
        add("the generated handler recorded the cause the CPU observed for the refused store")
        asm.lw(_SW_TMP, report, _report_offset("error_cause"))
        asm.sw(_SW_TMP, report, _report_offset("rom_write_cause"))
        asm.lw(_SW_AFTER, _SW_BASE, 0)
        asm.sw(_SW_BEFORE, report, _report_offset("rom_value_before"))
        asm.sw(_SW_AFTER, report, _report_offset("rom_value_after"))
        label_ok = "_sw_rom_ok"
        label_done = "_sw_rom_done"
        asm.beq(_SW_BEFORE, _SW_AFTER, label_ok)
        add("the region content changed: the read-only window did not hold")
        asm.sw(0, report, _report_offset("rom_unchanged"))
        asm.jal(0, label_done)
        asm.label(label_ok)
        asm.li32(_SW_TMP, 1)
        asm.sw(_SW_TMP, report, _report_offset("rom_unchanged"))
        asm.label(label_done)

    # -- direction probes ----------------------------------------------------
    probes = software["permission_probes"] if software["probes_enabled"] else []
    if isr and probes:
        add("direction probes: a write to every declared read-only register and a read of "
            "every declared write-only register; the exception cause the CPU observed is "
            "recorded per probe")
        for probe in probes:
            index = int(probe["index"])
            base = next(int(peripheral["window"]["base"])
                        for peripheral in software["peripherals"]
                        if peripheral["instance_id"] == probe["instance_id"])
            offset = int(probe["offset"])
            label_ok = f"_sw_pp_ok_{index}"
            asm.li32(_SW_BASE, base)
            bump("permission_probes")
            asm.sw(0, report, _report_offset("error_cause"))
            if probe["probe"] == "write":
                add(f"probe: {probe['instance_id']} {probe['register']} is declared ro; "
                    f"write 0x{_writeback_pattern(offset, 0xFFFF_FFFF):08x} to offset "
                    f"0x{offset:02x}")
                asm.li32(_SW_VAL, _writeback_pattern(offset, 0xFFFF_FFFF))
                asm.label(f"_sw_pp_probe_{probe['instance_id']}_{offset:x}")
                asm.sw(_SW_VAL, _SW_BASE, offset)
            else:
                add(f"probe: {probe['instance_id']} {probe['register']} is declared wo; "
                    f"read offset 0x{offset:02x}")
                asm.label(f"_sw_pp_probe_{probe['instance_id']}_{offset:x}")
                asm.lw(_SW_VAL, _SW_BASE, offset)
            asm.lw(_SW_TMP, report, _report_offset("error_cause"))
            asm.sw(_SW_TMP, report, _report_offset("permission_last_mcause"))
            asm.li32(_SW_VAL, offset)
            asm.sw(_SW_VAL, report, _report_offset("permission_last_offset"))
            asm.beq(_SW_TMP, 0, label_ok)
            add("the target answered the direction violation with an error: record it")
            asm.lw(_SW_TMP, report, _report_offset("permission_errors"))
            asm.addi(_SW_TMP, _SW_TMP, 1)
            asm.sw(_SW_TMP, report, _report_offset("permission_errors"))
            asm.lw(_SW_TMP, report, _report_offset("permission_error_mask"))
            asm.li32(_SW_VAL, 1 << index)
            asm.or_(_SW_TMP, _SW_TMP, _SW_VAL)
            asm.sw(_SW_TMP, report, _report_offset("permission_error_mask"))
            asm.label(label_ok)
            asm.sw(0, report, _report_offset("error_cause"))
    elif probes and not isr:
        add("direction probes are omitted: without a trap handler a refused access would "
            "restart the CPU instead of being recorded")

    # -- the phase is over ---------------------------------------------------
    add("restore the exception cause the composition recorded before this phase")
    asm.sw(_SW_CAUSE, report, _report_offset("error_cause"))


def _rom_write_region(plan: CompositionPlan, entry: int) -> dict | None:
    """The plan's executable, non-writable region the ROM-write check targets.

    ``None`` when the plan declares no such region; the caller then records that
    as a coverage note instead of inventing a target for the store.
    """
    region = _executable_region(plan, entry)
    permissions = region.get("permissions") or {}
    if permissions.get("write"):
        return None
    return region


def _disabled_software_plan(reason: str) -> dict:
    """The shape of the software plan when the request switches it off."""
    return {
        "peripherals": [],
        "skipped": [],
        "notes": [f"the declared-register software phase is not emitted: {reason}"],
        "totals": {"registers": 0, "init_writes": 0, "reads": 0, "writebacks": 0,
                   "side_effects": 0, "status_checks": 0, "probes": 0, "unchecked": 0,
                   "probe_unchecked": 0},
        "status_overflow": 0,
        "probes_enabled": False,
        "permission_probes": [],
        "rom_check": None,
        "enabled": False,
        "checks": {"faulting_checks_enabled": False, "init": False, "read": False,
                   "writeback": False, "side_effect": False, "status": False,
                   "permission_probes": False, "rom_write": False},
    }


# ---------------------------------------------------------------------------
# assembler: the matrix assembler's instruction set plus what an ISR needs
# ---------------------------------------------------------------------------


class _ProgramAssembler(_Assembler):
    """The matrix assembler (reused, not re-written) plus CSR/system opcodes."""

    def _r(self, text: str, funct3: int, funct7: int, rd: int, rs1: int, rs2: int) -> None:
        self._add(text, word=((funct7 & 0x7F) << 25) | ((rs2 & 0x1F) << 20)
                  | ((rs1 & 0x1F) << 15) | ((funct3 & 7) << 12) | ((rd & 0x1F) << 7) | 0x33)

    def add(self, rd: int, rs1: int, rs2: int) -> None:
        self._r("add x%d, x%d, x%d" % (rd, rs1, rs2), 0b000, 0x00, rd, rs1, rs2)

    def or_(self, rd: int, rs1: int, rs2: int) -> None:
        self._r("or x%d, x%d, x%d" % (rd, rs1, rs2), 0b110, 0x00, rd, rs1, rs2)

    def and_(self, rd: int, rs1: int, rs2: int) -> None:
        self._r("and x%d, x%d, x%d" % (rd, rs1, rs2), 0b111, 0x00, rd, rs1, rs2)

    def sub(self, rd: int, rs1: int, rs2: int) -> None:
        self._r("sub x%d, x%d, x%d" % (rd, rs1, rs2), 0b000, 0x20, rd, rs1, rs2)

    def andi(self, rd: int, rs1: int, imm: int) -> None:
        self._add("andi x%d, x%d, %d" % (rd, rs1, imm),
                  word=_enc_i(imm, rs1, 0b111, rd, 0x13))

    def csrrw(self, rd: int, csr: int, rs1: int) -> None:
        self._add("csrrw x%d, 0x%03x, x%d" % (rd, csr, rs1),
                  word=_enc_i(csr, rs1, 0b001, rd, 0x73))

    def csrrs(self, rd: int, csr: int, rs1: int) -> None:
        self._add("csrrs x%d, 0x%03x, x%d" % (rd, csr, rs1),
                  word=_enc_i(csr, rs1, 0b010, rd, 0x73))

    def csrw(self, csr: int, rs1: int) -> None:
        self.csrrw(0, csr, rs1)

    def csrr(self, rd: int, csr: int) -> None:
        self.csrrs(rd, csr, 0)

    def mret(self) -> None:
        self._add("mret", word=(0x302 << 20) | 0x73)

    def nop(self, reason: str) -> None:
        """An unreachable filler word used only to align the trap vector table."""
        self._add("nop (%s)" % reason, word=0x00000013)

    def _branch(self, text: str, funct3: int, rs1: int, rs2: int, label: str) -> None:
        self._add(text, kind="branch", rs1=rs1, rs2=rs2, funct3=funct3, label=label)

    def bne(self, rs1: int, rs2: int, label: str) -> None:
        self._branch("bne x%d, x%d, %s" % (rs1, rs2, label), 0b001, rs1, rs2, label)

    def bge(self, rs1: int, rs2: int, label: str) -> None:
        self._branch("bge x%d, x%d, %s" % (rs1, rs2, label), 0b101, rs1, rs2, label)

    def blt(self, rs1: int, rs2: int, label: str) -> None:
        self._branch("blt x%d, x%d, %s" % (rs1, rs2, label), 0b100, rs1, rs2, label)


# ---------------------------------------------------------------------------
# program emission
# ---------------------------------------------------------------------------

_RAM = 8      # report base (survives across the handler)
_CTRL = 5     # controller base inside the handler
_FLAG = 9
_SCRATCH = (6, 7, 28, 29, 30, 31)


def _emit(plan: CompositionPlan, *, request: ProgramRequest, isr: bool,
          handler_address: int, rom_base: int, body_base: int, entry: int,
          stack_pointer: int, flag_address: int, report_address: int,
          controller: dict | None, setups: Sequence[Mapping[str, object]],
          active_sources: Sequence[Mapping[str, object]],
          trigger: Mapping[str, object] | None, trigger_source: Mapping[str, object] | None,
          error_address: int | None, software: Mapping[str, object],
          rom_region: Mapping[str, object] | None) -> _ProgramAssembler:
    xlen = int(plan.request.cpu.profile.cpu.xlen)
    asm = _ProgramAssembler(xlen)
    add = asm.comment

    asm.label("_start")
    add(f"report record at 0x{report_address:08x} (RAM), completion flag at "
        f"0x{flag_address:08x}")
    asm.li32(_RAM, report_address)
    add(f"stack pointer at the top of the writable RAM region: 0x{stack_pointer:08x}")
    asm.li32(2, stack_pointer)

    # -- trap vector --------------------------------------------------------
    # Installed before the first bus access: an unexpected fault then lands in
    # the generated handler, which records mcause and skips the instruction,
    # instead of restarting the program through the CPU's reset vector (the
    # pinned cores reset mtvec to their boot address).
    if isr:
        add(f"mtvec = 0x{handler_address:08x} (direct mode, 4-byte aligned): one handler "
            f"decodes mcause into the interrupt and exception paths")
        asm.li32(5, handler_address)
        asm.csrw(MTVEC, 5)

    # -- peripheral interrupt-enable bits (peripheral initialisation) --------
    if isr:
        for setup in setups:
            base = int(setup["base"])
            offset = int(setup["enable_offset"])
            mask = 1 << int(setup["enable_bit"])
            add(f"source {setup['source_id']} ({setup['instance_id']} at 0x{base:08x}): "
                f"set {setup['enable_register']} (0x{offset:02x}) bit "
                f"{setup['enable_bit']} without changing the other declared bits")
            asm.li32(5, base)
            asm.lw(6, 5, offset)
            asm.li32(7, mask)
            asm.or_(6, 6, 7)
            asm.sw(6, 5, offset)

        # Some protocol sources have a separate operational prerequisite (for
        # example a UART receiver-enable bit) in addition to the interrupt
        # enable named by ``hold``.  The profile declares these bits; the
        # generic generator performs only the declared set-bits operation.
        for setup in setups:
            for prerequisite in setup.get("prerequisites", ()):
                base = int(setup["base"])
                offset = int(prerequisite["offset"])
                mask = int(prerequisite["mask"])
                add(f"source {setup['source_id']} prerequisite: set "
                    f"{prerequisite['register']} (0x{offset:02x}) mask "
                    f"0x{mask:08x} before the declared trigger: "
                    f"{prerequisite['reason']}")
                asm.li32(5, base)
                asm.lw(6, 5, offset)
                asm.li32(7, mask)
                asm.or_(6, 6, 7)
                asm.sw(6, 5, offset)

    # -- controller ENABLE + CPU interrupt enable ---------------------------
    if isr and request.enable_interrupts:
        if controller is None or not active_sources:
            _error("controller-missing-for-interrupt-enable")
        asm.li32(5, int(controller["base"]))
        for word_index in sorted({int(item["source_id"]) // 32 for item in active_sources}):
            selected = [item for item in active_sources
                        if int(item["source_id"]) // 32 == word_index]
            mask = 0
            for item in selected:
                mask |= int(item["controller_enable_mask"])
            offset = int(selected[0]["controller_enable_offset"])
            ids = ",".join(str(int(item["source_id"])) for item in selected)
            add(f"controller {controller['instance_id']} at 0x{controller['base']:08x}: "
                f"ENABLE{word_index} for source id(s) {ids} = 0x{mask:08x} "
                f"(single write, no read-modify-write)")
            asm.li32(6, mask)
            asm.sw(6, 5, offset)
        asm.li32(5, MIE_MEIE)
        asm.csrrs(0, MIE, 5)
        add("mstatus.MIE=1 (machine external interrupts unmasked)")
        asm.li32(5, MSTATUS_MIE)
        asm.csrrs(0, MSTATUS, 5)

    # -- unmapped access scenario -------------------------------------------
    if error_address is not None:
        add(f"unmapped access scenario: load 0x{error_address:08x}, which no declared "
            f"window decodes; the fabric must answer with an error")
        asm.li32(5, 1)
        asm.sw(5, _RAM, _report_offset("error_access_requested"))
        asm.sw(0, _RAM, _report_offset("error_cause"))
        asm.li32(5, error_address)
        asm.lw(6, 5, 0)
        add(f"unmapped access scenario, the store half: store 0x{_writeback_pattern(4, 0xFFFFFFFF):08x} "
            f"to the same undecoded address 0x{error_address:08x}.  The load's cause is kept "
            f"in the register file while the store's cause is recorded in its own field, so "
            f"the existing error_cause field keeps its meaning")
        asm.lw(29, _RAM, _report_offset("error_cause"))
        asm.sw(0, _RAM, _report_offset("error_cause"))
        asm.li32(5, error_address)
        asm.li32(6, _writeback_pattern(4, 0xFFFFFFFF))
        asm.sw(6, 5, 0)
        asm.lw(6, _RAM, _report_offset("error_cause"))
        asm.sw(6, _RAM, _report_offset("unmapped_store_cause"))
        asm.sw(29, _RAM, _report_offset("error_cause"))

    if isr:
        # -- prologue stamp --------------------------------------------------
        add("prologue stamp: mcycle after setup, so a run can prove the setup finished "
            "before the recorded trigger cycles")
        asm.csrr(5, MCYCLE)
        asm.sw(5, _RAM, _report_offset("prologue_cycle"))

    add("main flow completion: the flag and the main-completion marker are written "
        "whether or not an interrupt was taken (and before any wait, so a late "
        "trigger cannot hide that the CPU executed)")
    asm.li32(5, COMPLETION_FLAG)
    asm.li32(_FLAG, flag_address)
    asm.sw(5, _FLAG, 0)
    asm.li32(5, 1)
    asm.sw(5, _RAM, _report_offset("main_completed"))

    # For a component-owned transaction, the environment arms the attached
    # peer first; the CPU then performs only the profile-declared stores.
    if isr and trigger is not None and request.trigger_event:
        last_cycle = None
        for index, action in enumerate(trigger.get("mmio_writes", ())):
            after_cycle = int(action["after_cycle"])
            if after_cycle != last_cycle:
                label = f"_raise_wait_{index}"
                add(f"wait for peer arm through cycle {after_cycle} before the "
                    "component-owned MMIO trigger")
                asm.li32(6, after_cycle)
                asm.label(label)
                asm.csrr(5, MCYCLE)
                asm.blt(5, 6, label)
                last_cycle = after_cycle
            add(f"source {action['instance_id']} trigger: write "
                f"{action['register']} (0x{int(action['offset']):02x}) = "
                f"0x{int(action['value']):08x}: {action['reason']}")
            asm.li32(5, int(action["base"]))
            asm.li32(7, int(action["value"]))
            asm.sw(7, 5, int(action["offset"]))

    if isr:
        # -- bounded wait for the peripheral condition -----------------------
        if trigger_source is not None:
            base = int(trigger_source["base"])
            offset = int(trigger_source["status_offset"])
            mask = int(trigger_source["cause_mask"])
            add(f"wait (bounded, {POLL_ITERATIONS} iterations) for "
                f"{trigger_source['instance_id']} {trigger_source['status_register']} "
                f"(0x{offset:02x}) bit {trigger_source['cause_bit']}: the CPU observes the "
                f"peripheral's own condition, not a claim")
            asm.li32(5, base)
            asm.li32(6, POLL_ITERATIONS)
            asm.label("_poll")
            asm.lw(7, 5, offset)
            asm.andi(7, 7, mask)
            asm.bne(7, 0, "_latched")
            asm.addi(6, 6, -1)
            asm.bne(6, 0, "_poll")
            asm.sw(0, _RAM, _report_offset("status_latched_by_poll"))
            asm.jal(0, "_main_ready")
            asm.label("_latched")
            asm.sw(7, _RAM, _report_offset("status_latched_by_poll"))
            asm.label("_main_ready")
            if controller is not None and trigger_source.get("controller_pending_offset") is not None:
                add("the controller's own pending bitmap, read by the CPU after the "
                    "peripheral condition was observed")
                asm.li32(5, int(controller["base"]))
                asm.lw(6, 5, int(trigger_source["controller_pending_offset"]))
                asm.li32(7, int(trigger_source["controller_enable_mask"]))
                asm.and_(6, 6, 7)
                asm.sw(6, _RAM, _report_offset("pending_seen_by_main"))

    if controller is not None:
        add(f"the controller's declared source count, read over the bus from "
            f"SOURCE_COUNT (0x{int(controller['offsets']['SOURCE_COUNT']):02x})")
        asm.li32(5, int(controller["base"]))
        asm.lw(6, 5, int(controller["offsets"]["SOURCE_COUNT"]))
        asm.sw(6, _RAM, _report_offset("source_count"))

    # -- the declared-register software phase --------------------------------
    # Emitted after the main flow's wait: the checks write declared reset values
    # and offset-derived patterns into real registers, so running them after the
    # interrupt loop has closed keeps them from perturbing the source state the
    # loop depends on.  Nothing after this point waits on a peripheral.
    if software.get("enabled"):
        _emit_software_phase(asm, plan, dict(software), rom_region=rom_region, isr=isr)

    asm.label("_spin")
    asm.jal(0, "_spin")

    if not isr:
        return asm

    # -- trap vector table ---------------------------------------------------
    # The pinned cores disagree about what mtvec means: a direct-mode core jumps
    # to the base itself, the pinned Ibex clears mtvec[7:0] for exceptions and
    # jumps to base + 4*cause for interrupts (ibex_if_stage.sv:222-228), and a
    # pure-capability core uses base + 4*trap.  Nothing in the CPU profile
    # declares which convention applies, so the generated program uses the
    # intersection: mtvec points at a 256-byte-aligned table whose 64 entries
    # all jump to the one shared handler.  Every convention above lands inside
    # that table, and no convention is assumed.
    pad = (-(body_base + len(asm.items) * 4)) % VECTOR_ALIGNMENT
    if pad:
        add(f"{pad} bytes of padding so the trap vector table is "
            f"{VECTOR_ALIGNMENT}-byte aligned")
        for _ in range(pad // 4):
            asm.nop("alignment filler before the trap vector table")
    add(f"trap vector table ({VECTOR_ENTRIES} entries, every entry jumps to the shared "
        f"handler); mtvec is set to this table's base 0x{handler_address:08x}")
    asm.label("_vectors")
    for index in range(VECTOR_ENTRIES):
        if index == 0:
            asm.jal(0, "_handler")
            asm.comment("entry 0: direct-mode and exception entry lands here")
        else:
            asm.jal(0, "_handler")

    # -- the shared handler --------------------------------------------------
    asm.comment(f"handler at 0x{handler_address + VECTOR_ALIGNMENT:08x}: mcause bit 31 "
                f"selects the interrupt path; anything else is recorded and skipped")
    asm.label("_handler")
    add(f"save every register the handler uses on the stack the program set up "
        f"(x2 stays the stack pointer, x8 stays the report base): an interrupt is "
        f"asynchronous and must not corrupt the interrupted flow")
    asm.addi(2, 2, -4 * len(HANDLER_SAVED_REGISTERS))
    for index, register in enumerate(HANDLER_SAVED_REGISTERS):
        asm.sw(register, 2, 4 * index)
    asm.csrr(6, MCAUSE)
    asm.bge(6, 0, "_exception")

    add("interrupt path: count the entry, sample pending before claiming, then claim")
    asm.lw(6, _RAM, _report_offset("handler_entries"))
    asm.addi(6, 6, 1)
    asm.sw(6, _RAM, _report_offset("handler_entries"))
    asm.li32(_CTRL, int(controller["base"]))
    for index, slot in enumerate(PENDING_WORD_SLOTS):
        word = controller["offsets"].get(f"PENDING{index}")
        if word is None:
            break
        add(f"sample PENDING{index} (0x{int(word):02x}) before the claim, while the "
            f"claimed source's bit is still set")
        asm.lw(6, _CTRL, int(word))
        asm.sw(6, _RAM, _report_offset(slot))
    asm.lw(7, _CTRL, int(controller["offsets"]["CLAIM"]))
    if len(active_sources) > 1:
        # Preserve the first claim in the frozen field.  The aggregate
        # completion counter below makes repeated service observable while
        # keeping the one-source lifecycle document byte-compatible.
        asm.lw(6, _RAM, _report_offset("claim_id"))
        asm.bne(6, 0, "_claim_first_recorded")
        asm.sw(7, _RAM, _report_offset("claim_id"))
        asm.label("_claim_first_recorded")
    else:
        asm.sw(7, _RAM, _report_offset("claim_id"))
    asm.bne(7, 0, "_dispatch")
    add("CLAIM returned 0: nothing could be claimed, so nothing is completed")
    asm.jal(0, "_irq_return")

    asm.label("_dispatch")
    for setup in setups:
        asm.li32(6, int(setup["source_id"]))
        asm.beq(7, 6, f"_source_{setup['source_id']}")
    add("a claimed id outside the plan's source table is recorded and left in service "
        "instead of being completed with a wrong id")
    asm.li32(6, 1)
    asm.sw(6, _RAM, _report_offset("unknown_claim"))
    asm.jal(0, "_irq_return")

    for setup in setups:
        source_id = int(setup["source_id"])
        asm.label(f"_source_{source_id}")
        add(f"source {source_id} -> {setup['instance_id']} at 0x{int(setup['base']):08x} "
            f"({setup['target_id']}): pending bit, cause, declared clear, COMPLETE")
        word_index = source_id // 32
        slot = PENDING_WORD_SLOTS[word_index] if word_index < len(PENDING_WORD_SLOTS) \
            else PENDING_WORD_SLOTS[-1]
        add(f"pending bit for source {source_id} is bit {setup['controller_enable_shift']} of "
            f"PENDING{word_index}; bit 0 of each word is the reserved id 0")
        asm.lw(6, _RAM, _report_offset(slot))
        asm.li32(7, int(setup["controller_enable_mask"]))
        asm.and_(6, 6, 7)
        if len(active_sources) > 1:
            asm.lw(7, _RAM, _report_offset("pending_before_claim"))
            asm.bne(7, 0, f"_source_{source_id}_pending_recorded")
            asm.sw(6, _RAM, _report_offset("pending_before_claim"))
            asm.label(f"_source_{source_id}_pending_recorded")
        else:
            asm.sw(6, _RAM, _report_offset("pending_before_claim"))
        asm.li32(28, int(setup["base"]))
        asm.lw(6, 28, int(setup["status_offset"]))
        if len(active_sources) > 1:
            asm.lw(7, _RAM, _report_offset("status_raw_before_clear"))
            asm.bne(7, 0, f"_source_{source_id}_status_recorded")
            asm.sw(6, _RAM, _report_offset("status_raw_before_clear"))
            asm.label(f"_source_{source_id}_status_recorded")
        else:
            asm.sw(6, _RAM, _report_offset("status_raw_before_clear"))
        asm.li32(7, int(setup["cause_mask"]))
        asm.and_(6, 6, 7)
        if len(active_sources) > 1:
            asm.lw(7, _RAM, _report_offset("cause_before_clear"))
            asm.bne(7, 0, f"_source_{source_id}_cause_recorded")
            asm.sw(6, _RAM, _report_offset("cause_before_clear"))
            asm.label(f"_source_{source_id}_cause_recorded")
        else:
            asm.sw(6, _RAM, _report_offset("cause_before_clear"))
        if setup["clear_kind"] == "write_1_to_clear":
            add(f"clear: write 0x{int(setup['clear_mask']):08x} to "
                f"{setup['clear_register']} (0x{int(setup['clear_offset']):02x}), the "
                f"declared write-1-to-clear operation")
            asm.li32(7, int(setup["clear_mask"]))
            asm.sw(7, 28, int(setup["clear_offset"]))
        else:
            add(f"clear: read {setup['clear_register']} "
                f"(0x{int(setup['clear_offset']):02x}), the declared read-clears operation")
            asm.lw(29, 28, int(setup["clear_offset"]))
        asm.lw(6, 28, int(setup["status_offset"]))
        if len(active_sources) > 1:
            asm.lw(7, _RAM, _report_offset("status_raw_after_clear"))
            asm.bne(7, 0, f"_source_{source_id}_status_after_recorded")
            asm.sw(6, _RAM, _report_offset("status_raw_after_clear"))
            asm.label(f"_source_{source_id}_status_after_recorded")
        else:
            asm.sw(6, _RAM, _report_offset("status_raw_after_clear"))
        asm.li32(7, int(setup["cause_mask"]))
        asm.and_(6, 6, 7)
        if len(active_sources) > 1:
            asm.lw(7, _RAM, _report_offset("cause_after_clear"))
            asm.bne(7, 0, f"_source_{source_id}_cause_after_recorded")
            asm.sw(6, _RAM, _report_offset("cause_after_clear"))
            asm.label(f"_source_{source_id}_cause_after_recorded")
        else:
            asm.sw(6, _RAM, _report_offset("cause_after_clear"))
        add(f"COMPLETE with the claimed id {source_id}, then read IN_SERVICE to show "
            f"the controller left service")
        asm.li32(6, source_id)
        asm.sw(6, _CTRL, int(controller["offsets"]["COMPLETE"]))
        asm.lw(6, _CTRL, int(controller["offsets"]["IN_SERVICE"]))
        asm.sw(6, _RAM, _report_offset("final_in_service"))
        asm.li32(7, 1)
        asm.beq(6, 0, f"_complete_ok_{source_id}")
        asm.li32(7, 0)
        asm.label(f"_complete_ok_{source_id}")
        asm.sw(7, _RAM, _report_offset("complete_accepted"))
        asm.lw(6, _CTRL, int(controller["offsets"]["PENDING0"]))
        asm.sw(6, _RAM, _report_offset("pending_word_after_complete"))
        # Count every successful claim/complete pair.  In multi-source mode
        # ``loop_closed`` is asserted only after all requested source ids have
        # completed; a single-source program keeps its original behaviour.
        asm.lw(6, _RAM, _report_offset("interrupt_completions"))
        asm.addi(6, 6, 1)
        asm.sw(6, _RAM, _report_offset("interrupt_completions"))
        if len(active_sources) > 1:
            asm.li32(7, len(active_sources))
            asm.bne(6, 7, f"_source_{source_id}_not_all_closed")
            add("all requested sources completed: mark the multi-source loop closed")
            asm.li32(7, 1)
            asm.sw(7, _RAM, _report_offset("all_sources_closed"))
            asm.sw(7, _RAM, _report_offset("loop_closed"))
            asm.label(f"_source_{source_id}_not_all_closed")
        else:
            add("the loop closed: flag the completion and mark the closed loop")
            asm.li32(6, 1)
            asm.sw(6, _RAM, _report_offset("all_sources_closed"))
            asm.sw(6, _RAM, _report_offset("loop_closed"))
        asm.li32(6, COMPLETION_FLAG)
        asm.li32(7, flag_address)
        asm.sw(6, 7, 0)
        asm.jal(0, "_irq_return")

    asm.label("_irq_return")
    for index, register in enumerate(HANDLER_SAVED_REGISTERS):
        asm.lw(register, 2, 4 * index)
    asm.addi(2, 2, 4 * len(HANDLER_SAVED_REGISTERS))
    asm.mret()

    asm.label("_exception")
    add("exception path: count it, record mcause and skip the faulting 32-bit instruction. "
        "The count is what lets the software phase prove a declared register access did not "
        "trap the CPU, instead of only observing the last cause")
    asm.lw(6, _RAM, _report_offset("exception_count"))
    asm.addi(6, 6, 1)
    asm.sw(6, _RAM, _report_offset("exception_count"))
    asm.csrr(6, MEPC)
    asm.addi(6, 6, 4)
    asm.csrw(MEPC, 6)
    asm.csrr(7, MCAUSE)
    asm.sw(7, _RAM, _report_offset("error_cause"))
    asm.mret()
    return asm


def _report_offset(name: str) -> int:
    for field, offset in REPORT_FIELDS:
        if field == name:
            return offset
    _error(f"unknown-report-field:{name}")


def image_hex(image: bytes) -> str:
    """The ``$readmemh`` text of a byte image (one byte per line)."""
    if not isinstance(image, bytes):
        _error("image-must-be-bytes")
    return "".join(f"{byte:02x}\n" for byte in image)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_boot_program(plan: CompositionPlan, *,
                       request: ProgramRequest = ProgramRequest(),
                       isr: bool = True) -> BootProgram:
    """Generate the boot/ISR program for one composed SoC plan."""
    if not isinstance(plan, CompositionPlan):
        _error("composition-plan-required")
    if not isinstance(request, ProgramRequest):
        _error("program-request-required")
    for name in ("enable_interrupts", "exercise_all_sources", "stagger_sources", "trigger_event", "expect_error_access",
                 "verify_peripherals", "probe_permissions"):
        if not isinstance(getattr(request, name), bool):
            _error(f"program-request-field-not-a-bool:{name}")
    if not isinstance(isr, bool):
        _error("isr-flag-not-a-bool")
    if not isr and request.enable_interrupts:
        _error("interrupts-enabled-without-isr")
    if request.stagger_sources and not request.exercise_all_sources:
        _error("stagger-sources-requires-exercise-all-sources")

    instance, contract = _cpu(plan)
    isa = _check_isa(contract)
    entry = int(contract.reset_vector)
    rom = _executable_region(plan, entry)
    rom_base = int(rom["base"])
    rom_size = int(rom["size"])
    ram = _writable_region(plan)
    ram_base = int(ram["base"])
    stack_pointer = (ram_base + int(ram["size"])) & ~0xF
    flag_address = ram_base + FLAG_OFFSET
    report_address = ram_base + REPORT_OFFSET
    if REPORT_OFFSET + REPORT_BYTES > RAM_READBACK_BYTES:
        _error("report-record-outside-the-runtime-readback-window")

    controller = _controller(plan)
    setups, gaps = _source_setups(plan, controller)
    if isr and not setups:
        _error("no-interrupt-sources:the plan declares no interrupt source, so no ISR is "
               "generated; pass isr=False for a boot-only program")

    trigger_source = None
    trigger = None
    active_sources: list[dict] = []
    if isr:
        candidates: list[tuple[dict, dict]] = []
        for setup in setups:
            candidate = _trigger_for(plan, plan.instance(str(setup["instance_id"])),
                                     int(setup["source_id"]),
                                     setup.get("raise_actions", ()))
            if candidate is not None:
                candidates.append((setup, candidate))
        if request.exercise_all_sources:
            missing = [str(setup["instance_id"]) for setup in setups
                       if not any(setup is item[0] for item in candidates)]
            if missing:
                _error("multi-source-trigger-undeclared:" + ",".join(missing))
            if not candidates:
                _error("trigger-cause-undeclared:no declared source has an external input pin "
                       "the runtime can drive and no MMIO cause operation is declared")
            active_sources = [setup for setup, _ in candidates]
            trigger_source = active_sources[0]
            trigger = _combine_triggers(
                [candidate for _, candidate in candidates],
                stagger=request.stagger_sources)
        else:
            if candidates:
                trigger_source, trigger = candidates[0]
                active_sources = [trigger_source]
            else:
                _error("trigger-cause-undeclared:no declared source has an external input pin "
                       "the runtime can drive and no MMIO cause operation is declared")
        if trigger is not None and not request.trigger_event:
            trigger = dict(trigger)
            trigger["applied"] = False
            for event in trigger["events"]:
                event["applied"] = False
            for event in trigger.get("peer_events", ()):
                event["applied"] = False

    error_address = _unmapped_address(plan) if request.expect_error_access else None

    # The declared-register phase.  The two faulting checks (the direction
    # probes and the ROM write) need the generated trap handler to record the
    # cause, so a boot-only program leaves them out and says so in the document.
    permission_probes = bool(isr and request.probe_permissions)
    software = _software_plan(plan, faulting_checks=permission_probes) \
        if request.verify_peripherals else _disabled_software_plan(
            "verify_peripherals is false in the request")
    rom_region = _rom_write_region(plan, entry) \
        if (request.verify_peripherals and permission_probes) else None
    if permission_probes and rom_region is None:
        software["notes"].append(
            "the plan declares no executable, non-writable region, so the ROM-write check "
            "is not emitted; there is no image the plan claims is read-only")
    software["rom_check"] = None if rom_region is None else {
        "region_id": str(rom_region["region_id"]),
        "base": int(rom_region["base"]),
        "size": int(rom_region["size"]),
        "access": "store",
        "offset": 0,
        "address": int(rom_region["base"]),
        "value": _writeback_pattern(4, 0xFFFF_FFFF),
        "declared_permissions": dict(rom_region.get("permissions") or {}),
        "expected_exception": "store/AMO access fault (mcause 7)",
    }
    software["enabled"] = bool(request.verify_peripherals
                               and (software["totals"]["registers"] or rom_region))
    software["checks"] = {
        "faulting_checks_enabled": permission_probes,
        "init": bool(request.verify_peripherals),
        "read": bool(request.verify_peripherals),
        "writeback": bool(request.verify_peripherals),
        "side_effect": bool(request.verify_peripherals),
        "status": bool(request.verify_peripherals),
        "permission_probes": permission_probes,
        "rom_write": rom_region is not None,
    }

    # The body starts at the pinned {vector[31:8], 8'h80} entry; a jump at the
    # declared vector forwards a CPU that fetches there instead.  Neither path
    # is selected by CPU name.
    hw_entry = (entry & ~0xFF) | ENTRY_OFFSET
    if hw_entry < entry:
        _error(f"entry-vector-convention-unsupported:0x{entry:x}")
    if not (rom_base <= entry and hw_entry + 4 <= rom_base + rom_size):
        _error(f"entry-outside-the-executable-region:0x{entry:x}")

    def _assemble(handler_address: int):
        asm = _emit(plan, request=request, isr=isr, handler_address=handler_address,
                    rom_base=rom_base, body_base=hw_entry, entry=entry,
                    stack_pointer=stack_pointer, flag_address=flag_address,
                    report_address=report_address, controller=controller, setups=setups,
                    active_sources=active_sources,
                    trigger=trigger, trigger_source=trigger_source,
                    error_address=error_address, software=software, rom_region=rom_region)
        return asm

    # The handler address is materialised by li32, whose instruction count
    # depends on the constant, so the emission is iterated to a fixed point
    # instead of assuming one pass.
    if isr:
        handler_address = 0
        for _ in range(8):
            asm = _assemble(handler_address)
            asm.assemble()
            resolved = hw_entry + asm.labels["_vectors"] * 4
            if resolved == handler_address:
                break
            handler_address = resolved
        else:
            _error("handler-address-did-not-converge")
        if handler_address % VECTOR_ALIGNMENT:
            _error(f"trap-vector-table-misaligned:0x{handler_address:x}")
    else:
        handler_address = 0
        asm = _assemble(0)
    body_words = asm.assemble()

    pad_words = (hw_entry - rom_base) // 4
    if (hw_entry - rom_base) % 4:
        _error("entry-not-word-aligned")
    trampoline = _enc_j(hw_entry - entry, 0, 0x6F)
    program_words = [trampoline] + [0] * (pad_words - 1) + body_words

    image = b"".join(word.to_bytes(4, "little") for word in program_words)
    if len(image) > MAX_PROGRAM_BYTES:
        _error(f"program-exceeds-bound:{len(image)}>{MAX_PROGRAM_BYTES}")
    if len(image) > rom_base + rom_size - rom_base:
        _error(f"program-exceeds-region:{len(image)}>{rom_size}")
    if report_address + REPORT_BYTES > ram_base + int(ram["size"]):
        _error("report-record-outside-ram")

    steps = _steps(plan=plan, entry=entry, hw_entry=hw_entry, handler_address=handler_address,
                   stack_pointer=stack_pointer, flag_address=flag_address,
                   report_address=report_address, controller=controller, setups=setups,
                   active_sources=active_sources,
                   trigger=trigger, trigger_source=trigger_source, request=request, isr=isr,
                   error_address=error_address, software=software)
    observations = _promises(request=request, isr=isr, setups=setups,
                             active_sources=active_sources,
                             trigger_source=trigger_source, controller=controller,
                             flag=COMPLETION_FLAG, software=software)
    document = _document(plan=plan, contract=contract, instance=instance, asm=asm, entry=entry,
                         hw_entry=hw_entry, handler_address=handler_address, rom=rom, ram=ram,
                         stack_pointer=stack_pointer, flag_address=flag_address,
                         report_address=report_address, controller=controller, setups=setups,
                         active_sources=active_sources,
                         trigger=trigger, request=request, isr=isr, steps=steps,
                         observations=observations, error_address=error_address, gaps=gaps,
                         isa=isa, software=software)
    return BootProgram(entry_address=entry, image=image, flag_address=flag_address,
                       report_address=report_address, observations=observations,
                       steps=steps, document=document)


def _software_promises(software: Mapping[str, object],
                       request: ProgramRequest) -> dict[str, int]:
    """The software phase's plan-derived promises.

    Only what the plan and the declarations make deterministic is promised: how
    many accesses the phase performs, that no declared register access trapped,
    and what the plan's own read-only region must do with a store.  The observed
    outcomes (which side effect confirmed, which direction probe really errored)
    are recorded in the report but deliberately not promised, because they are
    properties of the target the run is meant to measure.
    """
    totals = dict(software["totals"])  # type: ignore[arg-type]
    checks = dict(software["checks"])  # type: ignore[arg-type]
    promises: dict[str, int] = {
        "software_phase": 1 if software["enabled"] else 0,
        "software_registers": int(totals["registers"]),
        "software_skipped": len(software["skipped"]),  # type: ignore[arg-type]
        "software_init_writes": int(totals["init_writes"]),
        "software_reads": int(totals["reads"]),
        "software_read_traps": 0,
        "software_traps": 0,
        "software_writeback_checks": int(totals["writebacks"]),
        "software_writeback_matches": int(totals["writebacks"]),
        "software_side_effects": int(totals["side_effects"]),
        "software_status_checks": int(totals["status_checks"]),
        "software_unchecked": int(totals["unchecked"]),
        "permission_probes": int(totals["probes"]) if checks["permission_probes"] else 0,
        "permission_unchecked": int(totals["probe_unchecked"]),
        "rom_write_requested": 0,
        "rom_write_cause": 0,
        "rom_unchanged": 0,
    }
    if software["rom_check"] is not None and software["enabled"]:
        promises.update({"rom_write_requested": 1, "rom_write_cause": 7, "rom_unchanged": 1})
    if request.expect_error_access:
        promises["unmapped_store_cause"] = 7
    return promises


def _promises(*, request: ProgramRequest, isr: bool, setups: Sequence[Mapping[str, object]],
              active_sources: Sequence[Mapping[str, object]],
              trigger_source: Mapping[str, object] | None, controller: dict | None,
              flag: int, software: Mapping[str, object]) -> dict[str, int]:
    """The values the program promises to have written when the run is read back."""
    count = len(setups)
    promises: dict[str, int] = {"completion_flag": flag}
    promises.update(_software_promises(software, request))
    promises.update({"interrupt_completions": 0,
                     "all_sources_closed": 0,
                     })
    if controller is not None:
        # The program reads SOURCE_COUNT over the bus and records it; a plan
        # without a controller has no such register to read.
        promises["source_count"] = count
    if not isr:
        # Boot-only program: no handler, no claim, no interrupt words written.
        promises.update({
            "claim_id": 0, "handler_entries": 0, "complete_accepted": 0,
            "final_in_service": 0, "loop_closed": 0, "unknown_claim": 0,
            "pending_before_claim": 0, "cause_before_clear": 0, "cause_after_clear": 0,
            "main_completed": 1,
        })
        return promises
    if trigger_source is None:
        # Interrupt program without an applied trigger: nothing may be claimed.
        promises.update({
            "claim_id": 0, "handler_entries": 0, "complete_accepted": 0,
            "final_in_service": 0, "loop_closed": 0, "unknown_claim": 0,
            "pending_before_claim": 0, "cause_before_clear": 0, "cause_after_clear": 0,
            "status_latched_by_poll": 0,
        })
        return promises
    source_id = int(trigger_source["source_id"])
    multi_source = len(active_sources) > 1
    if not request.trigger_event:
        # The trigger is not applied, so nothing may become pending and nothing
        # may be claimed; the poll is expected to time out.
        promises.update({
            "claim_id": 0, "handler_entries": 0, "complete_accepted": 0,
            "final_in_service": 0, "loop_closed": 0, "unknown_claim": 0,
            "pending_before_claim": 0, "cause_before_clear": 0, "cause_after_clear": 0,
            "status_latched_by_poll": 0, "main_completed": 1,
        })
        return promises
    if request.enable_interrupts:
        # The closed loop: the one enabled source pends, is claimed by id, its
        # declared cause is observed, the declared clear empties it and COMPLETE
        # retires the id.
        promises.update({
            "claim_id": source_id,
            "handler_entries": len(active_sources) if multi_source else 1,
            "complete_accepted": 1,
            "final_in_service": 0,
            "loop_closed": 1,
            "unknown_claim": 0,
            "pending_before_claim": int(trigger_source["controller_enable_mask"]),
            "cause_before_clear": int(trigger_source["cause_mask"]),
            "cause_after_clear": 0,
            "interrupt_completions": len(active_sources),
            "all_sources_closed": 1,
            "main_completed": 1,
        })
        return promises
    # Controller ENABLE left at its reset value: the source is sampled and pends
    # but can neither notify nor be claimed, while the CPU still sees both the
    # peripheral condition and the controller's pending bit.
    promises.update({
        "claim_id": 0, "handler_entries": 0, "complete_accepted": 0,
        "final_in_service": 0, "loop_closed": 0, "unknown_claim": 0,
        "pending_before_claim": 0, "cause_before_clear": 0, "cause_after_clear": 0,
        "status_latched_by_poll": int(trigger_source["cause_mask"]),
        "pending_seen_by_main": int(trigger_source["controller_enable_mask"]),
        "main_completed": 1,
    })
    return promises


def _steps(*, plan: CompositionPlan, entry: int, hw_entry: int, handler_address: int,
           stack_pointer: int, flag_address: int, report_address: int, controller: dict | None,
           setups: Sequence[Mapping[str, object]],
           active_sources: Sequence[Mapping[str, object]],
           trigger: Mapping[str, object] | None,
           trigger_source: Mapping[str, object] | None, request: ProgramRequest, isr: bool,
           error_address: int | None, software: Mapping[str, object]) -> tuple[str, ...]:
    steps: list[str] = [
        f"entry: the CPU profile declares reset vector 0x{entry:08x}; the body is at "
        f"0x{hw_entry:08x} (pinned fetch convention {{vector[31:8], 8'h80}}) and a jump at "
        f"the declared vector forwards a CPU that fetches at the vector itself",
        f"stack: sp = 0x{stack_pointer:08x} (top of the writable RAM region)",
    ]
    if not isr:
        steps.append("interrupt program omitted (isr=False): no mtvec, no ISR, no enables")
    else:
        steps.append(
            f"cpu: mtvec = 0x{handler_address:08x} ({VECTOR_ENTRIES} one-word jumps to the "
            f"shared handler at 0x{handler_address + VECTOR_ALIGNMENT:08x}) is installed "
            f"before the first bus access, so an unexpected fault is recorded in the report "
            f"record instead of restarting through the CPU's reset vector")
        for setup in setups:
            steps.append(
                f"peripheral setup for source {setup['source_id']} "
                f"({setup['instance_id']} at 0x{int(setup['base']):08x}): set "
                f"{setup['enable_register']} (offset 0x{int(setup['enable_offset']):02x}) "
                f"bit {setup['enable_bit']}")
            for prerequisite in setup.get("prerequisites", ()):
                steps.append(
                    f"source {setup['source_id']} prerequisite: set "
                    f"{prerequisite['register']} mask 0x{int(prerequisite['mask']):08x} "
                    f"before the trigger ({prerequisite['reason']})")
            for action in setup.get("raise_actions", ()):
                steps.append(
                    f"source {setup['source_id']} raise action: write "
                    f"{action['register']} = 0x{int(action['value']):08x} "
                    f"({action['reason']})")
        if request.enable_interrupts and controller is not None and active_sources:
            if len(active_sources) > 1:
                ids = ",".join(str(int(item["source_id"])) for item in active_sources)
                steps.append(
                    f"controller setup: {controller['instance_id']} at "
                    f"0x{int(controller['base']):08x}, enable all requested source ids "
                    f"{ids}; mie.MEIE and mstatus.MIE set")
            else:
                steps.append(
                    f"controller setup: {controller['instance_id']} at "
                    f"0x{int(controller['base']):08x}, {_enable_name(controller, active_sources[0])} "
                    f"(offset 0x{int(active_sources[0]['controller_enable_offset']):02x}) = "
                    f"0x{int(active_sources[0]['controller_enable_mask']):08x}; mie.MEIE and "
                    f"mstatus.MIE set")
        else:
            steps.append(
                f"interrupt delivery disabled by request: the controller's ENABLE stays at "
                f"its reset value 0 and the CPU stays masked; the handler and mtvec are "
                f"still installed")
    if error_address is not None:
        steps.append(f"error scenario: load 0x{error_address:08x} (no declared window "
                     f"decodes it) and record the exception cause, then store to the same "
                     f"undecoded address and record that cause too")
    if isr and trigger_source is not None:
        trigger_kind = str(trigger.get("kind", "external_event_plan")) if trigger else \
            "external_event_plan"
        if trigger_kind == "peer_event_plan":
            trigger_action = "the declared peer payload events"
        elif trigger_kind == "combined_event_plan":
            trigger_action = "the declared external and peer payload events"
        else:
            trigger_action = "the recorded external events"
        steps.append(
            f"trigger: {'apply' if request.trigger_event else 'do NOT apply'} "
            f"{trigger_action}; the program performs no trigger MMIO write "
            f"({trigger['basis'] if trigger else ''})")
        steps.append(
            f"wait: bounded poll ({POLL_ITERATIONS} iterations) of "
            f"{trigger_source['instance_id']} {trigger_source['status_register']} "
            f"(offset 0x{int(trigger_source['status_offset']):02x}) for cause bit "
            f"{trigger_source['cause_bit']}, then the controller's PENDING word")
        steps.append(
            f"isr: read PENDING then CLAIM (offset "
            f"0x{int(controller['offsets']['CLAIM']):02x}); a zero id returns without "
            f"completing, a non-zero id is matched against the plan's source table "
            f"(source id -> instance)")
        steps.append("isr: read the peripheral status, perform the profile's declared clear "
                     "operation, then write COMPLETE with the claimed id and read IN_SERVICE")
        if len(active_sources) > 1:
            steps.append("isr multi-source ledger: repeat claim/dispatch/clear/COMPLETE until "
                         "every requested source id has completed")
        steps.append(f"isr context: x5-x7 and x28-x31 are saved on the stack at handler entry "
                     f"and restored before mret, so the interrupted flow is not corrupted")
    steps.append(f"report: completion flag 0x{COMPLETION_FLAG:08x} at 0x{flag_address:08x}, "
                 f"observation record at 0x{report_address:08x} inside the first "
                 f"0x{RAM_READBACK_BYTES:x} bytes of RAM")
    if software["enabled"]:
        totals = dict(software["totals"])  # type: ignore[arg-type]
        steps.append(
            f"software: the declared-register phase runs after the wait, driven only by the "
            f"bound profiles' register declarations - {totals['init_writes']} declared "
            f"initialisation write(s), {totals['reads']} declared readable register read(s), "
            f"{totals['writebacks']} write+read-back comparison(s), "
            f"{totals['side_effects']} declared clear/side-effect check(s), "
            f"{totals['status_checks']} declared status re-read(s), "
            f"{totals['probes']} direction probe(s)")
    elif request.verify_peripherals:
        steps.append("software: the declared-register phase is enabled but the plan declares "
                     "no register to check and no read-only image, so it emits nothing")
    else:
        steps.append("software: the declared-register phase is switched off by the request")
    steps.append("spin: the program never leaves the final loop")
    return tuple(steps)


def _enable_name(controller: Mapping[str, object], trigger_source: Mapping[str, object]) -> str:
    """The ENABLE word that carries the trigger source's own bit."""
    return f"ENABLE{int(trigger_source['source_id']) // 32}"


def _document(*, plan: CompositionPlan, contract, instance, asm: _ProgramAssembler, entry: int,
              hw_entry: int, handler_address: int, rom: Mapping[str, object],
              ram: Mapping[str, object], stack_pointer: int, flag_address: int,
              report_address: int, controller: dict | None,
              setups: Sequence[Mapping[str, object]],
              active_sources: Sequence[Mapping[str, object]],
              trigger: Mapping[str, object] | None,
              request: ProgramRequest, isr: bool, steps: Sequence[str],
              observations: Mapping[str, int], error_address: int | None,
              gaps: Sequence[str], isa: Mapping[str, object],
              software: Mapping[str, object]) -> dict[str, object]:
    words = asm.assemble()
    listing = asm.listing(hw_entry)
    return {
        "schema_version": PROGRAM_SCHEMA,
        "plan_hash": plan.plan_hash,
        "request_id": plan.request_id,
        "request": {
            "enable_interrupts": request.enable_interrupts,
            "exercise_all_sources": request.exercise_all_sources,
            "stagger_sources": request.stagger_sources,
            "trigger_event": request.trigger_event,
            "expect_error_access": request.expect_error_access,
            "verify_peripherals": request.verify_peripherals,
            "probe_permissions": request.probe_permissions,
            "isr": isr,
        },
        "isa": {
            "family": str(contract.family),
            "xlen": int(contract.xlen),
            "extensions": [str(item) for item in contract.extensions],
            "compressed_supported": isa["compressed_supported"],
            "compressed_encodings": False,
            "privilege": "machine",
            "provenance": f"component_profile:{instance.component_id}",
        },
        "entry": {
            "reset_vector": entry,
            "hardware_entry": hw_entry,
            "handler_address": handler_address if isr else None,
            "isr_address": (handler_address + VECTOR_ALIGNMENT) if isr else None,
            "vector_table": ({
                "base": handler_address,
                "entries": VECTOR_ENTRIES,
                "alignment": VECTOR_ALIGNMENT,
                "convention": ("every entry jumps to the shared handler, so a direct-mode "
                               "base entry, a vectored base + 4*cause entry and a "
                               "capability trap vector all reach it; the CPU profile "
                               "declares no trap-vector convention"),
            } if isr else None),
            "rom_region_id": str(rom["region_id"]),
            "rom_base": int(rom["base"]),
            "image_bytes": len(words) * 4 + (hw_entry - entry),
            "image_anchored_at": int(rom["base"]),
            "trampoline": "jal x0, +0x%x at the declared vector" % (hw_entry - entry),
        },
        "memory": {
            "ram_region_id": str(ram["region_id"]),
            "ram_base": int(ram["base"]),
            "ram_size": int(ram["size"]),
            "stack_pointer": stack_pointer,
            "flag_address": flag_address,
            "report_address": report_address,
            "report_bytes": REPORT_BYTES,
            "readback_bytes": RAM_READBACK_BYTES,
        },
        "report": {
            "layout": [{"name": name, "offset": offset,
                        "address": report_address + offset,
                        "promised": name in observations}
                       for name, offset in REPORT_FIELDS],
            "observations": {name: int(value) for name, value in observations.items()},
        },
        "controller": None if controller is None else {
            "instance_id": controller["instance_id"],
            "base": controller["base"],
            "size": controller["size"],
            "num_sources": controller["num_sources"],
            "registers_used": {name: controller["offsets"][name] for name in
                               ("CLAIM", "COMPLETE", "IN_SERVICE", "SOURCE_COUNT",
                                "PENDING0", "ENABLE0")},
            "register_map_source": "plan.interrupt_document.controller.register_map",
        },
        "sources": [
            {
                "source_id": setup["source_id"],
                "instance_id": setup["instance_id"],
                "component_id": setup["component_id"],
                "target_id": setup["target_id"],
                "window_base": setup["base"],
                "enable": {"register": setup["enable_register"],
                           "offset": setup["enable_offset"],
                           "bit": setup["enable_bit"],
                           "side_effect": "none",
                           "operation": "read-modify-write to set only the declared bit"},
                "status": {"register": setup["status_register"],
                           "offset": setup["status_offset"],
                           "cause_bit": setup["cause_bit"]},
                "clear": {"kind": setup["clear_kind"], "register": setup["clear_register"],
                          "offset": setup["clear_offset"], "bit": setup["clear_bit"],
                          "declared": setup["clear_text"]},
                "prerequisites": [dict(item) for item in setup.get("prerequisites", ())],
                "raise_actions": [dict(item) for item in setup.get("raise_actions", ())],
                "hold": setup["hold"],
                "controller_enable": {
                    "offset": setup["controller_enable_offset"],
                    "mask": setup["controller_enable_mask"],
                           "enabled": bool(any(
                               int(item["source_id"]) == int(setup["source_id"])
                               for item in active_sources)
                                    and request.enable_interrupts and isr),
                },
            }
            for setup in setups
        ],
        "trigger": None if trigger is None else {
            "kind": trigger["kind"],
            "source_id": trigger["source_id"],
            "source_ids": list(trigger.get("source_ids", [trigger["source_id"]])),
            "instance_id": trigger["instance_id"],
            "instance_ids": list(trigger.get("instance_ids", [trigger["instance_id"]])),
            "staggered": bool(trigger.get("staggered", False)),
            "pins": list(trigger["pins"]),
            "events": [dict(event) for event in trigger["events"]],
            "peer_events": [dict(event) for event in trigger.get("peer_events", ())],
            "source_kinds": list(trigger.get("source_kinds", (trigger["kind"],))),
            "applied": bool(request.trigger_event),
            "mmio_writes": [dict(action) for action in trigger.get("mmio_writes", ())],
            "basis": trigger["basis"],
        },
        "enablement": {
            "peripheral_enable_written": bool(isr),
            "controller_enable_written": bool(isr and request.enable_interrupts),
            "cpu_enable_written": bool(isr and request.enable_interrupts),
        },
        "error_scenario": None if error_address is None else {
            "access": "load",
            "address": error_address,
            "recorded_at": report_address + _report_offset("error_cause"),
            "expected_exception": "load access fault (mcause 5)",
            # The same undecoded address is also stored to, so the store half of
            # the requirement is recorded separately and the existing load
            # fields keep their exact meaning.
            "store_access": "store",
            "store_address": error_address,
            "store_recorded_at": report_address + _report_offset("unmapped_store_cause"),
            "store_value": _writeback_pattern(4, 0xFFFF_FFFF),
            "store_expected_exception": "store/AMO access fault (mcause 7)",
        },
        "software": {
            "schema_version": SOFTWARE_SCHEMA,
            "enabled": bool(software["enabled"]),
            "phase": ("after the main flow's wait and before the final spin, so the declared "
                      "register accesses cannot perturb the interrupt-source state the loop "
                      "depends on"),
            "checks": dict(software["checks"]),  # type: ignore[arg-type]
            "totals": dict(software["totals"]),  # type: ignore[arg-type]
            "peripherals": [dict(item) for item in software["peripherals"]],  # type: ignore[arg-type]
            "skipped": [dict(item) for item in software["skipped"]],  # type: ignore[arg-type]
            "notes": list(software["notes"]),  # type: ignore[arg-type]
            "status_overflow": int(software["status_overflow"]),
            "status_slots": SOFTWARE_STATUS_SLOTS,
            "mask_bits": SOFTWARE_MASK_BITS,
            "permission_probes": [dict(item)
                                  for item in software["permission_probes"]],  # type: ignore[arg-type]
            "rom_check": (None if software["rom_check"] is None
                          else dict(software["rom_check"])),  # type: ignore[arg-type]
            "result_fields": {
                "writeback_mask": report_address + _report_offset("software_writeback_mask"),
                "side_effect_mask": report_address + _report_offset("software_side_effect_mask"),
                "permission_error_mask":
                    report_address + _report_offset("permission_error_mask"),
                "status": [report_address + _report_offset(f"status_{index}")
                           for index in range(SOFTWARE_STATUS_SLOTS)],
            },
        },
        "steps": list(steps),
        "gaps": list(gaps),
        "program_words": len(words) + (hw_entry - entry) // 4,
        "body_words": len(words),
        "listing": listing,
    }


__all__ = [
    "BootProgram",
    "BootProgramError",
    "COMPLETION_FLAG",
    "FLAG_OFFSET",
    "MAX_PROGRAM_BYTES",
    "POLL_ITERATIONS",
    "PROGRAM_SCHEMA",
    "ProgramRequest",
    "RAM_READBACK_BYTES",
    "REPORT_BYTES",
    "REPORT_FIELDS",
    "REPORT_OFFSET",
    "SOFTWARE_MASK_BITS",
    "SOFTWARE_SCHEMA",
    "SOFTWARE_STATUS_SLOTS",
    "TRIGGER_HIGH_CYCLE",
    "TRIGGER_LOW_CYCLE",
    "build_boot_program",
    "image_hex",
]
