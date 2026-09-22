"""Task D of the RFuzz input chain: the real-RTL gate, with its contract frozen.

Roadmap phase 1's real-RTL gate makes two claims that a projection-level test
cannot make, because a projector only *decides* what to drive:

* **D1 -- CPU execution.**  Changing an instruction candidate and changing a data
  candidate must change what the real CPU really asks the fabric to do.  The
  evidence is the CPU's own transactions: ``RunResult.requests`` is the harness's
  capture of the DUT's *write* transactions (reads are not in it), and
  ``RunResult.responses`` is the address-attributed capture of every fabric
  completion, so a memory or register read is evidenced only there.  The same
  samples must round-trip through ``EvidencePackage`` and ``replay_package`` to
  an agreement.
* **D2 -- peer behaviour.**  Changing one peer raw field must change what the real
  peripheral really does, and the expectation must not be a success counter of
  the device or of its peer.  The expectation used here is the raw field the test
  itself set, observed as an address-attributed register read of the peripheral.

Why this file exists next to ``tests/integration/test_soc_input_transport_ab.py``:
that sibling module already measures single-field A/B pairs on these same real
plans (one changed ``init_data`` changes the Ibex's writes; one changed peer raw
field changes a component register), and the measurements here **corroborate**
it rather than claiming novelty.  What Task D adds is the *gate* framing: both
halves in one place, a contract frozen and asserted before any RTL is compiled,
one build per class so a behavioural difference can never come from a different
executable, the evidence-package/replay agreement for the CPU half, and an
explicit statement of what each expectation does and does not depend on.

The D1 program, and why the raw payloads look the way they do
-------------------------------------------------------------
A raw instruction candidate is not an encoding.  The reference ISA layer
(``myfuzz.isa.transducer``) reads the payload's **top eight bits as the selector**
of an operation, then rebuilds the word from that template's fixed bits plus the
payload's free bits.  The declared program is therefore written as payloads whose
selector *is* the operation the gate needs, and whose remaining bits are the
operands it wants:

* selector ``0x12`` is ``XORI`` (its selectors are ``0x10..0x14``); an I-type
  template keeps ``rd``/``rs1``/``imm[11:0]``, so ``0x1230_0293`` derives to
  ``xori x5, x0, 0x123`` -- the immediate is the fuzz value, and ``x0`` makes the
  xor the identity, so the value the program publishes is the value the field
  carried;
* selector ``0x6c`` is ``LW`` (``0x6c..0x70``) and carries ``imm[11:4]``, so a
  load reaches ``data_base + 0x6c0 .. +0x6ff``: the declared data slot is put at
  ``+0x6c0`` by the candidate-program policy;
* selector ``0x86`` is ``SW`` (``0x86..0x8a``) and carries ``imm[11:5]`` plus
  ``rs2[4]``, so store immediates are ``0x860..0x8bf``.  Every one of those is
  *negative* as a signed 12-bit immediate, which is why the stores are based on
  the prologue's stack pointer (``0x8001_0000``) instead of the data base and land
  at ``0x8000_f860`` / ``0x8000_f870`` inside RAM.

The harness places the data candidate **before the CPU is released**
(``image_placements[*]["reset_held"]`` and its ``readback`` are the memory the
CPU then fetches from), the program loads it from the declared data slot, and
publishes both candidates to RAM: the store of ``x6`` carries the data candidate
and the store of ``x5`` carries the instruction candidate's immediate.  Both are
CPU *write* transactions, so a one-field change is visible directly in
``RunResult.requests``.

The boot image is the recorded one ``test_soc_input_repair_runtime`` froze for
this plan (seven instruction slots, one data slot at ``+0x80``); its entry
trampoline and prologue are asserted below to be the plan-derived ones, and every
declared slot word it holds is replaced by the raw offers, so what the CPU
executes is the record and not the file.  A boot image that does not match the
plan leaves the CPU executing nothing, which is why the match is an assertion and
not an assumption.

The D2 independence argument
----------------------------
The expectation is the value the test wrote into the peer's raw field, and the
observation is the peripheral's own register returned for a read of one declared
address (an entry of ``RunResult.responses`` with ``write == 0``).  Neither side
is a success counter: the peer's own ``uart0__tx_sent_count_o`` is 1 in *both*
samples of the byte pair, so a counter-derived expectation could not tell them
apart -- it is recorded as corroboration only.  ``soc_peer_oracle.v1`` is cited
where it can judge something: ``peer-event-transport`` passes for every sample
(the peer event plan is empty and nothing was applied), which is what makes the
raw fields the attributable cause.  The oracle's ``uart-tx-sent-count`` check is
**not** a criterion for this route and the tests say so: it derives its
expectation from the declared event plan, which is empty, so it reports expected
0 against an observed 1 for a raw-driven frame that the register readback proves
correct.  Its wire-level checks (``uart-rx-wire``, ``gpio-resolution-wire``,
``spi-transfer-wire``, ``uart-framing-wire``, ``uart-timeout-wire``) are
``not_assessed`` because no waveform is recorded, and they are never claimed as
passing.

Gate mechanics
--------------
``MYFUZZ_SOC_REAL=1`` gates the real halves; when it is set nothing skips and a
missing dependency fails naming it.  Each real class compiles its SoC once in
``setUpClass`` into a ``.myfuzz-`` temporary directory under the repository root
and reuses it for every sample, so the executable is one artifact.  The measured
wall time is printed at the end of each build (one Ibex build is ~12 s, one peer
build ~6 s, a run is well under a second).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import time
import unittest
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.composition import soc_runtime
from myfuzz.composition.soc_candidate_program import (
    CandidateProgram,
    decode_word,
    encode_jal,
    encode_lw,
    encode_sw,
)
from myfuzz.composition.soc_failure_evidence import (
    REPLAY_AGREEMENT,
    build_evidence_package,
    identity_mismatches,
    read_evidence_package,
    recorded_build_identity,
    replay_package,
    write_evidence_package,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RunResult,
    RuntimeBuild,
    RuntimeSample,
    build_profile_runtime,
)

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_input_arms_projection import (
    arms_for,
    field_by_role,
    ibex_plan,
    peer_plan,
    put,
)
from tests.integration.test_soc_peer_models import (
    GPIO_DATA_IN,
    GPIO_DATA_OUT,
    GPIO_DIR,
    UART_CTRL,
    UART_PEER_BYTE,
    UART_RXDATA,
    UART_STATUS,
    _offer_word,
    _window_base,
)

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"

# ---------------------------------------------------------------------------
# D1: the real Ibex execution gate, frozen
# ---------------------------------------------------------------------------

#: The gate's run window.  The declared program is 28 bytes; the stores appear in
#: the first ~110 cycles.  The response trace then shows the CPU fetching the zero
#: words after the declared window and re-entering the entry trampoline, so the
#: same stores appear a second time; every assertion below is stated over the value
#: each address carries, so it holds for any number of identical passes.
CPU_CYCLES = 400
#: Seven instruction slots and one data slot, i.e. the shape the recorded boot
#: image was frozen with, so every declared slot word is replaced by the record.
CPU_INSTRUCTION_SLOTS = 7
#: The declared data slot offset.  It must be reachable through the LW selector
#: (``imm[11:4] = 0x6c``), which the pure contract test asserts.
DATA_SLOT_OFFSET = 0x6C0
#: The two store immediates.  They must be reachable through the SW selector
#: (``imm[11:5] = 0x43``, ``rs2[4] = 0``) and are negative 12-bit values.
STORE_DATA_OFFSET = 0x860
STORE_INSTRUCTION_OFFSET = 0x870
#: The instruction candidate payloads: one selector (``0x12`` -> XORI), two
#: immediates one low nibble apart, so the whole difference is the fuzz value.
INSTRUCTION_CANDIDATE_A = 0x1230_0293
INSTRUCTION_CANDIDATE_B = 0x12C0_0293
#: The data candidate values.  They are whole words and cannot be confused with
#: either immediate.
DATA_CANDIDATE_A = 0x1111_2222
DATA_CANDIDATE_B = 0x3333_4444
#: A payload the reference ISA layer leaves as ``addi x0, x0, 0``: the two
#: trailing slots and the whole program tail are deliberate no-ops.
NOP_PAYLOAD = 0x0000_0013
#: The cycle each candidate is offered in.  The overlay scans the whole buffered
#: record before it releases the CPU, so the position carries no meaning; the
#: offers are spread over consecutive cycles only so a diff is readable.
OFFER_CYCLE = 4
#: The recorded boot image ``test_soc_input_repair_runtime`` freezes for this
#: plan (used read-only when present) and this module's own fallback path.  The
#: fallback is deliberately not the other module's file: that file is its
#: fixture and this module must not rewrite it.
RECORDED_BOOT_IMAGE = ROOT / "runs/soc-input-repair-runtime/candidate_program.hex"
OWN_BOOT_IMAGE = ROOT / "runs/soc-input-real-rtl-gate/boot_program.hex"
BUILD_TIMEOUT_S = int(os.environ.get("MYFUZZ_SOC_REAL_RTL_GATE_BUILD_TIMEOUT_S", "1800"))

#: The frozen combined ABI of the CPU half: seven instruction candidates and one
#: data candidate over ``ibex_plan()``.  A layout change must fail this test on
#: purpose: an old corpus is only replayable against the mapping it was produced
#: with, and the D1 offsets depend on this width.
FROZEN_CPU_WIDTH = 555
#: The addresses the gate asserts on, derived (and re-derived in the pure test)
#: from the declared program's register bindings and the payloads' immediates.
DATA_SLOT_ADDRESS = 0x8000_06C0
STORE_DATA_ADDRESS = 0x8000_F860
STORE_INSTRUCTION_ADDRESS = 0x8000_F870

# ---------------------------------------------------------------------------
# D2: the real peer behaviour gate, frozen
# ---------------------------------------------------------------------------

#: The BFM offers one MMIO write of UART CTRL (rx/tx/irq enable) and reads the
#: peripheral's STATUS and RXDATA back; the peer drives a GPIO level across the
#: whole window.  Long enough for the frame and for every read to be captured.
PEER_CYCLES = 200
#: The UART byte pair: one field apart, so the two runs cannot produce the same
#: received byte by accident.
PEER_BYTE_A = UART_PEER_BYTE
PEER_BYTE_B = 0xC3
#: The GPIO drive pair.  ``pin_value_o`` is the peer's own view of the resolved
#: level, i.e. a peer-side observation rather than a counter.
GPIO_DRIVE_A = 0x05
GPIO_DRIVE_B = 0x3A
GPIO_DRIVE_VALID = 0xFF
#: The frozen peer half of the combined ABI: ``top port -> (raw_hi, raw_lo)`` for
#: the ``bfm_isolated`` composition with one instruction and one data candidate.
#: The layout stays the only source of truth; this table exists so a layout change
#: fails here instead of silently reinterpreting a saved corpus.
FROZEN_PEER_RAW = {
    "gpio0__peer_drive_value_i": (376, 369),
    "gpio0__peer_drive_valid_i": (384, 377),
    "spi0__tx_request_valid_i": (385, 385),
    "spi0__tx_request_data_i": (393, 386),
    "uart0__tx_request_valid_i": (394, 394),
    "uart0__tx_request_data_i": (402, 395),
}
FROZEN_PEER_WIDTH = 403

#: The independent judgement basis both halves are recorded with.  It is not the
#: profile that generated the stimulus alone: the CPU's transactions are read
#: against the declared program and the peripheral's register against the raw
#: field, and neither statement is derived from a device counter.
CPU_CRITERION = {
    "criterion_id": "raw-candidate-reaches-the-cpu-transaction",
    "statement": "the word a raw instruction/data candidate carries is placed before "
                 "the CPU is released and the CPU's own requests carry it",
    "basis": "src/myfuzz/composition/soc_candidate_program.py + soc_image.py "
             "(placement) checked against RunResult.requests/responses of the "
             "composed Ibex (examples/soc_generation/request-ibex.json)",
    "independent": True,
}
PEER_CRITERION = {
    "criterion_id": "raw-peer-field-reaches-the-peripheral-register",
    "statement": "the value a raw peer field carries is the value the peripheral under "
                 "test returns when its own register is read at its declared address",
    "basis": "src/myfuzz/protocols/rtl/soc_uart_peer.sv and soc_gpio_peer.sv "
             "(independent peer RTL) checked against the peripheral's "
             "address-attributed bus response, never against a peer counter",
    "independent": True,
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def immediate(word: int) -> int:
    """The I-type immediate of a 32-bit encoding: bits [31:20]."""
    return (word >> 20) & 0xFFF


def effective_address(base: int, offset: int) -> int:
    """``base`` plus the sign-extended 12-bit immediate of an I/S-type access."""
    signed = offset - 0x1000 if offset & 0x800 else offset
    return (base + signed) & 0xFFFF_FFFF


def image_words(path: Path, base: int) -> dict[int, int]:
    """The 32-bit words of a ``$readmemh`` byte image, keyed by absolute address.

    ``ImagePlan.write_hex`` writes one byte per line starting at the region base
    the plan declares, so the byte at file offset ``k`` is the byte at
    ``base + k``.
    """
    data = bytes(int(item, 16)
                 for item in Path(path).read_text(encoding="utf-8").split())
    return {base + offset: int.from_bytes(data[offset:offset + 4], "little")
            for offset in range(0, len(data) - 3, 4)}


def ibex_boot_image(program: CandidateProgram) -> Path:
    """The boot image the D1 gate starts the CPU from.

    The image ``test_soc_input_repair_runtime`` records is used when it exists: it
    is a working static image for exactly this plan, and a boot image that does not
    match the plan would leave the CPU executing nothing.  ``runs/`` is not part of
    the source tree, so a fresh checkout freezes this module's own program there
    instead -- the same plan-derived program shape, whose entry trampoline and
    prologue are the ones the pure contract test asserts.
    """
    if RECORDED_BOOT_IMAGE.is_file():
        return RECORDED_BOOT_IMAGE
    if not OWN_BOOT_IMAGE.is_file():
        OWN_BOOT_IMAGE.parent.mkdir(parents=True, exist_ok=True)
        program.image.write_hex(program.static_image(), OWN_BOOT_IMAGE)
    return OWN_BOOT_IMAGE


def candidate_word(layout, prefix: str, kind: str, *, address: int, payload: int,
                   byte_enable: int = 0xF) -> int:
    """One raw word that offers exactly one candidate slot.

    Field offsets come from the combined layout, never from a literal: a word
    this test calls legal is legal for the same reason one from a campaign is.
    """
    value_segment = "data" if kind == "instruction" else "value"
    raw = 0
    for segment, field_value in (("offer", 1), ("address", address),
                                 (value_segment, payload), ("be", byte_enable)):
        raw = put(raw, field_by_role(layout, "soc_image", f"{prefix}_{segment}"),
                  field_value)
    return raw


def cpu_program_words(program: CandidateProgram, layout, *,
                      instruction_payload: int, data_value: int) -> list[int]:
    """The D1 record's offers, one per cycle from :data:`OFFER_CYCLE` onwards.

    Every declared instruction slot is offered exactly once (the declared program
    requires it), and the data slot once.  The words are payloads, not encodings:
    see the module docstring for the selector arithmetic.
    """
    slots = list(program.slots.instruction)
    data_slot = program.slots.data[0]
    words = [
        # x5 = the instruction candidate's immediate (the fuzz value).
        candidate_word(layout, slots[0].prefix, "instruction",
                       address=slots[0].declared_address, payload=instruction_payload),
        # x6 = the data candidate, placed in the declared data slot pre-release.
        candidate_word(layout, slots[1].prefix, "instruction",
                       address=slots[1].declared_address,
                       payload=encode_lw(6, 3, DATA_SLOT_OFFSET)),
        # Publish the data candidate to RAM: a CPU write transaction.
        candidate_word(layout, slots[2].prefix, "instruction",
                       address=slots[2].declared_address,
                       payload=encode_sw(6, 2, STORE_DATA_OFFSET)),
        # Publish the instruction candidate's immediate: a CPU write transaction.
        candidate_word(layout, slots[3].prefix, "instruction",
                       address=slots[3].declared_address,
                       payload=encode_sw(5, 2, STORE_INSTRUCTION_OFFSET)),
        *[candidate_word(layout, slot.prefix, "instruction",
                         address=slot.declared_address, payload=NOP_PAYLOAD)
          for slot in slots[4:]],
        candidate_word(layout, data_slot.prefix, "data",
                       address=data_slot.declared_address, payload=data_value),
    ]
    return words


def cpu_record(arm, layout, program: CandidateProgram, *,
               instruction_payload: int, data_value: int) -> tuple[int, ...]:
    """The projected D1 record: what the harness really drives for one sample."""
    raw = [0] * CPU_CYCLES
    for index, word in enumerate(cpu_program_words(
            program, layout, instruction_payload=instruction_payload,
            data_value=data_value)):
        raw[OFFER_CYCLE + index] = word
    return tuple(int(item) for item in arm.project_records(raw))


def peer_field(layout, role: str, value: int) -> int:
    """One peer raw field of a raw word, at the layout's own offset."""
    return put(0, field_by_role(layout, "soc_peer", role), value)


def uart_peer_record(plan, layout, arm, *, byte: int, valid: int) -> tuple[int, ...]:
    """A BFM sample that enables the UART, offers one peer byte, then reads back.

    ``uart0__tx_request_*`` are the peer's request ports: a raw level on them is
    latched by the peer model itself, so a one-cycle level is exactly one offered
    byte.  The peer event plan stays empty, so which of the port's two declared
    drivers produced the frame is never in doubt.
    """
    raw = [0] * PEER_CYCLES
    raw[4] = _offer_word(plan, "uart0_win", UART_CTRL, 1, 0x7)
    raw[20] = peer_field(layout, "uart.tx_byte:tx_request_data_i", byte)
    if valid:
        raw[20] |= peer_field(layout, "uart.tx_byte:tx_request_valid_i", 1)
    raw[150] = _offer_word(plan, "uart0_win", UART_STATUS, 0)
    raw[170] = _offer_word(plan, "uart0_win", UART_RXDATA, 0)
    return tuple(int(item) for item in arm.project_records(raw))


def gpio_peer_record(plan, layout, arm, *, drive: int) -> tuple[int, ...]:
    """A BFM sample whose peer holds one drive level across the read.

    The component is configured as an input (DIR = 0, DATA_OUT = 0), so the
    resolved pin level is the peer's drive and the component's DATA_IN register
    samples exactly it.
    """
    raw = [0] * PEER_CYCLES
    raw[4] = _offer_word(plan, "gpio0_win", GPIO_DATA_OUT, 1, 0x00)
    raw[20] = _offer_word(plan, "gpio0_win", GPIO_DIR, 1, 0x00)
    held = (peer_field(layout, "gpio.drive:peer_drive_valid_i", GPIO_DRIVE_VALID)
            | peer_field(layout, "gpio.drive:peer_drive_value_i", drive))
    for cycle in range(30, PEER_CYCLES):
        raw[cycle] |= held
    raw[60] |= _offer_word(plan, "gpio0_win", GPIO_DATA_IN, 0)
    return tuple(int(item) for item in arm.project_records(raw))


def build_runtime(plan, image, *, output_dir: Path,
                  boot_image: Path | None = None) -> RuntimeBuild:
    """Compile one composition exactly the way the profile runtime path does."""
    return build_profile_runtime(
        plan, output_dir=output_dir, base_dir=ROOT,
        top_text=render_composition(plan)["myfuzz_soc_top.sv"],
        sources=[item["path"] for item in source_list(plan)
                 if item["role"] != "include_root"],
        boot_image=boot_image, image_plan=image, timeout_seconds=BUILD_TIMEOUT_S)


def run_ok(build: RuntimeBuild, record: Sequence[int], request_id: int) -> RunResult:
    """Drive one projected record and refuse to continue on a non-OK status."""
    result = soc_runtime.run_sample(
        build, RuntimeSample(request_id=request_id, raw=tuple(int(item) for item in record)))
    if result.status != "OK":
        raise AssertionError(
            f"request {request_id}: {result.status} {result.reason} "
            f"{result.stdout[-2000:]}")
    return result


def writes(result: RunResult) -> list[tuple[int, int, int]]:
    """The DUT's own write transactions: ``(cycle, addr, wdata)`` in order."""
    return [(int(item["cycle"]), int(item["addr"]), int(item["wdata"]))
            for item in result.requests]


def written_values(result: RunResult, address: int) -> set[int]:
    """Every value the CPU wrote to exactly this address."""
    return {int(item["wdata"]) for item in result.requests
            if int(item["write"]) and int(item["addr"]) == address}


def read_values(result: RunResult, address: int) -> set[int]:
    """Every value the fabric returned for a *read* of exactly this address.

    ``RunResult.responses`` is the address-attributed capture: a value here is
    evidence that the component under test returned it for that address, which is
    what makes it usable as an expectation's observation.  ``RunResult.requests``
    cannot be used for that, because it holds write transactions only.
    """
    return {int(item["rdata"]) for item in result.responses
            if not int(item["write"]) and int(item["addr"]) == address}


def observation(result: RunResult, name: str) -> int:
    if name not in result.observations:
        raise AssertionError(f"{name} is not observed: {sorted(result.observations)}")
    return int(result.observations[name])


def oracle_checks(result: RunResult) -> dict[str, dict[str, object]]:
    oracle = result.peer_oracle
    if not isinstance(oracle, dict):
        raise AssertionError("the run reports no independent peer oracle")
    return {str(item["check_id"]): dict(item) for item in oracle.get("checks", [])}


def applied_legality(build: RuntimeBuild,
                     pairs: Sequence[tuple[RuntimeSample, RunResult]]) -> dict[str, object]:
    """Confirm, from the runs themselves, that the environment applied what it asked.

    The generated top exports ``<slot>__applied`` for every declared special input,
    so the driver's real output can be compared with the raw field that requested
    it instead of being assumed.  The synthetic master's request fields are not
    exported that way; they are asserted through the runs' own address-attributed
    responses (the BFM's reads return the value the raw fields asked for), and the
    record names them instead of claiming a coverage it does not have.
    """
    checks: list[dict[str, object]] = []
    violations: list[str] = []
    unmonitored: list[str] = []
    for index, (sample, result) in enumerate(pairs):
        final = int(sample.raw[-1])
        for slot in build.slots:
            name = str(slot["name"])
            observed = result.observations.get(f"{name}__applied")
            if observed is None:
                if name not in unmonitored:
                    unmonitored.append(name)
                continue
            width = int(slot["width"])
            requested = (final >> int(slot["raw_lo"])) & ((1 << width) - 1)
            held = int(observed) == requested
            checks.append({"monitor": "applied-special-input-matches-request",
                           "sample": index, "port": name, "cycle": len(sample.raw) - 1,
                           "requested": requested, "observed": int(observed),
                           "result": "pass" if held else "fail"})
            if not held:
                violations.append(f"sample{index}:{name}: requested {requested} "
                                  f"observed {observed}")
    if not checks:
        raise AssertionError("no run exported an applied special input to check")
    notes = ["checked against the applied value the DUT exported for the last cycle"]
    if unmonitored:
        notes.append("no applied value is exported for: " + ", ".join(sorted(unmonitored))
                     + " (the synthetic master's request fields; their effect is "
                       "asserted through the address-attributed read responses)")
    return {
        "environment_legality": "confirmed" if not violations else "violated",
        "driver_violations": violations,
        "constraint_rejections": [],
        "monitor_results": checks,
        "notes": notes,
    }


def differing_field_ids(left: Sequence[int], right: Sequence[int], layout) -> set[str]:
    """The layout fields whose raw bits differ anywhere between two records.

    Stated over the whole record, so "the only thing that changed is this field"
    is a property of the driven words rather than of one cycle.
    """
    if len(left) != len(right):
        raise AssertionError(f"record length changed: {len(left)} != {len(right)}")
    field_ids: set[str] = set()
    for left_word, right_word in zip(left, right):
        difference = int(left_word) ^ int(right_word)
        if not difference:
            continue
        for field in layout.fields:
            mask = ((1 << field.width) - 1) << field.raw_lo
            if difference & mask:
                field_ids.add(field.field_id)
    return field_ids


# ---------------------------------------------------------------------------
# D1 contract: the program, the boot image and the offsets, before any RTL
# ---------------------------------------------------------------------------


class CpuGateContractTests(unittest.TestCase):
    """The D1 program is derived from the plan, and what it derives to is frozen.

    These assertions are what make the real run below a fact about this plan
    instead of a fact about the recorded image: the selector arithmetic, the
    placed words and the addresses are all decided here, and a change in the ISA
    layer, the image layer or the layout fails in the fast suite.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = ibex_plan()
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(
            cls.plan, instruction_candidates=CPU_INSTRUCTION_SLOTS, data_candidates=1,
            data_slot_offset=DATA_SLOT_OFFSET, candidate_program=True)
        cls.arm = cls.arms["dependency_repair"]
        cls.program = cls.arm.candidate_program
        assert cls.program is not None, "the arm must declare the program the gate places"
        cls.record = cpu_record(cls.arm, cls.layout, cls.program,
                                instruction_payload=INSTRUCTION_CANDIDATE_A,
                                data_value=DATA_CANDIDATE_A)

    def placed(self, record) -> dict[str, int]:
        """The word the arm placed for each declared slot of one record."""
        list(self.arm.project_records(record))
        return {str(item["slot"]): int(item["word_value"])
                for item in self.arm.last_repaired_test.placements}

    def test_the_declared_program_is_the_shape_the_boot_image_was_frozen_with(self) -> None:
        self.assertEqual(CPU_INSTRUCTION_SLOTS, len(self.program.slots.instruction))
        self.assertEqual(CPU_INSTRUCTION_SLOTS * 4, self.program.program_size)
        self.assertEqual(self.image.base, self.program.entry_address)
        for index, slot in enumerate(self.program.slots.instruction):
            with self.subTest(slot=slot.prefix):
                self.assertEqual(self.program.program_base + 4 * index,
                                 slot.declared_address)
        data_slot = self.program.slots.data[0]
        self.assertEqual(DATA_SLOT_OFFSET,
                         data_slot.declared_address - self.image.data_base)
        self.assertEqual(DATA_SLOT_ADDRESS, data_slot.declared_address)
        self.assertEqual(FROZEN_CPU_WIDTH, self.layout.raw_width)
        self.assertEqual(self.image.raw_width, self.layout.raw_width)

    def _assert_boot_image(self, path: Path) -> None:
        """The entry trampoline and the prologue must be the plan-derived ones.

        Only those two are asserted: every *declared slot* word an image holds is
        replaced by the offers, so what the CPU executes is the record.  What the
        image must supply is the entry jump into the declared window and the
        prologue that establishes the declared registers (``x3`` = data base,
        ``x2`` = stack pointer) the program uses.
        """
        words = image_words(path, self.image.base)
        prologue = [int(word) for word in self.program.prologue_words]
        self.assertTrue(prologue)
        prologue_start = self.program.program_base - 4 * len(prologue)
        self.assertIn(self.program.entry_address, words)
        self.assertEqual(
            encode_jal(0, prologue_start - self.program.entry_address),
            words[self.program.entry_address],
            f"{path} does not jump to the declared program prologue")
        for index, word in enumerate(prologue):
            address = prologue_start + 4 * index
            with self.subTest(address=hex(address)):
                self.assertIn(address, words)
                self.assertEqual(word, words[address],
                                 f"{path} prologue disagrees with the plan")

    def test_the_boot_image_carries_the_plan_derived_entry_and_prologue(self) -> None:
        self._assert_boot_image(ibex_boot_image(self.program))
        # The prologue is what makes the two bases the gate's addresses come from.
        self.assertEqual(DATA_SLOT_ADDRESS,
                         int(self.program.register_bindings["data_base"]["value"])
                         + DATA_SLOT_OFFSET)
        self.assertEqual(
            STORE_DATA_ADDRESS,
            effective_address(int(self.program.register_bindings["stack_pointer"]["value"]),
                              STORE_DATA_OFFSET))
        self.assertEqual(
            STORE_INSTRUCTION_ADDRESS,
            effective_address(int(self.program.register_bindings["stack_pointer"]["value"]),
                              STORE_INSTRUCTION_OFFSET))

    def test_the_fallback_boot_image_is_a_matching_program_too(self) -> None:
        """A fresh checkout has no recorded image; the fallback must still boot.

        The fallback is the declared program's own *static* image: the plan-derived
        trampoline and prologue with the declared slot words unwritten, which is
        exactly what this gate needs, because every declared slot is offered by the
        record.  Asserting it here means the documented fallback is a checked path
        and not a file nobody ever generated.
        """
        with TemporaryDirectory(prefix=".myfuzz-real-gate-boot-", dir=ROOT) as directory:
            path = Path(directory) / "boot_program.hex"
            self.program.image.write_hex(self.program.static_image(), path)
            self._assert_boot_image(path)
            words = image_words(path, self.image.base)
            for slot in self.program.slots.instruction:
                with self.subTest(slot=slot.prefix):
                    self.assertEqual(0, words[slot.declared_address],
                                     "the fallback must not execute a word of its own")

    def test_each_payload_selects_the_operation_and_reaches_its_offsets(self) -> None:
        """The selector is the payload's top eight bits; the offsets follow it."""
        self.assertEqual(0x12, INSTRUCTION_CANDIDATE_A >> 24)
        self.assertEqual(0x12, INSTRUCTION_CANDIDATE_B >> 24)
        self.assertEqual(0x6C, encode_lw(6, 3, DATA_SLOT_OFFSET) >> 24)
        self.assertEqual(0x86, encode_sw(6, 2, STORE_DATA_OFFSET) >> 24)
        self.assertEqual(0x86, encode_sw(5, 2, STORE_INSTRUCTION_OFFSET) >> 24)
        self.assertLess(DATA_SLOT_OFFSET, 0x800, "the load offset must stay positive")
        self.assertLess(0x800, STORE_DATA_OFFSET, "the store offsets are negative")
        self.assertLess(0x800, STORE_INSTRUCTION_OFFSET)

    def test_the_placed_program_is_the_one_the_gate_measures(self) -> None:
        """What the ISA and declared-program layers really place, word by word."""
        placed = self.placed(self.record)
        slots = list(self.program.slots.instruction)
        # Only the instruction slots are decodable as instructions; the data slot
        # is a memory word and is asserted as a value.
        decoded = {slot.prefix: decode_word(placed[slot.prefix]) for slot in slots}
        instruction = decoded["init"]
        self.assertEqual("XORI", instruction.name)
        self.assertEqual(5, instruction.rd)
        self.assertEqual(0, instruction.rs1)
        self.assertEqual(immediate(INSTRUCTION_CANDIDATE_A),
                         instruction.imm & 0xFFF)
        load = decoded["init1"]
        self.assertEqual("LW", load.name)
        self.assertEqual((6, 3), (load.rd, load.rs1))
        self.assertEqual(DATA_SLOT_OFFSET, load.imm & 0xFFF)
        first_store = decoded["init2"]
        self.assertEqual("SW", first_store.name)
        self.assertEqual((6, 2), (first_store.rs2, first_store.rs1))
        second_store = decoded["init3"]
        self.assertEqual("SW", second_store.name)
        self.assertEqual((5, 2), (second_store.rs2, second_store.rs1))
        self.assertEqual(STORE_DATA_ADDRESS,
                         effective_address(
                             int(self.program.register_bindings["stack_pointer"]["value"]),
                             first_store.imm & 0xFFF))
        self.assertEqual(STORE_INSTRUCTION_ADDRESS,
                         effective_address(
                             int(self.program.register_bindings["stack_pointer"]["value"]),
                             second_store.imm & 0xFFF))
        for slot in slots[4:]:
            with self.subTest(slot=slot.prefix):
                self.assertEqual(NOP_PAYLOAD, placed[slot.prefix])
        self.assertEqual(DATA_CANDIDATE_A, placed["data"])

    def test_the_data_candidate_is_offered_at_the_declared_slot(self) -> None:
        """The offer carries the declared address, so the overlay places it there."""
        offers = cpu_program_words(self.program, self.layout,
                                   instruction_payload=INSTRUCTION_CANDIDATE_A,
                                   data_value=DATA_CANDIDATE_A)
        data_slot = self.program.slots.data[0]
        address = field_by_role(self.layout, "soc_image", f"{data_slot.prefix}_address")
        payload = field_by_role(self.layout, "soc_image", f"{data_slot.prefix}_value")
        self.assertEqual(DATA_SLOT_ADDRESS,
                         (offers[-1] >> address.raw_lo) & ((1 << address.width) - 1))
        self.assertEqual(DATA_CANDIDATE_A,
                         (offers[-1] >> payload.raw_lo) & ((1 << payload.width) - 1))

    def test_each_ab_pair_differs_in_exactly_one_raw_field(self) -> None:
        """The one-field claim, at the driven record and not at the intent."""
        instruction_b = cpu_record(self.arm, self.layout, self.program,
                                   instruction_payload=INSTRUCTION_CANDIDATE_B,
                                   data_value=DATA_CANDIDATE_A)
        data_b = cpu_record(self.arm, self.layout, self.program,
                            instruction_payload=INSTRUCTION_CANDIDATE_A,
                            data_value=DATA_CANDIDATE_B)
        cases = (("init_data", instruction_b), ("data_value", data_b))
        for role, other in cases:
            with self.subTest(field=role):
                field = field_by_role(self.layout, "soc_image", role)
                self.assertEqual({field.field_id},
                                 differing_field_ids(self.record, other, self.layout))
        # The instruction pair changes one cycle's one field, and nothing else:
        # every other field of that word and of every other word is identical.
        difference = [(index, left ^ right) for index, (left, right)
                      in enumerate(zip(self.record, instruction_b)) if left != right]
        field = field_by_role(self.layout, "soc_image", "init_data")
        self.assertEqual(
            [(OFFER_CYCLE, (INSTRUCTION_CANDIDATE_A ^ INSTRUCTION_CANDIDATE_B)
              << field.raw_lo)], difference)
        data_difference = [(index, left ^ right) for index, (left, right)
                           in enumerate(zip(self.record, data_b)) if left != right]
        value_field = field_by_role(self.layout, "soc_image", "data_value")
        data_cycle = OFFER_CYCLE + len(self.program.slots.instruction)
        self.assertEqual(
            [(data_cycle, (DATA_CANDIDATE_A ^ DATA_CANDIDATE_B) << value_field.raw_lo)],
            data_difference)


# ---------------------------------------------------------------------------
# D2 contract: the peer ABI and the one-field pairs, before any RTL
# ---------------------------------------------------------------------------


class PeerGateContractTests(unittest.TestCase):
    """The peer samples are built at the frozen ABI, one field apart."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = peer_plan("bfm_isolated")
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(
            cls.plan, instruction_candidates=1, data_candidates=1)
        cls.arm = cls.arms["dependency_repair"]
        cls.uart = uart_peer_record(cls.plan, cls.layout, cls.arm,
                                    byte=PEER_BYTE_A, valid=1)
        cls.gpio = gpio_peer_record(cls.plan, cls.layout, cls.arm, drive=GPIO_DRIVE_A)

    def test_the_peer_abi_is_the_frozen_one(self) -> None:
        """Two independently derived tables must agree, or the wrong port is driven."""
        layout_offsets = {field.port: (field.raw_hi, field.raw_lo)
                          for field in self.layout.fields if field.owner == "soc_peer"}
        runtime_offsets = {str(slot["name"]): (int(slot["raw_hi"]), int(slot["raw_lo"]))
                           for slot in soc_runtime._peer_raw_slots(self.plan, self.image)}
        self.assertEqual(FROZEN_PEER_RAW, layout_offsets)
        self.assertEqual(layout_offsets, runtime_offsets)
        self.assertEqual(FROZEN_PEER_WIDTH, self.layout.raw_width)

    def test_the_uart_pair_differs_in_one_peer_field_only(self) -> None:
        other = uart_peer_record(self.plan, self.layout, self.arm,
                                 byte=PEER_BYTE_B, valid=1)
        self.assertNotEqual(self.uart, other)
        field = field_by_role(self.layout, "soc_peer", "uart.tx_byte:tx_request_data_i")
        self.assertEqual({field.field_id},
                         differing_field_ids(self.uart, other, self.layout))

    def test_the_uart_validity_pair_differs_in_one_peer_field_only(self) -> None:
        other = uart_peer_record(self.plan, self.layout, self.arm,
                                 byte=PEER_BYTE_A, valid=0)
        self.assertNotEqual(self.uart, other)
        field = field_by_role(self.layout, "soc_peer", "uart.tx_byte:tx_request_valid_i")
        self.assertEqual({field.field_id},
                         differing_field_ids(self.uart, other, self.layout))

    def test_the_gpio_pair_differs_in_one_peer_field_only(self) -> None:
        other = gpio_peer_record(self.plan, self.layout, self.arm, drive=GPIO_DRIVE_B)
        self.assertNotEqual(self.gpio, other)
        field = field_by_role(self.layout, "soc_peer", "gpio.drive:peer_drive_value_i")
        self.assertEqual({field.field_id},
                         differing_field_ids(self.gpio, other, self.layout))

    def test_the_samples_really_carry_the_raw_fields_they_claim(self) -> None:
        """The record's bits are the layout's own fields, held where declared."""
        data = field_by_role(self.layout, "soc_peer", "uart.tx_byte:tx_request_data_i")
        valid = field_by_role(self.layout, "soc_peer", "uart.tx_byte:tx_request_valid_i")
        self.assertEqual(PEER_BYTE_A, (self.uart[20] >> data.raw_lo) & ((1 << data.width) - 1))
        self.assertEqual(1, (self.uart[20] >> valid.raw_lo) & ((1 << valid.width) - 1))
        drive = field_by_role(self.layout, "soc_peer", "gpio.drive:peer_drive_value_i")
        held = field_by_role(self.layout, "soc_peer", "gpio.drive:peer_drive_valid_i")
        self.assertEqual({GPIO_DRIVE_A},
                         {(self.gpio[cycle] >> drive.raw_lo) & ((1 << drive.width) - 1)
                          for cycle in range(30, PEER_CYCLES)})
        self.assertEqual({GPIO_DRIVE_VALID},
                         {(self.gpio[cycle] >> held.raw_lo) & ((1 << held.width) - 1)
                          for cycle in range(30, PEER_CYCLES)})
        # Every word of a sample is a word of the frozen ABI and nothing wider.
        for label, record in (("uart", self.uart), ("gpio", self.gpio)):
            with self.subTest(sample=label):
                self.assertEqual({0}, {int(word) & ~((1 << FROZEN_PEER_WIDTH) - 1)
                                       for word in record})


# ---------------------------------------------------------------------------
# D1 real: one changed raw field, one different CPU transaction
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real RTL gate")
class RealCpuExecutionGateTests(unittest.TestCase):
    """The real pinned Ibex: raw candidates change the CPU's own requests.

    One build serves all three samples, and the samples differ in exactly one raw
    field each (asserted in the pure contract above and re-asserted here on the
    records the harness really drove), so the measured difference is the field's:

    * ``base``            the accepted word at the data slot and at the store;
    * ``instruction-b``   one XORI immediate apart: only the store of ``x5`` moves;
    * ``data-b``          one data word apart: only the store of ``x6`` moves.

    The CPU's read of the data slot is the other half of the D1 statement: the
    value it fetched is the value the harness placed, address-attributed in
    ``RunResult.responses``.
    """

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None:
            raise AssertionError(
                "Verilator is required for the real RTL gate (MYFUZZ_SOC_REAL=1)")
        cls.started = time.monotonic()
        cls.plan = ibex_plan()
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(
            cls.plan, instruction_candidates=CPU_INSTRUCTION_SLOTS, data_candidates=1,
            data_slot_offset=DATA_SLOT_OFFSET, candidate_program=True)
        cls.arm = cls.arms["dependency_repair"]
        cls.program = cls.arm.candidate_program
        assert cls.program is not None
        cls.boot_image = ibex_boot_image(cls.program)
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-real-gate-cpu-", dir=ROOT)
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.build = build_runtime(cls.plan, cls.image,
                                  output_dir=Path(cls._temporary.name) / "ibex",
                                  boot_image=cls.boot_image)
        cls.executable_hash = file_hash(cls.build.executable)
        cls.samples = {
            "base": (INSTRUCTION_CANDIDATE_A, DATA_CANDIDATE_A),
            "instruction-b": (INSTRUCTION_CANDIDATE_B, DATA_CANDIDATE_A),
            "data-b": (INSTRUCTION_CANDIDATE_A, DATA_CANDIDATE_B),
        }
        cls.records = {}
        for index, (label, (instruction, data)) in enumerate(cls.samples.items()):
            record = cpu_record(cls.arm, cls.layout, cls.program,
                                instruction_payload=instruction, data_value=data)
            cls.records[label] = (
                record, RuntimeSample(request_id=index + 1, raw=record))
        cls.results = {label: run_ok(cls.build, sample.raw, sample.request_id)
                       for label, (_record, sample) in cls.records.items()}
        print("\nMYFUZZ_SOC_RTL_GATE_CPU build_s=%.1f boot_image=%s width=%d samples=%d "
              "writes=%s" % (time.monotonic() - cls.started, cls.boot_image.name,
                             cls.build.raw_width, len(cls.results),
                             {label: len(result.requests)
                              for label, result in cls.results.items()}))

    # -- the candidates really reach the memory the CPU fetches from ---------

    def test_the_data_candidate_is_placed_before_the_cpu_is_released(self) -> None:
        for label, value in (("base", DATA_CANDIDATE_A), ("data-b", DATA_CANDIDATE_B)):
            with self.subTest(sample=label):
                placements = [dict(item) for item in self.results[label].image_placements
                              if str(item["kind"]) == "data"]
                self.assertEqual(1, len(placements), placements)
                placement = placements[0]
                self.assertEqual(DATA_SLOT_ADDRESS, int(placement["addr"]))
                self.assertTrue(placement["reset_held"],
                                "the placement was not made before the CPU was released")
                self.assertEqual(value, int(placement["readback"]))
                self.assertEqual((), tuple(self.results[label].image_errors))

    def test_the_cpu_read_the_data_candidate_from_its_declared_slot(self) -> None:
        """The load is evidence; ``requests`` holds writes only, so it is in responses."""
        self.assertEqual({DATA_CANDIDATE_A},
                         read_values(self.results["base"], DATA_SLOT_ADDRESS))
        self.assertEqual({DATA_CANDIDATE_B},
                         read_values(self.results["data-b"], DATA_SLOT_ADDRESS))
        self.assertNotIn(DATA_SLOT_ADDRESS,
                         {int(item["addr"]) for item in self.results["base"].requests},
                         "a read must not be reported as a CPU write transaction")

    def test_the_instruction_candidate_changes_the_cpu_write_data(self) -> None:
        base = writes(self.results["base"])
        other = writes(self.results["instruction-b"])
        self.assertTrue(base, "the boot program never wrote to the fabric")
        # One program, one boot image, one executable: every store site is the
        # same and only the value the candidate carried moved.
        self.assertEqual([addr for _, addr, _ in base], [addr for _, addr, _ in other])
        self.assertNotEqual(base, other)
        self.assertEqual({immediate(INSTRUCTION_CANDIDATE_A)},
                         written_values(self.results["base"], STORE_INSTRUCTION_ADDRESS))
        self.assertEqual({immediate(INSTRUCTION_CANDIDATE_B)},
                         written_values(self.results["instruction-b"],
                                        STORE_INSTRUCTION_ADDRESS))
        # The other store is the data candidate's and did not move.
        self.assertEqual({DATA_CANDIDATE_A},
                         written_values(self.results["base"], STORE_DATA_ADDRESS))
        self.assertEqual({DATA_CANDIDATE_A},
                         written_values(self.results["instruction-b"], STORE_DATA_ADDRESS))

    def test_the_data_candidate_changes_the_cpu_write_data(self) -> None:
        base = writes(self.results["base"])
        other = writes(self.results["data-b"])
        self.assertTrue(base)
        self.assertEqual([addr for _, addr, _ in base], [addr for _, addr, _ in other])
        self.assertNotEqual(base, other)
        self.assertEqual({DATA_CANDIDATE_A},
                         written_values(self.results["base"], STORE_DATA_ADDRESS))
        self.assertEqual({DATA_CANDIDATE_B},
                         written_values(self.results["data-b"], STORE_DATA_ADDRESS))
        # The other store is the instruction candidate's and did not move.
        self.assertEqual({immediate(INSTRUCTION_CANDIDATE_A)},
                         written_values(self.results["base"], STORE_INSTRUCTION_ADDRESS))
        self.assertEqual({immediate(INSTRUCTION_CANDIDATE_A)},
                         written_values(self.results["data-b"], STORE_INSTRUCTION_ADDRESS))

    def test_the_difference_is_the_value_and_the_store_sites_are_unchanged(self) -> None:
        """An identical address set and store count is what makes the difference
        attributable to the value the candidate carried."""
        for other in ("instruction-b", "data-b"):
            with self.subTest(other=other):
                self.assertEqual(
                    sorted({addr for _, addr, _ in writes(self.results["base"])}),
                    sorted({addr for _, addr, _ in writes(self.results[other])}))
                self.assertEqual(len(writes(self.results["base"])),
                                 len(writes(self.results[other])))

    def test_the_two_records_that_were_driven_differ_in_one_field(self) -> None:
        """The A/B claim is about the driven words, not about the intent."""
        base_record, _ = self.records["base"]
        for label, role in (("instruction-b", "init_data"), ("data-b", "data_value")):
            with self.subTest(sample=label):
                record, _sample = self.records[label]
                field = field_by_role(self.layout, "soc_image", role)
                self.assertEqual({field.field_id},
                                 differing_field_ids(base_record, record, self.layout))

    # -- evidence package and replay ---------------------------------------

    def _package(self):
        samples = [sample for _record, sample in self.records.values()]
        results = [self.results[label] for label in self.records]
        return build_evidence_package(
            self.plan, self.build, self.policy, results,
            kind="real_rtl_cpu_execution_gate",
            samples=samples,
            criteria=[CPU_CRITERION],
            legality=applied_legality(self.build, list(zip(samples, results))),
            notes=["one build serves every sample; each A/B pair differs in exactly "
                   "one raw field of the driven record"])

    def test_the_gate_ran_on_one_build_and_one_executable(self) -> None:
        recorded = recorded_build_identity(self.build)
        self.assertEqual({"plan_hash": self.plan.plan_hash,
                          "layout_hash": str(self.plan.raw_layout["layout_hash"])},
                         recorded)
        self.assertEqual(self.layout.raw_width, self.build.raw_width)
        self.assertEqual(self.executable_hash, file_hash(self.build.executable))
        self.assertEqual(self.boot_image, self.build.boot_image)

    def test_the_package_binds_the_gate_and_replays_with_agreement(self) -> None:
        package = self._package()
        identity = package.identity
        self.assertEqual(self.plan.plan_hash, identity["plan_hash"])
        self.assertEqual(str(self.plan.raw_layout["layout_hash"]), identity["layout_hash"])
        self.assertEqual(self.policy.policy_hash, identity["policy_hash"])
        self.assertEqual(self.build.build_hash, identity["build_hash"])
        self.assertEqual(file_hash(self.boot_image), identity["boot_image_hash"])
        self.assertEqual("riscv", identity["isa"]["family"])
        self.assertEqual((), identity_mismatches(package, self.build))
        self.assertTrue(package.inputs_complete)
        directory = Path(self._temporary.name) / "cpu-evidence"
        document = write_evidence_package(package, directory)
        self.assertTrue(document.is_file())
        read_back = read_evidence_package(directory)
        self.assertEqual(package.document(), read_back.document())
        replay = replay_package(read_back, self.build)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
        self.assertTrue(replay.agreed)
        self.assertIsNone(replay.divergence)
        self.assertFalse(replay.mismatching_fields)
        self.assertEqual(len(self.records), len(replay.reruns))
        # The replayed comparison really covers the CPU half: the requests, the
        # pre-release placement and the observations are compared field by field.
        for prefix in ("sample0:", "sample1:", "sample2:"):
            with self.subTest(sample=prefix):
                self.assertTrue(
                    any(field.startswith(prefix + "fabric_request")
                        for field in replay.matching_fields), replay.matching_fields[:20])
                self.assertTrue(
                    any(field.startswith(prefix + "image_placement")
                        for field in replay.matching_fields))
        self.assertTrue(any(field.endswith("observation:fabric_responses")
                            for field in replay.matching_fields))


# ---------------------------------------------------------------------------
# D2 real: one changed peer raw field, one different register the component returns
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real RTL gate")
class RealPeerBehaviourGateTests(unittest.TestCase):
    """The real peers: a raw field changes what the peripheral really does.

    One build serves all five samples, every sample carries an **empty** peer
    event plan (asserted through ``peer_applied``), and the expectation of each
    pair is the raw value the sample itself set -- never a counter of the device
    or of its peer.  The observation is the peripheral's own register returned for
    a read of one declared address, i.e. an entry of ``RunResult.responses`` with
    ``write == 0``.

    * ``uart-byte-*``  the peer's ``tx_request_data_i`` decides the byte the UART
      hands back from RXDATA (the peer's ``tx_sent_count_o`` is 1 in both runs and
      therefore cannot be the expectation);
    * ``uart-offer-*``  the peer's ``tx_request_valid_i`` decides whether a frame
      is offered at all: without it the status never reports a received byte;
    * ``gpio-drive-*``  the peer's ``peer_drive_value_i`` decides the level the
      GPIO component samples into DATA_IN (and the level the peer itself drives).
    """

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None:
            raise AssertionError(
                "Verilator is required for the real RTL gate (MYFUZZ_SOC_REAL=1)")
        cls.started = time.monotonic()
        cls.plan = peer_plan("bfm_isolated")
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(
            cls.plan, instruction_candidates=1, data_candidates=1)
        cls.arm = cls.arms["dependency_repair"]
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-real-gate-peer-", dir=ROOT)
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.build = build_runtime(cls.plan, cls.image,
                                  output_dir=Path(cls._temporary.name) / "peers")
        cls.executable_hash = file_hash(cls.build.executable)
        cls.uart_window = _window_base(cls.plan, "uart0_win")
        cls.gpio_window = _window_base(cls.plan, "gpio0_win")
        cls.samples = {
            "uart-byte-0x5a": uart_peer_record(cls.plan, cls.layout, cls.arm,
                                               byte=PEER_BYTE_A, valid=1),
            "uart-byte-0xc3": uart_peer_record(cls.plan, cls.layout, cls.arm,
                                               byte=PEER_BYTE_B, valid=1),
            "uart-offer-on": uart_peer_record(cls.plan, cls.layout, cls.arm,
                                              byte=PEER_BYTE_A, valid=1),
            "uart-offer-off": uart_peer_record(cls.plan, cls.layout, cls.arm,
                                               byte=PEER_BYTE_A, valid=0),
            "gpio-drive-0x05": gpio_peer_record(cls.plan, cls.layout, cls.arm,
                                                drive=GPIO_DRIVE_A),
            "gpio-drive-0x3a": gpio_peer_record(cls.plan, cls.layout, cls.arm,
                                                drive=GPIO_DRIVE_B),
        }
        cls.runtime_samples = {
            label: RuntimeSample(request_id=100 + index, raw=record)
            for index, (label, record) in enumerate(cls.samples.items())}
        cls.results = {label: run_ok(cls.build, sample.raw, sample.request_id)
                       for label, sample in cls.runtime_samples.items()}
        print("\nMYFUZZ_SOC_RTL_GATE_PEER build_s=%.1f width=%d samples=%d"
              % (time.monotonic() - cls.started, cls.build.raw_width, len(cls.results)))

    @property
    def rxdata_address(self) -> int:
        return self.uart_window + UART_RXDATA

    @property
    def uart_status_address(self) -> int:
        return self.uart_window + UART_STATUS

    @property
    def gpio_datain_address(self) -> int:
        return self.gpio_window + GPIO_DATA_IN

    # -- the pairs ---------------------------------------------------------

    def test_a_different_raw_peer_byte_is_what_the_peripheral_returns(self) -> None:
        """The expectation is the raw field; the observation is an addressed read.

        Independence: the expected byte is the value this test wrote into the raw
        field, so no counter can produce it; the observation is the byte the UART
        returned for a read of its own RXDATA address (``RunResult.responses``,
        ``write == 0``).  The peer's ``tx_sent_count_o`` is 1 in *both* samples, so
        it is recorded as corroboration that a frame ran and is explicitly not the
        criterion.
        """
        first = self.results["uart-byte-0x5a"]
        second = self.results["uart-byte-0xc3"]
        self.assertEqual({PEER_BYTE_A}, read_values(first, self.rxdata_address))
        self.assertEqual({PEER_BYTE_B}, read_values(second, self.rxdata_address))
        # The same peripheral, one register earlier: rx-valid and tx-ready, i.e.
        # the byte really arrived in the component's receive register.
        self.assertEqual({0b0011}, read_values(first, self.uart_status_address))
        self.assertEqual({0b0011}, read_values(second, self.uart_status_address))
        self.assertEqual(1, observation(first, "uart0__tx_sent_count_o"))
        self.assertEqual(1, observation(second, "uart0__tx_sent_count_o"))
        self.assertEqual(0, observation(first, "uart0__framing_error_count_o"))
        self.assertEqual(0, observation(second, "uart0__framing_error_count_o"))

    def test_the_raw_valid_field_decides_whether_a_frame_is_offered(self) -> None:
        offered = self.results["uart-offer-on"]
        silent = self.results["uart-offer-off"]
        self.assertEqual({PEER_BYTE_A}, read_values(offered, self.rxdata_address))
        self.assertEqual({0}, read_values(silent, self.rxdata_address))
        # STATUS bit 0 is rx-valid, bit 1 is tx-ready: the silent sample keeps the
        # transmitter ready and never reports a received byte.
        self.assertEqual({0b0011}, read_values(offered, self.uart_status_address))
        self.assertEqual({0b0010}, read_values(silent, self.uart_status_address))
        self.assertEqual(1, observation(offered, "uart0__tx_sent_count_o"))
        self.assertEqual(0, observation(silent, "uart0__tx_sent_count_o"))

    def test_a_different_raw_gpio_drive_value_is_what_the_component_samples(self) -> None:
        """Two independent observations of one raw field, neither a counter.

        The GPIO component returns the peer's level from its own DATA_IN register
        (an addressed read), and the peer model's ``pin_value_o`` -- a peer-side
        observation, not a counter -- reports the same level.  The component is
        configured as an input, so the value is the peer's drive and not a
        resolution artifact; no contention is claimed in either sample.
        """
        first = self.results["gpio-drive-0x05"]
        second = self.results["gpio-drive-0x3a"]
        self.assertEqual({GPIO_DRIVE_A}, read_values(first, self.gpio_datain_address))
        self.assertEqual({GPIO_DRIVE_B}, read_values(second, self.gpio_datain_address))
        self.assertEqual(GPIO_DRIVE_A, observation(first, "gpio0__pin_value_o"))
        self.assertEqual(GPIO_DRIVE_B, observation(second, "gpio0__pin_value_o"))
        self.assertEqual(0, observation(first, "gpio0__contention_count_o"))
        self.assertEqual(0, observation(second, "gpio0__contention_count_o"))

    def test_each_pair_changes_exactly_one_peer_field_of_the_driven_record(self) -> None:
        """The A/B claim is about the records the harness drove, whole records."""
        pairs = (
            ("uart-byte-0x5a", "uart-byte-0xc3", "uart.tx_byte:tx_request_data_i"),
            ("uart-offer-on", "uart-offer-off", "uart.tx_byte:tx_request_valid_i"),
            ("gpio-drive-0x05", "gpio-drive-0x3a", "gpio.drive:peer_drive_value_i"),
        )
        for left, right, role in pairs:
            with self.subTest(field=role):
                field = field_by_role(self.layout, "soc_peer", role)
                self.assertEqual({field.field_id}, differing_field_ids(
                    self.samples[left], self.samples[right], self.layout))

    def test_the_raw_fields_alone_drove_every_sample(self) -> None:
        """No declared peer event was applied, so the raw route is the cause.

        ``peer_applied`` is the harness's own record of the events it applied; it
        is empty for every sample, and the independent oracle's
        ``peer-event-transport`` check compares that against the (empty) declared
        plan and passes.  A behaviour that came from the event route instead would
        fail both statements.
        """
        for label, result in self.results.items():
            with self.subTest(sample=label):
                self.assertEqual((), tuple(result.peer_applied))
                self.assertEqual((), tuple(result.image_errors))
                checks = oracle_checks(result)
                self.assertEqual("pass", checks["peer-event-transport"]["status"],
                                 checks["peer-event-transport"])
                self.assertIn("gpio-resolution-wire",
                              {str(item["check_id"]) for item in
                               (result.peer_oracle or {}).get("unassessed", [])},
                              "a wire property without a waveform must stay not_assessed")

    def test_the_oracle_assesses_the_raw_uart_route_from_the_raw_record(self) -> None:
        """The oracle now decides the raw route from the raw input, not the plan.

        This test used to freeze a measured *limitation*: ``uart-tx-sent-count``
        derived its expectation from the declared peer event plan, which is empty
        for a raw-driven sample, so it expected zero completions and reported
        ``mismatch`` for a frame the register readback proved arrived.  The oracle
        now also decodes the raw record independently and uses that when the plan
        is empty, so the same run is assessed correctly: one expected completion,
        one observed, ``pass``.  The gate's criterion remains the raw field plus
        the component's addressed read; this check is corroboration, and the
        assertion below is what keeps the raw basis from silently disappearing.
        """
        for label in ("uart-byte-0x5a", "uart-byte-0xc3"):
            with self.subTest(sample=label):
                checks = oracle_checks(self.results[label])
                sent = checks["uart-tx-sent-count"]
                self.assertEqual(1, sent["expected"],
                                 "the oracle's expectation must come from the raw record")
                self.assertEqual(1, sent["observed"])
                self.assertEqual("pass", sent["status"])
                self.assertIn("raw-decoded", str(sent.get("basis", "")),
                              "the deciding source must be recorded, not inferred")
                self.assertEqual(1, observation(self.results[label],
                                                "uart0__tx_sent_count_o"))

    # -- identity and replay -----------------------------------------------

    def _package(self):
        labels = list(self.samples)
        samples = [self.runtime_samples[label] for label in labels]
        results = [self.results[label] for label in labels]
        return build_evidence_package(
            self.plan, self.build, self.policy, results,
            kind="real_rtl_peer_behaviour_gate",
            samples=samples,
            criteria=[PEER_CRITERION],
            legality=applied_legality(self.build, list(zip(samples, results))),
            notes=["every sample carries an empty peer event plan; the expectation of "
                   "each pair is the raw field the sample itself set, observed as an "
                   "address-attributed register read, never a peer counter"])

    def test_the_pairs_ran_on_one_build_and_one_executable(self) -> None:
        recorded = recorded_build_identity(self.build)
        self.assertEqual({"plan_hash": self.plan.plan_hash,
                          "layout_hash": str(self.plan.raw_layout["layout_hash"])},
                         recorded)
        self.assertEqual(FROZEN_PEER_WIDTH, self.build.raw_width)
        self.assertEqual(self.executable_hash, file_hash(self.build.executable))
        # This gate is the BFM route: the composition boots no program, and the
        # build record says so instead of leaving the CPU's role implicit.
        self.assertEqual("bfm_isolated", self.plan.drive_profile)
        self.assertEqual("explicit_empty_image_no_program_loaded",
                         self.build.boot_image_policy)
        self.assertEqual("00\n",
                         Path(self.build.boot_image).read_text(encoding="utf-8"))

    def test_the_peer_gate_package_replays_with_agreement(self) -> None:
        package = self._package()
        self.assertTrue(package.inputs_complete)
        self.assertEqual((), identity_mismatches(package, self.build))
        directory = Path(self._temporary.name) / "peer-evidence"
        write_evidence_package(package, directory)
        read_back = read_evidence_package(directory)
        self.assertEqual(package.document(), read_back.document())
        # The saved input really is the sample the gate drove: the peer byte at
        # its declared offset is the value the register readback returned.
        byte_field = field_by_role(self.layout, "soc_peer",
                                   "uart.tx_byte:tx_request_data_i")
        saved = read_back.sample(0)
        self.assertEqual(
            PEER_BYTE_A,
            (int(saved.raw[20]) >> byte_field.raw_lo) & ((1 << byte_field.width) - 1))
        replay = replay_package(read_back, self.build)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
        self.assertTrue(replay.agreed)
        self.assertIsNone(replay.divergence)
        self.assertFalse(replay.mismatching_fields)
        self.assertEqual(len(self.samples), len(replay.reruns))
        self.assertTrue(any(field.endswith("observation:uart0__tx_sent_count_o")
                            for field in replay.matching_fields))
        self.assertTrue(any(field.endswith("observation:gpio0__pin_value_o")
                            for field in replay.matching_fields))


if __name__ == "__main__":                              # pragma: no cover
    unittest.main()
