"""Roadmap phase 1B: the transport half of the RFuzz input chain.

Task A (``test_soc_input_arms_projection.py``) fixes what each arm *projects*.
This module covers what the projected word then *drives*, in the three
statements that make a transport claim falsifiable:

* a record the projector refuses never reaches the simulator -- asserted with a
  mocked ``run_sample`` that a legal record through the same path really does
  reach, because "never called" is worthless if the path is not wired at all;
* the raw offsets the generated testbench reads are the frozen ABI's own offsets,
  for the attached peers' request fields and for the candidate-image overlay the
  harness runs before it releases the CPU;
* on the real pinned Ibex, one changed ``init_data`` field changes the word the
  CPU fetches, what the memory model holds and what the program then writes onto
  the fabric; and on the real peer composition, one changed peer raw field changes
  the register the peripheral under test returns (both ``MYFUZZ_SOC_REAL=1``).

The harness contract this module is written against:

* the raw word is one word per cycle, and for an attached peer its request field
  is that port's **default level**: ``assign <port> = <port>__event_active ?
  <port>__event : raw_bits[hi:lo];``, so the peer event plan overrides the raw
  level only in the cycle it fires and both sources stay usable;
* the candidate image is a *pre-release* overlay: the whole record is buffered,
  every offered candidate is placed in the memory model's ``initial_memory``, the
  model's working array is refreshed by one more reset assertion, and only then
  is the CPU released -- so ``image_placements[*]["readback"]`` and the memory
  readback are the memory the CPU really fetches from;
* ``RunResult.requests`` captures the DUT's **write** transactions (the harness
  records reads address-attributed in ``RunResult.responses`` instead).

Both real A/B classes compile one build and run every sample of the class against
it, so a behavioural difference can never come from a different executable; the
peer samples carry an empty peer event plan, so which of a request port's two
declared drivers produced the behaviour is never in doubt.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import time
import unittest
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.composition import soc_runtime
from myfuzz.composition.soc_candidate_program import (
    CandidateProgramPolicy,
    build_candidate_program,
    encode_addi,
    encode_sw,
)
from myfuzz.composition.soc_failure_evidence import build_identity, recorded_build_identity
from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    MAX_CYCLES,
    RuntimeBuild,
    RuntimeSample,
    _peer_raw_slots,
    build_profile_runtime,
    render_profile_testbench,
)
from myfuzz.integration.soc_builder import SocBuildError, _peer_projection_slots

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_input_arms_projection import (
    arms_for,
    field_by_role,
    ibex_plan,
    peer_plan,
    put,
    segment,
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
    _PeerRuntimeFixture,
    build_peer_plan,
)

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"

#: The real Ibex run: 400 cycles of the frozen boot program.
CYCLES = 400
#: The cycle the record offers its one candidate in.  The overlay scans the whole
#: buffered record before it releases the CPU, so the position carries no
#: meaning; an ordinary mid-record cycle is used so that nothing here depends on
#: where the record ends.
CANDIDATE_CYCLE = 4
#: The first declared candidate slot of the boot program, i.e. the word a raw
#: ``init_data`` offer replaces.
IBEX_SLOT_ADDRESS = 0x10098
#: The word the boot image itself holds at that slot (``addi x5, x0, 0x123``), and
#: the two raw candidates used for the A/B.  The candidates share every bit the
#: reference ISA layer fixes (opcode, funct3, rd, rs1, imm[11:4]) and differ only
#: in the low nibble of the immediate, so one raw field decides which word the CPU
#: executes and, through it, what the program stores.
BOOT_SLOT_WORD = 0x12300293
CANDIDATE_A = 0x12300293
CANDIDATE_B = 0x12C00293
#: Byte offset of the boot program's store from the declared data-region base.
RAM_SCRATCH_OFFSET = 0x40
#: The second UART peer byte: the pair is one field apart, so the two runs must
#: not be able to produce the same received byte by accident.
ALT_PEER_BYTE = 0xC3
#: The recorded candidate-program image ``test_soc_input_repair_runtime`` freezes
#: for ``ibex_plan()``, used read-only when it is present.
RECORDED_BOOT_IMAGE = ROOT / "runs/soc-input-repair-runtime/candidate_program.hex"
#: Where this module freezes its own program when the recorded image is absent.
#: It is deliberately not the other module's path: that file is its fixture and
#: this module must not rewrite it.
OWN_BOOT_IMAGE = ROOT / "runs/soc-input-transport-ab/boot_program.hex"
OWN_PROGRAM_SLOTS = 2
DATA_SLOT_OFFSET = 0x80

#: The frozen peer half of the combined ABI: ``drive profile -> top port ->
#: (raw_hi, raw_lo)``, measured on the real plans with one instruction and one
#: data candidate.  The layout stays the only source of truth for the offsets;
#: this table exists so a layout change fails here on purpose instead of silently
#: reinterpreting a saved corpus.
FROZEN_PEER_RAW = {
    "cpu_execute": {
        "gpio0__peer_drive_value_i": (152, 145),
        "gpio0__peer_drive_valid_i": (160, 153),
        "spi0__tx_request_valid_i": (161, 161),
        "spi0__tx_request_data_i": (169, 162),
        "uart0__tx_request_valid_i": (170, 170),
        "uart0__tx_request_data_i": (178, 171),
    },
    "bfm_isolated": {
        "gpio0__peer_drive_value_i": (376, 369),
        "gpio0__peer_drive_valid_i": (384, 377),
        "spi0__tx_request_valid_i": (385, 385),
        "spi0__tx_request_data_i": (393, 386),
        "uart0__tx_request_valid_i": (394, 394),
        "uart0__tx_request_data_i": (402, 395),
    },
}

#: The frozen combined width of the peer compositions with the same candidate
#: counts as above.
FROZEN_PEER_WIDTH = {"cpu_execute": 179, "bfm_isolated": 403}

#: The frozen candidate-image half for ``ibex_plan()`` with one instruction and
#: one data candidate: ``segment -> (raw_hi, raw_lo)``.  These are the fields the
#: pre-release overlay reads out of the buffered record.
FROZEN_IMAGE_RAW = {
    "init_offer": (3, 3),
    "init_address": (35, 4),
    "init_data": (67, 36),
    "init_be": (71, 68),
    "data_offer": (72, 72),
    "data_address": (104, 73),
    "data_value": (136, 105),
    "data_be": (140, 137),
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def project_then_run(arm, build: RuntimeBuild, values, *, request_id: int = 1):
    """The production order: project the whole record, then drive exactly it.

    Keeping both steps in one place is what lets the refusal tests assert that
    ``run_sample`` is never reached: a harness that ran the *unprojected* words
    after a refusal would be a silent fall-back to raw drive.
    """
    projected = arm.project_records(values)
    return soc_runtime.run_sample(
        build, RuntimeSample(request_id=request_id, raw=tuple(projected)))


def unbuilt_runtime() -> RuntimeBuild:
    """A build record for the projection gate, where a mock stands in for the sim."""
    directory = Path("/nonexistent")
    return RuntimeBuild(
        output_dir=directory, top_path=directory / "myfuzz_soc_top.sv",
        testbench_path=directory / "profile_tb.sv",
        executable=directory / "myfuzz_profile_sim", sources=(), raw_width=1, slots=(),
        observations=(), boot_image=None, boot_image_policy="no_preloaded_region",
        build_hash="sha256:" + "0" * 64)


def peer_field(layout, role: str, value: int) -> int:
    """One peer request field of a raw word, at the layout's own offset."""
    return put(0, field_by_role(layout, "soc_peer", role), value)


def peer_pulse(layout, plan, instance_id: str, slot_name: str,
               payload: int) -> tuple[int, int]:
    """One raw cycle that offers one peer slot, plus that slot's declared spacing.

    The word is built from the layout field that the plan's own projection slot
    names, so a word this test calls legal is legal for the same reason one from a
    campaign would be.
    """
    record = next(item for item in _peer_projection_slots(plan, layout, base_dir=ROOT)
                  if item["instance_id"] == instance_id and item["slot"] == slot_name)
    raw = 0
    for signal in record["signals"]:
        field = field_by_role(layout, "soc_peer", f"{slot_name}:{signal['peer_port']}")
        raw = put(raw, field, 1 if signal["source"] == "pulse" else payload)
    return raw, int(record["minimum_gap_cycles"])


def fallback_boot_program(plan):
    """This module's own boot program, frozen from the plan.

    Used when the recorded image is absent: the same entry trampoline and
    prologue the plan's candidate program generates, one ``addi`` at the offered
    slot and one store of it into RAM.  Returns the program and its image bytes.
    """
    program = build_candidate_program(
        plan, instruction_candidates=OWN_PROGRAM_SLOTS, data_candidates=1,
        policy=CandidateProgramPolicy(data_slot_offset=DATA_SLOT_OFFSET))
    directed = {
        "init": encode_addi(5, 0, (BOOT_SLOT_WORD >> 20) & 0xFFF),
        "init1": encode_sw(5, 3, RAM_SCRATCH_OFFSET),
    }
    repaired = program.repairer().repair_test([], directed=directed)
    return program, repaired.image.image


def ibex_boot_image(plan) -> Path:
    """The real boot image this test starts the CPU from.

    The image ``test_soc_input_repair_runtime`` records is used when it exists:
    it is a working static image for exactly this plan, and a boot image that does
    not match the plan would leave the CPU executing nothing.  ``runs/`` is not
    part of the source tree, so a fresh checkout writes its own program there
    instead (see :func:`fallback_boot_program`).  Every assertion below is stated
    so that both images satisfy it.
    """
    if RECORDED_BOOT_IMAGE.is_file():
        return RECORDED_BOOT_IMAGE
    program, image = fallback_boot_program(plan)
    OWN_BOOT_IMAGE.parent.mkdir(parents=True, exist_ok=True)
    program.image.write_hex(image, OWN_BOOT_IMAGE)
    return OWN_BOOT_IMAGE


def target_index(plan, region_id: str) -> int:
    """The fabric target index (``u_mem_<index>``) of one declared memory region."""
    for row in plan.plan["fabric"]["decode"]["windows"]:
        if str(row["window_id"]) == region_id:
            return int(row["target_index"])
    raise AssertionError(f"no decoded window backs {region_id}")


def memory_word(result, instance: int, base: int, address: int) -> int:
    """One 32-bit memory word out of a run's own hierarchical readback."""
    offset = address - base
    index, lane = divmod(offset, 8)
    key = f"u_mem_{instance}[{index}]"
    if key not in result.observations:
        raise AssertionError(f"the run read back no {key}")
    return (int(result.observations[key]) >> (lane * 8)) & 0xFFFF_FFFF


def writes(result) -> list[tuple[int, int, int]]:
    """The DUT's own write transactions: ``(cycle, addr, wdata)`` in order."""
    return [(int(item["cycle"]), int(item["addr"]), int(item["wdata"]))
            for item in result.requests]


def immediate(word: int) -> int:
    """The I-type immediate of a 32-bit instruction word.

    The raw ``init_data`` field carries the *instruction encoding*, so the
    immediate a candidate asks for is bits [31:20] of the word, not its low
    twelve bits (which are opcode and ``rd``).
    """
    return (word >> 20) & 0xFFF


def fetched_words(result, address: int) -> set[int]:
    """The read data every captured completion at one address returned."""
    return {int(item["rdata"]) for item in result.responses
            if not int(item["write"]) and int(item["addr"]) == address}


# ---------------------------------------------------------------------------
# refusal before drive
# ---------------------------------------------------------------------------


class RefusedFieldNeverReachesTheDriverTests(unittest.TestCase):
    """A refused raw value is refused, never driven as raw input.

    The projector is the gate in front of the simulator: if a refused record
    still produced a ``RunResult``, the refusal would describe a run that
    happened anyway.  Each case drives the same two-step path production uses and
    asserts the simulator entry point was never reached -- with a legal record
    through that same path as the positive control, because "never called" also
    holds for a path that is not wired to the simulator at all.
    """

    def _assert_refused_before_driving(self, arm, legal, refused, reason: str) -> None:
        build = unbuilt_runtime()
        with unittest.mock.patch.object(soc_runtime, "run_sample") as runner:
            with self.assertRaisesRegex(SocBuildError, reason):
                project_then_run(arm, build, refused)
            runner.assert_not_called()
            runner.reset_mock()
            project_then_run(arm, build, legal)
            runner.assert_called_once()
            _, sample = runner.call_args.args
            # What is driven is the projected record, not the offered one.
            self.assertEqual(tuple(arm.project_records(legal)), sample.raw)

    def test_a_peer_pulse_pair_closer_than_the_declared_gap_is_refused(self) -> None:
        plan = peer_plan()
        _, layout, _, arms = arms_for(plan)
        arm = arms["dependency_repair"]
        pulse, gap = peer_pulse(layout, plan, "uart0", "uart.tx_byte", UART_PEER_BYTE)
        self.assertGreater(gap, 1)
        self._assert_refused_before_driving(
            arm, [pulse] + [0] * gap, [pulse, 0, pulse] + [0] * gap,
            "peer-event-gap-violation:uart0:uart.tx_byte")

    def test_a_partial_byte_enable_instruction_offer_is_repaired_not_driven_raw(self) -> None:
        plan = ibex_plan()
        image, layout, _, arms = arms_for(plan, instruction_candidates=1,
                                          data_candidates=1)
        arm = arms["dependency_repair"]
        slot = image.candidates.instruction[0]

        def offer(byte_enable: int) -> int:
            raw = 0
            for role, value in ((f"{slot.prefix}_offer", 1),
                                (f"{slot.prefix}_address", IBEX_SLOT_ADDRESS),
                                (f"{slot.prefix}_data", BOOT_SLOT_WORD),
                                (f"{slot.prefix}_be", byte_enable)):
                raw = put(raw, field_by_role(layout, "soc_image", role), value)
            return raw

        # A candidate is one whole word, so the projection has a single legal
        # value for the enable field: it repairs a partial enable to the full
        # word and records the repair, rather than refusing the whole record.
        # The record that reaches the driver must therefore carry the full word,
        # never the partial one the fuzzer offered.
        arm.repair_counts.pop("byte_enable_repair", None)
        projected = list(arm.project_records([offer(0x3)]))
        self.assertEqual(1, len(projected))
        enable = field_by_role(layout, "soc_image", f"{slot.prefix}_be")
        self.assertEqual(0xF, segment(projected[0], enable),
                         "the applied word must request a full-word write")
        self.assertEqual(1, arm.repair_counts.get("byte_enable_repair"),
                         "the repair must be counted, not applied silently")

    def test_a_second_offer_of_a_committed_slot_is_refused(self) -> None:
        plan = ibex_plan()
        _, layout, _, arms = arms_for(plan, instruction_candidates=2, data_candidates=1)
        arm = arms["dependency_repair"]
        program = arm.candidate_program
        assert program is not None
        words = []
        for slot in program.slots.slots():
            raw = 0
            for name, value in (("offer", 1), ("address", slot.declared_address),
                                ("data" if slot.kind == "instruction" else "value",
                                 0x00000013 if slot.kind == "instruction" else 0x1234ABCD),
                                ("be", 0xF)):
                raw = put(raw, field_by_role(
                    layout, "soc_image", slot.segment(name).name), value)
            words.append(raw)
        # Every declared slot offered once is the legal record; offering the first
        # slot a second time is the rewrite the declared program forbids.
        self._assert_refused_before_driving(
            arm, words, words + [words[0]], "repair-would-rewrite-committed-word")


# ---------------------------------------------------------------------------
# the raw word reaches the port it declares
# ---------------------------------------------------------------------------


class PeerRawTransportTests(unittest.TestCase):
    """The raw peer field is the default level of the peer's own port.

    A peer request port has two declared drivers and they are not interchangeable:
    the raw ABI carries a per-cycle request (the peer model latches a pulse
    itself) and the peer event plan carries a payload at a declared cycle.  The
    port is continuously assigned the raw level and the event plan only overrides
    it while it is active -- ``assign <port> = <port>__event_active ? <port>__event
    : raw_bits[hi:lo];`` -- so both stay usable and a test can tell which one it
    used.  The real behavioural A/B through the raw fields is in
    :class:`PeerRawEventTransportTests`; what is asserted here is the wiring and
    the frozen offsets it depends on, and that a continuously assigned port
    carries no initial value (Verilator refuses that combination outright with
    ``%Error-CONTASSINIT``, which would make every peer composition unbuildable).
    """

    def test_every_peer_raw_field_is_the_default_level_of_its_own_port(self) -> None:
        for drive_profile, frozen in FROZEN_PEER_RAW.items():
            with self.subTest(drive_profile=drive_profile):
                plan = peer_plan(drive_profile)
                image = build_image_plan(plan)
                layout = combined_input_layout(plan, image)
                text = render_profile_testbench(plan, image_plan=image)
                self.assertEqual(
                    frozen,
                    {field.port: (field.raw_hi, field.raw_lo) for field in layout.fields
                     if field.owner == "soc_peer"})
                fields = {field.port: field for field in layout.fields
                          if field.owner == "soc_peer"}
                for port, (hi, lo) in sorted(frozen.items()):
                    field = fields[port]
                    shape = "logic" if field.width == 1 else f"logic [{field.width - 1}:0]"
                    # The port is continuously assigned, so its declaration carries
                    # no initial value; the level is still defined at time zero,
                    # because both sources of the assignment are.
                    self.assertIn(f"  {shape} {port};", text, port)
                    self.assertNotIn(f"  initial {port} = '0;", text, port)
                    self.assertNotIn(f"  {shape} {port} = ", text, port)
                    self.assertIn(
                        f"  assign {port} = {port}__event_active ? {port}__event : "
                        f"raw_bits[{hi}:{lo}];", text, port)
                    self.assertNotIn(f"  assign {port} = {port}__event;", text, port)
                    self.assertIn(f"  logic {port}__event_active = 1'b0;", text, port)
                self.assertIn(
                    f"  localparam integer RAW_WIDTH = {layout.raw_width};", text)
                self.assertEqual(FROZEN_PEER_WIDTH[drive_profile], layout.raw_width)

    def test_the_runtime_peer_offsets_are_the_combined_layout_offsets(self) -> None:
        """Two independently derived tables must agree, or the wrong port is driven."""
        for drive_profile in FROZEN_PEER_RAW:
            with self.subTest(drive_profile=drive_profile):
                plan = peer_plan(drive_profile)
                image = build_image_plan(plan)
                layout = combined_input_layout(plan, image)
                layout_offsets = {field.port: (field.raw_hi, field.raw_lo)
                                  for field in layout.fields if field.owner == "soc_peer"}
                runtime_offsets = {str(slot["name"]): (int(slot["raw_hi"]),
                                                       int(slot["raw_lo"]))
                                   for slot in _peer_raw_slots(plan, image)}
                self.assertEqual(layout_offsets, runtime_offsets)
                self.assertEqual(layout_offsets, FROZEN_PEER_RAW[drive_profile])


class ImageOverlayTransportTests(unittest.TestCase):
    """The candidate image is a pre-release overlay of the buffered raw record.

    The harness may only place a candidate the raw record really offered, at the
    address that record carries, so the offsets the overlay reads are the same
    frozen ABI the projector writes -- and the record it inspects is the record
    the cycle loop then drives.
    """

    def test_the_overlay_reads_the_offered_candidate_at_the_frozen_offsets(self) -> None:
        plan = ibex_plan()
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        text = render_profile_testbench(plan, image_plan=image)
        segments = {name: (image.segment(name).raw_hi, image.segment(name).raw_lo)
                    for name in FROZEN_IMAGE_RAW}
        self.assertEqual(FROZEN_IMAGE_RAW, segments)
        self.assertEqual(141, layout.raw_width)
        for slot in image.candidates.slots():
            value_name = "data" if slot.kind == "instruction" else "value"
            offer = image.segment(f"{slot.prefix}_offer")
            address = image.segment(f"{slot.prefix}_address")
            payload = image.segment(f"{slot.prefix}_{value_name}")
            be = image.segment(f"{slot.prefix}_be")
            with self.subTest(slot=slot.prefix):
                self.assertIn(f"      if (sample_words[cycle_index][{offer.raw_hi}:"
                              f"{offer.raw_lo}]) begin", text)
                self.assertIn(f"        image_address = sample_words[cycle_index]"
                              f"[{address.raw_hi}:{address.raw_lo}];", text)
                self.assertIn(f"        image_value = sample_words[cycle_index]"
                              f"[{payload.raw_hi}:{payload.raw_lo}];", text)
                self.assertIn(f"        image_be = sample_words[cycle_index]"
                              f"[{be.raw_hi}:{be.raw_lo}];", text)
                # Only the plan's own declared region may receive a placement.
                self.assertIn(f"dut.u_mem_{target_index(plan, slot.region_id)}"
                              f".initial_memory[image_address - 32'd{slot.region_base}",
                              text)
                self.assertIn(f"    if (placed_{slot.prefix}_kind) begin", text)

    def test_the_cycle_loop_drives_the_buffered_record_at_the_combined_width(self) -> None:
        """One raw word per cycle, and the buffered record is that same word.

        The buffer is bounded by the cycle bound rather than by the number of
        declared candidate slots: an offer near the end of a long record has to
        survive the buffering for the overlay to see it at all.
        """
        plan = ibex_plan()
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        text = render_profile_testbench(plan, image_plan=image)
        self.assertEqual(layout.raw_width, image.raw_width)
        self.assertIn(f"  localparam integer RAW_WIDTH = {layout.raw_width};", text)
        self.assertIn(f"  logic [RAW_WIDTH-1:0] sample_words [0:MAX_CYCLES-1];", text)
        self.assertIn("      sample_words[cycle_index] = raw_word;", text)
        self.assertIn("      raw_word = sample_words[cycle_index];", text)
        self.assertIn("      raw_bits = raw_word[RAW_WIDTH-1:0];", text)
        self.assertLessEqual(CYCLES, MAX_CYCLES)


class FrozenBootProgramTests(unittest.TestCase):
    """The A/B's boot program is derived from the plan, not written by hand.

    A boot image that does not match the plan leaves the CPU executing nothing,
    and an A/B on top of that would compare two empty runs; these assertions are
    what makes "the candidate replaced the word the program executes" a fact about
    this plan rather than about a checked-in file.
    """

    def test_the_boot_image_holds_the_word_the_candidates_replace(self) -> None:
        plan = ibex_plan()
        image = build_image_plan(plan)
        path = ibex_boot_image(plan)
        data = bytes(int(item, 16)
                     for item in path.read_text(encoding="utf-8").split())
        offset = IBEX_SLOT_ADDRESS - image.base
        self.assertEqual(BOOT_SLOT_WORD,
                         int.from_bytes(data[offset:offset + 4], "little"))
        self.assertEqual(encode_sw(5, 3, RAM_SCRATCH_OFFSET),
                         int.from_bytes(data[offset + 4:offset + 8], "little"))

    def test_the_fallback_program_declares_the_offered_slot_first(self) -> None:
        plan = ibex_plan()
        program, image = fallback_boot_program(plan)
        slot = program.slots.instruction[0]
        self.assertEqual(IBEX_SLOT_ADDRESS, slot.declared_address)
        offset = IBEX_SLOT_ADDRESS - program.image.base
        self.assertEqual(BOOT_SLOT_WORD, int.from_bytes(image[offset:offset + 4], "little"))


# ---------------------------------------------------------------------------
# the real Ibex: one raw field, one different bus write
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real SoC transport run")
class IbexCandidateTransportTests(unittest.TestCase):
    """One changed raw ``init_data`` field changes what the real Ibex does.

    The build is compiled once: the same plan, the same executable and the same
    frozen boot image serve the control run and both candidates, so the only thing
    that differs between them is the raw word the record offers.

    * ``control`` offers nothing: the boot image's own ``addi x5, x0, 0x123``
      executes and the program stores 0x123;
    * ``candidate-A`` offers that same word through the raw ``init_data`` field:
      the reference ISA layer resolves the payload's selector to ``xori``, the
      placed word executes, and the run must reproduce the control's writes;
    * ``candidate-B`` offers a word that differs only in the low nibble of the
      immediate: the same operation stores 0x12C instead.

    The transport is asserted on the harness's own pre-release evidence -- the
    placement the overlay reports, the memory word the CPU fetches and the RAM
    word the program leaves behind -- and then on the CPU's real write
    transactions.  A run whose boot image does not match the plan executes
    nothing, which is why the image is taken from the recorded fixture (or frozen
    from this plan) rather than written by hand.
    """

    build_timeout_s = int(os.environ.get("MYFUZZ_SOC_TRANSPORT_BUILD_TIMEOUT_S", "1800"))

    @classmethod
    def setUpClass(cls) -> None:
        if not OPT_IN:
            raise unittest.SkipTest("set MYFUZZ_SOC_REAL=1 for the real SoC transport run")
        if shutil.which("verilator") is None:
            raise AssertionError("Verilator is required for the real SoC transport run")
        cls.started = time.monotonic()
        cls.plan = ibex_plan()
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(
            cls.plan, instruction_candidates=1, data_candidates=1)
        cls.arm = cls.arms["dependency_repair"]
        cls.boot_image = ibex_boot_image(cls.plan)
        cls.ram_instance = target_index(cls.plan, cls.image.data_region_id)
        cls.rom_instance = target_index(cls.plan, cls.image.region_id)
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-transport-", dir=ROOT)
        cls.build = build_profile_runtime(
            cls.plan, output_dir=Path(cls._temporary.name) / "ibex", base_dir=ROOT,
            top_text=render_composition(cls.plan)["myfuzz_soc_top.sv"],
            sources=[item["path"] for item in source_list(cls.plan)
                     if item["role"] != "include_root"],
            boot_image=cls.boot_image, image_plan=cls.image,
            timeout_seconds=cls.build_timeout_s)
        cls.executable_hash = file_hash(cls.build.executable)
        cls.records = {label: cls._record(word)
                       for label, word in (("control", None), ("A", CANDIDATE_A),
                                           ("B", CANDIDATE_B))}
        cls.results = {label: cls._run(record, index + 1)
                       for index, (label, record) in enumerate(cls.records.items())}
        cls.placed = {label: cls._placed_word(record)
                      for label, record in cls.records.items() if label != "control"}
        print("\nMYFUZZ_SOC_TRANSPORT_TIMING build_s=%.1f boot_image=%s raw_width=%d "
              "writes=%d" % (time.monotonic() - cls.started, cls.boot_image.name,
                             cls.build.raw_width, len(cls.results["B"].requests)))

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    # -- fixtures ----------------------------------------------------------

    @classmethod
    def _record(cls, word: int | None) -> tuple[int, ...]:
        """The projected record: at most one offered candidate, at a fixed cycle."""
        raw = [0] * CYCLES
        if word is not None:
            value = 0
            for role, setting in (("init_offer", 1),
                                  ("init_address", IBEX_SLOT_ADDRESS),
                                  ("init_data", word), ("init_be", 0xF)):
                value = put(value, field_by_role(cls.layout, "soc_image", role), setting)
            raw[CANDIDATE_CYCLE] = value
        return tuple(int(item) for item in cls.arm.project_records(raw))

    @classmethod
    def _placed_word(cls, record: tuple[int, ...]) -> int:
        """The word the harness would really write for this record's offer."""
        records = cls.image.materialize_many(list(record)).initialization_records
        assert len(records) == 1, records
        return int(records[0]["corrected_candidate"]["data"])

    @classmethod
    def _run(cls, record: tuple[int, ...], request_id: int):
        result = soc_runtime.run_sample(
            cls.build, RuntimeSample(request_id=request_id, raw=record))
        if result.status != "OK":
            raise AssertionError(f"request {request_id}: {result.status} {result.reason} "
                                 f"{result.stdout[-2000:]}")
        return result

    def placements(self, label: str) -> list[dict[str, object]]:
        return [dict(item) for item in self.results[label].image_placements
                if str(item["slot"]) == "init"]

    # -- the candidate really reaches the memory the CPU fetches from ------

    def test_the_offered_candidate_is_placed_before_the_cpu_is_released(self) -> None:
        for label in ("A", "B"):
            with self.subTest(candidate=label):
                placements = self.placements(label)
                self.assertEqual(1, len(placements), placements)
                placement = placements[0]
                self.assertEqual("instruction", placement["kind"])
                self.assertEqual(IBEX_SLOT_ADDRESS, int(placement["addr"]))
                self.assertTrue(placement["reset_held"])
                # The readback is the value the memory model the CPU fetches from
                # really holds, i.e. the word the reference ISA layer froze.
                self.assertEqual(self.placed[label], int(placement["readback"]))
                self.assertEqual(
                    self.placed[label],
                    memory_word(self.results[label], self.rom_instance,
                                self.image.base, IBEX_SLOT_ADDRESS))
                self.assertEqual([], list(self.results[label].image_errors))
        # The control offers nothing, so its slot still holds the boot image's own
        # word: the difference below is the offer's, not the boot image's.
        self.assertEqual([], self.placements("control"))
        self.assertEqual(
            BOOT_SLOT_WORD,
            memory_word(self.results["control"], self.rom_instance, self.image.base,
                        IBEX_SLOT_ADDRESS))

    def test_the_candidate_word_is_what_the_cpu_fetched_and_what_ram_holds(self) -> None:
        for label in ("A", "B"):
            with self.subTest(candidate=label):
                result = self.results[label]
                self.assertEqual({self.placed[label]},
                                 fetched_words(result, IBEX_SLOT_ADDRESS),
                                 "the CPU did not fetch the placed candidate")
                self.assertEqual(
                    immediate(self.placed[label]),
                    memory_word(result, self.ram_instance, self.image.data_base,
                                self.image.data_base + RAM_SCRATCH_OFFSET))
        # The control is the same address with the boot image's own word in place,
        # which is what makes the replacement above attributable.
        self.assertEqual({BOOT_SLOT_WORD},
                         fetched_words(self.results["control"], IBEX_SLOT_ADDRESS))

    # -- the A/B -----------------------------------------------------------

    def test_one_changed_init_data_field_changes_the_cpu_s_real_writes(self) -> None:
        control = writes(self.results["control"])
        first = writes(self.results["A"])
        second = writes(self.results["B"])
        self.assertTrue(control, "the boot program never wrote to the fabric")
        # Offering the boot image's own word really places that word, so the A/B
        # compares two runs of one program and not two different programs.
        self.assertEqual(control, first)
        self.assertNotEqual(first, second)
        # Only the stored value moved; every address is the one the boot program
        # uses.  The value is the immediate the raw field carried: both candidates
        # encode rs1 = x0 and the reference ISA layer resolves their selector to a
        # bitwise XOR with zero, which is the identity on the immediate.
        self.assertEqual([addr for _, addr, _ in first],
                         [addr for _, addr, _ in second])
        self.assertEqual({immediate(CANDIDATE_A)}, {value for _, _, value in first})
        self.assertEqual({immediate(CANDIDATE_B)}, {value for _, _, value in second})

    def test_the_two_records_differ_in_exactly_the_offered_field(self) -> None:
        first = self.records["A"]
        second = self.records["B"]
        field = field_by_role(self.layout, "soc_image", "init_data")
        mask = ((1 << field.width) - 1) << field.raw_lo
        difference = (CANDIDATE_A ^ CANDIDATE_B) << field.raw_lo
        self.assertEqual([(CANDIDATE_CYCLE, difference)],
                         [(index, left ^ right) for index, (left, right)
                          in enumerate(zip(first, second)) if left != right])
        # The whole difference stays inside the one field the samples changed.
        self.assertEqual(0, difference & ~mask)
        for other in self.layout.fields:
            if other.field_id == field.field_id:
                continue
            with self.subTest(field=other.field_id):
                self.assertEqual(segment(first[CANDIDATE_CYCLE], other),
                                 segment(second[CANDIDATE_CYCLE], other))

    def test_the_placed_words_differ_only_in_the_immediate(self) -> None:
        """The reference ISA layer may repair the payload; the difference survives."""
        first = self.placed["A"]
        second = self.placed["B"]
        self.assertNotEqual(first, second)
        self.assertEqual(CANDIDATE_A ^ CANDIDATE_B, first ^ second)
        self.assertEqual(0, (first ^ second) & ~0x00F0_0000)
        # The immediate the raw field carried is the immediate the CPU executes.
        self.assertEqual(immediate(CANDIDATE_A), immediate(first))
        self.assertEqual(immediate(CANDIDATE_B), immediate(second))
        self.assertNotEqual(BOOT_SLOT_WORD, second,
                            "the A/B would be vacuous if both candidates placed the boot word")

    # -- identity and replay ----------------------------------------------

    def test_both_candidates_ran_on_one_build_and_one_executable(self) -> None:
        """One plan, one ABI, one executable -- and the build's own record says so.

        The build records the plan and the *profile* layout it consumed plus the
        image plan it overlays; the combined ABI those two make up is what the
        testbench consumes, so its width is the width both samples were projected
        at.
        """
        text = self.build.testbench_path.read_text(encoding="utf-8")
        recorded = recorded_build_identity(self.build)
        identity = build_identity(self.plan, self.build, self.policy)
        self.assertEqual({"plan_hash": self.plan.plan_hash,
                          "layout_hash": str(self.plan.raw_layout["layout_hash"])},
                         recorded)
        self.assertIn(f"// image plan: {self.image.image_hash}", text)
        self.assertEqual(recorded, identity["recorded_build_identity"])
        self.assertEqual(self.layout.raw_width, self.build.raw_width)
        self.assertEqual(self.build.build_hash, identity["build_hash"])
        self.assertEqual(self.executable_hash, identity["tool"]["executable_hash"])
        # Both samples went through this one build: the executable is unchanged
        # after them, and it is the same file the identity names.
        self.assertEqual(self.executable_hash, file_hash(self.build.executable))
        self.assertTrue(self.results["A"].requests and self.results["B"].requests)

    def test_a_replayed_candidate_reproduces_the_same_cpu_writes(self) -> None:
        replay = self._run(self.records["B"], request_id=4)
        self.assertEqual(self.results["B"].document()["fabric_requests"],
                         replay.document()["fabric_requests"])
        self.assertEqual(dict(self.results["B"].observations), dict(replay.observations))
        self.assertEqual([dict(item) for item in self.results["B"].image_placements],
                         [dict(item) for item in replay.image_placements])


# ---------------------------------------------------------------------------
# the real peers: one raw field, one different register readback
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer transport run")
class PeerRawEventTransportTests(_PeerRuntimeFixture):
    """One changed peer raw field changes what the peripheral really does.

    A raw request field is a level the peer model latches itself, so a one-cycle
    raw pulse on ``uart0__tx_request_valid_i`` is exactly one offered byte.  Three
    pairs are measured against one compiled build, and every record carries an
    **empty** peer event plan -- asserted below through ``peer_applied``, which is
    the harness's record of the events it really applied -- so the behaviour is
    attributable to the raw fields and not to the event route:

    * ``uart.tx_byte:tx_request_data_i`` 0x5A -> 0xC3: the component's own RXDATA
      register returns the byte the raw field carried;
    * ``uart.tx_byte:tx_request_valid_i`` 1 -> 0: with no offer, no frame is
      driven, so the component's STATUS never reports a received byte;
    * ``gpio.drive:peer_drive_value_i`` 0x05 -> 0x3A, with the drive valid bits
      held: the component's own DATA_IN register samples the peer's level.

    The expectation is the register the *component* returns through
    ``RunResult.responses`` -- an address-attributed read of the peripheral under
    test -- and never the peer's own success counter.  The UART pair shows why
    that distinction matters: ``uart0__tx_sent_count_o`` is 1 in both runs, so a
    counter-derived expectation could not tell the two candidates apart, while
    the received byte does.  The peer counter is corroboration, not the criterion.

    Measured limitation of the independent oracle: ``soc_peer_oracle.v1`` derives
    its UART transmit expectation from the *event plan*, which is empty here, so
    it reports ``uart-tx-sent-count: mismatch`` for a raw-driven frame that really
    arrived.  That check is therefore not the raw route's criterion and is left
    unasserted; the register readback above is.
    """

    build_timeout_s = int(os.environ.get("MYFUZZ_SOC_PEER_BUILD_TIMEOUT_S", "1800"))
    cycles = 200

    @classmethod
    def setUpClass(cls) -> None:
        if not OPT_IN:
            raise unittest.SkipTest("set MYFUZZ_SOC_REAL=1 for the real peer transport run")
        if shutil.which("verilator") is None:
            raise AssertionError("Verilator is required for the real peer transport run")
        cls.started = time.monotonic()
        cls.plan = build_peer_plan()
        cls.image, cls.layout, cls.policy, cls.arms = arms_for(
            cls.plan, instruction_candidates=1, data_candidates=1)
        cls.arm = cls.arms["dependency_repair"]
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-peer-raw-", dir=ROOT)
        cls.build = build_profile_runtime(
            cls.plan, output_dir=Path(cls._temporary.name) / "peers", base_dir=ROOT,
            top_text=render_composition(cls.plan)["myfuzz_soc_top.sv"],
            sources=[item["path"] for item in source_list(cls.plan)
                     if item["role"] != "include_root"],
            image_plan=cls.image, timeout_seconds=cls.build_timeout_s)
        cls.executable_hash = file_hash(cls.build.executable)
        cls.records = {
            "uart-data-0x5A": cls._uart_record(data=UART_PEER_BYTE, valid=1),
            "uart-data-0xC3": cls._uart_record(data=ALT_PEER_BYTE, valid=1),
            "uart-valid-on": cls._uart_record(data=UART_PEER_BYTE, valid=1),
            "uart-valid-off": cls._uart_record(data=UART_PEER_BYTE, valid=0),
            "gpio-value-0x05": cls._gpio_record(drive=0x05),
            "gpio-value-0x3A": cls._gpio_record(drive=0x3A),
        }
        cls.results = {label: cls._run(record, index + 1)
                       for index, (label, record) in enumerate(cls.records.items())}
        print("\nMYFUZZ_SOC_PEER_RAW_TIMING build_s=%.1f raw_width=%d samples=%d"
              % (time.monotonic() - cls.started, cls.build.raw_width, len(cls.results)))

    @classmethod
    def _uart_record(cls, *, data: int, valid: int) -> tuple[int, ...]:
        """One record that offers one peer byte and reads the peripheral back."""
        raw = [0] * cls.cycles
        raw[4] = _offer_word(cls.plan, "uart0_win", UART_CTRL, 1, 0x7)
        raw[20] = peer_field(cls.layout, "uart.tx_byte:tx_request_data_i", data)
        if valid:
            raw[20] |= peer_field(cls.layout, "uart.tx_byte:tx_request_valid_i", 1)
        raw[150] = _offer_word(cls.plan, "uart0_win", UART_STATUS, 0)
        raw[170] = _offer_word(cls.plan, "uart0_win", UART_RXDATA, 0)
        return tuple(int(item) for item in cls.arm.project_records(raw))

    @classmethod
    def _gpio_record(cls, *, drive: int) -> tuple[int, ...]:
        """One record whose peer holds a drive level across the read."""
        raw = [0] * cls.cycles
        raw[4] = _offer_word(cls.plan, "gpio0_win", GPIO_DATA_OUT, 1, 0x00)
        raw[20] = _offer_word(cls.plan, "gpio0_win", GPIO_DIR, 1, 0x00)
        held = (peer_field(cls.layout, "gpio.drive:peer_drive_valid_i", 0xFF)
                | peer_field(cls.layout, "gpio.drive:peer_drive_value_i", drive))
        for cycle in range(30, cls.cycles):
            raw[cycle] |= held
        raw[60] |= _offer_word(cls.plan, "gpio0_win", GPIO_DATA_IN, 0)
        return tuple(int(item) for item in cls.arm.project_records(raw))

    @classmethod
    def _run(cls, record: tuple[int, ...], request_id: int):
        result = soc_runtime.run_sample(
            cls.build, RuntimeSample(request_id=request_id, raw=record))
        if result.status != "OK":
            raise AssertionError(f"request {request_id}: {result.status} {result.reason} "
                                 f"{result.stdout[-2000:]}")
        return result

    # -- the A/B pairs -----------------------------------------------------

    def test_a_different_raw_peer_byte_is_the_byte_the_peripheral_receives(self) -> None:
        first = self.results["uart-data-0x5A"]
        second = self.results["uart-data-0xC3"]
        self.assertEqual(UART_PEER_BYTE, self.reads(first, "uart0_win")[UART_RXDATA])
        self.assertEqual(ALT_PEER_BYTE, self.reads(second, "uart0_win")[UART_RXDATA])
        self.assertEqual(0b0011, self.reads(first, "uart0_win")[UART_STATUS] & 0b0011,
                         "the peripheral never reported the peer's byte")
        # The peer's own success counter is 1 in *both* runs: it cannot be the
        # expectation this pair is judged by, only corroboration that a frame ran.
        self.assertEqual(1, self.observation(first, "uart0__tx_sent_count_o"))
        self.assertEqual(1, self.observation(second, "uart0__tx_sent_count_o"))
        self.assertEqual(0, self.observation(first, "uart0__framing_error_count_o"))

    def test_the_raw_valid_field_decides_whether_a_frame_is_offered(self) -> None:
        offered = self.results["uart-valid-on"]
        silent = self.results["uart-valid-off"]
        self.assertEqual(1, self.reads(offered, "uart0_win")[UART_STATUS] & 0b0001,
                         "the offered byte never reached the peripheral")
        self.assertEqual(0, self.reads(silent, "uart0_win")[UART_STATUS] & 0b0001,
                         "a byte arrived although the raw offer bit stayed low")
        self.assertEqual(UART_PEER_BYTE, self.reads(offered, "uart0_win")[UART_RXDATA])
        self.assertEqual(0, self.reads(silent, "uart0_win")[UART_RXDATA])
        self.assertEqual(1, self.observation(offered, "uart0__tx_sent_count_o"))
        self.assertEqual(0, self.observation(silent, "uart0__tx_sent_count_o"))

    def test_a_different_raw_gpio_drive_value_is_what_the_component_samples(self) -> None:
        first = self.results["gpio-value-0x05"]
        second = self.results["gpio-value-0x3A"]
        self.assertEqual(0x05, self.reads(first, "gpio0_win")[GPIO_DATA_IN] & 0xFF,
                         "the component did not sample the peer's drive")
        self.assertEqual(0x3A, self.reads(second, "gpio0_win")[GPIO_DATA_IN] & 0xFF)
        self.assertEqual(0, self.observation(first, "gpio0__contention_count_o"))
        self.assertEqual(0, self.observation(second, "gpio0__contention_count_o"))

    def test_the_raw_fields_alone_drove_every_pair(self) -> None:
        """No declared peer event was applied, so the raw route is the cause."""
        for label, result in self.results.items():
            with self.subTest(sample=label):
                self.assertEqual((), tuple(result.peer_applied))
                self.assertEqual((), tuple(result.image_errors))

    def test_each_pair_changes_exactly_one_raw_field_of_one_record(self) -> None:
        pairs = (
            ("uart-data-0x5A", "uart-data-0xC3", "uart.tx_byte:tx_request_data_i"),
            ("uart-valid-on", "uart-valid-off", "uart.tx_byte:tx_request_valid_i"),
            ("gpio-value-0x05", "gpio-value-0x3A", "gpio.drive:peer_drive_value_i"),
        )
        for left, right, role in pairs:
            with self.subTest(field=role):
                field = field_by_role(self.layout, "soc_peer", role)
                mask = ((1 << field.width) - 1) << field.raw_lo
                differences = [left_word ^ right_word
                               for left_word, right_word
                               in zip(self.records[left], self.records[right])
                               if left_word != right_word]
                self.assertTrue(differences, "the pair changed nothing")
                for difference in differences:
                    self.assertEqual(0, difference & ~mask)
                self.assertNotEqual(self.results[left].document()["fabric_responses"],
                                    [], "the sample read nothing back")

    # -- identity ----------------------------------------------------------

    def test_every_pair_ran_on_one_build_and_one_executable(self) -> None:
        text = self.build.testbench_path.read_text(encoding="utf-8")
        identity = build_identity(self.plan, self.build, self.policy)
        self.assertEqual({"plan_hash": self.plan.plan_hash,
                          "layout_hash": str(self.plan.raw_layout["layout_hash"])},
                         recorded_build_identity(self.build))
        self.assertIn(f"// image plan: {self.image.image_hash}", text)
        self.assertEqual(self.layout.raw_width, self.build.raw_width)
        self.assertEqual(self.executable_hash, identity["tool"]["executable_hash"])
        self.assertEqual(self.executable_hash, file_hash(self.build.executable))


if __name__ == "__main__":                              # pragma: no cover
    unittest.main()
