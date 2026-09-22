"""Task D step D3, cases 3 and 4: the two negatives that protect issued state.

A negative case is worth exactly as much as what it proves about the run that
already happened.  This module covers the two refusals whose whole purpose is to
keep an input the test has already committed from being changed:

* **D3.3 -- a peer pulse pair closer than the slot's declared gap.**  The peer
  model would drop the second pulse of a pair that arrives too early, so the pair
  must never be reported as a passing test.  Both routes to a peer request must
  refuse it, with the *two conflicting cycles* in the message: "a pair was too
  close" is not evidence a reader can replay, the pair itself is.

  * the raw ABI route: ``decode_peer_raw_events`` raises
    ``PeerRawReplayError`` (``peer-event-gap-violation:<instance>:<slot>:...``)
    and the projector surfaces that name unchanged as a ``SocBuildError``;
  * the declared event plan route: ``validate_peer_events`` refuses the same
    pair (``peer-event-too-close:<slot>:...``) inside ``run_sample``, before the
    simulator is spawned.

* **D3.4 -- a second offer of an already committed input.**  One test may offer
  each declared slot once.  A repeated offer, and a candidate seed that would
  rewrite a frozen byte or land across a declared slot, are refused by the
  declared program's own name; and the positive record the DUT already produced
  must be byte-for-byte unchanged afterwards, with no run executed for the
  refused input.

What this module adds over the existing coverage
------------------------------------------------
``test_soc_input_arms_projection.PeerSpacingTests`` asserts the raw gap refusal
by prefix and one legal gap; ``test_soc_peer_models.PeerEventPlanTests`` covers
the event path against a hand-written slot table (unknown index, payload out of
range, two events too close, the event bound); ``test_soc_input_repair
.CommittedInputTests`` covers the committed-word and seed refusals at the
declared-program layer; ``test_soc_input_transport_ab`` asserts the refusal
prefix and that the driver was never reached; and ``test_soc_input_repair_runtime``
asserts the arm-level repeated offer behind ``MYFUZZ_SOC_REAL=1``.  None of them
pins the *exact cycles* the two gap messages name on both routes, none shows the
raw route and the event route agreeing on the plan's own declared slot table, and
none states the invariant this task is really about: a refused negative must not
mutate anything the DUT already produced.  That invariant is the centre of
:class:`RefusedInputKeepsTheIssuedRecordTests`, which drives one legal sample
first and compares the saved ``RunResult`` byte for byte afterwards.

The pure classes need no Verilator: the compiled simulator is replaced by its own
documented ``MYFUZZ_*`` stdout protocol (the production parser still reads it) and
by mocks on the two entry points that would start it.  A refused record is
offered a build whose executable does not exist, so a refusal that *did* reach
the driver fails loudly instead of quietly running nothing.
:class:`RealRefusalImmutabilityTests` repeats the sequence on a real compiled peer
SoC behind ``MYFUZZ_SOC_REAL=1``.
"""
from __future__ import annotations

import copy
import os
import shutil
import subprocess
import unittest
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.composition import soc_runtime
from myfuzz.composition.input_layout import InputLayout
from myfuzz.composition.soc_candidate_program import (
    CandidateProgram,
    CandidateProgramError,
)
from myfuzz.composition.soc_image import CandidateSlot
from myfuzz.composition.soc_peer_replay import (
    PeerRawReplayError,
    decode_peer_raw_events,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    MAX_PEER_EVENTS,
    PeerStimulusEvent,
    RunResult,
    RuntimeBuild,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
    validate_peer_events,
)
from myfuzz.contracts import canonical_bytes
from myfuzz.integration.soc_builder import SocBuildError

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_input_arms_projection import (
    arms_for,
    field_by_role,
    peer_plan,
    put,
)

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"

#: Where a purely refused test must never look.  The runtime builds used by the
#: pure classes point their executable and output directory here: if a refusal
#: let its record through, the attempt dies on a missing binary instead of
#: appearing to have run something.
UNBUILT = Path("/nonexistent-myfuzz-refused-input")

#: The two payload bytes the declared pulse slots carry in these samples.
PULSE_PAYLOADS = (0x5A, 0x3C)

#: The register offsets of the example UART the real sample below drives.
UART_CTRL, UART_RXDATA = 0x00, 0x0C


# ---------------------------------------------------------------------------
# fixtures: one real peer plan, one arm, and the raw words the plan declares
# ---------------------------------------------------------------------------


def arms_for_plan(plan, *, candidate_program: bool = False):
    """The dependency-repair arm over one plan, with the layout it was compiled for."""
    image, layout, policy, arms = arms_for(plan, candidate_program=candidate_program)
    return layout, arms["dependency_repair"]


def peer_arm(*, candidate_program: bool = False, drive_profile: str = "cpu_execute"):
    """The dependency-repair arm over the real peer request, and its slot table.

    The arm's own ``peer_slots`` is the table the raw route validated against --
    ``_peer_projection_slots`` joined the peer plan's declared timing contract to
    the compiled layout -- so the event route below is checked against exactly the
    declaration the raw route used.  That is what makes "the two routes agree" a
    statement about one table rather than about two copies of a constant.
    """
    plan = peer_plan(drive_profile)
    layout, arm = arms_for_plan(plan, candidate_program=candidate_program)
    return plan, layout, arm


def field_for_port(layout: InputLayout, port: str):
    matches = [field for field in layout.fields if field.port == port]
    if len(matches) != 1:
        raise AssertionError(f"expected one raw field for {port}, found {len(matches)}")
    return matches[0]


def pulse_word(layout: InputLayout, plan, instance_id: str, slot_name: str,
               payload: int) -> int:
    """One raw cycle asserting one declared pulse slot and carrying its payload.

    The offsets come from the compiled layout, never from a copy of the ABI: a
    layout change has to fail here rather than silently drive another port.
    """
    peers = [item for item in plan.peers if item.instance_id == instance_id]
    if len(peers) != 1:
        raise AssertionError(f"the plan declares no peer instance {instance_id}")
    slots = [item for item in peers[0].slots if item.slot == slot_name]
    if len(slots) != 1:
        raise AssertionError(f"{instance_id} declares no slot {slot_name}")
    signals = slots[0].signals
    if not any(signal.source == "pulse" for signal in signals):
        raise AssertionError(f"{instance_id}/{slot_name} declares no pulse signal")
    raw, low_width = 0, 0
    for signal in signals:
        field = field_for_port(layout, signal.top_port)
        if signal.source == "pulse":
            raw = put(raw, field, 1)
        elif signal.source == "payload":
            raw = put(raw, field, payload)
        elif signal.source == "payload_low":
            raw = put(raw, field, payload & ((1 << signal.width) - 1))
            low_width = int(signal.width)
        elif signal.source == "payload_high":
            raw = put(raw, field, (payload >> low_width) & ((1 << signal.width) - 1))
    return raw


def slot_word(program: CandidateProgram, layout: InputLayout, slot: CandidateSlot, *,
              word: int = 0x00000013, data: int = 0x1234ABCD,
              address: int | None = None, be: int = 0xF) -> int:
    """One raw cycle offering one declared slot.

    The address is the slot's declared one unless a caller asks for another,
    which is how the committed-input tests show that the refusal names the
    address already committed rather than the one the second word asked for.
    """
    raw = 0
    settings = (
        ("offer", 1),
        ("address", slot.declared_address if address is None else address),
        ("data" if slot.kind == "instruction" else "value",
         word if slot.kind == "instruction" else data),
        ("be", be),
    )
    for name, value in settings:
        raw = put(raw, field_by_role(layout, "soc_image", slot.segment(name).name), value)
    return raw


def declared_words(program: CandidateProgram, layout: InputLayout) -> list[int]:
    """Every declared slot offered exactly once: this program's legal test."""
    return [slot_word(program, layout, slot) for slot in program.slots.slots()]


def gap_reason_raw(record, later: int, earlier: int) -> str:
    """The raw route's refusal for one conflicting pair, verbatim."""
    return (f"peer-event-gap-violation:{record['instance_id']}:{record['slot']}:"
            f"{later}-{earlier}<{record['minimum_gap_cycles']}")


def gap_reason_event(record, later: int, earlier: int) -> str:
    """The event route's refusal for the same pair, verbatim."""
    return (f"peer-event-too-close:{record['slot']}:{later}-{earlier}"
            f"<{record['minimum_gap_cycles']} ({record['instance_id']})")


def unbuilt_runtime(layout: InputLayout, peer_slots) -> RuntimeBuild:
    """A runtime build record with no compiled executable behind it.

    Only what a refusal reads is filled in: the raw width, the layout's own field
    table (so ``run_sample`` can build an applied trace) and the *projector's own*
    peer slot table.
    """
    return RuntimeBuild(
        output_dir=UNBUILT, top_path=UNBUILT / "myfuzz_soc_top.sv",
        testbench_path=UNBUILT / "profile_tb.sv",
        executable=UNBUILT / "obj_dir" / "myfuzz_profile_sim", sources=(),
        raw_width=int(layout.raw_width),
        slots=tuple({"name": str(field.port or field.role), "width": int(field.width),
                     "raw_lo": int(field.raw_lo)} for field in layout.fields),
        observations=(), boot_image=None, boot_image_policy="no_preloaded_region",
        build_hash="sha256:" + "0" * 64,
        peer_slots=tuple(dict(record) for record in peer_slots))


def scripted_harness_stdout(sample: RuntimeSample, build: RuntimeBuild) -> str:
    """The harness's documented ``MYFUZZ_*`` protocol, scripted for a pure test.

    The pure classes must not need Verilator, so the compiled simulator is
    replaced by the lines it would print -- but ``run_sample`` itself still parses
    them, which is what makes the positive record below a production record rather
    than a dataclass written by the test.  ``MYFUZZ_PEER_APPLIED`` mirrors the
    declared event plan, which is the harness's own report of what it applied.
    """
    by_index = {int(record["index"]): record for record in build.peer_slots}
    lines = [
        f"MYFUZZ_SOC_RUN status=OK cycles={len(sample.raw)} reason=",
        "MYFUZZ_REQ cycle=4 addr=0x80000010 write=1 wdata=deadbeef be=f source=0",
        "MYFUZZ_REQ cycle=6 addr=0x80000010 write=0 wdata=0 be=f source=0",
        "MYFUZZ_RSP seq=0 addr=0x80000010 write=1 rdata=0 source=0",
        "MYFUZZ_RSP seq=1 addr=0x80000010 write=0 rdata=deadbeef source=0",
        "MYFUZZ_APPLIED cycle=0 port=uart0__tx_request_data_i value=5a",
        "MYFUZZ_OBS uart0__tx_sent_count_o=1",
        "MYFUZZ_OBS uart0__rx_count_o=1",
    ]
    for event in sample.peer_events:
        record = by_index[int(event.slot)]
        lines.append(f"MYFUZZ_PEER_APPLIED cycle={int(event.cycle)} "
                     f"instance={record['instance_id']} slot={record['slot']} "
                     f"value={int(event.payload):x}")
    return "\n".join(lines) + "\n"


def scripted_simulator(sample: RuntimeSample, build: RuntimeBuild):
    """A ``subprocess.run`` stand-in answering with the scripted harness output."""
    return subprocess.CompletedProcess(
        args=["nice", "-n15", str(build.executable)], returncode=0,
        stdout=scripted_harness_stdout(sample, build), stderr="")


def project_then_run(arm, build: RuntimeBuild, values, *, request_id: int,
                     peer_events=()) -> RunResult:
    """The production chain: project one record, then drive the *projected* record.

    The driver receives ``project_records``' output, never the offered record, so
    a refusal raised here happens before the simulator entry point -- which is what
    the mocks in this module assert.
    """
    projected = tuple(int(value) for value in arm.project_records(values))
    sample = RuntimeSample(request_id=request_id, raw=projected,
                           peer_events=tuple(peer_events))
    return soc_runtime.run_sample(build, sample)


# ---------------------------------------------------------------------------
# D3.3, raw ABI route: the declared pulse gap
# ---------------------------------------------------------------------------


class RawPeerPulseGapRefusalTests(unittest.TestCase):
    """The declared gap is enforced on the per-cycle raw record itself.

    ``decode_peer_raw_events`` is the peer model's own decoder and raises
    ``PeerRawReplayError``; the projector surfaces that refusal name unchanged as
    a ``SocBuildError``.  Every cycle pair below is derived from the plan's
    declared ``minimum_gap_cycles``, so the assertions say *which* two requests
    conflicted -- and the last test proves the offending pair is reported, not
    merely the first pair in the record.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.layout, cls.arm = peer_arm()
        cls.pulse_slots = tuple(record for record in cls.arm.peer_slots
                                if str(record["kind"]) == "pulse_byte")
        if not cls.pulse_slots:
            raise AssertionError("the peer plan declares no pulse slot to check")

    def word_for(self, record) -> int:
        return pulse_word(self.layout, self.plan, str(record["instance_id"]),
                          str(record["slot"]), PULSE_PAYLOADS[0])

    def widest(self):
        """The pulse slot with the widest declared gap, for the sharpest pair."""
        return max(self.pulse_slots, key=lambda item: int(item["minimum_gap_cycles"]))

    def test_each_pulse_slot_accepts_exactly_its_declared_gap(self) -> None:
        """Distance == ``minimum_gap_cycles`` is legal; the peer keeps the pulse."""
        for record in self.pulse_slots:
            with self.subTest(slot=record["slot"]):
                gap = int(record["minimum_gap_cycles"])
                self.assertGreater(gap, 1, "a gap of one leaves no closer pair to refuse")
                word = self.word_for(record)
                values = [word] + [0] * (gap - 1) + [word]
                projected = self.arm.project_records(values)
                self.assertEqual(len(values), len(projected))
                events = [event for event in self.arm.last_peer_events
                          if event["slot"] == record["slot"]]
                self.assertEqual([0, gap], [int(event["cycle"]) for event in events])
                self.assertEqual([PULSE_PAYLOADS[0]] * 2,
                                 [int(event["payload"]) for event in events])

    def test_one_cycle_closer_is_refused_with_both_cycles(self) -> None:
        """Distance == gap - 1 is refused, naming the pair and the gap."""
        for record in self.pulse_slots:
            with self.subTest(slot=record["slot"]):
                gap = int(record["minimum_gap_cycles"])
                word = self.word_for(record)
                values = [word] + [0] * (gap - 2) + [word]
                expected = gap_reason_raw(record, gap - 1, 0)
                with self.assertRaises(SocBuildError) as caught:
                    self.arm.project_records(values)
                self.assertEqual(expected, str(caught.exception))
                # The projector invents no second name: the model's own refusal
                # is the cause, verbatim.
                self.assertIsInstance(caught.exception.__cause__, PeerRawReplayError)
                self.assertEqual(expected, str(caught.exception.__cause__))

    def test_the_reported_pair_is_the_offending_pair_not_the_first(self) -> None:
        """Three pulses: the third is refused against the second, not the first.

        A message that always named the record's first event would pass a
        prefix-only assertion and still be useless for replay; this pins the
        reported cycles to the pair that really conflicts.
        """
        record = self.widest()
        gap = int(record["minimum_gap_cycles"])
        word = self.word_for(record)
        values = [word] + [0] * (gap - 1) + [word, word]
        expected = gap_reason_raw(record, gap + 1, gap)
        with self.assertRaises(SocBuildError) as caught:
            self.arm.project_records(values)
        self.assertEqual(expected, str(caught.exception))

    def test_the_decoder_raises_the_models_own_error_name(self) -> None:
        """The raw decoder itself refuses, and the observing decode still records.

        ``validate_spacing=False`` is the direct-input arm's documented escape
        hatch: the record is *observed* rather than projected, so the refusal of
        the constrained arms is a policy and not a decoder defect.
        """
        record = self.widest()
        gap = int(record["minimum_gap_cycles"])
        word = self.word_for(record)
        values = [word] + [0] * (gap - 2) + [word]
        expected = gap_reason_raw(record, gap - 1, 0)
        with self.assertRaises(PeerRawReplayError) as caught:
            decode_peer_raw_events(values, self.layout, self.arm.peer_slots)
        self.assertEqual(expected, str(caught.exception))
        recorded = decode_peer_raw_events(values, self.layout, self.arm.peer_slots,
                                          validate_spacing=False)
        self.assertEqual([0, gap - 1], [int(event["cycle"]) for event in recorded])

    def test_a_refused_sequence_does_not_replace_the_last_accepted_events(self) -> None:
        """The projector's saved decode still describes the accepted test."""
        record = self.widest()
        gap = int(record["minimum_gap_cycles"])
        word = self.word_for(record)
        self.arm.project_records([word] + [0] * (gap - 1) + [word])
        accepted = self.arm.last_peer_events
        self.assertEqual(2, len(accepted))
        with self.assertRaises(SocBuildError):
            self.arm.project_records([word] + [0] * (gap - 2) + [word])
        self.assertEqual(accepted, self.arm.last_peer_events)


# ---------------------------------------------------------------------------
# D3.3, declared event plan route: the same declaration, the same pair
# ---------------------------------------------------------------------------


class PeerEventPlanGapRefusalTests(unittest.TestCase):
    """The same declared gap, checked inside ``run_sample`` before it drives.

    ``validate_peer_events`` is the gate ``run_sample`` calls before it builds a
    command, so a refused plan cannot spawn the simulator.  The slot table here is
    the projector's own ``peer_slots`` -- the very table the raw route used -- and
    :meth:`test_both_routes_name_the_same_pair` reads both messages back to show
    they agree on the slot, the gap and the cycle pair.

    The event route's *other* refusals (an unknown slot index, a payload wider
    than the slot, the ``MAX_PEER_EVENTS`` bound) are already covered by
    ``test_soc_peer_models.PeerEventPlanTests`` against a hand-written table.  This
    class therefore adds their raw-ABI counterparts and the exact message the real
    plan's own table produces, instead of repeating those cases.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.layout, cls.arm = peer_arm()
        cls.build = unbuilt_runtime(cls.layout, cls.arm.peer_slots)
        cls.pulse_slots = tuple(record for record in cls.arm.peer_slots
                                if str(record["kind"]) == "pulse_byte")
        if not cls.pulse_slots:
            raise AssertionError("the peer plan declares no pulse slot to check")
        cls.widest = max(cls.pulse_slots,
                         key=lambda item: int(item["minimum_gap_cycles"]))
        cls.gap = int(cls.widest["minimum_gap_cycles"])
        cls.index = int(cls.widest["index"])
        cls.word = pulse_word(cls.layout, cls.plan, str(cls.widest["instance_id"]),
                              str(cls.widest["slot"]), PULSE_PAYLOADS[0])

    def event(self, cycle: int, payload: int) -> PeerStimulusEvent:
        return PeerStimulusEvent(slot=self.index, cycle=cycle, payload=payload)

    def test_the_event_plan_accepts_exactly_the_declared_gap(self) -> None:
        sample = RuntimeSample(request_id=1, raw=(0,), peer_events=(
            self.event(10, PULSE_PAYLOADS[0]), self.event(10 + self.gap, PULSE_PAYLOADS[1])))
        validate_peer_events(self.build, sample)          # must not raise
        self.assertEqual(
            ["P 2", f"{self.index} 10 {PULSE_PAYLOADS[0]:x}",
             f"{self.index} {10 + self.gap} {PULSE_PAYLOADS[1]:x}"],
            sample.payload().splitlines()[2:5])

    def test_one_cycle_closer_is_refused_with_both_cycles(self) -> None:
        closer = 10 + self.gap - 1
        sample = RuntimeSample(request_id=2, raw=(0,), peer_events=(
            self.event(10, PULSE_PAYLOADS[0]), self.event(closer, PULSE_PAYLOADS[1])))
        with self.assertRaises(SocRuntimeError) as caught:
            validate_peer_events(self.build, sample)
        self.assertEqual(gap_reason_event(self.widest, closer, 10), str(caught.exception))

    def test_both_routes_name_the_same_pair(self) -> None:
        """One declaration, one conflict: the two messages agree field for field."""
        earlier, later = 10, 10 + self.gap - 1
        values = ([0] * earlier + [self.word] + [0] * (later - earlier - 1)
                  + [self.word])
        with self.assertRaises(SocBuildError) as raw_error:
            self.arm.project_records(values)
        with self.assertRaises(SocRuntimeError) as event_error:
            validate_peer_events(self.build, RuntimeSample(request_id=3, raw=(0,), peer_events=(
                self.event(earlier, PULSE_PAYLOADS[0]),
                self.event(later, PULSE_PAYLOADS[1]))))
        self.assertEqual(gap_reason_raw(self.widest, later, earlier),
                         str(raw_error.exception))
        self.assertEqual(gap_reason_event(self.widest, later, earlier),
                         str(event_error.exception))
        shared = (f"{self.widest['slot']}:{later}-{earlier}<{self.gap}")
        self.assertTrue(str(raw_error.exception).endswith(shared), str(raw_error.exception))
        self.assertTrue(str(event_error.exception).startswith(
            f"peer-event-too-close:{shared}"), str(event_error.exception))

    def test_the_event_plan_is_refused_before_the_simulator_is_spawned(self) -> None:
        """The gate runs before any command is built, with a positive control."""
        refused = RuntimeSample(request_id=4, raw=(0,), peer_events=(
            self.event(10, PULSE_PAYLOADS[0]),
            self.event(10 + self.gap - 1, PULSE_PAYLOADS[1])))
        legal = RuntimeSample(request_id=5, raw=(0,), peer_events=(
            self.event(10, PULSE_PAYLOADS[0]),
            self.event(10 + self.gap, PULSE_PAYLOADS[1])))
        with unittest.mock.patch.object(
                soc_runtime.subprocess, "run",
                return_value=scripted_simulator(legal, self.build)) as simulator:
            with self.assertRaises(SocRuntimeError) as caught:
                run_sample(self.build, refused)
            simulator.assert_not_called()
            # The same entry point does spawn the simulator for a legal plan, so
            # "never called" is not an artefact of a path that is wired to nothing.
            self.assertEqual("OK", run_sample(self.build, legal).status)
            simulator.assert_called_once()
        self.assertEqual(gap_reason_event(self.widest, 10 + self.gap - 1, 10),
                         str(caught.exception))

    def test_the_raw_abi_cannot_express_the_payload_the_event_plan_refuses(self) -> None:
        """A payload bound is an event-plan-only refusal, by construction.

        The raw ABI carries a payload as the declared layout fields themselves, so
        the largest payload a raw word can express is ``2**width - 1`` and it is
        read back in full.  The event plan carries a free integer, so it is that
        route which needs the check -- and it names the slot and the bound.
        """
        for record in self.pulse_slots:
            with self.subTest(slot=record["slot"]):
                width = int(record["width"])
                payload_width = sum(int(signal["width"]) for signal in record["signals"]
                                    if str(signal["source"]).startswith("payload"))
                self.assertLessEqual(payload_width, width)
                maximum = pulse_word(
                    self.layout, self.plan, str(record["instance_id"]),
                    str(record["slot"]), (1 << payload_width) - 1)
                # The largest expressible payload is driven, not refused...
                self.assertEqual(1, len(self.arm.project_records([maximum])))
                events = [event for event in self.arm.last_peer_events
                          if event["slot"] == record["slot"]]
                self.assertEqual(1, len(events))
                self.assertEqual((1 << payload_width) - 1, int(events[0]["payload"]))
                # ... and the event plan's free integer is refused at the bound.
                sample = RuntimeSample(request_id=6, raw=(0,), peer_events=(
                    PeerStimulusEvent(slot=int(record["index"]), cycle=0,
                                      payload=1 << width),))
                with self.assertRaises(SocRuntimeError) as caught:
                    validate_peer_events(self.build, sample)
                self.assertEqual(
                    f"peer-event-payload-out-of-range:{record['slot']}:"
                    f"{1 << width}!<{1 << width}", str(caught.exception))

    def test_the_raw_abi_cannot_name_a_slot_the_plan_never_declared(self) -> None:
        """Only the event plan addresses a slot by index, and a foreign index is refused.

        Every raw peer field belongs to exactly one declared slot, so a raw record
        cannot express a slot that was never declared; the index namespace is the
        declared table's own, contiguous from zero.
        """
        declared_ports = {int(record["index"]): {str(signal["top_port"])
                                                for signal in record["signals"]}
                          for record in self.arm.peer_slots}
        indices = sorted(declared_ports)
        self.assertEqual(list(range(len(self.arm.peer_slots))), indices)
        layout_ports = {field.port for field in self.layout.fields
                        if field.owner == "soc_peer"}
        self.assertEqual(set().union(*declared_ports.values()), layout_ports)
        foreign = len(self.arm.peer_slots)
        sample = RuntimeSample(request_id=7, raw=(0,), peer_events=(
            PeerStimulusEvent(slot=foreign, cycle=0, payload=1),))
        with self.assertRaises(SocRuntimeError) as caught:
            validate_peer_events(self.build, sample)
        self.assertEqual(f"peer-event-unknown-slot:{foreign}: the plan declares {indices}",
                         str(caught.exception))

    def test_the_event_plan_bound_is_exactly_the_declared_maximum(self) -> None:
        """Both sides of one bound: exactly ``MAX_PEER_EVENTS`` is accepted.

        The refusal itself is already covered by ``test_soc_peer_models``; what is
        added here is the accepted side, so "the bound" is pinned from both ends
        and a bound that silently shrank would fail.
        """
        bound = MAX_PEER_EVENTS
        accepted = RuntimeSample(request_id=8, raw=(0,), peer_events=tuple(
            PeerStimulusEvent(slot=0, cycle=index, payload=1) for index in range(bound)))
        self.assertEqual(bound, len(accepted.peer_events))
        with self.assertRaises(SocRuntimeError) as caught:
            RuntimeSample(request_id=9, raw=(0,), peer_events=tuple(
                PeerStimulusEvent(slot=0, cycle=index, payload=1)
                for index in range(bound + 1)))
        self.assertEqual(f"peer-event-plan-exceeds-bound:{bound + 1}>{bound}",
                         str(caught.exception))


# ---------------------------------------------------------------------------
# D3.4: an input the test already committed may not be rewritten
# ---------------------------------------------------------------------------


class CommittedInputRefusalTests(unittest.TestCase):
    """One offer per declared slot, and nothing may rewrite a frozen byte.

    ``tests/composition/test_soc_input_repair.py`` covers these refusals at the
    unit level and ``test_soc_input_transport_ab`` asserts the arm refuses a
    repeated offer by prefix; what this class adds is the arm boundary against the
    real layout, the *committed* address in the message (not the address the
    second word asked for), both seed refusals, and the fact that a refused test
    leaves the arm's own record of the accepted test untouched.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.layout, cls.arm = peer_arm(candidate_program=True)
        cls.program = cls.arm.candidate_program
        if cls.program is None:
            raise AssertionError("the arm was built without a declared program")
        cls.legal = declared_words(cls.program, cls.layout)
        cls.slot = cls.program.slots.instruction[0]

    def committed_reason(self, slot=None) -> str:
        slot = self.slot if slot is None else slot
        return (f"repair-would-rewrite-committed-word:{slot.prefix}:"
                f"0x{slot.declared_address:08x}")

    def second_offer(self) -> int:
        """A second offer of the committed slot, deliberately at another address."""
        return slot_word(self.program, self.layout, self.slot, word=0x00000033,
                         address=self.slot.declared_address + 4)

    def test_the_declared_program_refuses_a_second_offer_of_one_slot(self) -> None:
        with self.assertRaises(CandidateProgramError) as caught:
            self.program.repairer().repair_test(self.legal + [self.second_offer()])
        # The name is the *committed* word's, not the address this offer asked for:
        # that is what makes the refusal point at the input already issued.
        self.assertEqual(self.committed_reason(), str(caught.exception))

    def test_the_projector_arm_surfaces_the_same_refusal(self) -> None:
        with self.assertRaises(SocBuildError) as caught:
            self.arm.project_records(self.legal + [self.second_offer()])
        self.assertEqual(self.committed_reason(), str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, CandidateProgramError)
        self.assertEqual(self.committed_reason(), str(caught.exception.__cause__))

    def test_a_refused_test_leaves_the_accepted_record_alone(self) -> None:
        """The arm's own record and counters still describe the accepted test."""
        projected = list(self.arm.project_records(self.legal))
        repaired = self.arm.last_repaired_test
        counters = dict(self.arm.repair_counts)
        placements = tuple(repaired.placements)
        self.assertEqual(len(self.legal), len(projected))
        self.assertGreaterEqual(int(counters["slots_placed"]), 1)
        with self.assertRaises(SocBuildError):
            self.arm.project_records(self.legal + [self.second_offer()])
        self.assertIs(repaired, self.arm.last_repaired_test)
        self.assertEqual(counters, dict(self.arm.repair_counts))
        self.assertEqual(placements, tuple(repaired.placements))

    def test_a_seed_that_rewrites_a_frozen_byte_is_refused_by_name(self) -> None:
        """The entry image is not a fuzz candidate: a differing seed byte is refused."""
        frozen = self.program.entry_bytes()
        self.assertGreaterEqual(len(frozen), 4)
        tampered = bytes([frozen[0] ^ 0xFF, *frozen[1:4]])
        self.assertNotEqual(frozen[:4], tampered)
        with self.assertRaises(CandidateProgramError) as caught:
            self.program.repairer().repair_test(
                self.legal, seeds={self.program.entry_address: tampered})
        self.assertEqual(
            f"repair-would-rewrite-committed-word:seed:0x{self.program.entry_address:08x}",
            str(caught.exception))

    def test_a_seed_that_overlaps_a_declared_slot_is_refused_by_name(self) -> None:
        """A seed may not land across a declared slot, even with agreeing bytes."""
        with self.assertRaises(CandidateProgramError) as caught:
            self.program.repairer().repair_test(
                self.legal, seeds={self.slot.declared_address: bytes(4)})
        self.assertEqual(
            f"candidate-seed-overlaps-slot:{self.slot.prefix}:"
            f"0x{self.slot.declared_address:08x}", str(caught.exception))


class RefusedInputKeepsTheIssuedRecordTests(unittest.TestCase):
    """D3.4's invariant: a refusal may not touch what the DUT already produced.

    A refusal is only meaningful if it happens *instead of* the run it refuses.
    The positive record is built first, through the same production chain as the
    negatives; then every refusal of this module is attempted; then the saved
    record is compared byte for byte.  The simulator is scripted (the pure suite
    needs no Verilator) but the parsing is the production parser's, and the two
    entry points that could start a run are mocked, so "no run happened" is
    asserted on the function that would have started it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.layout, cls.arm = peer_arm(candidate_program=True)
        # The declared program owns one raw ABI: its own image.  A raw word
        # carrying a peer field above that width is refused outright
        # (``candidate-raw-word-outside-layout``), so the peer raw route is driven
        # through the arm *without* a declared program -- the same arm the raw-gap
        # class above uses.  Both arms are over one plan and one raw width, which
        # the assertion below keeps true.
        cls.peer_layout, cls.peer_arm = arms_for_plan(cls.plan)
        if cls.peer_layout.raw_width != cls.layout.raw_width:
            raise AssertionError("the two arms must share one raw ABI")
        cls.program = cls.arm.candidate_program
        if cls.program is None:
            raise AssertionError("the arm was built without a declared program")
        cls.legal = declared_words(cls.program, cls.layout)
        cls.build = unbuilt_runtime(cls.layout, cls.arm.peer_slots)
        cls.slot = cls.program.slots.instruction[0]
        cls.second_offer = slot_word(cls.program, cls.layout, cls.slot, word=0x00000033)
        pulse_slots = [record for record in cls.arm.peer_slots
                       if str(record["kind"]) == "pulse_byte"]
        if not pulse_slots:
            raise AssertionError("the peer plan declares no pulse slot to check")
        cls.pulse = max(pulse_slots, key=lambda item: int(item["minimum_gap_cycles"]))
        cls.gap = int(cls.pulse["minimum_gap_cycles"])
        cls.pulse_word = pulse_word(cls.peer_layout, cls.plan,
                                    str(cls.pulse["instance_id"]),
                                    str(cls.pulse["slot"]), PULSE_PAYLOADS[0])

    def positive(self):
        """Drive one legal test and return it with a byte-level baseline copy.

        The harness output is scripted from the sample that is really passed, so
        the record's requests, responses, observations and applied trace are
        produced by ``run_sample`` from a legal sample rather than written here.
        """
        events = (PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10,
                                    payload=PULSE_PAYLOADS[0]),
                  PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10 + self.gap,
                                    payload=PULSE_PAYLOADS[1]))
        projected = tuple(int(value) for value in self.arm.project_records(self.legal))
        sample = RuntimeSample(request_id=0xD30001, raw=projected, peer_events=events)
        patcher = unittest.mock.patch.object(
            soc_runtime.subprocess, "run",
            return_value=scripted_simulator(sample, self.build))
        simulator = patcher.start()
        self.addCleanup(patcher.stop)
        saved = run_sample(self.build, sample)
        # The positive record must be a real one, or "unchanged" would be a
        # statement about nothing.
        self.assertEqual("OK", saved.status, saved.reason)
        for name in ("requests", "responses", "observations", "applied", "peer_applied"):
            self.assertTrue(getattr(saved, name), f"the positive record has no {name}")
        checks = {str(item["check_id"]): str(item["status"])
                  for item in saved.peer_oracle["checks"]}
        self.assertEqual("pass", checks["peer-event-transport"])
        baseline = canonical_bytes(saved.document())
        before = copy.deepcopy({"requests": saved.requests, "responses": saved.responses,
                                "observations": saved.observations, "applied": saved.applied})
        return saved, simulator, sample, baseline, before

    def assert_refused_before_driving(self, call, reason: str) -> None:
        """Run one negative with the simulator entry point mocked out.

        ``run_sample`` is the function that would start the simulator; the refusal
        must be raised before it is reached, and the mock turns "it was reached"
        into a visible failure instead of a run.
        """
        with unittest.mock.patch.object(soc_runtime, "run_sample") as driver:
            with self.assertRaises(SocBuildError) as caught:
                call()
            driver.assert_not_called()
        self.assertEqual(reason, str(caught.exception))

    def test_a_refused_negative_leaves_the_saved_record_byte_for_byte_unchanged(self) -> None:
        saved, simulator, sample, baseline, before = self.positive()
        self.assertEqual(1, simulator.call_count)

        # (1) A raw pulse pair one cycle closer than the declared gap: the
        #     projector refuses it before the driver is reached.
        raw_closer = [self.pulse_word] + [0] * (self.gap - 2) + [self.pulse_word]
        self.assert_refused_before_driving(
            lambda: project_then_run(self.peer_arm, self.build, raw_closer, request_id=2),
            gap_reason_raw(self.pulse, self.gap - 1, 0))

        # (2) A second offer of an already committed slot: the declared program
        #     refuses it before the driver is reached.
        self.assert_refused_before_driving(
            lambda: project_then_run(self.arm, self.build,
                                     self.legal + [self.second_offer], request_id=3),
            f"repair-would-rewrite-committed-word:{self.slot.prefix}:"
            f"0x{self.slot.declared_address:08x}")

        # (3) The event plan one cycle closer: refused inside run_sample, before
        #     it builds a command.
        refused_sample = RuntimeSample(request_id=4, raw=sample.raw, peer_events=(
            PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10,
                              payload=PULSE_PAYLOADS[0]),
            PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10 + self.gap - 1,
                              payload=PULSE_PAYLOADS[1])))
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample(self.build, refused_sample)
        self.assertEqual(gap_reason_event(self.pulse, 10 + self.gap - 1, 10),
                         str(caught.exception))

        # The simulator was entered exactly once -- for the legal sample -- and
        # with the legal sample's own input.
        self.assertEqual(1, simulator.call_count)
        self.assertEqual(sample.payload(), simulator.call_args.kwargs["input"])
        # The saved record is the same record, byte for byte.
        self.assertEqual(baseline, canonical_bytes(saved.document()))
        self.assertEqual(before["requests"], saved.requests)
        self.assertEqual(before["responses"], saved.responses)
        self.assertEqual(before["observations"], saved.observations)
        self.assertEqual(before["applied"], saved.applied)

    def test_every_refusal_happens_before_the_run_it_refuses(self) -> None:
        """The same three negatives, each asserted on the entry point it must miss."""
        raw_closer = [self.pulse_word] + [0] * (self.gap - 2) + [self.pulse_word]
        self.assert_refused_before_driving(
            lambda: project_then_run(self.peer_arm, self.build, raw_closer, request_id=5),
            gap_reason_raw(self.pulse, self.gap - 1, 0))
        self.assert_refused_before_driving(
            lambda: project_then_run(self.arm, self.build,
                                     self.legal + [self.second_offer], request_id=6),
            f"repair-would-rewrite-committed-word:{self.slot.prefix}:"
            f"0x{self.slot.declared_address:08x}")
        refused_sample = RuntimeSample(request_id=7, raw=(0,), peer_events=(
            PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10,
                              payload=PULSE_PAYLOADS[0]),
            PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10 + self.gap - 1,
                              payload=PULSE_PAYLOADS[1])))
        with unittest.mock.patch.object(
                soc_runtime.subprocess, "run",
                side_effect=AssertionError("the refused plan reached the simulator")) as simulator:
            with self.assertRaises(SocRuntimeError):
                run_sample(self.build, refused_sample)
            simulator.assert_not_called()


# ---------------------------------------------------------------------------
# the same sequence on a real compiled peer SoC
# ---------------------------------------------------------------------------


def _synthetic_word(plan, **fields: int) -> int:
    """One raw cycle built from the plan's own synthetic-master raw ports."""
    value = 0
    for name, raw in fields.items():
        matches = [item for item in plan.synthetic["raw_ports"] if item["port"] == name]
        if len(matches) != 1:
            raise AssertionError(f"the plan declares no raw port {name}")
        slot = matches[0]
        mask = (1 << int(slot["width"])) - 1
        value |= (int(raw) & mask) << int(slot["raw_lo"])
    return value


def _window_base(plan, target_id: str) -> int:
    return next(int(window["base"]) for window in plan.plan["address_map"]["windows"]
                if str(window["target_id"]) == target_id)


def _mmio_offer(plan, target_id: str, offset: int, write: int, wdata: int = 0) -> int:
    """One raw cycle offering a synthetic-master access to one declared window."""
    bases = [int(value) for value in plan.synthetic["parameters"]["WINDOW_BASE"]]
    selector = bases.index(_window_base(plan, target_id))
    return _synthetic_word(
        plan, stim_offer=1, stim_target_selector=selector,
        stim_offset=_window_base(plan, target_id) + offset, stim_write=write,
        stim_wdata=wdata, stim_be=0xF)


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real refusal run")
class RealRefusalImmutabilityTests(unittest.TestCase):
    """D3.4 on real RTL: the refusals did not disturb a record a real DUT produced.

    :class:`RefusedInputKeepsTheIssuedRecordTests` proves the sequence against the
    production parser with the simulator scripted; this class compiles the real
    peer SoC, runs one legal sample on it, and then attempts the raw-gap and
    event-gap negatives against the same arm and the same build.  The refused
    negatives are given a driver that fails if it is called, so a refusal that
    stopped working shows up as a failed test rather than as a silent run.

    ``MYFUZZ_SOC_REAL=1`` gates the build; when the flag is set nothing here
    skips, and a missing Verilator fails naming it.
    """

    build_timeout_s = int(os.environ.get("MYFUZZ_SOC_PEER_BUILD_TIMEOUT_S", "1800"))
    cycles = 200

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None:
            raise AssertionError("Verilator is required for the real refusal run")
        cls.plan, cls.layout, cls.arm = peer_arm(drive_profile="bfm_isolated")
        pulse_slots = [record for record in cls.arm.peer_slots
                       if str(record["kind"]) == "pulse_byte"]
        if not pulse_slots:
            raise AssertionError("the peer plan declares no pulse slot to check")
        cls.pulse = max(pulse_slots, key=lambda item: int(item["minimum_gap_cycles"]))
        cls.gap = int(cls.pulse["minimum_gap_cycles"])
        cls.uart = next(record for record in cls.arm.peer_slots
                        if str(record["slot"]) == "uart.tx_byte")
        cls.uart_word = pulse_word(cls.layout, cls.plan, "uart0", "uart.tx_byte",
                                   PULSE_PAYLOADS[0])
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-refusal-", dir=ROOT)
        try:
            cls.build = build_profile_runtime(
                cls.plan, output_dir=Path(cls._temporary.name) / "soc", base_dir=ROOT,
                top_text=render_composition(cls.plan)["myfuzz_soc_top.sv"],
                sources=[item["path"] for item in source_list(cls.plan)
                         if item["role"] != "include_root"],
                timeout_seconds=cls.build_timeout_s)
        except Exception:
            cls._temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def legal_sample(self) -> RuntimeSample:
        """One legal record: MMIO traffic plus a pulse pair exactly at the gap."""
        raw = [0] * self.cycles
        raw[4] = _mmio_offer(self.plan, "uart0_win", UART_CTRL, write=1, wdata=0x7)
        raw[20] = _mmio_offer(self.plan, "uart0_win", UART_RXDATA, write=0)
        events = (PeerStimulusEvent(slot=int(self.uart["index"]), cycle=10,
                                    payload=PULSE_PAYLOADS[0]),
                  PeerStimulusEvent(slot=int(self.uart["index"]), cycle=10 + self.gap,
                                    payload=PULSE_PAYLOADS[1]))
        sample = RuntimeSample(request_id=0xD30002, raw=tuple(
            int(value) for value in self.arm.project_records(raw)), peer_events=events)
        return sample

    def test_the_real_run_is_untouched_by_the_refused_negatives(self) -> None:
        sample = self.legal_sample()
        saved = run_sample(self.build, sample)
        self.assertEqual("OK", saved.status, saved.reason or saved.stdout[-2000:])
        for name in ("requests", "responses", "observations", "peer_applied"):
            self.assertTrue(getattr(saved, name), f"the positive record has no {name}")
        baseline = canonical_bytes(saved.document())
        before = copy.deepcopy({"requests": saved.requests, "responses": saved.responses,
                                "observations": saved.observations, "applied": saved.applied})

        # (1) The raw pulse pair one cycle closer than the declared gap: the
        #     projector refuses it before the simulator entry point is reached.
        raw_closer = [self.uart_word] + [0] * (self.gap - 2) + [self.uart_word]
        with unittest.mock.patch.object(
                soc_runtime, "run_sample",
                side_effect=AssertionError("a refused record reached the simulator")) as driver:
            with self.assertRaises(SocBuildError) as raw_error:
                project_then_run(self.arm, self.build, raw_closer, request_id=2)
            driver.assert_not_called()
        self.assertEqual(gap_reason_raw(self.pulse, self.gap - 1, 0),
                         str(raw_error.exception))

        # (2) The event plan one cycle closer: refused before a command is built.
        refused_sample = RuntimeSample(request_id=4, raw=sample.raw, peer_events=(
            PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10,
                              payload=PULSE_PAYLOADS[0]),
            PeerStimulusEvent(slot=int(self.pulse["index"]), cycle=10 + self.gap - 1,
                              payload=PULSE_PAYLOADS[1])))
        with unittest.mock.patch.object(
                soc_runtime.subprocess, "run",
                side_effect=AssertionError("the refused plan reached the simulator")):
            with self.assertRaises(SocRuntimeError) as event_error:
                run_sample(self.build, refused_sample)
        self.assertEqual(gap_reason_event(self.pulse, 10 + self.gap - 1, 10),
                         str(event_error.exception))

        # The real DUT's record is the same record, byte for byte.
        self.assertEqual(baseline, canonical_bytes(saved.document()))
        self.assertEqual(before["requests"], saved.requests)
        self.assertEqual(before["responses"], saved.responses)
        self.assertEqual(before["observations"], saved.observations)
        self.assertEqual(before["applied"], saved.applied)


if __name__ == "__main__":                          # pragma: no cover
    unittest.main()
