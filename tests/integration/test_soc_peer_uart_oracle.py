"""Task 1: the raw-driven UART expectation source and the UART frame criteria.

``soc_peer_oracle.v1`` used to derive its UART transmit expectation from the
declared peer *event plan* alone.  A raw-driven frame has no plan entry, so the
expectation was ``0`` completed frames while the peer's own ``tx_sent_count_o``
reported the frame the register readback proves arrived -- a false ``mismatch``
that blamed the RTL for the oracle's own missing evidence source.

This module pins the corrected contract:

* :func:`uart_raw_expectation` decodes the raw per-cycle record with
  ``soc_peer_replay.decode_peer_raw_events`` and states that provenance as the
  check's ``basis`` (``soc_peer_oracle.v1:raw-decoded``).  The expectation is
  never taken from ``peer_applied`` or from a peer counter;
* an event-plan-driven sample keeps the original path, and a sample with neither
  source is ``not_assessed`` rather than a mismatch;
* the UART frame criteria reconstruct a complete frame from per-cycle samples of
  the component-to-peer line and decide ``uart-rx-wire`` (data), the framing
  negative (start/stop bit) and the baud negative (a line that changes inside a
  declared bit cell).  A missing line-level trace is ``not_assessed`` with a
  named reason, never a ``pass``;
* an unsupported wire format (non-8-bit data, more than one stop bit, parity) is
  refused at admission, so no default value can silently approximate it.

The real-RTL half runs only under ``MYFUZZ_SOC_REAL=1``.  It drives one raw peer
offer into a composed SoC and asserts the oracle now *passes* the sent-count
check on the raw route with the raw-decoded basis, while the frame criteria stay
``not_assessed`` because this runtime records no per-cycle UART line samples.
"""
from __future__ import annotations

import functools
import os
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
from myfuzz.composition.soc_peer_oracle import (
    PeerOracleError,
    audit_peer_run,
    uart_raw_expectation,
    uart_tx_expectation,
    uart_wire_expectation,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RuntimeSample,
    _peer_slots,
    build_profile_runtime,
    render_profile_testbench,
    run_sample,
)
from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_input_arms_projection import arms_for
from tests.integration.test_soc_peer_models import build_peer_plan


OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
RAW_BASIS = "soc_peer_oracle.v1:raw-decoded"
UART_BYTE = 0x5A
UART_WINDOW = 0x1000
UART_TXDATA = 0x04
UART_BASIS = "independent UART TXDATA register norm (fixture)"
CYCLES = 200
OFFER_CYCLE = 20


@functools.lru_cache(maxsize=None)
def peer_fixture():
    """The real bfm_isolated fixture: plan, image, combined ABI and runtime slots."""
    plan = build_peer_plan(drive_profile="bfm_isolated")
    image = build_image_plan(plan)
    layout = combined_input_layout(plan, image)
    return plan, image, layout, _peer_slots(plan)


def uart_slot(slots) -> dict:
    return next(item for item in slots
                if item["instance_id"] == "uart0" and item["slot"] == "uart.tx_byte")


def layout_fields(layout) -> dict:
    return {str(field.port): field for field in layout.fields}


def uart_offer_raw(slot, layout, *, byte: int, valid: int, cycles: int = CYCLES,
                   cycle: int = OFFER_CYCLE) -> list[int]:
    """One raw word per cycle, with the UART slot's declared fields set."""
    fields = layout_fields(layout)
    raw = [0] * cycles
    for signal in slot["signals"]:
        field = fields[str(signal["top_port"])]
        value = valid if str(signal["source"]) == "pulse" else byte
        raw[cycle] |= int(value) << int(field.raw_lo)
    return raw


def with_signal_offsets(slots, layout) -> tuple[dict[str, object], ...]:
    """The runtime slot records with the layout's offsets written onto them."""
    fields = layout_fields(layout)
    return tuple(
        dict(item, signals=tuple(
            dict(signal, raw_lo=int(fields[str(signal["top_port"])].raw_lo),
                 raw_hi=int(fields[str(signal["top_port"])].raw_hi))
            for signal in item["signals"]))
        for item in slots)


def frame_criteria(verdict: dict) -> dict[str, dict]:
    return {str(item["check_id"]): dict(item) for item in verdict["criteria"]}


def audit_checks(document: dict) -> dict[str, dict]:
    return {str(item["check_id"]): dict(item) for item in document["checks"]}


def audit_unassessed(document: dict) -> dict[str, str]:
    return {str(item["check_id"]): str(item["reason"])
            for item in document["unassessed"]}


def line_trace(byte: int, *, data_width: int = 8, period: int = 8,
               stop_bits: int = 1, idle: int = 1, lead: int = 4, tail: int = 4,
               flip: tuple[int, ...] = (), stop_level: int | None = None,
               level=lambda value: value) -> tuple[dict[str, object], ...]:
    """One line-sampled frame at the declared period, optionally corrupted.

    ``period`` is the *observed* bit period; passing a value other than the
    declared ``baud_div`` is exactly the wrong-baud negative.  ``flip`` inverts
    selected data bit indices (LSB first) and ``stop_level`` overrides the level
    the stop cell holds.
    """
    levels = [idle] * lead
    levels += [1 - idle] * period
    for index in range(data_width):
        bit = (byte >> index) & 1
        if index in flip:
            bit ^= 1
        levels += [bit] * period
    levels += [(idle if stop_level is None else stop_level)] * (period * stop_bits)
    levels += [idle] * tail
    return tuple({"cycle": index, "line": level(value)}
                 for index, value in enumerate(levels))


class RawDrivenUartExpectationTests(unittest.TestCase):
    """Step 1.1: the raw record, not the empty event plan, is the expectation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.image, cls.layout, cls.slots = peer_fixture()
        cls.uart = uart_slot(cls.slots)
        cls.parameters = dict(cls.uart["parameters"])

    def record(self, *, byte: int = UART_BYTE, valid: int = 1,
               cycles: int = CYCLES, cycle: int = OFFER_CYCLE) -> tuple[int, ...]:
        return tuple(uart_offer_raw(self.uart, self.layout, byte=byte, valid=valid,
                                    cycles=cycles, cycle=cycle))

    def expectation(self, record) -> dict[str, object]:
        return uart_raw_expectation(
            record, self.layout, self.slots, cycles=CYCLES,
            data_width=int(self.parameters["DATA_WIDTH"]),
            baud_div=int(self.parameters["BAUD_DIV"]),
            stop_bits=int(self.parameters["STOP_BITS"]))

    def audit(self, sample, result, *, slots=None, layout=None,
              **extra) -> dict[str, object]:
        """Audit one run; ``layout=False`` means the build carries no layout."""
        build = SimpleNamespace(
            peer_slots=tuple(self.slots if slots is None else slots),
            peer_observations=(), raw_width=int(self.layout.raw_width), **extra)
        if layout is not False:
            build.layout = self.layout if layout is None else layout
        return audit_peer_run(build, sample, result)

    def run_inputs(self, *, valid: int = 1):
        sample = SimpleNamespace(peer_events=(), raw=self.record(valid=valid))
        result = SimpleNamespace(
            cycles=CYCLES, peer_applied=(), observations={},
            counters={"peer.uart0.tx_drop_count_o": 0,
                      "peer.uart0.tx_sent_count_o": valid})
        return sample, result

    def test_the_raw_record_decodes_into_the_completed_frame_expectation(self) -> None:
        """The offer the test wrote is the offer the decoder finds."""
        expectation = self.expectation(self.record())
        self.assertEqual(1, expectation["completed_count"], expectation)
        self.assertEqual(0, expectation["drop_count"], expectation)
        self.assertEqual(1, expectation["accepted_count"], expectation)
        self.assertEqual(RAW_BASIS, expectation["basis"])
        # The plan-level model is the same one the event route uses; the raw
        # decode only supplies its input, it does not restate the timing.
        declared = uart_tx_expectation(
            ({"cycle": OFFER_CYCLE, "payload": UART_BYTE},), cycles=CYCLES,
            data_width=int(self.parameters["DATA_WIDTH"]),
            baud_div=int(self.parameters["BAUD_DIV"]),
            stop_bits=int(self.parameters["STOP_BITS"]))
        for key in ("frame_cycles", "minimum_gap_cycles", "completed_count",
                    "required_completion_cycles"):
            self.assertEqual(declared[key], expectation[key], key)

    def test_a_raw_driven_frame_is_not_reported_as_a_sent_count_mismatch(self) -> None:
        """The regression this task closes: pass, with the raw basis recorded."""
        sample, result = self.run_inputs()
        document = self.audit(sample, result)
        checks = audit_checks(document)
        sent = checks["uart-tx-sent-count"]
        self.assertEqual("pass", sent["status"], sent)
        self.assertEqual(1, sent["expected"])
        self.assertEqual(1, sent["observed"])
        self.assertEqual(RAW_BASIS, sent["basis"])
        self.assertIn("raw", str(sent["note"]).lower())
        drop = checks["uart-tx-drop-count"]
        self.assertEqual("pass", drop["status"], drop)
        self.assertEqual(RAW_BASIS, drop["basis"])

    def test_the_event_plan_route_keeps_its_own_expectation_source(self) -> None:
        index = int(self.uart["index"])
        sample = SimpleNamespace(peer_events=({"slot": index, "cycle": OFFER_CYCLE,
                                               "payload": UART_BYTE},),
                                 raw=(0,) * CYCLES)
        result = SimpleNamespace(
            cycles=CYCLES, observations={},
            peer_applied=({"cycle": OFFER_CYCLE, "instance": "uart0",
                           "slot": "uart.tx_byte", "value": UART_BYTE},),
            counters={"peer.uart0.tx_drop_count_o": 0,
                      "peer.uart0.tx_sent_count_o": 1})
        document = self.audit(sample, result)
        sent = audit_checks(document)["uart-tx-sent-count"]
        self.assertEqual("pass", sent["status"], sent)
        self.assertEqual(1, sent["expected"])
        self.assertNotEqual(RAW_BASIS, sent["basis"],
                            "the declared plan is the expectation source here")
        self.assertIn("plan", str(sent["note"]).lower())
        self.assertEqual("pass", document["status"], document)

    def test_no_event_plan_and_no_raw_record_is_not_assessed(self) -> None:
        """No evidence source at all must not be reported as a mismatch."""
        sample = SimpleNamespace(peer_events=(), raw=())
        result = SimpleNamespace(cycles=CYCLES, peer_applied=(), observations={},
                                 counters={"peer.uart0.tx_sent_count_o": 1})
        document = self.audit(sample, result)
        self.assertNotIn("uart-tx-sent-count", audit_checks(document))
        reasons = audit_unassessed(document)
        self.assertIn("uart-tx-sent-count", reasons)
        self.assertTrue(reasons["uart-tx-sent-count"].strip())
        self.assertEqual("pass", document["status"], document)

    def test_an_undecodable_raw_record_is_not_assessed_not_a_mismatch(self) -> None:
        """A build that declares no offsets cannot turn the raw route into blame."""
        sample, result = self.run_inputs()
        document = self.audit(sample, result, layout=False)
        self.assertNotIn("uart-tx-sent-count", audit_checks(document))
        reasons = audit_unassessed(document)
        self.assertIn("uart-tx-sent-count", reasons)
        self.assertIn("offsets", reasons["uart-tx-sent-count"])

    def test_the_slot_signals_own_offsets_are_an_accepted_source(self) -> None:
        """Projection records carry ``raw_lo``/``raw_hi`` themselves."""
        sample, result = self.run_inputs()
        document = self.audit(sample, result, layout=False,
                              slots=with_signal_offsets(self.slots, self.layout))
        sent = audit_checks(document)["uart-tx-sent-count"]
        self.assertEqual("pass", sent["status"], sent)
        self.assertEqual(RAW_BASIS, sent["basis"])

    def test_the_rendered_testbench_recovers_the_offsets_the_run_used(self) -> None:
        """A production build carries no layout, but its testbench records the ABI.

        ``build_profile_runtime`` keeps the peer slot records and the compiled
        testbench, and the testbench assigns each peer port from
        ``raw_bits[hi:lo]``.  Recovering the offsets from that artifact keeps the
        raw route decidable without changing the runtime, and the offsets must
        equal the ones the frozen ABI test declares.
        """
        with TemporaryDirectory() as directory:
            testbench = Path(directory) / "profile_tb.sv"
            testbench.write_text(render_profile_testbench(self.plan,
                                                          image_plan=self.image),
                                 encoding="utf-8")
            build = SimpleNamespace(
                peer_slots=tuple(self.slots), peer_observations=(),
                testbench_path=testbench, raw_width=int(self.layout.raw_width))
            sample, result = self.run_inputs()
            document = audit_peer_run(build, sample, result)
        sent = audit_checks(document)["uart-tx-sent-count"]
        self.assertEqual("pass", sent["status"], sent)
        self.assertEqual(1, sent["expected"])
        self.assertEqual(RAW_BASIS, sent["basis"])

    def test_a_raw_record_without_an_offer_expects_no_completed_frame(self) -> None:
        """The raw record is the source even when it carries no offer."""
        expectation = self.expectation(self.record(valid=0))
        self.assertEqual(0, expectation["completed_count"], expectation)
        self.assertEqual(0, expectation["accepted_count"], expectation)


class UartFrameCriteriaTests(unittest.TestCase):
    """Step 1.3: one complete frame, and the three negatives it must catch."""

    def verdict(self, trace, *, expected=(UART_BYTE,), data_width: int = 8,
                baud_div: int = 8, stop_bits: int = 1) -> dict:
        return uart_wire_expectation(
            trace, expected_bytes=expected, data_width=data_width,
            baud_div=baud_div, stop_bits=stop_bits)

    def test_a_complete_line_sampled_frame_passes_every_criterion(self) -> None:
        result = self.verdict(line_trace(UART_BYTE))
        criteria = frame_criteria(result)
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire"):
            with self.subTest(check=check_id):
                self.assertEqual("pass", criteria[check_id]["status"], criteria[check_id])
        self.assertEqual([UART_BYTE], result["observed_bytes"])
        self.assertEqual("pass", result["status"])

    def test_two_frames_are_decoded_in_order(self) -> None:
        trace = line_trace(0x31, lead=4, tail=8) + tuple(
            dict(item, cycle=int(item["cycle"]) + 4 + 8 * 10 + 8)
            for item in line_trace(0xA6, lead=0, tail=4))
        result = self.verdict(trace, expected=(0x31, 0xA6))
        self.assertEqual([0x31, 0xA6], result["observed_bytes"])
        self.assertEqual("pass", result["status"], result)

    def test_a_flipped_data_bit_is_a_data_mismatch(self) -> None:
        result = self.verdict(line_trace(UART_BYTE, flip=(3,)))
        criteria = frame_criteria(result)
        self.assertEqual("mismatch", criteria["uart-rx-wire"]["status"])
        self.assertEqual("pass", criteria["uart-framing-wire"]["status"])
        self.assertEqual("pass", criteria["uart-baud-wire"]["status"])
        self.assertIn("uart-rx-wire", str(criteria["uart-rx-wire"]["reason"]))

    def test_a_wrong_stop_level_is_a_framing_mismatch(self) -> None:
        result = self.verdict(line_trace(UART_BYTE, stop_level=0))
        criteria = frame_criteria(result)
        self.assertEqual("mismatch", criteria["uart-framing-wire"]["status"],
                         criteria["uart-framing-wire"])
        self.assertIn("stop", str(criteria["uart-framing-wire"]["reason"]))
        self.assertEqual("pass", criteria["uart-baud-wire"]["status"])

    def test_a_half_period_baud_offset_is_a_baud_mismatch(self) -> None:
        """The observed bit period is half the declared one, so cells break.

        The trace is padded past the declared frame span: the point is that the
        line changes *inside* a declared bit cell, not that the trace ran out.
        """
        result = self.verdict(line_trace(UART_BYTE, period=4, tail=60), baud_div=8)
        criteria = frame_criteria(result)
        self.assertEqual("mismatch", criteria["uart-baud-wire"]["status"],
                         criteria["uart-baud-wire"])
        self.assertIn("inside-bit-cell", str(criteria["uart-baud-wire"]["reason"]))
        self.assertEqual("mismatch", criteria["uart-rx-wire"]["status"],
                         criteria["uart-rx-wire"])

    def test_a_missing_or_unknown_trace_is_never_a_pass(self) -> None:
        empty = frame_criteria(self.verdict(()))
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire"):
            with self.subTest(check=check_id):
                self.assertEqual("not_assessed", empty[check_id]["status"])
                self.assertTrue(str(empty[check_id]["reason"]).strip())
        unknown = frame_criteria(self.verdict(line_trace(UART_BYTE, level=lambda _v: "x")))
        self.assertEqual("not_assessed", unknown["uart-rx-wire"]["status"])
        self.assertIn("unknown", str(unknown["uart-rx-wire"]["reason"]))
        truncated = frame_criteria(self.verdict(line_trace(UART_BYTE)[:12]))
        self.assertEqual("not_assessed", truncated["uart-rx-wire"]["status"])
        self.assertIn("incomplete", str(truncated["uart-rx-wire"]["reason"]))

    def test_a_missing_independent_byte_expectation_is_not_assessed(self) -> None:
        """Without a declared component-side norm the data is undecidable."""
        result = self.verdict(line_trace(UART_BYTE), expected=None)
        criteria = frame_criteria(result)
        self.assertEqual("not_assessed", criteria["uart-rx-wire"]["status"])
        self.assertEqual("pass", criteria["uart-framing-wire"]["status"])
        self.assertEqual("pass", criteria["uart-baud-wire"]["status"])

    def test_unsupported_wire_formats_are_refused_not_approximated(self) -> None:
        for label, arguments in {
                "data-width-16": {"data_width": 16},
                "two-stop-bits": {"stop_bits": 2},
                "parity-even": {"parity": "even"}}.items():
            with self.subTest(mode=label):
                with self.assertRaisesRegex(PeerOracleError,
                                            "uart-wire-mode-unsupported"):
                    uart_wire_expectation(line_trace(UART_BYTE), expected_bytes=(UART_BYTE,),
                                          data_width=arguments.get("data_width", 8),
                                          baud_div=8,
                                          stop_bits=arguments.get("stop_bits", 1),
                                          parity=arguments.get("parity", "none"))


class UartWireAuditTests(unittest.TestCase):
    """The frame criteria in the audit, driven by a real line-level trace."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan, cls.image, cls.layout, cls.slots = peer_fixture()
        cls.uart = uart_slot(cls.slots)

    def setUp(self) -> None:
        self.trace = line_trace(UART_BYTE)
        self.write = {"cycle": 0, "addr": UART_WINDOW + UART_TXDATA, "write": 1,
                      "wdata": UART_BYTE, "be": 0xF, "source": 0}

    def audit(self, *, trace=None, status=None, requests=None, parameters=None):
        slot = dict(self.uart)
        if parameters is not None:
            slot["parameters"] = dict(slot["parameters"], **parameters)
        rows = tuple(dict(item, instance_id="uart0")
                     for item in (self.trace if trace is None else trace))
        if status is None:
            status = ({"instance_id": "uart0", "count": len(rows),
                       "truncated": False},)
        build = SimpleNamespace(
            peer_slots=(slot,), peer_observations=(), cpu_data_sources=(0,),
            layout=self.layout,
            uart_wire_contracts={"uart0": {"txdata_address": UART_WINDOW + UART_TXDATA,
                                           "basis": UART_BASIS}})
        sample = SimpleNamespace(peer_events=(), raw=(0,) * CYCLES)
        result = SimpleNamespace(
            cycles=CYCLES, peer_applied=(), observations={},
            peer_wire_trace=rows, peer_wire_status=tuple(status),
            requests=(self.write,) if requests is None else tuple(requests),
            requests_truncated=False,
            counters={"peer.uart0.tx_drop_count_o": 0,
                      "peer.uart0.tx_sent_count_o": 0},
            trace=tuple({"cycle": cycle, "raw": 0} for cycle in range(CYCLES)))
        return audit_peer_run(build, sample, result)

    def test_a_complete_trace_decides_the_frame_against_the_cpu_write(self) -> None:
        document = self.audit()
        checks = audit_checks(document)
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire"):
            with self.subTest(check=check_id):
                self.assertIn(check_id, checks, document)
                self.assertEqual("pass", checks[check_id]["status"], checks[check_id])
        self.assertEqual(UART_BASIS, checks["uart-rx-wire"]["basis"])
        self.assertEqual([UART_BYTE], checks["uart-rx-wire"]["observed"])
        self.assertEqual([UART_BYTE], checks["uart-rx-wire"]["expected"])

    def test_a_flipped_line_bit_is_a_wire_mismatch_in_the_audit(self) -> None:
        document = self.audit(trace=line_trace(UART_BYTE, flip=(0,)))
        checks = audit_checks(document)
        self.assertEqual("mismatch", checks["uart-rx-wire"]["status"], checks["uart-rx-wire"])
        self.assertEqual("mismatch", document["status"], document)

    def test_a_missing_line_trace_is_not_assessed_with_a_named_reason(self) -> None:
        document = self.audit(trace=(), status=())
        checks = audit_checks(document)
        reasons = audit_unassessed(document)
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire",
                         "uart-timeout-wire"):
            with self.subTest(check=check_id):
                self.assertNotIn(check_id, checks, "a missing trace must not be decided")
                self.assertIn(check_id, reasons, document)
                self.assertTrue(reasons[check_id].strip())
        self.assertEqual("pass", document["status"], document)

    def test_a_truncated_line_trace_is_not_assessed(self) -> None:
        document = self.audit(status=({"instance_id": "uart0",
                                       "count": len(self.trace),
                                       "truncated": True},))
        reasons = audit_unassessed(document)
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire"):
            with self.subTest(check=check_id):
                self.assertIn(check_id, reasons, document)
                self.assertNotEqual("pass", reasons[check_id])

    def test_an_undeclared_wire_mode_is_not_assessed_not_approximated(self) -> None:
        document = self.audit(parameters={"DATA_WIDTH": 16})
        reasons = audit_unassessed(document)
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire"):
            with self.subTest(check=check_id):
                self.assertIn(check_id, reasons, document)
                self.assertIn("uart-wire-mode-unsupported", reasons[check_id])

    def test_without_an_independent_register_norm_the_data_is_not_assessed(self) -> None:
        document = self.audit(requests=())
        reasons = audit_unassessed(document)
        checks = audit_checks(document)
        self.assertIn("uart-rx-wire", reasons, document)
        self.assertNotIn("uart-rx-wire", checks)
        self.assertEqual("pass", checks["uart-framing-wire"]["status"])
        self.assertEqual("pass", checks["uart-baud-wire"]["status"])


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real raw-driven UART run")
class RealRawDrivenUartOracleTests(unittest.TestCase):
    """The real composed SoC: the raw offer decides, and the oracle says so."""

    build_timeout_s = int(os.environ.get("MYFUZZ_SOC_PEER_BUILD_TIMEOUT_S", "1800"))

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None:
            raise AssertionError(
                "Verilator is required for the real raw-driven UART run "
                "(MYFUZZ_SOC_REAL=1)")
        cls.plan, cls.image, cls.layout, cls.slots = peer_fixture()
        cls.uart = uart_slot(cls.slots)
        _image, _layout, _policy, arms = arms_for(cls.plan, instruction_candidates=1,
                                                  data_candidates=1)
        cls.arm = arms["dependency_repair"]
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-uart-oracle-", dir=ROOT)
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.build = build_profile_runtime(
            cls.plan, output_dir=Path(cls._temporary.name) / "uart",
            base_dir=ROOT,
            top_text=render_composition(cls.plan)["myfuzz_soc_top.sv"],
            sources=[item["path"] for item in source_list(cls.plan)
                     if item["role"] != "include_root"],
            image_plan=cls.image, timeout_seconds=cls.build_timeout_s)

    @classmethod
    def run_offer(cls, *, byte: int, valid: int, request_id: int):
        raw = uart_offer_raw(cls.uart, cls.layout, byte=byte, valid=valid)
        record = tuple(int(item) for item in cls.arm.project_records(raw))
        result = run_sample(cls.build,
                            RuntimeSample(request_id=request_id, raw=record))
        if result.status != "OK":
            raise AssertionError(f"request {request_id}: {result.status} "
                                 f"{result.reason} {result.stdout[-2000:]}")
        return result

    def test_the_raw_offer_passes_the_sent_count_check_with_the_raw_basis(self) -> None:
        result = self.run_offer(byte=UART_BYTE, valid=1, request_id=1)
        self.assertEqual(1, int(result.observations["uart0__tx_sent_count_o"]))
        oracle = result.peer_oracle
        self.assertIsNotNone(oracle, "the run reports no independent peer oracle")
        checks = audit_checks(dict(oracle))
        sent = checks["uart-tx-sent-count"]
        self.assertEqual("pass", sent["status"], sent)
        self.assertEqual(1, sent["expected"])
        self.assertEqual(1, sent["observed"])
        self.assertEqual(RAW_BASIS, sent["basis"], sent)
        self.assertEqual("pass", oracle["status"], oracle)

    def test_without_the_raw_offer_the_expectation_is_zero_and_passes(self) -> None:
        result = self.run_offer(byte=UART_BYTE, valid=0, request_id=2)
        self.assertEqual(0, int(result.observations["uart0__tx_sent_count_o"]))
        sent = audit_checks(dict(result.peer_oracle))["uart-tx-sent-count"]
        self.assertEqual("pass", sent["status"], sent)
        self.assertEqual(0, sent["expected"])
        self.assertEqual(0, sent["observed"])

    def test_the_frame_criteria_report_the_missing_line_trace_as_a_gap(self) -> None:
        """This runtime samples no UART line, so the frame stays undecided."""
        result = self.run_offer(byte=UART_BYTE, valid=1, request_id=3)
        oracle = dict(result.peer_oracle)
        reasons = audit_unassessed(oracle)
        checks = audit_checks(oracle)
        for check_id in ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire",
                         "uart-timeout-wire"):
            with self.subTest(check=check_id):
                self.assertNotIn(check_id, checks,
                                 "a line-level property without a trace must not be decided")
                self.assertIn(check_id, reasons, oracle)
                self.assertTrue(reasons[check_id].strip())
        uart_rows = [item for item in result.peer_wire_trace
                     if str(item.get("instance_id", "")) == "uart0"]
        self.assertEqual([], uart_rows,
                         "this build records no UART line samples at all")


if __name__ == "__main__":
    unittest.main()
