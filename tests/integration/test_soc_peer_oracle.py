"""Independent reference checks for profile peer runs.

The RTL peer remains the implementation under test.  This module is deliberately
small and declarative: it checks the event transport and the few behaviours for
which the current runtime exposes enough observations, while reporting wire
properties that are not observable as ``not_assessed``.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from myfuzz.composition.soc_peer_oracle import (
    PEER_ORACLE_SCHEMA,
    PeerOracleError,
    audit_peer_run,
    gpio_resolution,
    uart_tx_expectation,
)


class PeerReferenceModelTests(unittest.TestCase):
    def test_uart_reference_counts_busy_offers_and_completed_frames(self) -> None:
        result = uart_tx_expectation(
            ({"cycle": 2, "payload": 0x11},
             {"cycle": 20, "payload": 0x22},
             {"cycle": 30, "payload": 0x33}),
            cycles=55, data_width=8, baud_div=2, stop_bits=1)
        self.assertEqual(20, result["frame_cycles"])
        self.assertEqual(2, result["accepted_count"])
        self.assertEqual(1, result["drop_count"])
        self.assertEqual(2, result["completed_count"])
        self.assertEqual([2, 30], result["accepted_cycles"])

    def test_uart_reference_rejects_invalid_timing(self) -> None:
        with self.assertRaisesRegex(PeerOracleError, "uart-data-width-invalid"):
            uart_tx_expectation((), cycles=1, data_width=0, baud_div=1, stop_bits=1)

    def test_gpio_reference_resolves_drives_and_counts_contention_edges(self) -> None:
        same = gpio_resolution(
            peer_drive_value=0b01, peer_drive_valid=0b11,
            component_out=0b01, component_dir=0b11, pins=2,
            default_input_level=1, contention_is_error=1, previous_contention=0,
            previous_error=0)
        self.assertEqual(0b01, same["resolved"])
        self.assertEqual(0, same["contention"])
        self.assertEqual(0, same["contention_count"])

        opposite = gpio_resolution(
            peer_drive_value=0b01, peer_drive_valid=0b11,
            component_out=0b10, component_dir=0b11, pins=2,
            default_input_level=1, contention_is_error=1, previous_contention=0,
            previous_error=0)
        self.assertEqual(0, opposite["resolved"])
        self.assertEqual(0b11, opposite["contention"])
        self.assertEqual(2, opposite["contention_count"])
        self.assertEqual(1, opposite["contention_error"])

        held = gpio_resolution(
            peer_drive_value=0b01, peer_drive_valid=0b11,
            component_out=0b10, component_dir=0b11, pins=2,
            default_input_level=1, contention_is_error=1, previous_contention=0b11,
            previous_error=1)
        self.assertEqual(0, held["contention_count"])
        self.assertEqual(1, held["contention_error"])


class PeerOracleAuditTests(unittest.TestCase):
    def _build(self):
        return SimpleNamespace(
            peer_slots=(
                {"index": 0, "instance_id": "uart0", "peer_id": "uart",
                 "slot": "uart.tx_byte", "kind": "pulse_byte", "width": 8,
                 "minimum_gap_cycles": 21,
                 "parameters": {"DATA_WIDTH": 8, "BAUD_DIV": 2, "STOP_BITS": 1}},
                {"index": 1, "instance_id": "gpio0", "peer_id": "gpio",
                 "slot": "gpio.drive", "kind": "level_drive", "width": 2,
                 "minimum_gap_cycles": 1,
                 "parameters": {"PINS": 1, "DEFAULT_INPUT_LEVEL": 0,
                                "CONTENTION_IS_ERROR": 0}},
                {"index": 2, "instance_id": "spi0", "peer_id": "spi",
                 "slot": "spi.arm_byte", "kind": "pulse_byte", "width": 8,
                 "minimum_gap_cycles": 2,
                 "parameters": {"BITS": 8}},
            ),
            peer_observations=(
                {"name": "uart0__tx_drop_count_o", "instance_id": "uart0",
                 "peer_id": "uart", "peer_port": "tx_drop_count_o", "counter": True},
            ),
        )

    def test_audit_accepts_transport_and_observable_uart_drop_count(self) -> None:
        build = self._build()
        sample = SimpleNamespace(peer_events=(
            SimpleNamespace(slot=0, cycle=2, payload=0x11),
            SimpleNamespace(slot=0, cycle=20, payload=0x22),
            SimpleNamespace(slot=0, cycle=30, payload=0x33),
        ), raw=(0,) * 55)
        result = SimpleNamespace(
            cycles=55,
            peer_applied=(
                {"cycle": 2, "instance": "uart0", "slot": "uart.tx_byte", "value": 0x11},
                {"cycle": 20, "instance": "uart0", "slot": "uart.tx_byte", "value": 0x22},
                {"cycle": 30, "instance": "uart0", "slot": "uart.tx_byte", "value": 0x33},
            ),
            counters={"peer.uart0.tx_drop_count_o": 1},
            observations={},
        )
        document = audit_peer_run(build, sample, result)
        self.assertEqual(PEER_ORACLE_SCHEMA, document["schema_version"])
        self.assertEqual("pass", document["status"])
        self.assertIn("peer-event-transport", [item["check_id"] for item in document["checks"]])
        self.assertIn("uart-tx-drop-count", [item["check_id"] for item in document["checks"]])

    def test_audit_reports_tampered_peer_application_as_mismatch(self) -> None:
        build = self._build()
        sample = SimpleNamespace(peer_events=(SimpleNamespace(slot=0, cycle=2, payload=0x11),),
                                 raw=(0,) * 10)
        result = SimpleNamespace(
            cycles=10,
            peer_applied=({"cycle": 2, "instance": "uart0", "slot": "uart.tx_byte",
                           "value": 0x12},),
            counters={"peer.uart0.tx_drop_count_o": 0}, observations={})
        document = audit_peer_run(build, sample, result)
        self.assertEqual("mismatch", document["status"])
        transport = next(item for item in document["checks"]
                         if item["check_id"] == "peer-event-transport")
        self.assertEqual("mismatch", transport["status"])

    def test_unobservable_wire_behaviour_is_explicitly_not_assessed(self) -> None:
        build = self._build()
        sample = SimpleNamespace(peer_events=(), raw=(0,) * 8)
        result = SimpleNamespace(cycles=8, peer_applied=(), counters={}, observations={})
        document = audit_peer_run(build, sample, result)
        self.assertEqual("pass", document["status"])
        ids = {item["check_id"] for item in document["unassessed"]}
        self.assertIn("uart-rx-wire", ids)
        self.assertIn("spi-transfer-wire", ids)
        self.assertIn("gpio-resolution-wire", ids)

    def test_runtime_result_carries_oracle_into_its_serialized_document(self) -> None:
        from myfuzz.composition.soc_runtime import (
            PeerStimulusEvent,
            RuntimeBuild,
            RuntimeSample,
            run_sample,
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            build = RuntimeBuild(
                output_dir=root, top_path=root / "top.sv",
                testbench_path=root / "tb.sv", executable=root / "sim",
                sources=(), raw_width=1, slots=(), observations=(),
                boot_image=None, boot_image_policy="none", build_hash="build",
                peer_slots=({"index": 0, "instance_id": "uart0", "peer_id": "uart",
                             "slot": "uart.tx_byte", "kind": "pulse_byte", "width": 8,
                             "minimum_gap_cycles": 21,
                             "parameters": {"DATA_WIDTH": 8, "BAUD_DIV": 2,
                                            "STOP_BITS": 1}},),
                peer_observations=({"name": "uart0__tx_drop_count_o",
                                    "instance_id": "uart0", "peer_id": "uart",
                                    "peer_port": "tx_drop_count_o", "counter": True},),
            )
            sample = RuntimeSample(
                request_id=7, raw=(0,) * 30,
                peer_events=(PeerStimulusEvent(slot=0, cycle=2, payload=0x11),))
            completed = SimpleNamespace(
                returncode=0,
                stdout=("MYFUZZ_PEER_APPLIED cycle=2 instance=uart0 "
                        "slot=uart.tx_byte value=11\n"
                        "MYFUZZ_OBS uart0__tx_drop_count_o=0\n"
                        "MYFUZZ_SOC_RUN status=OK cycles=30\n"),
                stderr="")
            with patch("myfuzz.composition.soc_runtime.subprocess.run",
                       return_value=completed):
                result = run_sample(build, sample)
        self.assertIsNotNone(result.peer_oracle)
        self.assertEqual("pass", result.peer_oracle["status"])
        self.assertEqual(result.peer_oracle,
                         result.document()["peer_oracle"])


if __name__ == "__main__":
    unittest.main()
