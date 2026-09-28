"""RUN-04 real RTL combinations absent from the focused session tests."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from tests.integration import test_scenario_ibex_irq_observation as irq_fixture
from tests.integration.test_scenario_opentitan_uart_done_real import (
    _start_bound_gpio_and_uart_tx,
    _three_device_runner,
)


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealRun04MatrixTests(unittest.TestCase):
    def test_three_real_devices_drain_bound_gpio_and_uart_tx_together(self):
        gpio_a, gpio_b, uart, runner = _three_device_runner()
        runner.begin_test("run04-three-device-drain")
        try:
            _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner)
            start = runner.final_state_document()
            self.assertEqual(("gpio_b",), start["pending_dataflow_targets"])
            self.assertEqual(1, start["pending_events"]["uart"])
            before_a = runner.local_ticks["gpio_a"]
            outcome = runner.quiesce(1500)
            self.assertEqual("drained", outcome.status)
            self.assertGreater(outcome.steps, 1000)
            self.assertEqual(before_a, runner.local_ticks["gpio_a"])
            self.assertEqual(0, gpio_b.pending_events)
            self.assertEqual(0, uart.pending_events)
            self.assertEqual((), runner.final_state_document()[
                "pending_dataflow_targets"])
            self.assertTrue(any(event.get("component") == "gpio_b"
                                and event.get("inputs", {}).get("gpio_in", 0) & 1
                                for event in runner.events))
            self.assertTrue(any(event.get("component") == "gpio_b"
                                and event.get("outputs", {}).get("irq") == 1
                                for event in runner.events))
            self.assertTrue(any(event.get("component") == "uart"
                                and event.get("outputs", {}).get("tx_done") == 1
                                for event in runner.events))
            self.assertEqual("drained", [event for event in runner.events
                if event.get("kind") == "quiesce_end"][-1]["status"])
            with self.assertRaisesRegex(RuntimeError, "not running"):
                runner.inject_source("gpio_a", "gpio_in", 0,
                                     direction="IP_TO_IP")
        finally:
            runner.finalize()
        events = runner.events
        runner.finalize()
        self.assertEqual(events, runner.events)
        self.assertIsNone(gpio_a._process)
        self.assertIsNone(gpio_b._process)
        self.assertIsNone(uart._process)

    def test_real_gpio_irq_pulse_expires_during_bounded_cpu_quiesce(self):
        runner, gpio = irq_fixture.IbexIrqObservationTests._real_pulse_case(2)
        try:
            irq_fixture.IbexIrqObservationTests._real_rise(runner, 1)
            self.assertEqual({"cpu": 1}, runner.final_state_document()[
                "pending_irq_pulses"])
            cpu_before = runner.local_ticks["cpu"]
            outcome = runner.quiesce(40)
            self.assertEqual("drained", outcome.status)
            self.assertGreaterEqual(outcome.steps, 3)
            self.assertEqual(cpu_before + 3, runner.local_ticks["cpu"])
            self.assertEqual({"cpu": 1}, [event for event in runner.events
                if event.get("kind") == "quiesce_start"][-1][
                    "pending_irq_pulses"])
            self.assertEqual({}, [event for event in runner.events
                if event.get("kind") == "quiesce_end"][-1][
                    "pending_irq_pulses"])
            self.assertTrue(any(event.get("kind") == "expired_masked"
                                for event in runner.events))
            self.assertEqual([1, 1, 0], [event["inputs"]["irq"]
                for event in runner.events
                if event.get("component") == "cpu" and "inputs" in event])
            self.assertTrue(any(event.get("component") == "gpio"
                                and event.get("outputs", {}).get("irq") == 1
                                for event in runner.events))
            self.assertEqual((), runner.final_state_document()[
                "pending_dataflow_targets"])
        finally:
            runner.finalize()

    def test_uncertain_three_device_quiesce_cleans_up_once(self):
        gpio_a, gpio_b, uart, runner = _three_device_runner()
        runner.begin_test("run04-three-device-uncertain-cleanup")
        try:
            _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner)
            real_readline = gpio_b._line_reader.readline
            captured = []

            def lose_completed_reply(stream):
                captured.append(real_readline(stream))
                return ""

            with patch.object(gpio_b._line_reader, "readline",
                              side_effect=lose_completed_reply):
                with self.assertRaisesRegex(RuntimeError, "lost_reply"):
                    runner.quiesce(2)
            self.assertEqual(1, len(captured))
            self.assertTrue(captured[0].startswith(
                "RESULT " + gpio_b._wire_execution + " "))
            self.assertEqual("uncertain_effect", runner.failure_status)
            self.assertEqual(1, uart.pending_events)
            self.assertTrue(any(event.get("kind") == "quiesce_failure"
                                for event in runner.events))
        finally:
            runner.finalize()
        events = runner.events
        runner.finalize()
        self.assertEqual(events, runner.events)
        self.assertEqual("uncertain_effect", runner.failure_status)
        self.assertIsNone(gpio_a._process)
        self.assertIsNone(gpio_b._process)
        self.assertIsNone(uart._process)


if __name__ == "__main__":
    unittest.main()
