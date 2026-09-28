"""Two separate OpenTitan GPIO processes exchange only observed RTL values."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class LiveGpioScenarioTests(unittest.TestCase):
    def test_reset_cancels_undelivered_real_gpio_binding(self):
        ownership = compile_ownership(
            (InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_gpio_a"),
             InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 1, 31, "source", "external_gpio_b")))
        a, b = OpenTitanGpioSession(), OpenTitanGpioSession()
        runner = ScenarioRunner(
            sessions={"gpio_a": a, "gpio_b": b}, ownership=ownership,
            bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),))
        runner.begin_test("real-bound-reset")
        try:
            a.write_register(0x14, 1)
            runner.step("gpio_a")
            self.assertEqual(("gpio_b",), runner.final_state_document()[
                "pending_dataflow_targets"])
            runner.reset_all("cold_all")
            barrier = next(e for e in runner.events
                           if e.get("kind") == "reset_barrier")
            self.assertEqual(("gpio_b",), barrier["cancelled_dataflow_targets"])
            self.assertEqual((), runner.final_state_document()[
                "pending_dataflow_targets"])
            runner.step("gpio_b")
            self.assertEqual(0, b.read_register(0x10) & 1)
            self.assertEqual(0, a.read_register(0x14) & 1)
        finally:
            runner.finalize()

    def test_quiesce_reports_incomplete_while_real_gpio_pin_is_settling(self):
        ownership = compile_ownership(
            (InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_gpio_a"),
             InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 1, 31, "source", "external_gpio_b")))
        a, b = OpenTitanGpioSession(), OpenTitanGpioSession()
        runner = ScenarioRunner(
            sessions={"gpio_a": a, "gpio_b": b}, ownership=ownership,
            bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),))
        runner.begin_test("real-bound-quiesce-short")
        try:
            b.write_register(0x04, 1)
            b.write_register(0x2c, 1)
            a.write_register(0x14, 1)
            runner.step("gpio_a")
            outcome = runner.quiesce(2)
            self.assertEqual("incomplete", outcome.status)
            self.assertEqual(2, outcome.steps)
            self.assertGreater(b.pending_events, 0)
            self.assertEqual("incomplete", [event for event in runner.events
                         if event.get("kind") == "quiesce_end"][-1]["status"])
        finally:
            runner.finalize()

    def test_quiesce_drains_real_bound_gpio_input(self):
        ownership = compile_ownership(
            (InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_gpio_a"),
             InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 1, 31, "source", "external_gpio_b")))
        a, b = OpenTitanGpioSession(), OpenTitanGpioSession()
        runner = ScenarioRunner(
            sessions={"gpio_a": a, "gpio_b": b}, ownership=ownership,
            bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),))
        runner.begin_test("real-bound-quiesce")
        try:
            b.write_register(0x04, 1)
            b.write_register(0x2c, 1)
            a.write_register(0x14, 1)
            runner.step("gpio_a")
            self.assertEqual(("gpio_b",), runner.final_state_document()[
                "pending_dataflow_targets"])
            before = runner.local_ticks["gpio_b"]
            outcome = runner.quiesce(20)
            self.assertEqual("drained", outcome.status)
            self.assertEqual(20, outcome.steps)
            self.assertEqual(before + 20, runner.local_ticks["gpio_b"])
            self.assertEqual(1, b.read_register(0x00) & 1)
            self.assertEqual((), runner.final_state_document()[
                "pending_dataflow_targets"])
        finally:
            runner.finalize()

    def test_two_real_gpio_sessions_match_across_step_batch_sizes(self):
        ownership = compile_ownership(
            (InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_gpio_a"),
             InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 1, 31, "source", "external_gpio_b")))

        def run_with_batches(sizes):
            a, b = OpenTitanGpioSession(), OpenTitanGpioSession()
            runner = ScenarioRunner(
                sessions={"gpio_a": a, "gpio_b": b}, ownership=ownership,
                bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),))
            runner.begin_test("two-gpio-batching")
            try:
                runner.inject_source("gpio_b", "gpio_in", 1,
                                     direction="IP_TO_IP", bit_offset=8, width=1)
                b.write_register(0x04, 1)
                b.write_register(0x2c, 1)
                a.write_register(0x14, 1)
                schedule = ("gpio_a", "gpio_b") * 12
                offset = 0
                index = 0
                while offset < len(schedule):
                    count = sizes[index % len(sizes)]
                    runner.step_batch(schedule[offset:offset + count])
                    offset += count
                    index += 1
                return runner.events, dict(runner.local_ticks), runner.final_state_document()
            finally:
                runner.finalize()

        baseline = run_with_batches((1,))
        self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                            for event in baseline[0]))
        self.assertEqual(baseline, run_with_batches((24,)))
        self.assertEqual(baseline, run_with_batches((2, 5, 1)))

    def test_gpio_output_flows_into_second_real_gpio_irq_without_reset(self):
        ownership = compile_ownership(
            (InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_gpio_a"),
             InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 1, 31, "source", "external_gpio_b")))
        a = OpenTitanGpioSession()
        b = OpenTitanGpioSession()
        runner = ScenarioRunner(
            sessions={"gpio_a": a, "gpio_b": b}, ownership=ownership,
            bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),))
        try:
            runner.begin_test("real-gpio-chain")
            with self.assertRaisesRegex(ValueError, "bound input cannot be mutated"):
                runner.inject_source("gpio_b", "gpio_in", 1,
                                     direction="IP_TO_IP", bit_offset=0, width=1)
            runner.inject_source("gpio_b", "gpio_in", 1,
                                 direction="IP_TO_IP", bit_offset=8, width=1)
            # All writes go to the real TL-UL target, each in its own process.
            b.write_register(0x04, 1)  # INTR_ENABLE
            b.write_register(0x2c, 1)  # INTR_CTRL_EN_RISING
            a.write_register(0x14, 0)
            for _ in range(8):
                runner.step("gpio_a")
                self.assertEqual(0, runner.step("gpio_b")["irq"])
            a.write_register(0x14, 1)
            for _ in range(12):
                runner.step("gpio_a")
                result = runner.step("gpio_b")
            self.assertEqual(1, result["irq"])
            self.assertEqual(1, b.read_register(0x00) & 1)  # INTR_STATE
            self.assertEqual(1, a.read_register(0x14) & 1)  # DIRECT_OUT persists
            self.assertEqual(0x101, b.read_register(0x10) & 0x101)  # DATA_IN
            self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                                for event in runner.events))
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
