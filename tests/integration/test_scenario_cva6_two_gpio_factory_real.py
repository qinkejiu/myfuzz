"""Real CVA6 and two independent OpenTitan GPIO factory wiring smoke."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario import cva6_gpio_example
from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.runner import Binding


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCva6TwoGpioFactoryTests(unittest.TestCase):
    def test_factory_has_two_real_targets_and_bound_a_to_b_to_cpu_path(self):
        self.assertTrue(hasattr(cva6_gpio_example, "make_cva6_two_gpio_runner"))
        runner = cva6_gpio_example.make_cva6_two_gpio_runner()
        self.assertEqual({"cpu", "gpio_a", "gpio_b"}, set(runner.sessions))
        cpu = runner.sessions["cpu"]
        gpio_a = runner.sessions["gpio_a"]
        gpio_b = runner.sessions["gpio_b"]
        self.assertIsInstance(cpu, Cva6CpuSession)
        self.assertIsInstance(gpio_a, OpenTitanGpioSession)
        self.assertIsInstance(gpio_b, OpenTitanGpioSession)
        self.assertIsNot(gpio_a, gpio_b)
        self.assertEqual(
            {"gpio_a": (0x40001000, gpio_a),
             "gpio_b": (0x40000000, gpio_b)},
            {window.device_id: (window.base, window.target)
             for window in cpu.router.windows})
        self.assertEqual(
            (Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 8),
             Binding("gpio_b", "irq", "cpu", "irq", 1)),
            runner.bindings)
        self.assertEqual("external_a", runner.ownership.mutation_source(
            "gpio_a", "gpio_in", 0, 32, direction="IP_TO_CPU_TO_IP"))
        self.assertEqual("external_b", runner.ownership.mutation_source(
            "gpio_b", "gpio_in", 8, 24, direction="IP_TO_CPU_TO_IP"))
        with self.assertRaisesRegex(ValueError, "bound input"):
            runner.ownership.mutation_source(
                "gpio_b", "gpio_in", 0, 8, direction="IP_TO_CPU_TO_IP")
        with self.assertRaisesRegex(ValueError, "bound input"):
            runner.ownership.mutation_source(
                "cpu", "irq", 0, 1, direction="IP_TO_CPU_TO_IP")

        cpu.memory.preload(0x80000000, (0x0000006f).to_bytes(4, "little"))
        runner.begin_test("cva6-two-gpio-factory")
        try:
            gpio_b.write_register(0x04, 1)
            gpio_b.write_register(0x2c, 1)
            runner.inject_source("gpio_b", "gpio_in", 1,
                                 direction="IP_TO_CPU_TO_IP",
                                 bit_offset=8, width=24)
            for _ in range(12):
                initial_b = runner.step("gpio_b")
            self.assertEqual(0, initial_b["irq"])
            gpio_a.write_register(0x14, 0x5b)
            output_a = runner.step("gpio_a")
            self.assertEqual(0x5b, output_a["gpio_out"] & 0xff)
            for _ in range(24):
                output_b = runner.step("gpio_b")
                if output_b["irq"]:
                    break
            self.assertEqual(1, output_b["irq"])
            self.assertTrue(any(
                event.get("kind") == "dataflow_delivery"
                and event.get("source") == ("gpio_a", "gpio_out")
                and event.get("target") == ("gpio_b", "gpio_in")
                and event.get("value") == 0x5b
                for event in runner.events))
            self.assertTrue(any(
                event.get("component") == "gpio_b"
                and event.get("inputs", {}).get("gpio_in") == 0x15b
                for event in runner.events))
            self.assertTrue(any(
                event.get("kind") == "dataflow_delivery"
                and event.get("source") == ("gpio_b", "irq")
                and event.get("target") == ("cpu", "irq")
                and event.get("value") == 1
                for event in runner.events))
            runner.step("cpu")
            self.assertTrue(any(
                event.get("component") == "cpu"
                and event.get("inputs", {}).get("irq") == 1
                for event in runner.events))
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
