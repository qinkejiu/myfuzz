"""Source backed Ibex IRQ mask and controller take observations."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


class UnusedTarget:
    def write_register(self, offset, value, *, be=15):
        raise AssertionError("unexpected MMIO write")

    def read_register(self, offset):
        raise AssertionError("unexpected MMIO read")


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class IbexIrqObservationTests(unittest.TestCase):
    @staticmethod
    def _real_pulse_case(width):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=59,
                                  max_initialized_bytes=0x20000)
        memory.preload(0x10080, (0x0000006f).to_bytes(4, "little"))
        gpio = OpenTitanGpioSession()
        cpu = IbexCpuSession(
            memory=memory,
            router=DataflowRouter((DeviceWindow("gpio", 0x40000000, 0x1000,
                                                gpio),)))
        binding = Binding("gpio", "irq", "cpu", "irq", 1)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins")))
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                                ownership=ownership, bindings=(binding,),
                                irq_pulses={binding: width})
        runner.begin_test("real-gpio-irq-pulse")
        gpio.write_register(0x04, 1)  # INTR_ENABLE
        gpio.write_register(0x2c, 1)  # INTR_CTRL_EN_RISING
        for _ in range(12):
            runner.step("gpio")
        return runner, gpio

    @staticmethod
    def _real_rise(runner, value):
        runner.inject_source("gpio", "gpio_in", value, direction="IP_TO_CPU")
        for _ in range(24):
            current = runner.step("gpio")
            if current["irq"] == 1:
                return
        raise AssertionError("real GPIO did not assert IRQ")

    def test_real_csr_mask_opens_and_controller_takes_external_irq(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=57,
                                  max_initialized_bytes=0x20000)
        program = (0x000012b7, 0x80028293, 0x3042a073,  # MEIE
                   0x00800293, 0x3002a073,  # MIE
                   0x0000006f)
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little")
                                       for word in program))
        router = DataflowRouter((DeviceWindow("unused", 0x40000000, 0x1000,
                                              UnusedTarget()),))
        cpu = IbexCpuSession(memory=memory, router=router)
        cpu.begin_case("real-irq-observation")
        try:
            first = cpu.step_local({"irq": 0})
            self.assertEqual(1, first["irq_masked_pre"])
            for _ in range(300):
                current = cpu.step_local({"irq": 0})
                if current["irq_masked_pre"] == 0:
                    break
            self.assertEqual(0, current["irq_masked_pre"])
            for _ in range(100):
                current = cpu.step_local({"irq": 1})
                if current["irq_taken_pre"]:
                    break
            self.assertEqual(1, current["irq_taken_pre"])
        finally:
            cpu.end_case()

    def test_real_gpio_pulse_expires_while_ibex_masked_then_new_edge_delivers(self):
        runner, gpio = self._real_pulse_case(2)
        try:
            self._real_rise(runner, 1)
            first = [runner.step("cpu") for _ in range(3)]
            self.assertEqual([1, 1, 1], [step["irq_masked_pre"] for step in first])
            self.assertEqual([0, 0, 0], [step["irq_taken_pre"] for step in first])
            self.assertTrue(any(e.get("kind") == "expired_masked"
                                for e in runner.events))
            gpio.write_register(0x00, 1)  # actual W1C in GPIO RTL
            for _ in range(24):
                low = runner.step("gpio")
            self.assertEqual(0, low["irq"])
            runner.inject_source("gpio", "gpio_in", 0, direction="IP_TO_CPU")
            for _ in range(24):
                runner.step("gpio")
            self._real_rise(runner, 1)
            runner.step("cpu")
            self.assertEqual(1, [e["inputs"]["irq"] for e in runner.events
                                 if e.get("component") == "cpu" and "inputs" in e][-1])
            self.assertEqual(2, sum(e.get("kind") == "source_start"
                                    for e in runner.events))
        finally:
            runner.finalize()

    def test_real_gpio_second_edge_overruns_occupied_cpu_pulse(self):
        runner, gpio = self._real_pulse_case(20)
        try:
            self._real_rise(runner, 1)
            runner.step("cpu")
            gpio.write_register(0x00, 1)
            for _ in range(24):
                low = runner.step("gpio")
            self.assertEqual(0, low["irq"])
            runner.inject_source("gpio", "gpio_in", 0, direction="IP_TO_CPU")
            for _ in range(24):
                runner.step("gpio")
            self._real_rise(runner, 1)
            self.assertEqual("unsupported_irq_overrun", runner.failure_status)
            sources = [e for e in runner.events if e.get("kind") == "source_start"]
            overrun = [e for e in runner.events if e.get("kind") == "irq_overrun"]
            self.assertEqual(2, len(sources))
            self.assertEqual(1, len(overrun))
            self.assertEqual(sources[1]["source_event_id"],
                             overrun[0]["source_event_id"])
            self.assertEqual(sources[0]["source_event_id"],
                             overrun[0]["active_source_event_id"])
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
