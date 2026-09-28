"""Real Ibex and two OpenTitan GPIOs share one continuous scenario runner."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealRunnerIbexGpioTests(unittest.TestCase):
    def test_real_gpio_irq_enters_ibex_isr_and_is_cleared_by_cpu(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=31,
                                  max_initialized_bytes=0x20000)
        main = (0x000102b7,  # lui t0, 0x10: mtvec base 0x10100
                0x10028293,  # addi t0, t0, 0x100
                0x30529073,  # csrw mtvec, t0
                0x000012b7,  # lui t0, 1
                0x80028293,  # addi t0, t0, -2048: MEIE
                0x3042a073,  # csrs mie, t0
                0x00800293,  # addi t0, x0, 8: MIE
                0x3002a073,  # csrs mstatus, t0
                0x0000006f)
        isr = (0x400000b7,  # GPIO B base
               0x0100a103,  # lw x2, DATA_IN
               0x20202023,  # sw x2, RAM[0x200]
               0x00100193,  # li x3, 1
               0x0030a023,  # sw x3, INTR_STATE: W1C
               0x30200073)  # mret
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little") for word in main))
        image = b"".join(word.to_bytes(4, "little") for word in isr)
        memory.preload(0x10100, image)  # direct mtvec
        memory.preload(0x1012c, image)  # vectored external interrupt slot
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow("gpio_b", 0x40000000, 0x1000, gpio),))
        cpu = IbexCpuSession(memory=memory, router=router)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_pins")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio_b": gpio}, ownership=ownership,
            bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
        try:
            runner.begin_test("real-ibex-isr")
            gpio.write_register(0x04, 1)
            gpio.write_register(0x2c, 1)
            for _ in range(12):
                runner.step("gpio_b")
            runner.inject_source("gpio_b", "gpio_in", 0x5b,
                                 direction="IP_TO_CPU")
            for _ in range(24):
                runner.step("gpio_b")
            self.assertEqual(1, runner.events[-2]["outputs"]["irq"])
            for _ in range(2000):
                runner.step("cpu")
                if cpu.memory_write_count and cpu.mmio_write_count:
                    break
            self.assertGreaterEqual(cpu.memory_write_count, 1)
            self.assertEqual(0x5b, memory.read(0x200, 4,
                                               transaction_id="assert").value)
            self.assertGreaterEqual(cpu.mmio_read_count, 1)
            self.assertGreaterEqual(cpu.mmio_write_count, 1)
            self.assertEqual(0, gpio.read_register(0x00) & 1)
            first = memory.read(0x200, 4, transaction_id="first-round")
            for _ in range(24):
                low = runner.step("gpio_b")
            self.assertEqual(0, low["irq"])
            for _ in range(32):
                runner.step("cpu")  # retire MRET before the next external edge
            runner.inject_source("gpio_b", "gpio_in", 0x5a,
                                 direction="IP_TO_CPU")
            for _ in range(24):
                runner.step("gpio_b")
            runner.inject_source("gpio_b", "gpio_in", 0x59,
                                 direction="IP_TO_CPU")
            for _ in range(24):
                high = runner.step("gpio_b")
            self.assertEqual(1, high["irq"])
            for _ in range(2000):
                runner.step("cpu")
                if cpu.memory_write_count >= 2 and cpu.mmio_write_count >= 2:
                    break
            self.assertGreaterEqual(cpu.memory_write_count, 2)
            self.assertGreaterEqual(cpu.mmio_write_count, 2)
            second = memory.read(0x200, 4, transaction_id="second-round")
            self.assertEqual(0x5b, first.value)
            self.assertEqual(0x59, second.value)
            self.assertNotEqual(first.versions, second.versions)
            self.assertEqual(0, gpio.read_register(0x00) & 1)
        finally:
            runner.finalize()

    def test_gpio_irq_is_bound_cpu_input_and_gpio_data_reaches_other_ip(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=27,
                                  max_initialized_bytes=0x20000)
        program = (0x400000b7, 0x0100a103, 0x400011b7,
                   0x0021aa23, 0x20202223, 0x0000006f)
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little")
                                       for word in program))
        gpio_a, gpio_b = OpenTitanGpioSession(), OpenTitanGpioSession()
        router = DataflowRouter((
            DeviceWindow("gpio_b", 0x40000000, 0x1000, gpio_b),
            DeviceWindow("gpio_a", 0x40001000, 0x1000, gpio_a)))
        cpu = IbexCpuSession(memory=memory, router=router)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_pins")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio_a": gpio_a, "gpio_b": gpio_b},
            ownership=ownership,
            bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
        try:
            runner.begin_test("ibex-two-ot-gpio")
            gpio_b.write_register(0x04, 1)
            gpio_b.write_register(0x2c, 1)
            for _ in range(8):
                runner.step("gpio_b")
            runner.inject_source("gpio_b", "gpio_in", 0x5b,
                                 direction="IP_TO_CPU")
            for _ in range(24):
                gpio_result = runner.step("gpio_b")
            self.assertEqual(1, gpio_result["irq"])
            with self.assertRaisesRegex(ValueError, "bound input cannot be mutated"):
                runner.inject_source("cpu", "irq", 0,
                                     direction="IP_TO_CPU", bit_offset=0, width=1)
            for _ in range(2000):
                runner.step("cpu")
                if cpu.memory_write_count:
                    break
            self.assertEqual(0x5b, gpio_a.read_register(0x14))
            self.assertEqual(0x5b, memory.read(0x204, 4,
                                               transaction_id="assert").value)
            self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                                and event.get("target") == ("cpu", "irq")
                                and event.get("value") == 1 for event in runner.events))
            self.assertTrue(any(event.get("component") == "cpu"
                                and event["inputs"].get("irq") == 1
                                for event in runner.events))
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
