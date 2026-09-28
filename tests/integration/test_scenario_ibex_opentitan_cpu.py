"""A real Ibex request is routed to a separate real OpenTitan GPIO process."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealIbexOpenTitanTests(unittest.TestCase):
    def test_cpu_mmio_write_and_real_gpio_readback_persist(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=9,
                                  max_initialized_bytes=0x20000)
        # Ibex's fixed reset vector is 0x10080 for BOOT_ADDR=0x10000.
        program = (0x400000b7,  # lui x1, 0x40000: OpenTitan GPIO window
                   0x0a500113,  # addi x2, x0, 0xa5
                   0x0020aa23,  # sw x2, 0x14(x1): DIRECT_OUT
                   0x0140a183,  # lw x3, 0x14(x1): real RTL readback
                   0x20302023,  # sw x3, 0x200(x0): persistent RAM
                   0x0000006f)  # jal x0, 0
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little")
                                       for word in program))
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow("gpio", 0x40000000, 0x1000, gpio),))
        cpu = IbexCpuSession(memory=memory, router=router)
        gpio.begin_case("ibex-ot-mmio")
        try:
            cpu.begin_case("ibex-ot-mmio")
            for _ in range(2000):
                cpu.step_local({"irq": 0})
                if cpu.memory_write_count >= 1:
                    break
            self.assertGreaterEqual(cpu.mmio_write_count, 1)
            self.assertGreaterEqual(cpu.mmio_read_count, 1)
            self.assertEqual(0xa5, gpio.read_register(0x14))
            self.assertEqual(0xa5, memory.read(0x200, 4,
                                               transaction_id="assert").value)
            self.assertEqual(0xa5, gpio.read_register(0x14))
        finally:
            cpu.end_case()
            gpio.end_case()

    def test_external_gpio_data_flows_through_ibex_to_other_gpio(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=17,
                                  max_initialized_bytes=0x20000)
        program = (0x400000b7,  # B base
                   0x0100a103,  # lw x2, DATA_IN(x1)
                   0x400011b7,  # A base
                   0x0021aa23,  # sw x2, DIRECT_OUT(x3)
                   0x20202223,  # sw x2, 0x204(x0)
                   0x0000006f)
        memory.preload(0x10080, b"".join(word.to_bytes(4, "little")
                                       for word in program))
        gpio_a, gpio_b = OpenTitanGpioSession(), OpenTitanGpioSession()
        router = DataflowRouter((
            DeviceWindow("gpio_b", 0x40000000, 0x1000, gpio_b),
            DeviceWindow("gpio_a", 0x40001000, 0x1000, gpio_a)))
        cpu = IbexCpuSession(memory=memory, router=router)
        gpio_a.begin_case("gpio-ibex-gpio")
        gpio_b.begin_case("gpio-ibex-gpio")
        try:
            for _ in range(8):
                gpio_b.step_local({"gpio_in": 0x5a})
            self.assertEqual(0x5a, gpio_b.read_register(0x10))
            cpu.begin_case("gpio-ibex-gpio")
            for _ in range(2000):
                cpu.step_local({"irq": 0})
                if cpu.memory_write_count:
                    break
            self.assertGreaterEqual(cpu.mmio_read_count, 1)
            self.assertGreaterEqual(cpu.mmio_write_count, 1)
            self.assertEqual(0x5a, gpio_a.read_register(0x14))
            self.assertEqual(0x5a, memory.read(0x204, 4,
                                               transaction_id="assert").value)
        finally:
            cpu.end_case()
            gpio_a.end_case()
            gpio_b.end_case()


if __name__ == "__main__":
    unittest.main()
