"""A transport reorder cannot reverse writes into real OpenTitan GPIO RTL."""

import os
import unittest

from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealTransactionOrderTests(unittest.TestCase):
    def test_same_value_new_cpu_store_has_two_real_gpio_acceptances(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 0x20000),),
            initialization_seed=61, max_initialized_bytes=0x20000)
        program = (0x400000b7, 0x0a500113, 0x0020aa23,
                   0x0020aa23, 0x0000006f)
        memory.preload(0x10080, b"".join(
            word.to_bytes(4, "little") for word in program))
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow(
            "gpio", 0x40000000, 0x1000, gpio),))
        cpu = IbexCpuSession(memory=memory, router=router, defer_mmio=True)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 2, "fixed", "constant_zero"),
             InputOwner("gpio", "gpio_in", 0, 32, "fixed", "constant_zero")))
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                                ownership=ownership, bindings=())
        runner.begin_test("tx03-same-value-real-stores")
        try:
            for expected in (1, 2):
                for _ in range(20000):
                    runner.step("cpu")
                    if router.pending_target_counts.get("gpio", 0) == 1:
                        break
                else:
                    self.fail(f"CPU did not accept real Store {expected}")
                self.assertEqual(expected, len(router.acceptances))
                runner.step("gpio")
                self.assertEqual(expected, len(router.deliveries))
                self.assertEqual(0xa5, gpio.read_register(0x14))
            accepted = [item["source_transaction"] for item in router.acceptances]
            delivered = [item["source_transaction"] for item in router.deliveries]
            self.assertEqual(accepted, delivered)
            self.assertNotEqual(accepted[0], accepted[1])
            self.assertEqual([1, 2], [key.source_sequence for key in accepted])
            self.assertEqual([0xa5, 0xa5], [
                item["write_value"] for item in router.deliveries])
            self.assertEqual([1, 2], [
                item["target_delivery_order"] for item in router.deliveries])
            self.assertEqual(2, cpu.mmio_write_count)
            self.assertEqual((), router.pending_targets)
        finally:
            runner.finalize()

    def test_two_real_cpu_sources_can_complete_independent_gpio_targets_in_target_step_order(self):
        ibex_memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 0x20000),),
            initialization_seed=61, max_initialized_bytes=0x20000)
        ibex_memory.preload(0x10080, b"".join(
            word.to_bytes(4, "little") for word in
            (0x400000b7, 0x0a500113, 0x0020aa23, 0x0000006f)))
        cva6_memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
            initialization_seed=24, max_initialized_bytes=0x10000)
        cva6_memory.preload(0x80000000, (0x0800006f).to_bytes(4, "little"))
        cva6_memory.preload(0x80000080, b"".join(
            word.to_bytes(4, "little") for word in
            (0x500000b7, 0x05a00113, 0x0020aa23, 0x0000006f)))
        gpio_a, gpio_b = OpenTitanGpioSession(), OpenTitanGpioSession()
        router = DataflowRouter((
            DeviceWindow("gpio_a", 0x40000000, 0x1000, gpio_a),
            DeviceWindow("gpio_b", 0x50000000, 0x1000, gpio_b)))
        ibex = IbexCpuSession(memory=ibex_memory, router=router,
                              defer_mmio=True)
        cva6 = Cva6CpuSession(memory=cva6_memory, router=router,
                              defer_mmio=True)
        ownership = compile_ownership(
            (InputField("ibex", "irq", 2), InputField("cva6", "irq", 2),
             InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("ibex", "irq", 0, 2, "fixed", "constant_zero"),
             InputOwner("cva6", "irq", 0, 2, "fixed", "constant_zero"),
             InputOwner("gpio_a", "gpio_in", 0, 32, "fixed", "constant_zero"),
             InputOwner("gpio_b", "gpio_in", 0, 32, "fixed", "constant_zero")))
        runner = ScenarioRunner(
            sessions={"ibex": ibex, "cva6": cva6,
                      "gpio_a": gpio_a, "gpio_b": gpio_b},
            ownership=ownership, bindings=())
        runner.begin_test("tx04-two-targets")
        try:
            for name, target in (("ibex", "gpio_a"),
                                 ("cva6", "gpio_b")):
                for _ in range(20000):
                    runner.step(name)
                    if router.pending_target_counts.get(target, 0):
                        break
                else:
                    self.fail(f"{name} did not accept {target} MMIO")
            self.assertEqual({"gpio_a": 1, "gpio_b": 1},
                             router.pending_target_counts)
            runner.step("gpio_b")
            self.assertEqual(0x5a, gpio_b.read_register(0x14))
            self.assertEqual(0, gpio_a.read_register(0x14))
            runner.step("gpio_a")
            self.assertEqual(0xa5, gpio_a.read_register(0x14))
            self.assertEqual(["cva6", "ibex"], [
                entry["source_transaction"].source_component
                for entry in router.deliveries])
            self.assertEqual(["gpio_b", "gpio_a"], [
                entry["device_id"] for entry in router.deliveries])
            self.assertEqual([1, 1], [
                entry["target_delivery_order"] for entry in router.deliveries])
            self.assertEqual((), router.pending_targets)
        finally:
            runner.finalize()

    def test_two_real_cpu_sources_keep_shared_gpio_acceptance_order(self):
        ibex_memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 0x20000),),
            initialization_seed=61, max_initialized_bytes=0x20000)
        ibex_program = (0x400000b7, 0x0a500113, 0x0020aa23,
                        0x0140a183, 0x0000006f)
        ibex_memory.preload(0x10080, b"".join(
            word.to_bytes(4, "little") for word in ibex_program))
        cva6_memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
            initialization_seed=24, max_initialized_bytes=0x10000)
        cva6_memory.preload(0x80000000, (0x0800006f).to_bytes(4, "little"))
        cva6_program = (0x400000b7, 0x05a00113, 0x0020aa23,
                        0x0140a183, 0x0000006f)
        cva6_memory.preload(0x80000080, b"".join(
            word.to_bytes(4, "little") for word in cva6_program))
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow(
            "gpio", 0x40000000, 0x1000, gpio),))
        ibex = IbexCpuSession(memory=ibex_memory, router=router,
                              defer_mmio=True)
        cva6 = Cva6CpuSession(memory=cva6_memory, router=router,
                              defer_mmio=True)
        ownership = compile_ownership(
            (InputField("ibex", "irq", 2), InputField("cva6", "irq", 2),
             InputField("gpio", "gpio_in", 32)),
            (InputOwner("ibex", "irq", 0, 2, "fixed", "constant_zero"),
             InputOwner("cva6", "irq", 0, 2, "fixed", "constant_zero"),
             InputOwner("gpio", "gpio_in", 0, 32, "fixed", "constant_zero")))
        runner = ScenarioRunner(
            sessions={"ibex": ibex, "cva6": cva6, "gpio": gpio},
            ownership=ownership, bindings=())
        runner.begin_test("tx04-two-real-cpu-sources")
        try:
            for name in ("ibex", "cva6"):
                for _ in range(20000):
                    runner.step(name)
                    if router.pending_target_counts.get("gpio", 0) == (
                            1 if name == "ibex" else 2):
                        break
                else:
                    self.fail(f"{name} did not accept GPIO MMIO")
            self.assertEqual(2, router.pending_target_counts["gpio"])
            self.assertEqual(0, gpio.read_register(0x14))
            self.assertEqual(0, ibex.mmio_write_count + cva6.mmio_write_count)
            runner.step("gpio")
            self.assertEqual(1, router.pending_target_counts["gpio"])
            self.assertEqual(0xa5, gpio.read_register(0x14))
            runner.step("gpio")
            self.assertEqual((), router.pending_targets)
            self.assertEqual(0x5a, gpio.read_register(0x14))
            self.assertEqual(["ibex", "cva6"], [
                item["source_transaction"].source_component
                for item in router.deliveries])
            self.assertEqual([1, 2], [
                item["target_delivery_order"] for item in router.deliveries])
            self.assertEqual(1, ibex.mmio_write_count)
            self.assertEqual(1, cva6.mmio_write_count)
        finally:
            runner.finalize()

    def test_out_of_order_transport_does_not_reorder_gpio_writes(self):
        gpio = OpenTitanGpioSession()
        gpio.begin_case("tx04-real-order")
        try:
            router = DataflowRouter((DeviceWindow("gpio", 0x40000000,
                                                   0x1000, gpio),))
            ledger = TransactionLedger()

            def key(sequence):
                return TransactionKey("execution", "tx04-real-order", "cpu",
                                      0, "data", sequence)

            def write(sequence, value):
                return router.transact(
                    ledger, key(sequence), address=0x40000014, write=True,
                    wdata=value, be=15, beat_bytes=4)

            with self.assertRaisesRegex(ValueError, "out_of_order_transaction"):
                write(2, 3)
            self.assertEqual(0, gpio.read_register(0x14))
            self.assertEqual((0, 0), write(1, 1))
            self.assertEqual(1, gpio.read_register(0x14))
            self.assertEqual((0, 0), write(2, 3))
            self.assertEqual(3, gpio.read_register(0x14))
            self.assertEqual([1, 2], [delivery["source_transaction"].source_sequence
                                      for delivery in router.deliveries])
            self.assertEqual([1, 2], [delivery["source_sequence"]
                                      for delivery in router.deliveries])
            self.assertEqual([1, 2], [delivery["delivery_order"]
                                      for delivery in router.deliveries])
            self.assertEqual([1, 2], [delivery["target_delivery_order"]
                                      for delivery in router.deliveries])
            write(1, 1)
            self.assertEqual(2, len(router.deliveries))
            self.assertEqual(3, gpio.read_register(0x14))
        finally:
            gpio.end_case()


if __name__ == "__main__":
    unittest.main()
