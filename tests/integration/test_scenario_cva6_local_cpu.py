"""Pinned CVA6 runs by itself against the persistent scenario memory service."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCva6LocalTests(unittest.TestCase):
    def test_deferred_cva6_mmio_waits_for_separate_gpio_step(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
            initialization_seed=24, max_initialized_bytes=0x10000)
        memory.preload(0x80000000, (0x0800006f).to_bytes(4, "little"))
        program = (0x400000b7, 0x0a500113, 0x0020aa23,
                   0x0140a183, 0x0000006f)
        memory.preload(0x80000080, b"".join(
            word.to_bytes(4, "little") for word in program))
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow(
            "gpio", 0x40000000, 0x1000, gpio),))
        cpu = Cva6CpuSession(memory=memory, router=router, defer_mmio=True)
        runner = ScenarioRunner(sessions={"cva6": cpu, "gpio": gpio},
                                ownership=compile_ownership((), ()),
                                bindings=())
        runner.begin_test("cva6-deferred-gpio")
        try:
            for _ in range(20000):
                runner.step("cva6")
                if router.pending_targets:
                    break
            else:
                self.fail("CVA6 did not accept GPIO MMIO")
            self.assertEqual(("gpio",), router.pending_targets)
            self.assertEqual(0, cpu.mmio_write_count + cpu.mmio_read_count)
            self.assertEqual((), tuple(router.deliveries))
            runner.step("gpio")
            self.assertEqual((), router.pending_targets)
            self.assertEqual(1, cpu.mmio_write_count + cpu.mmio_read_count)
            self.assertEqual(1, len(router.deliveries))
            accepted = next(e for e in runner.events
                            if e.get("kind") == "mmio_acceptance")
            delivered = next(e for e in runner.events
                             if e.get("kind") == "mmio_delivery")
            self.assertLess(accepted["event_id"], delivered["event_id"])
            for _ in range(1000):
                output = runner.step("cva6")
                if output["response_consumed"]:
                    break
            else:
                self.fail("CVA6 did not consume the real GPIO write response")
            self.assertEqual(accepted["source_sequence"],
                             output["response_source_sequence"])
            for _ in range(20000):
                runner.step("cva6")
                if router.pending_targets:
                    break
            else:
                self.fail("CVA6 did not accept the real GPIO read")
            read_acceptance = router.acceptances[-1]
            self.assertFalse(read_acceptance["write"])
            runner.step("gpio")
            read_delivery = router.deliveries[-1]
            self.assertEqual(0xa5, read_delivery["read_value"] >> 32)
            for _ in range(1000):
                output = runner.step("cva6")
                if output["response_consumed"]:
                    break
            else:
                self.fail("CVA6 did not consume the real GPIO read response")
            self.assertEqual(read_acceptance["source_sequence"],
                             output["response_source_sequence"])
            self.assertEqual(read_delivery["read_value"],
                             output["response_rdata"])
        finally:
            runner.finalize()

    def test_transaction_cap_saves_and_replays_first_real_axi_commit(self):
        genome = ScenarioGenome(
            testcase_id="cva6-transaction-cap", direction="CPU_TO_IP",
            path_id="cva6-memory", schedule_order=("cva6",), max_steps=20000,
            actions=(), initial_images=(MemoryImage(
                "cva6.program", "cva6", 0x80000000, "6f000000"),))

        def factory():
            memory = PersistentMemory(
                regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
                initialization_seed=27, max_initialized_bytes=0x10000)
            return ScenarioRunner(
                sessions={"cva6": Cva6CpuSession(memory=memory)},
                ownership=compile_ownership((), ()), bindings=())

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "cva6-transaction-cap"
            trace = save_evidence_bundle(
                genome, factory, bundle,
                budget=ResourceBudget(max_transactions=1))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_transactions", trace.events[-1]["limit"])
            self.assertEqual(1, sum(event.get("kind") == "memory_read"
                                    for event in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches)
            self.assertEqual("full", replay.verification_scope)

    def test_old_result_after_local_reset_cannot_complete_new_step(self):
        class Capture:
            def __init__(self, stream):
                self.stream = stream
                self.lines = []

            def readline(self):
                line = self.stream.readline()
                self.lines.append(line)
                return line

            def close(self):
                self.stream.close()

        class OldFirst:
            def __init__(self, stream, old):
                self.stream = stream
                self.old = old
                self.real_reads = 0

            def readline(self):
                if self.old is not None:
                    line, self.old = self.old, None
                    return line
                self.real_reads += 1
                return self.stream.readline()

            def close(self):
                self.stream.close()

        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
            initialization_seed=26, max_initialized_bytes=0x10000)
        memory.preload(0x80000000, (0x0000006f).to_bytes(4, "little"))
        cpu = Cva6CpuSession(memory=memory)
        try:
            cpu.begin_case("cva6-stale-reset")
            capture = Capture(cpu._process.stdout)
            cpu._process.stdout = capture
            cpu.step_local({"irq": 0})
            old = capture.lines[0]
            self.assertTrue(old.startswith("RESULT " + cpu._wire_execution + " 1 "))
            execution = cpu._wire_execution
            cpu.reset_local()
            self.assertNotEqual(execution, cpu._wire_execution)
            proxy = OldFirst(cpu._process.stdout, old)
            cpu._process.stdout = proxy
            cpu.step_local({"irq": 0})
            self.assertIsNone(proxy.old)
            self.assertEqual(1, proxy.real_reads)
            self.assertEqual(2, cpu.local_ticks)
        finally:
            cpu.end_case()

    def test_cpu_store_persists_in_host_memory_without_soc_fabric(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
            initialization_seed=23, max_initialized_bytes=0x10000)
        # CVA6 starts at 0x80000000. The first jump reaches program +0x80.
        memory.preload(0x80000000, (0x0800006f).to_bytes(4, "little"))
        program = (0x00000097,  # auipc x1, 0 -> current PC
                   0x05a00113,  # addi x2, x0, 0x5a
                   0x2020a023,  # sw x2, 0x200(x1)
                   0x0000006f)  # jal x0, 0
        memory.preload(0x80000080, b"".join(word.to_bytes(4, "little")
                                         for word in program))
        cpu = Cva6CpuSession(memory=memory)
        try:
            cpu.begin_case("cva6-local-memory")
            for _ in range(20000):
                cpu.step_local({"irq": 0})
                if cpu.memory_write_count:
                    break
            self.assertGreaterEqual(cpu.memory_write_count, 1)
            self.assertEqual(0x5a, memory.read(0x80000280, 4,
                                               transaction_id="assert").value)
        finally:
            cpu.end_case()

    def test_cpu_mmio_reaches_separate_opentitan_gpio(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
            initialization_seed=24, max_initialized_bytes=0x10000)
        memory.preload(0x80000000, (0x0800006f).to_bytes(4, "little"))
        program = (0x400000b7,  # lui x1, GPIO base
                   0x0a500113,  # addi x2, x0, 0xa5
                   0x0020aa23,  # sw x2, DIRECT_OUT(x1)
                   0x0140a183,  # lw x3, DIRECT_OUT(x1)
                   0x0000006f)
        memory.preload(0x80000080, b"".join(word.to_bytes(4, "little")
                                         for word in program))
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow("gpio", 0x40000000, 0x1000, gpio),))
        cpu = Cva6CpuSession(memory=memory, router=router)
        gpio.begin_case("cva6-opentitan")
        try:
            cpu.begin_case("cva6-opentitan")
            for _ in range(20000):
                cpu.step_local({"irq": 0})
                if cpu.mmio_read_count:
                    break
            self.assertGreaterEqual(cpu.mmio_write_count, 1)
            self.assertGreaterEqual(cpu.mmio_read_count, 1)
            self.assertEqual(0xa5, gpio.read_register(0x14))
        finally:
            cpu.end_case()
            gpio.end_case()


if __name__ == "__main__":
    unittest.main()
