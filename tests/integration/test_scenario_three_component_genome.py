"""CPU program → GPIO A output → GPIO B IRQ → CPU ISR, with no SoC fabric."""

from __future__ import annotations

import os
import unittest
from copy import deepcopy

from myfuzz.scenario.checker import check_gpio_direct_out
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
from myfuzz.scenario.replay import record_scenario, replay_scenario


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _image(words: tuple[int, ...]) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class ThreeComponentGenomeTests(unittest.TestCase):
    @staticmethod
    def _case():
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=47,
                                  max_initialized_bytes=0x20000)
        a, b = OpenTitanGpioSession(), OpenTitanGpioSession()
        router = DataflowRouter((
            DeviceWindow("gpio_a", 0x40001000, 0x1000, a),
            DeviceWindow("gpio_b", 0x40000000, 0x1000, b)))
        cpu = IbexCpuSession(memory=memory, router=router)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
             InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 1, 31, "fixed", "constant_zero")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio_a": a, "gpio_b": b}, ownership=ownership,
            bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),
                      Binding("gpio_b", "irq", "cpu", "irq", 1)))
        main = (
            0x400000b7,  # lui x1, B base
            0x40001237,  # lui x4, A base
            0x00100113,  # addi x2,x0,1
            _sw(2, 1, 4),  # B.INTR_ENABLE
            _sw(2, 1, 44),  # B.INTR_CTRL_EN_RISING
            0x000102b7, 0x10028293, 0x30529073,  # mtvec=0x10100
            0x000012b7, 0x80028293, 0x3042a073,  # MEIE
            0x00800293, 0x3002a073,  # MIE
            _sw(2, 4, 20),  # A.DIRECT_OUT=1
            0x0000006f)
        isr = (
            0x400000b7,  # B base
            0x0100a103,  # lw x2, B.DATA_IN
            _sw(2, 0, 0x200),  # RAM snapshot
            0x00100193,  # li x3,1
            _sw(3, 1, 0),  # B.INTR_STATE W1C
            0x40001237,  # A base
            _sw(0, 4, 20),  # A low
            0x00000013, 0x00000013,
            _sw(3, 4, 20),  # A high for next round
            0x30200073)
        genome = ScenarioGenome(
            testcase_id="cpu-a-b-cpu", direction="CPU_TO_IP_TO_CPU",
            path_id="cpu-program-a-output-b-irq-cpu-isr",
            schedule_order=("cpu", "gpio_a", "gpio_b"), max_steps=3600,
            actions=(), initial_images=(
                MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
                MemoryImage("cpu.isr", "cpu", 0x10100, _image(isr)),
                MemoryImage("cpu.isr.vector", "cpu", 0x1012c, _image(isr))))
        return memory, cpu, runner, genome

    def test_cpu_gpio_a_gpio_b_cpu_chain_repeats_without_reset(self):
        memory, cpu, runner, genome = self._case()
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertGreaterEqual(cpu.memory_write_count, 2)
        self.assertGreaterEqual(cpu.mmio_write_count, 8)
        self.assertEqual(1, memory.read(0x200, 4, transaction_id="check").value & 1)
        self.assertTrue(any(e.get("kind") == "state_dependency"
                            and e.get("edge_kind") == "WAW"
                            for e in runner.events))
        self.assertTrue(any(e.get("kind") == "dataflow_delivery"
                            and e.get("source") == ("gpio_a", "gpio_out")
                            and e.get("value") == 1 for e in runner.events))
        self.assertTrue(any(e.get("kind") == "dataflow_delivery"
                            and e.get("source") == ("gpio_b", "irq")
                            and e.get("value") == 1 for e in runner.events))

    def test_independent_checker_detects_corrupted_real_gpio_observation(self):
        trace = record_scenario(self._case()[-1], lambda: self._case()[2])
        self.assertEqual((), check_gpio_direct_out(trace.events, ("gpio_a",)))
        corrupted = deepcopy(trace.events)
        written = False
        for event in corrupted:
            if (event.get("kind") == "mmio_delivery"
                    and event.get("device_id") == "gpio_a"
                    and event.get("offset") == 0x14 and event.get("write")):
                written = True
            elif written and event.get("component") == "gpio_a" \
                    and "outputs" in event:
                event["outputs"]["gpio_out"] ^= 1
                break
        else:
            self.fail("no real GPIO observation followed its accepted write")
        findings = check_gpio_direct_out(corrupted, ("gpio_a",))
        self.assertEqual(("gpio_direct_out_mismatch:gpio_a",),
                         tuple(item.finding_id for item in findings))

    def test_three_real_components_replay_same_state_evolution(self):
        genome = self._case()[3]
        reference = record_scenario(genome, lambda: self._case()[2])
        compared = replay_scenario(genome, lambda: self._case()[2], reference)
        self.assertTrue(compared.matches, compared.first_difference)
        self.assertTrue(any(e.get("kind") == "state_dependency"
                            and e.get("edge_kind") == "WAW"
                            for e in reference.events))


def make_three_component_runner():
    """Importable factory for disk evidence replay of the real chain."""
    return ThreeComponentGenomeTests._case()[2]


if __name__ == "__main__":
    unittest.main()
