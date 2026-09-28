"""A real OpenTitan GPIO IRQ enters the independent CVA6 RTL harness."""

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.cva6_gpio_example import make_cva6_gpio_irq_runner
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import (Action, GenomeCodec, MemoryImage,
                                    ScenarioGenome, Trigger)


def _addi(rd, rs1, immediate):
    return ((immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13)


def _sw(rs2, rs1, offset):
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, rs1, offset):
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _image(words):
    return b"".join(word.to_bytes(4, "little") for word in words)


def make_cva6_gpio_irq_genome():
    main = [
        0x400000b7,             # GPIO base in x1
        _addi(2, 0, 1),
        _sw(2, 1, 0x04),        # INTR_ENABLE
        _sw(2, 1, 0x2c),        # rising edge enable
    ]
    auipc_pc = 0x80000080 + len(main) * 4
    main.extend((
        0x00000297,             # auipc x5, 0
        _addi(5, 5, 0x80000100 - auipc_pc),
        0x30529073,             # csrw mtvec, x5
        0x000012b7,             # lui x5, 1
        _addi(5, 5, -2048),     # x5 = 0x800 (MEIE)
        0x3042a073,             # csrw mie, x5
        _addi(5, 0, 8),
        0x3002a073,             # csrw mstatus, x5
        0x0000006f,
    ))
    isr = [
        0x400000b7,             # GPIO base
        _lw(2, 1, 0),          # real INTR_STATE
    ]
    isr_auipc_pc = 0x80000100 + len(isr) * 4
    isr.extend((
        0x00000197,             # auipc x3, 0
        _addi(3, 3, 0x80000200 - isr_auipc_pc),
        _sw(2, 3, 0),          # record actual read data in RAM
        _sw(2, 1, 0),          # W1C
        0x30200073,             # mret
    ))
    return ScenarioGenome(
        testcase_id="cva6-gpio-irq", direction="IP_TO_CPU",
        path_id="gpio-irq-cva6-isr", schedule_order=("cpu", "gpio"),
        max_steps=2000,
        actions=(Action(
            "edge", "gpio", "gpio_in", 1, "IP_TO_CPU",
            Trigger("AFTER_OUTPUT", "cpu", "addr", (1 << 64) - 1,
                    0x4000002c), delay_component="cpu", delay_ticks=100),),
        initial_images=(
            MemoryImage("cpu.boot", "cpu", 0x80000000, "6f000008"),
            MemoryImage("cpu.main", "cpu", 0x80000080, _image(main).hex()),
            MemoryImage("cpu.isr", "cpu", 0x80000100, _image(isr).hex()),
            MemoryImage("cpu.result", "cpu", 0x80000200, "00000000"),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCva6GpioIrqTests(unittest.TestCase):
    def test_external_gpio_edge_causes_real_cva6_isr_read_and_ram_store(self):
        genome = make_cva6_gpio_irq_genome()
        runner = make_cva6_gpio_irq_runner()
        for image in genome.initial_images:
            runner.preload_image(image)
        cpu = runner.sessions["cpu"]
        memory = cpu.memory
        runner.begin_test("cva6-gpio-irq")
        try:
            for _ in range(20000):
                runner.step("cpu")
                if cpu.mmio_write_count >= 2:
                    break
            else:
                self.fail("CVA6 did not configure GPIO interrupt")
            for _ in range(100):
                runner.step("cpu")
            runner.inject_source("gpio", "gpio_in", 1,
                                 direction="IP_TO_CPU", action_id="edge")
            for _ in range(40):
                output = runner.step("gpio")
                if output["irq"]:
                    break
            else:
                self.fail("real GPIO did not raise IRQ")
            for _ in range(20000):
                runner.step("cpu")
                if cpu.memory_write_count:
                    break
            else:
                self.fail("CVA6 did not execute ISR RAM store")
            self.assertTrue(any(event.get("kind") == "memory_write"
                                and event.get("address") == 0x80000200
                                for event in runner.events))
            self.assertTrue(any(event.get("kind") == "mmio_delivery"
                                and event.get("device_id") == "gpio"
                                and event.get("offset") == 0
                                and not event.get("write")
                                and event.get("read_value", 0) & 1
                                for event in runner.events))
            self.assertEqual(1, memory.read(0x80000200, 4,
                                            transaction_id="assert").value)
        finally:
            runner.finalize()

    def test_continuous_genome_replays_cva6_gpio_irq_chain(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode(
            (root / "configs/scenario/cva6_gpio_irq.json").read_bytes())
        self.assertEqual(genome, make_cva6_gpio_irq_genome())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, make_cva6_gpio_irq_runner, bundle)
            self.assertEqual("complete", trace.status)
            self.assertTrue(any(event.get("kind") == "memory_write"
                                and event.get("address") == 0x80000200
                                for event in trace.events))
            comparison = replay_evidence_bundle(
                bundle, make_cva6_gpio_irq_runner)
            self.assertTrue(comparison.matches, comparison)
