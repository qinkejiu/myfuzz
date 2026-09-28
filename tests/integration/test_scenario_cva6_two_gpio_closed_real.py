"""CVA6 -> GPIO A -> GPIO B -> CVA6, twice in one real testcase."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.cva6_gpio_example import make_cva6_two_gpio_runner
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import GenomeCodec, MemoryImage, ScenarioGenome


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/scenario/cva6_cpu_two_gpio_two_rounds.json"


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return ((immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13)


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _image(words: list[int]) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def make_cva6_two_gpio_genome() -> ScenarioGenome:
    main = [
        0x400000b7,           # x1 = GPIO B base
        0x40001237,           # x4 = GPIO A base
        _addi(2, 0, 1),       # rising IRQ bit and first output value
        _sw(2, 1, 0x04),      # B.INTR_ENABLE
        _sw(2, 1, 0x2c),      # B.INTR_CTRL_EN_RISING
    ]
    mtvec_pc = 0x80000080 + len(main) * 4
    main.extend((
        0x00000297,           # auipc x5, 0
        _addi(5, 5, 0x80000100 - mtvec_pc),
        0x30529073,           # csrw mtvec, x5
        0x000012b7,           # lui x5, 1
        _addi(5, 5, -2048),   # MEIE
        0x3042a073,           # csrw mie, x5
        _addi(5, 0, 8),       # MIE
        0x3002a073,           # csrw mstatus, x5
        _sw(2, 4, 0x14),      # A.DIRECT_OUT = 1
        0x0000006f,           # wait for IRQ
    ))
    isr = [
        0x400000b7,           # x1 = GPIO B base
        _lw(2, 1, 0x10),      # actual B.DATA_IN
    ]
    result_pc = 0x80000100 + len(isr) * 4
    isr.extend((
        0x00000197,           # auipc x3, 0
        _addi(3, 3, 0x80000200 - result_pc),
        _sw(2, 3, 0),         # persistent RAM result
        _sw(2, 1, 0),         # B.INTR_STATE W1C
        0x40001237,           # x4 = GPIO A base
        _sw(0, 4, 0x14),      # A low, so the next high is a new edge
    ))
    isr.extend((0x00000013,) * 8)
    isr.extend((
        _addi(2, 0, 3),
        _sw(2, 4, 0x14),      # A high = 3 on the next round
        0x30200073,           # mret
    ))
    return ScenarioGenome(
        testcase_id="cva6-cpu-two-gpio-two-rounds",
        direction="CPU_TO_IP_TO_CPU",
        path_id="cva6-a-b-cva6-two-rounds",
        schedule_order=("cpu", "gpio_a", "gpio_b"), max_steps=6000,
        actions=(), initial_images=(
            MemoryImage("cpu.boot", "cpu", 0x80000000, "6f000008"),
            MemoryImage("cpu.main", "cpu", 0x80000080, _image(main)),
            MemoryImage("cpu.isr", "cpu", 0x80000100, _image(isr)),
            MemoryImage("cpu.result", "cpu", 0x80000200, "00000000"),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCva6TwoGpioClosedTests(unittest.TestCase):
    def test_two_rounds_write_distinct_ram_versions_and_replay_from_new_runner(self):
        self.assertTrue(CONFIG.is_file(), f"missing fixed Genome: {CONFIG}")
        genome = GenomeCodec.decode(CONFIG.read_bytes())
        self.assertEqual(make_cva6_two_gpio_genome(), genome)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, make_cva6_two_gpio_runner, bundle)
            self.assertEqual("complete", trace.status)
            writes = [event for event in trace.events
                      if event.get("kind") == "memory_write"
                      and event.get("address") == 0x80000200]
            self.assertGreaterEqual(len(writes), 2)
            self.assertEqual([1, 3],
                             [event["value"] & 0xffffffff for event in writes[:2]])
            self.assertNotEqual(writes[0]["event_id"], writes[1]["event_id"])
            self.assertNotEqual(writes[0]["version"], writes[1]["version"])
            self.assertNotEqual(writes[0]["transaction"], writes[1]["transaction"])
            self.assertFalse(any(event.get("kind") == "reset_barrier"
                                 for event in trace.events))

            a_writes = [event for event in trace.events
                        if event.get("kind") == "mmio_delivery"
                        and event.get("device_id") == "gpio_a"
                        and event.get("offset") == 0x14 and event.get("write")]
            self.assertGreaterEqual(len(a_writes), 3)
            self.assertEqual([1, 0, 3],
                             [event["write_value"] for event in a_writes[:3]])
            b_irq_setup = [event for event in trace.events
                           if event.get("kind") == "mmio_delivery"
                           and event.get("device_id") == "gpio_b"
                           and event.get("write")
                           and event.get("offset") in (0x04, 0x2c)]
            self.assertEqual([0x04, 0x2c],
                             [event["offset"] for event in b_irq_setup[:2]])
            self.assertTrue(all(event["write_value"] & 1
                                for event in b_irq_setup[:2]))
            self.assertLess(b_irq_setup[1]["event_id"], a_writes[0]["event_id"])
            b_reads = [event for event in trace.events
                       if event.get("kind") == "mmio_delivery"
                       and event.get("device_id") == "gpio_b"
                       and event.get("offset") == 0x10
                       and not event.get("write")]
            self.assertGreaterEqual(len(b_reads), 2)
            self.assertEqual([1, 3],
                             [event["read_value"] & 0xff for event in b_reads[:2]])
            a_to_b = [event for event in trace.events
                      if event.get("kind") == "dataflow_delivery"
                      and event.get("source") == ("gpio_a", "gpio_out")
                      and event.get("target") == ("gpio_b", "gpio_in")]
            for value, read in zip((1, 3), b_reads[:2]):
                self.assertTrue(any(event["value"] == value
                                    and event["event_id"] < read["event_id"]
                                    for event in a_to_b))
            w1c = [event for event in trace.events
                   if event.get("kind") == "mmio_delivery"
                   and event.get("device_id") == "gpio_b"
                   and event.get("offset") == 0 and event.get("write")]
            self.assertGreaterEqual(len(w1c), 2)
            self.assertTrue(all(event["write_value"] & 1 for event in w1c[:2]))

            b_observations = [event for event in trace.events
                              if event.get("component") == "gpio_b"
                              and "outputs" in event]
            for clear in w1c[:2]:
                self.assertTrue(any(event["event_id"] > clear["event_id"]
                                    and event["outputs"].get("irq") == 0
                                    for event in b_observations))

            rises = []
            previous = 0
            for event in trace.events:
                if event.get("component") != "gpio_b" or "outputs" not in event:
                    continue
                level = event["outputs"].get("irq", 0)
                if level and not previous:
                    rises.append(event["event_id"])
                previous = level
            self.assertGreaterEqual(len(rises), 2)
            for round_index in (0, 1):
                self.assertLess(rises[round_index], b_reads[round_index]["event_id"])
                self.assertLess(b_reads[round_index]["event_id"],
                                writes[round_index]["event_id"])
                self.assertLess(writes[round_index]["event_id"],
                                w1c[round_index]["event_id"])
            self.assertLess(w1c[0]["event_id"], rises[1])
            self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                                and event.get("source") == ("gpio_b", "irq")
                                and event.get("target") == ("cpu", "irq")
                                and event.get("value") == 1
                                for event in trace.events))
            self.assertTrue(any(event.get("component") == "cpu"
                                and event.get("inputs", {}).get("irq") == 1
                                for event in trace.events))

            consumed = [event["outputs"] for event in trace.events
                        if event.get("component") == "cpu"
                        and event.get("outputs", {}).get("response_consumed") == 1]
            for delivery in b_reads[:2]:
                source = delivery["source_transaction"]
                self.assertTrue(any(
                    output["response_source_sequence"] == source["source_sequence"]
                    and output["response_source_epoch"] == source["source_epoch"]
                    and output["response_rdata"] == delivery["read_value"]
                    for output in consumed))
            self.assertTrue(any(event.get("kind") == "state_dependency"
                                and event.get("edge_kind") == "WAW"
                                for event in trace.events))

            replay = replay_evidence_bundle(bundle, make_cva6_two_gpio_runner)
            self.assertTrue(replay.matches, replay.first_difference)
            self.assertEqual("full", replay.verification_scope)


if __name__ == "__main__":
    unittest.main()
