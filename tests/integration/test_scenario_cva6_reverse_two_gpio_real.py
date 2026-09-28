"""Two external GPIO B edges close through real CVA6 and GPIO A RTL."""

from __future__ import annotations

import os
import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.cva6_gpio_example import make_cva6_two_gpio_runner
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, GenomeCodec, MemoryImage, ScenarioGenome, Trigger


ROOT = Path(__file__).resolve().parents[2]
GENOME_PATH = ROOT / "configs/scenario/cva6_external_two_gpio_two_rounds.json"


def _addi(rd, rs1, immediate):
    return ((immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13)


def _sw(rs2, rs1, offset):
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | 2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, rs1, offset):
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _image(words):
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def make_cva6_reverse_two_gpio_genome():
    main = [
        0x400000b7,             # x1 = GPIO B base
        0x10000113,             # x2 = pin 8 mask
        _sw(2, 1, 0x04),        # B.INTR_ENABLE
        _sw(2, 1, 0x2c),        # B.INTR_CTRL_EN_RISING
    ]
    auipc_pc = 0x80000080 + len(main) * 4
    main.extend((
        0x00000297,
        _addi(5, 5, 0x80000100 - auipc_pc),
        0x30529073,             # mtvec = ISR
        0x000012b7,
        _addi(5, 5, -2048),
        0x3042a073,             # mie.MEIE
        _addi(5, 0, 8),
        0x3002a073,             # mstatus.MIE
        0x0000006f,
    ))
    isr = [
        0x400000b7,             # x1 = GPIO B base
        _lw(2, 1, 0x10),        # real B.DATA_IN
        0x40001237,             # x4 = GPIO A base
        _sw(2, 4, 0x14),        # A.DIRECT_OUT = observed B input
    ]
    isr_auipc_pc = 0x80000100 + len(isr) * 4
    isr.extend((
        0x00000197,
        _addi(3, 3, 0x80000200 - isr_auipc_pc),
        _sw(2, 3, 0),           # persistent RAM record
        _addi(5, 0, 0x100),
        _sw(5, 1, 0),           # B.INTR_STATE W1C
    ))
    isr.extend((0x00000013,) * 16)  # let real B IRQ deassert before mret
    isr.append(0x30200073)
    b_w1c = Trigger("AFTER_OUTPUT", "cpu", "addr", (1 << 64) - 1,
                    0x40000000)
    return ScenarioGenome(
        testcase_id="cva6-external-b-cpu-a-two-rounds",
        direction="IP_TO_CPU_TO_IP",
        path_id="external-b-irq-cva6-isr-a-output",
        schedule_order=("cpu", "gpio_b", "gpio_a"), max_steps=3600,
        actions=(
            Action("first-rise", "gpio_b", "gpio_in", 1,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "addr", (1 << 64) - 1,
                           0x4000002c),
                   delay_component="cpu", delay_ticks=100,
                   bit_offset=8, width=24),
            Action("second-low", "gpio_b", "gpio_in", 0,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "addr", (1 << 64) - 1,
                           0x40001014),
                   delay_component="gpio_b", delay_ticks=0,
                   bit_offset=8, width=24),
            Action("second-rise", "gpio_b", "gpio_in", 3,
                   "IP_TO_CPU_TO_IP", b_w1c,
                   delay_component="gpio_b", delay_ticks=60,
                   bit_offset=8, width=24)),
        initial_images=(
            MemoryImage("cpu.boot", "cpu", 0x80000000, "6f000008"),
            MemoryImage("cpu.main", "cpu", 0x80000080, _image(main)),
            MemoryImage("cpu.isr", "cpu", 0x80000100, _image(isr)),
            MemoryImage("cpu.result", "cpu", 0x80000200, "00000000"),
        ))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCva6ReverseTwoGpioTests(unittest.TestCase):
    def test_two_real_irq_rounds_reach_cva6_and_gpio_a_then_replay(self):
        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())
        self.assertEqual(make_cva6_reverse_two_gpio_genome(), genome)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(genome, make_cva6_two_gpio_runner,
                                         bundle)
            self.assertEqual("complete", trace.status)
            events = trace.events
            self.assertEqual(("first-rise", "second-low", "second-rise"),
                             tuple(event["action_id"] for event in events
                                   if event.get("kind") == "source_injection"))
            b_steps = [event for event in events
                       if event.get("component") == "gpio_b"
                       and "irq" in event.get("outputs", {})]
            rises = [event for index, event in enumerate(b_steps)
                     if event["outputs"]["irq"] == 1
                     and (index == 0 or b_steps[index - 1]["outputs"]["irq"] == 0)]
            self.assertEqual(2, len(rises))
            self.assertEqual(0, b_steps[-1]["outputs"]["irq"])

            def first(window, predicate):
                matches = [event for event in window if predicate(event)]
                self.assertTrue(matches, window)
                return matches[0]

            extra_isr_reads = 0
            for expected, start, end in ((0x100, rises[0]["event_id"],
                                          rises[1]["event_id"]),
                                         (0x300, rises[1]["event_id"],
                                          len(events) + 1)):
                with self.subTest(expected=hex(expected)):
                    window = [event for event in events
                              if start <= event["event_id"] < end]
                    irq_high = first(window, lambda event:
                                     event.get("kind") == "dataflow_delivery"
                                     and event.get("source") == ("gpio_b", "irq")
                                     and event.get("target") == ("cpu", "irq")
                                     and event.get("value") == 1)
                    cpu_irq_high = first(window, lambda event:
                                         event["event_id"] > irq_high["event_id"]
                                         and event.get("component") == "cpu"
                                         and event.get("inputs", {}).get("irq", 0) & 1)
                    reads = [event for event in window
                             if event.get("kind") == "mmio_delivery"
                             and event.get("device_id") == "gpio_b"
                             and event.get("offset") == 0x10
                             and not event.get("write")]
                    extra_isr_reads += max(0, len(reads) - 1)
                    read = first(reads, lambda event:
                                 event["read_value"] & 0xffffffff == expected)
                    self.assertEqual(expected, read["read_value"] & 0xffffffff)
                    response = first(window, lambda event:
                                     event.get("component") == "cpu"
                                     and event.get("outputs", {}).get(
                                         "response_consumed") == 1
                                     and event["outputs"].get(
                                         "response_source_sequence") ==
                                     read["source_sequence"]
                                     and event["outputs"].get(
                                         "response_source_epoch") ==
                                     read["source_transaction"]["source_epoch"])
                    self.assertEqual(read["read_value"],
                                     response["outputs"]["response_rdata"])
                    a_writes = [event for event in window
                                if event.get("kind") == "mmio_delivery"
                                and event.get("device_id") == "gpio_a"
                                and event.get("offset") == 0x14
                                and event.get("write")]
                    self.assertEqual(1, len(a_writes), a_writes)
                    a_write = first(a_writes, lambda event:
                                    event["event_id"] > response["event_id"]
                                    and event["write_value"] & 0xffffffff
                                    == expected)
                    self.assertEqual(expected,
                                     a_write["write_value"] & 0xffffffff)
                    a_output = next(event for event in window
                                    if event["event_id"] > a_write["event_id"]
                                    and event.get("component") == "gpio_a"
                                    and event.get("outputs", {}).get(
                                        "gpio_out") == expected)
                    ram_writes = [event for event in window
                                  if event.get("kind") == "memory_write"
                                  and event.get("component") == "cpu"
                                  and event.get("address") == 0x80000200]
                    self.assertEqual(1, len(ram_writes), ram_writes)
                    ram = first(ram_writes, lambda event:
                                event["event_id"] > a_write["event_id"]
                                and event["value"] & 0xffffffff == expected)
                    self.assertEqual(expected, ram["value"] & 0xffffffff)
                    w1c_writes = [event for event in window
                                  if event.get("kind") == "mmio_delivery"
                                  and event.get("device_id") == "gpio_b"
                                  and event.get("offset") == 0
                                  and event.get("write")]
                    self.assertEqual(1, len(w1c_writes), w1c_writes)
                    w1c = first(w1c_writes, lambda event:
                                event["event_id"] > ram["event_id"])
                    self.assertEqual(0x100, w1c["write_value"] & 0xffffffff)
                    irq_low = first(window, lambda event:
                                    event["event_id"] > w1c["event_id"]
                                    and event.get("kind") == "dataflow_delivery"
                                    and event.get("source") == ("gpio_b", "irq")
                                    and event.get("target") == ("cpu", "irq")
                                    and event.get("value") == 0)
                    cpu_irq_low = first(window, lambda event:
                                        event["event_id"] > irq_low["event_id"]
                                        and event.get("component") == "cpu"
                                        and event.get("inputs", {}).get("irq", 0) & 1
                                        == 0)
                    self.assertLess(start, irq_high["event_id"])
                    self.assertLess(irq_high["event_id"], cpu_irq_high["event_id"])
                    self.assertLess(cpu_irq_high["event_id"], read["event_id"])
                    self.assertLess(start, read["event_id"])
                    self.assertLess(read["event_id"], response["event_id"])
                    self.assertLess(response["event_id"], a_write["event_id"])
                    self.assertLess(a_write["event_id"], a_output["event_id"])
                    self.assertLess(a_write["event_id"], ram["event_id"])
                    self.assertLess(ram["event_id"], w1c["event_id"])
                    self.assertLess(w1c["event_id"], irq_low["event_id"])
                    self.assertLess(irq_low["event_id"], cpu_irq_low["event_id"])
            self.assertEqual(0, extra_isr_reads,
                             f"extra CVA6 ISR B reads: {extra_isr_reads}")
            self.assertFalse(any(event.get("kind") == "reset_barrier"
                                 for event in events))
            final_state = json.loads((bundle / "final_state.json").read_text())
            self.assertTrue(all(value == 0 for value in
                                final_state["pending_responses"].values()))
            replay = replay_evidence_bundle(bundle, make_cva6_two_gpio_runner)
            self.assertTrue(replay.matches, replay)
            self.assertEqual("full", replay.verification_scope)


if __name__ == "__main__":
    unittest.main()
