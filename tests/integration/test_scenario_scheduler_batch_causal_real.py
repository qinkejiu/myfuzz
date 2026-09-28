"""Real causal Genome: a batch observes and releases triggers after each step."""

from __future__ import annotations

import hashlib
import os
import unittest

from myfuzz.scenario.genome import (Action, ChunkAssembler, GenomeCodec,
                                    MemoryImage, ScenarioGenome, Trigger)
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler


def _case():
    memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                              initialization_seed=41,
                              max_initialized_bytes=0x20000)
    main = (0x400000b7, 0x00100113, 0x0020a223, 0x0220a623,
            0x000102b7, 0x10028293, 0x30529073, 0x000012b7,
            0x80028293, 0x3042a073, 0x00800293, 0x3002a073,
            0x0000006f)
    isr = (0x400000b7, 0x0100a103, 0x20202023,
           0x00100193, 0x0030a023, 0x30200073)
    gpio = OpenTitanGpioSession()
    cpu = IbexCpuSession(memory=memory,
                         router=DataflowRouter((DeviceWindow(
                             "gpio_b", 0x40000000, 0x1000, gpio),)))
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio_b", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_pins")))
    runner = ScenarioRunner(
        sessions={"cpu": cpu, "gpio_b": gpio}, ownership=ownership,
        bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
    image = lambda words: b"".join(x.to_bytes(4, "little") for x in words).hex()
    genome = ScenarioGenome(
        testcase_id="scheduler-causal-batch", direction="IP_TO_CPU_TO_IP",
        path_id="gpio-irq-cpu-ack", schedule_order=("cpu", "gpio_b"),
        max_steps=1200,
        initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10080, image(main)),
            MemoryImage("cpu.isr", "cpu", 0x10100, image(isr)),
            MemoryImage("cpu.isr.second", "cpu", 0x1012c, image(isr))),
        actions=(
            Action("initial-low", "gpio_b", "gpio_in", 0x5a,
                   "IP_TO_CPU_TO_IP", Trigger("START")),
            Action("first-rise", "gpio_b", "gpio_in", 0x5b,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 2),
                   delay_component="gpio_b", delay_ticks=4),
            Action("second-low", "gpio_b", "gpio_in", 0x58,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 4),
                   delay_component="gpio_b", delay_ticks=4),
            Action("second-rise", "gpio_b", "gpio_in", 0x59,
                   "IP_TO_CPU_TO_IP",
                   Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 4),
                   delay_component="gpio_b", delay_ticks=16)))
    return runner, genome


def _assemble(raw, sizes):
    chunks = ChunkAssembler(len(raw), hashlib.sha256(raw).hexdigest())
    offset = index = 0
    while offset < len(raw):
        size = min(sizes[index % len(sizes)], len(raw) - offset)
        chunks.accept(offset, raw[offset:offset + size])
        offset += size
        index += 1
    return chunks.finish()


def _run(genome, batch_sizes=None):
    runner, _ = _case()
    batch_calls = []
    if batch_sizes is not None:
        original_batch = runner.step_batch

        def recorded_batch(schedule, *, on_step=None):
            before = sum(event.get("kind") == "source_injection"
                         for event in runner.events)
            outputs = original_batch(schedule, on_step=on_step)
            after = sum(event.get("kind") == "source_injection"
                        for event in runner.events)
            batch_calls.append((schedule, before, after))
            return outputs

        runner.step_batch = recorded_batch
    result = DependencyScheduler().run(runner, genome, batch_sizes=batch_sizes)
    return (result, runner.events, dict(runner.local_ticks),
            runner.final_state_document(), tuple(batch_calls))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealSchedulerBatchCausalTests(unittest.TestCase):
    def test_triggered_gpio_irq_cpu_ack_matches_after_causal_batching(self):
        _, genome = _case()
        self.assertEqual((), genome.reset_actions)
        raw = GenomeCodec.encode(genome)
        baseline = _run(_assemble(raw, (len(raw),)))
        self.assertEqual("complete", baseline[0].status)
        self.assertEqual(tuple(action.action_id for action in genome.actions),
                         baseline[0].fired_actions)
        self.assertGreaterEqual(sum(event.get("kind") == "mmio_delivery"
                                    for event in baseline[1]), 6)
        self.assertGreaterEqual(sum(event.get("kind") == "memory_write"
                                    for event in baseline[1]), 2)
        self.assertTrue(any(event.get("component") == "cpu"
                            and event.get("outputs", {}).get("data_rsp_consumed") == 1
                            for event in baseline[1]))
        self.assertTrue(any(event.get("component") == "gpio_b"
                            and event.get("outputs", {}).get("irq") == 1
                            for event in baseline[1]))
        self.assertTrue(any(event.get("component") == "cpu"
                            and event.get("inputs", {}).get("irq") == 1
                            for event in baseline[1]))
        self.assertTrue(all(count == 0 for count in baseline[3][
            "pending_responses"].values()))
        for chunks, batches in (((1,), (genome.max_steps,)),
                                ((7, 1, 29, 2, 13), (2, 5, 1, 11))):
            with self.subTest(chunks=chunks, batches=batches):
                assembled = _assemble(raw, chunks)
                self.assertEqual(genome, assembled)
                actual = _run(assembled, batches)
                self.assertTrue(any(len(schedule) > 1 and after > before
                                    for schedule, before, after in actual[4]))
                self.assertEqual(baseline[:4], actual[:4])


if __name__ == "__main__":
    unittest.main()
