"""Complete Genome chunking and batch boundaries preserve one real IRQ trace.

RFuzz records decode before RTL starts. ChunkAssembler assembles a complete
Genome before execution; this test does not model online streaming into RTL.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import unittest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import ChunkAssembler, GenomeCodec
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder


ROOT = Path(__file__).resolve().parents[2]
GENOME_PATH = ROOT / "configs/scenario/ibex_two_gpio_closed_two_rounds.json"


def _rfuzz_decoded_genome():
    template = GenomeCodec.decode(GENOME_PATH.read_bytes())
    graph = DependencyGraph(
        sources=(FuzzableSource("cpu.main", "cpu", "cpu.main", 0, 32,
                                (template.direction,), kind="memory_image"),),
        rules=(DependencyRule("gpio_b.irq", ("cpu.main",),
                              "PERSISTENT_STATE_RULE"),))
    decoder = GenomeRecordDecoder(
        graph=graph, ownership=make_ibex_two_gpio_runner().ownership,
        templates=(DecoderTemplate("gpio_b.irq", template),))
    decoded = decoder.decode((bytes(8),))
    assert decoded.initial_images == template.initial_images
    assert decoded.schedule_order == template.schedule_order
    assert decoded.max_steps == template.max_steps
    return decoded


def _assemble(raw: bytes, sizes: tuple[int, ...]):
    assembly = ChunkAssembler(len(raw), hashlib.sha256(raw).hexdigest())
    offset = index = 0
    while offset < len(raw):
        size = min(sizes[index % len(sizes)], len(raw) - offset)
        assembly.accept(offset, raw[offset:offset + size])
        offset += size
        index += 1
    return assembly.finish()


def _run(genome, batch_sizes: tuple[int, ...] | None):
    if genome.actions or genome.reset_actions:
        raise ValueError("manual batch schedule requires no actions or resets")
    runner = make_ibex_two_gpio_runner()
    for image in genome.initial_images:
        runner.preload_image(image)
    runner.begin_test(genome.testcase_id)
    try:
        schedule = tuple(genome.schedule_order[index % len(genome.schedule_order)]
                         for index in range(genome.max_steps))
        if batch_sizes is None:
            for component in schedule:
                runner.step(component)
        else:
            offset = index = 0
            while offset < len(schedule):
                size = min(batch_sizes[index % len(batch_sizes)],
                           len(schedule) - offset)
                runner.step_batch(schedule[offset:offset + size])
                offset += size
                index += 1
        quiesce = runner.quiesce(genome.quiesce_steps)
        return (quiesce.status, runner.events, dict(runner.local_ticks),
                runner.final_state_document())
    finally:
        runner.finalize()


def _irq_and_response_observations(events):
    source = tuple((event["local_tick"], event["outputs"]["irq"])
                   for event in events if event.get("component") == "gpio_b"
                   and "outputs" in event)
    cpu_irq = tuple((event["local_tick"], event["inputs"].get("irq", 0))
                    for event in events if event.get("component") == "cpu"
                    and "inputs" in event)
    responses = tuple((event["local_tick"],
                       event["outputs"]["data_rsp_source_epoch"],
                       event["outputs"]["data_rsp_source_sequence"],
                       event["outputs"]["data_rsp_rdata"])
                      for event in events if event.get("component") == "cpu"
                      and event.get("outputs", {}).get("data_rsp_consumed") == 1)
    return source, cpu_irq, responses


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealIrqChunkBatchEquivalenceTests(unittest.TestCase):
    def test_complete_chunks_and_step_batches_keep_real_irq_and_receipts(self):
        decoded = _rfuzz_decoded_genome()
        self.assertEqual((), decoded.actions)
        self.assertEqual((), decoded.reset_actions)
        raw = GenomeCodec.encode(decoded)
        baseline = _run(_assemble(raw, (len(raw),)), None)
        self.assertEqual("drained", baseline[0])
        source, cpu_irq, responses = _irq_and_response_observations(baseline[1])
        source_levels = [level for _, level in source]
        self.assertGreaterEqual(sum(level == 1 and
                                    (index == 0 or source_levels[index - 1] == 0)
                                    for index, level in enumerate(source_levels)), 2)
        self.assertEqual(0, source_levels[-1])
        self.assertTrue(any(level == 1 for _, level in cpu_irq))
        self.assertEqual(0, cpu_irq[-1][1])
        self.assertTrue(responses)
        self.assertGreaterEqual(sum(event.get("kind") == "mmio_delivery"
                                    and event.get("device_id") == "gpio_b"
                                    and event.get("offset") == 0
                                    and event.get("write")
                                    for event in baseline[1]), 2)
        self.assertTrue(all(count == 0 for count in baseline[3][
            "pending_responses"].values()))

        for name, chunks, batches in (
                ("one_byte_full_batch", (1,), (decoded.max_steps,)),
                ("fixed_chunks_fixed_batches", (31,), (7,)),
                ("irregular_chunks_irregular_batches", (7, 1, 29, 2, 13),
                 (2, 5, 1, 11))):
            with self.subTest(name=name):
                assembled = _assemble(raw, chunks)
                self.assertEqual(decoded, assembled)
                actual = _run(assembled, batches)
                self.assertEqual(baseline, actual)
                self.assertEqual((source, cpu_irq, responses),
                                 _irq_and_response_observations(actual[1]))


if __name__ == "__main__":
    unittest.main()
