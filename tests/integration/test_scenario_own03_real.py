"""OWN-03 mutation write-set boundary with real Ibex and GPIO observations."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import unittest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import Action, GenomeCodec, Trigger
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.replay import record_scenario


ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "configs/scenario"


def _with_post_store_ram_load(genome):
    """Use an ISR NOP slot for a real CPU load of its earlier RAM Store."""
    images = []
    for image in genome.initial_images:
        if image.image_id not in ("cpu.isr", "cpu.isr.vector"):
            images.append(image)
            continue
        data = bytearray(image.data)
        assert data[28:32] == b"\x13\x00\x00\x00"
        data[28:32] = (0x20002303).to_bytes(4, "little")  # lw x6,0x200(x0)
        images.append(replace(image, data_hex=data.hex()))
    return replace(genome, initial_images=tuple(images))


def _plan(source: FuzzableSource) -> tuple[DependencyGraph, object]:
    graph = DependencyGraph(
        sources=(source,),
        rules=(DependencyRule("observed", (source.source_id,), "DATA_BINDING"),))
    return graph, choose_mutation(graph, {"observed": 1},
                                  direction="CPU_TO_IP_TO_CPU")


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class Own03RealMutationBoundaryTests(unittest.TestCase):
    def test_operator_rejects_observed_non_sources_and_new_program_changes_rtl(self):
        baseline = _with_post_store_ram_load(GenomeCodec.decode((
            CONFIGS / "ibex_two_gpio_closed_two_rounds.json").read_bytes()))
        expected_variant = _with_post_store_ram_load(GenomeCodec.decode((
            CONFIGS / "ibex_two_gpio_closed_two_rounds_variant.json").read_bytes()))
        original_runner = make_ibex_two_gpio_runner()
        self.assertTrue(all(session._process is None
                            for session in original_runner.sessions.values()))

        attempts = (
            ("gpio_b", "gpio_in", "bound"),
            ("gpio_a", "gpio_out", "undeclared input"),
            ("cpu", "data_rsp_rdata", "undeclared input"),
        )
        for component, port, expected_error in attempts:
            with self.subTest(component=component, port=port):
                graph, plan = _plan(FuzzableSource(
                    "attempt", component, port, 0, 1,
                    ("CPU_TO_IP_TO_CPU",)))
                attempted_genome = replace(
                    baseline,
                    actions=(Action("write-observed", component, port, 0,
                                    baseline.direction, Trigger("START"),
                                    width=1),))
                with self.assertRaisesRegex(ValueError, expected_error):
                    mutate_genome(attempted_genome, plan, graph,
                                  original_runner.ownership, bit_index=0)
        self.assertTrue(all(session._process is None
                            for session in original_runner.sessions.values()))

        original_trace = record_scenario(baseline, lambda: original_runner)
        self.assertEqual("complete", original_trace.status)
        self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                            and event.get("source") == ("gpio_a", "gpio_out")
                            and event.get("target") == ("gpio_b", "gpio_in")
                            for event in original_trace.events))
        self.assertTrue(any(event.get("component") == "gpio_a"
                            and "gpio_out" in event.get("outputs", {})
                            for event in original_trace.events))
        self.assertTrue(any(event.get("component") == "cpu"
                            and event.get("outputs", {}).get("data_rsp_consumed") == 1
                            and "data_rsp_rdata" in event["outputs"]
                            for event in original_trace.events))
        original_events = deepcopy(original_runner.events)
        original_memory = original_runner.sessions["cpu"].memory
        original_state = original_memory.state_summary()
        ram_reads = [event for event in original_events
                     if event.get("kind") == "memory_read"
                     and event.get("component") == "cpu"
                     and event.get("address") == 0x200]
        self.assertTrue(ram_reads, "real CPU must load the committed RAM value")
        first_ram_read = ram_reads[0]
        frozen_snapshot = original_runner.sessions["cpu"].service.read(
            TransactionKey(**first_ram_read["transaction"]), 0x200,
            width_bytes=first_ram_read["width_bytes"])
        self.assertEqual(1, frozen_snapshot.value)
        self.assertEqual(first_ram_read["value"], frozen_snapshot.value)
        frozen_response = next(event for event in original_events
                               if event.get("component") == "cpu"
                               and event.get("outputs", {}).get(
                                   "data_rsp_consumed") == 1
                               and event["outputs"].get(
                                   "data_rsp_source_sequence") ==
                               first_ram_read["transaction"]["source_sequence"])
        self.assertEqual(frozen_snapshot.value,
                         frozen_response["outputs"]["data_rsp_rdata"])
        gpio_history = tuple(event for event in original_events
                             if event.get("component") == "gpio_a"
                             and "gpio_out" in event.get("outputs", {}))
        self.assertTrue(gpio_history)

        changed = baseline
        for image_id, byte_index in (("cpu.main", 10), ("cpu.isr", 14),
                                     ("cpu.isr.vector", 14)):
            graph, plan = _plan(FuzzableSource(
                f"program:{image_id}", "cpu", image_id,
                byte_index * 8 + 5, 1, ("CPU_TO_IP_TO_CPU",),
                kind="memory_image"))
            changed = mutate_genome(changed, plan, graph,
                                    original_runner.ownership, bit_index=0)
        self.assertEqual(expected_variant.initial_images, changed.initial_images)
        changed = replace(changed, testcase_id=expected_variant.testcase_id)
        self.assertEqual(original_state, original_memory.state_summary())
        self.assertEqual(original_events, original_runner.events)
        self.assertEqual(gpio_history, tuple(event for event in original_runner.events
                             if event.get("component") == "gpio_a"
                             and "gpio_out" in event.get("outputs", {})))
        self.assertEqual(first_ram_read["value"], frozen_snapshot.value)
        self.assertIn(frozen_response, original_runner.events)

        changed_runner = make_ibex_two_gpio_runner()
        changed_trace = record_scenario(changed, lambda: changed_runner)
        self.assertEqual("complete", changed_trace.status)
        self.assertIsNot(original_runner, changed_runner)
        self.assertIsNot(original_memory, changed_runner.sessions["cpu"].memory)
        self.assertEqual(original_state, original_memory.state_summary())
        self.assertEqual(original_events, original_runner.events)
        self.assertEqual(gpio_history, tuple(event for event in original_runner.events
                             if event.get("component") == "gpio_a"
                             and "gpio_out" in event.get("outputs", {})))
        self.assertEqual(first_ram_read["value"], frozen_snapshot.value)
        self.assertIn(frozen_response, original_runner.events)

        def first_a_write(trace):
            return next(event["write_value"] for event in trace.events
                        if event.get("kind") == "mmio_delivery"
                        and event.get("device_id") == "gpio_a"
                        and event.get("offset") == 0x14 and event.get("write"))

        def ram_writes(trace):
            return [event["value"] for event in trace.events
                    if event.get("kind") == "memory_write"
                    and event.get("component") == "cpu"
                    and event.get("address") == 0x200]

        self.assertEqual((1, 3), (first_a_write(original_trace),
                                  first_a_write(changed_trace)))
        self.assertGreaterEqual(len(ram_writes(original_trace)), 2)
        self.assertGreaterEqual(len(ram_writes(changed_trace)), 2)
        self.assertEqual((1, 3), (ram_writes(original_trace)[-1],
                                  ram_writes(changed_trace)[-1]))
        old_ram = original_memory.read(0x200, 4,
                                       transaction_id="old-testcase-final")
        new_ram = changed_runner.sessions["cpu"].memory.read(
            0x200, 4, transaction_id="new-testcase-final")
        self.assertEqual((1, 3), (old_ram.value, new_ram.value))
        self.assertNotEqual(old_ram.writer_event_ids,
                            new_ram.writer_event_ids)
        self.assertEqual(1, frozen_snapshot.value)
        self.assertEqual(1, frozen_response["outputs"]["data_rsp_rdata"])
        self.assertNotEqual(original_trace.semantic_sha256,
                            changed_trace.semantic_sha256)


if __name__ == "__main__":
    unittest.main()
