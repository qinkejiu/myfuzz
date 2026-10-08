"""CVA6 two GPIO campaign fixtures, source trust, and search accounting."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.scenario_campaign import (
    CampaignConfig, IbexTwoGpioBoundProvider, _assess_closed_chain,
    _campaign_input_stability, _campaign_source_identity, _snapshot_campaign_inputs,
    campaign_matrix,
)
from myfuzz.integration.cva6_scenario_campaign import Cva6TwoGpioBoundProvider
from myfuzz.scenario.feedback import observed_targets
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.scheduler import DependencyScheduler


ROOT = Path(__file__).resolve().parents[2]
BOUND = ROOT / "configs/scenario/cva6_cpu_two_gpio_campaign_seed.json"
BASELINE = ROOT / "configs/scenario/cva6_two_gpio_campaign_baseline.json"


class Cva6CampaignTests(unittest.TestCase):
    def test_matrix_and_source_identity_include_cva6_provider(self):
        config = CampaignConfig(BOUND, BASELINE)
        self.assertEqual(18, len(campaign_matrix(config)))
        identity = _campaign_source_identity(config)
        name = "src/myfuzz/integration/cva6_scenario_campaign.py"
        self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                         identity[name])

    def test_indirect_reverse_and_baseline_seeds_are_in_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            bound = directory / BOUND.name
            bound.write_bytes(BOUND.read_bytes())
            reverse = directory / "cva6_external_two_gpio_campaign_seed.json"
            reverse.write_bytes((ROOT / "configs/scenario" / reverse.name).read_bytes())
            baseline_seed = directory / "cva6_independent_gpio_reverse_campaign_seed.json"
            baseline_seed.write_text("first\n")
            baseline = directory / BASELINE.name
            baseline.write_text(json.dumps({
                "cpu_seed": bound.name, "reverse_seed": baseline_seed.name}))
            config = CampaignConfig(bound, baseline)
            output = directory / "snapshot"
            first = _snapshot_campaign_inputs(config, output, Cva6TwoGpioBoundProvider())
            self.assertTrue(_campaign_input_stability(first, output)["originals_stable"])
            reverse.write_bytes(reverse.read_bytes() + b" ")
            second = _campaign_input_stability(first, output)
            self.assertFalse(second["originals_stable"])
            baseline_seed.write_text("second\n")
            third = _campaign_input_stability(first, output)
            self.assertNotEqual(second, third)
            self.assertTrue(third["snapshots_stable"])
            self.assertIn(reverse.name, {row["relative_path"] for row in first["bound"]["files"]})
            self.assertIn(baseline_seed.name, {row["relative_path"] for row in first["independent"]["files"]})

    def test_indirect_seed_path_cannot_escape_manifest_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            bound = directory / BOUND.name
            bound.write_bytes(BOUND.read_bytes())
            baseline = directory / BASELINE.name
            baseline.write_text(json.dumps({
                "cpu_seed": "../outside.json", "reverse_seed": "reverse.json"}))
            snapshot = _snapshot_campaign_inputs(
                CampaignConfig(bound, baseline), directory / "snapshot",
                Cva6TwoGpioBoundProvider())
            self.assertIn("seed path", snapshot["independent"]["closure_error"])
            baseline.write_text(json.dumps({
                "cpu_seed": "outside_alias.json", "reverse_seed": "reverse.json"}))
            outside = directory.parent / (directory.name + "-outside.json")
            outside.write_text("outside\n")
            try:
                (directory / "outside_alias.json").symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "escapes manifest directory"):
                    _snapshot_campaign_inputs(
                        CampaignConfig(bound, baseline), directory / "snapshot2",
                        Cva6TwoGpioBoundProvider())
            finally:
                outside.unlink(missing_ok=True)

    def test_ibex_default_checker_hook_preserves_existing_behavior(self):
        provider = IbexTwoGpioBoundProvider()
        self.assertEqual(
            _assess_closed_chain("CPU_TO_IP_TO_CPU", (), {}),
            provider._assess_trace_chain("CPU_TO_IP_TO_CPU", (), {}))

    def test_bound_sources_are_real_mutable_upstream_sources(self):
        provider = Cva6TwoGpioBoundProvider()
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            with self.subTest(direction=direction):
                factory, decoder, targets, seed = provider._fixture(direction, BOUND)
                self.assertEqual(direction, seed.direction)
                self.assertEqual(1, len(targets))
                self.assertEqual(2, len(decoder.graph.sources))
                self.assertTrue(decoder.trusted_for_search)
                self.assertEqual(decoder.document(),
                                 type(decoder).from_document(decoder.document()).document())
                self.assertEqual({"cpu", "gpio_a", "gpio_b"},
                                 set(factory().sessions))
                paths = decoder.graph.paths_to(targets[0].target_id,
                                               direction=direction)
                self.assertEqual(1, len(paths))
                self.assertEqual(2, len(paths[0].source_ids))
                for index, source_id in enumerate(paths[0].source_ids):
                    source = decoder.graph.sources[source_id]
                    self.assertTrue(decoder._choices(seed, source))
                    record = bytearray(8)
                    record[2] = index
                    record[5] = 1
                    mutated = decoder.decode((bytes(record),))
                    self.assertNotEqual(seed.initial_images + seed.actions,
                                        mutated.initial_images + mutated.actions)

    def test_independent_baseline_uses_three_real_isolated_harnesses(self):
        provider = Cva6TwoGpioBoundProvider()
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            with self.subTest(direction=direction):
                factory, decoder, targets, genome = provider._independent_fixture(
                    direction, BASELINE)
                runner = factory()
                self.assertEqual({"cpu", "gpio_a", "gpio_b"}, set(runner.sessions))
                self.assertEqual((), runner.bindings)
                self.assertTrue(runner.independent_baseline)
                self.assertFalse(any(owner["kind"] == "bound"
                                     for owner in runner.ownership.document()["owners"]))
                self.assertNotIn(runner.sessions["gpio_a"],
                                 [window.target for window in runner.sessions["cpu"].router.windows])
                self.assertNotIn(runner.sessions["gpio_b"],
                                 [window.target for window in runner.sessions["cpu"].router.windows])
                self.assertEqual(direction, genome.direction)
                self.assertTrue(decoder.trusted_for_search)
                self.assertEqual(1, len(targets))

    @unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                         "real CVA6 and OpenTitan RTL are opt-in")
    def test_two_round_checker_accepts_real_chain_and_rejects_cut_irq(self):
        provider = Cva6TwoGpioBoundProvider()
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            with self.subTest(direction=direction):
                factory, _, _, seed = provider._fixture(direction, BOUND)
                runner = factory()
                result = DependencyScheduler().run(runner, seed)
                self.assertEqual("complete", result.status)
                events = tuple(runner.events)
                state = runner.final_state_document()
                report = provider._assess_trace_chain(direction, events, state)
                self.assertTrue(report["complete"], report)
                self.assertEqual(2, report["rounds"])
                cut = tuple(event for event in events
                            if not (event.get("kind") == "dataflow_delivery"
                                    and event.get("source") == ("gpio_b", "irq")
                                    and event.get("target") == ("cpu", "irq")))
                self.assertFalse(provider._assess_trace_chain(
                    direction, cut, state)["complete"])

    @unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                         "real CVA6 and OpenTitan RTL are opt-in")
    def test_mutating_upstream_cpu_or_pin_reaches_real_gpio_a_target(self):
        provider = Cva6TwoGpioBoundProvider()
        for direction, source_id, action_index in (
                ("CPU_TO_IP_TO_CPU", "cpu.isr", 0),
                ("IP_TO_CPU_TO_IP", "b.pin9", 2)):
            with self.subTest(direction=direction):
                factory, decoder, targets, seed = provider._fixture(direction, BOUND)
                baseline = record_scenario(seed, factory)
                self.assertEqual("complete", baseline.status)
                self.assertNotIn(targets[0].target_id,
                                 observed_targets(baseline.events, targets))
                path = decoder.graph.paths_to(targets[0].target_id,
                                              direction=direction)[0]
                record = bytearray(8)
                record[2] = path.source_ids.index(source_id)
                record[4] = action_index
                record[5] = 1
                mutated = decoder.decode((bytes(record),))
                trace = record_scenario(mutated, factory)
                self.assertEqual("complete", trace.status)
                self.assertIn(targets[0].target_id,
                              observed_targets(trace.events, targets))


if __name__ == "__main__":
    unittest.main()
