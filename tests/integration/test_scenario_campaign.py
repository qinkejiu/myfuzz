"""G4 campaign accounting stays honest about missing search evidence."""

from __future__ import annotations

import json
import os
from itertools import count
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.integration.scenario_campaign import (
    CampaignConfig,
    IbexTwoGpioBoundProvider,
    UniformSourceScenarioExecutor,
    ReplayEvidence,
    SearchEvidence,
    _assess_closed_chain,
    _comparison_hint,
    _campaign_budgeted_factory,
    _replay_saved_failure_trace,
    CAMPAIGN_TESTCASE_WALL_TIME_MS,
    _post_seed_real_mutation_batches,
    _post_seed_effective_genotypes,
    _post_seed_completed_causal_chains,
    _search_manifest_status,
    campaign_matrix,
    run_scenario_campaign,
)


class CompleteProvider:
    def __init__(self, *, effective=60.0, seed_status="supported",
                 replay_matches=True):
        self.effective = effective
        self.seed_status = seed_status
        self.replay_matches = replay_matches
        self.searched = []

    def search(self, cell, output, manifest):
        self.searched.append((cell, manifest))
        output.mkdir(parents=True, exist_ok=True)
        (output / "search.json").write_text("{}\n", encoding="utf-8")
        return SearchEvidence(
            status="ok", effective_search_seconds=self.effective,
            seed_status=self.seed_status, testcases=12,
            local_cycles={"cpu": 12, "gpio_a": 8, "gpio_b": 8},
            valid_testcases=3,
            completed_chains=0 if cell.strategy == "independent_drive" else 2,
            coverage_count=2,
            failures={"input_invalid": 1}, saved_corpus_entries=2,
            post_seed_mutation_batches=2,
            applied_source_uses={"source0": 1, "source1": 1},
            post_seed_effective_genotypes=2,
            post_seed_completed_chains=1)

    def replay(self, cell, output, manifest):
        return ReplayEvidence(total_entries=2,
                              matched_entries=2 if self.replay_matches else 1,
                              failure_entries=0, matched_failure_entries=0)


class CampaignTests(unittest.TestCase):
    def test_saved_uncertain_failure_with_finalize_wall_cut_replays_prefix(self):
        from hashlib import sha256
        from myfuzz.scenario.replay import ScenarioTrace

        prefix = [{"event_id": 1, "kind": "harness_failure"}]
        marker = {"event_id": 2, "kind": "budget_exhausted",
                  "limit": "max_wall_time_ms", "phase": "inflight_finalize",
                  "effect_may_have_occurred": True,
                  "prefix_event_count": 1,
                  "prefix_local_ticks": {"gpio": 0},
                  "local_ticks": {"gpio": 0},
                  "status_before_finalize": "uncertain_effect"}
        expected = {"genome_sha256": "genome", "status": "uncertain_effect",
                    "events": prefix + [marker], "local_ticks": {"gpio": 0},
                    "semantic_sha256": "physical-clock-differs",
                    "manifest_sha256": "manifest"}

        class Runner:
            def set_replay_wall_cut(self, steps, phase, **kwargs):
                self.cut = (steps, phase, kwargs)

        def fake_record(genome, factory):
            runner = factory()
            self.assertEqual((0, "inflight_finalize",
                              {"prefix_event_count": 1}), runner.cut)
            return ScenarioTrace("genome", "uncertain_effect",
                                 tuple(prefix + [marker]), {"gpio": 0},
                                 sha256(b"replay").hexdigest(), "manifest")

        with patch("myfuzz.scenario.replay.record_scenario", fake_record):
            self.assertTrue(_replay_saved_failure_trace(object(), Runner,
                                                         expected))

    def test_campaign_budget_is_armed_on_each_fresh_runner(self):
        made = []

        class Runner:
            def set_resource_budget(self, budget):
                self.budget = budget

        def factory():
            runner = Runner()
            made.append(runner)
            return runner

        budgeted = _campaign_budgeted_factory(factory)
        first, second = budgeted(), budgeted()
        self.assertIsNot(first, second)
        self.assertEqual(CAMPAIGN_TESTCASE_WALL_TIME_MS,
                         first.budget.max_wall_time_ms)
        self.assertEqual(first.budget, second.budget)

    def test_completed_chain_requires_post_seed_effective_variant(self):
        receipts = [
            SimpleNamespace(genome_sha256="seed-trace", effective_genome_sha256="seed",
                            status="complete", total_local_ticks=5),
            SimpleNamespace(genome_sha256="same-trace", effective_genome_sha256="seed",
                            status="complete", total_local_ticks=5),
            SimpleNamespace(genome_sha256="variant-trace", effective_genome_sha256="different",
                            status="complete", total_local_ticks=5),
        ]
        checks = [
            {"genome_sha256": "seed-trace", "assessment": {"complete": True}},
            {"genome_sha256": "same-trace", "assessment": {"complete": True}},
            {"genome_sha256": "variant-trace", "assessment": {"complete": False}},
        ]
        self.assertEqual(0, _post_seed_completed_causal_chains(receipts, checks))
        checks[-1]["assessment"]["complete"] = True
        self.assertEqual(1, _post_seed_completed_causal_chains(receipts, checks))

    def test_seed_chain_and_duplicate_effective_genome_fail_bound_gate(self):
        class SeedOnlyChain(CompleteProvider):
            def search(self, cell, output, manifest):
                from dataclasses import replace
                result = super().search(cell, output, manifest)
                if cell.strategy == "independent_drive":
                    return result
                return replace(result, post_seed_effective_genotypes=0,
                               post_seed_completed_chains=0)

        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign",
                provider=SeedOnlyChain())
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("insufficient_effective_genome_diversity"
                            in cell["gate_failures"]
                            and "no_post_seed_causal_chain" in cell["gate_failures"]
                            for cell in report["cells"]
                            if cell["strategy"] != "independent_drive"))

    def test_post_seed_genotypes_ignore_raw_duplicates_and_environment_failure(self):
        receipts = [
            SimpleNamespace(buffer_id=0, status="complete", total_local_ticks=4,
                            effective_genome_sha256="seed"),
            SimpleNamespace(buffer_id=1, status="complete", total_local_ticks=4,
                            effective_genome_sha256="seed"),
            SimpleNamespace(buffer_id=2, status="environment_error", total_local_ticks=4,
                            effective_genome_sha256="variant-a"),
            SimpleNamespace(buffer_id=3, status="complete", total_local_ticks=0,
                            effective_genome_sha256="variant-a"),
            SimpleNamespace(buffer_id=4, status="complete", total_local_ticks=4,
                            effective_genome_sha256="variant-a"),
            SimpleNamespace(buffer_id=5, status="complete", total_local_ticks=4,
                            effective_genome_sha256="variant-a"),
            SimpleNamespace(buffer_id=6, status="dut_violation", total_local_ticks=4,
                            effective_genome_sha256="variant-b"),
        ]
        self.assertEqual({"variant-a", "variant-b"},
                         _post_seed_effective_genotypes(receipts))

    def test_mutation_batch_count_excludes_seed_and_receipts_without_rtl_ticks(self):
        receipts = [
            SimpleNamespace(buffer_id=0, genome_sha256="seed", total_local_ticks=4,
                            applied_sources=()),
            SimpleNamespace(buffer_id=1, genome_sha256=None, total_local_ticks=0,
                            applied_sources=("source0",)),
            SimpleNamespace(buffer_id=2, genome_sha256="bad", total_local_ticks=0,
                            applied_sources=("source0",)),
            SimpleNamespace(buffer_id=3, genome_sha256="a", total_local_ticks=5,
                            applied_sources=("source0",)),
            SimpleNamespace(buffer_id=3, genome_sha256="b", total_local_ticks=5,
                            applied_sources=("source1",)),
            SimpleNamespace(buffer_id=4, genome_sha256="c", total_local_ticks=2,
                            applied_sources=("source1",)),
            SimpleNamespace(buffer_id=5, genome_sha256="same", total_local_ticks=3,
                            applied_sources=()),
        ]
        self.assertEqual(2, _post_seed_real_mutation_batches(receipts))

    def test_bound_cell_rejects_seed_only_or_one_mutation_batch(self):
        class ThinSearch(CompleteProvider):
            def search(self, cell, output, manifest):
                from dataclasses import replace
                result = super().search(cell, output, manifest)
                if cell.strategy == "independent_drive":
                    return result
                return replace(result, testcases=9,
                               post_seed_mutation_batches=1)

        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign", provider=ThinSearch())
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("insufficient_mutation_batches" in cell["gate_failures"]
                            for cell in report["cells"]
                            if cell["strategy"] != "independent_drive"))

    def test_direction_group_requires_each_declared_source_in_real_receipts(self):
        class OneSource(CompleteProvider):
            def search(self, cell, output, manifest):
                from dataclasses import replace
                result = super().search(cell, output, manifest)
                if cell.strategy == "independent_drive":
                    return result
                return replace(result, applied_source_uses={
                    "source0": 8, "source1": 0})

        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign", provider=OneSource())
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("direction_source_not_exercised" in cell["gate_failures"]
                            for cell in report["cells"]
                            if cell["strategy"] != "independent_drive"))

    def config(self):
        return CampaignConfig(bound_manifest=Path("bound.json"),
                              independent_manifest=Path("independent.json"),
                              seconds=60, seeds=(11, 12, 13))

    def test_matrix_has_explicit_strategy_direction_and_seed_groups(self):
        cells = campaign_matrix(self.config())
        self.assertEqual(18, len(cells))
        self.assertEqual(18, len({cell.cell_id for cell in cells}))
        self.assertEqual({"dependency_guided", "uniform_source", "independent_drive"},
                         {cell.strategy for cell in cells})
        self.assertEqual({"CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"},
                         {cell.direction for cell in cells})
        self.assertEqual({11, 12, 13}, {cell.seed for cell in cells})
        self.assertTrue(all(cell.direction_role == "budget_group"
                            for cell in cells if cell.strategy == "independent_drive"))
        self.assertTrue(all(cell.direction_role == "causal_direction"
                            for cell in cells if cell.strategy != "independent_drive"))

    def test_complete_provider_reports_all_cells_and_replay(self):
        provider = CompleteProvider()
        with tempfile.TemporaryDirectory() as directory:
            with patch("myfuzz.integration.scenario_campaign.time.monotonic",
                       side_effect=(value for value in count(0, 60))):
                report = run_scenario_campaign(
                    self.config(), Path(directory) / "campaign", provider=provider)
            saved = json.loads((Path(directory) / "campaign" /
                                "campaign_report.json").read_text())
        self.assertEqual("complete", report["gate_status"])
        self.assertEqual("independent_local_ticks_and_causal_order",
                         report["clock_model"])
        self.assertEqual("host_search_and_replay_wall_seconds",
                         report["cost_clock_model"])
        self.assertEqual(1080.0, report["effective_search_seconds"])
        self.assertEqual(18, len(provider.searched))
        self.assertEqual(18, len(report["cells"]))
        self.assertTrue(all(set(cell["search"]["local_cycles"]) ==
                            {"cpu", "gpio_a", "gpio_b"}
                            for cell in report["cells"]))
        self.assertFalse(any("soc_latency" in cell or "dut_deadlock" in cell
                             for cell in report["cells"]))
        self.assertEqual(18, sum(cell["replay"]["matched_entries"] == 2
                                 for cell in report["cells"]))
        self.assertEqual(report, saved)
        self.assertEqual(64, len(report["campaign_source_identity"][
            "src/myfuzz/integration/scenario_campaign.py"]))
        self.assertEqual(64, len(report["campaign_source_identity"][
            "scenario_host_source_identity_sha256"]))
        self.assertEqual({"independent.json"},
                         {str(manifest) for cell, manifest in provider.searched
                          if cell.strategy == "independent_drive"})

    def test_provider_cannot_claim_unelapsed_effective_search_time(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign",
                provider=CompleteProvider(effective=60))
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("search_time_unsubstantiated" in cell["gate_failures"]
                            for cell in report["cells"]))

    def test_unsupported_global_seed_cannot_complete_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign",
                provider=CompleteProvider(seed_status="upstream_client_unsupported"))
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("deterministic_seed_unsupported" in cell["gate_failures"]
                            for cell in report["cells"]))

    def test_unmeasured_chain_and_uncertain_effect_fail_gate(self):
        class MissingChainEvidence(CompleteProvider):
            def search(self, cell, output, manifest):
                from dataclasses import replace
                evidence = super().search(cell, output, manifest)
                return replace(evidence, completed_chains=None,
                               failures={"uncertain_effect": 1})

        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign",
                provider=MissingChainEvidence())
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("causal_chain_unmeasured" in cell["gate_failures"]
                            and "unresolved_execution_failures" in cell["gate_failures"]
                            for cell in report["cells"]))

    def test_short_search_or_partial_replay_cannot_complete_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(
                self.config(), Path(directory) / "campaign",
                provider=CompleteProvider(effective=59, replay_matches=False))
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all("search_budget_short" in cell["gate_failures"]
                            and "corpus_replay_incomplete" in cell["gate_failures"]
                            for cell in report["cells"]))

    def test_missing_provider_marks_every_cell_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(self.config(), Path(directory) / "campaign")
        self.assertEqual("incomplete", report["gate_status"])
        self.assertEqual(0, report["effective_search_seconds"])
        self.assertTrue(all(cell["status"] == "blocked" for cell in report["cells"]))

    def test_independent_fixture_has_no_cross_component_delivery(self):
        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/independent_gpio_baseline.json")
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            factory, decoder, targets, genome = provider._independent_fixture(
                direction, manifest)
            runner = factory()
            self.assertEqual({"cpu", "gpio_a", "gpio_b"}, set(runner.sessions))
            self.assertEqual((), runner.bindings)
            self.assertFalse(any(owner["kind"] == "bound"
                                 for owner in runner.ownership.document()["owners"]))
            self.assertNotIn(runner.sessions["gpio_a"],
                             [window.target for window in runner.sessions["cpu"].router.windows])
            self.assertNotIn(runner.sessions["gpio_b"],
                             [window.target for window in runner.sessions["cpu"].router.windows])
            self.assertEqual(direction, genome.direction)
            self.assertEqual(1, len(decoder.templates))
            self.assertEqual(1, len(targets))
            self.assertEqual({"BASELINE_GROUPING"},
                             {rule.kind for rules in decoder.graph.rules.values()
                              for rule in rules})
            self.assertEqual(decoder.document(),
                             type(decoder).from_document(decoder.document()).document())

    def test_bound_fixture_has_two_real_mutable_sources_in_each_direction(self):
        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            _, decoder, _, seed = provider._fixture(direction, manifest)
            paths = decoder.graph.paths_to(decoder.templates[0].target_id,
                                           direction=direction)
            self.assertEqual(1, len(paths))
            self.assertEqual(2, len(paths[0].source_ids))
            for index, source_id in enumerate(paths[0].source_ids):
                source = decoder.graph.sources[source_id]
                self.assertTrue(decoder._choices(seed, source), source_id)
                record = bytearray(8)
                record[2] = index
                record[5] = 1
                mutated = decoder.decode((bytes(record),))
                self.assertNotEqual(seed.initial_images + seed.actions,
                                    mutated.initial_images + mutated.actions)

    def test_uniform_selection_is_seeded_and_ignores_coverage(self):
        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        factory, decoder, targets, _ = provider._fixture(
            "CPU_TO_IP_TO_CPU", manifest)
        a = UniformSourceScenarioExecutor(
            run_id="uniform-a", decoder=decoder, factory=factory,
            targets=targets, search_seed=7)
        b = UniformSourceScenarioExecutor(
            run_id="uniform-a", decoder=decoder, factory=factory,
            targets=targets, search_seed=7)
        c = UniformSourceScenarioExecutor(
            run_id="uniform-a", decoder=decoder, factory=factory,
            targets=targets, search_seed=8)
        a._target_hits.add(targets[0].target_id)
        self.assertEqual([x["source"] for x in (a.mutation_hint() for _ in range(20))],
                         [x["source"] for x in (b.mutation_hint() for _ in range(20))])
        self.assertNotEqual([x["source"] for x in (a.mutation_hint() for _ in range(20))],
                            [x["source"] for x in (c.mutation_hint() for _ in range(20))])

    def test_uniform_hint_carries_the_same_completed_feedback_identity(self):
        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        factory, decoder, targets, _ = provider._fixture(
            "CPU_TO_IP_TO_CPU", manifest)
        executor = UniformSourceScenarioExecutor(
            run_id="uniform-provenance", decoder=decoder, factory=factory,
            targets=targets, search_seed=7)
        executor._latest_completed_batch = (SimpleNamespace(
            run_id="uniform-provenance", buffer_id=12, slot=0,
            raw_sha256="a" * 64, genome_sha256="b" * 64,
            path_id="cpu-a-b-cpu", status="complete"),)
        executor._max_completed_buffer_id = 12
        hint = executor.mutation_hint()
        self.assertEqual(12, hint["max_completed_buffer_id"])
        self.assertEqual(12, hint["latest_completed_batch"][0]["buffer_id"])
        self.assertEqual("a" * 64,
                         hint["latest_completed_batch"][0]["raw_sha256"])

    def test_bound_comparison_uses_equal_energy_without_removing_adaptive_core(self):
        adaptive = {"source": 0, "energy": 64}
        self.assertEqual(64, adaptive["energy"])
        self.assertEqual(8, _comparison_hint(adaptive, "dependency_guided")["energy"])
        self.assertEqual(8, _comparison_hint(adaptive, "uniform_source")["energy"])
        self.assertEqual(64, _comparison_hint(adaptive, "independent_drive")["energy"])
        self.assertEqual(64, adaptive["energy"])

    @unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                         "real RTL source propagation is opt-in")
    def test_both_sources_propagate_through_real_rtl_in_each_direction(self):
        from myfuzz.scenario.feedback import observed_targets
        from myfuzz.scenario.replay import record_scenario

        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        observed = {}
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            factory, decoder, targets, seed = provider._fixture(direction, manifest)
            if direction == "CPU_TO_IP_TO_CPU":
                baseline = record_scenario(seed, factory)
                self.assertNotIn(targets[0].target_id,
                                 observed_targets(baseline.events, targets))
            else:
                baseline = record_scenario(seed, factory)
                baseline_a_writes = [event["write_value"]
                                     for event in baseline.events
                                     if event.get("kind") == "mmio_delivery"
                                     and event.get("device_id") == "gpio_a"
                                     and event.get("offset") == 0x14
                                     and event.get("write_value")]
                self.assertEqual([0x100, 0x100], baseline_a_writes)
            path = decoder.graph.paths_to(targets[0].target_id,
                                          direction=direction)[0]
            for index, source_id in enumerate(path.source_ids):
                record = bytearray(8)
                record[2] = index
                record[3] = 0
                record[5] = 1
                trace = record_scenario(decoder.decode((bytes(record),)), factory)
                if direction == "CPU_TO_IP_TO_CPU":
                    observed[source_id] = [event["write_value"] for event in trace.events
                                           if event.get("kind") == "mmio_delivery"
                                           and event.get("device_id") == "gpio_a"
                                           and event.get("offset") == 0x14
                                           and event.get("write_value")]
                    self.assertEqual(source_id == "cpu.isr.vector",
                                     targets[0].target_id in observed_targets(
                                         trace.events, targets))
                else:
                    observed[source_id] = {
                        "injections": [(event["action_id"], event["value"])
                                       for event in trace.events
                                       if event.get("kind") == "source_injection"],
                        "a_writes": [event["write_value"] for event in trace.events
                                     if event.get("kind") == "mmio_delivery"
                                     and event.get("device_id") == "gpio_a"
                                     and event.get("offset") == 0x14
                                     and event.get("write_value")],
                        "irq_taken": sum(event.get("component") == "cpu"
                                         and event.get("outputs", {}).get(
                                             "irq_taken_pre") == 1
                                         for event in trace.events),
                    }
        self.assertEqual([1, 3, 3], observed["cpu.isr.vector"])
        self.assertEqual([], observed["cpu.program"])
        self.assertEqual([("first-rise", 0)], observed["b.pin8"]["injections"])
        self.assertEqual([], observed["b.pin8"]["a_writes"])
        self.assertEqual(0, observed["b.pin8"]["irq_taken"])
        self.assertIn(("second-rise", 0x300),
                      observed["b.pin9"]["injections"])
        self.assertEqual([0x100, 0x300], observed["b.pin9"]["a_writes"])
        self.assertEqual(2, observed["b.pin9"]["irq_taken"])

    def test_search_rejects_source_identity_change_inside_cell(self):
        from types import SimpleNamespace

        receipts = [SimpleNamespace(manifest_sha256="first"),
                    SimpleNamespace(manifest_sha256="second")]
        self.assertEqual("mixed_manifest", _search_manifest_status(receipts))
        self.assertEqual("ok", _search_manifest_status(receipts[:1]))

    @unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                         "real RTL campaign smoke is opt-in")
    def test_independent_reverse_seed_completes_local_source_events(self):
        from myfuzz.scenario.replay import record_scenario

        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/independent_gpio_baseline.json")
        factory, _, _, genome = provider._independent_fixture(
            "IP_TO_CPU_TO_IP", manifest)
        trace = record_scenario(genome, factory)
        self.assertEqual("complete", trace.status)
        self.assertEqual({"first-rise", "second-low", "second-rise"},
                         {event.get("action_id") for event in trace.events
                          if event.get("kind") == "source_injection"})

    def test_real_provider_uses_production_factories_and_fixed_genomes(self):
        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
            factory, decoder, targets, genome = provider._fixture(direction, manifest)
            self.assertTrue(factory.__module__.startswith("myfuzz.scenario."))
            self.assertEqual(direction, genome.direction)
            self.assertEqual(1, len(decoder.templates))
            self.assertEqual(1, len(targets))
            self.assertEqual({"DATA_BINDING"},
                             {rule.kind for rules in decoder.graph.rules.values()
                              for rule in rules})
            self.assertEqual({"cpu", "gpio_a", "gpio_b"},
                             set(factory().sessions))

        _, cpu_decoder, _, _ = provider._fixture("CPU_TO_IP_TO_CPU", manifest)
        cpu_source = cpu_decoder.graph.sources["cpu.program"]
        self.assertEqual((84, 1), (cpu_source.bit_offset, cpu_source.width))
        vector_source = cpu_decoder.graph.sources["cpu.isr.vector"]
        self.assertEqual((117, 1),
                         (vector_source.bit_offset, vector_source.width))
        self.assertEqual("gpio_a.out_3", cpu_decoder.templates[0].target_id)

    def test_chain_assessment_uses_consistent_real_cpu_write_value(self):
        events = ({"kind": "mmio_delivery", "device_id": "gpio_a",
                   "offset": 0x14, "write": True, "write_value": 5},
                  {"kind": "mmio_delivery", "device_id": "gpio_a",
                   "offset": 0x14, "write": True, "write_value": 0},
                  {"kind": "mmio_delivery", "device_id": "gpio_a",
                   "offset": 0x14, "write": True, "write_value": 5})
        with patch("myfuzz.scenario.checker.check_cpu_gpio_closed_chain",
                   return_value={"complete": True, "rounds": 2,
                                 "findings": []}) as checker:
            result = _assess_closed_chain("CPU_TO_IP_TO_CPU", events, {})
        self.assertTrue(result["complete"])
        self.assertEqual(5, result["expected_value"])
        self.assertEqual(5, checker.call_args.kwargs["expected_value"])
        changed = _assess_closed_chain(
            "CPU_TO_IP_TO_CPU", events[:-1] + ({**events[-1], "write_value": 7},),
            {})
        self.assertFalse(changed["complete"])

    @unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                         "real RTL variable-round chain is opt-in")
    def test_mutated_cpu_vector_completes_distinct_real_round_values(self):
        from myfuzz.scenario.scheduler import DependencyScheduler

        provider = IbexTwoGpioBoundProvider()
        manifest = (Path(__file__).resolve().parents[2] /
                    "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        factory, decoder, _, _ = provider._fixture("CPU_TO_IP_TO_CPU", manifest)
        record = bytearray(8)
        record[2] = 0  # Trusted cpu.isr.vector source.
        record[5] = 1  # Bit mutation, not a direct GPIO input override.
        runner = factory()
        result = DependencyScheduler().run(runner, decoder.decode((bytes(record),)))
        self.assertEqual("complete", result.status)
        events = tuple(runner.events)
        final_state = runner.final_state_document()
        writes = [event["write_value"] for event in events
                  if event.get("kind") == "mmio_delivery"
                  and event.get("device_id") == "gpio_a"
                  and event.get("offset") == 0x14
                  and event.get("write_value")]
        self.assertEqual([1, 3, 3], writes)
        assessment = _assess_closed_chain(
            "CPU_TO_IP_TO_CPU", events, final_state)
        self.assertIsNotNone(assessment)
        self.assertTrue(assessment["complete"], assessment)
        self.assertEqual(2, assessment["rounds"])
        self.assertEqual((1, 3), assessment["expected_values"])

        deliveries = [event for event in events
                      if event.get("kind") == "dataflow_delivery"
                      and tuple(event.get("source", ())) == ("gpio_a", "gpio_out")
                      and tuple(event.get("target", ())) == ("gpio_b", "gpio_in")]
        self.assertGreaterEqual(len(deliveries), 2)
        cut = tuple({**event, "producer_event_id": -1}
                    if event in deliveries and event.get("value") == 3 else event
                    for event in events)
        broken = _assess_closed_chain("CPU_TO_IP_TO_CPU", cut, final_state)
        self.assertFalse(broken and broken["complete"])

        responses = [event for event in events
                     if event.get("component") == "cpu"
                     and event.get("outputs", {}).get("data_rsp_consumed") == 1]
        self.assertGreaterEqual(len(responses), 2)
        forged = tuple({**event, "outputs": {
            **event["outputs"], "data_rsp_source_sequence": -1}}
                       if event in responses
                       and event["outputs"].get("data_rsp_rdata") == 3 else event
                       for event in events)
        broken = _assess_closed_chain("CPU_TO_IP_TO_CPU", forged, final_state)
        self.assertFalse(broken and broken["complete"])

    def test_chain_assessment_uses_named_external_injections(self):
        events = ({"event_id": 1, "kind": "source_injection", "component": "gpio_b",
                   "port": "gpio_in", "action_id": "first-rise", "value": 0x100},
                  {"event_id": 2, "kind": "source_injection", "component": "gpio_b",
                   "port": "gpio_in", "action_id": "second-low", "value": 0},
                  {"event_id": 3, "kind": "source_injection", "component": "gpio_b",
                   "port": "gpio_in", "action_id": "second-rise", "value": 0x300})
        with patch("myfuzz.scenario.checker.check_gpio_cpu_gpio_closed_chain",
                   return_value={"complete": False, "rounds": 1,
                                 "findings": ["round_2:missing"]}) as checker:
            result = _assess_closed_chain("IP_TO_CPU_TO_IP", events, {})
        self.assertFalse(result["complete"])
        self.assertEqual((0x100, 0x300), result["expected_values"])
        self.assertEqual((0x100, 0x300), checker.call_args.kwargs["expected_values"])
        self.assertIsNone(_assess_closed_chain("IP_TO_CPU_TO_IP", events[:-1], {}))

    def test_independent_baseline_cannot_claim_causal_chain(self):
        class FalseCausality(CompleteProvider):
            def search(self, cell, output, manifest):
                from dataclasses import replace
                evidence = super().search(cell, output, manifest)
                return replace(evidence, completed_chains=2)

        with tempfile.TemporaryDirectory() as directory:
            report = run_scenario_campaign(self.config(), Path(directory) / "campaign",
                                           provider=FalseCausality())
        self.assertEqual("incomplete", report["gate_status"])
        self.assertTrue(all(cell["status"] == "error"
                            for cell in report["cells"]
                            if cell["strategy"] == "independent_drive"))

    def test_cli_reports_incomplete_without_search_provider(self):
        from scripts.run_scenario_campaign import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bound = root / "bound.json"
            baseline = root / "baseline.json"
            bound.write_text("{}\n", encoding="utf-8")
            baseline.write_text("{}\n", encoding="utf-8")
            output = root / "campaign"
            with patch("builtins.print"):
                exit_code = main(["--manifest", str(bound),
                                  "--baseline-manifest", str(baseline),
                                  "--seconds", "60", "--seed", "7",
                                  "--output", str(output)])
            saved = json.loads((output / "campaign_report.json").read_text())
        self.assertEqual(2, exit_code)
        self.assertEqual("incomplete", saved["gate_status"])
        self.assertEqual({7, 8, 9}, {cell["seed"] for cell in saved["cells"]})


if __name__ == "__main__":
    unittest.main()
