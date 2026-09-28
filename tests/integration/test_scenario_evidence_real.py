"""A disk bundle replays a fresh real OpenTitan GPIO process."""

import json
import os
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import (_evidence_base_bytes, _factory_identity,
                                      replay_evidence_bundle, save_evidence_bundle)
from myfuzz.scenario.edge_experiments import (make_cut_a_to_b_runner,
                                              make_fixed_b_input_runner)
from myfuzz.scenario.examples import (make_ibex_two_gpio_runner,
                                      make_opentitan_gpio_runner)
from myfuzz.scenario.genome import Action, GenomeCodec, ScenarioGenome, Trigger
from myfuzz.scenario.ip_cpu_ip_example import make_external_gpio_ibex_gpio_runner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealEvidenceBundleTests(unittest.TestCase):
    def test_real_ibex_mmio_reserves_gpio_local_ticks_before_step(self):
        genome = GenomeCodec.decode((Path("configs/scenario") /
                                     "ibex_two_gpio_multiround.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "gpio-local-cycle-cap"
            trace = save_evidence_bundle(
                genome, make_ibex_two_gpio_runner, bundle,
                budget=ResourceBudget(max_local_cycles_per_component=100,
                                      max_materialized_bytes_per_memory=131072))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_local_cycles_per_component",
                             trace.events[-1]["limit"])
            self.assertEqual("before_step", trace.events[-1]["phase"])
            self.assertLessEqual(max(trace.local_ticks.values()), 100)
            self.assertGreater(sum(event.get("kind") == "mmio_delivery"
                                   for event in trace.events), 0)
            replay = replay_evidence_bundle(bundle, make_ibex_two_gpio_runner)
            self.assertTrue(replay.matches)
            self.assertEqual("full", replay.verification_scope)

    def test_real_ibex_transaction_cap_stops_before_another_obi_commit(self):
        genome = GenomeCodec.decode((Path("configs/scenario") /
                                     "ibex_two_gpio_multiround.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "transaction-cap"
            trace = save_evidence_bundle(
                genome, make_ibex_two_gpio_runner, bundle,
                budget=ResourceBudget(max_transactions=2,
                                      max_materialized_bytes_per_memory=131072))
            commits = [event for event in trace.events
                       if event.get("kind") in (
                           "memory_read", "memory_write", "mmio_delivery")]
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_transactions", trace.events[-1]["limit"])
            self.assertGreaterEqual(len(commits), 1)
            self.assertLessEqual(len(commits), 2)
            replay = replay_evidence_bundle(bundle, make_ibex_two_gpio_runner)
            self.assertTrue(replay.matches)
            self.assertEqual("full", replay.verification_scope)

    def test_real_gpio_evidence_byte_cap_keeps_observed_output(self):
        genome = ScenarioGenome(
            testcase_id="real-gpio-evidence-cap", direction="IP_TO_CPU",
            path_id="gpio-evidence-cap", schedule_order=("gpio",),
            max_steps=3, actions=())
        sample = make_opentitan_gpio_runner()
        base = _evidence_base_bytes(
            genome, sample.identity_document(),
            _factory_identity(make_opentitan_gpio_runner))
        reserve = 1024 * 1024
        budget = ResourceBudget(
            max_evidence_bytes=reserve + base + 200,
            evidence_termination_reserve_bytes=reserve)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "byte-cap"
            trace = save_evidence_bundle(
                genome, make_opentitan_gpio_runner, bundle,
                budget=budget)
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertTrue(any(e.get("component") == "gpio"
                                and "outputs" in e for e in trace.events))
            self.assertEqual("max_evidence_bytes", trace.events[-1]["limit"])
            self.assertTrue(replay_evidence_bundle(
                bundle, make_opentitan_gpio_runner).matches)

    def test_real_gpio_missing_reply_hits_inflight_deadline_and_replays_prefix(self):
        genome = ScenarioGenome(
            testcase_id="real-gpio-inflight-timeout", direction="IP_TO_CPU",
            path_id="gpio-reply-timeout", schedule_order=("gpio",),
            max_steps=3, actions=())

        def missing_reply_factory():
            runner = make_opentitan_gpio_runner()
            session = runner.sessions["gpio"]
            real_begin = session.begin_case
            real_end = session.end_case
            streams = []

            def begin(case_id):
                real_begin(case_id)
                read_fd, write_fd = os.pipe()
                original = session._process.stdout
                session._process.stdout = os.fdopen(
                    read_fd, "r", encoding="ascii", buffering=1)
                streams.extend((write_fd, original))

            def end():
                real_end()
                if streams:
                    os.close(streams[0])
                    streams[1].close()

            session.begin_case = begin
            session.end_case = end
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "inflight"
            trace = save_evidence_bundle(
                genome, missing_reply_factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=40))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(0, trace.local_ticks["gpio"])
            self.assertEqual("LocalCommandDeadlineExceeded",
                             trace.events[-2]["error_type"])
            self.assertTrue(trace.events[-1]["effect_may_have_occurred"])
            comparison = replay_evidence_bundle(
                bundle, make_opentitan_gpio_runner,
                allow_factory_mismatch=True)
            self.assertTrue(comparison.matches)
            self.assertEqual("semantic_prefix", comparison.verification_scope)

    def test_real_gpio_wall_budget_keeps_replayable_prefix(self):
        genome = ScenarioGenome(
            testcase_id="real-gpio-wall-prefix", direction="IP_TO_CPU",
            path_id="gpio-external-wall-prefix", schedule_order=("gpio",),
            max_steps=3, actions=())

        def slow_real_gpio_factory():
            runner = make_opentitan_gpio_runner()
            session = runner.sessions["gpio"]
            real_step = session.step_local

            def slow_step(inputs):
                outputs = real_step(inputs)
                time.sleep(0.08)
                return outputs

            session.step_local = slow_step
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "wall-prefix"
            trace = save_evidence_bundle(
                genome, slow_real_gpio_factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=50))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertTrue(any(e.get("component") == "gpio"
                                and "outputs" in e for e in trace.events))
            self.assertEqual("max_wall_time_ms", trace.events[-1]["limit"])
            self.assertTrue(replay_evidence_bundle(
                bundle, make_opentitan_gpio_runner,
                allow_factory_mismatch=True).matches)

    def test_replay_rejects_changed_live_gpio_output(self):
        genome = ScenarioGenome(
            testcase_id="real-output-replay", direction="IP_TO_CPU",
            path_id="gpio-external", schedule_order=("gpio",), max_steps=3,
            actions=(Action("pin-rise", "gpio", "gpio_in", 1, "IP_TO_CPU",
                            Trigger("START")),))

        def changed_live_output_factory():
            runner = make_opentitan_gpio_runner()
            session = runner.sessions["gpio"]
            original_step = session.step_local
            altered = False

            def step_with_one_changed_observation(inputs):
                nonlocal altered
                outputs = dict(original_step(inputs))
                if not altered:
                    outputs["irq"] ^= 1
                    altered = True
                return outputs

            session.step_local = step_with_one_changed_observation
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "real-output"
            save_evidence_bundle(genome, make_opentitan_gpio_runner, bundle)
            comparison = replay_evidence_bundle(
                bundle, changed_live_output_factory,
                allow_factory_mismatch=True)
            self.assertFalse(comparison.matches)
            self.assertIsNotNone(comparison.first_difference)
            self.assertEqual("gpio", comparison.difference_context["component"])
            self.assertEqual(1, comparison.difference_context["local_tick"])

    def test_cut_edge_and_fixed_downstream_input_break_cpu_to_b_dataflow(self):
        root = Path(__file__).resolve().parents[2]
        baseline = GenomeCodec.decode((root / "configs/scenario/"
                                       "ibex_two_gpio_multiround.json").read_bytes())
        variant = GenomeCodec.decode((root / "configs/scenario/"
                                      "ibex_two_gpio_multiround_variant.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            cut = save_evidence_bundle(baseline, make_cut_a_to_b_runner,
                                       Path(directory) / "cut")
            self.assertEqual("complete", cut.status)
            self.assertFalse(any(event.get("kind") == "dataflow_delivery"
                                 and tuple(event.get("source", ())) ==
                                 ("gpio_a", "gpio_out") for event in cut.events))
            self.assertFalse(any(event.get("kind") == "memory_write"
                                 and event.get("address") == 0x200
                                 for event in cut.events))
            fixed_writes = []
            for index, genome in enumerate((baseline, variant)):
                fixed = replace(
                    genome, testcase_id=f"{genome.testcase_id}-isolated-b",
                    actions=(Action("fixed-b-rise", "gpio_b", "gpio_in", 1,
                                    genome.direction, Trigger("START"),
                                    delay_component="gpio_b", delay_ticks=40,
                                    width=8),))
                trace = save_evidence_bundle(
                    fixed, make_fixed_b_input_runner,
                    Path(directory) / f"fixed-{index}")
                self.assertEqual("complete", trace.status)
                self.assertTrue(any(event.get("component") == "gpio_a"
                                    and event.get("outputs", {}).get("gpio_out") ==
                                    (1 if index == 0 else 3)
                                    for event in trace.events))
                self.assertFalse(any(event.get("kind") == "dataflow_delivery"
                                     and tuple(event.get("source", ())) ==
                                     ("gpio_a", "gpio_out") for event in trace.events))
                writes = [event["value"] for event in trace.events
                          if event.get("kind") == "memory_write"
                          and event.get("address") == 0x200]
                self.assertTrue(writes)
                fixed_writes.append(set(writes))
            self.assertEqual([{1}, {1}], fixed_writes)

    def test_external_source_mutation_changes_real_cpu_memory_result(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode((root / "configs/scenario/"
                                     "external_gpio_ibex_gpio_multiround_variant.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-external-variant"
            trace = save_evidence_bundle(
                genome, make_external_gpio_ibex_gpio_runner, bundle)
            writes = [event["value"] for event in trace.events
                      if event.get("kind") == "memory_write"
                      and event.get("address") == 0x200]
            self.assertEqual([0x100, 0x100], writes)
            self.assertEqual("complete", trace.status)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            command = (sys.executable, str(root / "scripts/replay_scenario.py"),
                       "--evidence", str(bundle), "--factory",
                       "myfuzz.scenario.ip_cpu_ip_example:"
                       "make_external_gpio_ibex_gpio_runner",
                       "--rebuild", "--compare-trace")
            result = subprocess.run(command, cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=180)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["matches"])

    def test_cpu_program_mutation_propagates_through_two_real_gpio_rtls(self):
        root = Path(__file__).resolve().parents[2]
        cases = (("ibex_two_gpio_multiround.json", 1),
                 ("ibex_two_gpio_multiround_variant.json", 3))
        for name, expected in cases:
            with self.subTest(genome=name), tempfile.TemporaryDirectory() as directory:
                genome = GenomeCodec.decode((root / "configs/scenario" / name).read_bytes())
                bundle = Path(directory) / "case"
                trace = save_evidence_bundle(genome, make_ibex_two_gpio_runner, bundle)
                self.assertEqual("complete", trace.status)
                deliveries = [event["value"] for event in trace.events
                              if event.get("kind") == "dataflow_delivery"
                              and tuple(event.get("source", ())) == ("gpio_a", "gpio_out")
                              and tuple(event.get("target", ())) == ("gpio_b", "gpio_in")]
                self.assertIn(expected, deliveries)
                self.assertTrue(any(event.get("kind") == "dataflow_delivery"
                                    and tuple(event.get("source", ())) == ("gpio_b", "irq")
                                    and tuple(event.get("target", ())) == ("cpu", "irq")
                                    and event.get("value") == 1
                                    for event in trace.events))
                writes = [event["value"] for event in trace.events
                          if event.get("kind") == "memory_write"
                          and event.get("address") == 0x200]
                self.assertIn(expected, writes)
                if expected == 1:
                    self.assertNotIn(3, writes)
                environment = dict(os.environ)
                environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
                command = (sys.executable, str(root / "scripts/replay_scenario.py"),
                           "--evidence", str(bundle), "--factory",
                           "myfuzz.scenario.examples:make_ibex_two_gpio_runner",
                           "--rebuild", "--compare-trace")
                replay = subprocess.run(command, cwd=root, env=environment,
                                        capture_output=True, text=True, timeout=180)
                self.assertEqual(0, replay.returncode, replay.stderr)
                self.assertTrue(json.loads(replay.stdout)["matches"])

    def test_external_gpio_cpu_gpio_bundle_replays_two_real_rounds(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode((root / "configs/scenario/"
                                     "external_gpio_ibex_gpio_multiround.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-external-gpio-cpu-gpio"
            trace = save_evidence_bundle(
                genome, make_external_gpio_ibex_gpio_runner, bundle)
            writes = [event["value"] for event in trace.events
                      if event.get("kind") == "memory_write"
                      and event.get("address") == 0x200]
            self.assertEqual([0x100, 0x300], writes)
            self.assertEqual("complete", trace.status)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root / "src")
            command = (sys.executable, str(root / "scripts/replay_scenario.py"),
                       "--evidence", str(bundle), "--factory",
                       "myfuzz.scenario.ip_cpu_ip_example:"
                       "make_external_gpio_ibex_gpio_runner",
                       "--rebuild", "--compare-trace")
            result = subprocess.run(command, cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=180)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["matches"])

    def test_real_ibex_two_gpio_bundle_preserves_multiround_state(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode((root / "configs/scenario/"
                                     "ibex_two_gpio_multiround.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-ibex-two-gpio"
            trace = save_evidence_bundle(genome, make_ibex_two_gpio_runner,
                                         bundle)
            self.assertEqual("complete", trace.status)
            self.assertGreaterEqual(trace.local_ticks["cpu"], 1000)
            self.assertTrue(any(event.get("edge_kind") == "WAW"
                                for event in trace.events))
            self.assertTrue((bundle / "images" / "0000.bin").is_file())
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            command = (sys.executable, str(root / "scripts/replay_scenario.py"),
                       "--evidence", str(bundle), "--factory",
                       "myfuzz.scenario.examples:make_ibex_two_gpio_runner",
                       "--rebuild", "--compare-trace")
            result = subprocess.run(command, cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=180)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["matches"])

    def test_real_gpio_bundle_replays_with_cli(self):
        genome = ScenarioGenome(
            testcase_id="real-gpio-evidence", direction="IP_TO_CPU",
            path_id="gpio-external", schedule_order=("gpio",), max_steps=12,
            actions=(Action("pin-rise", "gpio", "gpio_in", 1, "IP_TO_CPU",
                            Trigger("START")),))
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-real-gpio"
            trace = save_evidence_bundle(genome, make_opentitan_gpio_runner,
                                         bundle)
            self.assertEqual("complete", trace.status)
            self.assertEqual(12, trace.local_ticks["gpio"])
            self.assertTrue(any(event.get("outputs") is not None
                                for event in trace.events))
            root = Path(__file__).resolve().parents[2]
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root / "src")
            command = (sys.executable, str(root / "scripts/replay_scenario.py"),
                       "--evidence", str(bundle), "--factory",
                       "myfuzz.scenario.examples:make_opentitan_gpio_runner",
                       "--rebuild", "--compare-trace")
            result = subprocess.run(command, cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["matches"])
            self.assertTrue(json.loads((bundle / "replay_report.json").read_text())[
                "matches"])


if __name__ == "__main__":
    unittest.main()
