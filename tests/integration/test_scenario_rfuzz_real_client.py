"""Actual Rust RFuzz client drives three independent source-backed RTL harnesses."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder

from tests.integration.test_scenario_ip_cpu_ip_genome import IpCpuIpGenomeTests


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_RFUZZ_REAL") == "1",
                     "set MYFUZZ_SCENARIO_RFUZZ_REAL=1 for Rust+RTL short run")
class ScenarioRfuzzRealClientTests(unittest.TestCase):
    def test_rust_rfuzz_drives_ibex_and_two_gpio_processes(self):
        root = Path(__file__).resolve().parents[2]
        binary = (root / "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                  "target/release/kfuzz")
        self.assertTrue(binary.is_file(), "build pinned Rust RFuzz client first")
        _, _, _, runner, baseline = IpCpuIpGenomeTests._case()
        seed_actions = list(baseline.actions)
        seed_actions[2] = replace(seed_actions[2], value=0x100)
        seed = replace(baseline, testcase_id="rust-real-seed",
                       actions=tuple(seed_actions))
        graph = DependencyGraph(
            sources=(FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                                    ("IP_TO_CPU_TO_IP",)),),
            rules=(DependencyRule("a.output.0x300", ("b.pin9",),
                                  "DATA_BINDING"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate("a.output.0x300", seed),))
        executor = ScenarioRfuzzExecutor(
            run_id="rust-real-short", decoder=decoder,
            factory=lambda: IpCpuIpGenomeTests._case()[3],
            targets=(CoverageTarget("a.output.0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300),), allow_legacy_search=True)
        with tempfile.TemporaryDirectory() as directory:
            result = run_scenario_rfuzz_live(
                executor=executor, client_binary=binary,
                output_dir=Path(directory) / "run",
                duration_seconds=1, max_tests=16)
            self.assertGreaterEqual(result.tests, 2)
            self.assertGreater(result.completed_feedback_exchanges, 0)
            self.assertEqual(0, result.statuses.get("environment_error", 0))
            self.assertGreaterEqual(len({receipt.raw_sha256
                                         for receipt in executor.receipts}), 2)
            self.assertTrue(all(receipt.total_local_ticks > 1000
                                for receipt in executor.receipts))
            report = json.loads((result.output_dir / "report.json").read_text())
            self.assertGreater(report["mutation_hint_updates"], 1)
            self.assertEqual("scenario_mutation_hint.v1",
                             report["mutation_hint_schema"])
            replay = replay_scenario_rfuzz_corpus(
                result.output_dir, lambda: IpCpuIpGenomeTests._case()[3])
            self.assertGreater(replay.total_entries, 0)
            self.assertEqual((), replay.mismatches)


if __name__ == "__main__":
    unittest.main()
