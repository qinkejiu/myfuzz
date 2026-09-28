"""Short opt-in end-to-end Rust RFuzz client and scenario host exchange."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.integration.test_scenario_rfuzz_acceptance import executor_for


class PinSession:
    def __init__(self, output):
        self.output = output

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {self.output: inputs.get("pin", 0)}

    def end_case(self):
        pass


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_RFUZZ_LIVE") == "1",
                     "set MYFUZZ_SCENARIO_RFUZZ_LIVE=1 for Rust client smoke")
class ScenarioRfuzzLiveClientTests(unittest.TestCase):
    def test_lost_mutation_sideband_fails_with_diagnostic(self):
        root = Path(__file__).resolve().parents[2]
        binary = (root / "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                  "target/release/kfuzz")
        self.assertTrue(binary.is_file())
        executor = executor_for()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            hint_path = output / "mutation_hint.json"
            real_replace = os.replace
            writes = 0

            def lose_second_hint(source, destination):
                nonlocal writes
                if Path(destination) == hint_path:
                    writes += 1
                    if writes == 2:
                        hint_path.unlink(missing_ok=True)
                        return
                return real_replace(source, destination)

            with patch("myfuzz.integration.scenario_rfuzz_live.os.replace",
                       side_effect=lose_second_hint):
                result = run_scenario_rfuzz_live(
                    executor=executor, client_binary=binary,
                    output_dir=output, duration_seconds=2, max_tests=128)
            self.assertGreaterEqual(writes, 2)
            self.assertGreater(result.tests, 0)
            self.assertNotEqual(0, result.client_returncode)
            self.assertIn("scenario hint file missing",
                          (output / "client.log").read_text())

    def test_delayed_initial_sideband_does_not_mutate_later_testcase(self):
        root = Path(__file__).resolve().parents[2]
        binary = (root / "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                  "target/release/kfuzz")
        self.assertTrue(binary.is_file())
        executor = executor_for()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            hint_path = output / "mutation_hint.json"
            real_replace = os.replace
            writes = 0

            def delay_feedback_hints(source, destination):
                nonlocal writes
                if Path(destination) == hint_path:
                    writes += 1
                    if writes >= 2:
                        return
                return real_replace(source, destination)

            with patch("myfuzz.integration.scenario_rfuzz_live.os.replace",
                       side_effect=delay_feedback_hints):
                result = run_scenario_rfuzz_live(
                    executor=executor, client_binary=binary,
                    output_dir=output, duration_seconds=1, max_tests=64)
            self.assertGreaterEqual(writes, 2)
            self.assertEqual([], json.loads(hint_path.read_text())[
                "latest_completed_batch"])
            self.assertNotEqual(0, result.client_returncode)
            self.assertIn("scenario hint has no completed feedback",
                          (output / "client.log").read_text())

    def test_delayed_later_sideband_rejects_stale_buffer_provenance(self):
        root = Path(__file__).resolve().parents[2]
        binary = (root / "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                  "target/release/kfuzz")
        executor = executor_for()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            hint_path = output / "mutation_hint.json"
            real_replace = os.replace
            writes = 0

            def delay_after_first_feedback(source, destination):
                nonlocal writes
                if Path(destination) == hint_path:
                    writes += 1
                    if writes >= 3:
                        return
                return real_replace(source, destination)

            with patch("myfuzz.integration.scenario_rfuzz_live.os.replace",
                       side_effect=delay_after_first_feedback):
                result = run_scenario_rfuzz_live(
                    executor=executor, client_binary=binary,
                    output_dir=output, duration_seconds=1, max_tests=128,
                    max_runs_per_batch=1)
            self.assertGreaterEqual(writes, 3)
            self.assertNotEqual(0, result.client_returncode)
            self.assertIn("scenario hint feedback is stale",
                          (output / "client.log").read_text())

    def test_rust_client_exchanges_scenario_coverage(self):
        root = Path(__file__).resolve().parents[2]
        binary = (root / "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                  "target/release/kfuzz")
        self.assertTrue(binary.is_file(), "build pinned Rust RFuzz client first")
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out")))
        graph = DependencyGraph(
            sources=(FuzzableSource("a.pin", "a", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("b.irq", ("a.pin",), "DATA_BINDING"),))
        genome = ScenarioGenome(
            testcase_id="seed", direction="IP_TO_IP", path_id="a-b",
            schedule_order=("a", "b"), max_steps=4,
            actions=(Action("edge", "a", "pin", 0, "IP_TO_IP",
                            Trigger("START"), width=1),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("b.irq", genome),))

        def factory():
            return ScenarioRunner(
                sessions={"a": PinSession("out"), "b": PinSession("irq")},
                ownership=ownership,
                bindings=(Binding("a", "out", "b", "pin", 1),))

        executor = ScenarioRfuzzExecutor(
            run_id="rust-smoke", decoder=decoder, factory=factory,
            targets=(CoverageTarget("b.irq", "b", "irq", 1, 1),),
            allow_legacy_search=True)
        with tempfile.TemporaryDirectory() as directory:
            result = run_scenario_rfuzz_live(
                executor=executor, client_binary=binary,
                output_dir=Path(directory) / "run",
                duration_seconds=1, max_tests=512)
            self.assertGreater(result.tests, 0)
            self.assertGreater(result.completed_feedback_exchanges, 0)
            report = json.loads((result.output_dir / "report.json").read_text())
            self.assertEqual(result.tests, report["tests"])
            self.assertEqual("sum_of_independent_local_ticks_cost_only",
                             report["total_local_ticks_semantics"])
            manifest = json.loads((result.output_dir / "decoder_manifest.json").read_text())
            self.assertEqual("scenario_rfuzz_decoder.v1", manifest["schema_version"])
            self.assertTrue(report["decoder_manifest_sha256"])
            self.assertTrue((result.output_dir / "receipts.jsonl").stat().st_size)
            receipts = [json.loads(line) for line in
                        (result.output_dir / "receipts.jsonl").read_text().splitlines()]
            self.assertEqual(result.tests, len(receipts))
            self.assertTrue(all("applied_source_ids" in row for row in receipts))
            self.assertEqual(result.statuses.get("complete", 0),
                             sum(row["status"] == "complete" for row in receipts))
            self.assertEqual(len(receipts), len({
                (row["buffer_id"], row["slot"]) for row in receipts}))
            self.assertTrue(all(row["path_id"] == "b.irq:a.pin"
                                for row in receipts if row["status"] == "complete"))
            replay = replay_scenario_rfuzz_corpus(result.output_dir, factory)
            self.assertGreater(replay.total_entries, 0)
            self.assertEqual((), replay.mismatches)
            entry = sorted((result.output_dir / "corpus").glob("entry_*.json"))[0]
            changed = json.loads(entry.read_text())
            changed["entry"]["inputs"].extend([0xAB] * 8)
            entry.write_text(json.dumps(changed))
            self.assertTrue(replay_scenario_rfuzz_corpus(
                result.output_dir, factory).mismatches)


if __name__ == "__main__":
    unittest.main()
