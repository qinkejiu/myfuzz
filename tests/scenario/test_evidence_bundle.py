"""A disk bundle is checked before fresh RTL replay starts."""

import json
import hashlib
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import (Action, GenomeCodec, MemoryImage,
                                    ScenarioGenome, Trigger)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.scenario.evidence_cli_fixture import make_runner


class _PinSession:
    def __init__(self, offset=0):
        self.offset = offset
        self.begins = 0

    def identity_document(self):
        return {"fixture_source": "pin-v1"}

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        return {"out": inputs.get("pin", 0) + self.offset}

    def end_case(self):
        pass


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.instances = []
        self.genome = ScenarioGenome(
            testcase_id="bundle", direction="IP_TO_IP", path_id="pin",
            schedule_order=("gpio",), max_steps=3,
            actions=(Action("edge", "gpio", "pin", 1, "IP_TO_IP",
                            Trigger("START")),))
        self.ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "external"),))

    def factory(self, offset=0):
        session = _PinSession(offset)
        self.instances.append(session)
        return ScenarioRunner(sessions={"gpio": session},
                              ownership=self.ownership, bindings=())

    def test_bundle_has_required_files_and_replays_from_fresh_session(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            trace = save_evidence_bundle(self.genome, self.factory, bundle)
            for name in ("manifest.json", "genome.bin", "genome.json",
                         "factory_source.json",
                         "trace.json", "initialization.jsonl",
                         "schedule.jsonl", "observations.jsonl",
                         "transactions.jsonl", "state_versions.jsonl",
                         "resets.jsonl", "checks.jsonl", "coverage.json",
                         "result.json", "bundle_index.json"):
                self.assertTrue((bundle / name).is_file(), name)
            self.assertEqual(trace.semantic_sha256,
                             json.loads((bundle / "result.json").read_text())[
                                 "semantic_sha256"])
            result = replay_evidence_bundle(bundle, self.factory)
            self.assertTrue(result.matches)
            self.assertEqual(2, len(self.instances))
            self.assertEqual([1, 1], [session.begins for session in self.instances])
            self.assertTrue((bundle / "replay_report.json").is_file())

    def test_tampered_material_is_rejected_before_any_rtl_begin(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, self.factory, bundle)
            before = len(self.instances)
            (bundle / "genome.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "genome.bin.*hash mismatch"):
                replay_evidence_bundle(bundle, self.factory)
            self.assertEqual(before, len(self.instances))

    def test_tampered_manifest_is_rejected_before_any_rtl_begin(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, self.factory, bundle)
            before = len(self.instances)
            manifest = bundle / "manifest.json"
            document = json.loads(manifest.read_text())
            document["ownership"]["fields"][0]["width"] = 2
            manifest.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "manifest.json.*hash mismatch"):
                replay_evidence_bundle(bundle, self.factory)
            self.assertEqual(before, len(self.instances))

    def test_reindexed_manifest_rule_tamper_still_fails_before_begin(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, self.factory, bundle)
            before = len(self.instances)
            manifest = bundle / "manifest.json"
            document = json.loads(manifest.read_text())
            document["ownership"]["owners"][0]["producer_ref"] = "different-source"
            manifest.write_text(json.dumps(document))
            index_path = bundle / "bundle_index.json"
            index = json.loads(index_path.read_text())
            index["files"]["manifest.json"] = hashlib.sha256(
                manifest.read_bytes()).hexdigest()
            index_path.write_text(json.dumps(index))
            with self.assertRaisesRegex(ValueError, "manifest identity mismatch"):
                replay_evidence_bundle(bundle, self.factory)
            self.assertEqual(before, len(self.instances))

    def test_image_bytes_are_saved_and_checked_before_replay(self):
        class MemoryPinSession(_PinSession):
            def __init__(self):
                super().__init__()
                self.memory = PersistentMemory(
                    regions=(MemoryRegion("ram", 0, 0x1000),),
                    initialization_seed=7, max_initialized_bytes=0x1000)

        def factory():
            session = MemoryPinSession()
            self.instances.append(session)
            return ScenarioRunner(sessions={"gpio": session},
                                  ownership=self.ownership, bindings=())

        genome = replace(self.genome, initial_images=(
            MemoryImage("firmware/segment", "gpio", 0x100, "01020304"),))
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(genome, factory, bundle)
            image = bundle / "images" / "0000.bin"
            self.assertEqual(b"\x01\x02\x03\x04", image.read_bytes())
            final_state = json.loads((bundle / "final_state.json").read_text())
            self.assertEqual(4, final_state["memories"]["gpio"][
                "initialized_bytes"])
            self.assertEqual(64, len(final_state["memories"]["gpio"][
                "cells_sha256"]))
            self.assertTrue(replay_evidence_bundle(bundle, factory).matches)
            before = len(self.instances)
            image.write_bytes(b"\x01\x02\x03\x05")
            with self.assertRaisesRegex(ValueError, "images/0000.bin.*hash mismatch"):
                replay_evidence_bundle(bundle, factory)
            self.assertEqual(before, len(self.instances))

    def test_reindexed_image_tamper_disagrees_with_genome_before_begin(self):
        class MemoryPinSession(_PinSession):
            def __init__(self):
                super().__init__()
                self.memory = PersistentMemory(
                    regions=(MemoryRegion("ram", 0, 0x1000),),
                    initialization_seed=7, max_initialized_bytes=0x1000)

        def factory():
            session = MemoryPinSession()
            self.instances.append(session)
            return ScenarioRunner(sessions={"gpio": session},
                                  ownership=self.ownership, bindings=())

        genome = replace(self.genome, initial_images=(
            MemoryImage("firmware", "gpio", 0x100, "01020304"),))
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(genome, factory, bundle)
            before = len(self.instances)
            image = bundle / "images" / "0000.bin"
            image.write_bytes(b"\x01\x02\x03\x05")
            index_path = bundle / "bundle_index.json"
            index = json.loads(index_path.read_text())
            index["files"]["images/0000.bin"] = hashlib.sha256(
                image.read_bytes()).hexdigest()
            index_path.write_text(json.dumps(index))
            with self.assertRaisesRegex(ValueError, "image material disagrees"):
                replay_evidence_bundle(bundle, factory)
            self.assertEqual(before, len(self.instances))

    def test_first_divergence_report_contains_local_context(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, self.factory, bundle)
            result = replay_evidence_bundle(
                bundle, lambda: self.factory(offset=1),
                allow_factory_mismatch=True)
            self.assertFalse(result.matches)
            self.assertEqual(1, result.first_difference)
            self.assertEqual("gpio", result.difference_context["component"])
            report = json.loads((bundle / "replay_report.json").read_text())
            self.assertFalse(report["matches"])

    def test_changed_factory_is_rejected_before_rtl_begin_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, self.factory, bundle)
            before = len(self.instances)
            with self.assertRaisesRegex(ValueError, "factory source identity"):
                replay_evidence_bundle(bundle, lambda: self.factory(offset=1))
            self.assertEqual(before, len(self.instances))

    def test_result_inconsistency_is_rejected_even_with_updated_file_index(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, self.factory, bundle)
            before = len(self.instances)
            result_path = bundle / "result.json"
            result = json.loads(result_path.read_text())
            result["event_count"] += 1
            result_path.write_text(json.dumps(result))
            index_path = bundle / "bundle_index.json"
            index = json.loads(index_path.read_text())
            index["files"]["result.json"] = hashlib.sha256(
                result_path.read_bytes()).hexdigest()
            index_path.write_text(json.dumps(index))
            with self.assertRaisesRegex(ValueError, "event count"):
                replay_evidence_bundle(bundle, self.factory)
            self.assertEqual(before, len(self.instances))

    def test_replay_cli_matches_saved_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            save_evidence_bundle(self.genome, make_runner, bundle)
            root = Path(__file__).resolve().parents[2]
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            result = subprocess.run(
                (sys.executable, str(root / "scripts/replay_scenario.py"),
                 "--evidence", str(bundle), "--factory",
                 "tests.scenario.evidence_cli_fixture:make_runner",
                 "--rebuild", "--compare-trace"),
                cwd=root, env=environment, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["matches"])

    def test_record_cli_creates_bundle_from_canonical_genome(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).resolve().parents[2]
            genome_path = Path(directory) / "genome.json"
            genome_path.write_bytes(GenomeCodec.encode(self.genome))
            bundle = Path(directory) / "case-bundle"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            result = subprocess.run(
                (sys.executable, str(root / "scripts/record_scenario.py"),
                 "--genome", str(genome_path), "--factory",
                 "tests.scenario.evidence_cli_fixture:make_runner",
                 "--output", str(bundle)),
                cwd=root, env=environment, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("complete", json.loads(result.stdout)["status"])
            self.assertTrue(replay_evidence_bundle(bundle, make_runner).matches)

    def test_record_cli_accepts_closed_chain_checker_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).resolve().parents[2]
            genome_path = Path(directory) / "genome.json"
            genome_path.write_bytes(GenomeCodec.encode(self.genome))
            bundle = Path(directory) / "case-bundle"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            result = subprocess.run(
                (sys.executable, str(root / "scripts/record_scenario.py"),
                 "--genome", str(genome_path), "--factory",
                 "tests.scenario.evidence_cli_fixture:make_runner",
                 "--output", str(bundle), "--closed-chain-value", "1"),
                cwd=root, env=environment, capture_output=True, text=True)
            self.assertEqual(1, result.returncode, result.stderr)
            checks = [json.loads(line) for line in
                      (bundle / "checks.jsonl").read_text().splitlines()]
            self.assertEqual("cpu_gpio_closed_chain.v1", checks[0]["checker"])
            self.assertFalse(checks[0]["complete"])
            self.assertTrue(replay_evidence_bundle(bundle, make_runner).matches)

    def test_record_cli_accepts_explicit_resource_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).resolve().parents[2]
            genome_path = Path(directory) / "genome.json"
            genome_path.write_bytes(GenomeCodec.encode(self.genome))
            budget_path = Path(directory) / "budget.json"
            budget_path.write_text(json.dumps(ResourceBudget().to_document()))
            bundle = Path(directory) / "case-bundle"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            result = subprocess.run(
                (sys.executable, str(root / "scripts/record_scenario.py"),
                 "--genome", str(genome_path), "--factory",
                 "tests.scenario.evidence_cli_fixture:make_runner",
                 "--output", str(bundle), "--budget", str(budget_path)),
                cwd=root, env=environment, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            saved = json.loads((bundle / "result.json").read_text())
            self.assertEqual(ResourceBudget().to_document(),
                             saved["resource_budget"])
            self.assertTrue(replay_evidence_bundle(bundle, make_runner).matches)

    def test_record_cli_accepts_reverse_chain_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).resolve().parents[2]
            genome_path = Path(directory) / "genome.json"
            genome_path.write_bytes(GenomeCodec.encode(self.genome))
            bundle = Path(directory) / "case-bundle"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            result = subprocess.run(
                (sys.executable, str(root / "scripts/record_scenario.py"),
                 "--genome", str(genome_path), "--factory",
                 "tests.scenario.evidence_cli_fixture:make_runner",
                 "--output", str(bundle),
                 "--reverse-chain-values", "0x100,0x300"),
                cwd=root, env=environment, capture_output=True, text=True)
            self.assertEqual(1, result.returncode, result.stderr)
            checks = [json.loads(line) for line in
                      (bundle / "checks.jsonl").read_text().splitlines()]
            self.assertEqual("gpio_cpu_gpio_closed_chain.v1", checks[0]["checker"])
            self.assertEqual([0x100, 0x300], checks[0]["expected_values"])
            self.assertTrue(replay_evidence_bundle(bundle, make_runner).matches)

    def test_checker_and_coverage_are_recorded_and_recomputed(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case-bundle"
            target = CoverageTarget("gpio.high", "gpio", "out", 1, 1)
            save_evidence_bundle(self.genome, self.factory, bundle,
                                 gpio_check_devices=("gpio",),
                                 coverage_targets=(target,))
            check = json.loads((bundle / "checks.jsonl").read_text())
            self.assertEqual("gpio_direct_out.v1", check["checker"])
            self.assertEqual([], check["findings"])
            coverage = json.loads((bundle / "coverage.json").read_text())
            self.assertEqual(["gpio.high"], coverage["hits"])
            self.assertTrue(replay_evidence_bundle(bundle, self.factory).matches)

    def test_cli_explicitly_rejects_host_checkpoint_resume(self):
        root = Path(__file__).resolve().parents[2]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
        result = subprocess.run(
            (sys.executable, str(root / "scripts/replay_scenario.py"),
             "--evidence", "unused", "--factory",
             "tests.scenario.evidence_cli_fixture:make_runner",
             "--resume", "host-summary.json"),
            cwd=root, env=environment, capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("unsupported_checkpoint_resume", result.stderr)


if __name__ == "__main__":
    unittest.main()
