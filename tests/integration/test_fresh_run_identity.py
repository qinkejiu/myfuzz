"""Fresh RFuzz evidence is checked before replay starts another runner."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz_live import (
    _fresh_checker_identity, _write_fresh_run_identity, render_scenario_rfuzz_config,
)
from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
from tests.integration.test_scenario_rfuzz_acceptance import executor_for


def stable_checker(trace):
    return ()


class FreshRunIdentityTests(unittest.TestCase):
    def make_bundle(self, output, *, versioned=True):
        output.mkdir()
        executor = executor_for()
        executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        receipt = executor.receipts[-1]
        self.assertEqual("complete", receipt.status)
        decoder = executor.decoder.document()
        encoded = json.dumps(decoder, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode()
        (output / "decoder_manifest.json").write_bytes(encoded)
        (output / "targets.json").write_text(json.dumps([asdict(t) for t in executor.targets]))
        (output / "seed.bin").write_bytes(bytes(8))
        (output / "rfuzz.toml").write_text(render_scenario_rfuzz_config(executor.targets))
        row = asdict(receipt)
        (output / "receipts.jsonl").write_text(json.dumps(row) + "\n")
        (output / "corpus").mkdir()
        (output / "corpus/entry_1.json").write_text(json.dumps({"entry": {"inputs": [0] * 8}}))
        (output / "failures").mkdir()
        (output / "failures/trace.json").write_text(json.dumps({"trace": row}))
        report = {"decoder_manifest_sha256": hashlib.sha256(encoded).hexdigest()}
        if versioned:
            with patch("myfuzz.integration.scenario_rfuzz_live._rfuzz_client_identity",
                       return_value={"binary_sha256": "test-client"}):
                digest = _write_fresh_run_identity(
                    output, executor=executor, checker_identity=None,
                    client_binary=Path("unused"), run_config={"search_seed": 1})
            report.update(run_identity_schema="scenario_fresh_run_identity.v1",
                          run_identity_sha256=digest)
        (output / "report.json").write_text(json.dumps(report))
        return executor

    def test_real_runner_is_frozen_without_extra_factory_or_identity_scan(self):
        executor = executor_for()
        actual_factory = executor.factory
        identities = []

        def factory():
            runner = actual_factory()
            runner.identity_document = Mock(wraps=runner.identity_document)
            identities.append(runner.identity_document)
            return runner

        executor.factory = Mock(side_effect=factory)
        with patch("myfuzz.integration.scenario_rfuzz_live._command_version") as version:
            executor.execute_batch(InputBatch(1, 8, ((bytes(8),), (bytes(8),))))
        self.assertEqual(2, executor.factory.call_count)
        self.assertEqual([1, 1], [method.call_count for method in identities])
        version.assert_not_called()
        self.assertIsInstance(executor.fresh_manifest_document, dict)
        self.assertTrue(all(r.manifest_sha256 == executor.fresh_manifest_sha256
                            for r in executor.receipts))

    def test_changed_real_runner_is_rejected_before_its_rtl_begin(self):
        executor = executor_for()
        actual_factory = executor.factory
        count = 0
        begins = []

        def factory():
            nonlocal count
            count += 1
            runner = actual_factory()
            if count == 2:
                identity = runner.identity_document()
                identity["changed_source"] = True
                runner.identity_document = lambda: identity
                runner.begin_test = Mock(side_effect=AssertionError("must not begin"))
                begins.append(runner.begin_test)
            return runner

        executor.factory = factory
        executor.execute_batch(InputBatch(1, 8, ((bytes(8),), (bytes(8),))))
        self.assertEqual("environment_error", executor.receipts[1].status)
        self.assertIn("identity changed", executor.receipts[1].error)
        begins[0].assert_not_called()

    def test_bundle_records_full_graph_templates_and_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            executor = self.make_bundle(output)
            identity = json.loads((output / "run_identity.json").read_text())["identity"]
            self.assertEqual("observed", identity["runner"]["status"])
            self.assertIn("genome_templates", identity)
            self.assertIn("corpus/entry_1.json", identity["artifacts"])
            result = replay_scenario_rfuzz_corpus(output, executor.factory)
            self.assertEqual(1, result.matched_entries)

    def test_targets_receipts_and_failure_trace_tamper_fail_before_factory(self):
        for filename in ("targets.json", "receipts.jsonl", "corpus/entry_1.json",
                         "failures/trace.json"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "run"
                self.make_bundle(output)
                (output / filename).write_text("{}\n")
                factory = Mock(side_effect=AssertionError("must not create runner"))
                with self.assertRaisesRegex(ValueError, "artifact mismatch"):
                    replay_scenario_rfuzz_corpus(output, factory)
                factory.assert_not_called()

    def test_missing_new_sidecar_and_extra_failure_are_rejected_before_factory(self):
        for mutation in ("remove_sidecar", "extra_failure"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "run"
                self.make_bundle(output)
                if mutation == "remove_sidecar":
                    (output / "run_identity.json").unlink()
                else:
                    (output / "failures/injected.json").write_text("{}")
                factory = Mock()
                with self.assertRaisesRegex(ValueError, "identity.*(missing|list mismatch)"):
                    replay_scenario_rfuzz_corpus(output, factory)
                factory.assert_not_called()

    def test_legacy_bundle_remains_replayable(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            executor = self.make_bundle(output, versioned=False)
            self.assertEqual(1, replay_scenario_rfuzz_corpus(
                output, executor.factory).matched_entries)

    def test_replay_changed_runtime_identity_does_not_begin(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            executor = self.make_bundle(output)
            runner = executor.factory()
            manifest = runner.identity_document()
            manifest["different_profile"] = True
            runner.identity_document = lambda: manifest
            runner.begin_test = Mock(side_effect=AssertionError("must not begin"))
            result = replay_scenario_rfuzz_corpus(output, lambda: runner)
            self.assertEqual(0, result.matched_entries)
            runner.begin_test.assert_not_called()

    def test_unrecorded_checker_is_rejected_before_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            self.make_bundle(output)
            factory = Mock()
            with self.assertRaisesRegex(ValueError, "checker identity mismatch"):
                replay_scenario_rfuzz_corpus(output, factory, checker=stable_checker)
            factory.assert_not_called()

    def test_reindexed_template_declarations_still_fail_before_factory(self):
        for field in ("genome_templates", "harness_templates"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "run"
                self.make_bundle(output)
                envelope = json.loads((output / "run_identity.json").read_text())
                envelope["identity"][field] = [{"invented_template": True}]
                envelope["sha256"] = hashlib.sha256(json.dumps(
                    envelope["identity"], sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()
                (output / "run_identity.json").write_text(json.dumps(envelope))
                report = json.loads((output / "report.json").read_text())
                report["run_identity_sha256"] = envelope["sha256"]
                (output / "report.json").write_text(json.dumps(report))
                factory = Mock()
                with self.assertRaisesRegex(ValueError, "declarations mismatch"):
                    replay_scenario_rfuzz_corpus(output, factory)
                factory.assert_not_called()

    def test_collector_declares_stable_config_without_serializing_runtime_objects(self):
        runtime = object()

        def collector(trace):
            return () if runtime else ()

        with self.assertRaisesRegex(ValueError, "closure value"):
            _fresh_checker_identity(collector)
        declaration = _fresh_checker_identity(
            collector, config={"direction": "CPU_TO_IP_TO_CPU", "rounds": 2},
            identity_target=stable_checker)
        self.assertEqual("stable_checker", declaration["qualname"])
        self.assertEqual(2, declaration["config"]["rounds"])


if __name__ == "__main__":
    unittest.main()
