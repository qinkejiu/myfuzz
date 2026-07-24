from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.experiments import ExperimentConfigurationError, load_experiment_config
from myfuzz.integration.pipeline import GenerationRequest, RuntimeRequest, run_candidate_pipeline


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "experiments" / "rvx_generated" / "experiment.json"
CANDIDATE_FIXTURE = ROOT / "tests" / "fixtures" / "contracts" / "candidate_manifest.v1.valid.json"


def _candidate() -> dict[str, object]:
    return json.loads(CANDIDATE_FIXTURE.read_text(encoding="utf-8"))


def _candidates() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index in range(3):
        candidate = _candidate()
        candidate["candidate_id"] = f"candidate-rvx-{index}"
        result.append(candidate)
    return result


def _runtime_fragment() -> dict[str, object]:
    return {
        "harnesses": {
            "flat-direct": [{"content_hash": "sha256:" + "1" * 64}],
            "candidate-direct": [{"content_hash": "sha256:" + "2" * 64}],
            "candidate-depaware": [{"content_hash": "sha256:" + "3" * 64}],
        },
        "raw_bit_mappings": {
            "flat-direct": [],
            "candidate-direct": [],
            "candidate-depaware": [],
        },
        "runtime": {"status": "ready"},
    }


def _document() -> dict[str, object]:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _write_declared_sources(repo_root: Path, document: dict[str, object]) -> None:
    for source_list in document["source_lists"]:
        for declared_path in source_list["files"]:
            source = repo_root / declared_path
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("module declared_source; endmodule\n", encoding="ascii")


class RvxGenerationBoundaryTests(unittest.TestCase):
    def test_generated_config_is_reference_free_and_declares_portable_cpu_ip_root(self) -> None:
        config = load_experiment_config(CONFIG)

        self.assertEqual(config.source_roots, ("external_designs/rvx/hardware",))
        self.assertIsNone(config.reference)
        self.assertTrue(config.components)
        self.assertTrue(config.ports)
        self.assertTrue(config.protocol_endpoints)
        self.assertTrue(
            all(
                source.startswith("external_designs/rvx/hardware/")
                for source_list in config.source_lists
                for source in source_list.files
            )
        )

    def test_evaluator_member_at_any_depth_is_rejected_before_producer_or_output(self) -> None:
        document = _document()
        document.pop("reference", None)
        document["target"]["nested"] = {"evaluator": {"path": "reference/evaluator"}}
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "experiment.json"
            output_dir = Path(temporary) / "out"
            config_path.write_text(json.dumps(document), encoding="utf-8")
            producer_called = False

            def producer(_request: GenerationRequest) -> list[dict[str, object]]:
                nonlocal producer_called
                producer_called = True
                return _candidates()

            with self.assertRaisesRegex(ValueError, "evaluator"):
                run_candidate_pipeline(
                    config_path,
                    output_dir=output_dir,
                    top_k=3,
                    dry_run=True,
                    composition_producer=producer,
                    runtime_preparer=lambda _candidate_value, _request: _runtime_fragment(),
                    repo_root=Path(temporary),
                )
            self.assertFalse(producer_called)
            self.assertFalse(output_dir.exists())

    def test_source_outside_explicit_cpu_ip_root_is_rejected_by_loader(self) -> None:
        document = _document()
        document.pop("reference", None)
        document["source_lists"][0]["files"][0] = "external_designs/rvx_reference/evaluator.sv"
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "experiment.json"
            config_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ExperimentConfigurationError, "source_roots"):
                load_experiment_config(config_path)

    def test_missing_external_rtl_returns_dependency_unavailable_before_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "out"
            calls: list[str] = []

            result = run_candidate_pipeline(
                CONFIG,
                output_dir=output_dir,
                top_k=3,
                dry_run=True,
                composition_producer=lambda _request: calls.append("producer") or [],
                runtime_preparer=lambda _candidate_value, _request: calls.append("runtime") or {},
                repo_root=Path(temporary),
            )

            self.assertEqual(result["status"], "dependency_unavailable")
            self.assertEqual(result["candidate_count"], 0)
            self.assertTrue(result["missing_dependencies"])
            self.assertEqual(calls, [])
            self.assertFalse(output_dir.exists())

    def test_reference_file_changes_do_not_reach_generation_request_or_cache_key(self) -> None:
        document = _document()
        document.pop("reference", None)
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            config_path = repo_root / "experiment.json"
            config_path.write_text(json.dumps(document), encoding="utf-8")
            _write_declared_sources(repo_root, document)
            evaluator_directory = repo_root / "reference_evaluator"
            evaluator_directory.mkdir()
            evaluator = evaluator_directory / "evaluate.py"
            evaluator.write_text("first\n", encoding="ascii")
            observed_requests: list[GenerationRequest] = []

            def producer(request: GenerationRequest) -> list[dict[str, object]]:
                observed_requests.append(request)
                return _candidates()

            first = run_candidate_pipeline(
                config_path,
                output_dir=repo_root / "out-first",
                top_k=3,
                dry_run=True,
                composition_producer=producer,
                runtime_preparer=lambda _candidate_value, _request: _runtime_fragment(),
                memory_state_path=repo_root / "memory-first.json",
                repo_root=repo_root,
            )
            evaluator.write_text("second\n", encoding="ascii")
            second = run_candidate_pipeline(
                config_path,
                output_dir=repo_root / "out-second",
                top_k=3,
                dry_run=True,
                composition_producer=producer,
                runtime_preparer=lambda _candidate_value, _request: _runtime_fragment(),
                memory_state_path=repo_root / "memory-second.json",
                repo_root=repo_root,
            )

            self.assertEqual(
                [manifest["build_cache_key"] for manifest in first["manifests"]],
                [manifest["build_cache_key"] for manifest in second["manifests"]],
            )
            self.assertEqual(len(observed_requests), 2)
            for request in observed_requests:
                self.assertFalse(hasattr(request, "reference"))
                self.assertFalse(hasattr(request, "evaluator"))
                self.assertFalse(hasattr(request, "argv"))
                visible_paths = (*request.source_roots, *(item.resolved_path for item in request.sources))
                self.assertTrue(all(not path.is_relative_to(evaluator_directory) for path in visible_paths))


if __name__ == "__main__":
    unittest.main()
