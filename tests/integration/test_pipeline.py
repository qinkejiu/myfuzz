from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from myfuzz.experiments import prepare_candidate_runtime
from myfuzz.integration.pipeline import GenerationRequest, RuntimeRequest, run_candidate_pipeline
from tests.runtime_fixtures import load_runtime_documents


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/experiments/synthetic_opaque.json"
CANDIDATE_FIXTURE = ROOT / "tests/fixtures/contracts/candidate_manifest.v1.valid.json"


def _candidate() -> dict[str, object]:
    return json.loads(CANDIDATE_FIXTURE.read_text(encoding="utf-8"))


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


def _blocking_pipeline_worker(
    output: Path,
    ready: object,
    release: object,
    connection: object,
) -> None:
    def producer(_request: GenerationRequest) -> list[dict[str, object]]:
        ready.set()
        if not release.wait(timeout=3):
            raise TimeoutError("parent did not release worker")
        return [_candidate()]

    try:
        result = run_candidate_pipeline(
            CONFIG,
            output_dir=output,
            top_k=1,
            dry_run=True,
            composition_producer=producer,
            runtime_preparer=lambda _candidate, _request: _runtime_fragment(),
        )
        connection.send(("ok", result["candidate_count"]))
    except BaseException as error:
        connection.send(("error", repr(error)))
    finally:
        connection.close()


def _shared_gate_worker(
    output: Path,
    entered: object,
    release: object,
    connection: object,
) -> None:
    def producer(_request: GenerationRequest) -> list[dict[str, object]]:
        entered.set()
        if not release.wait(timeout=3):
            raise TimeoutError("parent did not release worker")
        return [_candidate()]

    try:
        result = run_candidate_pipeline(
            CONFIG,
            output_dir=output,
            top_k=1,
            dry_run=True,
            composition_producer=producer,
            runtime_preparer=lambda _candidate, _request: _runtime_fragment(),
        )
        connection.send(("ok", result["candidate_count"]))
    except BaseException as error:
        connection.send(("error", repr(error)))
    finally:
        connection.close()


class PipelineTests(unittest.TestCase):
    def test_dry_run_joins_one_candidate_with_typed_reference_free_requests(self) -> None:
        calls: list[str] = []

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"

            def assert_lease_is_active() -> None:
                state = json.loads((output / "memory_tokens.json").read_text(encoding="utf-8"))
                self.assertEqual(state["active_builds"], 1)

            def producer(request: GenerationRequest) -> list[dict[str, object]]:
                self.assertIsInstance(request, GenerationRequest)
                self.assertFalse(hasattr(request, "document"))
                self.assertFalse(hasattr(request, "reference"))
                self.assertFalse(hasattr(request, "path"))
                self.assertEqual(request.top_k, 1)
                self.assertTrue(request.dry_run)
                with self.assertRaises(FrozenInstanceError):
                    request.target_id = 999  # type: ignore[misc]
                assert_lease_is_active()
                calls.append("produce:1")
                return [_candidate()]

            def runtime(candidate: dict[str, object], request: RuntimeRequest) -> dict[str, object]:
                self.assertIsInstance(request, RuntimeRequest)
                self.assertFalse(hasattr(request, "document"))
                self.assertFalse(hasattr(request, "reference"))
                self.assertTrue(request.dry_run)
                self.assertEqual(candidate["candidate_id"], _candidate()["candidate_id"])
                assert_lease_is_active()
                calls.append("runtime")
                return _runtime_fragment()

            result = run_candidate_pipeline(
                CONFIG,
                output_dir=output,
                top_k=1,
                dry_run=True,
                composition_producer=producer,
                runtime_preparer=runtime,
                memory_state_path=output / "memory_tokens.json",
            )
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(
                set(result["groups"]),
                {"flat-direct", "candidate-direct", "candidate-depaware"},
            )
            self.assertEqual(result["memory"]["max_active_builds"], 1)
            self.assertEqual(result["memory"]["active_builds"], 0)
            self.assertEqual(len(result["memory"]["history"]), 2)
            self.assertFalse(result["reference_used"])
            self.assertEqual(calls, ["produce:1", "runtime"])
            self.assertEqual(len(tuple(output.glob("candidate-*.json"))), 1)
            self.assertEqual(result["manifests"][0]["lifecycle"], "runtime_ready")

    def test_pipeline_accepts_actual_harness_runtime_public_fragment(self) -> None:
        facts, composition, candidate = load_runtime_documents()
        experiment = json.loads(
            (ROOT / "configs/experiments/ibex_opentitan.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"

            def runtime(
                runtime_candidate: dict[str, object],
                _request: RuntimeRequest,
            ) -> object:
                return prepare_candidate_runtime(
                    facts,
                    composition,
                    runtime_candidate,
                    experiment,
                    Path(temporary),
                )

            result = run_candidate_pipeline(
                CONFIG,
                output_dir=output,
                top_k=1,
                dry_run=True,
                composition_producer=lambda _request: [candidate],
                runtime_preparer=runtime,
            )
            manifest = result["manifests"][0]
            self.assertEqual(manifest["candidate_id"], candidate["candidate_id"])
            self.assertTrue(
                all(
                    isinstance(manifest["harnesses"][group], dict)
                    for group in manifest["harnesses"]
                )
            )
            self.assertEqual(manifest["lifecycle"], "top_validated")

    def test_config_cannot_smuggle_reference_at_any_depth(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["target"]["metadata"] = {"reference_command": ["outside.sv"]}
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "bad.json"
            config.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reference_command"):
                run_candidate_pipeline(
                    config,
                    output_dir=Path(temporary) / "out",
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [],
                    runtime_preparer=lambda _candidate, _request: {},
                )

    def test_producer_and_runtime_outputs_cannot_smuggle_reference_fields(self) -> None:
        producer_candidate = _candidate()
        producer_candidate["reference_path"] = "/private/reference/original_top.sv"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "reference_path"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=Path(temporary) / "producer",
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [producer_candidate],
                    runtime_preparer=lambda _candidate, _request: _runtime_fragment(),
                )

            fragment = _runtime_fragment()
            fragment["files"] = {"reference": "/private/reference/original_top.sv"}
            with self.assertRaisesRegex(ValueError, "reference"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=Path(temporary) / "runtime",
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [_candidate()],
                    runtime_preparer=lambda _candidate, _request: fragment,
                )

            tuple_candidate = _candidate()
            tuple_candidate["metadata"] = (
                {"reference_path": "/private/reference/original_top.sv"},
            )
            with self.assertRaisesRegex(ValueError, "reference_path"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=Path(temporary) / "producer-tuple",
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [tuple_candidate],
                    runtime_preparer=lambda _candidate, _request: _runtime_fragment(),
                )

            tuple_fragment = _runtime_fragment()
            tuple_fragment["files"] = (
                {"reference": "/private/reference/original_top.sv"},
            )
            with self.assertRaisesRegex(ValueError, "reference"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=Path(temporary) / "runtime-tuple",
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [_candidate()],
                    runtime_preparer=lambda _candidate, _request: tuple_fragment,
                )

    def test_concurrent_pipeline_cannot_overwrite_the_same_output_directory(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            ready = context.Event()
            release = context.Event()
            parent_connection, child_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=_blocking_pipeline_worker,
                args=(output, ready, release, child_connection),
            )
            process.start()
            child_connection.close()
            try:
                self.assertTrue(ready.wait(timeout=3))
                with self.assertRaisesRegex(RuntimeError, "output directory.*in use"):
                    run_candidate_pipeline(
                        CONFIG,
                        output_dir=output,
                        top_k=1,
                        dry_run=True,
                        composition_producer=lambda _request: [_candidate()],
                        runtime_preparer=lambda _candidate, _request: _runtime_fragment(),
                    )
                release.set()
                self.assertTrue(parent_connection.poll(3))
                self.assertEqual(parent_connection.recv(), ("ok", 1))
            finally:
                release.set()
                process.join(timeout=3)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=3)
                parent_connection.close()
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(len(tuple(output.glob("candidate-*.json"))), 1)

    def test_different_output_directories_share_the_workspace_build_gate(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            entered = [context.Event(), context.Event()]
            release = [context.Event(), context.Event()]
            connections = [context.Pipe(duplex=False), context.Pipe(duplex=False)]
            processes = [
                context.Process(
                    target=_shared_gate_worker,
                    args=(
                        Path(temporary) / f"out-{index}",
                        entered[index],
                        release[index],
                        connections[index][1],
                    ),
                )
                for index in range(2)
            ]
            try:
                processes[0].start()
                connections[0][1].close()
                self.assertTrue(entered[0].wait(timeout=3))
                processes[1].start()
                connections[1][1].close()
                self.assertFalse(entered[1].wait(timeout=0.2))
                release[0].set()
                self.assertTrue(entered[1].wait(timeout=3))
                release[1].set()
                self.assertTrue(connections[0][0].poll(3))
                self.assertEqual(connections[0][0].recv(), ("ok", 1))
                self.assertTrue(connections[1][0].poll(3))
                self.assertEqual(connections[1][0].recv(), ("ok", 1))
            finally:
                for event in release:
                    event.set()
                for process in processes:
                    process.join(timeout=3)
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=3)
                for parent, _child in connections:
                    parent.close()
            self.assertEqual([process.exitcode for process in processes], [0, 0])

    def test_top_k_must_match_config_and_producer_count_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            with self.assertRaisesRegex(ValueError, "generated candidate count"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=output,
                    top_k=2,
                    dry_run=True,
                    composition_producer=lambda _request: [],
                    runtime_preparer=lambda _candidate, _request: {},
                )

            with self.assertRaisesRegex(ValueError, "exactly 1"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=output,
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [_candidate(), _candidate()],
                    runtime_preparer=lambda _candidate, _request: _runtime_fragment(),
                )

    def test_runtime_failure_releases_memory_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"

            def fail_runtime(_candidate: dict[str, object], _request: RuntimeRequest) -> object:
                raise RuntimeError("runtime failed")

            with self.assertRaisesRegex(RuntimeError, "runtime failed"):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=output,
                    top_k=1,
                    dry_run=True,
                    composition_producer=lambda _request: [_candidate()],
                    runtime_preparer=fail_runtime,
                    memory_state_path=output / "memory_tokens.json",
                )
            state = json.loads((output / "memory_tokens.json").read_text(encoding="utf-8"))
            self.assertEqual(state["active_bytes"], 0)
            self.assertEqual(state["active_builds"], 0)
            self.assertEqual(state["history"][-1]["status"], "failed")

    def test_multi_candidate_failure_publishes_nothing_and_can_be_retried(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["generated_candidates"]["count"] = 2
        first = _candidate()
        second = _candidate()
        second["candidate_id"] = "candidate-001"
        candidates = [first, second]

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "experiment.json"
            config.write_text(json.dumps(document), encoding="utf-8")
            output = Path(temporary) / "out"
            runtime_calls = 0

            def fail_second(
                _candidate_value: dict[str, object],
                _request: RuntimeRequest,
            ) -> dict[str, object]:
                nonlocal runtime_calls
                runtime_calls += 1
                if runtime_calls == 2:
                    raise RuntimeError("second runtime failed")
                return _runtime_fragment()

            with self.assertRaisesRegex(RuntimeError, "second runtime failed"):
                run_candidate_pipeline(
                    config,
                    output_dir=output,
                    top_k=2,
                    dry_run=True,
                    composition_producer=lambda _request: candidates,
                    runtime_preparer=fail_second,
                )
            self.assertEqual(tuple(output.glob("candidate-*.json")), ())

            result = run_candidate_pipeline(
                config,
                output_dir=output,
                top_k=2,
                dry_run=True,
                composition_producer=lambda _request: candidates,
                runtime_preparer=lambda _candidate_value, _request: _runtime_fragment(),
            )
            self.assertEqual(result["candidate_count"], 2)
            self.assertEqual(len(tuple(output.glob("candidate-*.json"))), 2)

    def test_second_candidate_serialization_failure_publishes_nothing(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["generated_candidates"]["count"] = 2
        first = _candidate()
        second = _candidate()
        second["candidate_id"] = "candidate-001"
        second["forward_data"] = {"not_json": {"value"}}

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "experiment.json"
            config.write_text(json.dumps(document), encoding="utf-8")
            output = Path(temporary) / "out"
            with self.assertRaisesRegex(TypeError, "JSON serializable"):
                run_candidate_pipeline(
                    config,
                    output_dir=output,
                    top_k=2,
                    dry_run=True,
                    composition_producer=lambda _request: [first, second],
                    runtime_preparer=lambda _candidate_value, _request: _runtime_fragment(),
                )
            self.assertEqual(tuple(output.glob("candidate-*.json")), ())

    def test_second_candidate_publish_failure_rolls_back_first_manifest(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["generated_candidates"]["count"] = 2
        first = _candidate()
        second = _candidate()
        second["candidate_id"] = "candidate-001"
        real_replace = os.replace

        def fail_second_publish(source: object, destination: object) -> None:
            if Path(destination).name == "candidate-001.json":
                raise OSError("second publish failed")
            real_replace(source, destination)

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "experiment.json"
            config.write_text(json.dumps(document), encoding="utf-8")
            output = Path(temporary) / "out"
            with mock.patch(
                "myfuzz.integration.pipeline.os.replace",
                side_effect=fail_second_publish,
            ), self.assertRaisesRegex(OSError, "second publish failed"):
                run_candidate_pipeline(
                    config,
                    output_dir=output,
                    top_k=2,
                    dry_run=True,
                    composition_producer=lambda _request: [first, second],
                    runtime_preparer=lambda _candidate_value, _request: _runtime_fragment(),
                )
            self.assertEqual(tuple(output.glob("candidate-*.json")), ())


if __name__ == "__main__":
    unittest.main()
