from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest.mock import patch

from myfuzz.experiments import ExperimentJob, Job, JobKind
from myfuzz.integration import (
    BuildJobResult,
    ExperimentMatrixError,
    FuzzJobResult,
    ResourceCheckpointEvent,
    run_experiment_matrix,
)
from myfuzz.integration import experiment_matrix as matrix_module


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "contracts" / "candidate_manifest.v1.valid.json"
CONFIG = ROOT / "configs" / "experiments" / "rvx.json"
MIB = 1024 * 1024


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class RecordingRunner:
    def __init__(self, callback: object) -> None:
        self.callback = callback
        self.jobs: list[Job] = []
        self.persisted: list[str] = []

    def __call__(self, job: Job) -> object:
        self.jobs.append(job)
        assert callable(self.callback)
        return self.callback(job)

    def persist_checkpoint(self, event: ResourceCheckpointEvent) -> None:
        self.persisted.append(event.job_id)


class ExperimentMatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        planner_config = load_json(CONFIG)
        planner_config["candidate_selection"]["k"] = 1
        planner_config["candidate_pair"]["seeds"] = [17]
        planner_config["budgets"] = [
            {"name": "smoke", "kind": "cycles", "value": 1000}
        ]
        planner_config["soft_memory_bytes"] = 3 * MIB
        planner_config["hard_memory_bytes"] = 4 * MIB
        planner_config["token_bytes"] = MIB
        manifest = load_json(FIXTURE)
        manifest["resources"]["peak_rss_bytes"] = MIB
        self.planner_config = planner_config
        self.manifest = manifest
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.gates = self.root / "gates"
        self.previous_gate = os.environ.get("MYFUZZ_MEMORY_GATE_DIR")
        os.environ["MYFUZZ_MEMORY_GATE_DIR"] = str(self.gates)

    def tearDown(self) -> None:
        if self.previous_gate is None:
            os.environ.pop("MYFUZZ_MEMORY_GATE_DIR", None)
        else:
            os.environ["MYFUZZ_MEMORY_GATE_DIR"] = self.previous_gate
        self.temporary_directory.cleanup()

    def config(
        self,
        *,
        seed: int = 29,
        retries: int = 1,
        reference: dict[str, object] | None = None,
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "planner_config": copy.deepcopy(self.planner_config),
            "candidate_manifests": [copy.deepcopy(self.manifest)],
            "execution": {
                "interleaving_seed": seed,
                "max_resource_retries": retries,
                "job_timeout_seconds": 0,
            },
        }
        if reference is not None:
            value["reference_summary"] = copy.deepcopy(reference)
        return value

    @staticmethod
    def sample(
        job: ExperimentJob,
        *,
        resource_terminated: int = 0,
    ) -> dict[str, object]:
        return {
            "job_id": job.job_id,
            "candidate_id": job.candidate_id,
            "harness": job.harness,
            "seed": job.seed,
            "elapsed_seconds": 0,
            "sequence": 0,
            "common_total": 0,
            "covered_point_ids": [],
            "tests_executed": 0,
            "cycles_executed": 0,
            "peak_rss_bytes": MIB,
            "projection_count": 0,
            "correction_counts": {},
            "protocol_event_count": 0,
            "no_progress_cycles": 0,
            "generation_count": 0,
            "validation_passed": 0,
            "failure_reasons": {
                "dut_crash": 0,
                "resource_terminated": resource_terminated,
            },
        }

    def successful_result(self, job: Job) -> object:
        if job.kind is JobKind.BUILD:
            return BuildJobResult(job.job_id)
        assert isinstance(job, ExperimentJob)
        return FuzzJobResult(job.job_id, (self.sample(job),), MIB)

    def run_success(
        self,
        *,
        seed: int = 29,
        reference: dict[str, object] | None = None,
        name: str = "report.json",
    ) -> tuple[dict[str, object], RecordingRunner]:
        runner = RecordingRunner(self.successful_result)
        result = run_experiment_matrix(
            self.config(seed=seed, reference=reference),
            runner=runner,
            report_path=self.root / name,
        )
        return result, runner

    def test_public_entry_point_runs_build_and_fair_fuzz_jobs_without_build_samples(self) -> None:
        result, runner = self.run_success()

        builds = [job for job in runner.jobs if job.kind is JobKind.BUILD]
        fuzz = [job for job in runner.jobs if job.kind is JobKind.FUZZ]
        self.assertEqual(1, len(builds))
        self.assertEqual(3, len(fuzz))
        by_harness = {job.harness: job for job in fuzz if isinstance(job, ExperimentJob)}
        direct = by_harness["candidate-direct"]
        depaware = by_harness["candidate-depaware"]
        self.assertEqual(direct.candidate_hash, depaware.candidate_hash)
        self.assertEqual(direct.raw_width, depaware.raw_width)
        self.assertEqual(direct.instrumented_rtl_hash, depaware.instrumented_rtl_hash)
        self.assertEqual(direct.coverage_universe, depaware.coverage_universe)
        self.assertEqual(direct.mutation, depaware.mutation)
        self.assertEqual(direct.seed, depaware.seed)
        self.assertEqual(direct.budget_value, depaware.budget_value)
        self.assertNotEqual(by_harness["flat-direct"].coverage_universe, direct.coverage_universe)
        self.assertEqual("experiment_report.v1", result["report"]["schema_version"])
        self.assertNotIn(builds[0].job_id, json.dumps(result["report"], sort_keys=True))

    def test_interleaving_seed_is_stable_and_does_not_change_job_identity(self) -> None:
        first, first_runner = self.run_success(seed=5, name="first.json")
        repeated, repeated_runner = self.run_success(seed=5, name="repeat.json")
        changed, changed_runner = self.run_success(seed=11, name="changed.json")

        first_order = first["execution"]["execution_order"]
        self.assertEqual(first_order, repeated["execution"]["execution_order"])
        self.assertNotEqual(first_order, changed["execution"]["execution_order"])
        self.assertEqual(
            {job.job_id for job in first_runner.jobs},
            {job.job_id for job in changed_runner.jobs},
        )
        self.assertEqual(first["report"]["plan_hash"], changed["report"]["plan_hash"])
        self.assertEqual(5, first["execution"]["interleaving_seed"])
        self.assertEqual(
            [job.job_id for job in repeated_runner.jobs],
            repeated["execution"]["execution_order"],
        )

    def test_every_runner_exit_releases_the_exact_b_job_lease(self) -> None:
        for label, error in (
            ("error", RuntimeError("runner failed")),
            ("base", KeyboardInterrupt()),
        ):
            runner = RecordingRunner(lambda _job, error=error: (_ for _ in ()).throw(error))
            with self.subTest(label=label):
                with self.assertRaises(type(error)):
                    run_experiment_matrix(
                        self.config(),
                        runner=runner,
                        report_path=self.root / f"{label}.json",
                    )
                self.assertEqual([], list(self.gates.glob("*.lock")))

        self.run_success(name="success.json")
        self.assertEqual([], list(self.gates.glob("*.lock")))

    def test_resource_checkpoints_are_persisted_before_lowest_priority_retries(self) -> None:
        config = self.config(retries=1)
        config["planner_config"]["budgets"] = [
            {"name": "low", "kind": "cycles", "value": 100},
            {"name": "middle", "kind": "cycles", "value": 200},
            {"name": "top", "kind": "cycles", "value": 300},
        ]
        attempts: defaultdict[str, int] = defaultdict(int)
        runner: RecordingRunner

        def execute(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id)
            assert isinstance(job, ExperimentJob)
            attempts[job.job_id] += 1
            if attempts[job.job_id] == 1:
                return ResourceCheckpointEvent(
                    job.job_id,
                    4 * MIB,
                    "hard_memory_limit",
                    {"checkpoint_id": job.job_id},
                    (self.sample(job, resource_terminated=1),),
                )
            self.assertIn(job.job_id, runner.persisted)
            return FuzzJobResult(job.job_id, (self.sample(job),), MIB)

        runner = RecordingRunner(execute)
        result = run_experiment_matrix(
            config,
            runner=runner,
            report_path=self.root / "resource.json",
        )

        fuzz_calls = [job for job in runner.jobs if isinstance(job, ExperimentJob)]
        retry_calls = [job for job in fuzz_calls if attempts[job.job_id] == 2][-9:]
        self.assertEqual(sorted(job.priority for job in retry_calls), [job.priority for job in retry_calls])
        self.assertEqual(9, len(result["execution"]["checkpoints"]))
        self.assertEqual({2}, set(result["execution"]["attempts"].values()) - {1})

    def test_resource_retry_is_bounded_and_remains_distinct_from_dut_crash(self) -> None:
        attempts: defaultdict[str, int] = defaultdict(int)
        runner: RecordingRunner

        def execute(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id)
            assert isinstance(job, ExperimentJob)
            attempts[job.job_id] += 1
            if attempts[job.job_id] > 1:
                self.assertIn(job.job_id, runner.persisted)
            return ResourceCheckpointEvent(
                job.job_id,
                5 * MIB,
                "hard_memory_limit",
                {"attempt": attempts[job.job_id]},
                (self.sample(job, resource_terminated=1),),
            )

        runner = RecordingRunner(execute)
        result = run_experiment_matrix(
            self.config(retries=1),
            runner=runner,
            report_path=self.root / "bounded.json",
        )

        self.assertEqual({2}, set(attempts.values()))
        runtime = result["report"]["candidates"]["candidate-000"]["budgets"]["smoke"][
            "harnesses"
        ]["candidate-depaware"]["runtime"]
        self.assertEqual(1, runtime["failure_reasons"]["resource_terminated"])
        self.assertEqual(0, runtime["failure_reasons"]["dut_crash"])
        self.assertEqual(6, len(result["execution"]["checkpoints"]))

    def test_hard_limit_event_requires_actual_signal_rss_and_checkpoint_sink(self) -> None:
        def under_limit(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id)
            assert isinstance(job, ExperimentJob)
            return ResourceCheckpointEvent(
                job.job_id,
                3 * MIB,
                "hard_memory_limit",
                {},
                (self.sample(job, resource_terminated=1),),
            )

        with self.assertRaisesRegex(ExperimentMatrixError, "hard_memory_bytes"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(under_limit),
                report_path=self.root / "under-limit.json",
            )

        class NoCheckpointSink:
            def __call__(inner_self, job: Job) -> object:
                if job.kind is JobKind.BUILD:
                    return BuildJobResult(job.job_id)
                assert isinstance(job, ExperimentJob)
                return ResourceCheckpointEvent(
                    job.job_id,
                    4 * MIB,
                    "hard_memory_limit",
                    {},
                    (self.sample(job, resource_terminated=1),),
                )

        with self.assertRaisesRegex(ExperimentMatrixError, "persist_checkpoint"):
            run_experiment_matrix(
                self.config(),
                runner=NoCheckpointSink(),
                report_path=self.root / "no-sink.json",
            )

    def test_fuzz_samples_fail_closed_on_duplicate_or_wrong_identity(self) -> None:
        def duplicate(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id)
            assert isinstance(job, ExperimentJob)
            sample = self.sample(job)
            return FuzzJobResult(job.job_id, (sample, copy.deepcopy(sample)), MIB)

        with self.assertRaisesRegex(ExperimentMatrixError, "duplicate"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(duplicate),
                report_path=self.root / "duplicate.json",
            )

        def wrong(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id)
            assert isinstance(job, ExperimentJob)
            sample = self.sample(job)
            sample["job_id"] = "fuzz-wrong"
            return FuzzJobResult(job.job_id, (sample,), MIB)

        with self.assertRaisesRegex(ExperimentMatrixError, "job_id"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(wrong),
                report_path=self.root / "wrong.json",
            )

    def test_reference_is_descriptive_and_does_not_change_plan_or_interleaving(self) -> None:
        reference = {
            "comparison_scope": "reference-descriptive",
            "stable_source_ids": [],
            "covered_stable_source_ids": [],
        }
        plain, _ = self.run_success(seed=41, name="plain.json")
        described, _ = self.run_success(seed=41, reference=reference, name="reference.json")

        self.assertEqual(plain["report"]["plan_hash"], described["report"]["plan_hash"])
        self.assertEqual(
            plain["execution"]["execution_order"],
            described["execution"]["execution_order"],
        )
        budget = described["report"]["candidates"]["candidate-000"]["budgets"]["smoke"]
        self.assertEqual("reference-descriptive", budget["reference_comparison"]["comparison_scope"])

    def test_report_receives_only_manifests_selected_by_the_b_planner(self) -> None:
        second = copy.deepcopy(self.manifest)
        second["candidate_id"] = "candidate-z"
        second["build_cache_key"] = "sha256:" + "f" * 64
        config = self.config()
        config["candidate_manifests"].append(second)

        result = run_experiment_matrix(
            config,
            runner=RecordingRunner(self.successful_result),
            report_path=self.root / "selected.json",
        )

        self.assertEqual(["candidate-000"], list(result["report"]["candidates"]))

    def test_config_and_runner_results_are_strictly_validated(self) -> None:
        invalid = self.config()
        invalid["unexpected"] = True
        with self.assertRaisesRegex(ExperimentMatrixError, "unexpected"):
            run_experiment_matrix(
                invalid,
                runner=RecordingRunner(self.successful_result),
                report_path=self.root / "invalid.json",
            )

        with self.assertRaisesRegex(ExperimentMatrixError, "BuildJobResult"):
            run_experiment_matrix(
                self.config(),
                runner=lambda _job: {"status": "completed"},
                report_path=self.root / "mapping.json",
            )

    def test_atomic_write_preserves_existing_report_and_rejects_symlinks(self) -> None:
        report_path = self.root / "atomic.json"
        report_path.write_text("previous\n", encoding="utf-8")
        with patch.object(matrix_module, "_write_all", side_effect=OSError("write failed")):
            with self.assertRaises(OSError):
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )
        self.assertEqual("previous\n", report_path.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.root.glob(".*.tmp")))

        external = self.root / "external.json"
        external.write_text("external\n", encoding="utf-8")
        symlink = self.root / "report-link.json"
        symlink.symlink_to(external)
        with self.assertRaisesRegex(ExperimentMatrixError, "symlink"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(self.successful_result),
                report_path=symlink,
            )
        self.assertEqual("external\n", external.read_text(encoding="utf-8"))

    def test_parent_fsync_failure_rolls_back_an_existing_report(self) -> None:
        report_path = self.root / "durable.json"
        report_path.write_text("previous\n", encoding="utf-8")

        with patch.object(
            matrix_module,
            "_fsync_directory",
            side_effect=OSError("directory fsync failed"),
        ):
            with self.assertRaisesRegex(OSError, "directory fsync failed"):
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        self.assertEqual("previous\n", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
