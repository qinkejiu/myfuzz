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
        peak_rss_bytes: int = MIB,
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
            "peak_rss_bytes": peak_rss_bytes,
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
            return BuildJobResult(job.job_id, 1)
        assert isinstance(job, ExperimentJob)
        return FuzzJobResult(job.job_id, 1, (self.sample(job),), MIB)

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
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            attempts[job.job_id] += 1
            if attempts[job.job_id] == 1:
                return ResourceCheckpointEvent(
                    job.job_id,
                    attempts[job.job_id],
                    4 * MIB,
                    "hard_memory_limit",
                    {"checkpoint_id": job.job_id},
                    (self.sample(job, resource_terminated=1, peak_rss_bytes=4 * MIB),),
                )
            self.assertIn(job.job_id, runner.persisted)
            return FuzzJobResult(job.job_id, attempts[job.job_id], (self.sample(job),), MIB)

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
        self.assertEqual(1, result["execution"]["checkpoints"][0]["attempt"])
        self.assertIn("job_id", result["execution"]["checkpoints"][0])
        self.assertEqual({2}, set(result["execution"]["attempts"].values()) - {1})

    def test_resource_retry_is_bounded_and_remains_distinct_from_dut_crash(self) -> None:
        attempts: defaultdict[str, int] = defaultdict(int)
        runner: RecordingRunner

        def execute(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            attempts[job.job_id] += 1
            if attempts[job.job_id] > 1:
                self.assertIn(job.job_id, runner.persisted)
            return ResourceCheckpointEvent(
                job.job_id,
                attempts[job.job_id],
                5 * MIB,
                "hard_memory_limit",
                {"attempt": attempts[job.job_id]},
                (self.sample(job, resource_terminated=1, peak_rss_bytes=5 * MIB),),
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

    def test_checkpoint_sink_cannot_mutate_validated_internal_event(self) -> None:
        class MutatingSinkRunner(RecordingRunner):
            def persist_checkpoint(inner_self, event: ResourceCheckpointEvent) -> None:
                super().persist_checkpoint(event)
                failures = event.samples[0]["failure_reasons"]
                assert isinstance(failures, dict)
                failures["resource_terminated"] = 0
                failures["dut_crash"] = 1

        def terminate(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            return ResourceCheckpointEvent(
                job.job_id,
                1,
                4 * MIB,
                "hard_memory_limit",
                {},
                (self.sample(job, resource_terminated=1, peak_rss_bytes=4 * MIB),),
            )

        result = run_experiment_matrix(
            self.config(retries=0),
            runner=MutatingSinkRunner(terminate),
            report_path=self.root / "mutating-sink.json",
        )
        runtime = result["report"]["candidates"]["candidate-000"]["budgets"]["smoke"][
            "harnesses"
        ]["candidate-depaware"]["runtime"]
        self.assertEqual(1, runtime["failure_reasons"]["resource_terminated"])
        self.assertEqual(0, runtime["failure_reasons"]["dut_crash"])

    def test_hard_limit_event_requires_actual_signal_rss_and_checkpoint_sink(self) -> None:
        def under_limit(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            return ResourceCheckpointEvent(
                job.job_id,
                1,
                3 * MIB,
                "hard_memory_limit",
                {},
                (self.sample(job, resource_terminated=1, peak_rss_bytes=3 * MIB),),
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
                    return BuildJobResult(job.job_id, 1)
                assert isinstance(job, ExperimentJob)
                return ResourceCheckpointEvent(
                    job.job_id,
                    1,
                    4 * MIB,
                    "hard_memory_limit",
                    {},
                    (self.sample(job, resource_terminated=1, peak_rss_bytes=4 * MIB),),
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
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            sample = self.sample(job)
            return FuzzJobResult(job.job_id, 1, (sample, copy.deepcopy(sample)), MIB)

        with self.assertRaisesRegex(ExperimentMatrixError, "duplicate"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(duplicate),
                report_path=self.root / "duplicate.json",
            )

        def wrong(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            sample = self.sample(job)
            sample["job_id"] = "fuzz-wrong"
            return FuzzJobResult(job.job_id, 1, (sample,), MIB)

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

    def test_runner_results_bind_current_attempt_and_reject_stale_retries(self) -> None:
        with self.assertRaisesRegex(ExperimentMatrixError, "attempt"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(
                    lambda job: BuildJobResult(job.job_id, 2)
                ),
                report_path=self.root / "stale-build.json",
            )

        def stale_build_event(job: Job) -> object:
            return ResourceCheckpointEvent(
                job.job_id,
                2,
                4 * MIB,
                "hard_memory_limit",
                {},
            )

        with self.assertRaisesRegex(ExperimentMatrixError, "attempt"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(stale_build_event),
                report_path=self.root / "stale-build-event.json",
            )

        attempts: defaultdict[str, int] = defaultdict(int)

        def stale_retry(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            attempts[job.job_id] += 1
            if attempts[job.job_id] == 1:
                return ResourceCheckpointEvent(
                    job.job_id,
                    1,
                    4 * MIB,
                    "hard_memory_limit",
                    {},
                    (self.sample(job, resource_terminated=1, peak_rss_bytes=4 * MIB),),
                )
            return FuzzJobResult(job.job_id, 1, (self.sample(job),), MIB)

        with self.assertRaisesRegex(ExperimentMatrixError, "attempt"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(stale_retry),
                report_path=self.root / "stale-retry.json",
            )

    def test_runner_rss_evidence_cannot_bypass_typed_result_boundary(self) -> None:
        def ordinary_resource_failure(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            return FuzzJobResult(
                job.job_id,
                1,
                (self.sample(job, resource_terminated=1),),
                MIB,
            )

        with self.assertRaisesRegex(ExperimentMatrixError, "resource_terminated"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(ordinary_resource_failure),
                report_path=self.root / "ordinary-resource.json",
            )

        def mismatched_peak(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            return FuzzJobResult(job.job_id, 1, (self.sample(job),), 2 * MIB)

        with self.assertRaisesRegex(ExperimentMatrixError, "peak_rss_bytes"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(mismatched_peak),
                report_path=self.root / "mismatched-peak.json",
            )

        def mismatched_event_peak(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            return ResourceCheckpointEvent(
                job.job_id,
                1,
                4 * MIB,
                "hard_memory_limit",
                {},
                (self.sample(job, resource_terminated=1, peak_rss_bytes=3 * MIB),),
            )

        with self.assertRaisesRegex(ExperimentMatrixError, "peak_rss_bytes"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(mismatched_event_peak),
                report_path=self.root / "mismatched-event-peak.json",
            )

        def zero_sample_peak(job: Job) -> object:
            if job.kind is JobKind.BUILD:
                return BuildJobResult(job.job_id, 1)
            assert isinstance(job, ExperimentJob)
            return FuzzJobResult(
                job.job_id,
                1,
                (self.sample(job, peak_rss_bytes=0),),
                MIB,
            )

        with self.assertRaisesRegex(ExperimentMatrixError, "positive integer"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(zero_sample_peak),
                report_path=self.root / "zero-sample-peak.json",
            )

    def test_report_parent_is_pinned_before_planning_side_effects(self) -> None:
        trusted = self.root / "trusted"
        moved = self.root / "pinned-parent"
        trusted.mkdir()
        with self.assertRaisesRegex(ExperimentMatrixError, "unsafe component"):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(self.successful_result),
                report_path=trusted / ".." / "unsafe.json",
            )
        original_plan = matrix_module.plan_experiment

        def swap_parent(*args: object, **kwargs: object) -> object:
            plan = original_plan(*args, **kwargs)
            trusted.rename(moved)
            trusted.mkdir()
            return plan

        with patch.object(matrix_module, "plan_experiment", side_effect=swap_parent):
            run_experiment_matrix(
                self.config(),
                runner=RecordingRunner(self.successful_result),
                report_path=trusted / "report.json",
            )

        self.assertTrue((moved / "report.json").is_file())
        self.assertFalse((trusted / "report.json").exists())

    def test_existing_report_inode_swap_fails_closed(self) -> None:
        report_path = self.root / "swapped.json"
        original_path = self.root / "original-report.json"
        report_path.write_text("previous\n", encoding="utf-8")
        original_builder = matrix_module.build_report

        def swap_destination(*args: object, **kwargs: object) -> object:
            report = original_builder(*args, **kwargs)
            report_path.rename(original_path)
            report_path.write_text("attacker\n", encoding="utf-8")
            return report

        with patch.object(matrix_module, "build_report", side_effect=swap_destination):
            with self.assertRaisesRegex(ExperimentMatrixError, "changed during execution"):
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        self.assertEqual("previous\n", original_path.read_text(encoding="utf-8"))
        self.assertEqual("attacker\n", report_path.read_text(encoding="utf-8"))

    def test_destination_swap_after_backup_fsync_fails_closed(self) -> None:
        report_path = self.root / "late-swap.json"
        original_path = self.root / "late-original.json"
        report_path.write_text("previous\n", encoding="utf-8")
        fsync_calls = 0

        def swap_after_backup(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            os.fsync(descriptor)
            if fsync_calls == 1:
                report_path.rename(original_path)
                report_path.write_text("attacker\n", encoding="utf-8")

        with patch.object(
            matrix_module,
            "_fsync_directory",
            side_effect=swap_after_backup,
        ):
            with self.assertRaisesRegex(ExperimentMatrixError, "changed during publication"):
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        self.assertEqual("previous\n", original_path.read_text(encoding="utf-8"))
        self.assertEqual("attacker\n", report_path.read_text(encoding="utf-8"))

    def test_failed_exchange_rollback_preserves_displaced_destination(self) -> None:
        report_path = self.root / "compound.json"
        original_path = self.root / "compound-original.json"
        report_path.write_text("previous\n", encoding="utf-8")
        original_exchange = matrix_module._exchange_names
        exchange_calls = 0
        fsync_calls = 0

        def fail_exchange_rollback(directory: int, first: str, second: str) -> None:
            nonlocal exchange_calls
            exchange_calls += 1
            if exchange_calls == 2:
                raise OSError("exchange rollback failed")
            original_exchange(directory, first, second)

        def swap_after_backup(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            os.fsync(descriptor)
            if fsync_calls == 1:
                report_path.rename(original_path)
                report_path.write_text("attacker\n", encoding="utf-8")

        with patch.object(
            matrix_module,
            "_exchange_names",
            side_effect=fail_exchange_rollback,
        ), patch.object(
            matrix_module,
            "_fsync_directory",
            side_effect=swap_after_backup,
        ):
            with self.assertRaisesRegex(
                ExperimentMatrixError,
                "changed during publication",
            ) as raised:
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        backups = list(self.root.glob(".compound.json.*.backup"))
        recoveries = list(self.root.glob(".compound.json.*.tmp"))
        notes = " ".join(getattr(raised.exception, "__notes__", ()))
        self.assertEqual("previous\n", original_path.read_text(encoding="utf-8"))
        self.assertNotEqual("attacker\n", report_path.read_text(encoding="utf-8"))
        self.assertEqual(1, len(backups))
        self.assertEqual("previous\n", backups[0].read_text(encoding="utf-8"))
        self.assertEqual(1, len(recoveries))
        self.assertEqual("attacker\n", recoveries[0].read_text(encoding="utf-8"))
        self.assertIn(backups[0].name, notes)
        self.assertIn(recoveries[0].name, notes)

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
        fsync_calls = 0

        def fail_publish_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError("directory fsync failed")
            os.fsync(descriptor)

        with patch.object(
            matrix_module,
            "_fsync_directory",
            side_effect=fail_publish_fsync,
        ):
            with self.assertRaisesRegex(OSError, "directory fsync failed"):
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        self.assertEqual("previous\n", report_path.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.root.glob(".durable.json.*.backup")))

    def test_backup_fsync_or_publish_replace_failure_keeps_original_report(self) -> None:
        for label, target in (("backup-fsync", "fsync"), ("publish-replace", "replace")):
            with self.subTest(label=label):
                report_path = self.root / f"{label}.json"
                report_path.write_text("previous\n", encoding="utf-8")
                patcher = (
                    patch.object(
                        matrix_module,
                        "_fsync_directory",
                        side_effect=OSError("backup fsync failed"),
                    )
                    if target == "fsync"
                    else patch.object(
                        matrix_module,
                        "_exchange_names",
                        side_effect=OSError("publish replace failed"),
                    )
                )
                with patcher:
                    with self.assertRaises(OSError):
                        run_experiment_matrix(
                            self.config(),
                            runner=RecordingRunner(self.successful_result),
                            report_path=report_path,
                        )
                self.assertEqual("previous\n", report_path.read_text(encoding="utf-8"))
                self.assertEqual([], list(self.root.glob(f".{label}.json.*.backup")))

    def test_rollback_fsync_failure_retains_backup_after_restoring_old_report(self) -> None:
        report_path = self.root / "rollback-fsync.json"
        report_path.write_text("previous\n", encoding="utf-8")
        fsync_calls = 0

        def fail_publish_and_rollback_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls >= 2:
                raise OSError(f"directory fsync failed {fsync_calls}")
            os.fsync(descriptor)

        with patch.object(
            matrix_module,
            "_fsync_directory",
            side_effect=fail_publish_and_rollback_fsync,
        ):
            with self.assertRaisesRegex(OSError, "directory fsync failed 2") as raised:
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        backups = list(self.root.glob(".rollback-fsync.json.*.backup"))
        self.assertEqual("previous\n", report_path.read_text(encoding="utf-8"))
        self.assertEqual(1, len(backups))
        self.assertIn(backups[0].name, " ".join(getattr(raised.exception, "__notes__", ())))

    def test_backup_cleanup_failure_keeps_committed_report_and_backup(self) -> None:
        report_path = self.root / "cleanup.json"
        report_path.write_text("previous\n", encoding="utf-8")
        original_unlink = matrix_module.os.unlink

        def fail_backup_cleanup(path: object, *args: object, **kwargs: object) -> None:
            if str(path).endswith(".backup"):
                raise OSError("backup cleanup failed")
            original_unlink(path, *args, **kwargs)

        with patch.object(matrix_module.os, "unlink", side_effect=fail_backup_cleanup):
            with self.assertRaisesRegex(OSError, "backup cleanup failed"):
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        backups = list(self.root.glob(".cleanup.json.*.backup"))
        self.assertEqual(1, len(backups))
        self.assertNotEqual("previous\n", report_path.read_text(encoding="utf-8"))
        self.assertEqual("previous\n", backups[0].read_text(encoding="utf-8"))

    def test_failed_rollback_preserves_recoverable_backup(self) -> None:
        report_path = self.root / "recoverable.json"
        report_path.write_text("previous\n", encoding="utf-8")

        def fail_rollback_replace(*args: object, **kwargs: object) -> None:
            raise OSError("rollback replace failed")

        def fail_published_fsync(descriptor: int) -> None:
            if report_path.read_text(encoding="utf-8") != "previous\n":
                raise OSError("publish fsync failed")
            os.fsync(descriptor)

        with patch.object(matrix_module.os, "replace", side_effect=fail_rollback_replace), patch.object(
            matrix_module,
            "_fsync_directory",
            side_effect=fail_published_fsync,
        ):
            with self.assertRaisesRegex(OSError, "publish fsync failed") as raised:
                run_experiment_matrix(
                    self.config(),
                    runner=RecordingRunner(self.successful_result),
                    report_path=report_path,
                )

        backups = list(self.root.glob(".recoverable.json.*.backup"))
        self.assertEqual(1, len(backups))
        self.assertEqual("previous\n", backups[0].read_text(encoding="utf-8"))
        self.assertIn(backups[0].name, " ".join(getattr(raised.exception, "__notes__", ())))


if __name__ == "__main__":
    unittest.main()
