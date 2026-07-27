from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from myfuzz.experiments.jobs import JobKind
from myfuzz.experiments.planner import (
    ExperimentBuildJob,
    ExperimentJob,
    RfuzzExecution,
    plan_experiment,
)
from myfuzz.experiments.rfuzz_adapter import RfuzzAdapter


ROOT = Path(__file__).resolve().parents[2]


def job(
    *,
    budget_kind: str,
    budget_value: int,
    candidate_mode: str = "candidate_depaware",
    harness: str = "candidate-depaware",
    artifact_id: str | None = None,
    build_job_id: str = "",
) -> ExperimentJob:
    execution = RfuzzExecution(
        design_config_path="configs/designs/runtime/config.json",
        stage="fuzz",
        worker_count=1,
        candidate_mode=candidate_mode,
        server_artifact_id=artifact_id,
        seed=19,
        fuzz_seconds=budget_value if budget_kind == "seconds" else None,
        max_cycles=budget_value if budget_kind == "cycles" else None,
    )
    return ExperimentJob(
        job_id=f"job-{budget_kind}",
        kind=JobKind.FUZZ,
        gate_name="fuzz",
        owner=f"owner-{budget_kind}",
        requested_mib=64,
        seed=19,
        candidate_hash="sha256:" + "1" * 64,
        build_cache_key="sha256:" + "2" * 64,
        worker_limit=1,
        target_id="target-opaque",
        candidate_id="candidate-opaque",
        harness=harness,
        budget_kind=budget_kind,
        budget_value=budget_value,
        config_path="configs/experiments/runtime.json",
        estimated_rss_bytes=64_000_000,
        priority=1,
        budget_name=budget_kind,
        raw_width=18,
        instrumented_rtl_hash="sha256:" + "3" * 64,
        coverage_universe="sha256:" + "4" * 64,
        coverage_metadata_hash="sha256:" + "5" * 64,
        mutation=(("max_len", 4096),),
        execution=execution,
        build_job_id=build_job_id,
    )


def build_job(
    *,
    candidate_mode: str | None = None,
    harness: str = "",
    artifact_id: str = "",
) -> ExperimentBuildJob:
    return ExperimentBuildJob(
        job_id="job-build",
        kind=JobKind.BUILD,
        gate_name="build",
        owner="owner-build",
        requested_mib=64,
        seed=0,
        candidate_hash="sha256:" + "1" * 64,
        build_cache_key="sha256:" + "2" * 64,
        worker_limit=1,
        harness=harness,
        artifact_id=artifact_id,
        execution=RfuzzExecution(
            design_config_path="configs/designs/runtime/config.json",
            stage="server",
            worker_count=1,
            candidate_mode=candidate_mode,
            server_artifact_id=artifact_id or None,
        ),
    )


def static_plan():
    config = json.loads((ROOT / "configs/experiments/rvx.json").read_text(encoding="utf-8"))
    config["harness_groups"] = ["flat-direct", "candidate-direct", "candidate-static"]
    config["coverage"]["comparisons"][0]["right_harness"] = "candidate-static"
    manifest = json.loads(
        (ROOT / "tests/fixtures/contracts/candidate_manifest.v1.valid.json").read_text(
            encoding="utf-8"
        )
    )
    manifest["candidate_id"] = "candidate-static-test"
    manifest["build_cache_key"] = "sha256:" + hashlib.sha256(
        manifest["candidate_id"].encode("utf-8")
    ).hexdigest()
    manifest["harnesses"]["candidate-static"] = {
        "raw_width": 1,
        "content_hash": "sha256:" + "a" * 64,
        "abi_hash": "sha256:" + "b" * 64,
        "projection_plan_hash": "sha256:" + "c" * 64,
    }
    return plan_experiment(config, [copy.deepcopy(manifest)])


class RfuzzAdapterTest(unittest.TestCase):
    def test_execution_addition_preserves_existing_positional_parameters(self) -> None:
        execution = RfuzzExecution(
            "configs/designs/runtime/config.json",
            "fuzz",
            1,
            "candidate_direct",
            7,
            None,
            1_000,
        )

        self.assertEqual(7, execution.seed)
        self.assertEqual(1_000, execution.max_cycles)
        self.assertIsNone(execution.server_artifact_id)

    def test_static_candidate_mode_reaches_the_existing_driver(self) -> None:
        static_job = job(
            budget_kind="seconds",
            budget_value=60,
            candidate_mode="candidate_static",
            harness="candidate-static",
        )

        command = RfuzzAdapter(Path.cwd()).command(static_job)

        self.assertEqual(
            "candidate_static",
            command[command.index("--candidate-mode") + 1],
        )

    def test_planned_build_and_fuzz_commands_select_the_bound_artifacts(self) -> None:
        plan = static_plan()
        builds = {build.job_id: build for build in plan.build_jobs}
        direct_fuzz = next(job for job in plan.jobs if job.harness == "candidate-direct")
        static_fuzz = next(job for job in plan.jobs if job.harness == "candidate-static")
        static_build = builds[static_fuzz.build_job_id]

        for planned_job in (direct_fuzz, static_build, static_fuzz):
            build = planned_job if isinstance(planned_job, ExperimentBuildJob) else builds[planned_job.build_job_id]
            command = RfuzzAdapter(Path.cwd()).command(planned_job)
            with self.subTest(harness=planned_job.harness, stage=planned_job.execution.stage):
                self.assertEqual(build.artifact_id, planned_job.execution.server_artifact_id)
                self.assertEqual(
                    build.artifact_id,
                    command[command.index("--server-artifact-id") + 1],
                )
                self.assertEqual(
                    build.execution.candidate_mode,
                    command[command.index("--candidate-mode") + 1],
                )

    def test_planned_build_and_fuzz_commands_forward_matrix_hard_memory(self) -> None:
        plan = static_plan()

        for planned_job in (*plan.build_jobs, *plan.jobs):
            command = RfuzzAdapter(ROOT).command(planned_job)
            with self.subTest(job_id=planned_job.job_id):
                self.assertEqual(
                    plan.runtime_policy.hard_memory_bytes,
                    planned_job.execution.hard_memory_bytes,
                )
                self.assertEqual(
                    str(plan.runtime_policy.hard_memory_bytes),
                    command[command.index("--hard-memory-bytes") + 1],
                )

    def test_constructs_supported_fixed_runtime_commands_without_waveforms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            adapter = RfuzzAdapter(Path(directory).resolve())
            build = adapter.command(build_job())
            seconds = adapter.command(job(budget_kind="seconds", budget_value=300))
            cycles = adapter.command(job(budget_kind="cycles", budget_value=1000))

        for command in (build, seconds, cycles):
            self.assertIsInstance(command, tuple)
            self.assertEqual(sys.executable, command[0])
            self.assertEqual("src/myfuzz/scripts/run_design_flow.py", command[1])
            self.assertEqual(
                "configs/designs/runtime/config.json",
                command[command.index("--config") + 1],
            )
            self.assertIn("--stage", command)
            self.assertEqual("1", command[command.index("--jobs") + 1])
            self.assertFalse(any("trace" in item.lower() for item in command))
            self.assertFalse(any(suffix in " ".join(command).lower() for suffix in (".vcd", ".fst")))
        self.assertEqual("server", build[build.index("--stage") + 1])
        self.assertNotIn("--seed", build)
        self.assertNotIn("--fuzz-seconds", build)
        self.assertNotIn("--max-cycles", build)
        for command in (seconds, cycles):
            self.assertEqual("fuzz", command[command.index("--stage") + 1])
            self.assertEqual("19", command[command.index("--seed") + 1])
            self.assertEqual(
                "candidate_depaware",
                command[command.index("--candidate-mode") + 1],
            )
        self.assertEqual("300", seconds[seconds.index("--fuzz-seconds") + 1])
        self.assertNotIn("--max-cycles", seconds)
        self.assertEqual("1000", cycles[cycles.index("--max-cycles") + 1])
        self.assertNotIn("--fuzz-seconds", cycles)

    def test_result_document_path_is_forwarded_to_the_existing_driver(self) -> None:
        adapter = RfuzzAdapter(ROOT)

        command = adapter.command(
            build_job(),
            result_json=Path("runs/results/job-build.json"),
        )

        self.assertEqual(
            "runs/results/job-build.json",
            command[command.index("--result-json") + 1],
        )
        with self.assertRaisesRegex(ValueError, "repository-relative"):
            adapter.command(build_job(), result_json=Path("../outside.json"))

    def test_fuzz_command_forwards_planned_job_binding(self) -> None:
        artifact_id = "sha256:" + "a" * 64
        planned = job(
            budget_kind="seconds",
            budget_value=1,
            artifact_id=artifact_id,
            build_job_id="build-bound",
        )

        command = RfuzzAdapter(ROOT).command(planned)

        self.assertEqual(planned.job_id, command[command.index("--job-id") + 1])
        self.assertEqual(
            artifact_id,
            command[command.index("--server-artifact-id") + 1],
        )

    def test_reports_missing_fixed_installation_paths_without_importing_rfuzz(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            availability = RfuzzAdapter(Path(directory).resolve()).availability()

        self.assertFalse(availability.available)
        self.assertEqual(
            (
                "src/myfuzz/scripts/run_design_flow.py",
                "third_party/rfuzz/rfuzz_flow",
                "third_party/rfuzz/rfuzz_flow/verilator/top.cpp",
                "third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.cpp",
                "third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.hpp",
                "third_party/rfuzz/rfuzz_flow/fuzzer/target/release/kfuzz",
            ),
            availability.missing_paths,
        )

    def test_old_flow_and_fuzzer_without_original_server_sources_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            driver = root / "src/myfuzz/scripts/run_design_flow.py"
            driver.parent.mkdir(parents=True)
            driver.touch()
            flow = root / "third_party/rfuzz/rfuzz_flow"
            fuzzer = flow / "fuzzer/target/release/kfuzz"
            fuzzer.parent.mkdir(parents=True)
            fuzzer.write_text("#!/bin/sh\n", encoding="utf-8")
            fuzzer.chmod(0o755)

            availability = RfuzzAdapter(root).availability()

        self.assertFalse(availability.available)
        self.assertEqual(
            (
                "third_party/rfuzz/rfuzz_flow/verilator/top.cpp",
                "third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.cpp",
                "third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.hpp",
            ),
            availability.missing_paths,
        )


if __name__ == "__main__":
    unittest.main()
