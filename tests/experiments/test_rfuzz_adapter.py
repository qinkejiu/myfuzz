from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from myfuzz.experiments.jobs import JobKind
from myfuzz.experiments.planner import (
    ExperimentBuildJob,
    ExperimentJob,
    RfuzzExecution,
)
from myfuzz.experiments.rfuzz_adapter import RfuzzAdapter


def job(*, budget_kind: str, budget_value: int) -> ExperimentJob:
    execution = RfuzzExecution(
        design_config_path="configs/designs/runtime/config.json",
        stage="fuzz",
        worker_count=1,
        candidate_mode="candidate_depaware",
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
        harness="candidate-depaware",
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
    )


def build_job() -> ExperimentBuildJob:
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
        execution=RfuzzExecution(
            design_config_path="configs/designs/runtime/config.json",
            stage="server",
            worker_count=1,
        ),
    )


class RfuzzAdapterTest(unittest.TestCase):
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

    def test_reports_missing_fixed_installation_paths_without_importing_rfuzz(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            availability = RfuzzAdapter(Path(directory).resolve()).availability()

        self.assertFalse(availability.available)
        self.assertEqual(
            (
                "src/myfuzz/scripts/run_design_flow.py",
                "third_party/rfuzz/rfuzz_flow",
                "third_party/rfuzz/rfuzz_flow/fuzzer/target/release/kfuzz",
            ),
            availability.missing_paths,
        )


if __name__ == "__main__":
    unittest.main()
