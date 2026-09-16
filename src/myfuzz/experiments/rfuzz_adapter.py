"""Side-effect-free RFuzz installation discovery."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
import stat

from .planner import ExperimentBuildJob, ExperimentJob, RfuzzExecution


_FLOW_ROOT = "third_party/rfuzz/rfuzz_flow"
_FUZZER = "third_party/rfuzz/rfuzz_flow/fuzzer/target/release/kfuzz"
_DRIVER = "src/myfuzz/scripts/run_design_flow.py"
_TOP_CPP = "third_party/rfuzz/rfuzz_flow/verilator/top.cpp"
_QUEUE_CPP = "third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.cpp"
_QUEUE_HPP = "third_party/rfuzz/rfuzz_flow/verilator/fpga_queue.hpp"
_FUZZER_HPP = "third_party/rfuzz/rfuzz_flow/verilator/fuzzer.hpp"


@dataclass(frozen=True, slots=True)
class RfuzzAvailability:
    available: bool
    missing_paths: tuple[str, ...]


class RfuzzAdapter:
    """Inspect only fixed paths beneath an explicit repository root."""

    def __init__(self, repo_root: Path) -> None:
        if not isinstance(repo_root, Path):
            raise TypeError("repo_root must be a pathlib.Path")
        if not repo_root.is_absolute():
            raise ValueError("repo_root must be absolute")
        self._repo_root = repo_root

    def availability(self) -> RfuzzAvailability:
        requirements = (
            (_DRIVER, "file"),
            (_FLOW_ROOT, "directory"),
            (_TOP_CPP, "file"),
            (_QUEUE_CPP, "file"),
            (_QUEUE_HPP, "file"),
            (_FUZZER_HPP, "file"),
            (_FUZZER, "executable"),
        )
        missing: list[str] = []
        for relative, kind in requirements:
            path = self._repo_root / relative
            try:
                metadata = path.lstat()
            except OSError:
                present = False
            else:
                present = not path.is_symlink() and (
                    stat.S_ISDIR(metadata.st_mode)
                    if kind == "directory"
                    else stat.S_ISREG(metadata.st_mode)
                )
            if kind == "executable" and present:
                present = os.access(path, os.X_OK)
            if not present:
                missing.append(relative)
        return RfuzzAvailability(not missing, tuple(missing))

    def command(
        self,
        job: ExperimentBuildJob | ExperimentJob,
        *,
        result_json: Path | None = None,
    ) -> tuple[str, ...]:
        """Return one deterministic single-worker driver command without executing it."""
        if not isinstance(job, (ExperimentBuildJob, ExperimentJob)):
            raise TypeError("job must carry an RFuzz execution descriptor")
        execution = job.execution
        if not isinstance(execution, RfuzzExecution):
            raise TypeError("job execution must be an RfuzzExecution")
        config_path = Path(execution.design_config_path)
        command = [
            sys.executable,
            _DRIVER,
            "--config",
            config_path.as_posix(),
            "--stage",
            execution.stage,
            "--jobs",
            str(execution.worker_count),
        ]
        if execution.candidate_mode is not None:
            command.extend(("--candidate-mode", execution.candidate_mode))
        if execution.server_artifact_id is not None:
            command.extend(("--server-artifact-id", execution.server_artifact_id))
        if execution.server_input_identity is not None:
            command.extend(("--server-input-identity", execution.server_input_identity))
        if execution.seed is not None:
            command.extend(("--seed", str(execution.seed)))
        if execution.fuzz_seconds is not None:
            command.extend(("--fuzz-seconds", str(execution.fuzz_seconds)))
        if execution.max_cycles is not None:
            command.extend(("--max-cycles", str(execution.max_cycles)))
        if isinstance(job, ExperimentJob):
            command.extend(("--job-id", job.job_id))
        if execution.hard_memory_bytes is not None:
            command.extend(("--hard-memory-bytes", str(execution.hard_memory_bytes)))
        if result_json is not None:
            if not isinstance(result_json, Path):
                raise TypeError("result_json must be a pathlib.Path")
            if result_json.is_absolute() or any(
                part in {"", ".", ".."} for part in result_json.parts
            ):
                raise ValueError("result_json must be a repository-relative path")
            command.extend(("--result-json", result_json.as_posix()))
        return tuple(command)
