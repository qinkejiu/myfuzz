"""Side-effect-free RFuzz installation discovery."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .planner import ExperimentBuildJob, ExperimentJob, RfuzzExecution


_FLOW_ROOT = "third_party/rfuzz/rfuzz_flow"
_FUZZER = "third_party/rfuzz/rfuzz_flow/fuzzer/target/release/kfuzz"
_DRIVER = "src/myfuzz/scripts/run_design_flow.py"


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
            (_FUZZER, "executable"),
        )
        missing: list[str] = []
        for relative, kind in requirements:
            path = self._repo_root / relative
            present = path.is_dir() if kind == "directory" else path.is_file()
            if kind == "executable" and present:
                present = os.access(path, os.X_OK)
            if not present:
                missing.append(relative)
        return RfuzzAvailability(not missing, tuple(missing))

    def command(
        self,
        job: ExperimentBuildJob | ExperimentJob,
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
        if execution.seed is not None:
            command.extend(("--seed", str(execution.seed)))
        if execution.fuzz_seconds is not None:
            command.extend(("--fuzz-seconds", str(execution.fuzz_seconds)))
        if execution.max_cycles is not None:
            command.extend(("--max-cycles", str(execution.max_cycles)))
        return tuple(command)
