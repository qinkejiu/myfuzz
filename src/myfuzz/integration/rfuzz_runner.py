"""Concrete typed boundary for the existing RFuzz design-flow driver."""

from __future__ import annotations

import copy
import json
import math
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from myfuzz.experiments.planner import ExperimentBuildJob, ExperimentJob
from myfuzz.experiments.rfuzz_adapter import RfuzzAdapter
from myfuzz.contracts import canonical_bytes, content_hash, validate_contract

from .experiment_matrix import (
    BuildJobResult,
    FuzzJobResult,
    ResourceCheckpointEvent,
    RunnerResult,
)


_BUILD_KEYS = frozenset(("kind", "artifact_id", "server_path", "server_exists"))
_FUZZ_KEYS = frozenset((
    "kind", "elapsed_seconds", "tests_executed", "cycles_executed",
    "coverage_point_count", "covered_point_ids", "peak_rss_bytes",
    "server_returncode", "fuzzer_returncode", "handshake_succeeded",
    "fifo_cleanup_succeeded", "failure_reasons",
))
_MAX_RESULT_BYTES = 1024 * 1024


def _atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _closed_object(value: object, keys: frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    if set(value) != keys:
        raise ValueError(f"{label} fields do not match the published result schema")
    return value


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (1 if positive else 0):
        raise ValueError(f"{label} must be a {'positive' if positive else 'non-negative'} integer")
    return value


def _returncode(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


class RfuzzExperimentRunner:
    """Execute one planned RFuzz job and map one validated result document."""

    def __init__(self, repo_root: Path, result_dir: Path) -> None:
        if not isinstance(repo_root, Path) or not repo_root.is_absolute():
            raise ValueError("repo_root must be an absolute pathlib.Path")
        if not isinstance(result_dir, Path) or not result_dir.is_absolute():
            raise ValueError("result_dir must be an absolute pathlib.Path")
        root = repo_root.resolve()
        results = result_dir.resolve()
        try:
            results.relative_to(root)
        except ValueError as error:
            raise ValueError("result_dir must be beneath repo_root") from error
        self._repo_root = root
        self._result_dir = results
        self._adapter = RfuzzAdapter(root)
        self._attempts: dict[str, int] = {}

    def __call__(self, job: object) -> RunnerResult:
        if not isinstance(job, (ExperimentBuildJob, ExperimentJob)):
            raise TypeError("job must be a planned RFuzz build or fuzz job")
        attempt = self._attempts.get(job.job_id, 0) + 1
        self._attempts[job.job_id] = attempt
        name = f"{job.job_id}.{attempt}.{secrets.token_hex(8)}.json"
        destination = self._result_dir / name
        relative = destination.relative_to(self._repo_root)
        started_ns = time.time_ns()
        completed = subprocess.run(
            self._adapter.command(job, result_json=relative),
            cwd=self._repo_root,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError(
                f"RFuzz design flow exited with status {completed.returncode}"
            )
        document = self._load_result(destination, started_ns)
        if isinstance(job, ExperimentBuildJob):
            return self._build_result(job, attempt, document)
        return self._fuzz_result(job, attempt, document)

    def _load_result(self, path: Path, started_ns: int) -> object:
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            raise ValueError("RFuzz design flow did not publish a result document") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("RFuzz result must be a regular file")
        if metadata.st_mtime_ns < started_ns:
            raise ValueError("RFuzz result document is stale")
        if metadata.st_size > _MAX_RESULT_BYTES:
            raise ValueError("RFuzz result document exceeds the size limit")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("RFuzz result document is not valid JSON") from error

    def _repository_file(self, value: object, label: str) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a repository-relative path")
        path = Path(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError(f"{label} must be a repository-relative path")
        resolved = (self._repo_root / path).resolve()
        try:
            resolved.relative_to(self._repo_root)
        except ValueError as error:
            raise ValueError(f"{label} must be a repository-relative path") from error
        return resolved

    def _build_result(
        self, job: ExperimentBuildJob, attempt: int, value: object
    ) -> BuildJobResult:
        document = _closed_object(value, _BUILD_KEYS, "build result")
        if document["kind"] != "build":
            raise ValueError("build result kind must be build")
        if document["artifact_id"] != job.artifact_id:
            raise ValueError("build result artifact_id does not match the job")
        if document["server_exists"] is not True:
            raise ValueError("build result did not observe the server artifact")
        if not self._repository_file(document["server_path"], "server_path").is_file():
            raise ValueError("build result server_path does not exist")
        return BuildJobResult(job.job_id, attempt, job.artifact_id)

    def _fuzz_result(
        self, job: ExperimentJob, attempt: int, value: object
    ) -> FuzzJobResult | ResourceCheckpointEvent:
        document = _closed_object(value, _FUZZ_KEYS, "fuzz result")
        if document["kind"] != "fuzz":
            raise ValueError("fuzz result kind must be fuzz")
        elapsed = document["elapsed_seconds"]
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
            raise ValueError("elapsed_seconds must be finite and non-negative")
        elapsed = float(elapsed)
        if not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError("elapsed_seconds must be finite and non-negative")
        tests = _uint(document["tests_executed"], "tests_executed")
        cycles = _uint(document["cycles_executed"], "cycles_executed")
        total = _uint(document["coverage_point_count"], "coverage_point_count")
        peak = _uint(document["peak_rss_bytes"], "peak_rss_bytes", positive=True)
        covered_value = document["covered_point_ids"]
        if not isinstance(covered_value, list):
            raise ValueError("covered_point_ids must be an array")
        covered = tuple(_uint(item, "covered_point_ids", positive=True) for item in covered_value)
        if len(covered) != len(set(covered)) or any(item > total for item in covered):
            raise ValueError("covered_point_ids are invalid for coverage_point_count")
        if document["handshake_succeeded"] is not True:
            raise ValueError("RFuzz FIFO handshake did not succeed")
        if document["fifo_cleanup_succeeded"] is not True:
            raise ValueError("RFuzz FIFO cleanup did not succeed")
        failures = _closed_object(
            document["failure_reasons"],
            frozenset(("dut_crash", "resource_terminated")),
            "failure_reasons",
        )
        dut_crash = _uint(failures["dut_crash"], "failure_reasons.dut_crash")
        resource = _uint(
            failures["resource_terminated"], "failure_reasons.resource_terminated"
        )
        server_rc = _returncode(document["server_returncode"], "server_returncode")
        fuzzer_rc = _returncode(document["fuzzer_returncode"], "fuzzer_returncode")
        if resource == 0 and (server_rc not in (0, -15) or fuzzer_rc not in (0, 124)):
            raise ValueError("RFuzz result contains abnormal process return codes")
        if resource == 0 and dut_crash != 0:
            raise ValueError("successful RFuzz result cannot classify a DUT crash")
        sample = {
            "job_id": job.job_id,
            "candidate_id": job.candidate_id,
            "harness": job.harness,
            "seed": job.seed,
            "elapsed_seconds": elapsed,
            "sequence": 0,
            "common_total": total,
            "covered_point_ids": list(covered),
            "tests_executed": tests,
            "cycles_executed": cycles,
            "peak_rss_bytes": peak,
            "projection_count": 0,
            "correction_counts": {},
            "protocol_event_count": 0,
            "no_progress_cycles": 0,
            "generation_count": 0,
            "validation_passed": 0,
            "failure_reasons": {"dut_crash": dut_crash, "resource_terminated": resource},
        }
        if resource:
            return ResourceCheckpointEvent(
                job.job_id,
                attempt,
                peak,
                "hard_memory_limit",
                copy.deepcopy(dict(document)),
                (sample,),
            )
        return FuzzJobResult(job.job_id, attempt, (sample,), peak)

    def persist_checkpoint(self, event: ResourceCheckpointEvent) -> None:
        if not isinstance(event, ResourceCheckpointEvent):
            raise TypeError("event must be a ResourceCheckpointEvent")
        name = f"{event.job_id}.{event.attempt}.checkpoint.json"
        _atomic_json(self._result_dir / "checkpoints" / name, event.checkpoint)

    def prepare_manifest(
        self,
        runtime_manifest: Mapping[str, object],
        design_config_path: Path,
    ) -> dict[str, object]:
        """Run frontend/instrumentation and replace placeholder coverage evidence."""
        if not isinstance(runtime_manifest, Mapping):
            raise TypeError("runtime_manifest must be an object")
        if not isinstance(design_config_path, Path) or design_config_path.is_absolute():
            raise ValueError("design_config_path must be repository-relative")
        config_path = self._repository_file(
            design_config_path.as_posix(), "design_config_path"
        )
        for stage in ("frontend", "instrument"):
            completed = subprocess.run(
                (
                    sys.executable,
                    "src/myfuzz/scripts/run_design_flow.py",
                    "--config",
                    design_config_path.as_posix(),
                    "--stage",
                    stage,
                ),
                cwd=self._repo_root,
                check=False,
            )
            if completed.returncode != 0:
                raise ValueError(f"RFuzz coverage preparation {stage} stage failed")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, Mapping) or not isinstance(config.get("out_dir"), str):
            raise ValueError("design config out_dir is required")
        out = Path(os.path.expandvars(os.path.expanduser(config["out_dir"])))
        if not out.is_absolute():
            out = self._repo_root / out
        instrumentation_path = out.resolve() / "instrumented" / "instrumentation.json"
        try:
            instrumentation = json.loads(instrumentation_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("instrumentation stage did not publish valid JSON") from error
        from myfuzz.scripts.run_design_flow import coverage_universe_from_instrumentation

        points = coverage_universe_from_instrumentation(instrumentation)
        metadata_hash = content_hash({
            "coverage_universe": sorted(points, key=canonical_bytes)
        })
        prepared = copy.deepcopy(dict(runtime_manifest))
        prepared["coverage_universe"] = [copy.deepcopy(point) for point in points]
        prepared["coverage_metadata_hash"] = metadata_hash
        harnesses = prepared.get("harnesses")
        if not isinstance(harnesses, Mapping):
            raise ValueError("runtime manifest harnesses must be an object")
        detached_harnesses: dict[str, object] = {}
        for name, value in harnesses.items():
            if not isinstance(name, str) or not isinstance(value, Mapping):
                raise ValueError("runtime manifest harness records must be objects")
            record = copy.deepcopy(dict(value))
            record["coverage_universe"] = metadata_hash
            record["coverage_metadata_hash"] = metadata_hash
            detached_harnesses[name] = record
        prepared["harnesses"] = detached_harnesses
        validate_contract(prepared, "candidate_manifest.v1")
        return prepared


__all__ = ["RfuzzExperimentRunner"]
