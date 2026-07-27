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


_BUILD_KEYS = frozenset((
    "kind", "artifact_id", "server_path", "server_exists",
    "peak_rss_bytes", "resource_terminated",
))
_FUZZ_KEYS = frozenset((
    "kind", "job_id", "artifact_id", "elapsed_seconds", "tests_executed", "cycles_executed",
    "coverage_point_count", "covered_point_ids", "peak_rss_bytes",
    "server_returncode", "fuzzer_returncode", "handshake_succeeded",
    "fifo_cleanup_succeeded", "crash_restart_count", "failure_reasons",
))
_FUZZ_RESOURCE_KEYS = frozenset((
    "kind", "job_id", "artifact_id", "peak_rss_bytes",
    "server_returncode", "fuzzer_returncode", "handshake_succeeded",
    "fifo_cleanup_succeeded", "crash_restart_count", "failure_reasons",
))
_MAX_RESULT_BYTES = 1024 * 1024


def _read_regular_json(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    started_ns: int | None = None,
    repository_root: Path | None = None,
) -> object:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    directory: int | None = None
    if repository_root is None:
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError as error:
            raise ValueError(f"{label} is missing") from error
        except OSError as error:
            raise ValueError(f"{label} must be a regular file") from error
    else:
        try:
            parts = path.relative_to(repository_root).parts
        except ValueError as error:
            raise ValueError(f"{label} must remain beneath the repository") from error
        if not parts or any(
            part in {"", ".", ".."} or "/" in part or "\0" in part
            for part in parts
        ):
            raise ValueError(f"{label} must remain beneath the repository")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory = os.open(repository_root, directory_flags)
        try:
            for part in parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(parts[-1], flags, dir_fd=directory)
        except FileNotFoundError as error:
            if directory is not None:
                os.close(directory)
                directory = None
            raise ValueError(f"{label} is missing") from error
        except OSError as error:
            if directory is not None:
                os.close(directory)
                directory = None
            raise ValueError(f"{label} must remain beneath the repository") from error
    try:
        assert descriptor is not None
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if started_ns is not None and metadata.st_mtime_ns < started_ns:
            raise ValueError(f"{label} is stale")
        if metadata.st_size > max_bytes:
            raise ValueError(f"{label} exceeds the size limit")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            return json.load(stream)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _open_beneath_directory(root: Path, parts: tuple[str, ...], label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    try:
        for part in parts:
            if part in {"", ".", ".."} or "/" in part or "\0" in part:
                raise ValueError(f"{label} contains an unsafe path component")
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as error:
                raise ValueError(f"{label} must remain beneath the repository") from error
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_json_at(directory: int, name: str, document: object) -> None:
    if name in {"", ".", ".."} or "/" in name or "\0" in name:
        raise ValueError("checkpoint name is unsafe")
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            temporary, flags, 0o600, dir_fd=directory
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


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
        self._result_parts = results.relative_to(root).parts
        self._adapter = RfuzzAdapter(root)
        self._attempts: dict[str, int] = {}

    def _require_available(self) -> None:
        availability = self._adapter.availability()
        if not availability.available:
            raise ValueError(
                "RFuzz unavailable; missing: " + ", ".join(availability.missing_paths)
            )

    def __call__(self, job: object) -> RunnerResult:
        if not isinstance(job, (ExperimentBuildJob, ExperimentJob)):
            raise TypeError("job must be a planned RFuzz build or fuzz job")
        self._require_available()
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
            return _read_regular_json(
                path,
                "RFuzz result document",
                max_bytes=_MAX_RESULT_BYTES,
                started_ns=started_ns,
                repository_root=self._repo_root,
            )
        except ValueError as error:
            if "missing" in str(error):
                raise ValueError(
                    "RFuzz design flow did not publish a result document"
                ) from error
            raise

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
    ) -> BuildJobResult | ResourceCheckpointEvent:
        document = _closed_object(value, _BUILD_KEYS, "build result")
        if document["kind"] != "build":
            raise ValueError("build result kind must be build")
        if document["artifact_id"] != job.artifact_id:
            raise ValueError("build result artifact_id does not match the job")
        peak = _uint(document["peak_rss_bytes"], "peak_rss_bytes", positive=True)
        if not isinstance(document["resource_terminated"], bool):
            raise ValueError("resource_terminated must be a boolean")
        if document["resource_terminated"]:
            return ResourceCheckpointEvent(
                job.job_id,
                attempt,
                peak,
                "hard_memory_limit",
                copy.deepcopy(dict(document)),
            )
        if document["server_exists"] is not True:
            raise ValueError("build result did not observe the server artifact")
        if not self._repository_file(document["server_path"], "server_path").is_file():
            raise ValueError("build result server_path does not exist")
        return BuildJobResult(job.job_id, attempt, job.artifact_id)

    def _fuzz_result(
        self, job: ExperimentJob, attempt: int, value: object
    ) -> FuzzJobResult | ResourceCheckpointEvent:
        if isinstance(value, Mapping) and value.get("kind") == "fuzz-resource":
            return self._fuzz_resource_result(job, attempt, value)
        document = _closed_object(value, _FUZZ_KEYS, "fuzz result")
        if document["kind"] != "fuzz":
            raise ValueError("fuzz result kind must be fuzz")
        if document["job_id"] != job.job_id:
            raise ValueError("fuzz result job_id does not match the job")
        artifact_id = job.execution.server_artifact_id
        if not isinstance(artifact_id, str) or document["artifact_id"] != artifact_id:
            raise ValueError("fuzz result artifact_id does not match the planned artifact")
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
        crash_restarts = _uint(document["crash_restart_count"], "crash_restart_count")
        if resource:
            if dut_crash != 0:
                raise ValueError("resource termination must not be classified as dut_crash")
        elif dut_crash != crash_restarts:
            raise ValueError("dut_crash must equal crash_restart_count")
        server_rc = _returncode(document["server_returncode"], "server_returncode")
        fuzzer_rc = _returncode(document["fuzzer_returncode"], "fuzzer_returncode")
        if resource == 0 and (server_rc not in (0, -15, -9) or fuzzer_rc not in (0, -15, -9)):
            raise ValueError("RFuzz result contains abnormal process return codes")
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
            "artifact_id": artifact_id,
            "server_returncode": server_rc,
            "fuzzer_returncode": fuzzer_rc,
            "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": crash_restarts,
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

    def _fuzz_resource_result(
        self, job: ExperimentJob, attempt: int, value: object
    ) -> ResourceCheckpointEvent:
        document = _closed_object(value, _FUZZ_RESOURCE_KEYS, "fuzz resource result")
        if document["kind"] != "fuzz-resource":
            raise ValueError("fuzz resource result kind must be fuzz-resource")
        if document["job_id"] != job.job_id:
            raise ValueError("fuzz resource result job_id does not match the job")
        artifact_id = job.execution.server_artifact_id
        if not isinstance(artifact_id, str) or document["artifact_id"] != artifact_id:
            raise ValueError("fuzz resource result artifact_id does not match the planned artifact")
        peak = _uint(document["peak_rss_bytes"], "peak_rss_bytes", positive=True)
        _returncode(document["server_returncode"], "server_returncode")
        _returncode(document["fuzzer_returncode"], "fuzzer_returncode")
        if not isinstance(document["handshake_succeeded"], bool):
            raise ValueError("handshake_succeeded must be a boolean")
        if document["fifo_cleanup_succeeded"] is not True:
            raise ValueError("RFuzz FIFO cleanup did not succeed")
        _uint(document["crash_restart_count"], "crash_restart_count")
        failures = _closed_object(
            document["failure_reasons"],
            frozenset(("dut_crash", "resource_terminated")),
            "failure_reasons",
        )
        if _uint(failures["dut_crash"], "failure_reasons.dut_crash") != 0:
            raise ValueError("resource termination must not be classified as dut_crash")
        if _uint(
            failures["resource_terminated"],
            "failure_reasons.resource_terminated",
        ) != 1:
            raise ValueError("fuzz resource result must mark resource_terminated")
        return ResourceCheckpointEvent(
            job.job_id,
            attempt,
            peak,
            "hard_memory_limit",
            copy.deepcopy(dict(document)),
            (),
        )

    def persist_checkpoint(self, event: ResourceCheckpointEvent) -> None:
        if not isinstance(event, ResourceCheckpointEvent):
            raise TypeError("event must be a ResourceCheckpointEvent")
        name = f"{event.job_id}.{event.attempt}.checkpoint.json"
        directory = _open_beneath_directory(
            self._repo_root,
            self._result_parts + ("checkpoints",),
            "checkpoint destination",
        )
        try:
            _atomic_json_at(directory, name, event.checkpoint)
        finally:
            os.close(directory)

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
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("design config must be valid JSON") from error
        if not isinstance(config, Mapping) or not isinstance(config.get("out_dir"), str):
            raise ValueError("design config out_dir is required")
        out = Path(os.path.expandvars(os.path.expanduser(config["out_dir"])))
        if not out.is_absolute():
            out = self._repo_root / out
        out = out.resolve()
        try:
            out.relative_to(self._repo_root)
        except ValueError as error:
            raise ValueError("design config out_dir must remain beneath the repository") from error
        self._require_available()
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
        instrumentation_path = out / "instrumented" / "instrumentation.json"
        instrumentation = _read_regular_json(
            instrumentation_path,
            "instrumentation evidence",
            max_bytes=64 * 1024 * 1024,
            repository_root=self._repo_root,
        )
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
            if not isinstance(name, str):
                raise ValueError("runtime manifest harness names must be strings")
            if name not in {"candidate-direct", "candidate-static"}:
                detached_harnesses[name] = copy.deepcopy(value)
                continue
            if not isinstance(value, Mapping):
                raise ValueError(f"runtime manifest {name} harness record must be an object")
            record = copy.deepcopy(dict(value))
            record["coverage_universe"] = metadata_hash
            record["coverage_metadata_hash"] = metadata_hash
            detached_harnesses[name] = record
        prepared["harnesses"] = detached_harnesses
        validate_contract(prepared, "candidate_manifest.v1")
        return prepared


__all__ = ["RfuzzExperimentRunner"]
