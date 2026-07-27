"""Execute one published B experiment plan and atomically publish its report.

The injected runner receives exactly one B ``Job`` per call.  It must return a
``BuildJobResult`` for build jobs, a ``FuzzJobResult`` containing samples
accepted by B's ``build_report`` for fuzz jobs, or a
``ResourceCheckpointEvent`` after an actual hard-limit termination.  A runner
that emits a resource event must also provide ``persist_checkpoint(event)``;
the hook completes before the job becomes eligible for a bounded retry.
"""

from __future__ import annotations

import copy
import ctypes
import json
import math
import os
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import random
import re
import secrets
import stat
from typing import Protocol, TypeAlias

from myfuzz.experiments import (
    ExperimentJob,
    ExperimentPlanError,
    Job,
    JobKind,
    build_report,
    plan_experiment,
    resolve_build_prerequisite,
    run_job,
)


class ExperimentMatrixError(ValueError):
    """Raised when orchestration input or runner output fails closed."""


class ResourceTerminatedError(ExperimentMatrixError):
    """Raised when a build remains resource-terminated after bounded retries."""


@dataclass(frozen=True, slots=True)
class BuildJobResult:
    """Successful completion of one B build prerequisite."""

    job_id: str
    attempt: int
    artifact_id: str = ""


@dataclass(frozen=True, slots=True)
class FuzzJobResult:
    """Authoritative samples returned by one completed B fuzz job."""

    job_id: str
    attempt: int
    samples: tuple[Mapping[str, object], ...]
    observed_peak_rss_bytes: int


@dataclass(frozen=True, slots=True)
class ResourceCheckpointEvent:
    """Actual runner termination with a checkpoint captured at the hard limit."""

    job_id: str
    attempt: int
    observed_peak_rss_bytes: int
    termination_signal: str
    checkpoint: Mapping[str, object]
    samples: tuple[Mapping[str, object], ...] = ()


RunnerResult: TypeAlias = BuildJobResult | FuzzJobResult | ResourceCheckpointEvent


class ExperimentRunner(Protocol):
    """Injectable execution and hard-limit checkpoint persistence boundary."""

    def __call__(self, job: Job) -> RunnerResult: ...

    def persist_checkpoint(self, event: ResourceCheckpointEvent) -> None: ...


_MAX_RETRIES = 16
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_TOP_LEVEL_KEYS = frozenset(
    (
        "planner_config", "candidate_manifests", "execution", "reference_summary",
        "pair_metadata",
    )
)
_EXECUTION_KEYS = frozenset(
    ("interleaving_seed", "max_resource_retries", "job_timeout_seconds")
)


@dataclass(frozen=True, slots=True)
class _ExecutionConfig:
    interleaving_seed: int
    max_resource_retries: int
    job_timeout_seconds: float


@dataclass(frozen=True, slots=True)
class _PairMetadata:
    policy_id: str
    plan_hash: str
    parameters: Mapping[str, object]


@dataclass(slots=True)
class _ReportDestination:
    directory: int
    name: str
    existing: int | None

    def close(self) -> None:
        if self.existing is not None:
            os.close(self.existing)
            self.existing = None
        os.close(self.directory)


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ExperimentMatrixError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ExperimentMatrixError(f"{label} keys must be strings")
    return value


def _array(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ExperimentMatrixError(f"{label} must be an array")
    return value


def _strict_keys(
    value: Mapping[str, object],
    allowed: frozenset[str],
    required: frozenset[str],
    label: str,
) -> None:
    unexpected = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unexpected:
        raise ExperimentMatrixError(f"{label} contains unexpected fields: {unexpected}")
    if missing:
        raise ExperimentMatrixError(f"{label} is missing required fields: {missing}")


def _bounded_nonnegative_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise ExperimentMatrixError(
            f"{label} must be a non-negative integer no greater than {maximum}"
        )
    return value


def _parse_config(
    value: object,
) -> tuple[
    Mapping[str, object], tuple[object, ...], _ExecutionConfig,
    object | None, _PairMetadata | None,
]:
    document = _object(value, "config")
    _strict_keys(
        document,
        _TOP_LEVEL_KEYS,
        frozenset(("planner_config", "candidate_manifests", "execution")),
        "config",
    )
    planner_config = copy.deepcopy(dict(_object(document["planner_config"], "planner_config")))
    manifests = tuple(
        copy.deepcopy(item)
        for item in _array(document["candidate_manifests"], "candidate_manifests")
    )
    if not manifests:
        raise ExperimentMatrixError("candidate_manifests must not be empty")
    execution = _object(document["execution"], "execution")
    _strict_keys(execution, _EXECUTION_KEYS, _EXECUTION_KEYS, "execution")
    seed = _bounded_nonnegative_int(
        execution["interleaving_seed"], "execution.interleaving_seed", (1 << 64) - 1
    )
    retries = _bounded_nonnegative_int(
        execution["max_resource_retries"],
        "execution.max_resource_retries",
        _MAX_RETRIES,
    )
    timeout = execution["job_timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout < 0
    ):
        raise ExperimentMatrixError(
            "execution.job_timeout_seconds must be finite and non-negative"
        )
    reference = copy.deepcopy(document.get("reference_summary"))
    pair_metadata = None
    if "pair_metadata" in document:
        metadata = _object(document["pair_metadata"], "pair_metadata")
        metadata_keys = frozenset(("policy_id", "plan_hash", "parameters"))
        _strict_keys(metadata, metadata_keys, metadata_keys, "pair_metadata")
        policy_id = metadata["policy_id"]
        plan_hash = metadata["plan_hash"]
        parameters = _object(metadata["parameters"], "pair_metadata.parameters")
        parameter_keys = frozenset((
            "direct_ratio", "event_rarity", "legal_set_strength", "mutual_exclusion",
        ))
        _strict_keys(parameters, parameter_keys, parameter_keys, "pair_metadata.parameters")
        if not isinstance(policy_id, str) or not policy_id:
            raise ExperimentMatrixError("pair_metadata.policy_id must be a non-empty string")
        if not isinstance(plan_hash, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", plan_hash
        ) is None:
            raise ExperimentMatrixError("pair_metadata.plan_hash must be canonical SHA-256")
        pair_metadata = _PairMetadata(
            policy_id, plan_hash, copy.deepcopy(dict(parameters))
        )
    return (
        planner_config, manifests, _ExecutionConfig(seed, retries, float(timeout)),
        reference, pair_metadata,
    )


def _promotion_pairs(
    plan: object,
    samples_by_job: Mapping[str, tuple[dict[str, object], ...]],
    metadata: _PairMetadata,
) -> list[dict[str, object]]:
    jobs = {job.job_id: job for job in plan.jobs}
    pairs: list[dict[str, object]] = []

    def summary(job: ExperimentJob) -> dict[str, object]:
        samples = samples_by_job[job.job_id]
        sample = max(samples, key=lambda item: (item["elapsed_seconds"], item["sequence"]))
        elapsed = sample["elapsed_seconds"]
        tests = sample["tests_executed"]
        if (
            isinstance(elapsed, bool) or not isinstance(elapsed, (int, float))
            or elapsed <= 0 or not math.isfinite(float(elapsed))
        ):
            raise ExperimentMatrixError("pair evidence elapsed_seconds must be positive")
        if isinstance(tests, bool) or not isinstance(tests, int) or tests < 0:
            raise ExperimentMatrixError("pair evidence tests_executed must be non-negative")
        expected_artifact = job.execution.server_artifact_id
        if sample.get("artifact_id") != expected_artifact:
            raise ExperimentMatrixError("pair evidence artifact_id does not match planned job")
        for field in ("handshake_succeeded", "fifo_cleanup_succeeded"):
            if sample.get(field) is not True:
                raise ExperimentMatrixError(f"pair evidence {field} must be true")
        for field in ("server_returncode", "fuzzer_returncode", "crash_restart_count"):
            value = sample.get(field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ExperimentMatrixError(f"pair evidence {field} must be an integer")
        failures = copy.deepcopy(dict(_object(
            sample.get("failure_reasons"), "pair evidence failure_reasons"
        )))
        return {
            "covered": len(sample["covered_point_ids"]),
            "tests_per_second": tests / float(elapsed),
            "failure_reasons": failures,
            "artifact_id": expected_artifact,
            "server_returncode": sample["server_returncode"],
            "fuzzer_returncode": sample["fuzzer_returncode"],
            "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": sample["crash_restart_count"],
        }

    for block in plan.run_blocks:
        block_jobs = [jobs[job_id] for job_id in block]
        direct = next(job for job in block_jobs if job.harness == "candidate-direct")
        candidate = next(
            job for job in block_jobs
            if job.harness not in {"flat-direct", "candidate-direct"}
        )
        pairs.append({
            "policy_id": metadata.policy_id,
            "plan_hash": metadata.plan_hash,
            "parameters": copy.deepcopy(dict(metadata.parameters)),
            "target_id": direct.target_id,
            "seed": direct.seed,
            "baseline": summary(direct),
            "candidate": summary(candidate),
        })
    return sorted(pairs, key=lambda pair: (pair["target_id"], pair["seed"]))


def matrix_promotion_pairs(results: object) -> tuple[dict[str, object], ...]:
    """Collect only matrix-published per-seed promotion evidence."""
    wrappers = _array(results, "matrix results")
    pairs: list[dict[str, object]] = []
    for index, value in enumerate(wrappers):
        wrapper = _object(value, f"matrix results[{index}]")
        published = _array(
            wrapper.get("promotion_pairs"),
            f"matrix results[{index}].promotion_pairs",
        )
        for pair_index, pair in enumerate(published):
            pairs.append(copy.deepcopy(dict(_object(
                pair,
                f"matrix results[{index}].promotion_pairs[{pair_index}]",
            ))))
    return tuple(pairs)


def _open_report_destination(report_path: Path) -> _ReportDestination:
    if not isinstance(report_path, Path):
        raise TypeError("report_path must be a pathlib.Path")
    path = report_path.absolute()
    if not path.name or path.name in {".", ".."}:
        raise ExperimentMatrixError("report_path must name a report file")
    parent_parts = path.parent.parts
    if not parent_parts or parent_parts[0] != os.sep:
        raise ExperimentMatrixError("report_path must resolve beneath the filesystem root")
    if any(part in {"", ".", ".."} for part in parent_parts[1:]):
        raise ExperimentMatrixError("report_path parent contains an unsafe component")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory = os.open(os.sep, directory_flags)
    except OSError as error:
        raise ExperimentMatrixError("cannot open trusted filesystem root") from error
    try:
        for component in parent_parts[1:]:
            next_directory = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            existing = os.open(path.name, file_flags, dir_fd=directory)
        except FileNotFoundError:
            existing = None
        except OSError as error:
            raise ExperimentMatrixError("report_path must be a regular non-symlink file") from error
        if existing is not None and not stat.S_ISREG(os.fstat(existing).st_mode):
            os.close(existing)
            raise ExperimentMatrixError("report_path must be a regular file")
        return _ReportDestination(directory, path.name, existing)
    except BaseException:
        os.close(directory)
        raise


def _positive_rss(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExperimentMatrixError(f"{label} must be a positive integer")
    return value


def _positive_attempt(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExperimentMatrixError(f"{label} must be a positive integer")
    return value


def _sample_identity(
    job: ExperimentJob,
    samples: object,
    *,
    resource_event: bool,
) -> tuple[tuple[dict[str, object], ...], int]:
    values = _array(samples, "runner samples")
    if not values:
        raise ExperimentMatrixError("fuzz runner samples must not be empty")
    detached: list[dict[str, object]] = []
    keys: set[tuple[object, object, object]] = set()
    peak_rss_values: list[int] = []
    for index, value in enumerate(values):
        sample = dict(_object(value, f"runner samples[{index}]"))
        for field in ("job_id", "candidate_id", "harness", "seed"):
            if sample.get(field) != getattr(job, field):
                raise ExperimentMatrixError(
                    f"runner sample {field} does not match job_id {job.job_id}"
                )
        key = (sample.get("job_id"), sample.get("elapsed_seconds"), sample.get("sequence"))
        if key in keys:
            raise ExperimentMatrixError("runner samples contain a duplicate job/time/sequence key")
        keys.add(key)
        peak_rss_values.append(
            _positive_rss(sample.get("peak_rss_bytes"), "runner sample peak_rss_bytes")
        )
        failures = _object(sample.get("failure_reasons"), "runner sample failure_reasons")
        terminated = failures.get("resource_terminated")
        if isinstance(terminated, bool) or not isinstance(terminated, int):
            raise ExperimentMatrixError(
                "runner sample resource_terminated must be a non-negative integer"
            )
        if resource_event:
            crash = failures.get("dut_crash", 0)
            if terminated <= 0:
                raise ExperimentMatrixError(
                    "resource checkpoint sample must mark resource_terminated"
                )
            if crash != 0:
                raise ExperimentMatrixError(
                    "resource checkpoint sample must not classify termination as dut_crash"
                )
        elif terminated != 0:
            raise ExperimentMatrixError(
                "FuzzJobResult sample resource_terminated must be zero"
            )
        detached.append(copy.deepcopy(sample))
    return tuple(detached), max(peak_rss_values)


def _validated_result(
    job: Job,
    result: object,
    hard_memory_bytes: int,
    expected_attempt: int,
) -> BuildJobResult | FuzzJobResult | ResourceCheckpointEvent:
    if isinstance(result, BuildJobResult):
        if job.kind is not JobKind.BUILD:
            raise ExperimentMatrixError("fuzz jobs must return FuzzJobResult")
        if result.job_id != job.job_id:
            raise ExperimentMatrixError("BuildJobResult job_id does not match job")
        if _positive_attempt(result.attempt, "BuildJobResult.attempt") != expected_attempt:
            raise ExperimentMatrixError("BuildJobResult attempt does not match current attempt")
        if result.artifact_id != getattr(job, "artifact_id", ""):
            raise ExperimentMatrixError(
                "BuildJobResult artifact_id does not match planned build artifact_id"
            )
        return result
    if isinstance(result, FuzzJobResult):
        if not isinstance(job, ExperimentJob) or job.kind is not JobKind.FUZZ:
            raise ExperimentMatrixError("build jobs must return BuildJobResult")
        if result.job_id != job.job_id:
            raise ExperimentMatrixError("FuzzJobResult job_id does not match job")
        if _positive_attempt(result.attempt, "FuzzJobResult.attempt") != expected_attempt:
            raise ExperimentMatrixError("FuzzJobResult attempt does not match current attempt")
        observed = _positive_rss(result.observed_peak_rss_bytes, "observed_peak_rss_bytes")
        if observed >= hard_memory_bytes:
            raise ExperimentMatrixError(
                "RSS at hard_memory_bytes requires a ResourceCheckpointEvent"
            )
        samples, sample_peak = _sample_identity(job, result.samples, resource_event=False)
        if sample_peak != observed:
            raise ExperimentMatrixError(
                "FuzzJobResult observed_peak_rss_bytes must equal sample peak_rss_bytes"
            )
        return FuzzJobResult(
            result.job_id,
            result.attempt,
            samples,
            observed,
        )
    if isinstance(result, ResourceCheckpointEvent):
        if result.job_id != job.job_id:
            raise ExperimentMatrixError("ResourceCheckpointEvent job_id does not match job")
        if (
            _positive_attempt(result.attempt, "ResourceCheckpointEvent.attempt")
            != expected_attempt
        ):
            raise ExperimentMatrixError(
                "ResourceCheckpointEvent attempt does not match current attempt"
            )
        observed = _positive_rss(
            result.observed_peak_rss_bytes,
            "ResourceCheckpointEvent.observed_peak_rss_bytes",
        )
        if result.termination_signal != "hard_memory_limit":
            raise ExperimentMatrixError(
                "ResourceCheckpointEvent termination_signal must be hard_memory_limit"
            )
        if observed < hard_memory_bytes:
            raise ExperimentMatrixError(
                "ResourceCheckpointEvent RSS must reach plan.runtime_policy.hard_memory_bytes"
            )
        checkpoint = copy.deepcopy(
            dict(_object(result.checkpoint, "ResourceCheckpointEvent.checkpoint"))
        )
        if isinstance(job, ExperimentJob):
            samples, sample_peak = _sample_identity(job, result.samples, resource_event=True)
            if sample_peak != observed:
                raise ExperimentMatrixError(
                    "ResourceCheckpointEvent observed_peak_rss_bytes must equal sample peak_rss_bytes"
                )
        else:
            if result.samples:
                raise ExperimentMatrixError("build resource events cannot contain fuzz samples")
            samples = ()
        return ResourceCheckpointEvent(
            result.job_id,
            result.attempt,
            observed,
            result.termination_signal,
            checkpoint,
            samples,
        )
    expected = "BuildJobResult, FuzzJobResult, or ResourceCheckpointEvent"
    raise ExperimentMatrixError(f"runner must return {expected}")


def _persist_checkpoint(
    runner: Callable[[Job], object],
    event: ResourceCheckpointEvent,
    job: Job,
    attempt: int,
    checkpoints: list[dict[str, object]],
) -> None:
    sink = getattr(runner, "persist_checkpoint", None)
    if not callable(sink):
        raise ExperimentMatrixError(
            "runner must provide persist_checkpoint for resource events"
        )
    sink(
        ResourceCheckpointEvent(
            event.job_id,
            event.attempt,
            event.observed_peak_rss_bytes,
            event.termination_signal,
            copy.deepcopy(dict(event.checkpoint)),
            tuple(copy.deepcopy(dict(sample)) for sample in event.samples),
        )
    )
    checkpoints.append(
        {
            "job_id": job.job_id,
            "attempt": attempt,
            "termination_signal": event.termination_signal,
            "observed_peak_rss_bytes": event.observed_peak_rss_bytes,
            "checkpoint": copy.deepcopy(dict(event.checkpoint)),
        }
    )


def _is_legacy_build_prerequisite(job: Job) -> bool:
    return (
        getattr(job, "target_id", "") == ""
        and getattr(job, "candidate_id", "") == ""
        and getattr(job, "harness", "") == ""
        and getattr(job, "artifact_id", "") == ""
        and getattr(job, "harness_content_hash", None) is None
        and getattr(job, "harness_abi_hash", None) is None
        and getattr(job, "projection_plan_hash", None) is None
        and getattr(getattr(job, "execution", None), "candidate_mode", None) is None
        and getattr(getattr(job, "execution", None), "server_artifact_id", None) is None
    )


def _require_completed_build_prerequisite(
    job: ExperimentJob,
    prerequisites: Mapping[str, Job],
    completed_builds: set[str],
) -> Job:
    required = prerequisites[job.job_id]
    if required.job_id not in completed_builds:
        raise ExperimentMatrixError(
            f"fuzz build prerequisite did not complete: {required.job_id}"
        )
    return required


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("report write made no progress")
        offset += written


def _fsync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def _exchange_names(directory: int, first: str, second: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise ExperimentMatrixError("atomic report exchange is unavailable") from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(directory, os.fsencode(first), directory, os.fsencode(second), 2) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _atomic_write_report(
    destination: _ReportDestination,
    document: Mapping[str, object],
) -> None:
    payload = (
        json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_REPORT_BYTES:
        raise ExperimentMatrixError("experiment report exceeds size limit")

    directory = destination.directory
    report_name = destination.name
    temporary_name = f".{report_name}.{secrets.token_hex(8)}.tmp"
    backup_name = f".{report_name}.{secrets.token_hex(8)}.backup"
    rollback_name = f".{report_name}.{secrets.token_hex(8)}.rollback"
    descriptor: int | None = None
    backup_created = False
    backup_obsolete = False
    backup_must_be_retained = False
    rollback_created = False
    temporary_obsolete = True
    try:
        try:
            current = os.stat(report_name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if destination.existing is None:
            if current is not None:
                raise ExperimentMatrixError("report_path changed during execution")
        else:
            pinned = os.fstat(destination.existing)
            if (
                current is None
                or not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)
            ):
                raise ExperimentMatrixError("report_path changed during execution")
            os.link(
                report_name,
                backup_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            backup_created = True
            backup = os.stat(backup_name, dir_fd=directory, follow_symlinks=False)
            if (backup.st_dev, backup.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise ExperimentMatrixError("report_path changed while creating backup")
            _fsync_directory(directory)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if destination.existing is None:
            try:
                os.link(
                    temporary_name,
                    report_name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise ExperimentMatrixError(
                    "report_path changed during publication"
                ) from error
        else:
            backup_must_be_retained = True
            _exchange_names(directory, temporary_name, report_name)
            displaced = os.stat(
                temporary_name,
                dir_fd=directory,
                follow_symlinks=False,
            )
            pinned = os.fstat(destination.existing)
            if (displaced.st_dev, displaced.st_ino) != (pinned.st_dev, pinned.st_ino):
                error = ExperimentMatrixError("report_path changed during publication")
                try:
                    _exchange_names(directory, temporary_name, report_name)
                except BaseException as rollback_error:
                    temporary_obsolete = False
                    error.add_note(f"report exchange rollback failed: {rollback_error}")
                    error.add_note(f"recoverable report backup: {backup_name}")
                    error.add_note(
                        f"recoverable displaced report: {temporary_name}"
                    )
                raise error
        try:
            _fsync_directory(directory)
        except BaseException as error:
            try:
                if backup_created:
                    os.link(
                        backup_name,
                        rollback_name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                        follow_symlinks=False,
                    )
                    rollback_created = True
                    os.replace(
                        rollback_name,
                        report_name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                    )
                    rollback_created = False
                else:
                    os.unlink(report_name, dir_fd=directory)
                _fsync_directory(directory)
                backup_obsolete = True
            except BaseException as rollback_error:
                error.add_note(f"report rollback failed: {rollback_error}")
                if backup_created:
                    error.add_note(f"recoverable report backup: {backup_name}")
            raise
        if backup_created:
            os.unlink(backup_name, dir_fd=directory)
            backup_created = False
    except BaseException as error:
        if backup_created and not backup_obsolete:
            if not backup_must_be_retained:
                try:
                    current = os.stat(
                        report_name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                    pinned = os.fstat(destination.existing)
                    current_identity = (current.st_dev, current.st_ino)
                    pinned_identity = (pinned.st_dev, pinned.st_ino)
                    if current_identity == pinned_identity:
                        _fsync_directory(directory)
                        backup_obsolete = True
                except BaseException:
                    pass
            if not backup_obsolete:
                error.add_note(f"recoverable report backup: {backup_name}")
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_obsolete:
            try:
                os.unlink(temporary_name, dir_fd=directory)
            except FileNotFoundError:
                pass
        try:
            if rollback_created:
                os.unlink(rollback_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        try:
            if backup_created and backup_obsolete:
                os.unlink(backup_name, dir_fd=directory)
        except FileNotFoundError:
            pass


def run_experiment_matrix(
    config: Mapping[str, object],
    *,
    runner: Callable[[Job], object],
    report_path: Path,
) -> dict[str, object]:
    """Run B's immutable plan through B leases and publish B's report unchanged."""
    if not callable(runner):
        raise TypeError("runner must be callable")
    destination = _open_report_destination(report_path)
    try:
        return _run_experiment_matrix(config, runner, destination)
    finally:
        destination.close()


def _run_experiment_matrix(
    config: Mapping[str, object],
    runner: Callable[[Job], object],
    destination: _ReportDestination,
) -> dict[str, object]:
    planner_config, manifests, execution, reference_summary, pair_metadata = _parse_config(config)
    plan = plan_experiment(planner_config, manifests)
    try:
        prerequisites = {}
        for job in plan.jobs:
            required = resolve_build_prerequisite(plan, job)
            if not job.build_job_id and not _is_legacy_build_prerequisite(required):
                raise ExperimentPlanError(
                    "harness-specific fuzz build prerequisite is missing build_job_id"
                )
            prerequisites[job.job_id] = required
    except ExperimentPlanError as error:
        raise ExperimentMatrixError(str(error)) from error
    completed_builds: set[str] = set()

    jobs_by_id = {job.job_id: job for job in plan.jobs}
    run_blocks = list(plan.run_blocks)
    random.Random(execution.interleaving_seed).shuffle(run_blocks)
    fuzz_order = [jobs_by_id[job_id] for block in run_blocks for job_id in block]
    execution_order: list[str] = []
    attempts: defaultdict[str, int] = defaultdict(int)
    checkpoints: list[dict[str, object]] = []
    samples_by_job: dict[str, tuple[dict[str, object], ...]] = {}
    resource_terminated: set[str] = set()

    def execute(job: Job) -> BuildJobResult | FuzzJobResult | ResourceCheckpointEvent:
        attempts[job.job_id] += 1
        execution_order.append(job.job_id)
        result = run_job(
            job,
            runner,
            timeout_seconds=execution.job_timeout_seconds,
        )
        return _validated_result(
            job,
            result,
            plan.runtime_policy.hard_memory_bytes,
            attempts[job.job_id],
        )

    for build_job in plan.build_jobs:
        while True:
            result = execute(build_job)
            if isinstance(result, BuildJobResult):
                completed_builds.add(build_job.job_id)
                break
            if not isinstance(result, ResourceCheckpointEvent):
                raise ExperimentMatrixError("build jobs must return BuildJobResult")
            _persist_checkpoint(
                runner,
                result,
                build_job,
                attempts[build_job.job_id],
                checkpoints,
            )
            if attempts[build_job.job_id] > execution.max_resource_retries:
                raise ResourceTerminatedError(
                    f"build job remained resource_terminated: {build_job.job_id}"
                )

    retry_queue: list[tuple[ExperimentJob, ResourceCheckpointEvent, int]] = []
    stable_order = {job.job_id: index for index, job in enumerate(fuzz_order)}

    def accept_fuzz_result(job: ExperimentJob, result: RunnerResult) -> None:
        if isinstance(result, FuzzJobResult):
            samples_by_job[job.job_id] = tuple(dict(sample) for sample in result.samples)
            return
        if not isinstance(result, ResourceCheckpointEvent):
            raise ExperimentMatrixError("fuzz jobs must return FuzzJobResult")
        _persist_checkpoint(
            runner,
            result,
            job,
            attempts[job.job_id],
            checkpoints,
        )
        if attempts[job.job_id] <= execution.max_resource_retries:
            retry_queue.append((job, result, stable_order[job.job_id]))
        else:
            samples_by_job[job.job_id] = tuple(dict(sample) for sample in result.samples)
            resource_terminated.add(job.job_id)

    for job in fuzz_order:
        _require_completed_build_prerequisite(job, prerequisites, completed_builds)
        accept_fuzz_result(job, execute(job))

    while retry_queue:
        retry_queue.sort(key=lambda item: (item[0].priority, item[2], item[0].job_id))
        job, _previous_event, order_index = retry_queue.pop(0)
        _require_completed_build_prerequisite(job, prerequisites, completed_builds)
        result = execute(job)
        if isinstance(result, ResourceCheckpointEvent):
            _persist_checkpoint(
                runner,
                result,
                job,
                attempts[job.job_id],
                checkpoints,
            )
            if attempts[job.job_id] <= execution.max_resource_retries:
                retry_queue.append((job, result, order_index))
            else:
                samples_by_job[job.job_id] = tuple(
                    dict(sample) for sample in result.samples
                )
                resource_terminated.add(job.job_id)
        elif isinstance(result, FuzzJobResult):
            samples_by_job[job.job_id] = tuple(dict(sample) for sample in result.samples)
        else:
            raise ExperimentMatrixError("fuzz jobs must return FuzzJobResult")

    missing = {job.job_id for job in plan.jobs} - set(samples_by_job)
    if missing:
        raise ExperimentMatrixError(f"runner samples are missing planned jobs: {sorted(missing)}")
    samples = [
        sample
        for job in plan.jobs
        for sample in samples_by_job[job.job_id]
    ]
    selected_candidate_ids = {job.candidate_id for job in plan.jobs}
    selected_manifests = tuple(
        manifest
        for manifest in manifests
        if isinstance(manifest, Mapping)
        and manifest.get("candidate_id") in selected_candidate_ids
    )
    authoritative_report = build_report(
        plan,
        selected_manifests,
        samples,
        reference_summary,
    )
    wrapper: dict[str, object] = {
        "schema_version": "experiment_matrix_run.v1",
        "report": authoritative_report,
        "execution": {
            "interleaving_seed": execution.interleaving_seed,
            "execution_order": execution_order,
            "attempts": {job_id: attempts[job_id] for job_id in sorted(attempts)},
            "checkpoints": checkpoints,
            "resource_terminated_job_ids": sorted(resource_terminated),
        },
    }
    if pair_metadata is not None:
        wrapper["promotion_pairs"] = _promotion_pairs(
            plan, samples_by_job, pair_metadata
        )
    _atomic_write_report(destination, wrapper)
    return copy.deepcopy(wrapper)


__all__ = [
    "BuildJobResult",
    "ExperimentMatrixError",
    "ExperimentRunner",
    "FuzzJobResult",
    "ResourceCheckpointEvent",
    "ResourceTerminatedError",
    "RunnerResult",
    "matrix_promotion_pairs",
    "run_experiment_matrix",
]
