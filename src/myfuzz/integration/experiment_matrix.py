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
import json
import math
import os
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import random
import secrets
import stat
from typing import Protocol, TypeAlias

from myfuzz.experiments import (
    ExperimentJob,
    Job,
    JobKind,
    build_report,
    plan_experiment,
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


@dataclass(frozen=True, slots=True)
class FuzzJobResult:
    """Authoritative samples returned by one completed B fuzz job."""

    job_id: str
    samples: tuple[Mapping[str, object], ...]
    observed_peak_rss_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class ResourceCheckpointEvent:
    """Actual runner termination with a checkpoint captured at the hard limit."""

    job_id: str
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
    ("planner_config", "candidate_manifests", "execution", "reference_summary")
)
_EXECUTION_KEYS = frozenset(
    ("interleaving_seed", "max_resource_retries", "job_timeout_seconds")
)


@dataclass(frozen=True, slots=True)
class _ExecutionConfig:
    interleaving_seed: int
    max_resource_retries: int
    job_timeout_seconds: float


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
) -> tuple[Mapping[str, object], tuple[object, ...], _ExecutionConfig, object | None]:
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
    return planner_config, manifests, _ExecutionConfig(seed, retries, float(timeout)), reference


def _audit_report_path(report_path: Path) -> Path:
    if not isinstance(report_path, Path):
        raise TypeError("report_path must be a pathlib.Path")
    path = report_path.absolute()
    if not path.name or path.name in {".", ".."}:
        raise ExperimentMatrixError("report_path must name a report file")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise ExperimentMatrixError("report_path parent must be an existing directory") from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or resolved_parent != parent:
        raise ExperimentMatrixError("report_path parent must not traverse a symlink")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as error:
        raise ExperimentMatrixError("cannot inspect report_path") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ExperimentMatrixError("report_path must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise ExperimentMatrixError("report_path must be a regular file")
    return path


def _positive_rss(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExperimentMatrixError(f"{label} must be a positive integer")
    return value


def _sample_identity(
    job: ExperimentJob,
    samples: object,
    *,
    resource_event: bool,
) -> tuple[dict[str, object], ...]:
    values = _array(samples, "runner samples")
    if not values:
        raise ExperimentMatrixError("fuzz runner samples must not be empty")
    detached: list[dict[str, object]] = []
    keys: set[tuple[object, object, object]] = set()
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
        if resource_event:
            failures = _object(sample.get("failure_reasons"), "resource sample failure_reasons")
            terminated = failures.get("resource_terminated")
            crash = failures.get("dut_crash", 0)
            if isinstance(terminated, bool) or not isinstance(terminated, int) or terminated <= 0:
                raise ExperimentMatrixError(
                    "resource checkpoint sample must mark resource_terminated"
                )
            if crash != 0:
                raise ExperimentMatrixError(
                    "resource checkpoint sample must not classify termination as dut_crash"
                )
        detached.append(copy.deepcopy(sample))
    return tuple(detached)


def _validated_result(
    job: Job,
    result: object,
    hard_memory_bytes: int,
) -> BuildJobResult | FuzzJobResult | ResourceCheckpointEvent:
    if isinstance(result, BuildJobResult):
        if job.kind is not JobKind.BUILD:
            raise ExperimentMatrixError("fuzz jobs must return FuzzJobResult")
        if result.job_id != job.job_id:
            raise ExperimentMatrixError("BuildJobResult job_id does not match job")
        return result
    if isinstance(result, FuzzJobResult):
        if not isinstance(job, ExperimentJob) or job.kind is not JobKind.FUZZ:
            raise ExperimentMatrixError("build jobs must return BuildJobResult")
        if result.job_id != job.job_id:
            raise ExperimentMatrixError("FuzzJobResult job_id does not match job")
        observed = result.observed_peak_rss_bytes
        if observed is not None:
            observed = _positive_rss(observed, "observed_peak_rss_bytes")
            if observed >= hard_memory_bytes:
                raise ExperimentMatrixError(
                    "RSS at hard_memory_bytes requires a ResourceCheckpointEvent"
                )
        return FuzzJobResult(
            result.job_id,
            _sample_identity(job, result.samples, resource_event=False),
            observed,
        )
    if isinstance(result, ResourceCheckpointEvent):
        if result.job_id != job.job_id:
            raise ExperimentMatrixError("ResourceCheckpointEvent job_id does not match job")
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
            samples = _sample_identity(job, result.samples, resource_event=True)
        else:
            if result.samples:
                raise ExperimentMatrixError("build resource events cannot contain fuzz samples")
            samples = ()
        return ResourceCheckpointEvent(
            result.job_id,
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
    sink(event)
    checkpoints.append(
        {
            "job_id": job.job_id,
            "attempt": attempt,
            "termination_signal": event.termination_signal,
            "observed_peak_rss_bytes": event.observed_peak_rss_bytes,
            "checkpoint": copy.deepcopy(dict(event.checkpoint)),
        }
    )


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


def _atomic_write_report(report_path: Path, document: Mapping[str, object]) -> None:
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

    path = _audit_report_path(report_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(path.parent, directory_flags)
    temporary_name = f".{path.name}.{secrets.token_hex(8)}.tmp"
    backup_name = f".{path.name}.{secrets.token_hex(8)}.backup"
    descriptor: int | None = None
    backup_created = False
    try:
        try:
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            if stat.S_ISLNK(current.st_mode):
                raise ExperimentMatrixError("report_path must not be a symlink")
            if not stat.S_ISREG(current.st_mode):
                raise ExperimentMatrixError("report_path must be a regular file")
            os.link(
                path.name,
                backup_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            backup_created = True
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        try:
            _fsync_directory(directory)
            if backup_created:
                os.unlink(backup_name, dir_fd=directory)
                backup_created = False
        except BaseException as error:
            try:
                if backup_created:
                    os.replace(
                        backup_name,
                        path.name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                    )
                    backup_created = False
                else:
                    os.unlink(path.name, dir_fd=directory)
                os.fsync(directory)
            except BaseException as rollback_error:
                error.add_note(f"report rollback failed: {rollback_error}")
            raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        try:
            if backup_created:
                os.unlink(backup_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory)


def run_experiment_matrix(
    config: Mapping[str, object],
    *,
    runner: Callable[[Job], object],
    report_path: Path,
) -> dict[str, object]:
    """Run B's immutable plan through B leases and publish B's report unchanged."""
    if not callable(runner):
        raise TypeError("runner must be callable")
    destination = _audit_report_path(report_path)
    planner_config, manifests, execution, reference_summary = _parse_config(config)
    plan = plan_experiment(planner_config, manifests)

    fuzz_order = list(plan.jobs)
    random.Random(execution.interleaving_seed).shuffle(fuzz_order)
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
        return _validated_result(job, result, plan.runtime_policy.hard_memory_bytes)

    for build_job in plan.build_jobs:
        while True:
            result = execute(build_job)
            if isinstance(result, BuildJobResult):
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
        accept_fuzz_result(job, execute(job))

    while retry_queue:
        retry_queue.sort(key=lambda item: (item[0].priority, item[2], item[0].job_id))
        job, _previous_event, order_index = retry_queue.pop(0)
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
    "run_experiment_matrix",
]
