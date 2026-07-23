"""Immutable jobs and owner-checked memory-gate operations."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import TypeVar


class JobKind(str, Enum):
    """The host resource class required by an experiment job."""

    BUILD = "build"
    FUZZ = "fuzz"


@dataclass(frozen=True, slots=True)
class Job:
    """One deterministic unit of host work using opaque input identities."""

    job_id: str
    kind: JobKind
    gate_name: str
    owner: str
    requested_mib: int
    seed: int
    candidate_hash: str
    build_cache_key: str
    worker_limit: int


@dataclass(frozen=True, slots=True)
class JobClaim:
    """Audit information for a successful memory-gate claim."""

    job_id: str
    gate_name: str
    owner: str
    requested_mib: int
    pid: int
    seed: int
    candidate_hash: str


_Result = TypeVar("_Result")


def _memory_gate_script() -> Path:
    script = Path(__file__).resolve().parents[3] / "scripts" / "memory_gate.py"
    if not script.is_file():
        raise RuntimeError(f"memory gate script is unavailable: {script}")
    return script


def _memory_gate() -> ModuleType:
    specification = importlib.util.spec_from_file_location("myfuzz_memory_gate", _memory_gate_script())
    if specification is None or specification.loader is None:
        raise RuntimeError("memory gate script cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def claim_job(job: Job, *, timeout_seconds: float = 60.0) -> JobClaim:
    """Claim the job's gate and return the persisted lock audit record."""
    if not isinstance(job, Job):
        raise TypeError("job must be a Job")
    gate = _memory_gate()
    try:
        lock_path = gate.claim(
            job.gate_name,
            job.requested_mib,
            job.owner,
            timeout_seconds=timeout_seconds,
        )
    except gate.GateError as error:
        raise RuntimeError(str(error)) from error

    try:
        record = json.loads(lock_path.read_text(encoding="utf-8"))
        pid = record["pid"]
    except (KeyError, OSError, json.JSONDecodeError) as error:
        raise RuntimeError("memory gate did not persist a readable claim record") from error
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise RuntimeError("memory gate claim record has an invalid PID")
    if record.get("owner") != job.owner or record.get("memory_mib") != job.requested_mib:
        raise RuntimeError("memory gate claim record does not match the requested job")
    return JobClaim(
        job_id=job.job_id,
        gate_name=job.gate_name,
        owner=job.owner,
        requested_mib=job.requested_mib,
        pid=pid,
        seed=job.seed,
        candidate_hash=job.candidate_hash,
    )


def release_job(job: Job) -> bool:
    """Release a job gate only when the stored owner still matches the job."""
    if not isinstance(job, Job):
        raise TypeError("job must be a Job")
    return bool(_memory_gate().release(job.gate_name, job.owner))


def run_job(job: Job, runner: Callable[[Job], _Result], *, timeout_seconds: float = 60.0) -> _Result:
    """Run a job while guaranteeing its memory-gate release on every exit."""
    claim_job(job, timeout_seconds=timeout_seconds)
    try:
        return runner(job)
    finally:
        release_job(job)
