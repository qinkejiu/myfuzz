"""Immutable jobs and capability-checked memory-gate operations."""

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
    """Audit information and the exact capability for one gate lease."""

    job_id: str
    gate_name: str
    owner: str
    requested_mib: int
    pid: int
    seed: int
    candidate_hash: str
    lease: object


_Result = TypeVar("_Result")
_MAX_LEASE_RECORD_BYTES = 64 * 1024


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


def _validated_lease(lease: object) -> tuple[Path, str, str, int, int, int]:
    try:
        path = lease.path
        owner = lease.owner
        token = lease.token
        pid = lease.pid
        device = lease.device
        inode = lease.inode
    except AttributeError as error:
        raise ValueError("memory gate did not return a complete lease capability") from error
    if not isinstance(path, Path):
        raise ValueError("memory gate lease path is invalid")
    if not isinstance(owner, str) or not owner:
        raise ValueError("memory gate lease owner is invalid")
    if (
        not isinstance(token, str)
        or len(token) != 32
        or any(character not in "0123456789abcdef" for character in token)
    ):
        raise ValueError("memory gate lease token is invalid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("memory gate lease PID is invalid")
    if isinstance(device, bool) or not isinstance(device, int) or device < 0:
        raise ValueError("memory gate lease device is invalid")
    if isinstance(inode, bool) or not isinstance(inode, int) or inode <= 0:
        raise ValueError("memory gate lease inode is invalid")
    return path, owner, token, pid, device, inode


def _validated_record_payload(lease: object) -> bytes:
    try:
        payload = lease.record_payload
    except AttributeError as error:
        raise ValueError("memory gate lease has no persisted audit record") from error
    if not isinstance(payload, bytes):
        raise ValueError("memory gate lease audit record is not immutable bytes")
    if len(payload) > _MAX_LEASE_RECORD_BYTES:
        raise ValueError("memory gate lease audit record exceeds the size limit")
    return payload


def _release_lease(gate: ModuleType, job: Job, lease: object) -> bool:
    path, owner, token, _pid, _device, _inode = _validated_lease(lease)
    if owner != job.owner or path.name != f"{job.gate_name}.lock":
        raise ValueError("memory gate lease does not match job")
    return bool(
        gate.release(
            job.gate_name,
            job.owner,
            token=token,
            lock_directory=path.parent,
        )
    )


def claim_job(job: Job, *, timeout_seconds: float = 60.0) -> JobClaim:
    """Claim the job's gate and return the persisted lock audit record."""
    if not isinstance(job, Job):
        raise TypeError("job must be a Job")
    gate = _memory_gate()
    try:
        lease = gate.claim(
            job.gate_name,
            job.requested_mib,
            job.owner,
            timeout_seconds=timeout_seconds,
            record_fields={"seed": job.seed, "candidate_hash": job.candidate_hash},
        )
    except gate.GateError as error:
        raise RuntimeError(str(error)) from error

    try:
        _path, lease_owner, lease_token, lease_pid, _device, _inode = _validated_lease(lease)
        record = json.loads(_validated_record_payload(lease))
        pid = record["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise ValueError("invalid PID")
        if (
            lease_owner != job.owner
            or pid != lease_pid
            or record.get("owner") != lease_owner
            or record.get("token") != lease_token
            or record.get("memory_mib") != job.requested_mib
            or record.get("seed") != job.seed
            or record.get("candidate_hash") != job.candidate_hash
        ):
            raise ValueError("record does not match job")
    except (AttributeError, KeyError, OSError, RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        cleanup_error: BaseException | None = None
        try:
            _release_lease(gate, job, lease)
        except BaseException as release_error:
            cleanup_error = release_error
        message = "memory gate did not persist a readable claim record"
        if cleanup_error is not None:
            message = f"{message}; token-checked release failed: {cleanup_error}"
        raise RuntimeError(message) from error
    return JobClaim(
        job_id=job.job_id,
        gate_name=job.gate_name,
        owner=job.owner,
        requested_mib=job.requested_mib,
        pid=pid,
        seed=job.seed,
        candidate_hash=job.candidate_hash,
        lease=lease,
    )


def release_job(job: Job, claim: JobClaim) -> bool:
    """Release only the exact gate lease represented by ``claim``."""
    if not isinstance(job, Job):
        raise TypeError("job must be a Job")
    if not isinstance(claim, JobClaim):
        raise TypeError("claim must be a JobClaim")
    if (
        claim.job_id != job.job_id
        or claim.gate_name != job.gate_name
        or claim.owner != job.owner
        or claim.requested_mib != job.requested_mib
        or claim.seed != job.seed
        or claim.candidate_hash != job.candidate_hash
    ):
        raise ValueError("claim does not match job")
    _path, owner, _token, pid, _device, _inode = _validated_lease(claim.lease)
    if owner != claim.owner or pid != claim.pid:
        raise ValueError("claim does not match lease capability")
    gate = _memory_gate()
    try:
        return _release_lease(gate, job, claim.lease)
    except gate.GateError as error:
        raise RuntimeError(str(error)) from error


def run_job(job: Job, runner: Callable[[Job], _Result], *, timeout_seconds: float = 60.0) -> _Result:
    """Run a job while guaranteeing its memory-gate release on every exit."""
    claim = claim_job(job, timeout_seconds=timeout_seconds)
    try:
        return runner(job)
    finally:
        release_job(job, claim)
