"""Deterministic measured-RSS experiment job planning."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence

from .identity import candidate_semantic_hash
from .jobs import Job, JobKind


MIB_BYTES = 1024 * 1024


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _manifest_rss_mib(manifest: Mapping[str, object]) -> int:
    resources = manifest.get("resources")
    if not isinstance(resources, Mapping):
        raise ValueError("manifest resources must be an object")
    peak_rss_bytes = resources.get("peak_rss_bytes")
    _positive_int(peak_rss_bytes, "manifest resources.peak_rss_bytes")
    return math.ceil(peak_rss_bytes / MIB_BYTES)


def _manifest_seeds(manifest: Mapping[str, object]) -> tuple[int, ...]:
    values = manifest.get("seeds", (0,))
    if not isinstance(values, (list, tuple)):
        raise ValueError("manifest seeds must be a list of non-negative integers")
    seeds = tuple(sorted(values))
    if not seeds:
        raise ValueError("manifest seeds must not be empty")
    if len(set(seeds)) != len(seeds):
        raise ValueError("manifest seeds must be unique")
    for seed in seeds:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("manifest seeds must be a list of non-negative integers")
    return seeds


def _candidate_hash(manifest: Mapping[str, object]) -> str:
    return candidate_semantic_hash(manifest)


def _job_token(kind: JobKind, candidate_hash: str, cache_key: str, seed: int) -> str:
    return hashlib.sha256(f"{kind.value}|{candidate_hash}|{cache_key}|{seed}".encode("utf-8")).hexdigest()


def _make_job(
    kind: JobKind,
    candidate_hash: str,
    cache_key: str,
    requested_mib: int,
    seed: int,
    worker_limit: int,
    gate_name: str,
) -> Job:
    token = _job_token(kind, candidate_hash, cache_key, seed)
    return Job(
        job_id=f"{kind.value}-{token}",
        kind=kind,
        gate_name=gate_name,
        owner=f"job-{token}",
        requested_mib=requested_mib,
        seed=seed,
        candidate_hash=candidate_hash,
        build_cache_key=cache_key,
        worker_limit=worker_limit,
    )


def plan_jobs(
    manifests: Sequence[Mapping[str, object]], host_memory_mib: int, max_workers: int
) -> tuple[Job, ...]:
    """Plan stable build and fuzz jobs without inspecting any identifier text."""
    _positive_int(host_memory_mib, "host_memory_mib")
    _positive_int(max_workers, "max_workers")

    records: list[tuple[str, str, int, tuple[int, ...]]] = []
    for manifest in manifests:
        if not isinstance(manifest, Mapping):
            raise TypeError("manifests must contain mapping objects")
        cache_key = manifest.get("build_cache_key")
        if not isinstance(cache_key, str) or not cache_key:
            raise ValueError("manifest build_cache_key must be a non-empty string")
        records.append((_candidate_hash(manifest), cache_key, _manifest_rss_mib(manifest), _manifest_seeds(manifest)))

    records.sort()
    if not records:
        return ()
    largest_rss_mib = max(record[2] for record in records)
    worker_limit = min(max_workers, host_memory_mib // largest_rss_mib)
    if worker_limit < 1:
        raise ValueError("host memory cannot fit one measured worker")

    build_records: dict[str, tuple[str, int]] = {}
    for candidate_hash, cache_key, requested_mib, _seeds in records:
        previous = build_records.get(cache_key)
        if previous is None:
            build_records[cache_key] = (candidate_hash, requested_mib)
        else:
            build_records[cache_key] = (min(previous[0], candidate_hash), max(previous[1], requested_mib))

    builds = tuple(
        _make_job(JobKind.BUILD, candidate_hash, cache_key, requested_mib, 0, 1, "build")
        for cache_key, (candidate_hash, requested_mib) in sorted(build_records.items())
    )
    fuzzes: list[Job] = []
    ordered_fuzz_inputs = tuple(
        (candidate_hash, cache_key, requested_mib, seed)
        for candidate_hash, cache_key, requested_mib, seeds in records
        for seed in seeds
    )
    for index, (candidate_hash, cache_key, requested_mib, seed) in enumerate(ordered_fuzz_inputs):
        fuzzes.append(
            _make_job(
                JobKind.FUZZ,
                candidate_hash,
                cache_key,
                requested_mib,
                seed,
                worker_limit,
                f"fuzz-slot-{index % worker_limit}",
            )
        )
    return builds + tuple(fuzzes)
