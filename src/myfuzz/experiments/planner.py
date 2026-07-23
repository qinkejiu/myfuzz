"""Deterministic planning for fair declarative harness experiments."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.contracts import canonical_bytes, content_hash, validate_contract

from .jobs import Job, JobKind


class ExperimentPlanError(ValueError):
    """Raised when an experiment cannot satisfy its fairness contract."""


@dataclass(frozen=True, slots=True)
class ExperimentJob(Job):
    """One stable runnable cell in an experiment matrix."""

    target_id: str
    candidate_id: str
    harness: str
    budget_kind: str
    budget_value: int
    config_path: str
    estimated_rss_bytes: int
    priority: int
    budget_name: str = ""
    raw_width: int = 0
    instrumented_rtl_hash: str = ""
    coverage_universe: str = ""
    mutation: tuple[tuple[str, int | bool | str], ...] = ()


@dataclass(frozen=True, slots=True)
class FairnessAudit:
    candidate_pair_has_equal_budget: bool
    candidate_pair_has_equal_seeds: bool
    candidate_pair_has_equal_raw_width: bool
    shared_instrumented_rtl: bool
    shared_coverage_universe: bool


@dataclass(frozen=True, slots=True)
class RuntimePolicy:
    """Bounded host-resource policy retained with every experiment plan."""

    build_concurrency: int
    waveforms: bool
    replay_queue_capacity: int
    event_ring_capacity: int
    field_groups_per_batch: int
    soft_memory_bytes: int
    hard_memory_bytes: int
    token_bytes: int
    unknown_rss_bytes: int


@dataclass(frozen=True, slots=True)
class ExperimentPlan:
    jobs: tuple[ExperimentJob, ...]
    build_jobs: tuple[Job, ...]
    run_blocks: tuple[tuple[str, ...], ...]
    fairness: FairnessAudit
    runtime_policy: RuntimePolicy
    plan_hash: str

    @property
    def execution_jobs(self) -> tuple[Job, ...]:
        """Return build prerequisites followed by the runnable fuzz matrix."""
        return self.build_jobs + self.jobs


@dataclass(frozen=True, slots=True)
class _Budget:
    name: str
    kind: str
    value: int


@dataclass(frozen=True, slots=True)
class _PlannerConfig:
    target_id: str
    config_path: str
    candidate_count: int
    seeds: tuple[int, ...]
    budgets: tuple[_Budget, ...]
    mutation: tuple[tuple[str, int | bool | str], ...]
    runtime_policy: RuntimePolicy


@dataclass(frozen=True, slots=True)
class _Candidate:
    candidate_id: str
    candidate_hash: str
    build_cache_key: str
    estimated_rss_bytes: int
    flat_raw_width: int
    candidate_raw_width: int
    flat_instrumented_rtl_hash: str
    candidate_instrumented_rtl_hash: str
    flat_coverage_universe: str
    candidate_coverage_universe: str


_HARNESS_GROUPS = ("flat-direct", "candidate-direct", "candidate-depaware")
_CANDIDATE_GROUPS = ("candidate-direct", "candidate-depaware")
_BUDGET_KINDS = frozenset(("cycles", "seconds"))
_COVERAGE_MEASURES = frozenset(("percentage", "covered-count", "shared-stable-source-id"))
_MIB_BYTES = 1024 * 1024


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ExperimentPlanError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ExperimentPlanError(f"{label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExperimentPlanError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExperimentPlanError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExperimentPlanError(f"{label} must be a non-negative integer")
    return value


def _parse_mutation(value: object) -> tuple[tuple[str, int | bool | str], ...]:
    document = _object(value, "mutation")
    if not document:
        raise ExperimentPlanError("mutation must not be empty")
    result: list[tuple[str, int | bool | str]] = []
    for key, item in sorted(document.items()):
        _string(key, "mutation key")
        if not isinstance(item, (int, bool, str)) or isinstance(item, str) and not item:
            raise ExperimentPlanError(f"mutation.{key} must be a scalar")
        result.append((key, item))
    return tuple(result)


def _parse_budgets(value: object) -> tuple[_Budget, ...]:
    budgets: list[_Budget] = []
    seen: set[str] = set()
    for index, item in enumerate(_array(value, "budgets")):
        record = _object(item, f"budgets[{index}]")
        name = _string(record.get("name"), f"budgets[{index}].name")
        kind = _string(record.get("kind"), f"budgets[{index}].kind")
        budget_value = _positive_int(record.get("value"), f"budgets[{index}].value")
        if name in seen:
            raise ExperimentPlanError("budget names must be unique")
        if kind not in _BUDGET_KINDS:
            raise ExperimentPlanError(f"unsupported budget kind: {kind}")
        seen.add(name)
        budgets.append(_Budget(name, kind, budget_value))
    if not budgets:
        raise ExperimentPlanError("budgets must not be empty")
    return tuple(sorted(budgets, key=lambda budget: (budget.name, budget.kind, budget.value)))


def _validate_coverage(value: object, harness_groups: tuple[str, ...]) -> None:
    coverage = _object(value, "coverage")
    _string(coverage.get("metric"), "coverage.metric")
    scopes = {
        "flat-direct": "flat",
        "candidate-direct": "candidate",
        "candidate-depaware": "candidate",
    }
    for index, item in enumerate(_array(coverage.get("comparisons"), "coverage.comparisons")):
        comparison = _object(item, f"coverage.comparisons[{index}]")
        left = _string(comparison.get("left_harness"), f"coverage.comparisons[{index}].left_harness")
        right = _string(comparison.get("right_harness"), f"coverage.comparisons[{index}].right_harness")
        measure = _string(comparison.get("measure"), f"coverage.comparisons[{index}].measure")
        if left not in harness_groups or right not in harness_groups:
            raise ExperimentPlanError("coverage comparison references an undeclared harness")
        if measure not in _COVERAGE_MEASURES:
            raise ExperimentPlanError(f"unsupported coverage comparison measure: {measure}")
        if measure == "percentage" and scopes[left] != scopes[right]:
            raise ExperimentPlanError("cannot compare coverage percentages across distinct universes")


def _validate_reference(value: object) -> None:
    reference = _object(value, "reference")
    expected = {
        "mode": "evaluation-only",
        "allowed_stage": "report",
        "comparison": "shared-stable-source-id",
    }
    if dict(reference) != expected:
        raise ExperimentPlanError("reference must be evaluation-only report metadata")


def _parse_config(config: object) -> _PlannerConfig:
    document = _object(config, "config")
    if document.get("schema_version") != "experiment.v1":
        raise ExperimentPlanError("schema_version must be experiment.v1")

    target = _object(document.get("target"), "target")
    target_id = _string(target.get("target_id"), "target.target_id")
    config_path_value = document.get("config_path", "")
    config_path = "" if config_path_value == "" else _string(config_path_value, "config_path")
    selection = _object(document.get("candidate_selection"), "candidate_selection")
    candidate_count = _positive_int(selection.get("k"), "candidate_selection.k")

    declared_groups = tuple(
        _string(item, "harness_groups") for item in _array(document.get("harness_groups"), "harness_groups")
    )
    if len(declared_groups) != len(_HARNESS_GROUPS) or set(declared_groups) != set(_HARNESS_GROUPS):
        raise ExperimentPlanError("harness_groups must declare each supported group once")

    candidate_pair = _object(document.get("candidate_pair"), "candidate_pair")
    seeds = tuple(
        sorted(_nonnegative_int(item, "candidate_pair.seeds") for item in _array(candidate_pair.get("seeds"), "candidate_pair.seeds"))
    )
    if not seeds or len(seeds) != len(set(seeds)):
        raise ExperimentPlanError("candidate_pair.seeds must be non-empty and unique")

    budgets = _parse_budgets(document.get("budgets"))
    mutation = _parse_mutation(document.get("mutation"))
    _validate_coverage(document.get("coverage"), declared_groups)

    build_concurrency = _positive_int(document.get("build_concurrency"), "build_concurrency")
    if build_concurrency != 1:
        raise ExperimentPlanError("build_concurrency must be 1")
    waveforms = document.get("waveforms")
    if waveforms is not False:
        raise ExperimentPlanError("waveforms must be false")
    replay_capacity = _positive_int(document.get("replay_queue_capacity"), "replay_queue_capacity")
    event_capacity = _positive_int(document.get("event_ring_capacity"), "event_ring_capacity")
    field_groups = _positive_int(document.get("field_groups_per_batch"), "field_groups_per_batch")
    if replay_capacity > 128 or event_capacity > 4_096 or field_groups > 64:
        raise ExperimentPlanError("runtime queues and field batches exceed bounded limits")

    soft_memory = _positive_int(document.get("soft_memory_bytes"), "soft_memory_bytes")
    hard_memory = _positive_int(document.get("hard_memory_bytes"), "hard_memory_bytes")
    token_bytes = _positive_int(document.get("token_bytes"), "token_bytes")
    if soft_memory >= hard_memory:
        raise ExperimentPlanError("soft_memory_bytes must be less than hard_memory_bytes")
    if token_bytes > soft_memory:
        raise ExperimentPlanError("token_bytes must not exceed soft_memory_bytes")

    reference = document.get("reference")
    if reference is not None:
        _validate_reference(reference)
    runtime_policy = RuntimePolicy(
        build_concurrency=build_concurrency,
        waveforms=waveforms,
        replay_queue_capacity=replay_capacity,
        event_ring_capacity=event_capacity,
        field_groups_per_batch=field_groups,
        soft_memory_bytes=soft_memory,
        hard_memory_bytes=hard_memory,
        token_bytes=token_bytes,
        # No measurement means no evidence for a smaller reservation. Reserving
        # the complete soft allowance admits at most one unknown worker.
        unknown_rss_bytes=soft_memory,
    )
    return _PlannerConfig(
        target_id,
        config_path,
        candidate_count,
        seeds,
        budgets,
        mutation,
        runtime_policy,
    )


def _harness_record(manifest: Mapping[str, object], harness: str) -> Mapping[str, object]:
    harnesses = _object(manifest.get("harnesses"), "manifest.harnesses")
    value = harnesses.get(harness)
    return value if isinstance(value, Mapping) else {}


def _fallback_raw_width(manifest: Mapping[str, object]) -> int:
    width = 0
    for index, item in enumerate(_array(manifest.get("top_port_abi"), "manifest.top_port_abi")):
        port = _object(item, f"manifest.top_port_abi[{index}]")
        if port.get("direction") in ("input", "inout"):
            width += _positive_int(port.get("width"), f"manifest.top_port_abi[{index}].width")
    if width <= 0:
        raise ExperimentPlanError("candidate manifest has no runnable raw input width")
    return width


def _raw_width(record: Mapping[str, object], fallback: int, label: str) -> int:
    value = record.get("raw_width")
    return fallback if value is None else _positive_int(value, f"{label}.raw_width")


def _universe_from_record(record: Mapping[str, object]) -> str | None:
    for key in ("coverage_universe", "coverage_universe_id", "coverage_universe_hash"):
        value = record.get(key)
        if value is not None:
            return _string(value, f"harness.{key}")
    return None


def _candidate_universe(manifest: Mapping[str, object]) -> str:
    points = _array(manifest.get("coverage_universe"), "manifest.coverage_universe")
    ordered = sorted(points, key=canonical_bytes)
    return content_hash({"coverage_universe": ordered})


def _instrumented_rtl(record: Mapping[str, object], fallback: str) -> str:
    for key in ("instrumented_rtl_hash", "top_content_hash"):
        value = record.get(key)
        if value is not None:
            return _string(value, f"harness.{key}")
    return fallback


def _estimated_rss(manifest: Mapping[str, object], fallback: int) -> int:
    resources = _object(manifest.get("resources"), "manifest.resources")
    value = resources.get("peak_rss_bytes")
    return fallback if value is None else _positive_int(value, "manifest.resources.peak_rss_bytes")


def _parse_candidate(manifest: Mapping[str, object], config: _PlannerConfig) -> _Candidate:
    candidate_id = _string(manifest.get("candidate_id"), "manifest.candidate_id")
    composition_ir_hash = _string(manifest.get("composition_ir_hash"), "manifest.composition_ir_hash")
    build_cache_key = _string(manifest.get("build_cache_key"), "manifest.build_cache_key")
    top = _object(manifest.get("top"), "manifest.top")
    top_hash = _string(top.get("content_hash"), "manifest.top.content_hash")

    direct_record = _harness_record(manifest, "candidate-direct")
    depaware_record = _harness_record(manifest, "candidate-depaware")
    flat_record = _harness_record(manifest, "flat-direct")
    fallback_width = _fallback_raw_width(manifest)
    direct_width = _raw_width(direct_record, fallback_width, "candidate-direct")
    depaware_width = _raw_width(depaware_record, fallback_width, "candidate-depaware")
    if direct_width != depaware_width:
        raise ExperimentPlanError("candidate pair raw width must be equal")

    direct_rtl = _instrumented_rtl(direct_record, top_hash)
    depaware_rtl = _instrumented_rtl(depaware_record, top_hash)
    if direct_rtl != depaware_rtl:
        raise ExperimentPlanError("candidate pair instrumented RTL must be shared")

    default_universe = _candidate_universe(manifest)
    direct_universe = _universe_from_record(direct_record) or default_universe
    depaware_universe = _universe_from_record(depaware_record) or default_universe
    if direct_universe != depaware_universe:
        raise ExperimentPlanError("candidate pair coverage universe must be shared")

    flat_universe = _universe_from_record(flat_record) or content_hash(
        {"scope": "flat-direct", "target_id": config.target_id}
    )
    if flat_universe == direct_universe:
        raise ExperimentPlanError("flat-direct must use a distinct coverage universe")

    return _Candidate(
        candidate_id=candidate_id,
        candidate_hash=content_hash(
            {
                "candidate_id": candidate_id,
                "composition_ir_hash": composition_ir_hash,
                "top_content_hash": top_hash,
                "build_cache_key": build_cache_key,
            }
        ),
        build_cache_key=build_cache_key,
        estimated_rss_bytes=_estimated_rss(manifest, config.runtime_policy.unknown_rss_bytes),
        flat_raw_width=_raw_width(flat_record, fallback_width, "flat-direct"),
        candidate_raw_width=direct_width,
        flat_instrumented_rtl_hash=_instrumented_rtl(flat_record, top_hash),
        candidate_instrumented_rtl_hash=direct_rtl,
        flat_coverage_universe=flat_universe,
        candidate_coverage_universe=direct_universe,
    )


def _base_job_document(job: Job) -> dict[str, object]:
    return {
        "job_id": job.job_id,
        "kind": job.kind.value,
        "gate_name": job.gate_name,
        "owner": job.owner,
        "requested_mib": job.requested_mib,
        "seed": job.seed,
        "candidate_hash": job.candidate_hash,
        "build_cache_key": job.build_cache_key,
        "worker_limit": job.worker_limit,
    }


def _job_document(job: ExperimentJob) -> dict[str, object]:
    document = _base_job_document(job)
    document.update({
        "target_id": job.target_id,
        "candidate_id": job.candidate_id,
        "harness": job.harness,
        "budget_name": job.budget_name,
        "budget_kind": job.budget_kind,
        "budget_value": job.budget_value,
        "config_path": job.config_path,
        "estimated_rss_bytes": job.estimated_rss_bytes,
        "priority": job.priority,
        "raw_width": job.raw_width,
        "instrumented_rtl_hash": job.instrumented_rtl_hash,
        "coverage_universe": job.coverage_universe,
        "mutation": dict(job.mutation),
    })
    return document


def _runtime_policy_document(policy: RuntimePolicy) -> dict[str, object]:
    return {
        "build_concurrency": policy.build_concurrency,
        "waveforms": policy.waveforms,
        "replay_queue_capacity": policy.replay_queue_capacity,
        "event_ring_capacity": policy.event_ring_capacity,
        "field_groups_per_batch": policy.field_groups_per_batch,
        "soft_memory_bytes": policy.soft_memory_bytes,
        "hard_memory_bytes": policy.hard_memory_bytes,
        "token_bytes": policy.token_bytes,
        "unknown_rss_bytes": policy.unknown_rss_bytes,
    }


def _requested_mib(estimated_rss_bytes: int) -> int:
    return (estimated_rss_bytes + _MIB_BYTES - 1) // _MIB_BYTES


def _make_job(
    config: _PlannerConfig,
    candidate: _Candidate,
    harness: str,
    seed: int,
    budget: _Budget,
    priority: int,
    worker_limit: int,
    slot_index: int,
) -> ExperimentJob:
    is_flat = harness == "flat-direct"
    raw_width = candidate.flat_raw_width if is_flat else candidate.candidate_raw_width
    rtl_hash = (
        candidate.flat_instrumented_rtl_hash if is_flat else candidate.candidate_instrumented_rtl_hash
    )
    universe = candidate.flat_coverage_universe if is_flat else candidate.candidate_coverage_universe
    requested_mib = _requested_mib(candidate.estimated_rss_bytes)
    gate_name = f"fuzz-slot-{slot_index % worker_limit}"
    identity = {
        "target_id": config.target_id,
        "candidate_id": candidate.candidate_id,
        "candidate_hash": candidate.candidate_hash,
        "harness": harness,
        "seed": seed,
        "budget_name": budget.name,
        "budget_kind": budget.kind,
        "budget_value": budget.value,
        "build_cache_key": candidate.build_cache_key,
        "config_path": config.config_path,
        "estimated_rss_bytes": candidate.estimated_rss_bytes,
        "priority": priority,
        "kind": JobKind.FUZZ.value,
        "gate_name": gate_name,
        "requested_mib": requested_mib,
        "worker_limit": worker_limit,
        "raw_width": raw_width,
        "instrumented_rtl_hash": rtl_hash,
        "coverage_universe": universe,
        "mutation": dict(config.mutation),
    }
    token = content_hash(identity).removeprefix("sha256:")
    return ExperimentJob(
        job_id=f"fuzz-{token}",
        kind=JobKind.FUZZ,
        gate_name=gate_name,
        owner=f"job-{token}",
        requested_mib=requested_mib,
        seed=seed,
        candidate_hash=candidate.candidate_hash,
        build_cache_key=candidate.build_cache_key,
        worker_limit=worker_limit,
        target_id=config.target_id,
        candidate_id=candidate.candidate_id,
        harness=harness,
        budget_kind=budget.kind,
        budget_value=budget.value,
        config_path=config.config_path,
        estimated_rss_bytes=candidate.estimated_rss_bytes,
        priority=priority,
        budget_name=budget.name,
        raw_width=raw_width,
        instrumented_rtl_hash=rtl_hash,
        coverage_universe=universe,
        mutation=config.mutation,
    )


def _make_build_jobs(candidates: tuple[_Candidate, ...]) -> tuple[Job, ...]:
    build_records: dict[str, tuple[str, int]] = {}
    for candidate in candidates:
        previous = build_records.get(candidate.build_cache_key)
        if previous is None:
            build_records[candidate.build_cache_key] = (
                candidate.candidate_hash,
                candidate.estimated_rss_bytes,
            )
        else:
            build_records[candidate.build_cache_key] = (
                min(previous[0], candidate.candidate_hash),
                max(previous[1], candidate.estimated_rss_bytes),
            )

    jobs: list[Job] = []
    for cache_key, (candidate_hash, estimated_rss_bytes) in sorted(build_records.items()):
        requested_mib = _requested_mib(estimated_rss_bytes)
        identity = {
            "kind": JobKind.BUILD.value,
            "gate_name": "build",
            "requested_mib": requested_mib,
            "seed": 0,
            "candidate_hash": candidate_hash,
            "build_cache_key": cache_key,
            "worker_limit": 1,
        }
        token = content_hash(identity).removeprefix("sha256:")
        jobs.append(
            Job(
                job_id=f"build-{token}",
                kind=JobKind.BUILD,
                gate_name="build",
                owner=f"job-{token}",
                requested_mib=requested_mib,
                seed=0,
                candidate_hash=candidate_hash,
                build_cache_key=cache_key,
                worker_limit=1,
            )
        )
    return tuple(jobs)


def _audit_fairness(jobs: tuple[ExperimentJob, ...]) -> FairnessAudit:
    candidate_ids = {job.candidate_id for job in jobs}
    equal_budget = True
    equal_seeds = True
    equal_width = True
    shared_rtl = True
    shared_universe = True
    for candidate_id in candidate_ids:
        direct = tuple(job for job in jobs if job.candidate_id == candidate_id and job.harness == _CANDIDATE_GROUPS[0])
        depaware = tuple(job for job in jobs if job.candidate_id == candidate_id and job.harness == _CANDIDATE_GROUPS[1])
        equal_budget &= {
            (job.seed, job.budget_name, job.budget_kind, job.budget_value) for job in direct
        } == {(job.seed, job.budget_name, job.budget_kind, job.budget_value) for job in depaware}
        equal_seeds &= {job.seed for job in direct} == {job.seed for job in depaware}
        equal_width &= {job.raw_width for job in direct} == {job.raw_width for job in depaware}
        shared_rtl &= {job.instrumented_rtl_hash for job in direct} == {
            job.instrumented_rtl_hash for job in depaware
        }
        shared_universe &= {job.coverage_universe for job in direct} == {
            job.coverage_universe for job in depaware
        }
    return FairnessAudit(equal_budget, equal_seeds, equal_width, shared_rtl, shared_universe)


def _require_fairness(audit: FairnessAudit) -> None:
    checks = (
        (audit.candidate_pair_has_equal_budget, "candidate pair budget must be equal"),
        (audit.candidate_pair_has_equal_seeds, "candidate pair seeds must be equal"),
        (audit.candidate_pair_has_equal_raw_width, "candidate pair raw width must be equal"),
        (audit.shared_instrumented_rtl, "candidate pair instrumented RTL must be shared"),
        (audit.shared_coverage_universe, "candidate pair coverage universe must be shared"),
    )
    for passed, message in checks:
        if not passed:
            raise ExperimentPlanError(message)


def _run_blocks(
    jobs: tuple[ExperimentJob, ...],
    config: _PlannerConfig,
    candidates: tuple[_Candidate, ...],
) -> tuple[tuple[str, ...], ...]:
    by_key = {
        (job.candidate_id, job.budget_name, job.seed, job.harness): job.job_id
        for job in jobs
    }
    blocks: list[tuple[str, ...]] = []
    for candidate in candidates:
        for budget in config.budgets:
            for seed in config.seeds:
                digest = hashlib.sha256(
                    canonical_bytes({"seed": seed, "candidate_id": candidate.candidate_id})
                ).digest()
                pair = _CANDIDATE_GROUPS if digest[0] & 1 == 0 else tuple(reversed(_CANDIDATE_GROUPS))
                blocks.append(
                    (
                        by_key[(candidate.candidate_id, budget.name, seed, "flat-direct")],
                        *(by_key[(candidate.candidate_id, budget.name, seed, harness)] for harness in pair),
                    )
                )
    return tuple(blocks)


def plan_experiment(config: object, candidate_manifests: Sequence[object]) -> ExperimentPlan:
    """Create a stable, fair run matrix from declarative configuration data."""
    validated: list[Mapping[str, object]] = []
    for manifest in candidate_manifests:
        validate_contract(manifest, "candidate_manifest.v1")
        validated.append(_object(manifest, "candidate manifest"))
    if not validated:
        raise ExperimentPlanError("candidate_manifests must not be empty")

    parsed_config = _parse_config(config)
    candidates = tuple(sorted((_parse_candidate(item, parsed_config) for item in validated), key=lambda item: item.candidate_id))
    if len({item.candidate_id for item in candidates}) != len(candidates):
        raise ExperimentPlanError("candidate IDs must be unique")
    selected = candidates[: parsed_config.candidate_count]
    if any(
        candidate.estimated_rss_bytes > parsed_config.runtime_policy.soft_memory_bytes
        for candidate in selected
    ):
        raise ExperimentPlanError("measured peak_rss_bytes cannot fit soft memory policy")
    build_jobs = _make_build_jobs(selected)
    largest_rss_bytes = max(candidate.estimated_rss_bytes for candidate in selected)
    worker_limit = max(1, parsed_config.runtime_policy.soft_memory_bytes // largest_rss_bytes)

    jobs: list[ExperimentJob] = []
    for candidate in selected:
        for budget_index, budget in enumerate(parsed_config.budgets):
            priority = len(parsed_config.budgets) - budget_index
            for seed in parsed_config.seeds:
                for harness in _HARNESS_GROUPS:
                    jobs.append(
                        _make_job(
                            parsed_config,
                            candidate,
                            harness,
                            seed,
                            budget,
                            priority,
                            worker_limit,
                            len(jobs),
                        )
                    )
    frozen_jobs = tuple(jobs)
    fairness = _audit_fairness(frozen_jobs)
    _require_fairness(fairness)
    run_blocks = _run_blocks(frozen_jobs, parsed_config, selected)
    plan_document = {
        "build_jobs": [_base_job_document(job) for job in build_jobs],
        "jobs": [_job_document(job) for job in frozen_jobs],
        "run_blocks": [list(block) for block in run_blocks],
        "fairness": {
            "candidate_pair_has_equal_budget": fairness.candidate_pair_has_equal_budget,
            "candidate_pair_has_equal_seeds": fairness.candidate_pair_has_equal_seeds,
            "candidate_pair_has_equal_raw_width": fairness.candidate_pair_has_equal_raw_width,
            "shared_instrumented_rtl": fairness.shared_instrumented_rtl,
            "shared_coverage_universe": fairness.shared_coverage_universe,
        },
        "runtime_policy": _runtime_policy_document(parsed_config.runtime_policy),
    }
    return ExperimentPlan(
        jobs=frozen_jobs,
        build_jobs=build_jobs,
        run_blocks=run_blocks,
        fairness=fairness,
        runtime_policy=parsed_config.runtime_policy,
        plan_hash=content_hash(plan_document),
    )
