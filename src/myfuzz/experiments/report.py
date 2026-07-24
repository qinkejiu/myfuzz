"""Deterministic per-candidate experiment result aggregation."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.contracts import canonical_bytes, content_hash, validate_contract

from .identity import candidate_semantic_hash
from .planner import ExperimentJob, ExperimentPlan


class ReportError(ValueError):
    """Raised when result samples violate experiment fairness contracts."""


_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
_HARNESS_GROUPS = frozenset(("flat-direct", "candidate-direct", "candidate-depaware"))
_CANDIDATE_GROUPS = ("candidate-direct", "candidate-depaware")
_CUMULATIVE_COUNTER_FIELDS = (
    "tests_executed",
    "cycles_executed",
    "peak_rss_bytes",
    "projection_count",
    "protocol_event_count",
    "no_progress_cycles",
    "generation_count",
    "validation_passed",
)
_CUMULATIVE_MAP_FIELDS = ("correction_counts", "failure_reasons")


@dataclass(frozen=True, slots=True)
class _CoveragePoint:
    point_id: int
    stable_source_id: str
    component_role: str


@dataclass(frozen=True, slots=True)
class _CandidateManifest:
    candidate_id: str
    points: tuple[_CoveragePoint, ...]
    default_coverage_universe: str
    coverage_universe_overrides: tuple[tuple[str, str | None], ...]
    candidate_hash: str
    build_cache_key: str
    peak_rss_bytes: int | None
    raw_widths: tuple[tuple[str, int], ...]
    instrumented_rtl_hashes: tuple[tuple[str, str], ...]

    @property
    def point_ids(self) -> frozenset[int]:
        return frozenset(point.point_id for point in self.points)

    @property
    def stable_source_ids(self) -> frozenset[str]:
        return frozenset(point.stable_source_id for point in self.points)

    def raw_width(self, harness: str) -> int:
        return dict(self.raw_widths)[harness]

    def instrumented_rtl_hash(self, harness: str) -> str:
        return dict(self.instrumented_rtl_hashes)[harness]

    def coverage_universe(self, harness: str, target_id: str) -> str:
        override = dict(self.coverage_universe_overrides)[harness]
        if override is not None:
            return override
        if harness == "flat-direct":
            return content_hash({"scope": "flat-direct", "target_id": target_id})
        return self.default_coverage_universe

    def estimated_rss_bytes(self, fallback: int) -> int:
        return fallback if self.peak_rss_bytes is None else self.peak_rss_bytes


@dataclass(frozen=True, slots=True)
class _Sample:
    job_id: str
    candidate_id: str
    harness: str
    seed: int
    elapsed_seconds: int | float
    sequence: int
    common_total: int
    covered_point_ids: tuple[int, ...]
    tests_executed: int
    cycles_executed: int
    peak_rss_bytes: int
    projection_count: int
    correction_counts: tuple[tuple[str, int], ...]
    protocol_event_count: int
    no_progress_cycles: int
    generation_count: int
    validation_passed: int
    failure_reasons: tuple[tuple[str, int], ...]

    @property
    def sort_key(self) -> tuple[str, str, int, int | float, int, str]:
        return (
            self.candidate_id,
            self.harness,
            self.seed,
            self.elapsed_seconds,
            self.sequence,
            self.job_id,
        )


@dataclass(frozen=True, slots=True)
class _PlanIndex:
    candidate_ids: tuple[str, ...]
    jobs_by_id: dict[str, ExperimentJob]
    candidate_budgets: dict[str, tuple[str, ...]]
    budget_metadata: dict[str, tuple[str, int]]
    universes: dict[tuple[str, str], str]


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ReportError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ReportError(f"{label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReportError(f"{label} must be a non-empty string")
    return value


def _bounded_int(value: object, label: str, maximum: int, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        qualifier = "positive" if positive else "non-negative"
        raise ReportError(f"{label} must be a {qualifier} integer no greater than {maximum}")
    return value


def _uint32(value: object, label: str, *, positive: bool = False) -> int:
    return _bounded_int(value, label, _UINT32_MAX, positive=positive)


def _uint64(value: object, label: str) -> int:
    return _bounded_int(value, label, _UINT64_MAX)


def _elapsed(value: object, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{label} must be a finite non-negative number")
    if not math.isfinite(value) or value < 0 or value > _UINT64_MAX:
        raise ReportError(f"{label} must be a finite non-negative number")
    return value


def _counter_map(value: object, label: str) -> tuple[tuple[str, int], ...]:
    document = _object(value, label)
    counters: list[tuple[str, int]] = []
    for key, count in document.items():
        name = _string(key, f"{label} key")
        counters.append((name, _uint64(count, f"{label}.{name}")))
    return tuple(sorted(counters))


def _harness_record(manifest: Mapping[str, object], harness: str) -> Mapping[str, object]:
    harnesses = _object(manifest.get("harnesses"), "manifest.harnesses")
    value = harnesses.get(harness)
    return value if isinstance(value, Mapping) else {}


def _fallback_raw_width(manifest: Mapping[str, object]) -> int:
    width = 0
    for index, item in enumerate(_array(manifest.get("top_port_abi"), "manifest.top_port_abi")):
        port = _object(item, f"manifest.top_port_abi[{index}]")
        if port.get("direction") in ("input", "inout"):
            width += _bounded_int(
                port.get("width"),
                f"manifest.top_port_abi[{index}].width",
                _UINT64_MAX,
                positive=True,
            )
    if width <= 0 or width > _UINT64_MAX:
        raise ReportError("manifest top_port_abi must have a bounded positive raw_width")
    return width


def _manifest_raw_width(
    manifest: Mapping[str, object],
    harness: str,
    fallback: int,
) -> int:
    value = _harness_record(manifest, harness).get("raw_width")
    if value is None:
        return fallback
    return _bounded_int(
        value,
        f"manifest.harnesses.{harness}.raw_width",
        _UINT64_MAX,
        positive=True,
    )


def _manifest_instrumented_rtl_hash(
    manifest: Mapping[str, object],
    harness: str,
    fallback: str,
) -> str:
    record = _harness_record(manifest, harness)
    for key in ("instrumented_rtl_hash", "top_content_hash"):
        value = record.get(key)
        if value is not None:
            return _string(value, f"manifest.harnesses.{harness}.{key}")
    return fallback


def _manifest_coverage_universe_override(
    manifest: Mapping[str, object],
    harness: str,
) -> str | None:
    record = _harness_record(manifest, harness)
    for key in ("coverage_universe", "coverage_universe_id", "coverage_universe_hash"):
        value = record.get(key)
        if value is not None:
            return _string(value, f"manifest.harnesses.{harness}.{key}")
    return None


def _parse_manifest(value: object, index: int) -> _CandidateManifest:
    validate_contract(value, "candidate_manifest.v1")
    manifest = _object(value, f"candidate_manifests[{index}]")
    candidate_id = _string(manifest.get("candidate_id"), f"candidate_manifests[{index}].candidate_id")
    points: list[_CoveragePoint] = []
    seen_point_ids: set[int] = set()
    coverage_points = _array(
        manifest.get("coverage_universe"),
        f"candidate_manifests[{index}].coverage_universe",
    )
    for point_index, point_value in enumerate(coverage_points):
        label = f"candidate_manifests[{index}].coverage_universe[{point_index}]"
        point = _object(point_value, label)
        point_id = _uint32(point.get("point_id"), f"{label}.point_id", positive=True)
        if point_id in seen_point_ids:
            raise ReportError(f"{label}.point_id must be unique within a candidate")
        seen_point_ids.add(point_id)
        stable_source_id = _string(point.get("stable_source_id"), f"{label}.stable_source_id")
        _uint32(point.get("component_id"), f"{label}.component_id", positive=True)
        component_role = _string(point.get("component_role"), f"{label}.component_role")
        source = _object(point.get("source"), f"{label}.source")
        _uint32(source.get("file_id"), f"{label}.source.file_id", positive=True)
        _uint32(source.get("line"), f"{label}.source.line", positive=True)
        _uint32(source.get("column"), f"{label}.source.column")
        points.append(_CoveragePoint(point_id, stable_source_id, component_role))
    _string(
        manifest.get("composition_ir_hash"),
        f"candidate_manifests[{index}].composition_ir_hash",
    )
    build_cache_key = _string(
        manifest.get("build_cache_key"),
        f"candidate_manifests[{index}].build_cache_key",
    )
    resources = _object(
        manifest.get("resources"),
        f"candidate_manifests[{index}].resources",
    )
    peak_rss_value = resources.get("peak_rss_bytes")
    if peak_rss_value is None:
        peak_rss_bytes = None
    elif (
        isinstance(peak_rss_value, bool)
        or not isinstance(peak_rss_value, int)
        or peak_rss_value <= 0
    ):
        raise ReportError(
            f"candidate_manifests[{index}].resources.peak_rss_bytes "
            "must be a positive integer or null"
        )
    else:
        peak_rss_bytes = peak_rss_value
    top = _object(manifest.get("top"), f"candidate_manifests[{index}].top")
    top_content_hash = _string(
        top.get("content_hash"),
        f"candidate_manifests[{index}].top.content_hash",
    )
    fallback_width = _fallback_raw_width(manifest)
    raw_widths = tuple(
        (harness, _manifest_raw_width(manifest, harness, fallback_width))
        for harness in sorted(_HARNESS_GROUPS)
    )
    instrumented_rtl_hashes = tuple(
        (
            harness,
            _manifest_instrumented_rtl_hash(
                manifest,
                harness,
                top_content_hash,
            ),
        )
        for harness in sorted(_HARNESS_GROUPS)
    )
    default_coverage_universe = content_hash(
        {"coverage_universe": sorted(coverage_points, key=canonical_bytes)}
    )
    coverage_universe_overrides = tuple(
        (harness, _manifest_coverage_universe_override(manifest, harness))
        for harness in sorted(_HARNESS_GROUPS)
    )
    candidate_hash = candidate_semantic_hash(manifest)
    return _CandidateManifest(
        candidate_id,
        tuple(sorted(points, key=lambda point: point.point_id)),
        default_coverage_universe,
        coverage_universe_overrides,
        candidate_hash,
        build_cache_key,
        peak_rss_bytes,
        raw_widths,
        instrumented_rtl_hashes,
    )


def _parse_sample(value: object, index: int) -> _Sample:
    label = f"samples[{index}]"
    sample = _object(value, label)
    covered_point_ids = tuple(
        _uint32(point_id, f"{label}.covered_point_ids[{point_index}]", positive=True)
        for point_index, point_id in enumerate(
            _array(sample.get("covered_point_ids"), f"{label}.covered_point_ids")
        )
    )
    if len(covered_point_ids) != len(set(covered_point_ids)):
        raise ReportError(f"{label}.covered_point_ids must not contain duplicates")
    parsed = _Sample(
        job_id=_string(sample.get("job_id"), f"{label}.job_id"),
        candidate_id=_string(sample.get("candidate_id"), f"{label}.candidate_id"),
        harness=_string(sample.get("harness"), f"{label}.harness"),
        seed=_uint64(sample.get("seed"), f"{label}.seed"),
        elapsed_seconds=_elapsed(sample.get("elapsed_seconds"), f"{label}.elapsed_seconds"),
        sequence=_uint64(sample.get("sequence"), f"{label}.sequence"),
        common_total=_uint32(sample.get("common_total"), f"{label}.common_total"),
        covered_point_ids=tuple(sorted(covered_point_ids)),
        tests_executed=_uint64(sample.get("tests_executed"), f"{label}.tests_executed"),
        cycles_executed=_uint64(sample.get("cycles_executed"), f"{label}.cycles_executed"),
        peak_rss_bytes=_uint64(sample.get("peak_rss_bytes"), f"{label}.peak_rss_bytes"),
        projection_count=_uint64(sample.get("projection_count"), f"{label}.projection_count"),
        correction_counts=_counter_map(sample.get("correction_counts"), f"{label}.correction_counts"),
        protocol_event_count=_uint64(
            sample.get("protocol_event_count"), f"{label}.protocol_event_count"
        ),
        no_progress_cycles=_uint64(
            sample.get("no_progress_cycles"), f"{label}.no_progress_cycles"
        ),
        generation_count=_uint64(sample.get("generation_count"), f"{label}.generation_count"),
        validation_passed=_uint64(sample.get("validation_passed"), f"{label}.validation_passed"),
        failure_reasons=_counter_map(sample.get("failure_reasons"), f"{label}.failure_reasons"),
    )
    if parsed.harness not in _HARNESS_GROUPS:
        raise ReportError(f"{label}.harness is not declared by the report contract")
    if parsed.validation_passed > parsed.generation_count:
        raise ReportError(f"{label}.validation_passed must not exceed generation_count")
    return parsed


def _plan_index(plan: ExperimentPlan) -> _PlanIndex:
    if not isinstance(plan, ExperimentPlan):
        raise ReportError("plan must be an ExperimentPlan")
    candidate_ids = tuple(sorted({job.candidate_id for job in plan.jobs}))
    jobs_by_id: dict[str, ExperimentJob] = {}
    budget_metadata: dict[str, tuple[str, int]] = {}
    candidate_budgets: defaultdict[str, set[str]] = defaultdict(set)
    planned_cells: set[tuple[str, str, str, int]] = set()
    universes: dict[tuple[str, str], str] = {}
    for job in plan.jobs:
        if not isinstance(job, ExperimentJob):
            raise ReportError("plan.jobs must contain only ExperimentJob values")
        if job.job_id in jobs_by_id:
            raise ReportError(f"plan contains duplicate job_id {job.job_id}")
        if job.harness not in _HARNESS_GROUPS:
            raise ReportError(f"plan contains unsupported harness {job.harness}")
        if not job.budget_name:
            raise ReportError(f"plan job {job.job_id} has an empty budget_name")
        cell = (job.candidate_id, job.budget_name, job.harness, job.seed)
        if cell in planned_cells:
            raise ReportError(
                "plan contains duplicate candidate/budget/harness/seed fuzz jobs"
            )
        planned_cells.add(cell)
        jobs_by_id[job.job_id] = job
        candidate_budgets[job.candidate_id].add(job.budget_name)
        metadata = (job.budget_kind, job.budget_value)
        previous_metadata = budget_metadata.setdefault(job.budget_name, metadata)
        if previous_metadata != metadata:
            raise ReportError(f"plan has inconsistent metadata for budget {job.budget_name}")
        key = (job.candidate_id, job.harness)
        previous = universes.setdefault(key, job.coverage_universe)
        if previous != job.coverage_universe:
            raise ReportError(f"plan has inconsistent coverage universes for {job.candidate_id}/{job.harness}")
    for candidate_id in candidate_ids:
        direct_key = (candidate_id, "candidate-direct")
        depaware_key = (candidate_id, "candidate-depaware")
        flat_key = (candidate_id, "flat-direct")
        if direct_key not in universes or depaware_key not in universes or flat_key not in universes:
            raise ReportError(f"plan is missing a harness group for {candidate_id}")
        if universes[direct_key] != universes[depaware_key]:
            raise ReportError(f"candidate pair coverage universe must be shared for {candidate_id}")
        if universes[flat_key] == universes[direct_key]:
            raise ReportError(f"flat-direct coverage universe must be distinct for {candidate_id}")
        for budget_name in candidate_budgets[candidate_id]:
            budget_jobs = [
                job
                for job in jobs_by_id.values()
                if job.candidate_id == candidate_id and job.budget_name == budget_name
            ]
            seeds_by_harness = {
                harness: {job.seed for job in budget_jobs if job.harness == harness}
                for harness in _HARNESS_GROUPS
            }
            if any(not seeds for seeds in seeds_by_harness.values()):
                raise ReportError(
                    f"plan is missing a harness group for {candidate_id}/{budget_name}"
                )
            if len({frozenset(seeds) for seeds in seeds_by_harness.values()}) != 1:
                raise ReportError(
                    f"plan seeds differ across harnesses for {candidate_id}/{budget_name}"
                )
    return _PlanIndex(
        candidate_ids,
        jobs_by_id,
        {
            candidate_id: tuple(sorted(candidate_budgets[candidate_id]))
            for candidate_id in candidate_ids
        },
        budget_metadata,
        universes,
    )


def _validate_cumulative_samples(samples: Sequence[_Sample]) -> None:
    by_job: defaultdict[str, list[_Sample]] = defaultdict(list)
    for sample in samples:
        by_job[sample.job_id].append(sample)
    for job_id, job_samples in sorted(by_job.items()):
        previous: _Sample | None = None
        for sample in sorted(
            job_samples,
            key=lambda item: (item.elapsed_seconds, item.sequence),
        ):
            if previous is not None:
                if not set(previous.covered_point_ids).issubset(sample.covered_point_ids):
                    raise ReportError(
                        "covered_point_ids must be non-decreasing within "
                        f"job_id {job_id}"
                    )
                for field in _CUMULATIVE_COUNTER_FIELDS:
                    if getattr(sample, field) < getattr(previous, field):
                        raise ReportError(
                            f"{field} must be non-decreasing within job_id {job_id}"
                        )
                for field in _CUMULATIVE_MAP_FIELDS:
                    previous_counts = dict(getattr(previous, field))
                    current_counts = dict(getattr(sample, field))
                    for key, previous_count in sorted(previous_counts.items()):
                        if current_counts.get(key, 0) < previous_count:
                            raise ReportError(
                                f"{field}.{key} must be non-decreasing within "
                                f"job_id {job_id}"
                            )
            previous = sample


def _validate_inputs(
    plan: ExperimentPlan,
    candidate_manifests: Sequence[object],
    samples: Sequence[object],
) -> tuple[
    _PlanIndex,
    dict[str, _CandidateManifest],
    tuple[_Sample, ...],
]:
    plan_index = _plan_index(plan)
    manifests: dict[str, _CandidateManifest] = {}
    for index, value in enumerate(_array(candidate_manifests, "candidate_manifests")):
        manifest = _parse_manifest(value, index)
        if manifest.candidate_id in manifests:
            raise ReportError(f"candidate_manifests contains duplicate candidate_id {manifest.candidate_id}")
        manifests[manifest.candidate_id] = manifest
    if set(manifests) != set(plan_index.candidate_ids):
        raise ReportError("candidate_manifests must exactly match candidates selected by the plan")
    for job in plan_index.jobs_by_id.values():
        manifest = manifests[job.candidate_id]
        if job.build_cache_key != manifest.build_cache_key:
            raise ReportError(f"manifest build_cache_key does not match job_id {job.job_id}")
        if job.candidate_hash != manifest.candidate_hash:
            raise ReportError(f"manifest candidate_hash does not match job_id {job.job_id}")
        if job.estimated_rss_bytes != manifest.estimated_rss_bytes(
            plan.runtime_policy.unknown_rss_bytes
        ):
            raise ReportError(
                f"manifest estimated_rss_bytes does not match job_id {job.job_id}"
            )
        if job.raw_width != manifest.raw_width(job.harness):
            raise ReportError(f"manifest raw_width does not match job_id {job.job_id}")
        if job.instrumented_rtl_hash != manifest.instrumented_rtl_hash(job.harness):
            raise ReportError(
                f"manifest instrumented_rtl_hash does not match job_id {job.job_id}"
            )
        if job.coverage_universe != manifest.coverage_universe(
            job.harness,
            job.target_id,
        ):
            raise ReportError(
                f"manifest coverage_universe does not match job_id {job.job_id}"
            )
        if job.coverage_metadata_hash != manifest.default_coverage_universe:
            raise ReportError(
                "manifest coverage_universe coverage_metadata_hash does not match "
                f"job_id {job.job_id}"
            )

    parsed_samples = tuple(
        sorted(
            (_parse_sample(value, index) for index, value in enumerate(_array(samples, "samples"))),
            key=lambda sample: sample.sort_key,
        )
    )
    seen_keys: set[tuple[str, int | float, int]] = set()
    totals: dict[str, int] = {}
    sampled_jobs: set[str] = set()
    for sample in parsed_samples:
        key = (sample.job_id, sample.elapsed_seconds, sample.sequence)
        if key in seen_keys:
            raise ReportError("samples must have unique job_id/time/sequence keys")
        seen_keys.add(key)
        job = plan_index.jobs_by_id.get(sample.job_id)
        if job is None:
            raise ReportError(f"sample job_id is not present in the plan: {sample.job_id}")
        for field in ("candidate_id", "harness", "seed"):
            if getattr(sample, field) != getattr(job, field):
                raise ReportError(
                    f"sample {field} does not match job_id {sample.job_id}"
                )
        manifest = manifests[sample.candidate_id]
        if sample.harness in _CANDIDATE_GROUPS:
            unknown_points = set(sample.covered_point_ids) - manifest.point_ids
            if unknown_points:
                raise ReportError(
                    "sample covered_point_ids are outside candidate "
                    f"{sample.candidate_id}: {sorted(unknown_points)}"
                )
        if len(sample.covered_point_ids) > sample.common_total:
            raise ReportError("sample covered_point_ids exceeds common_total")
        previous_total = totals.setdefault(sample.job_id, sample.common_total)
        if previous_total != sample.common_total:
            raise ReportError(f"common_total changes within job_id {sample.job_id}")
        sampled_jobs.add(sample.job_id)

    missing_jobs = set(plan_index.jobs_by_id) - sampled_jobs
    if missing_jobs:
        raise ReportError(f"samples are missing planned job_id values: {sorted(missing_jobs)}")
    _validate_cumulative_samples(parsed_samples)
    flat_totals: dict[str, int] = {}
    for job in plan_index.jobs_by_id.values():
        if job.harness != "flat-direct":
            continue
        common_total = totals[job.job_id]
        previous_total = flat_totals.setdefault(job.coverage_universe, common_total)
        if previous_total != common_total:
            raise ReportError(
                "flat common_total must be consistent for one coverage universe"
            )
    for candidate_id in plan_index.candidate_ids:
        expected_candidate_total = len(manifests[candidate_id].points)
        for budget_name in plan_index.candidate_budgets[candidate_id]:
            candidate_jobs = [
                job
                for job in plan_index.jobs_by_id.values()
                if job.candidate_id == candidate_id and job.budget_name == budget_name
            ]
            candidate_totals = {
                totals[job.job_id]
                for job in candidate_jobs
                if job.harness in _CANDIDATE_GROUPS
            }
            if len(candidate_totals) != 1:
                raise ReportError(
                    f"candidate pair common_total must be shared for {candidate_id}/{budget_name}"
                )
            if candidate_totals != {expected_candidate_total}:
                raise ReportError(
                    "candidate pair common_total must equal the frozen manifest universe "
                    f"for {candidate_id}/{budget_name}"
                )
    return plan_index, manifests, parsed_samples


def _sum_counter_maps(samples: Sequence[_Sample], attribute: str) -> dict[str, int]:
    totals: defaultdict[str, int] = defaultdict(int)
    for sample in samples:
        for key, value in getattr(sample, attribute):
            totals[key] += value
    return {key: totals[key] for key in sorted(totals)}


def _per_second(count: int, elapsed_seconds: int | float) -> float:
    if not elapsed_seconds:
        return 0.0
    rate = count / elapsed_seconds
    if not math.isfinite(rate):
        raise ReportError("elapsed_seconds produces a non-finite runtime rate")
    return rate


def _runtime_summary(samples: Sequence[_Sample]) -> dict[str, object]:
    by_job: defaultdict[str, list[_Sample]] = defaultdict(list)
    for sample in samples:
        by_job[sample.job_id].append(sample)
    final_samples = [
        sorted(job_samples, key=lambda sample: (sample.elapsed_seconds, sample.sequence))[-1]
        for _, job_samples in sorted(by_job.items())
    ]
    tests_executed = sum(sample.tests_executed for sample in final_samples)
    cycles_executed = sum(sample.cycles_executed for sample in final_samples)
    elapsed_seconds = sum(sample.elapsed_seconds for sample in final_samples)
    projections = sum(sample.projection_count for sample in final_samples)
    generations = sum(sample.generation_count for sample in final_samples)
    validations = sum(sample.validation_passed for sample in final_samples)
    failures = _sum_counter_maps(final_samples, "failure_reasons")
    failures.setdefault("dut_crash", 0)
    failures.setdefault("resource_terminated", 0)
    failures = {key: failures[key] for key in sorted(failures)}
    return {
        "tests_executed": tests_executed,
        "cycles_executed": cycles_executed,
        "elapsed_seconds": elapsed_seconds,
        "tests_per_second": _per_second(tests_executed, elapsed_seconds),
        "cycles_per_second": _per_second(cycles_executed, elapsed_seconds),
        "peak_rss_bytes": max(sample.peak_rss_bytes for sample in samples),
        "projection_count": projections,
        "projection_rate": projections / tests_executed if tests_executed else 0.0,
        "correction_distribution": _sum_counter_maps(final_samples, "correction_counts"),
        "protocol_event_count": sum(sample.protocol_event_count for sample in final_samples),
        "no_progress_cycles": sum(sample.no_progress_cycles for sample in final_samples),
        "generation_count": generations,
        "validation_passed": validations,
        "validation_rate": validations / generations if generations else 0.0,
        "failure_reasons": failures,
    }


def _component_roles(
    manifest: _CandidateManifest,
    covered_point_ids: frozenset[int],
) -> dict[str, object]:
    role_points: defaultdict[str, list[int]] = defaultdict(list)
    for point in manifest.points:
        role_points[point.component_role].append(point.point_id)
    result: dict[str, object] = {}
    for role in sorted(role_points):
        point_ids = sorted(role_points[role])
        covered = sorted(covered_point_ids.intersection(point_ids))
        result[role] = {
            "covered": len(covered),
            "common_total": len(point_ids),
            "covered_point_ids": covered,
        }
    return result


def _harness_summary(
    samples: Sequence[_Sample],
    manifest: _CandidateManifest,
    coverage_universe: str,
    *,
    component_roles_available: bool,
) -> tuple[dict[str, object], frozenset[int]]:
    by_job: defaultdict[str, list[_Sample]] = defaultdict(list)
    for sample in samples:
        by_job[sample.job_id].append(sample)
    covered_all: set[int] = set()
    time_series: list[dict[str, object]] = []
    area = 0.0
    first_discovery: int | float | None = None
    for job_id, job_samples in sorted(by_job.items()):
        seen: set[int] = set()
        previous_time: int | float | None = None
        previous_count = 0
        for sample in sorted(job_samples, key=lambda item: (item.elapsed_seconds, item.sequence)):
            before = len(seen)
            seen.update(sample.covered_point_ids)
            covered = len(seen)
            if previous_time is not None:
                area += (sample.elapsed_seconds - previous_time) * (previous_count + covered) / 2
            if covered > before and (first_discovery is None or sample.elapsed_seconds < first_discovery):
                first_discovery = sample.elapsed_seconds
            time_series.append(
                {
                    "job_id": job_id,
                    "seed": sample.seed,
                    "elapsed_seconds": sample.elapsed_seconds,
                    "sequence": sample.sequence,
                    "covered": covered,
                    "common_total": sample.common_total,
                }
            )
            previous_time = sample.elapsed_seconds
            previous_count = covered
        covered_all.update(seen)
    time_series.sort(
        key=lambda item: (
            item["seed"],
            item["elapsed_seconds"],
            item["sequence"],
            item["job_id"],
        )
    )
    final_covered = frozenset(covered_all)
    common_total = samples[0].common_total
    if len(final_covered) > common_total:
        raise ReportError("covered_point_ids exceeds common_total after aggregation")
    return (
        {
            "coverage_universe": coverage_universe,
            "covered": len(final_covered),
            "common_total": common_total,
            "covered_point_ids": sorted(final_covered),
            "coverage_over_time": time_series,
            "coverage_auc": float(area),
            "first_discovery_seconds": first_discovery,
            "discovery_count": len(final_covered),
            "component_roles_available": component_roles_available,
            "component_roles": (
                _component_roles(manifest, final_covered)
                if component_roles_available
                else {}
            ),
            "runtime": _runtime_summary(samples),
        },
        final_covered,
    )


def _reference_sets(value: object | None) -> tuple[frozenset[str], frozenset[str]] | None:
    if value is None:
        return None
    document = _object(value, "reference_summary")
    if _string(
        document.get("comparison_scope"),
        "reference_summary.comparison_scope",
    ) != "reference-descriptive":
        raise ReportError("reference_summary.comparison_scope must be reference-descriptive")
    stable_sources = frozenset(
        _string(item, f"reference_summary.stable_source_ids[{index}]")
        for index, item in enumerate(
            _array(document.get("stable_source_ids"), "reference_summary.stable_source_ids")
        )
    )
    covered_sources = frozenset(
        _string(item, f"reference_summary.covered_stable_source_ids[{index}]")
        for index, item in enumerate(
            _array(
                document.get("covered_stable_source_ids"),
                "reference_summary.covered_stable_source_ids",
            )
        )
    )
    if not covered_sources.issubset(stable_sources):
        raise ReportError("reference covered_stable_source_ids must belong to stable_source_ids")
    return stable_sources, covered_sources


def _reference_comparison(
    manifest: _CandidateManifest,
    covered_by_harness: Mapping[str, frozenset[int]],
    reference: tuple[frozenset[str], frozenset[str]],
) -> dict[str, object]:
    reference_sources, reference_covered = reference
    shared = manifest.stable_source_ids.intersection(reference_sources)
    source_by_point = {point.point_id: point.stable_source_id for point in manifest.points}
    harness_covered: dict[str, object] = {}
    for harness in sorted(_CANDIDATE_GROUPS):
        sources = {source_by_point[point_id] for point_id in covered_by_harness[harness]}
        harness_covered[harness] = sorted(sources.intersection(shared))
    return {
        "comparison_scope": "reference-descriptive",
        "shared_stable_source_ids": sorted(shared),
        "reference_covered_stable_source_ids": sorted(reference_covered.intersection(shared)),
        "harness_covered_stable_source_ids": harness_covered,
    }


def build_report(
    plan: ExperimentPlan,
    candidate_manifests: Sequence[object],
    samples: Sequence[object],
    reference_summary: object | None = None,
) -> dict[str, object]:
    """Build a canonical-order report without crossing candidate coverage scopes."""
    plan_index, manifests, parsed_samples = _validate_inputs(plan, candidate_manifests, samples)
    reference = _reference_sets(reference_summary)
    grouped: defaultdict[tuple[str, str, str], list[_Sample]] = defaultdict(list)
    for sample in parsed_samples:
        job = plan_index.jobs_by_id[sample.job_id]
        grouped[(sample.candidate_id, job.budget_name, sample.harness)].append(sample)

    candidates: dict[str, object] = {}
    for candidate_id in plan_index.candidate_ids:
        manifest = manifests[candidate_id]
        budgets: dict[str, object] = {}
        for budget_name in plan_index.candidate_budgets[candidate_id]:
            harnesses: dict[str, object] = {}
            covered_by_harness: dict[str, frozenset[int]] = {}
            for harness in sorted(_HARNESS_GROUPS):
                summary, covered = _harness_summary(
                    grouped[(candidate_id, budget_name, harness)],
                    manifest,
                    plan_index.universes[(candidate_id, harness)],
                    component_roles_available=harness in _CANDIDATE_GROUPS,
                )
                harnesses[harness] = summary
                covered_by_harness[harness] = covered

            direct = covered_by_harness["candidate-direct"]
            depaware = covered_by_harness["candidate-depaware"]
            direct_total = harnesses["candidate-direct"]["common_total"]
            budget_kind, budget_value = plan_index.budget_metadata[budget_name]
            budget: dict[str, object] = {
                "budget_kind": budget_kind,
                "budget_value": budget_value,
                "harnesses": harnesses,
                "coverage_attribution": {
                    "comparison_scope": "harness-attribution",
                    "coverage_universe": plan_index.universes[
                        (candidate_id, "candidate-direct")
                    ],
                    "common_total": direct_total,
                    "direct_only_point_ids": sorted(direct - depaware),
                    "depaware_only_point_ids": sorted(depaware - direct),
                    "overlap_point_ids": sorted(direct & depaware),
                },
                "structure_and_projection": {
                    "comparison_scope": "structure-and-projection",
                    "candidate-direct": harnesses["candidate-direct"]["runtime"],
                    "candidate-depaware": harnesses["candidate-depaware"]["runtime"],
                },
                "flat_scope": {
                    "comparison_scope": "harness-attribution",
                    "coverage_universe": plan_index.universes[(candidate_id, "flat-direct")],
                    "candidate_coverage_universe": plan_index.universes[
                        (candidate_id, "candidate-direct")
                    ],
                    "common_total": harnesses["flat-direct"]["common_total"],
                    "percentage_comparison": None,
                },
            }
            if reference is not None:
                budget["reference_comparison"] = _reference_comparison(
                    manifest, covered_by_harness, reference
                )
            budgets[budget_name] = budget
        candidates[candidate_id] = {"budgets": budgets}
    return {
        "schema_version": "experiment_report.v1",
        "plan_hash": plan.plan_hash,
        "candidates": candidates,
    }
