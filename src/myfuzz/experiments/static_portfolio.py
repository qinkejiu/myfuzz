"""Target-independent static-policy portfolio screening and promotion."""

from __future__ import annotations

import math
import os
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, median

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.harness.abi import RawBitAbi
from myfuzz.harness.static_policy import (
    StaticPolicyParameters,
    StaticPolicyPlan,
    compile_static_policy,
)


SCREEN_COVERAGE_RATIO = 0.95
SCREEN_THROUGHPUT_RATIO = 0.85
PROMOTION_IMPROVEMENT = 0.10
PROMOTION_MAX_REGRESSION = -0.02
PROMOTION_THROUGHPUT_RATIO = 0.90

PORTFOLIO = tuple(
    StaticPolicyParameters(direct, rarity, strength, exclusion)
    for direct in (1, 2, 4)
    for rarity in (2, 4, 8)
    for strength in (1, 2)
    for exclusion in ("none", "one_hot", "priority")
)


@dataclass(frozen=True, slots=True)
class ScreenDecision:
    policy_id: str
    target_id: str
    accepted: bool
    reason: str | None
    coverage_ratio: float | None = None
    throughput_ratio: float | None = None


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    policy_id: str
    plan_hash: str
    parameters: StaticPolicyParameters
    min_target_improvement: float
    mean_improvement: float
    median_throughput: float
    training_evidence_hash: str
    evidence: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class _PairMetrics:
    policy_id: str
    plan_hash: str
    parameters: StaticPolicyParameters
    target_id: str
    coverage_improvement: float
    throughput_ratio: float
    evidence: dict[str, object]
    abnormal_exit: bool


def compile_portfolio(
    raw_abi: RawBitAbi,
    declarations: Mapping[str, object],
) -> tuple[StaticPolicyPlan, ...]:
    """Compile the fixed global portfolio and deduplicate by canonical plan hash."""
    plans = {
        plan.plan_hash: plan
        for parameters in PORTFOLIO
        for plan in (compile_static_policy(raw_abi, declarations, parameters),)
    }
    return tuple(plans[plan_hash] for plan_hash in sorted(plans))


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _number(value: object, label: str, *, positive: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < 0 or positive and result == 0:
        raise ValueError(f"{label} must be a finite {'positive' if positive else 'non-negative'} number")
    return result


def _metric(summary: Mapping[str, object], name: str) -> float:
    top_level = name in summary
    runtime = summary.get("runtime")
    runtime_metric = isinstance(runtime, Mapping) and name in runtime
    if top_level and runtime_metric:
        raise ValueError(f"{name} must use exactly one representation")
    if top_level:
        return _number(summary[name], name, positive=False)
    if runtime_metric:
        return _number(runtime[name], f"runtime.{name}", positive=False)
    raise ValueError(f"missing {name}")


def _normal_exit(summary: Mapping[str, object]) -> bool:
    if "runtime" not in summary:
        runtime: Mapping[str, object] | None = None
    elif isinstance(summary["runtime"], Mapping):
        runtime_value = summary["runtime"]
        runtime = runtime_value
    else:
        raise ValueError("runtime must be an object")
    status_fields = ("return_code", "failure_reasons")
    top_level_status = any(field in summary for field in status_fields)
    runtime_status = runtime is not None and any(field in runtime for field in status_fields)
    if not top_level_status and not runtime_status:
        raise ValueError("normal exit evidence is required")
    if top_level_status and runtime_status:
        raise ValueError("status must use exactly one representation")
    status = runtime if runtime_status else summary
    return_code = status.get("return_code", 0)
    if isinstance(return_code, bool) or not isinstance(return_code, int):
        raise ValueError("return_code must be an integer")
    failures = status.get("failure_reasons", {})
    if not isinstance(failures, Mapping):
        raise ValueError("failure_reasons must be an object")
    for reason, count in failures.items():
        _string(reason, "failure_reasons key")
        if _number(count, f"failure_reasons.{reason}", positive=False) > 0 and reason in {
            "dut_crash",
            "resource_terminated",
        }:
            return False
    return return_code == 0


def _parameters(value: object) -> StaticPolicyParameters:
    document = _object(value, "parameters")
    expected = {
        "direct_ratio",
        "event_rarity",
        "legal_set_strength",
        "mutual_exclusion",
    }
    if set(document) != expected:
        raise ValueError("parameters must contain exactly the global policy fields")
    try:
        return StaticPolicyParameters(
            document["direct_ratio"],
            document["event_rarity"],
            document["legal_set_strength"],
            document["mutual_exclusion"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError("parameters contain invalid values") from error


def _pair_metrics(value: object) -> _PairMetrics:
    document = _object(value, "pair")
    policy_id = _string(document.get("policy_id"), "policy_id")
    plan_hash = _string(document.get("plan_hash"), "plan_hash")
    target_id = _string(document.get("target_id"), "target_id")
    parameters = _parameters(document.get("parameters"))
    baseline = _object(document.get("baseline"), "baseline")
    candidate = _object(document.get("candidate"), "candidate")
    baseline_coverage = _metric(baseline, "covered")
    baseline_throughput = _metric(baseline, "tests_per_second")
    candidate_coverage = _metric(candidate, "covered")
    candidate_throughput = _metric(candidate, "tests_per_second")
    if baseline_coverage == 0 or baseline_throughput == 0:
        raise ValueError("baseline metrics must be non-zero")
    coverage_improvement = (candidate_coverage - baseline_coverage) / baseline_coverage
    throughput_ratio = candidate_throughput / baseline_throughput
    if not math.isfinite(coverage_improvement) or not math.isfinite(throughput_ratio):
        raise ValueError("paired ratios must be finite")
    abnormal_exit = not _normal_exit(baseline) or not _normal_exit(candidate)
    evidence = {
        "policy_id": policy_id,
        "plan_hash": plan_hash,
        "parameters": asdict(parameters),
        "target_id": target_id,
        "baseline": {
            "covered": baseline_coverage,
            "tests_per_second": baseline_throughput,
            "return_code": baseline.get("return_code", 0),
        },
        "candidate": {
            "covered": candidate_coverage,
            "tests_per_second": candidate_throughput,
            "return_code": candidate.get("return_code", 0),
        },
    }
    return _PairMetrics(
        policy_id,
        plan_hash,
        parameters,
        target_id,
        coverage_improvement,
        throughput_ratio,
        evidence,
        abnormal_exit,
    )


def screen(pair: object) -> ScreenDecision:
    """Apply the 60-second paired screening threshold, failing closed."""
    try:
        metrics = _pair_metrics(pair)
    except (OverflowError, ValueError):
        return ScreenDecision("", "", False, "invalid")
    coverage_ratio = 1.0 + metrics.coverage_improvement
    if metrics.abnormal_exit:
        return ScreenDecision(metrics.policy_id, metrics.target_id, False, "abnormal_exit")
    if coverage_ratio < SCREEN_COVERAGE_RATIO:
        return ScreenDecision(
            metrics.policy_id, metrics.target_id, False, "coverage_loss", coverage_ratio, metrics.throughput_ratio
        )
    if metrics.throughput_ratio < SCREEN_THROUGHPUT_RATIO:
        return ScreenDecision(
            metrics.policy_id, metrics.target_id, False, "throughput", coverage_ratio, metrics.throughput_ratio
        )
    return ScreenDecision(metrics.policy_id, metrics.target_id, True, None, coverage_ratio, metrics.throughput_ratio)


def _pairs(results: object) -> tuple[object, ...]:
    if isinstance(results, Mapping):
        if "baseline" in results or "candidate" in results:
            return (results,)
        flattened: list[object] = []
        for policy_id, values in results.items():
            if not isinstance(policy_id, str) or not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
                raise ValueError("promotion results must be paired summaries")
            for value in values:
                document = dict(_object(value, "pair"))
                document.setdefault("policy_id", policy_id)
                flattened.append(document)
        return tuple(flattened)
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes, bytearray)):
        raise ValueError("promotion results must be paired summaries")
    return tuple(results)


def promote(results: object) -> tuple[PromotionDecision, ...]:
    """Promote only policies that meet every paired two-target threshold."""
    try:
        values = _pairs(results)
    except (OverflowError, ValueError):
        return ()
    grouped: defaultdict[str, list[object]] = defaultdict(list)
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(value.get("policy_id"), str):
            return ()
        grouped[value["policy_id"]].append(value)

    promoted: list[PromotionDecision] = []
    for policy_id in sorted(grouped):
        try:
            pairs = tuple(_pair_metrics(value) for value in grouped[policy_id])
        except (OverflowError, ValueError):
            continue
        if not pairs or any(pair.abnormal_exit for pair in pairs):
            continue
        plan_hashes = {pair.plan_hash for pair in pairs}
        parameter_sets = {pair.parameters for pair in pairs}
        if len(plan_hashes) != 1 or len(parameter_sets) != 1:
            continue
        targets: defaultdict[str, list[_PairMetrics]] = defaultdict(list)
        for pair in pairs:
            targets[pair.target_id].append(pair)
        if len(targets) != 2:
            continue
        target_improvements = [
            median(pair.coverage_improvement for pair in targets[target_id])
            for target_id in sorted(targets)
        ]
        if any(value < PROMOTION_IMPROVEMENT for value in target_improvements):
            continue
        if any(pair.coverage_improvement < PROMOTION_MAX_REGRESSION for pair in pairs):
            continue
        throughput = median(pair.throughput_ratio for pair in pairs)
        if throughput < PROMOTION_THROUGHPUT_RATIO:
            continue
        evidence = tuple(sorted((pair.evidence for pair in pairs), key=canonical_bytes))
        promoted.append(
            PromotionDecision(
                policy_id,
                next(iter(plan_hashes)),
                next(iter(parameter_sets)),
                min(target_improvements),
                mean(target_improvements),
                throughput,
                content_hash({"pairs": evidence}),
                evidence,
            )
        )
    return tuple(
        sorted(
            promoted,
            key=lambda decision: (
                -decision.min_target_improvement,
                -decision.mean_improvement,
                -decision.median_throughput,
                decision.policy_id,
            ),
        )
    )


def freeze_policy(decision: PromotionDecision, destination: Path) -> dict[str, object]:
    """Atomically publish one immutable, canonical frozen-policy record."""
    if not isinstance(decision, PromotionDecision):
        raise TypeError("decision must be a PromotionDecision")
    if not isinstance(destination, Path):
        raise TypeError("destination must be a pathlib.Path")
    document = {
        "schema_version": "static-policy-freeze.v1",
        "policy_id": decision.policy_id,
        "plan_hash": decision.plan_hash,
        "parameters": asdict(decision.parameters),
        "training_evidence_hash": decision.training_evidence_hash,
    }
    payload = canonical_bytes(document)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return document


__all__ = [
    "PORTFOLIO",
    "PROMOTION_IMPROVEMENT",
    "PROMOTION_MAX_REGRESSION",
    "PROMOTION_THROUGHPUT_RATIO",
    "SCREEN_COVERAGE_RATIO",
    "SCREEN_THROUGHPUT_RATIO",
    "PromotionDecision",
    "ScreenDecision",
    "compile_portfolio",
    "freeze_policy",
    "promote",
    "screen",
]
