"""Fresh-file binding for the offline SoC defect-confirmation workflow.

This first slice only establishes that an offline confirmation is looking at
the intended pair of builds.  Execution, replay, structure audit and the
isolated fixture are added by subsequent slices; a successfully bound pair is
therefore still a component candidate here.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .soc_composition import CompositionPlan
from .soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    UNDIAGNOSED,
    EvidencePackage,
    classify_boundary,
    identity_mismatches,
    recorded_build_identity,
)
from .soc_runtime import RuntimeBuild


@dataclass(frozen=True, slots=True)
class IsolationFixture:
    testbench: Path
    top_module: str
    marker: str
    source_name: str


@dataclass(frozen=True, slots=True)
class OfflineConfirmation:
    status: str
    reason: str
    evidence: Mapping[str, object]


def file_hash(path: Path) -> str:
    """Return the SHA-256 identity of the bytes currently stored at *path*."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _source_bytes(build: RuntimeBuild, base_dir: Path) -> tuple[dict[str, str], tuple[str, ...]]:
    """Rehash a source closure and identify build records that have drifted."""
    current: dict[str, str] = {}
    drift: list[str] = []
    recorded = dict(build.source_hashes)
    for source in build.sources:
        name = str(source)
        path = Path(name)
        resolved = path if path.is_absolute() else base_dir / path
        if not resolved.is_file():
            raise ValueError(f"source-missing:{name}")
        actual = file_hash(resolved)
        current[name] = actual
        if recorded.get(name) != actual:
            drift.append(name)
    return current, tuple(drift)


def build_differential(baseline: RuntimeBuild, mutant: RuntimeBuild, *,
                       base_dir: Path | None = None) -> Mapping[str, object]:
    """Compare build artifacts from their current bytes, never caller claims."""
    root = Path.cwd() if base_dir is None else Path(base_dir)
    baseline_sources, baseline_drift = _source_bytes(baseline, root)
    mutant_sources, mutant_drift = _source_bytes(mutant, root)
    baseline_hashes = Counter(baseline_sources.values())
    mutant_hashes = Counter(mutant_sources.values())
    return {
        "top_equal": file_hash(baseline.top_path) == file_hash(mutant.top_path),
        "testbench_equal": (file_hash(baseline.testbench_path) ==
                            file_hash(mutant.testbench_path)),
        "boot_equal": _boot_hash(baseline) == _boot_hash(mutant),
        "removed_source_hashes": tuple(sorted((baseline_hashes - mutant_hashes).elements())),
        "added_source_hashes": tuple(sorted((mutant_hashes - baseline_hashes).elements())),
        "baseline_source_hashes": baseline_sources,
        "mutant_source_hashes": mutant_sources,
        "baseline_source_drift": baseline_drift,
        "mutant_source_drift": mutant_drift,
    }


def _boot_hash(build: RuntimeBuild) -> str:
    return "none" if build.boot_image is None else file_hash(Path(build.boot_image))


def _same_build_abi(baseline: RuntimeBuild, mutant: RuntimeBuild) -> str | None:
    if baseline.raw_width != mutant.raw_width:
        return "raw-width"
    if baseline.slots != mutant.slots:
        return "slots"
    try:
        baseline_record = recorded_build_identity(baseline)
        mutant_record = recorded_build_identity(mutant)
    except Exception as error:  # the evidence module gives a stable diagnostic
        return f"build-record:{error}"
    if baseline_record["layout_hash"] != mutant_record["layout_hash"]:
        return "layout"
    if baseline_record["plan_hash"] != mutant_record["plan_hash"]:
        return "build-record"
    return None


def _criterion_problem(package: EvidencePackage, criterion: Mapping[str, object]) -> str | None:
    if not isinstance(criterion, Mapping) or not criterion.get("independent_of_profile"):
        return "independent-criterion-missing"
    text = criterion.get("specification_text")
    stated_hash = criterion.get("specification_hash")
    if not isinstance(text, str) or not text or not isinstance(stated_hash, str) or \
            stated_hash != "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest():
        return "independent-criterion-hash"
    anomaly = package.anomaly if isinstance(package.anomaly, Mapping) else {}
    if str(criterion.get("criterion_id", "")) != str(anomaly.get("criterion", "")):
        return "independent-criterion-id"
    if criterion.get("expected") != anomaly.get("expected") or \
            criterion.get("observed") != anomaly.get("observed"):
        return "independent-criterion-observation"
    return None


def confirm_component_offline(
        package: EvidencePackage, *, plan: CompositionPlan, baseline: RuntimeBuild,
        mutant: RuntimeBuild, fixture: IsolationFixture, criterion: Mapping[str, object],
        base_dir: Path, include_roots: Sequence[str] = (), timeout_seconds: int = 600,
) -> OfflineConfirmation:
    """Bind an offline confirmation request to actual build files.

    ``plan``, ``fixture``, include roots and timeout deliberately remain part of
    the stable entry-point now; later phases consume them to re-run the builds.
    """
    del plan, fixture, include_roots, timeout_seconds
    boundary, reason = classify_boundary(package)
    if boundary != COMPONENT_CANDIDATE:
        return OfflineConfirmation(boundary, reason, {})

    mismatches = identity_mismatches(package, mutant)
    if mismatches:
        return OfflineConfirmation(UNDIAGNOSED, "mutant-identity:" + mismatches[0], {})
    abi_problem = _same_build_abi(baseline, mutant)
    if abi_problem is not None:
        return OfflineConfirmation(UNDIAGNOSED, "build-identity:" + abi_problem, {})
    try:
        differential = build_differential(baseline, mutant, base_dir=base_dir)
    except (OSError, ValueError) as error:
        return OfflineConfirmation(UNDIAGNOSED, "build-files:" + str(error), {})
    for side in ("baseline", "mutant"):
        drift = differential[f"{side}_source_drift"]
        if drift:
            return OfflineConfirmation(UNDIAGNOSED, f"{side}-source-drift:{drift[0]}",
                                       differential)
    if not differential["top_equal"]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "generated-top-changed", differential)
    if not differential["testbench_equal"]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "testbench-changed", differential)
    if not differential["boot_equal"]:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "boot-image-changed", differential)
    removed = differential["removed_source_hashes"]
    added = differential["added_source_hashes"]
    if len(removed) != 1 or len(added) != 1:
        return OfflineConfirmation(COMPONENT_CANDIDATE, "source-differential-not-single", differential)
    criterion_problem = _criterion_problem(package, criterion)
    if criterion_problem is not None:
        return OfflineConfirmation(COMPONENT_CANDIDATE, criterion_problem, differential)
    return OfflineConfirmation(COMPONENT_CANDIDATE, "build-binding-complete", differential)


__all__ = ["IsolationFixture", "OfflineConfirmation", "build_differential",
           "confirm_component_offline", "file_hash"]
