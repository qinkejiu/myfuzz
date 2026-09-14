"""Instance-mapped RTL coverage for generated SoCs.

This module keeps branch coverage separate from sampled RFuzz input/output
observations.  A point is counted only when an instrumented RTL backend reports
that point as executed; changing raw input bits alone never creates a branch
hit.  Instance identity is part of every point so two instances of the same
module cannot alias feedback.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from myfuzz.contracts import content_hash


COVERAGE_SCHEMA = "soc_coverage.v1"
CATEGORIES = ("cpu", "ip", "fabric", "model", "harness", "interaction")


class SocCoverageError(ValueError):
    """Malformed or semantically unsafe coverage evidence."""


@dataclass(frozen=True, slots=True)
class CoveragePoint:
    point_id: str
    instance_id: str
    module: str
    category: str
    kind: str
    source: str
    line: int
    column: int = 1
    branch: str = ""

    def __post_init__(self) -> None:
        for name in ("point_id", "instance_id", "module", "source", "kind"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise SocCoverageError(f"point:{name}")
        if self.category not in CATEGORIES:
            raise SocCoverageError("point:category")
        if self.kind not in {"branch", "statement", "toggle", "interaction"}:
            raise SocCoverageError("point:kind")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise SocCoverageError("point:line")
        if isinstance(self.column, bool) or not isinstance(self.column, int) or self.column < 1:
            raise SocCoverageError("point:column")
        if self.kind == "branch" and self.category == "interaction":
            raise SocCoverageError("point:interaction-branch")

    def as_mapping(self) -> dict[str, object]:
        return {
            "point_id": self.point_id, "instance_id": self.instance_id,
            "module": self.module, "category": self.category, "kind": self.kind,
            "source": self.source, "line": self.line, "column": self.column,
            "branch": self.branch,
        }


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SocCoverageError(label)
    return value


def _point(value: CoveragePoint | Mapping[str, object], *, instance_id: str | None = None,
           module: str | None = None, category: str | None = None) -> CoveragePoint:
    if isinstance(value, CoveragePoint):
        point = value
    elif isinstance(value, Mapping):
        raw_kind = value.get("kind", value.get("type", "branch"))
        # Input-bit/event counters are not branch evidence.  Require callers
        # to label them explicitly so an accidental fallback cannot inflate a
        # branch universe.
        if isinstance(raw_kind, str) and raw_kind in {"input", "sampled_input", "sampled-output-bit-events"}:
            raise SocCoverageError("sampled-input-is-not-rtl-coverage")
        point = CoveragePoint(
            point_id=_text(value.get("point_id", value.get("id")), "point:id"),
            instance_id=_text(value.get("instance_id", instance_id), "point:instance_id"),
            module=_text(value.get("module", module), "point:module"),
            category=_text(value.get("category", category), "point:category"),
            kind=_text(raw_kind, "point:kind"),
            source=_text(value.get("source", value.get("file")), "point:source"),
            line=value.get("line", 1), column=value.get("column", 1),
            branch=str(value.get("branch", value.get("arm", ""))),
        )
    else:
        raise SocCoverageError("point:mapping")
    if instance_id is not None and point.instance_id != instance_id:
        point = CoveragePoint(point.point_id, instance_id, point.module, point.category,
                              point.kind, point.source, point.line, point.column, point.branch)
    if module is not None and point.module != module:
        point = CoveragePoint(point.point_id, point.instance_id, module, point.category,
                              point.kind, point.source, point.line, point.column, point.branch)
    if category is not None and point.category != category:
        point = CoveragePoint(point.point_id, point.instance_id, point.module, category,
                              point.kind, point.source, point.line, point.column, point.branch)
    return point


def _manifest_points(source: Mapping[str, object]) -> list[CoveragePoint]:
    # A backend may publish a flat ``points``/``coverage_points`` array (the
    # renderer does not require a module hierarchy).  Preserve those exact
    # instance mappings rather than interpreting each point as a module.
    flat = source.get("points")
    if flat is None:
        flat = source.get("coverage_points")
    if isinstance(flat, Sequence) and not isinstance(flat, (str, bytes)) and any(
            isinstance(item, Mapping) and ("point_id" in item or "id" in item)
            for item in flat):
        return [_point(item) for item in flat if isinstance(item, Mapping)]
    points: list[CoveragePoint] = []
    for module in source.get("modules", source.get("coverage_points", source.get("points", []))):
        if not isinstance(module, Mapping):
            continue
        instance = str(module.get("instance_id", module.get("instance", module.get("name", ""))))
        module_name = str(module.get("module", module.get("name", "")))
        category = str(module.get("category", "ip"))
        branches = module.get("branches", module.get("points", []))
        if not isinstance(branches, Sequence) or isinstance(branches, (str, bytes)):
            continue
        for index, branch in enumerate(branches):
            if isinstance(branch, Mapping):
                value = dict(branch)
                value.setdefault("point_id", f"{instance}:branch:{index}")
                value.setdefault("instance_id", instance)
                value.setdefault("module", module_name)
                value.setdefault("category", category)
                value.setdefault("kind", "branch")
                value.setdefault("source", module.get("source", module.get("file", "unknown")))
                points.append(_point(value))
            else:
                points.append(CoveragePoint(
                    f"{instance}:branch:{index}", instance, module_name, category,
                    "branch", str(module.get("source", module.get("file", "unknown"))),
                    index + 1,
                ))
    return points


def build_coverage_universe(points: Iterable[CoveragePoint | Mapping[str, object]] | Mapping[str, object],
                            instances: Sequence[Mapping[str, object]] = ()) -> dict[str, object]:
    """Build a deterministic instance-mapped universe from RTL evidence."""
    values = _manifest_points(points) if isinstance(points, Mapping) else [
        _point(value) for value in points
    ]
    # Add no synthetic branch points for an instance.  The optional instance
    # list only supplies provenance and category checks for existing points.
    instance_index = {
        str(item.get("instance_id")): item for item in instances if isinstance(item, Mapping)
    }
    for point in values:
        if point.instance_id in instance_index:
            record = instance_index[point.instance_id]
            if record.get("top_module") and str(record["top_module"]) != point.module:
                raise SocCoverageError(f"instance-module-mismatch:{point.instance_id}")
    unique: dict[str, CoveragePoint] = {}
    for point in values:
        if point.point_id in unique and unique[point.point_id] != point:
            raise SocCoverageError(f"duplicate-point-id:{point.point_id}")
        unique[point.point_id] = point
    ordered = [unique[key] for key in sorted(unique)]
    branch_points = [point for point in ordered if point.kind == "branch"]
    return {
        "schema_version": COVERAGE_SCHEMA,
        "backend": "source-instrumented-rtl",
        "branch_feedback_is_rtl_only": True,
        "points": [point.as_mapping() for point in ordered],
        "branch_points": [point.point_id for point in branch_points],
        "categories": {category: [point.point_id for point in ordered if point.category == category]
                        for category in CATEGORIES},
        "universe_hash": content_hash({"points": [point.as_mapping() for point in ordered]}),
    }


def observe_rtl_coverage(universe: Mapping[str, object], observed: Iterable[str]) -> dict[str, object]:
    """Normalize backend branch ids; reject input samples masquerading as hits."""
    points = universe.get("points")
    if not isinstance(points, list):
        raise SocCoverageError("universe:points")
    known = {str(item.get("point_id")) for item in points if isinstance(item, Mapping)}
    values = list(observed)
    if any(not isinstance(value, str) for value in values):
        raise SocCoverageError("observed:point-id")
    unknown = sorted(set(values) - known)
    if unknown:
        raise SocCoverageError(f"observed:unknown:{unknown[0]}")
    hits = sorted(set(values))
    return {
        "backend": "source-instrumented-rtl",
        "coverage_kind": "rtl-branch-hit",
        "hits": hits,
        "hit_count": len(hits),
        "universe_hash": universe.get("universe_hash"),
    }


def coverage_delta(universe: Mapping[str, object], before: Iterable[str], after: Iterable[str]) -> dict[str, object]:
    """Return only newly observed RTL points, independent of raw input bits."""
    first = set(observe_rtl_coverage(universe, before)["hits"])
    second = set(observe_rtl_coverage(universe, after)["hits"])
    return {"new_hits": sorted(second - first), "before": sorted(first), "after": sorted(second),
            "changed": bool(second - first)}


def coverage_feedback_document(universe: Mapping[str, object], observed: Iterable[str], *,
                               include_interactions: bool = False) -> dict[str, object]:
    evidence = observe_rtl_coverage(universe, observed)
    interaction_ids = set(universe.get("categories", {}).get("interaction", []))
    if not include_interactions:
        evidence["feedback_hits"] = [value for value in evidence["hits"] if value not in interaction_ids]
        evidence["interaction_hits"] = [value for value in evidence["hits"] if value in interaction_ids]
    else:
        evidence["feedback_hits"] = evidence["hits"]
        evidence["interaction_hits"] = []
    evidence["include_interactions"] = include_interactions
    return evidence


# Explicit aliases make the boundary easy to discover from campaign code.
build_soc_coverage_universe = build_coverage_universe
map_rtl_coverage = observe_rtl_coverage


#: Modules the SoC renderer generates itself: bus adapters and the arbiter and
#: router between the CPU and the targets.  Their points are fabric, not IP.
FABRIC_MODULES = frozenset({
    "soc_arbiter", "soc_router", "mmio_width_adapter", "beat_address_narrow",
    "beat_to_apb", "beat_to_tlul", "beat_to_wishbone", "soc_irq_router",
})
#: The generated RAM/ROM models.
MODEL_MODULES = frozenset({"riscv_boot_memory_32", "riscv_boot_memory_64"})
#: The generated harness itself: top level, synthetic initiator, pin peers.
HARNESS_MODULES = frozenset({
    "myfuzz_soc_top", "fuzz_mmio_master", "fuzz_uart_peer", "fuzz_spi_peer",
})

#: Normal boot should raise CPU and real-IP coverage first, so those points are
#: the ones worth spending a bounded observation budget on.
CATEGORY_PRIORITY = ("cpu", "ip", "fabric", "model", "harness")


def instance_root(instance_path: str) -> str:
    """Return the top-level instance name under the rendered SoC top."""
    segments = [segment for segment in str(instance_path).split("/") if segment]
    if len(segments) >= 2:
        return segments[1]
    return segments[0] if segments else ""


def coverage_category(instance_path: str, module: str, *, cpu_instance: str = "u_cpu",
                      ip_instances: Sequence[str] = ()) -> str:
    """Classify one instrumented point by the subtree it lives in.

    The rendered top instantiates the CPU wrapper, each real peripheral wrapper,
    each memory model and the fabric as separate top-level instances, so the
    second path segment is the authoritative discriminator.  Classifying by
    module name alone would call a peripheral's own submodules fabric.
    """
    root = instance_root(instance_path)
    if root and root == cpu_instance:
        return "cpu"
    if root and root in set(ip_instances):
        return "ip"
    if root.startswith("u_mem"):
        return "model"
    if module in FABRIC_MODULES:
        return "fabric"
    if module in MODEL_MODULES:
        return "model"
    if module in HARNESS_MODULES:
        return "harness"
    return "harness"


def universe_from_instance_bits(bits: Iterable[Mapping[str, object]], *,
                                cpu_instance: str = "u_cpu",
                                ip_instances: Sequence[str] = ()) -> dict[str, object]:
    """Build a branch universe from the instrumenter's instance-mapped bits.

    Every point keeps its own instance path, so two instances of one module stay
    distinguishable in feedback.  Only bits that describe real RTL branches are
    accepted; the sampled input/output counters the campaign used before are not
    branch evidence and are deliberately not representable here.
    """
    points: list[dict[str, object]] = []
    for entry in bits:
        instance = _text(entry.get("instance_path"), "bit:instance_path")
        module = _text(entry.get("module"), "bit:module")
        signal = _text(entry.get("signal"), "bit:signal")
        raw_kind = str(entry.get("kind", "if"))
        if raw_kind not in {"if", "case", "branch"}:
            raise SocCoverageError(f"bit:kind:{raw_kind}")
        points.append({
            "point_id": f"{instance}:{signal}",
            "instance_id": instance,
            "module": module,
            "category": coverage_category(instance, module, cpu_instance=cpu_instance,
                                          ip_instances=ip_instances),
            "kind": "branch",
            "source": _text(entry.get("file"), "bit:file"),
            "line": entry.get("line", 1),
            "column": entry.get("column", 1) or 1,
            "branch": str(entry.get("subtype", "")),
        })
    return build_coverage_universe(points)


def coverage_observation_plan(universe: Mapping[str, object],
                              bits: Iterable[Mapping[str, object]], limit: int) -> dict[str, object]:
    """Choose which RTL bits the harness observes within a bounded counter budget.

    A generated harness exposes a fixed number of counters, while an
    instrumented cell can carry thousands of points.  The selection is
    deterministic and prioritises CPU and real-IP points, and it reports how
    many points were left unobserved instead of implying full coverage.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise SocCoverageError("observation-limit")
    by_point = {str(item["point_id"]): item for item in universe.get("points", [])
                if isinstance(item, Mapping)}
    if not by_point:
        raise SocCoverageError("universe:points")
    candidates: list[tuple[int, int, str]] = []
    for entry in bits:
        instance = str(entry.get("instance_path", ""))
        point_id = f"{instance}:{entry.get('signal')}"
        point = by_point.get(point_id)
        if point is None:
            raise SocCoverageError(f"observation-bit:unknown:{point_id}")
        category = str(point.get("category"))
        rank = CATEGORY_PRIORITY.index(category) if category in CATEGORY_PRIORITY else len(CATEGORY_PRIORITY)
        bit = entry.get("bit")
        if isinstance(bit, bool) or not isinstance(bit, int):
            raise SocCoverageError("observation-bit:index")
        candidates.append((rank, bit, point_id))
    candidates.sort()
    selected = candidates[:limit]
    observed = [{"bit": bit, "point_id": point_id, "category": str(by_point[point_id]["category"]),
                 "instance_id": str(by_point[point_id]["instance_id"]),
                 "module": str(by_point[point_id]["module"])}
                for _rank, bit, point_id in selected]
    counts: dict[str, int] = {}
    for _rank, _bit, point_id in selected:
        category = str(by_point[point_id]["category"])
        counts[category] = counts.get(category, 0) + 1
    return {
        "observed": observed,
        "observed_count": len(observed),
        "unobserved_count": len(candidates) - len(observed),
        "observed_by_category": dict(sorted(counts.items())),
        "category_priority": list(CATEGORY_PRIORITY),
        "limit": limit,
    }


__all__ = [
    "CATEGORIES", "CATEGORY_PRIORITY", "COVERAGE_SCHEMA", "CoveragePoint",
    "FABRIC_MODULES", "HARNESS_MODULES", "MODEL_MODULES", "SocCoverageError",
    "build_coverage_universe", "build_soc_coverage_universe", "coverage_category",
    "coverage_delta", "coverage_feedback_document", "coverage_observation_plan",
    "instance_root", "map_rtl_coverage", "observe_rtl_coverage",
    "universe_from_instance_bits",
]
