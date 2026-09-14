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


__all__ = [
    "CATEGORIES", "COVERAGE_SCHEMA", "CoveragePoint", "SocCoverageError",
    "build_coverage_universe", "build_soc_coverage_universe", "coverage_delta",
    "coverage_feedback_document", "map_rtl_coverage", "observe_rtl_coverage",
]
