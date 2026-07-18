"""Build the variant-independent primary coverage catalog."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from typing import Iterable, Mapping

from .contracts import CoverageABI, CoverageABIV2, canonical_json
from .input_model import InputValidationError


_PRIMARY_KINDS = {"if", "case", "loop", "control"}
_SEQUENTIAL_PROCESSES = {"always_ff", "edge_always"}


def infer_hierarchy_component_ids(
    points: Iterable[Mapping[str, object]],
    component_roots: Mapping[str, Iterable[str]],
) -> dict[str, str]:
    """Map elaborated point hierarchies to preregistered component roots."""
    roots = tuple(
        (str(root), str(component_id))
        for component_id, values in component_roots.items()
        for root in values
    )
    if not roots or any(not root or not component_id for root, component_id in roots):
        raise InputValidationError("coverage component roots must be non-empty")
    result: dict[str, str] = {}
    for point in points:
        hierarchy = str(point.get("hierarchy", ""))
        if not hierarchy:
            continue
        matches = [(root, component_id) for root, component_id in roots
                   if hierarchy == root or hierarchy.startswith(root + ".")]
        if not matches:
            continue
        longest = max(len(root) for root, _component_id in matches)
        owners = {component_id for root, component_id in matches if len(root) == longest}
        if len(owners) != 1:
            raise InputValidationError(f"ambiguous coverage component ownership for {hierarchy!r}")
        result[hierarchy] = owners.pop()
    return result


def infer_hierarchy_component_paths(
    points: Iterable[Mapping[str, object]],
    component_roots: Mapping[str, Iterable[str]],
) -> dict[str, str]:
    """Return the stable hierarchy suffix below each preregistered component root."""
    roots = tuple(
        (str(root), str(component_id))
        for component_id, values in component_roots.items()
        for root in values
    )
    result: dict[str, str] = {}
    for point in points:
        hierarchy = str(point.get("hierarchy", ""))
        matches = [(root, component_id) for root, component_id in roots
                   if hierarchy == root or hierarchy.startswith(root + ".")]
        if not matches:
            continue
        longest = max(len(root) for root, _component_id in matches)
        selected = {(root, component_id) for root, component_id in matches if len(root) == longest}
        if len(selected) != 1:
            raise InputValidationError(f"ambiguous coverage component path for {hierarchy!r}")
        root, _component_id = selected.pop()
        result[hierarchy] = hierarchy[len(root):].removeprefix(".")
    return result


def build_common_coverage_abi_v2(
    source: CoverageABI,
    hierarchy_component_ids: Mapping[str, str],
    *,
    hierarchy_component_paths: Mapping[str, str] | None = None,
    epoch_width: int = 16,
    port_name: str | None = None,
) -> CoverageABIV2:
    """Select sequential control-flow points and replace hierarchy with stable component IDs."""
    included = []
    excluded = []
    for raw in source.points:
        hierarchy = str(raw.get("hierarchy", ""))
        component_id = hierarchy_component_ids.get(hierarchy)
        component_path = ((hierarchy_component_paths or {}).get(hierarchy, "")
                          if component_id is not None else None)
        kind = str(raw.get("kind", ""))
        process_kind = str(raw.get("process_kind", "unknown_process"))
        reason = None
        if not raw.get("included"):
            reason = str(raw.get("skip_reason") or "source_abi_excluded")
        elif component_id is None:
            reason = "non_primary_component"
        elif process_kind not in _SEQUENTIAL_PROCESSES:
            reason = process_kind if process_kind in {
                "always_comb", "always_latch", "initial", "final", "expression",
            } else "unknown_process"
        elif kind not in _PRIMARY_KINDS:
            reason = "non_control_flow_point"
        entry = {
            "component_id": component_id,
            "component_path": component_path,
            "node_id": str(raw.get("node_id", "")),
            "module": str(raw.get("module", "")),
            "kind": kind,
            "subtype": str(raw.get("subtype", "")),
            "process_kind": process_kind,
            "source_id": str(raw.get("source_id", "")),
            "source_line": int(raw.get("source_line", 0)),
            "included": reason is None,
            "offset": None,
            "source_offset": int(raw.get("offset", -1)) if raw.get("included") else None,
            "exclusion_reason": reason,
        }
        if reason is None:
            identity = {key: entry[key] for key in (
                "component_id", "component_path", "node_id", "kind", "subtype",
            )}
            entry["point_id"] = hashlib.sha256(canonical_json(identity)).hexdigest()
            included.append(entry)
        else:
            entry["point_id"] = hashlib.sha256(canonical_json({
                "source_point_id": raw.get("point_id", ""), "reason": reason,
            })).hexdigest()
            excluded.append(entry)
    included.sort(key=lambda item: (str(item["component_id"]), str(item["component_path"]),
                                    str(item["node_id"]), str(item["kind"]),
                                    str(item["subtype"])))
    if len({item["point_id"] for item in included}) != len(included):
        raise InputValidationError("CoverageABI v2 primary point IDs are not unique")
    for offset, entry in enumerate(included): entry["offset"] = offset
    excluded.sort(key=lambda item: (str(item["exclusion_reason"]), str(item["point_id"])))
    catalog = tuple(included + excluded)
    primary_catalog = tuple(
        {key: value for key, value in point.items() if key != "source_offset"}
        for point in included
    )
    digest_payload = {
        "schema": "myfuzz.coverage-abi/v2", "port_name": port_name or source.port_name,
        "width": len(included), "epoch_width": epoch_width,
        "writer": "instrumented_sequential_processes",
        "sampling": "after_rising_edge_nba_settle", "points": primary_catalog,
    }
    if not included:
        raise InputValidationError("CoverageABI v2 primary catalog is empty")
    return CoverageABIV2(hashlib.sha256(canonical_json(digest_payload)).hexdigest(),
                         port_name or source.port_name, len(included), epoch_width, catalog,
                         transport_width=source.width)


def coverage_abi_v2_digest_payload(abi: CoverageABIV2) -> Mapping[str, object]:
    value = asdict(abi)
    value.pop("catalog_digest")
    return value
