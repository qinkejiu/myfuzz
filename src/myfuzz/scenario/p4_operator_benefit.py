"""Same-budget benefit comparison for the P4 legal operators (read-only).

The P4 legal operators (declarative path switch, pre-session initial RAM data,
closed-loop energy) are already proven to *take effect* per case by their own
gates.  What was missing is the other half of the P4 claim: whether, at the same
budget, an operator-enabled arm (ON) and an operator-disabled arm (OFF) reach
different coverage / complete-chain outcomes.

This module answers that question from *saved run directories only*.  It starts
no RTL, renders no harness and executes no fuzz client; every number is either
recomputed in one streaming pass over ``receipts.jsonl`` or taken from the
shipped read-only analyses:

* ``myfuzz.scenario.acceptance_metrics.analyze_run`` -- the same single-pass
  analysis ``paired_efficiency`` uses, which supplies
  ``effective_search_seconds``, the per-status counts, the chain-certificate
  accounting and ``local_target_novelty.new_target_bits_per_second`` (defined
  there, identically to ``paired_efficiency``'s group summary, as
  ``first_seen_target_bits / effective_search_seconds``);
* the default chain producer of that analyzer, i.e.
  ``myfuzz.scenario.chain_certificates``, for certified/incomplete chain
  certificate counts and the chains-per-second rate;
* ``myfuzz.scenario.edge_provenance.edge_provenance_session`` +
  ``edge_provenance_report`` for the ``runtime_edge_provenance_report.v1``
  witness counts, joined per direction through the run's *own* compiled
  declaration selections (``online_session_manifest.json``).

Honesty rules enforced here, not by convention:

* **Never a fabricated 0.**  A quantity the artifacts cannot support is
  ``null`` plus a precise ``reason``; it is never reported as ``0``.
* **Fail closed.**  An arm that lacks a core artifact (``receipts.jsonl`` or
  ``report.json``) cannot be compared at all and raises
  :class:`P4OperatorBenefitEvidenceError`; a metric family whose evidence is
  missing on either arm is listed in ``refusals`` and makes the comparison
  ``evidence_status = "refused"`` so the driving script can exit non-zero.
* **No implied per-case pairing.**  The two arms' searches diverge by
  construction, so the document states the *shared raw-input prefix* explicitly
  and computes per-case comparisons only inside it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
from itertools import zip_longest
from pathlib import Path

from myfuzz.scenario.acceptance_metrics import (
    DEFAULT_INGEST_BATCH_SIZE,
    DEFAULT_MAX_CERTIFICATES,
    TraceEventStream,
    TraceUnavailable,
    analyze_run,
)
from myfuzz.scenario.edge_provenance import (
    edge_provenance_report,
    edge_provenance_session,
)


SCHEMA_VERSION = "p4_operator_benefit.v1"

RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"
IDENTITY_NAME = "online_run_identity.json"
MANIFEST_NAME = "online_session_manifest.json"
TARGETS_NAME = "targets.json"
TRACE_ARTIFACT_RULE = (
    "online_final_trace.meta.json (jsonl.v1 / zlib_chunks.v1) or "
    "online_final_trace.json (json.v1)")

#: Artifacts every comparison needs.  Without them there is no case-level or
#: budget evidence at all, so the comparison refuses instead of degrading.
CORE_ARTIFACTS = (RECEIPTS_NAME, REPORT_NAME)

#: ``report.json`` blocks that state whether a P4 legal operator ran.  The list
#: is the recognized operator-state vocabulary; a new operator extends it here.
OPERATOR_STATE_KEYS = ("path_switch", "initial_ram_data", "closed_loop_energy")

METRIC_FAMILIES = ("search_budget", "coverage", "chains", "witnessed_edges")
DEFAULT_REQUIRED_FAMILIES = METRIC_FAMILIES

DEFAULT_MAX_PREFIX_ITEMS = 100_000
MAX_DETAIL_INDEXES = 20

#: Per-case fields compared inside the shared raw-input prefix only.
PAIRED_FIELDS = ("status", "coverage_hex", "effective_genome_sha256", "path_id",
                 "applied_sources", "direction", "operator_id")

RAW_FIELD_PREFERENCE = ("raw_sha256", "online_raw_records_hex")
SEED_FIELDS = ("search_seed", "global_mutation_seed")
BUDGET_FIELDS = ("max_tests", "duration_seconds", "feedback_interval")
SOURCE_IDENTITY_FIELDS = ("decoder_manifest_sha256", "component_identity_sha256",
                          "source_files_sha256")

_MISSING = object()


class P4OperatorBenefitEvidenceError(ValueError):
    """Raised when a pair cannot be compared at all (fail closed)."""


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _read_json_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise P4OperatorBenefitEvidenceError(
            f"invalid JSON in {path}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise P4OperatorBenefitEvidenceError(f"{path} is not a JSON object")
    return document


def _read_targets(path: Path) -> tuple[list | None, str | None]:
    """Read the optional ``targets.json`` list; a broken document degrades."""
    if not path.is_file():
        return None, f"{TARGETS_NAME} is absent from the run directory"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {TARGETS_NAME}: {exc.msg}"
    if not isinstance(document, list) or not document:
        return None, (f"{TARGETS_NAME} does not declare a non-empty target list")
    return document, None


def _iter_receipts(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                raise P4OperatorBenefitEvidenceError(
                    f"blank line {number} in {path}")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise P4OperatorBenefitEvidenceError(
                    f"invalid JSON on line {number} of {path}: {exc.msg}") from exc
            if type(row) is not dict:
                raise P4OperatorBenefitEvidenceError(
                    f"non-object JSON value on line {number} of {path}")
            yield row


def _finite_positive(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        number = float(value)
        if number > 0 and number == number and number not in (float("inf"),
                                                              float("-inf")):
            return number
    return None


def _finite_non_negative(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        number = float(value)
        if number >= 0 and number == number and number not in (float("inf"),
                                                               float("-inf")):
            return number
    return None


def _int_or_none(value: object) -> int | None:
    return value if type(value) is int else None


def _sorted_counter(values: Iterable[int]) -> list[int]:
    return sorted(values)


def _bounded_indexes(indexes: list[int]) -> tuple[list[int], bool]:
    return indexes[:MAX_DETAIL_INDEXES], len(indexes) > MAX_DETAIL_INDEXES


# ---------------------------------------------------------------------------
# receipt scan (one pass per arm)
# ---------------------------------------------------------------------------


def _raw_identity(row: Mapping) -> tuple[str | None, str | None]:
    """Primary/secondary raw-input identity of one case, when present."""
    primary = row.get("raw_sha256")
    primary = primary if isinstance(primary, str) and primary else None
    secondary = row.get("online_raw_records_hex")
    if isinstance(secondary, list):
        secondary_key = json.dumps(secondary, sort_keys=True, ensure_ascii=False)
    elif isinstance(secondary, str):
        secondary_key = secondary
    else:
        secondary_key = None
    return primary, secondary_key


def _scan_arm_receipts(path: Path, *, max_prefix_items: int) -> dict:
    """Stream one arm's receipts; keep counts, coverage counters and a bounded
    per-case prefix window (never the whole row set)."""
    scan = {
        "rows": 0,
        "status_counts": {},
        "raw_identities": [],
        "case_fields": [],
        "prefix_truncated": False,
        "coverage_widths": set(),
        "counter_hit_cases": [],
        "counter_observed_values": [],
        "coverage_missing_cases": 0,
        "invalid_coverage_cases": 0,
        "total_seconds": [],
    }
    for row in _iter_receipts(path):
        scan["rows"] += 1
        status = row.get("status")
        status = status if isinstance(status, str) and status else "unknown"
        scan["status_counts"][status] = scan["status_counts"].get(status, 0) + 1
        if len(scan["raw_identities"]) < max_prefix_items:
            scan["raw_identities"].append(_raw_identity(row))
            scan["case_fields"].append(
                {name: _jsonable(row.get(name)) for name in PAIRED_FIELDS})
        else:
            scan["prefix_truncated"] = True
        timing = row.get("online_phase_timing_seconds")
        if isinstance(timing, Mapping):
            total = _finite_non_negative(timing.get("total"))
            if total is not None:
                scan["total_seconds"].append(total)
        coverage = row.get("coverage_hex")
        if not isinstance(coverage, str) or not coverage:
            scan["coverage_missing_cases"] += 1
            continue
        try:
            flags = bytes.fromhex(coverage)
        except ValueError:
            scan["invalid_coverage_cases"] += 1
            continue
        if len(coverage) != 2 * len(flags):
            scan["invalid_coverage_cases"] += 1
            continue
        scan["coverage_widths"].add(len(coverage))
        while len(scan["counter_hit_cases"]) < len(flags):
            scan["counter_hit_cases"].append(0)
            scan["counter_observed_values"].append(set())
        for counter, flag in enumerate(flags):
            scan["counter_observed_values"][counter].add(flag)
            if flag:
                scan["counter_hit_cases"][counter] += 1
    return scan


def _jsonable(value: object) -> object:
    return None if value is _MISSING else value


# ---------------------------------------------------------------------------
# coverage layout
# ---------------------------------------------------------------------------


def _counter_order_rule() -> str:
    return (
        "one counter byte per declared coverage target, in targets.json "
        "declaration order: target i occupies hex characters [2i, 2i+2) of "
        "coverage_hex, and a non-zero byte means target i was observed in that "
        "case (the shipped online producer encodes each target as one boolean "
        "byte, and the shipped campaign consumer reads byte i for target i)")


def _coverage_layout(arm_scans: Mapping[str, Mapping],
                     targets_documents: Mapping[str, object],
                     targets_reasons: Mapping[str, str | None]) -> dict:
    widths: set[int] = set()
    for scan in arm_scans.values():
        widths.update(scan["coverage_widths"])
    consistent = len(widths) == 1
    counter_bytes = (next(iter(widths)) // 2) if consistent else None

    declared_ids = None
    declared_document = None
    targets_reason = None
    for label in ("off", "on"):
        document = targets_documents.get(label)
        if isinstance(document, list):
            if declared_ids is None:
                declared_ids = [entry.get("target_id")
                                if isinstance(entry, Mapping) else None
                                for entry in document]
                declared_document = label
            elif [entry.get("target_id") if isinstance(entry, Mapping) else None
                  for entry in document] != declared_ids:
                targets_reason = (f"the two arms declare different "
                                  f"{TARGETS_NAME} target lists")
                declared_ids = None
                break
    counter_values: set[int] = set()
    for scan in arm_scans.values():
        for values in scan["counter_observed_values"]:
            counter_values.update(values)
    boolean_counters = counter_values <= {0, 1} if counter_values else False

    confirmed = bool(consistent and declared_ids
                     and counter_bytes == len(declared_ids) and boolean_counters)
    reason = None
    if not consistent:
        reason = (f"coverage_hex widths are inconsistent across the compared "
                  f"receipts: {_sorted_counter(widths)} hexadecimal characters; "
                  "no counter order or width can be stated")
    elif declared_ids is None:
        reason = targets_reason or next(
            (item for item in targets_reasons.values() if item), None) or (
            f"{TARGETS_NAME} is unavailable (or declares an unusable list), so "
            "the counter-to-target order cannot be confirmed from the artifacts")
    elif counter_bytes != len(declared_ids):
        reason = (f"coverage_hex holds {counter_bytes} counter byte(s) per case "
                  f"but {TARGETS_NAME} declares {len(declared_ids)} target(s), so "
                  "the counter-to-target order is not confirmed")
    elif not boolean_counters:
        reason = ("the observed counter values are not boolean 0x00/0x01, so the "
                  "one-byte-per-target shape is not confirmed")

    confirmed_by = []
    if consistent:
        confirmed_by.append(
            f"every compared receipt carries {next(iter(widths))} hexadecimal "
            f"characters ({counter_bytes} byte(s))")
    if declared_ids is not None:
        confirmed_by.append(
            f"{TARGETS_NAME} declares {len(declared_ids)} target(s): "
            f"{declared_ids}")
    if counter_values:
        confirmed_by.append(
            f"observed counter values: {_sorted_counter(counter_values)}")
    if declared_document:
        confirmed_by.append(f"target list read from the {declared_document} arm")
    return {
        "counter_order_rule": _counter_order_rule(),
        "hex_characters_per_case": {"values": _sorted_counter(widths),
                                    "consistent": consistent},
        "counter_bytes_per_case": counter_bytes,
        "bits_per_counter": 8 if consistent else None,
        "declared_target_count": None if declared_ids is None else len(declared_ids),
        "declared_target_ids": declared_ids,
        "observed_counter_values": _sorted_counter(counter_values),
        "counter_order_confirmed": confirmed,
        "confirmed_by": confirmed_by,
        "reason": reason,
    }


def _coverage_arm(scan: Mapping, analysis: Mapping, *, layout: Mapping,
                  declared_ids: Sequence | None, effective_seconds: float | None,
                  label: str, pair_widths_consistent: bool) -> dict:
    novelty = analysis.get("local_target_novelty") or {}
    widths = scan["coverage_widths"]
    arm_consistent = len(widths) == 1 and not scan["coverage_missing_cases"] \
        and not scan["invalid_coverage_cases"]
    per_target = None
    reason = None
    if not scan["rows"]:
        reason = f"the {label} arm has no receipt, so no coverage was observed"
    elif scan["coverage_missing_cases"] or scan["invalid_coverage_cases"]:
        reason = (f"{scan['coverage_missing_cases']} receipt(s) lack coverage_hex "
                  f"and {scan['invalid_coverage_cases']} carry an invalid value")
    elif not pair_widths_consistent:
        reason = (
            "the two arms do not even agree on the coverage_hex width "
            f"(counter bytes per case: {layout.get('counter_bytes_per_case')}), "
            "so per-target counts are not comparable across the arms")
    elif not arm_consistent:
        reason = (f"coverage_hex widths are inconsistent within the {label} arm: "
                  f"{_sorted_counter(widths)} hexadecimal characters")
    else:
        counters = next(iter(widths)) // 2
        per_target = []
        for counter in range(counters):
            target_id = None
            target = None
            if declared_ids is not None and counter < len(declared_ids):
                target = declared_ids[counter]
                target_id = (target.get("target_id")
                             if isinstance(target, Mapping) else None)
            per_target.append({
                "counter_index": counter,
                "target_id": target_id,
                "target_declaration": target,
                "hit_cases": scan["counter_hit_cases"][counter],
                "first_hit_case_index": _first_hit_case_index(scan, counter),
                "observed_values": _sorted_counter(
                    scan["counter_observed_values"][counter]),
            })
    hit_slots = (None if per_target is None
                 else sum(1 for entry in per_target if entry["hit_cases"]))
    rate = novelty.get("new_target_bits_per_second")
    rate_reason = novelty.get("reason")
    if rate is None and rate_reason is None:
        rate_reason = ("effective_search_seconds is unknown, so the shipped "
                       "per-second rule cannot be evaluated")
    return {
        "available": per_target is not None,
        "reason": reason,
        "per_target_hit_counts": per_target,
        "targets_hit_at_least_once": hit_slots,
        "targets_hit_at_least_once_scope": ("declared_targets"
                                            if layout.get("counter_order_confirmed")
                                            else "counter_slots"),
        "first_seen_target_slots": novelty.get("first_seen_target_slots"),
        "first_seen_target_bits": novelty.get("first_seen_target_bits"),
        "new_target_slots_per_second": novelty.get("new_target_slots_per_second"),
        "new_target_bits_per_second": rate,
        "new_target_bits_per_second_rule": (
            "first_seen_target_bits / effective_search_seconds (the same "
            "quantity and rule the shipped paired_efficiency group summary "
            "reports as coverage_novelty.new_target_bits_per_second)"),
        "new_target_bits_per_second_source": (
            "acceptance_metrics.analyze_run:local_target_novelty"),
        "rate_reason": rate_reason,
        "coverage_width_bytes": novelty.get("coverage_width_bytes"),
        "effective_search_seconds": effective_seconds,
    }


def _first_hit_case_index(scan: Mapping, counter: int) -> int | None:
    for index, fields in enumerate(scan["case_fields"]):
        coverage = fields.get("coverage_hex")
        if not isinstance(coverage, str) or len(coverage) < 2 * counter + 2:
            continue
        try:
            flag = int(coverage[2 * counter:2 * counter + 2], 16)
        except ValueError:
            continue
        if flag:
            return index
    return None


# ---------------------------------------------------------------------------
# shared raw-input prefix and the bounded in-prefix pairing
# ---------------------------------------------------------------------------


def _shared_raw_prefix(off_scan: Mapping, on_scan: Mapping, *,
                       off_cases: int, on_cases: int, max_items: int) -> dict:
    off_identities = off_scan["raw_identities"]
    on_identities = on_scan["raw_identities"]
    usable = min(len(off_identities), len(on_identities), max_items)
    length = 0
    for index in range(usable):
        if off_identities[index] != on_identities[index]:
            break
        length += 1
    capped = False
    if length == usable and (len(off_identities) < off_cases
                             or len(on_identities) < on_cases):
        capped = True
    if length == min(off_cases, on_cases) and min(off_cases, on_cases) > 0:
        scope = "full" if off_cases == on_cases else "shared_prefix_only"
    elif length == 0:
        scope = "none"
    else:
        scope = "shared_prefix_only"
    divergent = None
    if length < min(len(off_identities), len(on_identities)):
        divergent = {
            "case_index": length,
            "off_raw_sha256": off_identities[length][0],
            "on_raw_sha256": on_identities[length][0],
            "off_raw_identity": off_identities[length][1],
            "on_raw_identity": on_identities[length][1],
        }
    reason = None
    if length == 0:
        reason = ("the two arms share no raw input case, so no case is paired; "
                  "only whole-arm aggregates can be compared")
    elif capped:
        reason = (f"the raw identity window was capped at max_prefix_items="
                  f"{max_items} cases, so the prefix length is a lower bound")
    return {
        "definition": (
            "the number of leading cases whose raw input identity is identical "
            "in both arms, compared in receipt order; the searches diverge by "
            "construction, so this prefix is the only per-case comparable window"),
        "raw_identity_field": RAW_FIELD_PREFERENCE[0],
        "raw_identity_cross_check_field": RAW_FIELD_PREFERENCE[1],
        "length": length,
        "off_cases": off_cases,
        "on_cases": on_cases,
        "covered_by_prefix": {
            "off": length == off_cases,
            "on": length == on_cases,
        },
        "capped_by_shorter_arm": length == min(off_cases, on_cases)
                                 and off_cases != on_cases,
        "truncated_by_max_prefix_items": capped,
        "per_case_pairing_scope": scope,
        "first_divergent_case_index": length if divergent is not None else None,
        "first_divergent_case": divergent,
        "reason": reason,
    }


def _paired_within_prefix(off_scan: Mapping, on_scan: Mapping, *,
                          prefix: Mapping) -> dict:
    length = prefix["length"]
    per_field = {
        name: {"equal": 0, "different": 0, "different_case_indexes": [],
               "indexes_truncated": False}
        for name in PAIRED_FIELDS}
    for index in range(length):
        off_fields = off_scan["case_fields"][index]
        on_fields = on_scan["case_fields"][index]
        for name in PAIRED_FIELDS:
            left = off_fields.get(name)
            right = on_fields.get(name)
            entry = per_field[name]
            if _canonical(left) == _canonical(right):
                entry["equal"] += 1
            else:
                entry["different"] += 1
                if len(entry["different_case_indexes"]) < MAX_DETAIL_INDEXES:
                    entry["different_case_indexes"].append(index)
                else:
                    entry["indexes_truncated"] = True
    reason = None
    if length == 0:
        reason = ("the shared raw-input prefix is empty, so no per-case field "
                  "comparison exists")
    return {
        "cases_compared": length,
        "scope": prefix["per_case_pairing_scope"],
        "comparison_boundary": (
            "only cases inside the shared raw-input prefix are compared; beyond "
            "it the arms ran different inputs and no per-case pairing exists"),
        "fields": per_field,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# per-direction witness rollup over runtime_edge_provenance_report.v1
# ---------------------------------------------------------------------------


def _declared_directions(selections: object) -> list[dict]:
    """Declared edges per direction, in declaration order (last row wins)."""
    declared: dict[str, dict] = {}
    if isinstance(selections, Mapping):
        selections = selections.get("selections")
    if not isinstance(selections, (list, tuple)):
        return []
    for row in selections:
        if not isinstance(row, Mapping):
            continue
        direction = row.get("direction")
        if not isinstance(direction, str) or not direction:
            continue
        declared[direction] = {
            "path_id": row.get("path_id"),
            "target": row.get("target"),
            "edges": [edge for edge in (row.get("edges") or ())
                      if isinstance(edge, Mapping)]}
    return [{"direction": direction, **row} for direction, row in declared.items()]


def roll_up_edge_directions(provenance_report: Mapping,
                            selections: object) -> dict:
    """Join ``runtime_edge_provenance_report.v1`` rows to declared directions.

    The shipped report carries one row per *declared runtime edge*, keyed by
    ``(rule_index, prerequisite_index)``; the run's own compiled declaration
    selections say which direction declared that key.  A selected edge whose key
    has no provenance row is not a declared runtime edge in that contract and is
    counted as ``non_runtime_edge_count`` instead of being credited.
    """
    rows_by_key: dict[tuple, Mapping] = {}
    for row in provenance_report.get("edges") or ():
        if not isinstance(row, Mapping):
            continue
        key = (row.get("rule_index"), row.get("prerequisite_index"))
        rows_by_key[key] = row
    directions: dict[str, dict] = {}
    for declaration in _declared_directions(selections):
        direction = declaration["direction"]
        counts = {"certified": 0, "incomplete": 0, "unknown": 0}
        runtime = 0
        non_runtime = 0
        rows = []
        for edge in declaration["edges"]:
            key = (edge.get("rule_index"), edge.get("prerequisite_index"))
            provenance_row = rows_by_key.get(key)
            if provenance_row is None:
                non_runtime += 1
                rows.append({
                    "rule_index": key[0], "prerequisite_index": key[1],
                    "kind": edge.get("kind"), "runtime_edge": False,
                    "status": None, "reason": "not_declared_in_runtime_contract",
                    "missing_hops": None})
                continue
            runtime += 1
            status = provenance_row.get("status")
            if status in counts:
                counts[status] += 1
            rows.append({
                "rule_index": key[0], "prerequisite_index": key[1],
                "kind": edge.get("kind"), "runtime_edge": True,
                "status": status, "reason": provenance_row.get("reason"),
                "relation": provenance_row.get("relation"),
                "scope": provenance_row.get("scope"),
                "missing_hops": list(provenance_row.get("missing") or ())})
        directions[direction] = {
            "direction": direction,
            "path_id": declaration.get("path_id"),
            "target": declaration.get("target"),
            "declared_edge_count": len(declaration["edges"]),
            "runtime_edge_count": runtime,
            "non_runtime_edge_count": non_runtime,
            "counts": counts,
            "certified_edges": counts["certified"],
            "edges": rows,
        }
    return directions


def _selections_from_manifest(document: Mapping | None) -> object:
    if not isinstance(document, Mapping):
        return None
    runtime_paths = document.get("runtime_paths")
    if not isinstance(runtime_paths, Mapping):
        return None
    declaration = runtime_paths.get("declaration")
    if not isinstance(declaration, Mapping):
        return None
    return declaration.get("selections")


def _witnessed_edges_arm(directory: Path, analysis: Mapping, *,
                         max_pending: int, max_event_gap: int,
                         verify_semantic: bool) -> dict:
    novelty = analysis.get("witnessed_edge_novelty") or {}
    block = {
        "unique_edges": novelty.get("unique_edges"),
        "new_edges_per_second": novelty.get("new_edges_per_second"),
        "edge_definition": novelty.get("edge_definition"),
        "candidate_observations": novelty.get("candidate_observations"),
        "invalid_candidate_records": novelty.get("invalid_candidate_records"),
        "events_without_provenance": novelty.get("events_without_provenance"),
        "reason": novelty.get("reason"),
        "declared_selections_source":
            f"{MANIFEST_NAME}:runtime_paths.declaration.selections",
        "by_direction": None,
        "by_direction_reason": None,
        "provenance": None,
    }
    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.is_file():
        block["by_direction_reason"] = (
            f"{MANIFEST_NAME} is absent, so the declared direction of each "
            "witnessed runtime edge cannot be resolved")
        return block
    try:
        manifest = _read_json_object(manifest_path)
    except P4OperatorBenefitEvidenceError as exc:
        block["by_direction_reason"] = str(exc)
        return block
    selections = _selections_from_manifest(manifest)
    if not selections:
        block["by_direction_reason"] = (
            f"{MANIFEST_NAME} declares no runtime_paths.declaration.selections, "
            "so no direction is declared for any witnessed edge")
        return block
    try:
        contract, endpoints = edge_provenance_session(directory)
        stream = TraceEventStream(directory, verify_semantic=verify_semantic)
        report = edge_provenance_report(
            contract, stream.events(), endpoints=endpoints,
            max_pending=max_pending, max_event_gap=max_event_gap)
    except (TraceUnavailable, ValueError, KeyError, TypeError, OSError) as exc:
        block["by_direction_reason"] = (
            f"the shipped runtime_edge_provenance analysis could not be run on "
            f"this arm: {type(exc).__name__}: {exc}")
        return block
    block["by_direction"] = roll_up_edge_directions(report, selections)
    block["provenance"] = {
        "schema_version": report.get("schema_version"),
        "contract_identity": report.get("contract_identity"),
        "graph_sha256": report.get("graph_sha256"),
        "counts": report.get("counts"),
        "proof_scope": report.get("proof_scope"),
        "bounds": report.get("bounds"),
        "events_observed": report.get("events_observed"),
        "events_rejected": report.get("events_rejected"),
        "resets": report.get("resets"),
        "dropped_late_hops": report.get("dropped_late_hops"),
    }
    return block


# ---------------------------------------------------------------------------
# chains / budgets
# ---------------------------------------------------------------------------


def _chains_arm(analysis: Mapping) -> dict:
    chains = analysis.get("certified_chains") or {}
    admissions = analysis.get("chain_completion_by_admission") or {}
    gaps = analysis.get("chain_gap_evidence") or {}
    producer = analysis.get("chain_producer") or {}
    certified = chains.get("total")
    reason = analysis.get("certified_chains_reason")
    if certified is not None and reason is None and chains.get("cap_reached"):
        reason = ("the certificate cap was reached, so the reported counts are "
                  "lower bounds")
    return {
        "available": certified is not None,
        "certified_total": certified,
        "by_direction": chains.get("by_direction"),
        "same_case": chains.get("same_case"),
        "cross_case": chains.get("cross_case"),
        "incomplete_total": chains.get("incomplete_total"),
        "cap_reached": chains.get("cap_reached"),
        "duplicate_certificate_ids": chains.get("duplicate_certificate_ids"),
        "certified_per_second": analysis.get("certified_chains_per_second"),
        "certified_per_second_denominator": "effective_search_seconds",
        "certified_per_second_reason":
            analysis.get("certified_chains_per_second_reason"),
        "admissions_total": admissions.get("admissions_total"),
        "certified_admissions": admissions.get("certified_admissions"),
        "incomplete_admissions": admissions.get("incomplete_admissions"),
        "certified_ratio": admissions.get("certified_ratio"),
        "first_missing_hop_counts": gaps.get("first_missing_hop_counts"),
        "semantics": analysis.get("certified_chains_semantics"),
        "producer": {
            "available": producer.get("available"),
            "kind": producer.get("kind"),
            "module": producer.get("producer_module"),
            "reason": producer.get("reason"),
        },
        "reason": reason,
    }


def _identity_fields(identity_document: Mapping | None,
                     report_document: Mapping | None) -> dict:
    identity = (identity_document or {}).get("identity")
    identity = identity if isinstance(identity, Mapping) else {}
    run_config = identity.get("run_config")
    run_config = run_config if isinstance(run_config, Mapping) else {}
    components = identity.get("components")
    components = components if isinstance(components, Mapping) else {}
    session = identity.get("session")
    session = session if isinstance(session, Mapping) else {}
    genome = identity.get("genome")
    genome = genome if isinstance(genome, Mapping) else {}
    feedback = identity.get("feedback")
    feedback = feedback if isinstance(feedback, Mapping) else {}
    report = report_document or {}
    source_files = identity.get("source_files")
    source_digest = None
    if isinstance(source_files, list) and source_files and all(
            isinstance(entry, Mapping)
            and isinstance(entry.get("path"), str)
            and isinstance(entry.get("sha256"), str) for entry in source_files):
        source_digest = _sha256_of(sorted(
            (entry["path"], entry["sha256"]) for entry in source_files))
    return {
        "run_id": run_config.get("run_id"),
        "identity_document_sha256": (identity_document or {}).get("sha256"),
        "search_seed": run_config.get("search_seed"),
        "max_tests": run_config.get("max_tests"),
        "duration_seconds": _finite_non_negative(run_config.get("duration_seconds")),
        "feedback_interval": run_config.get("feedback_interval"),
        "source_files_sha256": source_digest,
        "component_identity_sha256": (session.get("component_identity_sha256")
                                      or components.get("identity_sha256")),
        "decoder_manifest_sha256": report.get("decoder_manifest_sha256"),
        "global_mutation_seed": report.get("global_mutation_seed"),
        "genome_plan_sha256": genome.get("plan_sha256"),
        "targets_sha256": feedback.get("targets_sha256"),
        "identity_document_present": identity_document is not None,
    }


def _sha256_of(value: object) -> str | None:
    import hashlib
    try:
        return hashlib.sha256(_canonical(value)).hexdigest()
    except (TypeError, ValueError):
        return None


def _operator_state(report_document: Mapping | None) -> dict:
    report = report_document or {}
    state = {}
    for key in OPERATOR_STATE_KEYS:
        block = report.get(key)
        if isinstance(block, Mapping):
            state[key] = dict(block)
    return state


# ---------------------------------------------------------------------------
# the pair comparison
# ---------------------------------------------------------------------------


def _compare_one(off_dir: Path, on_dir: Path, *, label: str,
                 chain_producer: object, max_certificates: int,
                 max_pending: int, max_event_gap: int,
                 require_native_receipts: bool, ingest_batch_size: int,
                 edge_max_pending: int, edge_max_event_gap: int,
                 verify_semantic: bool,
                 max_prefix_items: int) -> dict:
    limits: list[dict] = []
    for arm_label, directory in (("off", off_dir), ("on", on_dir)):
        if not directory.is_dir():
            raise P4OperatorBenefitEvidenceError(
                f"{arm_label} arm run directory does not exist: {directory}")
        missing = [name for name in CORE_ARTIFACTS
                   if not (directory / name).is_file()]
        if missing:
            raise P4OperatorBenefitEvidenceError(
                f"{arm_label} arm {directory} lacks required artifact(s) "
                f"{missing}; without them no case-level or budget evidence "
                "exists, so the comparison refuses instead of degrading")

    reports: dict[str, dict | None] = {}
    identities: dict[str, dict | None] = {}
    identity_limits: list[dict] = []
    targets_documents: dict[str, object] = {}
    targets_reasons: dict[str, str | None] = {}
    scans: dict[str, dict] = {}
    analyses: dict[str, dict] = {}
    for arm_label, directory in (("off", off_dir), ("on", on_dir)):
        reports[arm_label] = _read_json_object(directory / REPORT_NAME)
        try:
            identities[arm_label] = _read_json_object(directory / IDENTITY_NAME)
        except P4OperatorBenefitEvidenceError as exc:
            identities[arm_label] = None
            identity_limits.append({
                "pair": "pending", "arm": arm_label,
                "quantity": "same_budget.identity",
                "reason": str(exc)})
        targets_document, targets_reason = _read_targets(directory / TARGETS_NAME)
        targets_documents[arm_label] = targets_document
        targets_reasons[arm_label] = targets_reason
        scans[arm_label] = _scan_arm_receipts(
            directory / RECEIPTS_NAME, max_prefix_items=max_prefix_items)
        try:
            analyses[arm_label] = analyze_run(
                directory, chain_producer=chain_producer,
                max_certificates=max_certificates, max_pending=max_pending,
                max_event_gap=max_event_gap,
                require_native_receipts=require_native_receipts,
                ingest_batch_size=ingest_batch_size,
                verify_semantic=verify_semantic)
        except ValueError as exc:
            raise P4OperatorBenefitEvidenceError(
                f"{arm_label} arm {directory} cannot be analyzed: {exc}") from exc

    identities_fields = {
        arm_label: _identity_fields(identities[arm_label], reports[arm_label])
        for arm_label in ("off", "on")}
    off_run_id = identities_fields["off"]["run_id"] or off_dir.name
    on_run_id = identities_fields["on"]["run_id"] or on_dir.name
    pair_id = f"{off_run_id}__vs__{on_run_id}"
    for entry in identity_limits:
        entry["pair"] = pair_id
    limits.extend(identity_limits)

    layout = _coverage_layout(scans, targets_documents, targets_reasons)
    declared_ids = None
    if layout["declared_target_ids"] is not None:
        for arm_label in ("off", "on"):
            document = targets_documents.get(arm_label)
            if isinstance(document, list) and document:
                declared_ids = document
                break

    # -- same-budget evidence -------------------------------------------------
    arm_budget = {}
    for arm_label in ("off", "on"):
        scan = scans[arm_label]
        analysis = analyses[arm_label]
        report = reports[arm_label] or {}
        identity = identities_fields[arm_label]
        reported_statuses = report.get("statuses")
        reported_tests = report.get("tests")
        if _int_or_none(reported_tests) != scan["rows"]:
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "same_budget.tests",
                "reason": (f"{REPORT_NAME} declares tests={reported_tests!r} while "
                           f"{RECEIPTS_NAME} holds {scan['rows']} row(s); both "
                           "values are reported")})
        if (isinstance(reported_statuses, Mapping)
                and dict(reported_statuses) != scan["status_counts"]):
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "same_budget.statuses",
                "reason": (f"{REPORT_NAME} statuses {dict(reported_statuses)} "
                           f"disagree with the receipt statuses "
                           f"{scan['status_counts']}; both values are reported")})
        arm_budget[arm_label] = {
            "run_dir": str(off_dir if arm_label == "off" else on_dir),
            "run_id": identity["run_id"],
            "cases": scan["rows"],
            "tests": {"reported": _int_or_none(reported_tests),
                      "receipts": scan["rows"]},
            "statuses": {
                "reported": dict(reported_statuses)
                if isinstance(reported_statuses, Mapping) else None,
                "receipts": dict(scan["status_counts"])},
            "effective_search_seconds": analysis.get("effective_search_seconds"),
            "effective_search_seconds_reason":
                analysis.get("effective_search_seconds_reason"),
            "elapsed_seconds": analysis.get("elapsed_seconds"),
            "declared": {name: identity.get(name)
                         for name in ("max_tests", "duration_seconds",
                                      "feedback_interval", "search_seed")},
            "identity": identity,
        }

    budget_fields = {}
    for name in BUDGET_FIELDS + SEED_FIELDS:
        left = arm_budget["off"]["declared"].get(name)
        right = arm_budget["on"]["declared"].get(name)
        if left is None or right is None:
            budget_fields[name] = {"off": left, "on": right, "equal": None}
        else:
            budget_fields[name] = {"off": left, "on": right, "equal": left == right}
    comparable_budget = [entry["equal"] for entry in budget_fields.values()
                         if entry["equal"] is not None]
    declared_budget_equal = (None if not comparable_budget
                             else all(comparable_budget))

    identity_pairs = {}
    for name in SOURCE_IDENTITY_FIELDS:
        left = arm_budget["off"]["identity"].get(name)
        right = arm_budget["on"]["identity"].get(name)
        if left is None or right is None:
            identity_pairs[name] = {"off": left, "on": right, "equal": None}
        else:
            identity_pairs[name] = {"off": left, "on": right, "equal": left == right}
    source_identity_equal = (None if not [entry for entry in identity_pairs.values()
                                          if entry["equal"] is not None]
                             else all(entry["equal"]
                                      for entry in identity_pairs.values()
                                      if entry["equal"] is not None))

    effective_off = arm_budget["off"]["effective_search_seconds"]
    effective_on = arm_budget["on"]["effective_search_seconds"]
    effective_ratio = (None if not effective_off or effective_on is None
                       else effective_on / effective_off)

    plan_identity_fields = {}
    for name in ("genome_plan_sha256", "targets_sha256"):
        left = arm_budget["off"]["identity"].get(name)
        right = arm_budget["on"]["identity"].get(name)
        plan_identity_fields[name] = {
            "off": left, "on": right,
            "equal": None if left is None or right is None else left == right}

    prefix = _shared_raw_prefix(
        scans["off"], scans["on"], off_cases=arm_budget["off"]["cases"],
        on_cases=arm_budget["on"]["cases"], max_items=max_prefix_items)
    if scans["off"]["prefix_truncated"] or scans["on"]["prefix_truncated"]:
        limits.append({
            "pair": pair_id, "arm": "pair",
            "quantity": "same_budget.shared_raw_input_prefix",
            "reason": f"only the first max_prefix_items={max_prefix_items} cases "
                      "per arm were retained for the prefix comparison"})
    if prefix["reason"]:
        limits.append({"pair": pair_id, "arm": "pair",
                       "quantity": "same_budget.shared_raw_input_prefix",
                       "reason": prefix["reason"]})

    same_budget = {
        "definition": (
            "the evidence that fixes the comparison window: case counts and "
            "statuses, the declared search budget, the measured effective "
            "search window and the shared raw-input prefix"),
        "arms": arm_budget,
        "case_count_equal": arm_budget["off"]["cases"] == arm_budget["on"]["cases"],
        "tests_equal": (arm_budget["off"]["tests"]["reported"]
                        == arm_budget["on"]["tests"]["reported"]),
        "declared_budget_fields": budget_fields,
        "declared_budget_equal": declared_budget_equal,
        "source_identity_fields": identity_pairs,
        "source_identity_equal": source_identity_equal,
        "run_plan_identity_fields": plan_identity_fields,
        "run_plan_identity_note": (
            "genome.plan_sha256 digests the whole run plan, so it is expected to "
            "differ per run and, for a plan-mutating operator such as initial RAM "
            "data, it must differ: the operator's declared effect is exactly a "
            "changed plan/initial image. It is therefore reported but not used as "
            "a comparability prerequisite; the frozen source identity fields "
            "above are."),
        "effective_search_seconds_ratio_on_over_off": effective_ratio,
        "shared_raw_input_prefix": prefix,
    }

    # -- coverage -------------------------------------------------------------
    arm_coverage = {}
    for arm_label in ("off", "on"):
        arm_coverage[arm_label] = _coverage_arm(
            scans[arm_label], analyses[arm_label], layout=layout,
            declared_ids=declared_ids,
            effective_seconds=arm_budget[arm_label]["effective_search_seconds"],
            label=arm_label,
            pair_widths_consistent=bool(
                layout["hex_characters_per_case"]["consistent"]))
        if not arm_coverage[arm_label]["available"]:
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "coverage.per_target_hit_counts",
                "reason": arm_coverage[arm_label]["reason"]})
        if arm_coverage[arm_label]["new_target_bits_per_second"] is None:
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "coverage.new_target_bits_per_second",
                "reason": arm_coverage[arm_label]["rate_reason"]})
    if not layout["counter_order_confirmed"] and layout["reason"]:
        limits.append({"pair": pair_id, "arm": "pair",
                       "quantity": "coverage.counter_order",
                       "reason": layout["reason"]})
    paired_prefix = _paired_within_prefix(scans["off"], scans["on"],
                                          prefix=prefix)
    coverage = {
        "boundary": (
            "per-target counts are computed from each arm's own receipts over "
            "that arm's own window; they state what each arm observed, not which "
            "arm reaches a target first"),
        "layout": layout,
        "arms": arm_coverage,
        "paired_within_prefix": paired_prefix,
    }

    # -- chains ---------------------------------------------------------------
    arm_chains = {arm_label: _chains_arm(analyses[arm_label])
                  for arm_label in ("off", "on")}
    for arm_label in ("off", "on"):
        if not arm_chains[arm_label]["available"]:
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "chains.certified_total",
                "reason": arm_chains[arm_label]["reason"]
                          or "the shipped analysis certified no measurable count"})
    chains = {
        "definition": (
            "certificate counts the shipped chain_certificates producer emitted "
            "for each arm's own trace, as accounted by "
            "acceptance_metrics.analyze_run; certified means the producer "
            "witnessed every required hop of a declared chain"),
        "arms": arm_chains,
    }

    # -- witnessed edges ------------------------------------------------------
    arm_edges = {}
    for arm_label, directory in (("off", off_dir), ("on", on_dir)):
        arm_edges[arm_label] = _witnessed_edges_arm(
            directory, analyses[arm_label], max_pending=edge_max_pending,
            max_event_gap=edge_max_event_gap, verify_semantic=verify_semantic)
        if arm_edges[arm_label]["by_direction"] is None:
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "witnessed_edges.by_direction",
                "reason": arm_edges[arm_label]["by_direction_reason"]})
        if arm_edges[arm_label]["unique_edges"] is None:
            limits.append({
                "pair": pair_id, "arm": arm_label,
                "quantity": "witnessed_edges.unique_edges",
                "reason": arm_edges[arm_label]["reason"]})
    witnessed_edges = {
        "definitions": {
            "unique_edges": (
                "analyze_run counted unique "
                "(graph_sha256, tuple(path_ids), relation, rule_index, scope) "
                "candidate tuples over the arm's own trace"),
            "by_direction": (
                "runtime_edge_provenance_report.v1 rows (one per declared "
                "runtime edge) rolled up through the run's own "
                "runtime_paths.declaration.selections direction labels"),
        },
        "arms": arm_edges,
    }

    # -- explicit non-comparability ------------------------------------------
    not_comparable = [
        ("The two arms' raw input sequences are identical only for the first "
         f"{prefix['length']} case(s); the searches diverge by construction, so "
         "everything beyond that prefix compares two different search processes, "
         "not paired cases."),
        ("Per-case causal pairing is undefined beyond the shared raw-input "
         f"prefix (length {prefix['length']}); no per-case causal claim is made "
         "for later cases."),
        ("The arms' absolute counts are only like-for-like once normalised by "
         "each arm's own effective_search_seconds and case count; a raw "
         "difference is not a benefit claim."),
        ("Target-hit counts come from each arm's own receipts over its own "
         "window: they do not state which arm would reach a target first."),
        ("Chain certificate counts state what the shipped producer could certify "
         "over each arm's own trajectory, not an independent DUT chain rate."),
        ("Witnessed edges are per declared runtime edge over each arm's own "
         "trace; direction labels come from that run's own manifest selections."),
        ("Nothing here re-executes RTL: every number is read from saved "
         "artifacts and no operator effect is re-derived from raw events."),
    ]
    if not same_budget["case_count_equal"]:
        not_comparable.append(
            f"The arms executed different case counts "
            f"({arm_budget['off']['cases']} off vs {arm_budget['on']['cases']} "
            "on) at the same declared budget, so per-arm totals and rates are not "
            "directly like-for-like.")
    if arm_budget["off"]["effective_search_seconds"] != \
            arm_budget["on"]["effective_search_seconds"]:
        not_comparable.append(
            "The arms' measured effective search windows differ "
            f"({arm_budget['off']['effective_search_seconds']} s off vs "
            f"{arm_budget['on']['effective_search_seconds']} s on), so per-second "
            "rates differ partly through the denominator.")

    operator_state = {"off": _operator_state(reports["off"]),
                      "on": _operator_state(reports["on"])}
    enabled_differences = {}
    for key in sorted(set(operator_state["off"]) | set(operator_state["on"])):
        left = (operator_state["off"].get(key) or {}).get("enabled")
        right = (operator_state["on"].get(key) or {}).get("enabled")
        enabled_differences[key] = {"off": left, "on": right}
    operator = {
        "label": label,
        "state_evidence": (
            f"{REPORT_NAME} operator-state blocks that declare whether the "
            "operator ran; an arm without the block simply did not declare it"),
        "arms": {
            arm_label: {
                "state": operator_state[arm_label],
                "state_keys": sorted(operator_state[arm_label]),
                "reason": (None if operator_state[arm_label] else
                           f"{REPORT_NAME} declares none of the known operator "
                           f"state blocks {list(OPERATOR_STATE_KEYS)}"),
            } for arm_label in ("off", "on")},
        "enabled_by_key": enabled_differences,
    }

    return {
        "pair_id": pair_id,
        "operator": operator,
        "same_budget": same_budget,
        "coverage": coverage,
        "chains": chains,
        "witnessed_edges": witnessed_edges,
        "not_comparable": not_comparable,
        "limits": limits,
    }


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------


def _family_refusals(pair: Mapping, family: str) -> list[dict]:
    refusals = []
    pair_id = pair["pair_id"]
    for arm_label in ("off", "on"):
        budget = pair["same_budget"]["arms"][arm_label]
        coverage = pair["coverage"]["arms"][arm_label]
        chains = pair["chains"]["arms"][arm_label]
        edges = pair["witnessed_edges"]["arms"][arm_label]
        if family == "search_budget":
            if not budget["cases"]:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "same_budget.cases",
                    "reason": (f"{RECEIPTS_NAME} holds no case for the "
                               f"{arm_label} arm")})
            if budget["effective_search_seconds"] is None:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "same_budget.effective_search_seconds",
                    "reason": budget["effective_search_seconds_reason"]
                              or f"{REPORT_NAME} declares no finite positive "
                                 "effective_search_seconds"})
        elif family == "coverage":
            if not coverage["available"]:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "coverage.per_target_hit_counts",
                    "reason": coverage["reason"]})
            if coverage["new_target_bits_per_second"] is None:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "coverage.new_target_bits_per_second",
                    "reason": coverage["rate_reason"]})
        elif family == "chains":
            if not chains["available"]:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "chains.certified_total",
                    "reason": chains["reason"]
                              or "the shipped chain analysis could not measure "
                                 "this arm"})
        elif family == "witnessed_edges":
            if edges["by_direction"] is None:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "witnessed_edges.by_direction",
                    "reason": edges["by_direction_reason"]})
            if edges["unique_edges"] is None:
                refusals.append({
                    "pair": pair_id, "arm": arm_label,
                    "metric_family": family,
                    "quantity": "witnessed_edges.unique_edges",
                    "reason": edges["reason"]})
    return refusals


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------


def compare_pairs(pairs: Sequence, *, required_families: Sequence[str] = (),
                  chain_producer: object = None,
                  max_certificates: int = DEFAULT_MAX_CERTIFICATES,
                  max_pending: int = 128, max_event_gap: int = 4096,
                  require_native_receipts: bool = True,
                  ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                  edge_max_pending: int = 4096,
                  edge_max_event_gap: int = 65536,
                  verify_semantic: bool = True,
                  max_prefix_items: int = DEFAULT_MAX_PREFIX_ITEMS) -> dict:
    """Compare operator ON/OFF arm pairs read-only and return one document.

    ``pairs`` items are either ``(off_dir, on_dir)`` tuples or mappings with
    ``off``/``on`` and an optional ``operator`` label.  ``required_families``
    names the metric families that must be fully measurable; any missing
    evidence for them is listed in ``refusals`` and flips ``evidence_status``
    to ``"refused"`` (the caller turns that into a non-zero exit).  Missing
    evidence is always ``null`` + ``reason`` -- never ``0``.
    """
    if type(max_prefix_items) is not int or max_prefix_items < 1:
        raise ValueError("max_prefix_items must be a positive integer")
    unknown = [family for family in required_families
               if family not in METRIC_FAMILIES]
    if unknown:
        raise ValueError(f"unknown metric family/families: {unknown}; "
                         f"known: {list(METRIC_FAMILIES)}")
    pair_documents = []
    for item in pairs:
        if isinstance(item, Mapping):
            off_dir = item.get("off")
            on_dir = item.get("on")
            label = item.get("operator") or item.get("label")
        else:
            off_dir, on_dir = item[0], item[1]
            label = item[2] if len(item) > 2 else None
        if off_dir is None or on_dir is None:
            raise ValueError(f"a pair needs an off and an on run directory: {item!r}")
        pair_documents.append(_compare_one(
            Path(off_dir), Path(on_dir), label=label, chain_producer=chain_producer,
            max_certificates=max_certificates, max_pending=max_pending,
            max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts,
            ingest_batch_size=ingest_batch_size,
            edge_max_pending=edge_max_pending,
            edge_max_event_gap=edge_max_event_gap,
            verify_semantic=verify_semantic, max_prefix_items=max_prefix_items))

    refusals = []
    for pair in pair_documents:
        for family in required_families:
            refusals.extend(_family_refusals(pair, family))
    limits = [limit for pair in pair_documents for limit in pair["limits"]]
    document = {
        "schema_version": SCHEMA_VERSION,
        "produced_by": "scripts/compare_p4_operator_benefit.py",
        "comparison_scope": (
            "read-only same-budget comparison of operator-ON and operator-OFF "
            "saved runs; it re-executes no RTL and renders no harness"),
        "required_families": list(required_families),
        "evidence_status": "refused" if refusals else "measurable",
        "comparison_boundaries": [
            "The arms' searches diverge by construction; only the shared "
            "raw-input prefix is a per-case comparable window.",
            "Different case counts make per-arm totals incomparable unless "
            "normalised by each arm's own window.",
            "No per-case causal pairing exists beyond the shared prefix.",
            "Null means unmeasurable from these artifacts, never zero.",
        ],
        "pairs": pair_documents,
        "refusals": refusals,
        "limits": limits,
    }
    return document


def compare_arm_pair(off_dir, on_dir, *, operator_label: str | None = None,
                     required_families: Sequence[str] = (),
                     **kwargs) -> dict:
    """Compare one ON/OFF arm pair; see :func:`compare_pairs`."""
    return compare_pairs([(off_dir, on_dir, operator_label)],
                         required_families=required_families, **kwargs)


# ---------------------------------------------------------------------------
# markdown rendering
# ---------------------------------------------------------------------------


def _format(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, Mapping):
        return ", ".join(f"{name}={_format(item)}" for name, item in value.items())
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_format(item) for item in value) + "]"
    return str(value)


def _table(lines: list[str], header: Sequence[str], rows: Iterable[Sequence]) -> None:
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for row in rows:
        lines.append("| " + " | ".join(_format(cell) for cell in row) + " |")


def render_markdown(document: Mapping) -> str:
    lines = ["# P4 operator benefit comparison (same budget, read-only)", ""]
    lines.append(f"- schema_version: `{document.get('schema_version')}`")
    lines.append(f"- evidence_status: `{document.get('evidence_status')}`")
    lines.append(f"- required metric families: "
                 f"`{document.get('required_families')}`")
    lines.append(f"- scope: {document.get('comparison_scope')}")
    lines.append("")
    lines.append("## What is not comparable")
    lines.append("")
    for item in document.get("comparison_boundaries") or ():
        lines.append(f"- {item}")
    lines.append("")
    for index, pair in enumerate(document.get("pairs") or ()):
        _render_pair(lines, pair, index)
    lines.append("## Refusals (fail closed)")
    lines.append("")
    if document.get("refusals"):
        _table(lines, ("pair", "arm", "metric family", "quantity", "reason"),
               [(item["pair"], item["arm"], item["metric_family"],
                 f"`{item['quantity']}`", item["reason"])
                for item in document["refusals"]])
    else:
        lines.append("- none: every required metric family is measurable from "
                     "the compared artifacts")
    lines.append("")
    lines.append("## Limits (null quantities)")
    lines.append("")
    if document.get("limits"):
        _table(lines, ("pair", "arm", "quantity", "reason"),
               [(item.get("pair"), item.get("arm"), f"`{item['quantity']}`",
                 item["reason"]) for item in document["limits"]])
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _compact_state(block: Mapping) -> dict:
    """Bounded, human-readable summary of one operator-state block."""
    preferred = ("schema_version", "enabled", "status", "source", "attempts",
                 "adopted", "granted", "changed", "no_op", "bounds", "bytes",
                 "declaration", "operator", "counts", "credit_totals",
                 "certificates", "certificates_truncated", "refusals",
                 "rejection_codes", "hit_ids", "penalized", "penalty_totals")
    summary: dict = {}
    for name in preferred:
        if name not in block:
            continue
        value = block[name]
        if isinstance(value, Mapping):
            summary[name] = {key: item for key, item in list(value.items())[:12]
                             if isinstance(item, (int, float, str, bool))}
        elif isinstance(value, (list, tuple)):
            summary[name] = f"{len(value)} item(s)"
        else:
            summary[name] = value
    omitted = [name for name in block if name not in summary]
    if omitted:
        summary["omitted_key_count"] = len(omitted)
    return summary


def _render_pair(lines: list[str], pair: Mapping, index: int) -> None:
    lines.append(f"## pairs[{index}]: `{pair.get('pair_id')}`")
    lines.append("")
    operator = pair.get("operator") or {}
    lines.append(f"- operator label: `{operator.get('label')}`")
    for arm_label in ("off", "on"):
        state = (operator.get("arms", {}).get(arm_label) or {}).get("state") or {}
        if not state:
            lines.append(f"- {arm_label} operator state: null (the arm declares "
                         "no recognized operator-state block)")
            continue
        for key in sorted(state):
            lines.append(f"- {arm_label} `{key}`: "
                         f"`{_format(_compact_state(state[key]))}`")
    lines.append("")
    budget = pair.get("same_budget") or {}
    prefix = budget.get("shared_raw_input_prefix") or {}
    lines.append("### Same-budget evidence")
    lines.append("")
    _table(lines, ("quantity", "off arm", "on arm"), [
        ("cases", budget["arms"]["off"]["cases"], budget["arms"]["on"]["cases"]),
        ("tests (report.json)",
         budget["arms"]["off"]["tests"]["reported"],
         budget["arms"]["on"]["tests"]["reported"]),
        ("statuses (receipts)", budget["arms"]["off"]["statuses"]["receipts"],
         budget["arms"]["on"]["statuses"]["receipts"]),
        ("effective_search_seconds",
         budget["arms"]["off"]["effective_search_seconds"],
         budget["arms"]["on"]["effective_search_seconds"]),
        ("elapsed_seconds", budget["arms"]["off"]["elapsed_seconds"],
         budget["arms"]["on"]["elapsed_seconds"]),
        ("declared max_tests", budget["arms"]["off"]["declared"]["max_tests"],
         budget["arms"]["on"]["declared"]["max_tests"]),
        ("declared duration_seconds",
         budget["arms"]["off"]["declared"]["duration_seconds"],
         budget["arms"]["on"]["declared"]["duration_seconds"]),
        ("search_seed", budget["arms"]["off"]["declared"]["search_seed"],
         budget["arms"]["on"]["declared"]["search_seed"]),
    ])
    lines.append("")
    lines.append(f"- case counts equal: `{budget.get('case_count_equal')}`")
    lines.append(f"- declared budget equal: `{budget.get('declared_budget_equal')}`")
    lines.append(f"- source identity equal: `{budget.get('source_identity_equal')}`")
    plan_fields = budget.get("run_plan_identity_fields") or {}
    lines.append("- run plan identity (not a comparability prerequisite): "
                 + ", ".join(
                     f"`{name}` off=`{_format(entry.get('off'))}` "
                     f"on=`{_format(entry.get('on'))}` equal=`{entry.get('equal')}`"
                     for name, entry in plan_fields.items()))
    lines.append(f"- effective_search_seconds ratio (on/off): "
                 f"`{_format(budget.get('effective_search_seconds_ratio_on_over_off'))}`")
    lines.append("")
    lines.append("### Shared raw-input prefix")
    lines.append("")
    lines.append(f"- length: `{prefix.get('length')}` "
                 f"(off cases `{prefix.get('off_cases')}`, on cases "
                 f"`{prefix.get('on_cases')}`)")
    lines.append(f"- per-case pairing scope: `{prefix.get('per_case_pairing_scope')}`")
    lines.append(f"- covers off arm: `{(prefix.get('covered_by_prefix') or {}).get('off')}`, "
                 f"covers on arm: `{(prefix.get('covered_by_prefix') or {}).get('on')}`")
    first = prefix.get("first_divergent_case")
    lines.append(f"- first divergent case index: "
                 f"`{prefix.get('first_divergent_case_index')}`: `{_format(first)}`")
    if prefix.get("reason"):
        lines.append(f"- reason: {prefix['reason']}")
    lines.append("")
    coverage = pair.get("coverage") or {}
    layout = coverage.get("layout") or {}
    lines.append("### Coverage (per-target hit counts from coverage_hex)")
    lines.append("")
    lines.append(f"- counter order rule: {layout.get('counter_order_rule')}")
    lines.append(f"- counter bytes per case: `{layout.get('counter_bytes_per_case')}`; "
                 f"hex characters per case: "
                 f"`{(layout.get('hex_characters_per_case') or {}).get('values')}`")
    lines.append(f"- counter order confirmed: `{layout.get('counter_order_confirmed')}`"
                 + (f" ({layout['reason']})" if layout.get("reason") else ""))
    lines.append(f"- declared targets: `{layout.get('declared_target_ids')}`")
    lines.append("")
    for arm_label in ("off", "on"):
        arm = coverage["arms"][arm_label]
        lines.append(f"#### {arm_label} arm targets")
        lines.append("")
        if arm.get("per_target_hit_counts"):
            _table(lines, ("counter", "target_id", "hit cases", "first hit",
                           "observed counter values"),
                   [(entry["counter_index"], entry["target_id"], entry["hit_cases"],
                     entry["first_hit_case_index"], entry["observed_values"])
                    for entry in arm["per_target_hit_counts"]])
        else:
            lines.append(f"- null: {arm.get('reason')}")
        lines.append("")
        lines.append(f"- targets hit at least once "
                     f"(`{arm.get('targets_hit_at_least_once_scope')}`): "
                     f"`{arm.get('targets_hit_at_least_once')}`")
        lines.append(f"- first_seen_target_bits: `{arm.get('first_seen_target_bits')}`")
        lines.append(f"- first_seen_target_slots: `{arm.get('first_seen_target_slots')}`")
        lines.append(f"- new_target_bits_per_second: "
                     f"`{_format(arm.get('new_target_bits_per_second'))}`"
                     + (f" ({arm['rate_reason']})" if arm.get("rate_reason") else ""))
        lines.append("")
    paired = coverage.get("paired_within_prefix") or {}
    lines.append("#### Per-case field agreement inside the shared prefix")
    lines.append("")
    _table(lines, ("field", "equal", "different", "different case indexes"),
           [(f"`{name}`", entry["equal"], entry["different"],
             entry["different_case_indexes"])
            for name, entry in (paired.get("fields") or {}).items()])
    lines.append("")
    chains = pair.get("chains") or {}
    lines.append("### Chain certificates (shipped analysis)")
    lines.append("")
    _table(lines, ("quantity", "off arm", "on arm"), [
        ("certified_total", chains["arms"]["off"]["certified_total"],
         chains["arms"]["on"]["certified_total"]),
        ("incomplete_total", chains["arms"]["off"]["incomplete_total"],
         chains["arms"]["on"]["incomplete_total"]),
        ("by_direction", chains["arms"]["off"]["by_direction"],
         chains["arms"]["on"]["by_direction"]),
        ("same_case", chains["arms"]["off"]["same_case"],
         chains["arms"]["on"]["same_case"]),
        ("cross_case", chains["arms"]["off"]["cross_case"],
         chains["arms"]["on"]["cross_case"]),
        ("certified_per_second", chains["arms"]["off"]["certified_per_second"],
         chains["arms"]["on"]["certified_per_second"]),
        ("certified_admissions / admissions_total",
         f"{chains['arms']['off']['certified_admissions']} / "
         f"{chains['arms']['off']['admissions_total']}",
         f"{chains['arms']['on']['certified_admissions']} / "
         f"{chains['arms']['on']['admissions_total']}"),
        ("first_missing_hop_counts",
         chains["arms"]["off"]["first_missing_hop_counts"],
         chains["arms"]["on"]["first_missing_hop_counts"]),
    ])
    lines.append("")
    for arm_label in ("off", "on"):
        reason = chains["arms"][arm_label].get("reason")
        if reason:
            lines.append(f"- {arm_label} chain reason: {reason}")
    lines.append("")
    edges = pair.get("witnessed_edges") or {}
    lines.append("### Witnessed edges (runtime_edge_provenance)")
    lines.append("")
    _table(lines, ("quantity", "off arm", "on arm"), [
        ("unique_edges", edges["arms"]["off"]["unique_edges"],
         edges["arms"]["on"]["unique_edges"]),
        ("new_edges_per_second", edges["arms"]["off"]["new_edges_per_second"],
         edges["arms"]["on"]["new_edges_per_second"]),
        ("candidate_observations",
         edges["arms"]["off"]["candidate_observations"],
         edges["arms"]["on"]["candidate_observations"]),
        ("events_without_provenance",
         edges["arms"]["off"]["events_without_provenance"],
         edges["arms"]["on"]["events_without_provenance"]),
    ])
    lines.append("")
    for arm_label in ("off", "on"):
        arm = edges["arms"][arm_label]
        if arm.get("by_direction") is None:
            lines.append(f"- {arm_label} per-direction counts: null: "
                         f"{arm.get('by_direction_reason')}")
            continue
        lines.append(f"#### {arm_label} arm per-direction witness counts")
        lines.append("")
        _table(lines, ("direction", "path_id", "declared", "runtime",
                       "certified", "incomplete", "unknown", "non-runtime"),
               [(direction, entry["path_id"], entry["declared_edge_count"],
                 entry["runtime_edge_count"], entry["counts"]["certified"],
                 entry["counts"]["incomplete"], entry["counts"]["unknown"],
                 entry["non_runtime_edge_count"])
                for direction, entry in arm["by_direction"].items()])
        lines.append("")
        provenance = arm.get("provenance") or {}
        lines.append(f"- provenance counts: `{_format(provenance.get('counts'))}`, "
                     f"events_observed `{provenance.get('events_observed')}`, "
                     f"rejected `{provenance.get('events_rejected')}`, "
                     f"dropped_late_hops `{provenance.get('dropped_late_hops')}`")
        lines.append(f"- proof scope: `{_format(provenance.get('proof_scope'))}`")
        lines.append("")
    lines.append("### Not comparable")
    lines.append("")
    for item in pair.get("not_comparable") or ():
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Pair limits")
    lines.append("")
    if pair.get("limits"):
        _table(lines, ("arm", "quantity", "reason"),
               [(item.get("arm"), f"`{item['quantity']}`", item["reason"])
                for item in pair["limits"]])
    else:
        lines.append("- none")
    lines.append("")


__all__ = [
    "SCHEMA_VERSION",
    "CORE_ARTIFACTS",
    "METRIC_FAMILIES",
    "DEFAULT_REQUIRED_FAMILIES",
    "P4OperatorBenefitEvidenceError",
    "compare_arm_pair",
    "compare_pairs",
    "render_markdown",
    "roll_up_edge_directions",
]
