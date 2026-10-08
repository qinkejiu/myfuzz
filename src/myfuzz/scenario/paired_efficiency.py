"""Paired first-step efficiency comparison: one continuous session vs cold starts.

``compare_runs`` reads two run directories that are supposed to describe the
same frozen source, seed and budget:

* a **continuous** directory produced by one initialised online session that
  executed several cases in a row, and
* a **cold** directory whose receipts were produced by restarting the runtime
  (or the whole harness) for every single case.

Every artifact is streamed: receipts are parsed one JSON object per line and
never retained as rows, so the memory ceiling does not grow with the number of
cases. Quantities the artifacts cannot prove are reported as ``null`` with an
explicit reason in ``limits``; they are never reported as ``0``, and a field
that is absent or ``null`` on either side counts as *missing evidence*, never as
an equality.

Reuse, deliberately:

* both groups are summarised by :func:`myfuzz.scenario.acceptance_metrics.
  analyze_run` (single-pass streaming analysis, chain certificate accounting
  through the injected producer protocol, percentile phase timing);
* the percentile rule itself is imported from ``acceptance_metrics`` as
  ``_percentiles`` so the paired report and the per-run acceptance report can
  never disagree on what ``p50`` means;
* the cold group's *initialization* cost is **not** re-measured here. It is read
  from ``cold_start.json``, the ``ibex_pulp_cold_baseline.v1`` document written
  by ``scripts/bench_ibex_pulp_cold_start.py`` (``measure_cold_cases``). That
  script owns cold-start measurement and timing; this module only consumes its
  per-case ``init_seconds`` / ``total_seconds`` / ``raw_hex`` fields, so no
  measurement code is duplicated. ``COLD_BASELINE_SCHEMA_VERSION`` pins the
  consumed schema.

Two different verdicts are kept apart on purpose:

* ``comparison_validity.comparable`` states whether the pair is a *controlled*
  comparison at all (same source identity, seed, budget, input sequence, path
  and checker outcome). A false or unverified prerequisite makes the pair
  non-comparable.
* ``comparison_validity.output_equivalence.claimed`` states whether the compared
  per-case outputs (status, genome, raw, path, sources, violations, coverage,
  local ticks) actually matched. It is only ever true when ``comparable`` is
  true and every compared field matched with real evidence on both sides.

Coverage/state differences between the groups do not by themselves invalidate
the comparison (they are the observation), but they do forbid claiming output
equivalence. Both facts are reported separately, and the non-extrapolable
boundaries (different pre-case component state, different total-cost
boundaries, ``continuous first-N minus cold init`` not being a saving estimate)
are enumerated in ``comparison_validity.boundaries``.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import hashlib
import json
import math
from itertools import zip_longest
from pathlib import Path

from myfuzz.scenario.acceptance_metrics import (
    DEFAULT_INGEST_BATCH_SIZE,
    DEFAULT_MAX_CERTIFICATES,
    _percentiles,
    analyze_run,
)


SCHEMA_VERSION = "paired_efficiency_report.v1"
DEFAULT_MAX_ITEMS = 200_000
DEFAULT_MAX_CASE_DETAILS = 200
MAX_DETAIL_INDEXES = 20
MAX_DETAIL_VALUE_CHARS = 4096

RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"
IDENTITY_NAME = "online_run_identity.json"
COLD_BASELINE_NAME = "cold_start.json"
COLD_BASELINE_SCHEMA_VERSION = "ibex_pulp_cold_baseline.v1"

TOTAL_TIMING_FIELD = "online_phase_timing_seconds"
TOTAL_TIMING_KEY = "total"
RECEIPT_TOTAL_SOURCE = f"{RECEIPTS_NAME}:{TOTAL_TIMING_FIELD}.{TOTAL_TIMING_KEY}"
# Key emitted by scripts/bench_ibex_pulp_cold_start.py:measure_cold_cases.
COLD_DOCUMENT_TOTAL_SOURCE = f"{COLD_BASELINE_NAME}:cases[].total_seconds"
COLD_INIT_SOURCE = f"{COLD_BASELINE_NAME}:cases[].init_seconds"
COLD_RAW_SOURCE = f"{COLD_BASELINE_NAME}:cases[].raw_hex"

PER_CASE_FIELDS = ("status", "effective_genome_sha256", "raw_identity", "path_id",
                   "applied_sources", "violations", "coverage_hex", "local_ticks")
RAW_FIELD_PREFERENCE = ("raw_sha256", "online_raw_records_hex")
TICKS_FIELD_PREFERENCE = ("local_ticks", "total_local_ticks")
SOURCE_IDENTITY_FIELDS = ("source_files_sha256", "component_identity_sha256",
                          "decoder_manifest_sha256", "genome_plan_sha256",
                          "targets_sha256")
SEED_FIELDS = ("search_seed", "global_mutation_seed")
BUDGET_FIELDS = ("max_tests", "duration_seconds", "feedback_interval")

_MISSING = object()


class PairedEfficiencyInputError(ValueError):
    """Raised when the two run directories cannot be aligned at all."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _read_json_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PairedEfficiencyInputError(
            f"invalid JSON in {path}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise PairedEfficiencyInputError(f"{path} is not a JSON object")
    return document


def _finite_non_negative(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        number = float(value)
        if math.isfinite(number) and number >= 0:
            return number
    return None


def _int_or_none(value: object) -> int | None:
    return value if type(value) is int else None


def _sha256_of(value: object) -> str | None:
    try:
        return hashlib.sha256(_canonical(value)).hexdigest()
    except (TypeError, ValueError):
        return None


def _bounded_value(value: object) -> tuple[object, bool]:
    """Return a JSON-safe value plus whether it had to be truncated."""
    try:
        encoded = _canonical(value)
    except (TypeError, ValueError):
        return {"unencodable": True}, True
    if len(encoded) <= MAX_DETAIL_VALUE_CHARS:
        return value, False
    return {"truncated": True, "canonical_prefix":
            encoded[:MAX_DETAIL_VALUE_CHARS].decode("utf-8", "replace")}, True


def _iter_receipts(path: Path) -> Iterator[dict]:
    """Yield one receipt object per line; never retain the row."""
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PairedEfficiencyInputError(
                    f"invalid JSON on line {number} of {path}: {exc.msg}") from exc
            if type(row) is not dict:
                raise PairedEfficiencyInputError(
                    f"non-object JSON value on line {number} of {path}")
            yield row


def _present(row: Mapping, name: str):
    value = row.get(name, _MISSING)
    return value if value is not None else _MISSING


def _verdict(left: object, right: object) -> str:
    """``equal`` / ``mismatch`` / ``missing``; absence is never equality."""
    if left is _MISSING or right is _MISSING:
        return "missing"
    return "equal" if _canonical(left) == _canonical(right) else "mismatch"


def _resolve_pair_field(left: Mapping, right: Mapping,
                        preferences: tuple[str, ...]) -> str | None:
    for name in preferences:
        if _present(left, name) is not _MISSING and _present(right, name) is not _MISSING:
            return name
    return None


def _pair_value(row: Mapping, name: str, raw_field: str | None,
                ticks_field: str | None):
    if name == "raw_identity":
        return _MISSING if raw_field is None else _present(row, raw_field)
    if name == "local_ticks":
        return _MISSING if ticks_field is None else _present(row, ticks_field)
    return _present(row, name)


class _Tally:
    """Per-comparison-field counters with a bounded mismatch index list."""

    __slots__ = ("field", "equal", "mismatch", "missing", "mismatch_indexes",
                 "missing_indexes", "indexes_truncated")

    def __init__(self, field: str | None = None) -> None:
        self.field = field
        self.equal = 0
        self.mismatch = 0
        self.missing = 0
        self.mismatch_indexes: list[int] = []
        self.missing_indexes: list[int] = []
        self.indexes_truncated = False

    def add(self, index: int, verdict: str) -> None:
        if verdict == "equal":
            self.equal += 1
            return
        if verdict == "mismatch":
            self.mismatch += 1
            if len(self.mismatch_indexes) < MAX_DETAIL_INDEXES:
                self.mismatch_indexes.append(index)
            else:
                self.indexes_truncated = True
            return
        self.missing += 1
        if len(self.missing_indexes) < MAX_DETAIL_INDEXES:
            self.missing_indexes.append(index)
        else:
            self.indexes_truncated = True

    def as_dict(self) -> dict:
        return {
            "field": self.field,
            "equal": self.equal,
            "mismatch": self.mismatch,
            "missing": self.missing,
            "mismatch_case_indexes": list(self.mismatch_indexes),
            "missing_case_indexes": list(self.missing_indexes),
            "case_indexes_truncated": self.indexes_truncated,
        }


# --------------------------------------------------------------------------
# the single streaming alignment pass
# --------------------------------------------------------------------------


def _align_receipts(continuous_path: Path, cold_path: Path, *, max_items: int,
                    max_case_details: int) -> dict:
    """Stream both receipt files in lockstep and keep aggregates only."""
    # ``field`` records which receipt key was actually compared; the two resolved
    # entries stay null until the first compared pair selects their key.
    tallies = {name: _Tally(None if name in ("raw_identity", "local_ticks") else name)
               for name in PER_CASE_FIELDS}
    transitions: dict[str, int] = {}
    details: list[dict] = []
    totals = {"continuous": [], "cold": []}
    cold_receipt_total_missing = 0
    cold_raw: list[object] = []
    compared = 0
    left_rows = 0
    right_rows = 0
    truncated = False
    raw_field = None
    ticks_field = None
    alignment_key = "receipt_ordinal"
    case_index_mismatch = 0
    case_index_missing = 0
    case_index_mismatch_indexes: list[int] = []

    paired = zip_longest(_iter_receipts(continuous_path), _iter_receipts(cold_path),
                         fillvalue=_MISSING)
    for left, right in paired:
        if left is not _MISSING:
            left_rows += 1
        if right is not _MISSING:
            right_rows += 1
        if left is _MISSING or right is _MISSING:
            continue
        if compared >= max_items:
            truncated = True
            continue
        if compared == 0:
            raw_field = _resolve_pair_field(left, right, RAW_FIELD_PREFERENCE)
            ticks_field = _resolve_pair_field(left, right, TICKS_FIELD_PREFERENCE)
            tallies["raw_identity"].field = raw_field
            tallies["local_ticks"].field = ticks_field
            if (_int_or_none(left.get("case_index")) is not None
                    and _int_or_none(right.get("case_index")) is not None):
                alignment_key = "case_index"

        verdicts = {}
        for name in PER_CASE_FIELDS:
            verdict = _verdict(_pair_value(left, name, raw_field, ticks_field),
                               _pair_value(right, name, raw_field, ticks_field))
            tallies[name].add(compared, verdict)
            verdicts[name] = verdict
        if verdicts["status"] == "mismatch":
            key = f"{left.get('status')}->{right.get('status')}"
            transitions[key] = transitions.get(key, 0) + 1
        if alignment_key == "case_index":
            left_index = _int_or_none(left.get("case_index"))
            right_index = _int_or_none(right.get("case_index"))
            if left_index is None or right_index is None:
                case_index_missing += 1
            elif left_index != right_index:
                case_index_mismatch += 1
                if len(case_index_mismatch_indexes) < MAX_DETAIL_INDEXES:
                    case_index_mismatch_indexes.append(compared)

        continuous_total = _receipt_total(left)
        if continuous_total is not None:
            totals["continuous"].append(continuous_total)
        cold_total = _receipt_total(right)
        if cold_total is not None:
            totals["cold"].append(cold_total)
        else:
            cold_receipt_total_missing += 1
        if len(cold_raw) < max_case_details:
            # Raw *input* records, so cold_start.json's raw_hex can be checked
            # against the receipts independently of the compared identity field.
            cold_raw.append(_jsonable(_present(right, "online_raw_records_hex")))
        if len(details) < max_case_details:
            details.append(_case_detail(compared, left, right, verdicts,
                                        raw_field, ticks_field))
        compared += 1

    if left_rows != right_rows:
        raise PairedEfficiencyInputError(
            f"receipt counts differ: continuous={left_rows} cold={right_rows}; "
            "per-case alignment is undefined")
    if left_rows == 0:
        raise PairedEfficiencyInputError(
            "both receipt streams are empty; no case can be compared")
    return {
        "tallies": tallies,
        "transitions": transitions,
        "details": details,
        "totals": {name: list(values) for name, values in totals.items()},
        "cold_receipt_total_missing": cold_receipt_total_missing,
        "cold_raw_records": cold_raw,
        "compared": compared,
        "rows": {"continuous": left_rows, "cold": right_rows},
        "truncated": truncated,
        "raw_field": raw_field,
        "ticks_field": ticks_field,
        "alignment": {
            "key": alignment_key,
            "case_index_mismatch_count": case_index_mismatch,
            "case_index_missing_count": case_index_missing,
            "case_index_mismatch_case_indexes": case_index_mismatch_indexes,
        },
    }


def _receipt_total(row: Mapping) -> float | None:
    timing = row.get(TOTAL_TIMING_FIELD)
    if not isinstance(timing, Mapping):
        return None
    return _finite_non_negative(timing.get(TOTAL_TIMING_KEY))


def _case_detail(index: int, left: Mapping, right: Mapping, verdicts: Mapping,
                 raw_field: str | None, ticks_field: str | None) -> dict:
    entry: dict = {"case_index": index, "receipt_ordinal": index,
                   "equal_fields": sorted(name for name, verdict in verdicts.items()
                                          if verdict == "equal")}
    truncated_values = False
    for name in PER_CASE_FIELDS:
        left_value, left_cut = _bounded_value(
            _jsonable(_pair_value(left, name, raw_field, ticks_field)))
        right_value, right_cut = _bounded_value(
            _jsonable(_pair_value(right, name, raw_field, ticks_field)))
        truncated_values = truncated_values or left_cut or right_cut
        verdict = verdicts[name]
        entry[name] = {
            "continuous": left_value,
            "cold": right_value,
            "verdict": verdict,
            "equal": verdict == "equal",
        }
    entry["values_truncated"] = truncated_values
    return entry


def _jsonable(value: object) -> object:
    return None if value is _MISSING else value


# --------------------------------------------------------------------------
# identity / prerequisite evidence
# --------------------------------------------------------------------------


def _identity_fields(directory: Path) -> dict:
    identity_document = _read_json_object(directory / IDENTITY_NAME)
    report_document = _read_json_object(directory / REPORT_NAME)
    identity = identity_document.get("identity") if identity_document else None
    identity = identity if isinstance(identity, Mapping) else {}
    run_config = identity.get("run_config")
    run_config = run_config if isinstance(run_config, Mapping) else {}
    session = identity.get("session")
    session = session if isinstance(session, Mapping) else {}
    components = identity.get("components")
    components = components if isinstance(components, Mapping) else {}
    genome = identity.get("genome")
    genome = genome if isinstance(genome, Mapping) else {}
    feedback = identity.get("feedback")
    feedback = feedback if isinstance(feedback, Mapping) else {}
    toolchain = identity.get("toolchain")
    toolchain = toolchain if isinstance(toolchain, Mapping) else {}
    client = toolchain.get("client")
    client = client if isinstance(client, Mapping) else {}
    report = report_document or {}

    source_files = identity.get("source_files")
    source_digest = None
    if isinstance(source_files, list) and source_files and all(
            isinstance(entry, Mapping)
            and isinstance(entry.get("path"), str)
            and isinstance(entry.get("sha256"), str)
            for entry in source_files):
        source_digest = _sha256_of(sorted(
            (entry["path"], entry["sha256"]) for entry in source_files))

    requirement = identity.get("requirement")
    return {
        "run_id": run_config.get("run_id"),
        "source_files_sha256": source_digest,
        "component_identity_sha256": (session.get("component_identity_sha256")
                                      or components.get("identity_sha256")),
        "decoder_manifest_sha256": report.get("decoder_manifest_sha256"),
        "genome_plan_sha256": genome.get("plan_sha256"),
        "targets_sha256": feedback.get("targets_sha256"),
        "client_binary_sha256": client.get("binary_sha256"),
        "search_seed": run_config.get("search_seed"),
        "global_mutation_seed": report.get("global_mutation_seed"),
        "max_tests": run_config.get("max_tests"),
        "duration_seconds": _finite_non_negative(run_config.get("duration_seconds")),
        "feedback_interval": run_config.get("feedback_interval"),
        "execution_mode": identity.get("execution_mode") or report.get("execution_mode"),
        "identity_document_present": identity_document is not None,
        "report_document_present": report_document is not None,
        "requirement_present": requirement is not None,
    }


def _aggregate_identity_pairs(pairs: Mapping[str, tuple]) -> tuple[bool | None, dict]:
    compared = {}
    missing = []
    mismatch = []
    for name, (left, right) in pairs.items():
        if left is None or right is None:
            missing.append(name)
            continue
        compared[name] = {"continuous": left, "cold": right, "equal": left == right}
        if left != right:
            mismatch.append(name)
    if mismatch:
        satisfied = False
    elif compared:
        satisfied = True
    else:
        satisfied = None
    return satisfied, {"compared_fields": compared, "missing_fields": sorted(missing),
                       "mismatch_fields": sorted(mismatch)}


def _tally_prerequisite(name: str, tally: _Tally, *, compared: int) -> dict:
    if tally.mismatch:
        satisfied = False
        reason = f"{tally.mismatch} of {compared} compared cases disagree on {name}"
    elif tally.missing:
        satisfied = None
        reason = (f"{tally.missing} of {compared} compared cases have no "
                  f"{name} evidence on both sides, so agreement is unverified")
    else:
        satisfied = compared > 0
        reason = None
    evidence = tally.as_dict()
    evidence["cases_compared"] = compared
    return {"name": name, "satisfied": satisfied, "evidence": evidence,
            "reason": reason}


def _prerequisite(name: str, satisfied: bool | None, evidence: dict,
                  reason: str | None = None) -> dict:
    return {"name": name, "satisfied": satisfied, "evidence": evidence,
            "reason": reason}


def _comparison_validity(alignment: Mapping, tallies: Mapping, *,
                         compared: int, continuous_identity: Mapping,
                         cold_identity: Mapping) -> dict:
    pairs = {
        "source": {name: (continuous_identity.get(name), cold_identity.get(name))
                   for name in SOURCE_IDENTITY_FIELDS},
        "seed": {name: (continuous_identity.get(name), cold_identity.get(name))
                 for name in SEED_FIELDS},
        "budget": {name: (continuous_identity.get(name), cold_identity.get(name))
                   for name in BUDGET_FIELDS},
    }
    source_satisfied, source_evidence = _aggregate_identity_pairs(pairs["source"])
    seed_satisfied, seed_evidence = _aggregate_identity_pairs(pairs["seed"])
    budget_satisfied, budget_evidence = _aggregate_identity_pairs(pairs["budget"])

    raw_tally = tallies["raw_identity"]
    key = alignment["key"]
    case_index_aligned = (key == "case_index"
                          and alignment["case_index_mismatch_count"] == 0
                          and alignment["case_index_missing_count"] == 0)
    raw_aligned = compared > 0 and raw_tally.equal == compared
    if alignment["case_index_mismatch_count"]:
        # Conflicting alignment labels are a definite contradiction, even when the
        # raw inputs happen to line up ordinally.
        alignment_satisfied = False
        alignment_reason = ("the two groups declare different case_index values for "
                            "the same receipt ordinal, so the alignment labels "
                            "contradict each other")
    elif case_index_aligned or raw_aligned:
        alignment_satisfied = True
        alignment_reason = None
    elif raw_tally.mismatch:
        alignment_satisfied = False
        alignment_reason = ("the two groups did not execute the same input sequence "
                            "in the same order")
    else:
        alignment_satisfied = None
        alignment_reason = ("neither integer case_index nor raw input identity is "
                            "available on both sides for every compared case")
    alignment_evidence = {
        "alignment_key": key,
        "case_index_mismatch_count": alignment["case_index_mismatch_count"],
        "case_index_missing_count": alignment["case_index_missing_count"],
        "case_index_mismatch_case_indexes":
            alignment["case_index_mismatch_case_indexes"],
        "raw_identity_field": raw_tally.field,
        "raw_identity_equal_cases": raw_tally.equal,
        "raw_identity_mismatch_cases": raw_tally.mismatch,
        "cases_compared": compared,
    }

    prerequisites = [
        # Equal receipt counts are enforced by compare_runs before this point, so
        # this prerequisite records the enforced fact rather than re-testing it.
        _prerequisite("equal_case_count", True,
                      {"cases_compared": compared,
                       "continuous_receipt_rows": alignment.get("continuous_rows"),
                       "cold_receipt_rows": alignment.get("cold_rows")},
                      "enforced before comparison: unequal receipt counts raise"),
        _prerequisite("source_identity_equal", source_satisfied, source_evidence,
                      None if source_satisfied else
                      "source identity fields are missing or disagree, so the two "
                      "groups are not proven to run the same frozen source"),
        _prerequisite("seed_equal", seed_satisfied, seed_evidence,
                      None if seed_satisfied else
                      "the declared search seed is missing or differs between the "
                      "two groups"),
        _prerequisite("budget_equal", budget_satisfied, budget_evidence,
                      None if budget_satisfied else
                      "the declared case/duration budget is missing or differs "
                      "between the two groups"),
        _prerequisite("input_sequence_alignment", alignment_satisfied,
                      alignment_evidence, alignment_reason),
        _tally_prerequisite("raw_identity_agreement", raw_tally, compared=compared),
        _tally_prerequisite("genome_agreement", tallies["effective_genome_sha256"],
                            compared=compared),
        _tally_prerequisite("path_agreement", tallies["path_id"], compared=compared),
        _tally_prerequisite("assertion_agreement", tallies["violations"],
                            compared=compared),
    ]
    failed = [item["name"] for item in prerequisites if item["satisfied"] is False]
    unverified = [item["name"] for item in prerequisites if item["satisfied"] is None]
    comparable = not failed and not unverified

    fields_fully_equal = [name for name in PER_CASE_FIELDS
                          if tallies[name].equal == compared and compared > 0]
    mismatches = {name: tallies[name].mismatch for name in PER_CASE_FIELDS
                  if tallies[name].mismatch}
    missing = {name: tallies[name].missing for name in PER_CASE_FIELDS
               if tallies[name].missing}
    equivalence_claimed = bool(comparable and not mismatches and not missing
                               and len(fields_fully_equal) == len(PER_CASE_FIELDS))
    return {
        "definition": (
            "comparable means the pair is a controlled comparison: equal receipt "
            "counts, equal declared source identity, seed and budget, and the same "
            "input sequence in the same order, with raw identity, genome, path and "
            "checker violations verifiably equal per case. Coverage and local-tick "
            "differences do not by themselves break comparability; they only forbid "
            "claiming output equivalence."),
        "comparable": comparable,
        "status": "comparable" if comparable else "not_comparable",
        "prerequisites": prerequisites,
        "failed_prerequisites": failed,
        "unverified_prerequisites": unverified,
        "output_equivalence": {
            "claimed": equivalence_claimed,
            "scope": ("per-case compared fields over the compared window; not a DUT "
                      "equivalence, coverage-equivalence or timing-equivalence proof"),
            "fields_fully_equal": fields_fully_equal,
            "fields_with_mismatch": mismatches,
            "fields_with_missing_evidence": missing,
        },
    }


# --------------------------------------------------------------------------
# group summaries
# --------------------------------------------------------------------------


def _group_summary(label: str, analysis: Mapping, *, case_count: int,
                   cases_compared: int, truncated: bool, total_samples: list,
                   total_source: str | None, total_reason: str | None,
                   receipt_rows: int) -> dict:
    effective = analysis.get("effective_search_seconds")
    elapsed = analysis.get("elapsed_seconds")
    denominator_name = None
    denominator = None
    if effective is not None:
        denominator_name, denominator = "effective_search_seconds", effective
    elif elapsed is not None:
        denominator_name, denominator = "elapsed_seconds", elapsed
    cases_per_second = None
    cases_per_second_reason = None
    if denominator:
        cases_per_second = case_count / denominator
    else:
        cases_per_second_reason = (
            "report.json provides neither effective_search_seconds nor "
            "elapsed_seconds, so no per-second rate can be computed")
    chains = analysis.get("certified_chains") or {}
    targets = analysis.get("local_target_novelty") or {}
    edges = analysis.get("witnessed_edge_novelty") or {}
    replay = analysis.get("replay")
    percentiles = _percentiles(total_samples, (0.5, 0.95))
    return {
        "group": label,
        "run_dir": analysis.get("run_dir"),
        "run_id": analysis.get("run_id"),
        "case_count": case_count,
        "cases_compared": cases_compared,
        "receipt_rows_in_analysis": receipt_rows,
        "analysis_truncated_to_max_items": truncated,
        "effective_search_seconds": effective,
        "elapsed_seconds": elapsed,
        "cases_per_second": cases_per_second,
        "cases_per_second_boundary": denominator_name,
        "cases_per_second_reason": cases_per_second_reason,
        "complete_cases_per_second": analysis.get("complete_cases_per_second"),
        "complete_cases_per_second_reason": analysis.get(
            "complete_cases_per_second_reason"),
        "test_counts": analysis.get("test_counts"),
        "invalid_or_timeout_ratio": analysis.get("invalid_or_timeout_ratio"),
        "invalid_or_timeout_ratio_reason": analysis.get(
            "invalid_or_timeout_ratio_reason"),
        "per_case_total_seconds": {
            "count": len(total_samples),
            "p50": percentiles["p50"],
            "p95": percentiles["p95"],
            "source": total_source,
            "reason": total_reason,
        },
        "certified_chains": {
            "total": chains.get("total"),
            "by_direction": chains.get("by_direction"),
            "same_case": chains.get("same_case"),
            "cross_case": chains.get("cross_case"),
            "incomplete_total": chains.get("incomplete_total"),
            "cap_reached": chains.get("cap_reached"),
        },
        "certified_chains_reason": analysis.get("certified_chains_reason"),
        "certified_chains_semantics": analysis.get("certified_chains_semantics"),
        "chain_completion_by_admission": analysis.get("chain_completion_by_admission"),
        "certified_chains_per_second": analysis.get("certified_chains_per_second"),
        "certified_chains_per_second_reason": analysis.get(
            "certified_chains_per_second_reason"),
        "chain_producer_available": (analysis.get("chain_producer") or {}).get("available"),
        "coverage_novelty": {
            "first_seen_target_bits": targets.get("first_seen_target_bits"),
            "new_target_bits_per_second": targets.get("new_target_bits_per_second"),
            "reason": targets.get("reason"),
        },
        "witnessed_edge_novelty": {
            "unique_edges": edges.get("unique_edges"),
            "new_edges_per_second": edges.get("new_edges_per_second"),
            "reason": edges.get("reason"),
        },
        "finalization_timing_seconds": analysis.get("finalization_timing_seconds"),
        "replay_verified": (replay or {}).get("verified") if replay else None,
        "replay_analyzed": replay is not None,
        "trace_evidence": analysis.get("trace_evidence"),
        "analysis_schema_version": analysis.get("schema_version"),
        "analysis_limits": analysis.get("limits"),
    }


# --------------------------------------------------------------------------
# initialization cost (cold_start.json produced by the cold-start script)
# --------------------------------------------------------------------------


def load_cold_baseline(run_dir: str | Path) -> dict | None:
    """Load ``cold_start.json`` (``ibex_pulp_cold_baseline.v1``) if present.

    The document is written by
    ``scripts/bench_ibex_pulp_cold_start.py``; this loader keeps the producer as
    the single owner of cold-start measurement and only exposes its per-case
    fields. A document with an unexpected schema raises
    :class:`PairedEfficiencyInputError` instead of being silently ignored.
    """
    document = _read_json_object(Path(run_dir) / COLD_BASELINE_NAME)
    if document is None:
        return None
    version = document.get("schema_version")
    if version != COLD_BASELINE_SCHEMA_VERSION:
        raise PairedEfficiencyInputError(
            f"{COLD_BASELINE_NAME} declares schema_version {version!r}, expected "
            f"{COLD_BASELINE_SCHEMA_VERSION!r}")
    return document


def _cold_baseline_cases(document: Mapping | None) -> list | None:
    cases = document.get("cases") if document else None
    if not isinstance(cases, list):
        return None
    if not all(isinstance(entry, Mapping) for entry in cases):
        return None
    return cases


def _initialization_summary(document: Mapping | None, *, compared: int,
                            cold_analysis: Mapping,
                            cold_raw: list) -> tuple[dict, list]:
    limits: list[dict] = []
    cases = _cold_baseline_cases(document)
    init_source = None
    init_values: list[float] = []
    baseline_totals: list[float] = []
    baseline_total_complete = False
    raw_check = {"available": False, "compared": 0, "equal": 0,
                 "mismatch_case_indexes": [], "source": COLD_RAW_SOURCE,
                 "reason": None}
    baseline_reason = None
    if document is None:
        baseline_reason = (
            f"{COLD_BASELINE_NAME} is absent from the cold run directory, so the "
            "cold group's initialization cost was not measured by this comparison; "
            "scripts/bench_ibex_pulp_cold_start.py writes that document")
    elif cases is None:
        baseline_reason = (f"{COLD_BASELINE_NAME} has no cases list, so the cold "
                           "group's initialization cost is unknown")
    else:
        window = cases[:compared]
        if len(window) != compared:
            baseline_reason = (
                f"{COLD_BASELINE_NAME} holds {len(cases)} cases but {compared} were "
                "compared, so no initialization cost can be attributed to the "
                "compared window")
        for entry in window:
            init_values.append(_finite_non_negative(entry.get("init_seconds")))
        if len(window) == compared and all(value is not None for value in init_values):
            init_source = COLD_INIT_SOURCE
        else:
            init_values = []
            baseline_reason = (baseline_reason or
                               f"{COLD_BASELINE_NAME} cases lack finite "
                               "non-negative init_seconds for the compared window")
        if len(window) == compared:
            baseline_totals = [_finite_non_negative(entry.get("total_seconds"))
                               for entry in window]
            baseline_total_complete = all(value is not None for value in baseline_totals)
        # Independent input cross-check: the baseline's raw_hex per case must be
        # the cold receipt's raw input, otherwise the document belongs elsewhere.
        raw_hexes = [entry.get("raw_hex") for entry in window]
        if cold_raw and all(isinstance(value, str) for value in raw_hexes):
            raw_check["available"] = True
            raw_check["compared"] = len(window)
            for index, (raw_hex, receipt_raw) in enumerate(zip(raw_hexes, cold_raw)):
                if isinstance(receipt_raw, list) and len(receipt_raw) == 1:
                    observed = receipt_raw[0]
                elif isinstance(receipt_raw, str):
                    observed = receipt_raw
                else:
                    observed = None
                if observed != raw_hex:
                    raw_check["mismatch_case_indexes"].append(index)
                    if len(raw_check["mismatch_case_indexes"]) >= MAX_DETAIL_INDEXES:
                        break
            raw_check["equal"] = raw_check["compared"] - len(
                raw_check["mismatch_case_indexes"])
        else:
            raw_check["reason"] = (
                f"{COLD_BASELINE_NAME} raw_hex or the compared receipts' raw input "
                "identity is unavailable, so the baseline document is not proven to "
                "belong to the compared input sequence")

    if document is not None and baseline_reason is not None:
        limits.append({"group": "cold",
                       "quantity": "initialization.cold_init_seconds_total",
                       "reason": baseline_reason})
    if not raw_check["available"] and document is not None:
        limits.append({"group": "cold",
                       "quantity": "initialization.cold_baseline_input_alignment",
                       "reason": raw_check["reason"]})

    cold_elapsed = cold_analysis.get("elapsed_seconds")
    share = None
    share_reason = None
    if init_source is not None and cold_elapsed:
        share = sum(init_values) / cold_elapsed
    elif init_source is None:
        share_reason = baseline_reason
    else:
        share_reason = ("the cold group's elapsed_seconds is unavailable, so the "
                        "initialization share of its wall clock cannot be computed")
    if share_reason:
        limits.append({"group": "cold",
                       "quantity": "initialization.cold_init_share_of_elapsed",
                       "reason": share_reason})

    limits.append({
        "group": "continuous",
        "quantity": "initialization.continuous_init_seconds",
        "reason": ("the continuous session charges no initialization to any single "
                   "case: its one-time build/init is outside every per-case total and "
                   "is not recorded per case, so this quantity stays null rather than 0")})

    percentiles = _percentiles(init_values, (0.5, 0.95))
    summary = {
        "cold_baseline_document": COLD_BASELINE_NAME if document is not None else None,
        "cold_baseline_schema_version": (document.get("schema_version")
                                         if document is not None else None),
        "cold_baseline_case_count": len(cases) if cases is not None else None,
        "cold_baseline_covers_compared_window": bool(cases is not None
                                                     and len(cases) >= compared),
        "cold_cases_with_init_seconds": len(init_values) or None,
        "cold_init_seconds_source": init_source,
        "cold_init_seconds_total": sum(init_values) if init_values else None,
        "cold_init_seconds_p50": percentiles["p50"] if init_values else None,
        "cold_init_seconds_p95": percentiles["p95"] if init_values else None,
        "cold_init_share_of_elapsed": share,
        "cold_init_share_of_elapsed_reason": share_reason,
        "continuous_init_seconds": None,
        "continuous_init_seconds_reason":
            "not recorded per case by the continuous session; never reported as 0",
        "cold_baseline_total_seconds_available": baseline_total_complete,
        "cold_baseline_total_seconds_source":
            COLD_DOCUMENT_TOTAL_SOURCE if baseline_total_complete else None,
        "cold_baseline_input_alignment": raw_check,
        "reason": baseline_reason,
    }
    return summary, limits


# --------------------------------------------------------------------------
# paired deltas
# --------------------------------------------------------------------------


def _ratio(numerator: float | None, denominator: float | None, *,
           name: str, allowed: bool, blocked_reason: str | None,
           interpretation: str) -> dict:
    if not allowed:
        reason = blocked_reason
        value = None
    elif numerator is None or denominator is None or denominator == 0:
        reason = "at least one of the two quantities is null or the denominator is zero"
        value = None
    else:
        reason = None
        value = numerator / denominator
    return {"quantity": name, "value": value, "reason": reason,
            "interpretation": interpretation}


def _delta(left: float | None, right: float | None, *, name: str,
           interpretation: str) -> dict:
    if left is None or right is None:
        return {"quantity": name, "value": None,
                "reason": "at least one of the two quantities is null, so a "
                          "difference would be an unfounded claim",
                "interpretation": interpretation}
    return {"quantity": name, "value": right - left, "reason": None,
            "interpretation": interpretation}


# --------------------------------------------------------------------------
# boundaries
# --------------------------------------------------------------------------


def _empty_quantity_limits(groups: Mapping, initialization: Mapping,
                           paired: Mapping) -> list[dict]:
    """One limit entry for every null quantity the report exposes."""
    limits: list[dict] = []
    for label in ("continuous", "cold"):
        group = groups[label]
        totals = group["per_case_total_seconds"]
        entries = [
            (f"groups.{label}.cases_per_second", group["cases_per_second"],
             group["cases_per_second_reason"]),
            (f"groups.{label}.complete_cases_per_second",
             group["complete_cases_per_second"],
             group["complete_cases_per_second_reason"]),
            (f"groups.{label}.invalid_or_timeout_ratio",
             group["invalid_or_timeout_ratio"],
             group["invalid_or_timeout_ratio_reason"]),
            (f"groups.{label}.certified_chains.total",
             group["certified_chains"]["total"], group["certified_chains_reason"]),
            (f"groups.{label}.certified_chains_per_second",
             group["certified_chains_per_second"],
             group["certified_chains_per_second_reason"]),
            (f"groups.{label}.coverage_novelty.new_target_bits_per_second",
             group["coverage_novelty"]["new_target_bits_per_second"],
             group["coverage_novelty"]["reason"]),
            (f"groups.{label}.witnessed_edge_novelty.new_edges_per_second",
             group["witnessed_edge_novelty"]["new_edges_per_second"],
             group["witnessed_edge_novelty"]["reason"]),
            (f"groups.{label}.replay_verified", group["replay_verified"],
             None if group["replay_analyzed"] else
             "no replay directory was analyzed for this group, so fresh-replay "
             "verification is unknown for the whole group"),
        ]
        if totals["p50"] is None or totals["p95"] is None:
            if totals["count"] == 0:
                reason = totals["reason"] or "no per-case total sample is available"
            else:
                reason = ("a single per-case total sample yields p50 only; p95 needs "
                          "at least two samples")
            entries.append((f"groups.{label}.per_case_total_seconds", None, reason))
        for quantity, value, reason in entries:
            if value is None:
                limits.append({"group": label, "quantity": quantity,
                               "reason": reason or "value unavailable"})
    if initialization.get("cold_init_seconds_total") is None and not any(
            item["quantity"] == "initialization.cold_init_seconds_total"
            for item in limits):
        limits.append({"group": "cold",
                       "quantity": "initialization.cold_init_seconds_total",
                       "reason": initialization.get("reason")
                                 or "no cold initialization cost is available"})
    for entry in paired.values():
        if entry.get("value") is None:
            limits.append({"group": "paired", "quantity": entry["quantity"],
                           "reason": entry.get("reason")})
    return limits


def _boundaries(*, truncated: bool, max_items: int,
                continuous_boundary: str | None,
                cold_boundary: str | None, continuous_total_source: str | None,
                cold_total_source: str | None, cold_init_known: bool) -> list[str]:
    boundaries = [
        "The continuous group carries the preceding case's component state into the "
        "next case, while the cold group starts from a freshly initialised runtime "
        "per case. Equal per-case status/raw/path/coverage observations therefore do "
        "not prove that the two groups had identical pre-case hardware state.",
        "The two groups have different total-cost boundaries: a continuous per-case "
        "total excludes the one-time build/startup and the session finalisation, "
        "while a cold per-case total includes that case's runtime initialisation.",
        "The continuous group's first N per-case totals and the cold group's "
        "initialization seconds must not be subtracted from each other as a saving: "
        "the continuous initialisation is charged to no case at all, the cold "
        "initialisation repeats per case, and the two quantities have different "
        "denominators and different timing boundaries.",
        "Coverage figures come from receipts.jsonl coverage_hex; this report only "
        "tests per-case equality of that field and of local_ticks. It does not "
        "extrapolate a coverage-novelty rate difference between the groups.",
        "All rates are computed by acceptance_metrics.analyze_run from the group's "
        "own declared window; the denominators are named per group and are not "
        "interchangeable.",
    ]
    if truncated:
        boundaries.append(
            f"Only the first max_items={max_items} cases of each group were aligned; "
            "the totals and rates that follow describe the whole receipt stream while "
            "the per-case agreement describes the truncated window.")
    if continuous_boundary != cold_boundary:
        boundaries.append(
            f"cases_per_second uses a different denominator boundary per group "
            f"(continuous: {continuous_boundary}, cold: {cold_boundary}), so no "
            "rate ratio between them is reported.")
    if continuous_total_source != cold_total_source:
        boundaries.append(
            f"per-case total samples come from different artifacts per group "
            f"(continuous: {continuous_total_source}, cold: {cold_total_source}), "
            "so their percentiles are not like-for-like.")
    if not cold_init_known:
        boundaries.append(
            "No cold initialization cost is available, so no statement about the "
            "cost of per-case startup can be made from these artifacts.")
    return boundaries


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def compare_runs(continuous_dir: str | Path, cold_dir: str | Path, *,
                 chain_producer: object = None,
                 max_items: int = DEFAULT_MAX_ITEMS,
                 max_case_details: int = DEFAULT_MAX_CASE_DETAILS,
                 max_certificates: int = DEFAULT_MAX_CERTIFICATES,
                 max_pending: int = 128, max_event_gap: int = 4096,
                 require_native_receipts: bool = True,
                 ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                 continuous_replay_dir: str | Path | None = None,
                 cold_replay_dir: str | Path | None = None) -> dict:
    """Compare one continuous run directory with one per-case cold-start run.

    Both directories must carry ``receipts.jsonl``; unequal receipt counts, empty
    receipt streams and malformed artifacts raise
    :class:`PairedEfficiencyInputError`. ``chain_producer`` is forwarded to
    ``acceptance_metrics.analyze_run`` for both groups, so chain counts and
    chains/second are produced by the same frozen protocol.
    """
    if type(max_items) is not int or max_items < 1:
        raise ValueError("max_items must be a positive integer")
    if type(max_case_details) is not int or max_case_details < 1:
        raise ValueError("max_case_details must be a positive integer")
    continuous = Path(continuous_dir)
    cold = Path(cold_dir)
    for label, directory in (("continuous", continuous), ("cold", cold)):
        if not directory.is_dir():
            raise PairedEfficiencyInputError(
                f"{label} run directory does not exist: {directory}")
        if not (directory / RECEIPTS_NAME).is_file():
            raise PairedEfficiencyInputError(
                f"{label} run directory has no {RECEIPTS_NAME}: "
                f"{directory / RECEIPTS_NAME}")

    limits: list[dict] = []
    alignment = _align_receipts(continuous / RECEIPTS_NAME, cold / RECEIPTS_NAME,
                                max_items=max_items,
                                max_case_details=max_case_details)
    compared = alignment["compared"]
    tallies = alignment["tallies"]
    if alignment["truncated"]:
        limits.append({
            "group": "paired", "quantity": "per_case_agreement",
            "reason": f"only the first max_items={max_items} cases per group were "
                      "aligned; later cases were counted but not compared"})

    analyses = {}
    for label, directory, replay_dir in (
            ("continuous", continuous, continuous_replay_dir),
            ("cold", cold, cold_replay_dir)):
        try:
            analyses[label] = analyze_run(
                directory, chain_producer=chain_producer, replay_dir=replay_dir,
                max_certificates=max_certificates, max_pending=max_pending,
                max_event_gap=max_event_gap,
                require_native_receipts=require_native_receipts,
                ingest_batch_size=ingest_batch_size)
        except ValueError as exc:
            raise PairedEfficiencyInputError(
                f"{label} run directory cannot be analyzed: {exc}") from exc

    identities = {"continuous": _identity_fields(continuous),
                  "cold": _identity_fields(cold)}

    cold_baseline = load_cold_baseline(cold)
    initialization, init_limits = _initialization_summary(
        cold_baseline, compared=compared, cold_analysis=analyses["cold"],
        cold_raw=alignment["cold_raw_records"])
    limits.extend(init_limits)

    total_sources = {}
    total_reasons = {}
    total_samples = {}
    for label in ("continuous", "cold"):
        samples = alignment["totals"][label]
        source = RECEIPT_TOTAL_SOURCE if len(samples) == compared else None
        reason = None
        if source is None:
            missing = alignment["cold_receipt_total_missing"] if label == "cold" else (
                compared - len(samples))
            reason = (f"{missing} of {compared} compared cases carry no finite "
                      f"non-negative {TOTAL_TIMING_FIELD}.{TOTAL_TIMING_KEY}")
        total_sources[label] = source
        total_reasons[label] = reason
        total_samples[label] = samples
    if total_sources["cold"] is None and initialization[
            "cold_baseline_total_seconds_available"]:
        cases = _cold_baseline_cases(cold_baseline) or []
        fallback = [_finite_non_negative(entry.get("total_seconds"))
                    for entry in cases[:compared]]
        if len(fallback) == compared and all(value is not None for value in fallback):
            total_samples["cold"] = fallback
            total_sources["cold"] = COLD_DOCUMENT_TOTAL_SOURCE
            total_reasons["cold"] = None
            limits.append({
                "group": "cold", "quantity": "groups.cold.per_case_total_seconds",
                "reason": f"cold receipts lack {TOTAL_TIMING_FIELD}.{TOTAL_TIMING_KEY}"
                          f"; falling back to {COLD_DOCUMENT_TOTAL_SOURCE} from "
                          f"{COLD_BASELINE_NAME}, a different timing boundary than the "
                          "continuous group's receipts"})
    if alignment["raw_field"] is None:
        limits.append({
            "group": "paired", "quantity": "per_case_agreement.raw_identity",
            "reason": "neither raw_sha256 nor online_raw_records_hex is present "
                      "on both sides, so raw input identity is unverified"})

    groups = {}
    for label in ("continuous", "cold"):
        analysis = analyses[label]
        row_count = alignment["rows"][label]
        analysis_rows = analysis.get("test_counts_total")
        if analysis_rows is not None and analysis_rows != row_count:
            limits.append({
                "group": label, "quantity": "groups.%s.case_count" % label,
                "reason": f"the alignment pass counted {row_count} receipt rows but "
                          f"the acceptance pass counted {analysis_rows}; the artifact "
                          "changed between passes or one pass is wrong"})
        groups[label] = _group_summary(
            label, analysis, case_count=row_count, cases_compared=compared,
            truncated=alignment["truncated"], total_samples=total_samples[label],
            total_source=total_sources[label], total_reason=total_reasons[label],
            receipt_rows=analysis_rows if analysis_rows is not None else row_count)

    validity = _comparison_validity(
        {**alignment["alignment"], "continuous_rows": alignment["rows"]["continuous"],
         "cold_rows": alignment["rows"]["cold"]},
        tallies, compared=compared,
        continuous_identity=identities["continuous"],
        cold_identity=identities["cold"])
    for item in validity["prerequisites"]:
        if item["satisfied"] is None:
            limits.append({"group": "paired",
                           "quantity": f"comparison_validity.{item['name']}",
                           "reason": item["reason"]})
        elif item["satisfied"] is False:
            limits.append({"group": "paired",
                           "quantity": f"comparison_validity.{item['name']}",
                           "reason": item["reason"] or "precondition not satisfied"})
    if not validity["output_equivalence"]["claimed"]:
        limits.append({
            "group": "paired",
            "quantity": "comparison_validity.output_equivalence.claimed",
            "reason": "per-case outputs are not verifiably equal for every compared "
                      "field, so no equivalence is claimed"})

    continuous_boundary = groups["continuous"]["cases_per_second_boundary"]
    cold_boundary = groups["cold"]["cases_per_second_boundary"]
    same_boundary = (continuous_boundary is not None
                     and continuous_boundary == cold_boundary)
    paired = {
        "cases_per_second_ratio_cold_over_continuous": _ratio(
            groups["cold"]["cases_per_second"],
            groups["continuous"]["cases_per_second"],
            name="cases_per_second_ratio_cold_over_continuous",
            allowed=same_boundary,
            blocked_reason=("the two groups use different rate denominators "
                            f"(continuous: {continuous_boundary}, cold: "
                            f"{cold_boundary}), so their rates are not like-for-like"),
            interpretation=("ratio of two differently bounded rates; the cold rate "
                            "carries per-case initialisation that the continuous rate "
                            "does not, so this is not a speedup measurement")),
        "per_case_total_p50_delta_seconds_cold_minus_continuous": _delta(
            groups["continuous"]["per_case_total_seconds"]["p50"],
            groups["cold"]["per_case_total_seconds"]["p50"],
            name="per_case_total_p50_delta_seconds_cold_minus_continuous",
            interpretation=("difference of two percentile values whose measurement "
                            "boundaries are named per group; it is not a saving "
                            "estimate and must not be subtracted from cold "
                            "initialization cost")),
        "certified_chains_delta_cold_minus_continuous": _delta(
            (groups["continuous"]["certified_chains"] or {}).get("total"),
            (groups["cold"]["certified_chains"] or {}).get("total"),
            name="certified_chains_delta_cold_minus_continuous",
            interpretation=("certificate counts come from the injected producer over "
                            "each group's own window; a difference states artifact "
                            "capability over different windows, not a DUT chain-rate "
                            "difference")),
        "certified_chains_per_second_ratio_cold_over_continuous": _ratio(
            groups["cold"]["certified_chains_per_second"],
            groups["continuous"]["certified_chains_per_second"],
            name="certified_chains_per_second_ratio_cold_over_continuous",
            allowed=True, blocked_reason=None,
            interpretation=("both rates use their own group's effective search window "
                            "and their own certificate producer run; the ratio is a "
                            "comparison of measured windows, not a causal speedup")),
    }
    limits.extend(_empty_quantity_limits(groups, initialization, paired))

    boundaries = _boundaries(
        truncated=alignment["truncated"], max_items=max_items,
        continuous_boundary=continuous_boundary,
        cold_boundary=cold_boundary, continuous_total_source=total_sources["continuous"],
        cold_total_source=total_sources["cold"],
        cold_init_known=initialization["cold_init_seconds_total"] is not None)
    validity["boundaries"] = boundaries

    return {
        "schema_version": SCHEMA_VERSION,
        "continuous_dir": str(continuous),
        "cold_dir": str(cold),
        "max_items": max_items,
        "max_case_details": max_case_details,
        "comparison_scope": (
            "per-case artifact alignment plus per-group rates for two run directories "
            "that must share source, seed and budget; this is not a DUT equivalence, "
            "coverage-equivalence, replay or speedup proof"),
        "comparison_validity": validity,
        "per_case_agreement": {
            "cases_compared": compared,
            "receipt_rows": dict(alignment["rows"]),
            "alignment": alignment["alignment"],
            "truncated": alignment["truncated"],
            "status_transitions": dict(sorted(alignment["transitions"].items())),
            "fields": {name: tallies[name].as_dict() for name in PER_CASE_FIELDS},
            "case_details": alignment["details"],
            "case_details_truncated_at": (
                max_case_details if compared > len(alignment["details"]) else None),
        },
        "groups": groups,
        "initialization": initialization,
        "paired": paired,
        "limits": limits,
        "memory_model": {
            "receipt_rows_retained": 0,
            "case_details_retained": len(alignment["details"]),
            "timing_samples_retained": {label: len(total_samples[label])
                                        for label in ("continuous", "cold")},
            "note": ("receipts are parsed line by line; the report retains aggregate "
                     "counters, at most max_case_details comparison rows and the "
                     "per-case total samples needed for exact p50/p95"),
        },
    }


# --------------------------------------------------------------------------
# markdown rendering
# --------------------------------------------------------------------------


def _format_value(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, dict):
        return ", ".join(f"{name}={_format_value(item)}" for name, item in value.items())
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_format_value(item) for item in value) + "]"
    return str(value)


def render_paired_markdown(report: Mapping) -> str:
    """Render the paired report; the evidence boundary section comes first."""
    validity = report.get("comparison_validity") or {}
    groups = report.get("groups") or {}
    continuous = groups.get("continuous") or {}
    cold = groups.get("cold") or {}
    initialization = report.get("initialization") or {}
    paired = report.get("paired") or {}
    agreement = report.get("per_case_agreement") or {}
    limits = list(report.get("limits") or ())

    lines = ["# Paired first-step efficiency: continuous vs per-case cold start", ""]
    lines.append(f"- schema_version: `{report.get('schema_version')}`")
    lines.append(f"- continuous_dir: `{report.get('continuous_dir')}`")
    lines.append(f"- cold_dir: `{report.get('cold_dir')}`")
    lines.append(f"- comparison status: `{validity.get('status')}`")
    lines.append(f"- cases compared: `{agreement.get('cases_compared')}`")
    lines.append(f"- output equivalence claimed: "
                 f"`{(validity.get('output_equivalence') or {}).get('claimed')}`")
    lines.append("")
    lines.append("## Evidence boundary")
    lines.append("")
    lines.append("Measured by this comparison (recomputable from the two run "
                 "directories):")
    lines.append("")
    measured = [
        ("continuous.cases_per_second", continuous.get("cases_per_second"),
         continuous.get("cases_per_second_reason")),
        ("continuous.cases_per_second_boundary",
         continuous.get("cases_per_second_boundary"), None),
        ("continuous.per_case_total_seconds.p50",
         (continuous.get("per_case_total_seconds") or {}).get("p50"),
         (continuous.get("per_case_total_seconds") or {}).get("reason")),
        ("continuous.per_case_total_seconds.p95",
         (continuous.get("per_case_total_seconds") or {}).get("p95"),
         (continuous.get("per_case_total_seconds") or {}).get("reason")),
        ("continuous.certified_chains.total",
         (continuous.get("certified_chains") or {}).get("total"),
         continuous.get("certified_chains_reason")),
        ("continuous.certified_chains_per_second",
         continuous.get("certified_chains_per_second"),
         continuous.get("certified_chains_per_second_reason")),
        ("cold.cases_per_second", cold.get("cases_per_second"),
         cold.get("cases_per_second_reason")),
        ("cold.cases_per_second_boundary", cold.get("cases_per_second_boundary"), None),
        ("cold.per_case_total_seconds.p50",
         (cold.get("per_case_total_seconds") or {}).get("p50"),
         (cold.get("per_case_total_seconds") or {}).get("reason")),
        ("cold.per_case_total_seconds.p95",
         (cold.get("per_case_total_seconds") or {}).get("p95"),
         (cold.get("per_case_total_seconds") or {}).get("reason")),
        ("cold.certified_chains.total",
         (cold.get("certified_chains") or {}).get("total"),
         cold.get("certified_chains_reason")),
        ("cold.certified_chains_per_second",
         cold.get("certified_chains_per_second"),
         cold.get("certified_chains_per_second_reason")),
        ("initialization.cold_init_seconds_total",
         initialization.get("cold_init_seconds_total"), initialization.get("reason")),
        ("initialization.cold_init_seconds_p50",
         initialization.get("cold_init_seconds_p50"), initialization.get("reason")),
        ("paired.cases_per_second_ratio_cold_over_continuous",
         (paired.get("cases_per_second_ratio_cold_over_continuous") or {}).get("value"),
         (paired.get("cases_per_second_ratio_cold_over_continuous") or {}).get("reason")),
    ]
    for name, value, _reason in measured:
        if value is not None:
            lines.append(f"- `{name}` = {_format_value(value)}")
    lines.append("")
    lines.append("Not provable from these artifacts (reported as `null`, never as "
                 "`0`):")
    lines.append("")
    shown = 0
    for name, value, reason in measured:
        if value is None:
            lines.append(f"- `{name}` = null"
                         + (f": {reason}" if reason else ""))
            shown += 1
    for name, entry in paired.items():
        if entry.get("value") is None and name != (
                "cases_per_second_ratio_cold_over_continuous"):
            lines.append(f"- `{name}` = null: {entry.get('reason')}")
            shown += 1
    for label, group in (("continuous", continuous), ("cold", cold)):
        if group.get("replay_verified") is None:
            lines.append(f"- `{label}.replay_verified` = null: no replay directory was "
                         "analyzed for this group")
            shown += 1
    lines.append(f"- `initialization.continuous_init_seconds` = null: "
                 f"{initialization.get('continuous_init_seconds_reason')}")
    shown += 1
    if not shown:
        lines.append("- none: every quantity listed above was measured")
    lines.append("")
    lines.append("Limits and non-extrapolable boundaries:")
    lines.append("")
    for name in validity.get("failed_prerequisites") or ():
        lines.append(f"- prerequisite failed: `{name}` — "
                     + _format_value(next(
                         (item.get("reason") for item in validity.get("prerequisites") or ()
                          if item["name"] == name), None)))
    for name in validity.get("unverified_prerequisites") or ():
        lines.append(f"- prerequisite unverified: `{name}` — "
                     + _format_value(next(
                         (item.get("reason") for item in validity.get("prerequisites") or ()
                          if item["name"] == name), None)))
    for boundary in validity.get("boundaries") or ():
        lines.append(f"- {boundary}")
    lines.append("")
    lines.append("## Prerequisites for comparability")
    lines.append("")
    lines.append("| prerequisite | satisfied | reason |")
    lines.append("| --- | --- | --- |")
    for item in validity.get("prerequisites") or ():
        lines.append(f"| `{item['name']}` | {_format_value(item['satisfied'])} | "
                     f"{_format_value(item['reason'])} |")
    lines.append("")
    lines.append("## Per-case agreement")
    lines.append("")
    lines.append("| field | equal | mismatch | missing evidence |")
    lines.append("| --- | ---: | ---: | ---: |")
    for name, entry in (agreement.get("fields") or {}).items():
        lines.append(f"| `{name}` | {entry['equal']} | {entry['mismatch']} | "
                     f"{entry['missing']} |")
    lines.append("")
    lines.append(f"- status transitions: {_format_value(agreement.get('status_transitions'))}")
    lines.append(f"- output equivalence: "
                 f"{_format_value((validity.get('output_equivalence') or {}).get('claimed'))}"
                 f" (fields with mismatch: "
                 f"{_format_value((validity.get('output_equivalence') or {}).get('fields_with_mismatch'))})")
    lines.append("")
    lines.append("## Group summary")
    lines.append("")
    lines.append("| quantity | continuous | cold |")
    lines.append("| --- | ---: | ---: |")
    rows = [
        ("case_count", continuous.get("case_count"), cold.get("case_count")),
        ("cases_compared", continuous.get("cases_compared"), cold.get("cases_compared")),
        ("effective_search_seconds", continuous.get("effective_search_seconds"),
         cold.get("effective_search_seconds")),
        ("elapsed_seconds", continuous.get("elapsed_seconds"),
         cold.get("elapsed_seconds")),
        ("cases_per_second", continuous.get("cases_per_second"),
         cold.get("cases_per_second")),
        ("per_case_total_seconds.p50",
         (continuous.get("per_case_total_seconds") or {}).get("p50"),
         (cold.get("per_case_total_seconds") or {}).get("p50")),
        ("per_case_total_seconds.p95",
         (continuous.get("per_case_total_seconds") or {}).get("p95"),
         (cold.get("per_case_total_seconds") or {}).get("p95")),
        ("certified_chains.total",
         (continuous.get("certified_chains") or {}).get("total"),
         (cold.get("certified_chains") or {}).get("total")),
        ("certified_chains_per_second", continuous.get("certified_chains_per_second"),
         cold.get("certified_chains_per_second")),
        ("invalid_or_timeout_ratio", continuous.get("invalid_or_timeout_ratio"),
         cold.get("invalid_or_timeout_ratio")),
        ("new_target_bits_per_second",
         (continuous.get("coverage_novelty") or {}).get("new_target_bits_per_second"),
         (cold.get("coverage_novelty") or {}).get("new_target_bits_per_second")),
    ]
    for name, left, right in rows:
        lines.append(f"| `{name}` | {_format_value(left)} | {_format_value(right)} |")
    lines.append("")
    for label, group in (("continuous", continuous), ("cold", cold)):
        lines.append(f"- `{label}.certified_chains_semantics`: "
                     f"{_format_value(group.get('certified_chains_semantics'))}")
        admissions = group.get("chain_completion_by_admission") or {}
        lines.append(f"- `{label}.chain_completion_by_admission`: "
                     f"admissions_total={_format_value(admissions.get('admissions_total'))}, "
                     f"certified_admissions={_format_value(admissions.get('certified_admissions'))}, "
                     f"certified_ratio={_format_value(admissions.get('certified_ratio'))}")
    lines.append("")
    lines.append("## Initialization cost")
    lines.append("")
    for name in ("cold_baseline_document", "cold_baseline_schema_version",
                 "cold_baseline_case_count", "cold_cases_with_init_seconds",
                 "cold_init_seconds_source", "cold_init_seconds_total",
                 "cold_init_seconds_p50", "cold_init_seconds_p95",
                 "cold_init_share_of_elapsed", "continuous_init_seconds",
                 "continuous_init_seconds_reason", "reason"):
        lines.append(f"- `{name}` = {_format_value(initialization.get(name))}")
    lines.append("")
    lines.append("## Paired quantities")
    lines.append("")
    for name, entry in paired.items():
        lines.append(f"- `{name}` = {_format_value(entry.get('value'))}"
                     + (f" (reason: {entry['reason']})" if entry.get("reason") else ""))
        lines.append(f"  - interpretation: {entry.get('interpretation')}")
    lines.append("")
    lines.append("## Limits")
    lines.append("")
    lines.append("| group | quantity | reason |")
    lines.append("| --- | --- | --- |")
    for item in limits:
        lines.append(f"| {item.get('group')} | `{item['quantity']}` | {item['reason']} |")
    lines.append("")
    return "\n".join(lines)
