"""Read-only same-condition equivalence between two saved run arms.

A run *pair* is two saved run directories produced under the same declared
condition except for one factor (operator ON/OFF, continuous vs cold start,
JSONL vs zlib trace container, ...).  This module answers one narrow question:

    are the two arms *field-identical* case by case, and if not, on exactly
    which declared fields and inside exactly which comparison window?

The comparison window is the **shared raw-input prefix**: the leading receipts
whose ``raw_sha256`` is identical in both arms, compared in receipt order.  The
searches diverge by construction (a mutation decision changes the next input),
so this prefix - and nothing else - is the only per-case comparable region.

Per case and per declared field the comparison classifies the pair as
``equal`` / ``unequal`` / ``missing_left`` / ``missing_right`` / ``missing_both``
(absence is never equality, and an explicit JSON ``null`` counts as absent).
A field family then gets ``equivalent`` / ``not_equivalent`` / ``unknown``
plus a precise reason; ``unknown`` is the honest answer when part of the window
cannot be read on either arm.

``output_equivalence.claimed`` is deliberately hard to earn: it is true only
when the window covers *both* arms completely, both arms have the same receipt
case count, the window was not truncated by the case cap, and every in-scope
declared field is equal.  It is never implied by ``evidence_status ==
"compared"``.

The comparison fails closed (``evidence_status == "refused"`` and a non-zero
CLI exit code) when the arms do not share a decodable identity: no receipts,
no cases, a different decoder manifest, a different source identity, or a
zero-length shared prefix.

Nothing here starts RTL, Verilator, cargo or the fuzz client, and no trace
container is ever opened: only ``receipts.jsonl`` (streamed line by line),
``report.json``, ``online_run_identity.json`` and ``decoder_manifest.json``.
Memory stays bounded by the tallies, the bounded case-index lists and the
``max_window_cases`` cap; no receipt row is retained.

Schema: ``arm_equivalence.v1``.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from typing import Iterator, Mapping, Sequence


SCHEMA_VERSION = "arm_equivalence.v1"

RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"
IDENTITY_NAME = "online_run_identity.json"
MANIFEST_NAME = "decoder_manifest.json"
RAW_IDENTITY_FIELD = "raw_sha256"
RAW_RECORDS_FIELD = "online_raw_records_hex"

DEFAULT_MAX_WINDOW_CASES = 200_000
DEFAULT_MAX_DETAIL_INDEXES = 20
DEFAULT_MAX_UNDECLARED_FIELDS = 64

VERDICT_EQUIVALENT = "equivalent"
VERDICT_NOT_EQUIVALENT = "not_equivalent"
VERDICT_UNKNOWN = "unknown"
VERDICT_NOT_APPLICABLE = "not_applicable"

_SEVERITY = {
    VERDICT_EQUIVALENT: 0,
    VERDICT_UNKNOWN: 1,
    VERDICT_NOT_EQUIVALENT: 2,
}
_FAMILY_VERDICTS = (
    VERDICT_NOT_EQUIVALENT, VERDICT_UNKNOWN, VERDICT_EQUIVALENT)

#: Declared comparison field set: family -> {"verdict": (...), "context": (...)}.
#: ``verdict`` fields define the family verdict; ``context`` fields are
#: conditionally populated diagnostics that are reported with full tallies but
#: can never define a verdict (a field that is null on successful cases by
#: contract must not turn every family into ``unknown``).
FAMILY_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "status": {"verdict": ("status",), "context": ()},
    "effective_genome": {
        "verdict": ("effective_genome_sha256", "genome_sha256"), "context": ()},
    "path": {"verdict": ("path_id", "applied_path"), "context": ()},
    "direction": {"verdict": ("direction",), "context": ()},
    "applied_sources": {
        "verdict": ("applied_sources", "applied_source_ids", "source_id"),
        "context": ()},
    "checker_violations": {
        "verdict": ("violations",), "context": ("rejection", "error")},
    "coverage": {"verdict": ("coverage_hex",), "context": ()},
    "local_ticks": {
        "verdict": ("local_ticks", "total_local_ticks"), "context": ()},
}
FIELD_FAMILIES: tuple[str, ...] = tuple(FAMILY_FIELDS)

#: Declared semantics a family's numbers depend on.  When a semantics field is
#: declared by both arms and differs, the family cannot be compared across the
#: arms and is reported ``unknown`` instead of ``equivalent``.
FAMILY_PRECONDITIONS: dict[str, tuple[str, ...]] = {
    "status": ("record_semantics",),
    "effective_genome": ("record_semantics",),
    "path": ("record_semantics",),
    "direction": ("record_semantics",),
    "applied_sources": ("record_semantics",),
    "checker_violations": ("record_semantics",),
    "coverage": ("record_semantics",),
    "local_ticks": ("total_local_ticks_semantics", "clock_model"),
}

IDENTITY_COMPARE_FIELDS = (
    "decoder_manifest_sha256",
    "source_files_sha256",
    "component_identity_sha256",
    "targets_sha256",
)
IDENTITY_CONTEXT_FIELDS = (
    "record_semantics",
    "total_local_ticks_semantics",
    "clock_model",
)

#: Declared budget fields compared between the arms; the realized case count is
#: reported next to them but is not a budget.
BUDGET_FIELDS = (
    "max_tests",
    "duration_seconds",
    "feedback_interval",
    "search_seed",
    "global_mutation_seed",
)

#: Refusals in precedence order: nothing to compare, then undecodable identity,
#: then a window that does not exist.
REFUSAL_CODES = (
    "no_receipts",
    "empty_receipts",
    "decoder_manifest_undecodable",
    "decoder_manifest_inconsistent",
    "decoder_manifest_mismatch",
    "source_identity_undecodable",
    "source_identity_mismatch",
    "zero_shared_prefix",
)

_MISSING = object()
_SENTINEL = object()

#: Every declared comparison field, primary and context.
_DECLARED_FIELD_NAMES = frozenset(
    field_name
    for family in FIELD_FAMILIES
    for role in ("verdict", "context")
    for field_name in FAMILY_FIELDS[family][role])

#: Receipt fields that carry the identity of the run/case/container rather than
#: an observed outcome; used to classify fields outside the declared projection.
_RUN_BOOKKEEPING_FIELDS = frozenset({
    "run_id", "case_id", "case_index", "index", "slot", "buffer_id",
    "candidate_id", "manifest_sha256", "identity_document_sha256",
})

BOUNDARIES = (
    "an `equivalent` verdict covers only the declared per-case receipt "
    "projection inside the shared raw-input window; it says nothing about "
    "search quality (target hits, coverage novelty, chain yield, certificates) "
    "or about the trace containers, which are never opened",
    "`output_equivalence.claimed = true` requires the window to cover both arms "
    "completely, both arms to have the same receipt case count, no window "
    "truncation and every in-scope declared field to be equal; it is never "
    "implied by `evidence_status = compared`",
    "a `not_equivalent` verdict names the exact field(s) and case indexes; a "
    "field recorded only by one arm's bookkeeping path (for example the "
    "duplicated `applied_source_ids` alias) can produce a real "
    "`not_equivalent` verdict without a DUT behaviour difference, so the "
    "driving field must be read with the per-field table",
    "`unknown` is the absence of evidence: a declared field that is null or "
    "absent in the window - on one arm or on both - is never counted as equal",
    "the window is a prefix in receipt order, not a set intersection: cases "
    "that match later but not in prefix order stay outside the window",
    "the window proves *byte-level* raw-input identity, not source or plan "
    "identity: the same raw bytes can be produced by a different applied "
    "source (the path-switch pair is the concrete case - identical "
    "`raw_sha256` and `online_raw_records_hex` at case 0, different "
    "`online_source`, `operator_id`, path and direction), which is why the "
    "per-field comparison and `outside_declared_projection` must be read "
    "together with the window length",
    "the declared projection fixes the claim, not the record: receipt fields "
    "outside it (timing maps, `run_id`/`slot`/`buffer_id` bookkeeping, "
    "`semantic_sha256`, interaction deltas) are reported separately under "
    "`outside_declared_projection` and a differing `other` field there is a "
    "warning that the projection hides part of the case record",
    "the comparison reads saved artifacts only; no RTL, Verilator, cargo or "
    "fuzz client is started and no trace container is opened",
)


class ArmEquivalenceInputError(ValueError):
    """Raised when a core artifact is unreadable, so no comparison exists."""


# ---------------------------------------------------------------------------
# canonical JSON helpers
# ---------------------------------------------------------------------------


def canonical_bytes(value: object) -> bytes:
    """Canonical JSON encoding used for every equality decision."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _finite_non_negative(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        number = float(value)
        if number == number and number not in (float("inf"), float("-inf")):
            return number if number >= 0 else None
    return None


def _int_or_none(value: object) -> int | None:
    return value if type(value) is int else None


def _mapping(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


# ---------------------------------------------------------------------------
# bounded, streamed artifact access
# ---------------------------------------------------------------------------


class _ArmReader:
    """Reads one arm's small artifacts and streams its receipts.

    Every open goes through :meth:`_path` and is recorded in
    ``artifacts_read``, so the produced document can state exactly which files
    the comparison touched.  Trace containers are never in that set.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.artifacts_read: list[str] = []

    def exists(self, name: str) -> bool:
        return (self.directory / name).is_file()

    def read_json(self, name: str) -> dict | None:
        path = self.directory / name
        if not path.is_file():
            return None
        self.artifacts_read.append(name)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ArmEquivalenceInputError(
                f"invalid JSON in {path}: {getattr(exc, 'msg', exc)}") from exc
        if type(document) is not dict:
            raise ArmEquivalenceInputError(f"{path} is not a JSON object")
        return document

    def canonical_file_sha256(self, name: str) -> str | None:
        document = self.read_json(name)
        if document is None:
            return None
        return canonical_sha256(document)

    def iter_receipts(self, name: str) -> Iterator[dict]:
        """Yield one receipt object per line; never retain the row."""
        path = self.directory / name
        self.artifacts_read.append(name)
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as exc:
            raise ArmEquivalenceInputError(f"cannot read {path}: {exc}") from exc
        with handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ArmEquivalenceInputError(
                        f"invalid JSON on line {number} of {path}: "
                        f"{exc.msg}") from exc
                if type(row) is not dict:
                    raise ArmEquivalenceInputError(
                        f"non-object JSON value on line {number} of {path}")
                yield row

    def as_read_scope(self) -> list[str]:
        return list(self.artifacts_read)


def _case_value(row: Mapping, name: str) -> tuple[object, bool]:
    """Return ``(value, missing)``; an explicit JSON null counts as missing."""
    value = row.get(name, _MISSING)
    if value is _MISSING or value is None:
        return None, True
    return value, False


# ---------------------------------------------------------------------------
# per-field tallies
# ---------------------------------------------------------------------------


class _FieldTally:
    """Counters for one declared field inside the comparison window."""

    __slots__ = ("name", "role", "equal", "unequal", "missing_left",
                 "missing_right", "missing_both", "unequal_indexes",
                 "missing_indexes", "indexes_truncated")

    def __init__(self, name: str, role: str) -> None:
        self.name = name
        self.role = role
        self.equal = 0
        self.unequal = 0
        self.missing_left = 0
        self.missing_right = 0
        self.missing_both = 0
        self.unequal_indexes: list[int] = []
        self.missing_indexes: list[int] = []
        self.indexes_truncated = False

    # -- bounded detail bookkeeping -----------------------------------
    def _record(self, bucket: list[int], index: int, limit: int) -> None:
        if len(bucket) < limit:
            bucket.append(index)
        else:
            self.indexes_truncated = True

    def add(self, index: int, left_value: object, left_missing: bool,
            right_value: object, right_missing: bool, *, limit: int) -> None:
        if left_missing and right_missing:
            self.missing_both += 1
            self._record(self.missing_indexes, index, limit)
        elif left_missing:
            self.missing_left += 1
            self._record(self.missing_indexes, index, limit)
        elif right_missing:
            self.missing_right += 1
            self._record(self.missing_indexes, index, limit)
        elif canonical_bytes(left_value) == canonical_bytes(right_value):
            self.equal += 1
        else:
            self.unequal += 1
            self._record(self.unequal_indexes, index, limit)

    # -- derived ------------------------------------------------------
    @property
    def observed(self) -> int:
        return self.equal + self.unequal + self.missing_left + self.missing_right

    @property
    def missing(self) -> int:
        return self.missing_left + self.missing_right + self.missing_both

    @property
    def in_scope(self) -> bool:
        """True when at least one window case records the field on some arm."""
        return self.observed > 0

    def verdict(self, window_cases: int) -> tuple[str, str]:
        if window_cases == 0:
            return VERDICT_UNKNOWN, "the comparison window is empty"
        if not self.in_scope:
            return (VERDICT_NOT_APPLICABLE,
                    f"{self.name} is null or absent in all {window_cases} "
                    "window cases on both arms")
        if self.unequal:
            return (VERDICT_NOT_EQUIVALENT,
                    f"{self.name} differs in {self.unequal} of "
                    f"{window_cases} window cases")
        if self.missing:
            return (VERDICT_UNKNOWN,
                    f"{self.name} is missing (null or absent) in {self.missing} "
                    f"of {window_cases} window cases (left-only "
                    f"{self.missing_left}, right-only {self.missing_right}, "
                    f"both {self.missing_both})")
        return (VERDICT_EQUIVALENT,
                f"{self.name} is identical in all {window_cases} window cases")

    def as_dict(self, window_cases: int) -> dict:
        verdict, reason = self.verdict(window_cases)
        return {
            "name": self.name,
            "role": self.role,
            "in_scope": self.in_scope,
            "verdict": verdict,
            "reason": reason,
            "window_cases": window_cases,
            "equal": self.equal,
            "unequal": self.unequal,
            "missing_left": self.missing_left,
            "missing_right": self.missing_right,
            "missing_both": self.missing_both,
            "missing": self.missing,
            "unequal_case_indexes": list(self.unequal_indexes),
            "missing_case_indexes": list(self.missing_indexes),
            "case_indexes_truncated": self.indexes_truncated,
        }


def _new_tallies() -> dict[str, list[_FieldTally]]:
    tallies: dict[str, list[_FieldTally]] = {}
    for family in FIELD_FAMILIES:
        fields = []
        for name in FAMILY_FIELDS[family]["verdict"]:
            fields.append(_FieldTally(name, "verdict"))
        for name in FAMILY_FIELDS[family]["context"]:
            fields.append(_FieldTally(name, "context"))
        tallies[family] = fields
    return tallies


# ---------------------------------------------------------------------------
# the single streaming comparison pass
# ---------------------------------------------------------------------------


def _stream_arms(left: _ArmReader, right: _ArmReader, *, max_window_cases: int,
                 max_detail_indexes: int, max_undeclared_fields: int) -> dict:
    """Stream both receipt files in lockstep and keep aggregates only.

    Nothing is retained beyond the tallies, the bounded case-index lists and
    the two status counters, so the memory footprint does not grow with the
    receipt count.
    """
    tallies = _new_tallies()
    left_cases = 0
    right_cases = 0
    left_status: dict[str, int] = {}
    right_status: dict[str, int] = {}
    window_cases = 0
    prefix_open = True
    capped = False
    first_divergent: dict | None = None
    records_compared = 0
    records_agreed = 0
    records_disagreed_index: int | None = None
    undeclared: dict[str, _FieldTally] = {}
    undeclared_skipped: list[str] = []
    undeclared_truncated = False

    left_rows = left.iter_receipts(RECEIPTS_NAME)
    right_rows = right.iter_receipts(RECEIPTS_NAME)
    for index, (left_row, right_row) in enumerate(
            itertools.zip_longest(left_rows, right_rows, fillvalue=_SENTINEL)):
        if left_row is not _SENTINEL:
            left_cases += 1
            name = left_row.get("status")
            name = name if isinstance(name, str) and name else "unknown"
            left_status[name] = left_status.get(name, 0) + 1
        if right_row is not _SENTINEL:
            right_cases += 1
            name = right_row.get("status")
            name = name if isinstance(name, str) and name else "unknown"
            right_status[name] = right_status.get(name, 0) + 1
        if not prefix_open:
            continue
        if left_row is _SENTINEL or right_row is _SENTINEL:
            prefix_open = False
            ended = "left" if left_row is _SENTINEL else "right"
            first_divergent = {
                "case_index": index,
                "divergence_reason": f"{ended}_arm_ended",
                "left_raw_sha256": None if left_row is _SENTINEL
                else _case_value(left_row, RAW_IDENTITY_FIELD)[0],
                "right_raw_sha256": None if right_row is _SENTINEL
                else _case_value(right_row, RAW_IDENTITY_FIELD)[0],
                "left_case_id": None if left_row is _SENTINEL
                else left_row.get("case_id"),
                "right_case_id": None if right_row is _SENTINEL
                else right_row.get("case_id"),
            }
            continue
        if window_cases >= max_window_cases:
            prefix_open = False
            capped = True
            continue
        left_raw, left_missing = _case_value(left_row, RAW_IDENTITY_FIELD)
        right_raw, right_missing = _case_value(right_row, RAW_IDENTITY_FIELD)
        if left_missing or right_missing:
            prefix_open = False
            first_divergent = {
                "case_index": index,
                "divergence_reason": "raw_identity_missing",
                "left_raw_sha256": left_raw,
                "right_raw_sha256": right_raw,
                "left_case_id": left_row.get("case_id"),
                "right_case_id": right_row.get("case_id"),
            }
            continue
        if left_raw != right_raw:
            prefix_open = False
            first_divergent = {
                "case_index": index,
                "divergence_reason": "raw_sha256_differs",
                "left_raw_sha256": left_raw,
                "right_raw_sha256": right_raw,
                "left_case_id": left_row.get("case_id"),
                "right_case_id": right_row.get("case_id"),
            }
            continue

        window_cases += 1
        for family in FIELD_FAMILIES:
            for tally in tallies[family]:
                value_left, missing_left = _case_value(left_row, tally.name)
                value_right, missing_right = _case_value(right_row, tally.name)
                tally.add(index, value_left, missing_left, value_right,
                          missing_right, limit=max_detail_indexes)
        for candidate in sorted(set(left_row) | set(right_row)):
            if candidate in _DECLARED_FIELD_NAMES:
                continue
            tally = undeclared.get(candidate)
            if tally is None:
                if len(undeclared) >= max_undeclared_fields:
                    undeclared_truncated = True
                    if (candidate not in undeclared_skipped
                            and len(undeclared_skipped) < max_undeclared_fields):
                        undeclared_skipped.append(candidate)
                    continue
                tally = _FieldTally(candidate, "undeclared")
                undeclared[candidate] = tally
            value_left, missing_left = _case_value(left_row, candidate)
            value_right, missing_right = _case_value(right_row, candidate)
            tally.add(index, value_left, missing_left, value_right,
                      missing_right, limit=max_detail_indexes)
        left_records, left_records_missing = _case_value(left_row,
                                                         RAW_RECORDS_FIELD)
        right_records, right_records_missing = _case_value(right_row,
                                                           RAW_RECORDS_FIELD)
        if not (left_records_missing or right_records_missing):
            records_compared += 1
            if canonical_bytes(left_records) == canonical_bytes(right_records):
                records_agreed += 1
            elif records_disagreed_index is None:
                records_disagreed_index = index

    return {
        "tallies": tallies,
        "left_cases": left_cases,
        "right_cases": right_cases,
        "left_status": left_status,
        "right_status": right_status,
        "window_cases": window_cases,
        "capped": capped,
        "first_divergent": first_divergent,
        "records_cross_check": {
            "field": RAW_RECORDS_FIELD,
            "compared": records_compared,
            "agreed": records_agreed,
            "disagreed": records_compared - records_agreed,
            "first_disagreement_case_index": records_disagreed_index,
        },
        "undeclared": undeclared,
        "undeclared_skipped": undeclared_skipped,
        "undeclared_truncated": undeclared_truncated,
    }


# ---------------------------------------------------------------------------
# identity / budget views
# ---------------------------------------------------------------------------


def _source_files_sha256(identity: Mapping) -> str | None:
    source_files = identity.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        return None
    pairs = []
    for entry in source_files:
        if not isinstance(entry, Mapping):
            return None
        path = entry.get("path")
        digest = entry.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            return None
        pairs.append((path, digest))
    return canonical_sha256(sorted(pairs))


def _arm_view(reader: _ArmReader, label: str) -> dict:
    report = reader.read_json(REPORT_NAME)
    identity_document = reader.read_json(IDENTITY_NAME)
    manifest_file_sha256 = reader.canonical_file_sha256(MANIFEST_NAME)
    identity = _mapping(_mapping(identity_document).get("identity"))
    run_config = _mapping(identity.get("run_config"))
    session = _mapping(identity.get("session"))
    components = _mapping(identity.get("components"))
    feedback = _mapping(identity.get("feedback"))
    report = report or {}
    report_decoder = report.get("decoder_manifest_sha256")
    report_decoder = report_decoder if isinstance(report_decoder, str) else None
    consistent = None
    if report_decoder is not None and manifest_file_sha256 is not None:
        consistent = report_decoder == manifest_file_sha256
    return {
        "label": label,
        "directory": str(reader.directory),
        "identity_document_present": identity_document is not None,
        "identity_document_sha256": _mapping(identity_document).get("sha256"),
        "run_id": run_config.get("run_id") or report.get("run_id"),
        "max_tests": _int_or_none(run_config.get("max_tests")),
        "duration_seconds": _finite_non_negative(
            run_config.get("duration_seconds")),
        "feedback_interval": _int_or_none(run_config.get("feedback_interval")),
        "search_seed": run_config.get("search_seed"),
        "declared_tests": _int_or_none(report.get("tests")),
        "declared_statuses": report.get("statuses"),
        "receipt_cases": None,
        "receipt_status_counts": None,
        "effective_search_seconds": _finite_non_negative(
            report.get("effective_search_seconds")),
        "elapsed_seconds": _finite_non_negative(report.get("elapsed_seconds")),
        "execution_mode": report.get("execution_mode"),
        "global_mutation_seed": report.get("global_mutation_seed"),
        "decoder_manifest_report_sha256": report_decoder,
        "decoder_manifest_file_sha256": manifest_file_sha256,
        "decoder_manifest_report_matches_file": consistent,
        "decoder_manifest_matches_continuous": report.get(
            "decoder_manifest_matches_continuous"),
        "source_files_sha256": _source_files_sha256(identity),
        "component_identity_sha256": (session.get("component_identity_sha256")
                                      or components.get("identity_sha256")),
        "targets_sha256": feedback.get("targets_sha256"),
        "record_semantics": report.get("record_semantics"),
        "total_local_ticks_semantics": report.get(
            "total_local_ticks_semantics"),
        "clock_model": report.get("clock_model"),
    }


def _decoder_identity(view: Mapping) -> str | None:
    """The decodable decoder identity of one arm (report first, file second)."""
    report_sha = view.get("decoder_manifest_report_sha256")
    file_sha = view.get("decoder_manifest_file_sha256")
    return report_sha or file_sha


def _identity_comparison(left: Mapping, right: Mapping) -> dict:
    compare: dict[str, dict] = {}
    for candidate in IDENTITY_COMPARE_FIELDS + IDENTITY_CONTEXT_FIELDS:
        left_value = left.get(candidate)
        right_value = right.get(candidate)
        if candidate == "decoder_manifest_sha256":
            left_value = _decoder_identity(left)
            right_value = _decoder_identity(right)
        decodable = left_value is not None and right_value is not None
        compare[candidate] = {
            "left": left_value,
            "right": right_value,
            "decodable_on_both_arms": decodable,
            "equal": None if not decodable else left_value == right_value,
        }
    required = [_decoder_identity(left), _decoder_identity(right),
                left.get("source_files_sha256"), right.get("source_files_sha256"),
                left.get("component_identity_sha256"),
                right.get("component_identity_sha256")]
    return {
        "compare": compare,
        "required_identity_fields": [
            "decoder_manifest_sha256", "source_files_sha256",
            "component_identity_sha256"],
        "required_identity_decodable_on_both_arms": all(
            value is not None for value in required),
        "context_semantics_equal": {
            name: compare[name]["equal"] for name in IDENTITY_CONTEXT_FIELDS},
    }


def _refusal_check(stream: Mapping, views: Mapping[str, Mapping],
                   identity: Mapping) -> dict | None:
    """Return the highest-precedence refusal, or None when comparable."""
    if stream["left_cases"] == 0 or stream["right_cases"] == 0:
        empty = [arm for arm, count in
                 (("left", stream["left_cases"]), ("right", stream["right_cases"]))
                 if count == 0]
        return {
            "code": "empty_receipts",
            "reason": ("no case could be decoded from "
                       f"{RECEIPTS_NAME} of the {'/'.join(empty)} arm(s), so "
                       "there is no case sequence to compare"),
            "detail": {"left_cases": stream["left_cases"],
                       "right_cases": stream["right_cases"]},
        }
    decoder = identity["compare"]["decoder_manifest_sha256"]
    if not decoder["decodable_on_both_arms"]:
        missing = [arm for arm in ("left", "right")
                   if _decoder_identity(views[arm]) is None]
        return {
            "code": "decoder_manifest_undecodable",
            "reason": (f"the decoder manifest identity cannot be decoded for "
                       f"the {'/'.join(missing)} arm(s): neither "
                       f"{REPORT_NAME}:decoder_manifest_sha256 nor "
                       f"{MANIFEST_NAME} is available, so the two arms cannot "
                       "be shown to share a decoder"),
            "detail": {"decoder_manifest": decoder},
        }
    for arm in ("left", "right"):
        if views[arm].get("decoder_manifest_report_matches_file") is False:
            return {
                "code": "decoder_manifest_inconsistent",
                "reason": (f"the {arm} arm declares decoder_manifest_sha256="
                           f"{views[arm]['decoder_manifest_report_sha256']} in "
                           f"{REPORT_NAME} but its {MANIFEST_NAME} hashes to "
                           f"{views[arm]['decoder_manifest_file_sha256']}"),
                "detail": {"arm": arm,
                           "report": views[arm]["decoder_manifest_report_sha256"],
                           "file": views[arm]["decoder_manifest_file_sha256"]},
            }
    if decoder["equal"] is False:
        return {
            "code": "decoder_manifest_mismatch",
            "reason": ("the arms were decoded with different decoder manifests "
                       f"(left {decoder['left']}, right {decoder['right']}), so "
                       "their case fields are not the same quantity"),
            "detail": {"decoder_manifest": decoder},
        }
    source_fields = [compare for candidate, compare in identity["compare"].items()
                     if candidate in ("source_files_sha256",
                                      "component_identity_sha256")]
    undecodable = [candidate for candidate, compare
                   in identity["compare"].items()
                   if candidate in ("source_files_sha256",
                                    "component_identity_sha256")
                   and not compare["decodable_on_both_arms"]]
    if undecodable:
        return {
            "code": "source_identity_undecodable",
            "reason": ("the source identity cannot be decoded for both arms: "
                       f"{', '.join(undecodable)} missing in "
                       f"{IDENTITY_NAME}, so the arms cannot be shown to run "
                       "the same sources"),
            "detail": {"undecodable_fields": undecodable,
                       "compare": identity["compare"]},
        }
    different = [candidate for candidate, compare
                 in identity["compare"].items()
                 if candidate in ("source_files_sha256",
                                  "component_identity_sha256")
                 and compare["equal"] is False]
    if different:
        return {
            "code": "source_identity_mismatch",
            "reason": ("the arms do not share a source identity: "
                       + "; ".join(
                           f"{name} left={identity['compare'][name]['left']} "
                           f"right={identity['compare'][name]['right']}"
                           for name in different)),
            "detail": {"different_fields": different, "compare": source_fields},
        }
    if stream["window_cases"] == 0:
        divergent = stream["first_divergent"] or {}
        return {
            "code": "zero_shared_prefix",
            "reason": ("the arms share no raw input case: the first case "
                       f"(index {divergent.get('case_index', 0)}) already "
                       f"diverges ({divergent.get('divergence_reason', 'unknown')}"
                       f", left raw {divergent.get('left_raw_sha256')}, right "
                       f"raw {divergent.get('right_raw_sha256')}), so there is "
                       "no per-case comparable window"),
            "detail": {"first_divergent_case": stream["first_divergent"],
                       "left_cases": stream["left_cases"],
                       "right_cases": stream["right_cases"]},
        }
    return None


# ---------------------------------------------------------------------------
# document assembly
# ---------------------------------------------------------------------------


def _classify_outside_field(candidate: str) -> str:
    """Classify one receipt field outside the declared projection."""
    tokens = candidate.lower().split("_")
    if "timing" in tokens or "seconds" in tokens:
        return "timing"
    if candidate.lower() in _RUN_BOOKKEEPING_FIELDS:
        return "run_bookkeeping"
    return "other"


def _outside_projection_block(stream: Mapping, *,
                              max_undeclared_fields: int) -> dict:
    """Report receipt fields outside the declared projection, never a verdict."""
    window_cases = stream["window_cases"]
    entries = []
    classes: dict[str, int] = {"timing": 0, "run_bookkeeping": 0, "other": 0}
    differences: list[str] = []
    for candidate, tally in sorted(stream["undeclared"].items()):
        recorded = tally.as_dict(window_cases)
        classification = _classify_outside_field(candidate)
        entry = {
            "field": candidate,
            "classification": classification,
            "in_scope": recorded["in_scope"],
            "equal": recorded["equal"],
            "unequal": recorded["unequal"],
            "missing_left": recorded["missing_left"],
            "missing_right": recorded["missing_right"],
            "missing_both": recorded["missing_both"],
            "unequal_case_indexes": recorded["unequal_case_indexes"],
            "missing_case_indexes": recorded["missing_case_indexes"],
        }
        entries.append(entry)
        if not recorded["in_scope"]:
            continue
        if (recorded["unequal"] or recorded["missing_left"]
                or recorded["missing_right"]):
            differences.append(candidate)
            classes[classification] = classes.get(classification, 0) + 1
    entries.sort(key=lambda item: (item["classification"], item["field"]))
    return {
        "definition": (
            "receipt fields present in the window rows that are not part of "
            "the declared comparison projection; they are reported for "
            "transparency, never define a family verdict and are never part of "
            "the output-equivalence claim"),
        "declared_field_count": len(_DECLARED_FIELD_NAMES),
        "window_cases": window_cases,
        "max_tracked_fields": max_undeclared_fields,
        "truncated": bool(stream["undeclared_truncated"]),
        "skipped_field_count": len(stream["undeclared_skipped"]),
        "skipped_fields": list(stream["undeclared_skipped"]),
        "fields_with_differences": sorted(differences),
        "difference_classes": classes,
        "fields": entries,
        "note": (
            "`timing` and `run_bookkeeping` differences are expected between "
            "two arms; a differing `other` field (for example "
            "`semantic_sha256`, `target_id`, interaction deltas) means the "
            "declared projection hides part of the case record and must be "
            "read before trusting an `equivalent` verdict"),
    }


def _family_blocks(stream: Mapping, identity: Mapping) -> list[dict]:
    window_cases = stream["window_cases"]
    blocks = []
    for family in FIELD_FAMILIES:
        fields = stream["tallies"][family]
        field_dicts = [tally.as_dict(window_cases) for tally in fields]
        # only verdict-role fields may define the family verdict; context-role
        # fields are conditionally populated diagnostics and are reported with
        # their own tallies instead
        in_scope = [tally for tally in fields
                    if tally.in_scope and tally.role == "verdict"]
        context_differences = [
            {"field": tally.name, "unequal": tally.unequal,
             "missing_left": tally.missing_left,
             "missing_right": tally.missing_right,
             "unequal_case_indexes": list(tally.unequal_indexes)}
            for tally in fields if tally.role == "context" and tally.in_scope
            and (tally.unequal or tally.missing_left or tally.missing_right)]
        uncomparable = []
        for candidate in FAMILY_PRECONDITIONS[family]:
            compare = identity["compare"].get(candidate, {})
            if compare.get("decodable_on_both_arms") and compare.get("equal") is False:
                uncomparable.append(candidate)
        if window_cases == 0:
            verdict = VERDICT_UNKNOWN
            reason = ("the comparison window is empty, so no case of this "
                      "family could be compared")
            driver = None
        elif uncomparable:
            verdict = VERDICT_UNKNOWN
            reason = ("declared semantics differ between the arms ("
                      + ", ".join(uncomparable) + "), so the field values of "
                      "this family are not the same quantity")
            driver = None
        elif not in_scope:
            verdict = VERDICT_UNKNOWN
            reason = ("no declared field of family "
                      f"'{family}' is observable in the comparison window")
            driver = None
        else:
            driver_tally = max(
                in_scope,
                key=lambda tally: (_SEVERITY[tally.verdict(window_cases)[0]],
                                   -fields.index(tally)))
            verdict, driver_reason = driver_tally.verdict(window_cases)
            reason = f"{driver_tally.name}: {driver_reason}"
            driver = driver_tally.name
        blocks.append({
            "family": family,
            "verdict": verdict,
            "reason": reason,
            "verdict_driver_field": driver,
            "declared_verdict_fields": list(FAMILY_FIELDS[family]["verdict"]),
            "declared_context_fields": list(FAMILY_FIELDS[family]["context"]),
            "required_semantics": list(FAMILY_PRECONDITIONS[family]),
            "uncomparable_semantics": uncomparable,
            "window_cases": window_cases,
            "context_differences": context_differences,
            "fields": field_dicts,
        })
    return blocks


def _output_equivalence(window: Mapping, stream: Mapping,
                        family_blocks: Sequence[Mapping]) -> dict:
    window_cases = stream["window_cases"]
    family_verdicts = {block["family"]: block["verdict"]
                       for block in family_blocks}
    not_equivalent = sorted(name for name, verdict in family_verdicts.items()
                            if verdict == VERDICT_NOT_EQUIVALENT)
    unknown = sorted(name for name, verdict in family_verdicts.items()
                     if verdict == VERDICT_UNKNOWN)
    unequal_fields = []
    not_applicable_fields = []
    in_scope_fields = 0
    for block in family_blocks:
        for field in block["fields"]:
            if not field["in_scope"]:
                not_applicable_fields.append(f"{block['family']}.{field['name']}")
                continue
            if field["role"] == "verdict":
                in_scope_fields += 1
            if field["unequal"]:
                unequal_fields.append({
                    "field": f"{block['family']}.{field['name']}",
                    "role": field["role"],
                    "unequal": field["unequal"],
                    "unequal_case_indexes": field["unequal_case_indexes"],
                })
    same_case_count = stream["left_cases"] == stream["right_cases"]
    conditions = [
        {"condition": "window_computable",
         "satisfied": bool(window["computable"]),
         "detail": (f"shared raw-input prefix of {window_cases} case(s)"
                    if window["computable"] else "the window is not computable")},
        {"condition": "same_receipt_case_count",
         "satisfied": same_case_count,
         "detail": f"left {stream['left_cases']}, right {stream['right_cases']}"},
        {"condition": "window_covers_left_arm",
         "satisfied": window_cases == stream["left_cases"],
         "detail": f"window {window_cases} of left {stream['left_cases']}"},
        {"condition": "window_covers_right_arm",
         "satisfied": window_cases == stream["right_cases"],
         "detail": f"window {window_cases} of right {stream['right_cases']}"},
        {"condition": "window_not_truncated",
         "satisfied": not stream["capped"],
         "detail": (f"window case cap {window['window_case_cap']} reached"
                    if stream["capped"] else "the cap was not reached")},
        {"condition": "every_inscope_field_equivalent",
         "satisfied": not unequal_fields and not unknown,
         "detail": (f"{in_scope_fields} in-scope verdict field(s); "
                    f"{len(unequal_fields)} unequal, "
                    f"{len(unknown)} family/families unknown")},
        {"condition": "every_family_equivalent",
         "satisfied": not not_equivalent and not unknown,
         "detail": (f"not_equivalent {not_equivalent or '[]'}, "
                    f"unknown {unknown or '[]'}")},
    ]
    claimed = all(condition["satisfied"] for condition in conditions)
    reasons = []
    for condition in conditions:
        if condition["satisfied"]:
            continue
        reasons.append(f"{condition['condition']}: {condition['detail']}")
    for entry in unequal_fields:
        reasons.append(
            f"{entry['field']} ({entry['role']}) differs in "
            f"{entry['unequal']} window case(s): "
            f"{entry['unequal_case_indexes']}")
    return {
        "claimed": claimed,
        "claim_definition": (
            "output equivalence is claimed only when the shared raw-input "
            "window covers both arms completely, both arms have the same "
            "receipt case count, the window was not truncated by the case cap, "
            "and every in-scope declared field is equal in every window case; "
            "a `compared` evidence status never implies it"),
        "conditions": conditions,
        "not_claimed_reasons": reasons,
        "unequal_declared_fields": unequal_fields,
        "not_applicable_fields": sorted(not_applicable_fields),
        "family_verdicts": family_verdicts,
        "does_not_claim": list(BOUNDARIES),
    }


def _window_block(stream: Mapping, views: Mapping[str, Mapping], *,
                  max_window_cases: int, computable: bool,
                  reason: str | None) -> dict:
    first = stream["first_divergent"]
    covers_left = computable and stream["window_cases"] == stream["left_cases"]
    covers_right = computable and stream["window_cases"] == stream["right_cases"]
    return {
        "definition": (
            "the leading receipt cases whose raw_sha256 is identical in both "
            "arms, compared in receipt order; the searches diverge by "
            "construction, so this prefix is the only per-case comparable "
            "window"),
        "raw_identity_field": RAW_IDENTITY_FIELD,
        "computable": computable,
        "not_computable_reason": reason,
        "shared_prefix_cases": stream["window_cases"] if computable else None,
        "left": {
            "receipt_cases": stream["left_cases"],
            "declared_tests": views["left"].get("declared_tests"),
            "declared_statuses": views["left"].get("declared_statuses"),
        },
        "right": {
            "receipt_cases": stream["right_cases"],
            "declared_tests": views["right"].get("declared_tests"),
            "declared_statuses": views["right"].get("declared_statuses"),
        },
        "covers": {"left": covers_left, "right": covers_right},
        "window_case_cap": max_window_cases,
        "truncated_by_window_case_cap": bool(stream["capped"]),
        "first_divergent_case": first,
        "raw_records_cross_check": stream["records_cross_check"],
    }


def _budget_pair(name: str, left_value: object, right_value: object) -> dict:
    if left_value is None or right_value is None:
        equal: bool | None = None
    else:
        equal = left_value == right_value
    return {"left": left_value, "right": right_value, "equal": equal}


def _budgets_block(views: Mapping[str, Mapping], stream: Mapping) -> dict:
    left, right = views["left"], views["right"]
    pairs = {
        "max_tests": _budget_pair("max_tests", left.get("max_tests"),
                                  right.get("max_tests")),
        "duration_seconds": _budget_pair("duration_seconds",
                                         left.get("duration_seconds"),
                                         right.get("duration_seconds")),
        "feedback_interval": _budget_pair("feedback_interval",
                                          left.get("feedback_interval"),
                                          right.get("feedback_interval")),
        "search_seed": _budget_pair("search_seed", left.get("search_seed"),
                                    right.get("search_seed")),
        "global_mutation_seed": _budget_pair(
            "global_mutation_seed", left.get("global_mutation_seed"),
            right.get("global_mutation_seed")),
        # the realized case count is *not* part of the declared budget; it is
        # reported next to it and is one of the output-equivalence conditions
        "declared_tests": _budget_pair("declared_tests",
                                       left.get("declared_tests"),
                                       right.get("declared_tests")),
    }
    budget_only = [pairs[name]["equal"] for name in BUDGET_FIELDS]
    if any(equal is False for equal in budget_only):
        same: bool | None = False
    elif all(equal is True for equal in budget_only):
        same = True
    else:
        same = None
    block = {
        "budget_fields": list(BUDGET_FIELDS),
        "left": {"run_id": left.get("run_id"),
                 "max_tests": left.get("max_tests"),
                 "duration_seconds": left.get("duration_seconds"),
                 "feedback_interval": left.get("feedback_interval"),
                 "search_seed": left.get("search_seed"),
                 "global_mutation_seed": left.get("global_mutation_seed"),
                 "declared_tests": left.get("declared_tests"),
                 "receipt_cases": stream["left_cases"],
                 "effective_search_seconds": left.get("effective_search_seconds"),
                 "elapsed_seconds": left.get("elapsed_seconds")},
        "right": {"run_id": right.get("run_id"),
                  "max_tests": right.get("max_tests"),
                  "duration_seconds": right.get("duration_seconds"),
                  "feedback_interval": right.get("feedback_interval"),
                  "search_seed": right.get("search_seed"),
                  "global_mutation_seed": right.get("global_mutation_seed"),
                  "declared_tests": right.get("declared_tests"),
                  "receipt_cases": stream["right_cases"],
                  "effective_search_seconds": right.get("effective_search_seconds"),
                  "elapsed_seconds": right.get("elapsed_seconds")},
        "same_declared_budget": same,
        "same_declared_case_count": pairs["declared_tests"]["equal"],
        "undecodable_budget_fields": sorted(
            name for name in BUDGET_FIELDS if pairs[name]["equal"] is None),
        "note": ("declared budgets are reported, never a refusal reason: two "
                 "arms under different budgets can still be compared inside "
                 "the shared window, but they cannot claim output equivalence"),
    }
    block.update(pairs)
    return block


def _arms_block(views: Mapping[str, Mapping], stream: Mapping) -> dict:
    block = {}
    for arm in ("left", "right"):
        view = views[arm]
        cases = stream[f"{arm}_cases"]
        declared = view.get("declared_tests")
        block[arm] = {
            "directory": view.get("directory"),
            "label": view.get("label"),
            "run_id": view.get("run_id"),
            "identity_document_present": view.get("identity_document_present"),
            "identity_document_sha256": view.get("identity_document_sha256"),
            "execution_mode": view.get("execution_mode"),
            "receipt_cases": cases,
            "receipt_status_counts": stream[f"{arm}_status"],
            "declared_tests": declared,
            "declared_statuses": view.get("declared_statuses"),
            "receipt_cases_match_declared_tests": (
                None if declared is None else cases == declared),
            "decoder_manifest_matches_continuous": view.get(
                "decoder_manifest_matches_continuous"),
        }
    return block


def compare_arms(left_dir: str | Path, right_dir: str | Path, *,
                 left_label: str | None = None,
                 right_label: str | None = None,
                 max_window_cases: int = DEFAULT_MAX_WINDOW_CASES,
                 max_detail_indexes: int = DEFAULT_MAX_DETAIL_INDEXES,
                 max_undeclared_fields: int = DEFAULT_MAX_UNDECLARED_FIELDS) -> dict:
    """Compare two saved run arms and return the ``arm_equivalence.v1`` document.

    The function is read-only and deterministic: the same directories produce
    byte-identical JSON.  A refusal is *returned* (``evidence_status ==
    "refused"``) with a precise ``refusal`` block rather than raised, so the
    caller can persist the diagnostic; only unreadable artifacts raise
    :class:`ArmEquivalenceInputError`.
    """
    if type(max_window_cases) is not int or max_window_cases <= 0:
        raise ValueError("max_window_cases must be a positive integer")
    if type(max_detail_indexes) is not int or max_detail_indexes <= 0:
        raise ValueError("max_detail_indexes must be a positive integer")
    if type(max_undeclared_fields) is not int or max_undeclared_fields <= 0:
        raise ValueError("max_undeclared_fields must be a positive integer")

    left_reader = _ArmReader(Path(left_dir))
    right_reader = _ArmReader(Path(right_dir))
    left_label = left_label or left_reader.directory.name
    right_label = right_label or right_reader.directory.name

    stream: dict = {
        "tallies": _new_tallies(),
        "left_cases": 0,
        "right_cases": 0,
        "left_status": {},
        "right_status": {},
        "window_cases": 0,
        "capped": False,
        "first_divergent": None,
        "records_cross_check": {"field": RAW_RECORDS_FIELD, "compared": 0,
                               "agreed": 0, "disagreed": 0,
                               "first_disagreement_case_index": None},
        "undeclared": {},
        "undeclared_skipped": [],
        "undeclared_truncated": False,
    }
    refusal: dict | None = None
    missing = [arm for arm, reader in (("left", left_reader),
                                       ("right", right_reader))
               if not reader.exists(RECEIPTS_NAME)]
    if missing:
        refusal = {
            "code": "no_receipts",
            "reason": (f"{RECEIPTS_NAME} is missing in the "
                       f"{'/'.join(missing)} arm(s), so the case sequences "
                       "cannot be aligned at all"),
            "detail": {"missing_arms": missing,
                       "left_directory": str(left_reader.directory),
                       "right_directory": str(right_reader.directory)},
        }
    else:
        stream = _stream_arms(left_reader, right_reader,
                             max_window_cases=max_window_cases,
                             max_detail_indexes=max_detail_indexes,
                             max_undeclared_fields=max_undeclared_fields)

    views = {"left": _arm_view(left_reader, left_label),
             "right": _arm_view(right_reader, right_label)}
    for arm in ("left", "right"):
        views[arm]["receipt_cases"] = stream[f"{arm}_cases"]
        views[arm]["receipt_status_counts"] = stream[f"{arm}_status"]
    identity = _identity_comparison(views["left"], views["right"])
    if refusal is None:
        refusal = _refusal_check(stream, views, identity)

    computable = refusal is None or refusal["code"] == "zero_shared_prefix"
    window = _window_block(
        stream, views, max_window_cases=max_window_cases,
        computable=computable,
        reason=None if computable else refusal["reason"])
    families = _family_blocks(stream, identity)
    document = {
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "refused" if refusal is not None else "compared",
        "refusal": refusal,
        "definition": {
            "window": (
                "the shared raw-input prefix computed from receipts by "
                f"{RAW_IDENTITY_FIELD}, compared in receipt order"),
            "per_case_field_equivalence": (
                "a declared field is `equal` when both arms carry a non-null "
                "value and the canonical JSON bytes are identical; it is "
                "`unequal` when both carry a value and the canonical bytes "
                "differ; any other combination is `missing_left`, "
                "`missing_right` or `missing_both` and is never equality"),
            "field_verdicts": {
                "equivalent": "every window case is `equal`",
                "not_equivalent": "at least one window case is `unequal`",
                "unknown": ("no case is `unequal` but at least one case is "
                            "unreadable, or the window is empty"),
                "not_applicable": ("the field is null/absent in every window "
                                   "case on both arms and therefore carries "
                                   "no information"),
            },
            "family_verdict_rule": (
                "the worst verdict of the family's in-scope verdict-role "
                "fields (not_equivalent > unknown > equivalent); context-role "
                "fields are reported but cannot define a verdict"),
            "comparability_preconditions": (
                "a family whose declared semantics field (record_semantics, "
                "total_local_ticks_semantics, clock_model) differs between the "
                "arms is `unknown`, never `equivalent`"),
            "refusals": list(REFUSAL_CODES),
        },
        "arms": _arms_block(views, stream),
        "identity": identity,
        "budgets": _budgets_block(views, stream),
        "window": window,
        "families": families,
        "verdict": {
            "families": {block["family"]: block["verdict"]
                         for block in families},
            "equivalent_families": sorted(
                block["family"] for block in families
                if block["verdict"] == VERDICT_EQUIVALENT),
            "not_equivalent_families": sorted(
                block["family"] for block in families
                if block["verdict"] == VERDICT_NOT_EQUIVALENT),
            "unknown_families": sorted(
                block["family"] for block in families
                if block["verdict"] == VERDICT_UNKNOWN),
            "declared_field_set": {
                family: {"verdict": list(FAMILY_FIELDS[family]["verdict"]),
                         "context": list(FAMILY_FIELDS[family]["context"])}
                for family in FIELD_FAMILIES},
        },
        "output_equivalence": _output_equivalence(window, stream, families),
        "outside_declared_projection": _outside_projection_block(
            stream, max_undeclared_fields=max_undeclared_fields),
        "read_scope": {
            "artifacts_read": {"left": left_reader.as_read_scope(),
                               "right": right_reader.as_read_scope()},
            "streamed_receipts": True,
            "max_window_cases": max_window_cases,
            "window_case_cap_reached": bool(stream["capped"]),
            "full_trace_loaded": False,
            "note": ("the comparator opens only receipts.jsonl (streamed line "
                     "by line), report.json, online_run_identity.json and "
                     "decoder_manifest.json; trace containers "
                     "(online_final_trace.json, online_events.jsonl, "
                     "online_events.zlib) are never opened"),
        },
        "boundaries": list(BOUNDARIES),
    }
    return document


# ---------------------------------------------------------------------------
# markdown rendering
# ---------------------------------------------------------------------------


def _format_value(value: object, *, limit: int = 72) -> str:
    if value is None:
        return "-"
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _table(lines: list[str], header: Sequence[str],
           rows: Sequence[Sequence[object]]) -> None:
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("---" for _ in header) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    lines.append("")


def render_markdown(document: Mapping) -> str:
    """Render one comparison document; deterministic and RTL-free."""
    lines: list[str] = []
    schema = document.get("schema_version")
    lines.append(f"# Arm equivalence ({schema})")
    lines.append("")
    arms = document["arms"]
    lines.append(f"- left arm: `{arms['left']['directory']}` "
                 f"(label `{arms['left']['label']}`, run_id "
                 f"`{arms['left']['run_id']}`)")
    lines.append(f"- right arm: `{arms['right']['directory']}` "
                 f"(label `{arms['right']['label']}`, run_id "
                 f"`{arms['right']['run_id']}`)")
    lines.append("")
    if document["evidence_status"] == "refused":
        refusal = document["refusal"]
        lines.append(f"## Refused (`{refusal['code']}`)")
        lines.append("")
        lines.append(refusal["reason"])
        lines.append("")
    else:
        lines.append("## Compared")
        lines.append("")
        lines.append("The arms share a decodable identity and a non-empty "
                     "shared raw-input window.")
        lines.append("")

    window = document["window"]
    lines.append("## Comparison window")
    lines.append("")
    lines.append(window["definition"])
    lines.append("")
    _table(lines, ["quantity", "left", "right", "shared"],
           [["receipt cases", window["left"]["receipt_cases"],
             window["right"]["receipt_cases"], window["shared_prefix_cases"]],
            ["declared tests", _format_value(window["left"]["declared_tests"]),
             _format_value(window["right"]["declared_tests"]), "-"],
            ["declared statuses", _format_value(window["left"]["declared_statuses"]),
             _format_value(window["right"]["declared_statuses"]), "-"],
            ["covered by the window", window["covers"]["left"],
             window["covers"]["right"], "-"],
            ["window case cap", window["window_case_cap"], window["window_case_cap"],
             f"reached={window['truncated_by_window_case_cap']}"]])
    divergent = window["first_divergent_case"]
    if divergent:
        lines.append("First divergence: "
                     f"case {divergent['case_index']} "
                     f"({divergent['divergence_reason']}), left raw "
                     f"`{divergent['left_raw_sha256']}`, right raw "
                     f"`{divergent['right_raw_sha256']}`.")
        lines.append("")
    check = window["raw_records_cross_check"]
    lines.append(f"Raw-records cross-check ({check['field']}): "
                 f"{check['agreed']}/{check['compared']} agreed.")
    lines.append("")

    budgets = document["budgets"]
    lines.append("## Declared budgets")
    lines.append("")
    _table(lines, ["quantity", "left", "right", "equal"],
           [[name, _format_value(budgets[name]["left"]),
             _format_value(budgets[name]["right"]), budgets[name]["equal"]]
            for name in BUDGET_FIELDS]
           + [["declared_tests (realized case count)",
               _format_value(budgets["declared_tests"]["left"]),
               _format_value(budgets["declared_tests"]["right"]),
               budgets["declared_tests"]["equal"]]])
    lines.append(f"same declared budget: {budgets['same_declared_budget']}; "
                 f"same declared case count: "
                 f"{budgets['same_declared_case_count']}")
    lines.append("")

    lines.append("## Per-family equivalence")
    lines.append("")
    rows = []
    for block in document["families"]:
        totals = {"equal": 0, "unequal": 0, "missing_left": 0,
                  "missing_right": 0, "missing_both": 0}
        for field in block["fields"]:
            if not field["in_scope"] or field["role"] != "verdict":
                continue
            for key in totals:
                totals[key] += field[key]
        rows.append([block["family"], block["verdict"],
                     block["verdict_driver_field"] or "-", totals["equal"],
                     totals["unequal"], totals["missing_left"],
                     totals["missing_right"], totals["missing_both"],
                     block["reason"]])
    _table(lines, ["family", "verdict", "driver", "equal", "unequal",
                   "miss L", "miss R", "miss both", "reason"], rows)
    lines.append("The counts above sum the family's in-scope *verdict-role* "
                 "fields; context-role fields are listed per field below and "
                 "never define a family verdict.")
    lines.append("")

    lines.append("## Per-field detail")
    lines.append("")
    field_rows = []
    for block in document["families"]:
        for field in block["fields"]:
            field_rows.append([
                f"{block['family']}.{field['name']}", field["role"],
                field["in_scope"], field["verdict"], field["equal"],
                field["unequal"], field["missing_left"],
                field["missing_right"], field["missing_both"],
                _format_value(field["unequal_case_indexes"] or
                              field["missing_case_indexes"], limit=32)])
    _table(lines, ["field", "role", "in scope", "verdict", "equal", "unequal",
                   "miss L", "miss R", "miss both", "case indexes"],
           field_rows)

    claim = document["output_equivalence"]
    lines.append(f"## Output equivalence claimed = {claim['claimed']}")
    lines.append("")
    lines.append(claim["claim_definition"])
    lines.append("")
    _table(lines, ["condition", "satisfied", "detail"],
           [[condition["condition"], condition["satisfied"],
             condition["detail"]] for condition in claim["conditions"]])
    if claim["not_claimed_reasons"]:
        lines.append("Why output equivalence is not claimed:")
        lines.append("")
        for reason in claim["not_claimed_reasons"]:
            lines.append(f"- {reason}")
        lines.append("")
    if claim["not_applicable_fields"]:
        lines.append("Declared fields that carry no information in this window "
                     "(reported, never counted as equal): "
                     + ", ".join(f"`{name}`"
                                 for name in claim["not_applicable_fields"]))
        lines.append("")

    lines.append("## What an `equivalent` verdict does NOT claim")
    lines.append("")
    for boundary in document["boundaries"]:
        lines.append(f"- {boundary}")
    lines.append("")
    outside = document["outside_declared_projection"]
    lines.append("## Receipt fields outside the declared projection")
    lines.append("")
    lines.append(outside["note"])
    lines.append("")
    lines.append("Difference classes: "
                 + ", ".join(f"{name}={count}" for name, count
                             in sorted(outside["difference_classes"].items()))
                 + f"; tracked {len(outside['fields'])} of at most "
                 f"{outside['max_tracked_fields']} field(s), truncated="
                 f"{outside['truncated']}.")
    lines.append("")
    if outside["fields_with_differences"]:
        _table(lines, ["field", "class", "equal", "unequal", "miss L",
                       "miss R", "miss both", "case indexes"],
               [[entry["field"], entry["classification"], entry["equal"],
                 entry["unequal"], entry["missing_left"],
                 entry["missing_right"], entry["missing_both"],
                 _format_value(entry["unequal_case_indexes"] or
                               entry["missing_case_indexes"], limit=32)]
                for entry in outside["fields"]
                if entry["field"] in outside["fields_with_differences"]])
    else:
        lines.append("No field outside the declared projection differs inside "
                     "the window.")
        lines.append("")
    lines.append("Read scope: "
                 + ", ".join(f"`{name}`"
                             for name in document["read_scope"]
                             ["artifacts_read"]["left"])
                 + " (left); "
                 + ", ".join(f"`{name}`"
                             for name in document["read_scope"]
                             ["artifacts_read"]["right"])
                 + " (right). No trace container was opened.")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "ArmEquivalenceInputError",
    "BOUNDARIES",
    "BUDGET_FIELDS",
    "DEFAULT_MAX_DETAIL_INDEXES",
    "DEFAULT_MAX_UNDECLARED_FIELDS",
    "DEFAULT_MAX_WINDOW_CASES",
    "FAMILY_FIELDS",
    "FAMILY_PRECONDITIONS",
    "FIELD_FAMILIES",
    "IDENTITY_COMPARE_FIELDS",
    "IDENTITY_CONTEXT_FIELDS",
    "REFUSAL_CODES",
    "SCHEMA_VERSION",
    "canonical_sha256",
    "compare_arms",
    "render_markdown",
]
