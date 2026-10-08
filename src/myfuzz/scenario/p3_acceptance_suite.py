"""P3 acceptance **suite**: an honest per-item union of evidence across runs.

The frozen consumer :mod:`myfuzz.scenario.p3_acceptance` judges **one** saved
run directory and answers with a ``p3_acceptance_report.v1`` document whose gate
is ready only when that single run measured and met every critical P3 item.
Reality is weaker: no saved run in this repository satisfies all seven critical
items at once, while different runs prove different items.  This module keeps
that fact visible instead of hiding it behind a pass:

* every input is a run declaration that names its own **role** explicitly
  (``{"role": ..., "run_dir": ..., "compare_run": ...|None}`` or
  :class:`SuiteRun`); a role is never guessed from a file name;
* the frozen producer is called once per declared run with the declared
  ``compare_run``, and its document is the only source of per-item verdicts --
  this module re-implements no criterion;
* an item is ``met`` for the suite only when **at least one** run has
  ``measured=true`` *and* ``met=true`` on it, and the report lists every run
  that proves it together with an ``evidence_digest`` and the JSON field paths
  inside that run's report that carry the proof;
* a run that measured the item without meeting it is **never** hidden: it stays
  in ``per_run``, in ``not_met_by`` and (when relevant) in
  ``excluded_from_met_by``;
* ``finding_stops_and_replays`` only counts from a ``controlled_fault`` run that
  declares a ``compare_run``, and the item is annotated as **injected-fault
  calibration**, not a naturally discovered RTL defect;
* the suite-level ``gate.exit_code`` is ``0`` only when every critical item has
  at least one proving run; it is ``2`` otherwise, when a declared run's report
  could not be produced at all, when runs disagree about the frozen producer
  version, and when a caller-declared ``engine_hashes`` entry does not match the
  module actually in use.  Exit ``0`` is **not** a single-run P3 pass, and the
  gate says so in its own ``limits``.

Nothing here renders a harness, starts a process or touches RTL: every quantity
comes from saved artifacts plus the frozen consumer's declaration-only checks.

Digest recipe (also reported verbatim as ``EVIDENCE_DIGEST_RECIPE`` and as
``engine.digest_recipe``)::

    subject = {
      "schema_version": "p3_acceptance_suite.evidence.v1",
      "suite_schema_version": "p3_acceptance_suite.v1",
      "run_dir": <the run_dir exactly as the declaration spelled it>,
      "report_schema_version": <that run's report schema_version>,
      "run_identity_sha256": <that run's report run_identity_sha256>,
      "manifest_identity_sha256": <that run's report manifest.identity_sha256>,
      "engine": {"p3_acceptance": <sha256>, "p3_acceptance_suite": <sha256>},
      "item": {"key": ..., "measured": ..., "met": ..., "reason": ...,
               "evidence": <that item's evidence document>}}
    evidence_digest = sha256(utf-8(json.dumps(subject, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True)))

so anyone can recompute an entry from the run's own report (regenerate it with
``scripts/run_p3_acceptance_gate.py analyze --run-dir DIR`` or from the
``--reports-dir`` dump of :mod:`scripts.run_p3_acceptance_suite`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import importlib
import json
import math
import os
from pathlib import Path

from .p3_acceptance import (
    CRITERIA,
    EXIT_NOT_READY,
    EXIT_READY,
    SCHEMA_VERSION as REPORT_SCHEMA_VERSION,
    p3_acceptance_report,
)

SCHEMA_VERSION = "p3_acceptance_suite.v1"
SUITE_MODULE = __name__
FROZEN_MODULE = "myfuzz.scenario.p3_acceptance"
PRODUCER_MODULES = (FROZEN_MODULE, SUITE_MODULE)

#: The frozen report names its engine entries by short module name
#: (``engine.p3_acceptance``); a caller may declare either spelling.
ENGINE_ALIASES = {"p3_acceptance": FROZEN_MODULE,
                  "p3_acceptance_suite": SUITE_MODULE}

#: The one frozen criterion the frozen consumer already marks non-critical.
RTL_EVENT_LEVEL_KEY = "chunk_split_invariance.rtl_event_level"
NON_CRITICAL_ITEMS = frozenset({RTL_EVENT_LEVEL_KEY})

#: The frozen critical set, derived from the frozen consumer's own CRITERIA
#: mapping (declaration order preserved) instead of a copied literal.
CRITICAL_ITEMS = tuple(key for key in CRITERIA if key not in NON_CRITICAL_ITEMS)

#: The only role allowed to prove the replay item, and only with a compare_run.
CONTROLLED_FAULT_ROLE = "controlled_fault"

#: Roles a declaration may name.  A role is a declaration, not a measurement:
#: the suite never infers it from a directory name and never verifies it.
LEGAL_ROLES = frozenset({
    "primary", "controlled_fault", "cross_case", "feedback", "chunk_split",
    "execution_identity", "store_then_load", "supporting"})

FINDING_ITEM = "finding_stops_and_replays"
DECLARATION_KEYS = frozenset({"role", "run_dir", "compare_run"})
MAX_EVIDENCE_FIELDS = 96
EVIDENCE_DIGEST_SCHEMA = "p3_acceptance_suite.evidence.v1"
ENGINE_SCHEMA = "p3_acceptance_suite_engine.v1"

EVIDENCE_DIGEST_RECIPE = (
    "evidence_digest = sha256(utf-8(json.dumps(subject, sort_keys=True, "
    "separators=(\",\", \":\"), ensure_ascii=True))) where subject = "
    "{schema_version: \"p3_acceptance_suite.evidence.v1\", suite_schema_version, "
    "run_dir (exactly as declared), report_schema_version, "
    "run_identity_sha256, manifest_identity_sha256, engine: {p3_acceptance: "
    "sha256, p3_acceptance_suite: sha256}, item: {key, measured, met, reason, "
    "evidence}} read from that run's p3_acceptance_report.v1 document; "
    "regenerate the run's report with scripts/run_p3_acceptance_gate.py analyze "
    "--run-dir DIR [--compare-run DIR], or read the --reports-dir dump of this "
    "suite.")


class P3AcceptanceSuiteError(ValueError):
    """A run declaration, artifact or engine binding the suite cannot honour."""


# ---------------------------------------------------------------------------
# run declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SuiteRun:
    """One explicitly declared run: a role, a directory and an optional replay.

    ``compare_run`` is the companion run that reproduced a finding in a fresh
    harness; it is required for a ``controlled_fault`` declaration to count
    toward ``finding_stops_and_replays``.
    """

    role: str
    run_dir: str
    compare_run: str | None = None


@dataclass(frozen=True)
class _Declaration:
    role: str
    run_dir: str
    compare_run: str | None
    resolved_run_dir: str
    resolved_compare_run: str | None


def _text(value: object, *, field: str, index: int) -> str:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value.strip():
        raise P3AcceptanceSuiteError(
            f"run declaration {index} has no {field}: {value!r}")
    return value


def _declarations(runs) -> list[_Declaration]:
    if isinstance(runs, (str, bytes, bytearray)) or not isinstance(runs,
                                                                 Sequence):
        raise P3AcceptanceSuiteError(
            "runs must be a sequence of run declarations "
            "({'role': ..., 'run_dir': ..., 'compare_run': ...} or SuiteRun), "
            f"got {type(runs).__name__}")
    if not runs:
        raise P3AcceptanceSuiteError("at least one run declaration is required")
    declarations: list[_Declaration] = []
    roles: set[str] = set()
    for index, entry in enumerate(runs):
        if isinstance(entry, SuiteRun):
            role_value = entry.role
            run_dir_value = entry.run_dir
            compare_value = entry.compare_run
        elif isinstance(entry, Mapping):
            unknown = sorted(str(key) for key in entry
                             if str(key) not in DECLARATION_KEYS)
            if unknown:
                raise P3AcceptanceSuiteError(
                    f"run declaration {index} carries unknown key(s) {unknown}; "
                    "a declaration is exactly role/run_dir/compare_run")
            role_value = entry.get("role")
            run_dir_value = entry.get("run_dir")
            compare_value = entry.get("compare_run")
        else:
            raise P3AcceptanceSuiteError(
                f"run declaration {index} is not a run declaration: expected a "
                "mapping with role/run_dir or a SuiteRun, got "
                f"{type(entry).__name__}")
        role = _text(role_value, field="role", index=index)
        if role not in LEGAL_ROLES:
            raise P3AcceptanceSuiteError(
                f"run declaration {index} declares role {role!r}, which is not "
                f"a legal role; legal roles: {sorted(LEGAL_ROLES)}")
        if role in roles:
            raise P3AcceptanceSuiteError(
                f"duplicate role {role!r} in run declaration {index}; every "
                "declared run must carry its own role")
        roles.add(role)
        run_dir = _text(run_dir_value, field="run_dir", index=index)
        if not Path(run_dir).is_dir():
            raise P3AcceptanceSuiteError(
                f"run directory does not exist: {run_dir}")
        compare_run = None
        if compare_value is not None:
            compare_run = _text(compare_value, field="compare_run", index=index)
            if not Path(compare_run).is_dir():
                raise P3AcceptanceSuiteError(
                    f"comparison run directory does not exist: {compare_run}")
            if Path(compare_run).resolve() == Path(run_dir).resolve():
                raise P3AcceptanceSuiteError(
                    f"run declaration {index} ({role}) names the same directory "
                    f"as run_dir and compare_run ({run_dir}); a compare_run must "
                    "be a different run directory")
        declarations.append(_Declaration(
            role=role, run_dir=run_dir, compare_run=compare_run,
            resolved_run_dir=str(Path(run_dir).resolve()),
            resolved_compare_run=(None if compare_run is None
                                  else str(Path(compare_run).resolve()))))
    return declarations


# ---------------------------------------------------------------------------
# module identity and canonical digests
# ---------------------------------------------------------------------------


def _module_identity(name: str) -> dict | None:
    """Path and sha256 of one module file, so a verdict names its producer."""
    try:
        module = importlib.import_module(name)
        path = Path(getattr(module, "__file__", "") or "")
        if not path.is_file():
            return None
        return {"module": name, "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    except Exception:  # pragma: no cover - import topology change
        return None


def _engine_identity(name: str) -> dict:
    identity = _module_identity(name)
    if identity is None or not identity.get("sha256"):  # pragma: no cover
        raise P3AcceptanceSuiteError(
            f"the engine module {name!r} has no readable file, so no evidence "
            "can be bound to a producer version")
    return identity


def _jsonable(value: object, *, depth: int = 0) -> object:
    """A deterministic JSON-safe copy of one artifact value.

    Artifacts are JSON, but a producer version could hand back a Mapping with
    non-string keys, a tuple or a non-finite float; none of those may make the
    digest unreproducible, so each is replaced by an explicit marker instead of
    being dropped.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"$non_finite": repr(value)}
    if depth > 64:
        return {"$depth_limit": True}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(value[key], depth=depth + 1)
                for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_jsonable(entry, depth=depth + 1) for entry in value]
    return {"$unserializable": f"{type(value).__name__}: {value!r}"[:200]}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _item_document(report: Mapping, key: str) -> Mapping | None:
    """The frozen consumer's item document for one key.

    The seven critical keys are top-level; a dotted key such as
    ``chunk_split_invariance.rtl_event_level`` lives in the parent item's
    ``evidence`` document.
    """
    direct = report.get(key)
    if isinstance(direct, Mapping):
        return direct
    if "." in key:
        head, _, tail = key.partition(".")
        parent = report.get(head)
        if isinstance(parent, Mapping):
            evidence = parent.get("evidence")
            if isinstance(evidence, Mapping):
                nested = evidence.get(tail)
                if isinstance(nested, Mapping):
                    return nested
    return None


def _manifest_identity(report: Mapping) -> str | None:
    manifest = report.get("manifest")
    if not isinstance(manifest, Mapping):
        return None
    value = manifest.get("identity_sha256")
    return value if isinstance(value, str) else None


def item_evidence_digest(report: Mapping, key: str, *,
                         run_dir: str | None = None) -> str:
    """The sha256 that binds one item's evidence to its run and both engines.

    The subject is documented in :data:`EVIDENCE_DIGEST_RECIPE`; recomputing it
    from the run's own ``p3_acceptance_report.v1`` document must reproduce this
    value exactly.
    """
    if not isinstance(report, Mapping):
        raise P3AcceptanceSuiteError(
            f"a p3_acceptance_report.v1 mapping is required, got "
            f"{type(report).__name__}")
    item = _item_document(report, key)
    if item is None:
        raise P3AcceptanceSuiteError(
            f"the report has no item document for {key!r}")
    subject_run_dir = run_dir if run_dir is not None else report.get("run_dir")
    subject = {
        "schema_version": EVIDENCE_DIGEST_SCHEMA,
        "suite_schema_version": SCHEMA_VERSION,
        "run_dir": subject_run_dir,
        "report_schema_version": report.get("schema_version"),
        "run_identity_sha256": report.get("run_identity_sha256"),
        "manifest_identity_sha256": _manifest_identity(report),
        "engine": {"p3_acceptance": _engine_identity(FROZEN_MODULE)["sha256"],
                   "p3_acceptance_suite": _engine_identity(SUITE_MODULE)["sha256"]},
        "item": {"key": key, "measured": item.get("measured"),
                 "met": item.get("met"), "reason": item.get("reason"),
                 "evidence": item.get("evidence")},
    }
    return hashlib.sha256(_canonical_bytes(subject)).hexdigest()


def _evidence_field_paths(item: Mapping | None, *,
                          maximum: int = MAX_EVIDENCE_FIELDS
                          ) -> tuple[list[str], bool]:
    """Every non-null leaf path of one item document, as a JSON path.

    The paths are relative to the run's ``p3_acceptance_report.v1`` document and
    each one holds a non-null value there, so a reader can resolve them in the
    regenerated report (or in the ``--reports-dir`` dump).  Scalar paths are
    listed before indexed ones, so a long array (``case_ids[0]`` ...) can never
    push the decisive scalar fields out of a truncated list.
    """
    if item is None:
        return [], False
    scalar: list[str] = []
    indexed: list[str] = []

    def walk(value: object, prefix: str) -> None:
        if isinstance(value, Mapping):
            for key in sorted(value, key=str):
                walk(value[key], f"{prefix}.{key}" if prefix else str(key))
        elif isinstance(value, (list, tuple)):
            for index, entry in enumerate(value):
                walk(entry, f"{prefix}[{index}]")
        elif value is not None:
            (indexed if "[" in prefix else scalar).append(prefix)

    walk(item.get("evidence"), "")
    verdict_paths = []
    for field in ("measured", "met"):
        if item.get(field) is not None:
            verdict_paths.append(field)
    reason = item.get("reason")
    if isinstance(reason, str) and reason:
        verdict_paths.append("reason")
    ordered = sorted(scalar) + sorted(indexed)
    # The measured/met/reason paths always stay in the list: they are the
    # verdict the evidence is attached to, so room is reserved for them first.
    room = max(0, maximum - len(verdict_paths))
    truncated = len(ordered) > room or len(scalar) + len(indexed) > room
    return ordered[:room] + verdict_paths, truncated


# ---------------------------------------------------------------------------
# per-run evaluation
# ---------------------------------------------------------------------------


def _status(measured: object, met: object) -> str:
    """The suite's three-valued view of one frozen item document.

    ``met`` requires an explicit ``measured is True`` **and** ``met is True``;
    a criterion that was measured but left undecided (``met`` null) is never a
    pass and counts as ``unmet`` here (its ``measured``/``met``/``reason`` stay
    visible in ``per_run``).
    """
    if measured is not True:
        return "unmeasured"
    if met is True:
        return "met"
    return "unmet"


def _evaluate(declaration: _Declaration) -> dict:
    """One declared run: the frozen report call and its per-item details."""
    record = {
        "role": declaration.role,
        "run_dir": declaration.run_dir,
        "resolved_run_dir": declaration.resolved_run_dir,
        "compare_run": declaration.compare_run,
        "resolved_compare_run": declaration.resolved_compare_run,
        "report_schema_version": None,
        "report_run_id": None,
        "report_run_identity_sha256": None,
        "report_compare_run_dir": None,
        "frozen_gate_exit_code": None,
        "frozen_gate_summary": None,
        "frozen_critical_missing": None,
        "frozen_critical_unmet": None,
        "limit_count": None,
        "critical_met": [],
        "critical_missing": [],
        "critical_unmet": [],
        "error": None,
        "report": None,
        "items": {},
    }
    try:
        report = p3_acceptance_report(declaration.run_dir,
                                      compare_run=declaration.compare_run)
    except Exception as exc:
        # A declared run whose evidence cannot be read is recorded verbatim and
        # contributes nothing; the gate is forced closed by the caller.
        record["error"] = {"type": type(exc).__name__, "message": str(exc)}
        report = None
    if report is not None and not isinstance(report, Mapping):
        record["error"] = {
            "type": "TypeError",
            "message": "the producer did not return a report mapping: "
                       f"{type(report).__name__}"}
        report = None
    if report is not None:
        record["report"] = report
        record["report_schema_version"] = report.get("schema_version")
        record["report_run_id"] = report.get("run_id")
        record["report_run_identity_sha256"] = report.get("run_identity_sha256")
        record["report_compare_run_dir"] = report.get("compare_run_dir")
        gate = report.get("gate")
        if isinstance(gate, Mapping):
            record["frozen_gate_exit_code"] = gate.get("exit_code")
            record["frozen_gate_summary"] = gate.get("summary")
            record["frozen_critical_missing"] = gate.get("critical_missing")
            record["frozen_critical_unmet"] = gate.get("critical_unmet")
        limits = report.get("limits")
        record["limit_count"] = len(limits) if isinstance(limits, list) else None
    for key in CRITICAL_ITEMS + (RTL_EVENT_LEVEL_KEY,):
        item = _item_document(report, key) if report is not None else None
        if item is None:
            record["items"][key] = {
                "key": key, "status": "unmeasured", "measured": False,
                "met": None,
                "criterion": CRITERIA.get(key),
                "reason": (record["error"]["message"] if record["error"]
                           else "the frozen report carries no item document for "
                                "this key"),
                "evidence_digest": None, "evidence_fields": [],
                "evidence_fields_truncated": False}
        else:
            measured = item.get("measured")
            met = item.get("met")
            fields, fields_truncated = _evidence_field_paths(item)
            record["items"][key] = {
                "key": key,
                "status": _status(measured, met),
                "measured": measured if isinstance(measured, bool) else False,
                "met": met if isinstance(met, bool) else None,
                "criterion": item.get("criterion") or CRITERIA.get(key),
                "reason": item.get("reason"),
                "evidence_digest": item_evidence_digest(
                    report, key, run_dir=declaration.run_dir),
                "evidence_fields": fields,
                "evidence_fields_truncated": fields_truncated}
    critical_items = record["items"]
    record["critical_met"] = [key for key in CRITICAL_ITEMS
                              if critical_items[key]["status"] == "met"]
    record["critical_missing"] = [key for key in CRITICAL_ITEMS
                                  if critical_items[key]["status"] == "unmeasured"]
    record["critical_unmet"] = [key for key in CRITICAL_ITEMS
                                if critical_items[key]["status"] == "unmet"]
    return record


def _disqualification(role: str, key: str, compare_run: str | None
                      ) -> str | None:
    """Why a run may not count for one item, or ``None`` when it may."""
    if key != FINDING_ITEM:
        return None
    if role != CONTROLLED_FAULT_ROLE:
        return (f"role {role!r} is not {CONTROLLED_FAULT_ROLE!r}; the replay "
                "item is only counted from a controlled-fault calibration run, "
                "whatever this run's own report claims")
    if not compare_run:
        return ("this controlled-fault declaration names no compare_run, so the "
                "fresh-harness replay half is not declared and the item cannot "
                "be counted as proven")
    return None


def _per_run_detail(record: Mapping, declaration: _Declaration, key: str) -> dict:
    item = record["items"][key]
    return {
        "role": declaration.role,
        "run_dir": declaration.run_dir,
        "resolved_run_dir": declaration.resolved_run_dir,
        "compare_run": declaration.compare_run,
        "status": item["status"], "measured": item["measured"],
        "met": item["met"], "reason": item["reason"],
        "criterion": item["criterion"],
        "evidence_digest": item["evidence_digest"],
        "evidence_fields": item["evidence_fields"],
        "evidence_fields_truncated": item["evidence_fields_truncated"],
        "frozen_gate_exit_code": record["frozen_gate_exit_code"]}


def _aggregate_item(key: str, records: list[dict],
                    declarations: list[_Declaration]) -> dict:
    met_by: list[dict] = []
    not_met_by: list[dict] = []
    excluded: list[dict] = []
    per_run: dict[str, dict] = {}
    measured_by: list[str] = []
    undecided_by: list[str] = []
    for record, declaration in zip(records, declarations):
        item = record["items"][key]
        detail = _per_run_detail(record, declaration, key)
        per_run[declaration.role] = detail
        if item["measured"] and item["met"] is None:
            undecided_by.append(declaration.role)
        if item["measured"]:
            measured_by.append(declaration.role)
        disqualified = _disqualification(declaration.role, key,
                                         declaration.compare_run)
        # An entry here means the run's own report *claimed* the item and the
        # suite refuses to count it; a run that never measured the item is not
        # an excluded claim and stays in not_met_by alone.
        refused = (disqualified
                   if (item["measured"] is True and item["met"] is True)
                   else None)
        if refused is not None:
            excluded.append({"role": declaration.role,
                             "run_dir": declaration.run_dir,
                             "reason": refused})
        if (item["status"] == "met" and disqualified is None):
            met_by.append({
                "role": declaration.role,
                "run_dir": declaration.run_dir,
                "resolved_run_dir": declaration.resolved_run_dir,
                "compare_run": declaration.compare_run,
                "evidence_digest": item["evidence_digest"],
                "evidence_fields": item["evidence_fields"],
                "evidence_fields_truncated": item["evidence_fields_truncated"],
                "report_schema_version": record["report_schema_version"],
                "report_run_id": record["report_run_id"],
                "report_run_identity_sha256": record["report_run_identity_sha256"],
                "manifest_identity_sha256": _manifest_identity(
                    record["report"] or {}),
                "frozen_gate_exit_code": record["frozen_gate_exit_code"],
                "counts_as": ("injected_fault_calibration"
                              if key == FINDING_ITEM else "artifact_measurement"),
                "note": (None if key != FINDING_ITEM else
                         "counted only because this declaration is a "
                         "controlled_fault calibration with a compare_run")})
        elif item["status"] != "met" or disqualified is not None:
            not_met_by.append({"role": declaration.role,
                               "run_dir": declaration.run_dir,
                               "status": item["status"],
                               "measured": item["measured"], "met": item["met"],
                               "reason": item["reason"],
                               "excluded_reason": refused})
    if met_by:
        status = "met"
    elif all(entry["status"] == "unmeasured" for entry in per_run.values()):
        status = "unmeasured"
    else:
        status = "unmet"
    injected = key == FINDING_ITEM
    document = {
        "key": key,
        "criterion": next(
            (entry["criterion"] for entry in per_run.values()
             if entry.get("criterion")), CRITERIA.get(key)),
        "critical": key in CRITICAL_ITEMS,
        "status": status,
        "met_by_at_least_one_run": bool(met_by),
        "met_by": met_by,
        "not_met_by": not_met_by,
        "excluded_from_met_by": excluded,
        "measured_by": measured_by,
        "undecided_by": undecided_by,
        "per_run": per_run,
        "proof_scope": ("per-item union across the declared runs; a run that "
                        "did not prove this item stays in per_run/not_met_by"),
        "injected_calibration": bool(injected and met_by),
        "evidence_kind": (("injected_fault_calibration" if met_by else None)
                          if injected else
                          ("artifact_measurement" if met_by else None)),
        "caveat": (None if not injected else
                   "finding_stops_and_replays is proven here by an injected "
                   "fault calibrated on purpose (role "
                   f"{CONTROLLED_FAULT_ROLE!r} with a compare_run); it shows "
                   "that an injected finding stops case acceptance and that the "
                   "saved prefix replays in a fresh harness -- it is not "
                   "evidence that a natural RTL defect was discovered"),
    }
    return document


# ---------------------------------------------------------------------------
# limits and gate
# ---------------------------------------------------------------------------


def _limit(limits: list[dict], quantity: str, reason: str) -> None:
    limits.append({"quantity": quantity, "reason": reason})


def _gate_limits(records, declarations, coverage, satisfying, verification,
                 engine_groups, errors) -> list[dict]:
    limits: list[dict] = []
    if satisfying:
        _limit(limits, "single_run_vs_cross_run_union",
               f"{len(satisfying)} declared run(s) prove every critical item on "
               f"their own ({', '.join(satisfying)}); the suite still reports a "
               "per-item union across runs, which is weaker than the plan's "
               "single-session P3 condition -- gate.exit_code 0 is not a "
               "single-run pass")
    else:
        counts = ", ".join(
            f"{role}={len(coverage[role]['critical_met'])}/"
            f"{len(CRITICAL_ITEMS)}" for role in coverage)
        _limit(limits, "single_run_vs_cross_run_union",
               "no declared run proves all critical P3 items itself (per-run "
               f"coverage: {counts}); every verdict below is a union across "
               "runs, so gate.exit_code 0 would mean only that each critical "
               "item has at least one proving run -- it is never a single-run "
               "P3 pass and this fact is recorded here on purpose")
    _limit(limits, "finding_stops_and_replays.calibration",
           "the replay item is only counted from a run declared with role "
           f"{CONTROLLED_FAULT_ROLE!r} that also declares compare_run; that run "
           "is an injected-fault calibration, so the item proves the "
           "stop/save/replay mechanism, never that a natural RTL defect was "
           "discovered")
    _limit(limits, "role_declaration",
           "roles are caller declarations: the suite never guesses a role from "
           "a directory name and never verifies why a run was given one, so a "
           "mis-declared role is reported as evidence for that role")
    _limit(limits, RTL_EVENT_LEVEL_KEY,
           "this key is not in the frozen critical set; it stays null for a "
           "saved run (the real-RTL event/final-state half needs the real-RTL "
           "chunk/batch equivalence test) and can never turn the gate ready")
    _limit(limits, "scope",
           "every verdict is derived from saved artifacts plus the frozen "
           "consumer's declaration-only checks; this suite renders no harness, "
           "starts no process and executes no RTL")
    for record, declaration in zip(records, declarations):
        if record["limit_count"]:
            _limit(limits, f"per_run_limits.{declaration.role}",
                   f"the frozen consumer recorded {record['limit_count']} "
                   "limit(s) for this run; they stay in that run's own "
                   "p3_acceptance_report.v1 document (dump it with "
                   "--reports-dir) and are not copied into this suite")
    if errors:
        _limit(limits, "producer_errors",
               "the frozen consumer could not be produced for "
               f"{len(errors)} declared run(s) "
               f"({', '.join(errors)}); their evidence is unavailable and the "
               "gate is forced to 2, whatever the other runs prove")
    for name, entry in verification.items():
        if entry["match"] is False:
            _limit(limits, f"engine_version_declaration.{name}",
                   f"the caller-declared sha256 {entry['expected']} does not "
                   f"match the module in use ({entry['actual']}), so this "
                   "suite's evidence is not bound to the declared producer "
                   "version and the gate is forced to 2")
        elif entry["match"] is None:
            _limit(limits, f"engine_version_declaration.{name}",
                   f"no engine binding is known for the declared module {name!r}"
                   f" ({entry['reason']}); the declaration is reported unverified")
    if len(engine_groups) > 1:
        grouped = "; ".join(f"{sha} -> {', '.join(roles)}"
                            for sha, roles in sorted(engine_groups.items()))
        _limit(limits, "engine.mixed_versions_across_runs",
               "the declared runs do not agree on the frozen producer version "
               f"({grouped}); a union across different producer versions is not "
               "one engine's evidence and the gate is forced to 2")
    return limits


def _gate(items: Mapping[str, Mapping], records, declarations,
          verification, engine_groups, errors) -> dict:
    coverage: dict[str, dict] = {}
    for record in records:
        coverage[record["role"]] = {
            "critical_met": list(record["critical_met"]),
            "critical_missing": list(record["critical_missing"]),
            "critical_unmet": list(record["critical_unmet"]),
            "frozen_gate_exit_code": record["frozen_gate_exit_code"],
            "report_available": record["report"] is not None}
    satisfying = [record["role"] for record in records
                  if not record["critical_missing"] and not record["critical_unmet"]
                  and record["report"] is not None]
    met_at_least_one = [key for key in CRITICAL_ITEMS
                        if items[key]["status"] == "met"]
    not_met = [key for key in CRITICAL_ITEMS if key not in met_at_least_one]
    unmeasured_everywhere = [
        key for key in CRITICAL_ITEMS
        if all(entry["status"] == "unmeasured"
               for entry in items[key]["per_run"].values())]
    measured_somewhere_unmet = [
        key for key in CRITICAL_ITEMS
        if key not in met_at_least_one
        and any(entry["measured"] for entry in items[key]["per_run"].values())]
    undecided = [key for key in CRITICAL_ITEMS if items[key]["undecided_by"]]
    limits = _gate_limits(records, declarations, coverage, satisfying,
                          verification, engine_groups, errors)
    frozen_keys: list[str] = []
    for record in records:
        gate = (record["report"] or {}).get("gate")
        if not isinstance(gate, Mapping):
            continue
        for row in gate.get("items") or ():
            if isinstance(row, Mapping) and row.get("critical") is True:
                key = str(row.get("key"))
                if key not in frozen_keys:
                    frozen_keys.append(key)
    artifact_rows = [key for key in frozen_keys if key not in CRITICAL_ITEMS]
    if artifact_rows:
        _limit(limits, "frozen_gate_artifact_rows",
               "the frozen gate also marks the per-run availability rows "
               f"{artifact_rows} as critical, but their met value is null by "
               "construction (they report whether a manifest/receipts/trace "
               "artifact could be read). They are per-run prerequisites shown "
               "in runs[*].frozen_critical_missing and are not part of this "
               "suite's criterion union")
    version_mismatch = any(entry["match"] is False
                           for entry in verification.values())
    ready = (not not_met and not errors and not version_mismatch
             and len(engine_groups) <= 1)
    parts = []
    if ready:
        parts.append("every critical P3 item is proven by at least one "
                     "declared run (union across runs, not a single-run pass)")
    else:
        if not_met:
            parts.append("not proven by any declared run: "
                         + ", ".join(not_met))
        if errors:
            parts.append("no report could be produced for: "
                         + ", ".join(errors))
        if version_mismatch:
            parts.append("a caller-declared engine version does not match the "
                         "module in use")
        if len(engine_groups) > 1:
            parts.append("the declared runs disagree on the frozen producer "
                         "version")
    return {
        "critical_items": list(CRITICAL_ITEMS),
        "non_critical_items": sorted(NON_CRITICAL_ITEMS),
        "frozen_gate_critical_keys": frozen_keys,
        "critical_set_source": (
            "myfuzz.scenario.p3_acceptance.CRITERIA minus "
            f"{RTL_EVENT_LEVEL_KEY!r} (the frozen consumer's own non-critical "
            "row), cross-checked against the critical keys each run's frozen "
            "gate document reports"),
        "met_by_at_least_one_run": met_at_least_one,
        "not_met_by_any_run": not_met,
        "unmeasured_across_all_runs": unmeasured_everywhere,
        "unmet_by_at_least_one_run": measured_somewhere_unmet,
        "undecided_by_at_least_one_run": undecided,
        "proven_by": {key: [entry["role"] for entry in items[key]["met_by"]]
                      for key in CRITICAL_ITEMS},
        "single_run_coverage": coverage,
        "runs_satisfying_all_critical_items": satisfying,
        "runs_with_errors": list(errors),
        "exit_code": EXIT_READY if ready else EXIT_NOT_READY,
        "ready": ready,
        "summary": "; ".join(parts),
        "limits": limits,
        "exit_code_semantics": (
            "0 = every critical P3 item has at least one declared run with "
            "measured=true and met=true (a per-item union across runs, NOT a "
            "single-run P3 pass); 2 = some critical item has no proving run, a "
            "declared run's report could not be produced, the runs disagree on "
            "the frozen producer version, or a declared engine hash does not "
            "match the module in use. Non-critical keys never affect the code."),
    }


# ---------------------------------------------------------------------------
# the suite
# ---------------------------------------------------------------------------


def _engine_section(records, declarations, engine_hashes) -> tuple[dict, dict, dict]:
    per_run = {record["role"]: ((record["report"] or {}).get("engine")
                                if record["report"] else None)
               for record in records}
    groups: dict[str, list[str]] = {}
    for record in records:
        frozen_identity = _frozen_engine_sha256(record["report"])
        if frozen_identity is not None:
            groups.setdefault(frozen_identity, []).append(record["role"])
    expected: dict[str, str | None] = {}
    if engine_hashes is not None:
        if isinstance(engine_hashes, (str, bytes)) or not isinstance(
                engine_hashes, Mapping):
            raise P3AcceptanceSuiteError(
                "engine_hashes must be a mapping of module name to sha256, got "
                f"{type(engine_hashes).__name__}")
        for name, value in engine_hashes.items():
            digest = value
            if isinstance(value, Mapping):
                digest = value.get("sha256")
            if not isinstance(digest, str) or not digest:
                raise P3AcceptanceSuiteError(
                    f"engine_hashes[{name!r}] is not a sha256 string: {value!r}")
            canonical = ENGINE_ALIASES.get(str(name), str(name))
            expected[canonical] = digest
    known = {name: _engine_identity(name) for name in PRODUCER_MODULES}
    verification: dict[str, dict] = {}
    for name, digest in expected.items():
        if name in known:
            actual = known[name]["sha256"]
            verification[name] = {
                "expected": digest, "actual": actual,
                "match": digest == actual, "reason": None}
        else:
            verification[name] = {
                "expected": digest, "actual": None, "match": None,
                "reason": "no module of this name is part of this suite's "
                          "engine binding"}
    section = {
        "schema_version": ENGINE_SCHEMA,
        "p3_acceptance": known[FROZEN_MODULE],
        "p3_acceptance_suite": known[SUITE_MODULE],
        "per_run": per_run,
        "frozen_version_groups": {sha: roles
                                  for sha, roles in sorted(groups.items())},
        "expected": expected or None,
        "verification": verification or None,
        "digest_recipe": EVIDENCE_DIGEST_RECIPE,
    }
    return section, groups, verification


def _frozen_engine_sha256(report: Mapping | None) -> str | None:
    """The frozen producer sha256 one run's report declares, if any.

    The frozen report keys its engine entries by short module name
    (``engine.p3_acceptance``); a report that keys them by the full module name
    is accepted too, so the version check survives either spelling.
    """
    if not isinstance(report, Mapping):
        return None
    engine = report.get("engine")
    if not isinstance(engine, Mapping):
        return None
    for key in ("p3_acceptance", FROZEN_MODULE):
        entry = engine.get(key)
        if isinstance(entry, Mapping):
            digest = entry.get("sha256")
            module = entry.get("module")
            if (isinstance(digest, str) and digest
                    and module in (None, FROZEN_MODULE)):
                return digest
    for entry in engine.values():
        if (isinstance(entry, Mapping)
                and entry.get("module") == FROZEN_MODULE
                and isinstance(entry.get("sha256"), str) and entry["sha256"]):
            return entry["sha256"]
    return None


def p3_acceptance_suite(runs: Sequence, *, engine_hashes=None) -> dict:
    """Aggregate the frozen per-run P3 reports into one honest suite document.

    ``runs`` is a sequence of run declarations that name their own role
    explicitly (mapping or :class:`SuiteRun`).  ``engine_hashes`` optionally
    declares the sha256 each engine module is expected to have; a mismatch never
    silently passes: it is reported in ``engine.verification``, recorded as a
    limit and forces ``gate.exit_code == 2``.
    """
    declarations = _declarations(runs)
    records = [_evaluate(declaration) for declaration in declarations]
    items = {key: _aggregate_item(key, records, declarations)
             for key in CRITICAL_ITEMS}
    non_critical = {key: _aggregate_item(key, records, declarations)
                    for key in sorted(NON_CRITICAL_ITEMS)}
    engine, groups, verification = _engine_section(records, declarations,
                                                   engine_hashes)
    errors = [record["role"] for record in records if record["error"]]
    gate = _gate(items, records, declarations, verification, groups, errors)
    return {
        "schema_version": SCHEMA_VERSION,
        "frozen_report_schema_version": REPORT_SCHEMA_VERSION,
        "runs": [{key: value for key, value in record.items()
                  if key not in ("items", "report")}
                 for record in records],
        "runs_with_errors": errors,
        "critical_items": list(CRITICAL_ITEMS),
        "items": items,
        "non_critical_items": non_critical,
        "gate": gate,
        "limits": gate["limits"],
        "engine": engine,
        "evidence_digest_recipe": EVIDENCE_DIGEST_RECIPE,
    }


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------


def _cell(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def _note(value: object) -> str:
    return "—" if value is None else _cell(value)


def _item_row(item: Mapping) -> str:
    proven = ", ".join(f"`{entry['role']}`" for entry in item["met_by"]) or "—"
    return f"| `{item['key']}` | `{item['status']}` | {proven} |"


def render_markdown(suite: Mapping) -> str:
    """Render one suite document, evidence boundary first."""
    lines: list[str] = []
    add = lines.append
    gate = suite.get("gate") or {}
    runs = list(suite.get("runs") or ())
    add("# P3 acceptance suite report")
    add("")
    add(f"- schema: `{suite.get('schema_version')}`")
    add(f"- frozen per-run report schema: "
        f"`{suite.get('frozen_report_schema_version')}`")
    add(f"- declared runs: {len(runs)}")
    for row in runs:
        compare = (f", compare_run `{row['compare_run']}`"
                   if row.get("compare_run") else "")
        error = (f", **report error: {row['error']['type']}: "
                 f"{row['error']['message']}**" if row.get("error") else "")
        add(f"  - `{row.get('role')}` -> `{row.get('run_dir')}` "
            f"(frozen gate exit: {_cell(row.get('frozen_gate_exit_code'))}"
            f"{compare}){error}")
    add(f"- gate: **exit code {_cell(gate.get('exit_code'))}** -- "
        f"{_cell(gate.get('summary'))}")
    add("")

    add("## 证据边界 (evidence boundary)")
    add("")
    add("### 实测 (measured)")
    add("")
    add("| role | run_dir | frozen gate | critical met | critical missing |")
    add("|---|---|---|---|---|")
    for row in runs:
        coverage = (gate.get("single_run_coverage") or {}).get(
            row.get("role"), {})
        add(f"| `{row.get('role')}` | `{row.get('run_dir')}` | "
            f"`{_cell(row.get('frozen_gate_exit_code'))}` | "
            f"`{_cell(len(coverage.get('critical_met') or ()))}/"
            f"{len(gate.get('critical_items') or ())}` | "
            f"`{_cell(coverage.get('critical_missing'))}` |")
    add("")
    add("Per item, the runs whose frozen report proves it:")
    add("")
    add("| item | status | proven by |")
    add("|---|---|---|")
    for key in gate.get("critical_items") or ():
        item = (suite.get("items") or {}).get(key)
        if item:
            add(_item_row(item))
    add("")

    add("### 未证实与原因 (not proven, and why)")
    add("")
    unproven = [key for key in gate.get("not_met_by_any_run") or ()]
    if unproven:
        add("| item | status | per-run detail |")
        add("|---|---|---|")
        for key in unproven:
            item = (suite.get("items") or {})[key]
            for role, detail in (item.get("per_run") or {}).items():
                add(f"| `{key}` | `{detail.get('status')}` | "
                    f"`{role}`: {_note(detail.get('reason'))} |")
    else:
        add("none: every critical item is proven by at least one declared run")
    exclusions = [(key, entry)
                  for key in (suite.get("items") or {})
                  for entry in (suite["items"][key].get("excluded_from_met_by")
                                or ())]
    if exclusions:
        add("")
        add("Claims the suite refuses to count:")
        add("")
        for key, entry in exclusions:
            add(f"- `{key}` on `{entry['role']}`: {_note(entry.get('reason'))}")
    add("")

    add("### 限制 (limits)")
    add("")
    for limit in gate.get("limits") or ():
        add(f"- `{limit.get('quantity')}`: {_note(limit.get('reason'))}")
    add("")

    add("## 逐子项汇总 (item by item)")
    add("")
    for key in gate.get("critical_items") or ():
        item = (suite.get("items") or {}).get(key)
        if not item:
            continue
        add(f"### `{key}`")
        add("")
        add(f"- criterion: {_note(item.get('criterion'))}")
        add(f"- status: **{item.get('status')}** "
            f"(proven by {len(item.get('met_by') or ())} run(s))")
        if item.get("injected_calibration"):
            add(f"- evidence kind: `{item.get('evidence_kind')}` -- "
                f"{_note(item.get('caveat'))}")
        for entry in item.get("met_by") or ():
            add(f"- proven by `{entry['role']}` at `{entry['run_dir']}` "
                f"(digest `{entry['evidence_digest']}`"
                f"{(', compare_run `' + entry['compare_run'] + '`')
                   if entry.get('compare_run') else ''})")
            fields = entry.get("evidence_fields") or []
            if fields:
                add(f"  - field paths in that run's report: "
                    + ", ".join(f"`{path}`" for path in fields)
                    + (" (truncated)" if entry.get("evidence_fields_truncated")
                       else ""))
        add("")
        add("| run | status | measured | met | reason |")
        add("|---|---|---|---|---|")
        for role, detail in (item.get("per_run") or {}).items():
            add(f"| `{role}` | `{detail.get('status')}` | "
                f"`{_cell(detail.get('measured'))}` | "
                f"`{_cell(detail.get('met'))}` | {_note(detail.get('reason'))} |")
        add("")

    engine = suite.get("engine") or {}
    add("## 引擎与版本绑定 (engine binding)")
    add("")
    # The engine section keys the producer identities by short module name
    # (p3_acceptance / p3_acceptance_suite), the same spelling the frozen report
    # uses for its own engine entries.
    for short_name, module_name in (("p3_acceptance", FROZEN_MODULE),
                                    ("p3_acceptance_suite", SUITE_MODULE)):
        identity = engine.get(short_name) or {}
        add(f"- `{module_name}`: sha256 `{identity.get('sha256')}` "
            f"({identity.get('path')})")
    for name, entry in (engine.get("verification") or {}).items():
        add(f"- declared `{name}`: expected `{entry.get('expected')}`, actual "
            f"`{entry.get('actual')}`, match `{_cell(entry.get('match'))}`")
    for sha, roles in (engine.get("frozen_version_groups") or {}).items():
        add(f"- frozen producer version `{sha}` seen in: {', '.join(roles)}")
    add("")
    add("Evidence digest recipe (recompute any `evidence_digest` above):")
    add("")
    add(f"```\n{suite.get('evidence_digest_recipe')}\n```")
    add("")
    return "\n".join(lines)
