"""P5 stage acceptance: judge declared runs and union their real evidence.

The P5 checklist has no single saved run that proves every item, exactly like P3
and P4.  This module therefore does two things:

* :func:`p5_acceptance_report` judges **one** declared run directory against the
  six P5 critical items and answers with a ``p5_acceptance_report.v1`` document.
  Every item carries ``measured`` / ``met`` / ``value`` / ``evidence`` /
  ``reason``; an item that cannot be measured keeps ``measured=false`` and
  ``met=null`` with a precise reason -- never a fabricated ``0``, never a silent
  pass, and never ``met=true`` without ``measured=true``;
* :func:`p5_acceptance_suite` unions those per-run verdicts into a
  ``p5_acceptance_suite.v1`` document that names, for every critical item, which
  run proves it, which run measured it without meeting it and which item no run
  proves at all.  One item (``normal_control_has_no_finding``) is a *cross-run*
  statement: it needs a clean control run **and** an injected finding to be
  absent from it, so the union refuses to measure it when no declared run proves
  an antecedent finding.

The six critical items are the P5 acceptance checklist:

``assertion_classes_separated``
    protocol-checker / cross-component provenance-order / CPU-IP behaviour are
    reported separately, with a fail-closed abnormal-record census.  Evidence:
    the shipped ``scripts/report_p5_assertion_classes.py`` CLI report
    (``p5_assertion_classes.v1``) on a real run, whose ``engine.module.sha256``
    must equal the shipped ``myfuzz.scenario.assertion_classes`` revision.
``controlled_fault_caught_and_reproduced``
    at least one injected fault caught by an existing checker invariant, with the
    ``calibration_only`` / ``checker_input_copy`` markers, a ``minimal_replay``
    document and a fresh-process reproduce root whose ``violations`` and
    ``fault_document_sha256`` agree.
``normal_control_has_no_finding``
    the control run of that fault carries no ``dut_violation`` receipt, no
    violation string and no failure record.
``complete_prefix_saved_and_identity_refused_before_start``
    the saved run carries raw/plan/trace/manifest identities that bind to the
    files on disk, a fresh-replay document with ``matches=true``, and a shipped
    refusal mechanism (with its module sha256) that rejects an identity mismatch
    before any RTL start.
``ten_minute_search_reports_chains_and_replay``
    a real >=600 effective-second search with a certified chain count, chain/s,
    a fresh-replay result and the natural-finding count stated honestly.
``same_budget_continuous_beats_per_case_restart``
    the paired continuous vs per-case cold-start evidence with a wall-clock and
    effective-case comparison plus the explicit statement that chain/s
    equivalence is (or is not) measurable from the pair.

The module reads saved artifacts only: it never renders a harness, never starts
an RTL process and never writes inside a saved run.  The one optional write is
the assertion-class CLI report produced by ``invoke_assertion_classes=True``,
which goes to the caller's scratch directory.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import importlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys


SCHEMA_VERSION = "p5_acceptance_report.v1"
SUITE_SCHEMA_VERSION = "p5_acceptance_suite.v1"
ERROR_SCHEMA_VERSION = "p5_acceptance_suite_error.v1"

EXIT_READY = 0
EXIT_NOT_READY = 2
EXIT_USAGE = 1

#: Repository root, derived from this module's own location (src/myfuzz/scenario).
ROOT = Path(__file__).resolve().parents[3]

#: The six P5 acceptance items, in checklist order.
ITEM_ASSERTION_CLASSES = "assertion_classes_separated"
ITEM_CONTROLLED_FAULT = "controlled_fault_caught_and_reproduced"
ITEM_NORMAL_CONTROL = "normal_control_has_no_finding"
ITEM_COMPLETE_PREFIX = "complete_prefix_saved_and_identity_refused_before_start"
ITEM_LONG_SEARCH = "ten_minute_search_reports_chains_and_replay"
ITEM_PAIRED_BUDGET = "same_budget_continuous_beats_per_case_restart"

CRITICAL_ITEMS = (
    ITEM_ASSERTION_CLASSES,
    ITEM_CONTROLLED_FAULT,
    ITEM_NORMAL_CONTROL,
    ITEM_COMPLETE_PREFIX,
    ITEM_LONG_SEARCH,
    ITEM_PAIRED_BUDGET,
)

ITEM_CRITERIA = {
    ITEM_ASSERTION_CLASSES:
        "protocol-checker, cross-component provenance/order and CPU/IP behaviour "
        "findings are reported as three separate classes, and every abnormal "
        "record the run holds is enumerated by a fail-closed census "
        "(artifact: p5_assertion_classes.v1 from the shipped CLI)",
    ITEM_CONTROLLED_FAULT:
        "at least one injected fault is caught by an existing checker invariant "
        "with the calibration_only / checker_input_copy markers, a minimal "
        "replay document and a fresh-process reproduce root",
    ITEM_NORMAL_CONTROL:
        "the control run of that injected fault carries no such finding: no "
        "dut_violation status, no violation string, no failure record",
    ITEM_COMPLETE_PREFIX:
        "raw/plan/trace/manifest identities are saved and bound to the files on "
        "disk, a fresh-replay document reports matches=true, and a shipped "
        "mechanism refuses an identity mismatch before any RTL start",
    ITEM_LONG_SEARCH:
        "a real run of at least 600 effective search seconds reports certified "
        "chains, chain/s, a fresh-replay result and its natural findings "
        "(0 stated honestly, never fabricated)",
    ITEM_PAIRED_BUDGET:
        "the paired continuous vs per-case cold-start run shows the wall-clock "
        "and effective-case comparison and states explicitly whether chain/s "
        "equivalence is measurable",
}

# ---------------------------------------------------------------- artifact keys

ARTIFACT_REPORT = "report"
ARTIFACT_IDENTITY = "identity"
ARTIFACT_PLAN = "plan"
ARTIFACT_MANIFEST = "manifest"
ARTIFACT_TRACE_META = "trace_meta"
ARTIFACT_RECEIPTS = "receipts"
ARTIFACT_SEED = "seed"
ARTIFACT_FAULT_DOCUMENT = "fault_document"
ARTIFACT_FAULT_RUN_SUMMARY = "fault_run_summary"
ARTIFACT_MINIMAL_REPLAY = "minimal_replay"
ARTIFACT_REPRODUCTION_SUMMARY = "reproduction_summary"
ARTIFACT_FAULT_FAMILY_CALIBRATION = "fault_family_calibration"
ARTIFACT_FAULT_FAMILY_VERIFY = "fault_family_verify"
ARTIFACT_COLD_START = "cold_start"
ARTIFACT_PAIRED_REPORT = "paired_report"
ARTIFACT_CONTINUED_REPORT = "continued_report"
ARTIFACT_FIRST_STEP_ACCEPTANCE = "first_step_acceptance"
ARTIFACT_ASSERTION_CLASSES = "assertion_classes"
ARTIFACT_REPLAY = "replay"

#: File names each artifact key may carry, in search order.  Every name is an
#: artifact a shipped producer really writes; nothing here is synthesised.
ARTIFACT_NAMES = {
    ARTIFACT_REPORT: ("report.json",),
    ARTIFACT_IDENTITY: ("online_run_identity.json",),
    ARTIFACT_PLAN: ("online_plan.json",),
    ARTIFACT_MANIFEST: ("online_session_manifest.json",),
    ARTIFACT_TRACE_META: ("online_final_trace.meta.json",),
    ARTIFACT_RECEIPTS: ("receipts.jsonl",),
    ARTIFACT_SEED: ("seed.bin",),
    ARTIFACT_FAULT_DOCUMENT: ("fault_document.json",),
    ARTIFACT_FAULT_RUN_SUMMARY: ("fault_run_summary.json",),
    ARTIFACT_MINIMAL_REPLAY: ("minimal_replay.json",),
    ARTIFACT_REPRODUCTION_SUMMARY: ("reproduction_summary.json",),
    ARTIFACT_FAULT_FAMILY_CALIBRATION: ("fault_family_calibration.json",),
    ARTIFACT_FAULT_FAMILY_VERIFY: ("fault_family_calibration_verify.json",),
    ARTIFACT_COLD_START: ("cold_start.json",),
    ARTIFACT_PAIRED_REPORT: ("paired_efficiency_report.json",),
    ARTIFACT_CONTINUED_REPORT: ("report.json",),
    ARTIFACT_FIRST_STEP_ACCEPTANCE: (
        "first_step_acceptance.json", "acceptance.json",
        "chain_600s_acceptance.json", "chain_acceptance.json"),
    ARTIFACT_ASSERTION_CLASSES: (
        "assertion_classes.json", "p5_assertion_classes.json",
        "assertion_classes_acceptance.json", "assertion_classes_fault.json",
        "acceptance.json"),
    ARTIFACT_REPLAY: ("replay.json", "replay.log"),
}

#: The repository's two well-known P5 evidence stores.  They are searched last,
#: and only a document whose own ``run_dir``/root binding names the declared run
#: is accepted, so a report of another run can never be read for this one.
EVIDENCE_STORES = (
    "current-dataflow-p5-final-20261007-logs",
    "current-dataflow-p5-assertion-classes-20261007-logs",
)

#: The ``schema_version`` each artifact key must carry when its producer writes
#: one.  A candidate whose schema disagrees is skipped (with a reported note), so
#: a report of another producer can never be read as this artifact.
ARTIFACT_SCHEMAS = {
    ARTIFACT_IDENTITY: ("scenario_online_run_identity_envelope.v1",),
    ARTIFACT_TRACE_META: ("online_trace_zlib_chunks.v1",),
    ARTIFACT_FAULT_DOCUMENT: ("p5_controlled_fault.v1",),
    ARTIFACT_MINIMAL_REPLAY: ("p5_controlled_fault_replay.v1",),
    ARTIFACT_FAULT_FAMILY_CALIBRATION: ("p5_fault_family_calibration.v1",),
    ARTIFACT_FAULT_FAMILY_VERIFY: ("p5_fault_family_calibration_verify.v1",),
    ARTIFACT_COLD_START: ("ibex_pulp_cold_baseline.v1",),
    ARTIFACT_FIRST_STEP_ACCEPTANCE: ("first_step_acceptance_report.v1",),
    ARTIFACT_ASSERTION_CLASSES: ("p5_assertion_classes.v1",),
    ARTIFACT_PAIRED_REPORT: ("paired_efficiency_report.v1",),
}

#: JSON field paths inside an artifact that must name the declared run for the
#: artifact to be accepted.  A candidate that declares a different run is
#: skipped (and the skip is reported) instead of being silently used.
ARTIFACT_BINDINGS = {
    ARTIFACT_FIRST_STEP_ACCEPTANCE: ("run_dir",),
    ARTIFACT_ASSERTION_CLASSES: ("run_dir",),
    ARTIFACT_FAULT_FAMILY_CALIBRATION: ("output_root.resolved",
                                        "calibration_root.resolved"),
    ARTIFACT_PAIRED_REPORT: ("groups.continuous.run_dir",
                             "groups.cold.run_dir"),
}

#: Shipped, read-only mechanisms that refuse an identity mismatch before any RTL
#: start.  The item cites the module identity (path + sha256), the stage at which
#: the refusal happens and the shipped report that documents it.
IDENTITY_REFUSAL_MECHANISMS = (
    {"module": "myfuzz.integration.scenario_rfuzz_live",
     "symbol": "_verify_online_run_identity",
     "refusal": "online run identity digest/report/decode-space/artifact/plan/host/"
                "trace mismatch (for example 'online decode space source identity "
                "mismatch: <path> (recorded ..., current ...)')",
     "citation": "docs/reports/current-dataflow-p5-cold-group-replay-20261008.md",
     "stage": "replay identity verification, called before the RTL factory is "
              "built (myfuzz.integration.ibex_pulp_online."
              "replay_pulp_dual_source_online_files verifies at line 319 and calls "
              "factory_builder at line 328)"},
    {"module": "myfuzz.scenario.acceptance_metrics",
     "symbol": "TraceEventStream",
     "refusal": "unsupported trace metadata schema / declared events_file "
                "missing / event count mismatch / canonical semantic sha256 "
                "mismatch",
     "citation": "docs/reports/current-dataflow-p5-zlib-chunk-trace-20261007.md",
     "stage": "trace open, before any replay RTL start"},
)

#: Saved artifacts that show a real identity mismatch being refused.  They belong
#: to the 24 per-case cold-group replays of the paired run (the same frozen
#: bundle family), not to the declared run itself; the item records that subject
#: verbatim instead of implying the declared run was the one refused.
IDENTITY_REFUSAL_ARTIFACTS = (
    ("runs/current-dataflow-p5-final-20261007-logs/cold-replay-0000.log",
     "refusal log"),
    ("runs/current-dataflow-p5-final-20261007-logs/p5_cold_group_replay.json",
     "replay summary"),
    ("runs/current-dataflow-p5-final-20261007-logs/cold_replay_summary.json",
     "replay summary"),
)
IDENTITY_REFUSAL_SUBJECT = (
    "the 24 per-case cold-group replays of "
    "runs/current-dataflow-p5-paired-20261007-online (the same frozen bundle "
    "family as the declared runs), not the declared run itself")

#: Roles a declaration may name, with the artifacts that role must really carry.
#: A role is a declaration, not a measurement: the suite reports a mismatch
#: between the declared role and the artifacts it finds, and never infers a role
#: from a directory name.
ROLE_REQUIREMENTS = {
    "chain_acceptance": (ARTIFACT_REPORT, ARTIFACT_IDENTITY, ARTIFACT_PLAN,
                         ARTIFACT_RECEIPTS),
    "long_search": (ARTIFACT_REPORT, ARTIFACT_IDENTITY, ARTIFACT_PLAN,
                    ARTIFACT_RECEIPTS),
    "paired_continuous": (ARTIFACT_REPORT, ARTIFACT_IDENTITY, ARTIFACT_RECEIPTS),
    "paired_cold_start": (ARTIFACT_REPORT, ARTIFACT_COLD_START,
                          ARTIFACT_RECEIPTS),
    "fault_calibration": (ARTIFACT_REPORT, ARTIFACT_FAULT_DOCUMENT,
                          ARTIFACT_FAULT_RUN_SUMMARY, ARTIFACT_MINIMAL_REPLAY),
    "fault_family": (ARTIFACT_FAULT_FAMILY_CALIBRATION,
                     ARTIFACT_FAULT_FAMILY_VERIFY),
    "control": (ARTIFACT_REPORT, ARTIFACT_RECEIPTS),
    "heterogeneous_uart": (ARTIFACT_REPORT, ARTIFACT_IDENTITY,
                           ARTIFACT_RECEIPTS),
    "supporting": (),
}
LEGAL_ROLES = frozenset(ROLE_REQUIREMENTS)

#: Receipt / report statuses that are a finding rather than a clean completion.
FINDING_STATUSES = frozenset({"dut_violation"})
#: Receipt / report statuses a control run may carry at all.
CONTROL_STATUSES = frozenset({"complete"})

#: The aggregate report file both the judge and the writers name.
REPORT_FILE = "report.json"

#: Report schemas that declare their run status under a field other than
#: ``session_status``.  The judge reads that declared field only when the report
#: carries no ``session_status`` key of its own, and never trusts it alone: a
#: declared "complete" is still refused unless every per-case receipt row the
#: judge streams itself is complete.  ``first_step_cold_start_run_report.v1``
#: is the per-case cold-start aggregate, which exposes ``execution_status``.
DECLARED_SESSION_STATUS_FIELDS = {
    "first_step_cold_start_run_report.v1": "execution_status",
}

DECLARATION_KEYS = frozenset({"role", "run_dir", "compare_run", "artifacts"})
MAX_UNION_EVIDENCE = 24

MINIMUM_LONG_SEARCH_SECONDS = 600.0


class P5AcceptanceError(ValueError):
    """A declaration or artifact the suite cannot honour."""


# --------------------------------------------------------------- small helpers


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def _module_identity(name: str) -> dict | None:
    """Path and sha256 of one module file, so a verdict names its producer."""
    try:
        module = importlib.import_module(name)
    except ImportError:
        return None
    path = Path(getattr(module, "__file__", "") or "")
    if not path.is_file():
        return None
    return {"module": name, "path": str(path),
            "sha256": _sha256_file(path)}


def _normalized_path(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return os.path.realpath(path)


def _load_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def _finite(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


#: The characters a lowercase hexadecimal sha256 is built from.
DIGEST_ALPHABET = frozenset("0123456789abcdef")

#: Directory components of the saved raw-input artifacts in
#: ``identity.artifacts`` (``corpus/entry_NNNN.json``).
CORPUS_COMPONENTS = frozenset({"corpus"})


def _is_digest(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and set(value) <= DIGEST_ALPHABET)


def _field(document: Mapping, path: str) -> object:
    node: object = document
    for part in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def _evidence(record: Mapping) -> dict:
    return {"key": record.get("key"), "path": record.get("path"),
            "resolved": record.get("resolved"), "sha256": record.get("sha256"),
            "available": bool(record.get("available"))}


def _notes_text(record: Mapping, *, limit: int = 3) -> str:
    """The resolution notes of an unavailable artifact, ready for a reason."""
    notes = [str(note)[:240] for note in (record.get("notes") or [])]
    return "; ".join(notes[-limit:])


def _item(key: str, *, measured: bool, met, value, evidence: list,
          reason: str | None = None) -> dict:
    # A verdict that claims ``met`` without measuring anything is a fabricated
    # pass, whatever produced it; the constructor refuses to emit one.
    if met is True and not measured:
        raise P5AcceptanceError(
            f"item {key} claims met=true without measured=true")
    if met is None and measured and reason is None:
        raise P5AcceptanceError(f"item {key} is measured but carries no reason")
    return {"key": key, "critical": True, "criterion": ITEM_CRITERIA[key],
            "measured": bool(measured), "met": met, "value": value,
            "evidence": evidence, "reason": reason}


# ----------------------------------------------------------- run declarations


def parse_run_declaration(spec: str) -> dict:
    """``ROLE=DIR[@COMPARE_DIR]`` -> one explicit run declaration.

    The role is the text before the first ``=`` and is never guessed from the
    directory name; the comparison directory is taken from the last ``@`` so a
    path may contain ``@``.
    """
    if not isinstance(spec, str) or "=" not in spec:
        raise P5AcceptanceError(
            f"run declaration {spec!r} is not ROLE=DIR[@COMPARE_DIR]")
    role, _, remainder = spec.partition("=")
    run_dir, _, compare_run = remainder.rpartition("@")
    if not run_dir:
        run_dir = remainder
        compare_run = ""
    if not role.strip():
        raise P5AcceptanceError(f"run declaration {spec!r} has an empty role")
    if not run_dir.strip():
        raise P5AcceptanceError(
            f"run declaration {spec!r} has an empty run directory")
    return {"role": role.strip(), "run_dir": run_dir.strip(),
            "compare_run": (compare_run.strip() or None), "artifacts": {}}


def parse_artifact_declaration(spec: str) -> dict:
    """``ROLE=KEY=PATH`` -> one explicitly declared artifact path."""
    if not isinstance(spec, str) or spec.count("=") < 2:
        raise P5AcceptanceError(
            f"artifact declaration {spec!r} is not ROLE=KEY=PATH")
    role, _, remainder = spec.partition("=")
    key, _, path = remainder.partition("=")
    if not role.strip():
        raise P5AcceptanceError(f"artifact declaration {spec!r} has no role")
    if not key.strip():
        raise P5AcceptanceError(f"artifact declaration {spec!r} has no key")
    if not path.strip():
        raise P5AcceptanceError(f"artifact declaration {spec!r} has no path")
    return {"role": role.strip(), "key": key.strip(), "path": path.strip()}


def _declarations(runs: Sequence) -> list[dict]:
    if isinstance(runs, (str, bytes, bytearray)) or not isinstance(runs, Sequence):
        raise P5AcceptanceError(
            "runs must be a sequence of declarations "
            f"({{'role': ..., 'run_dir': ..., 'compare_run': ...}}), got "
            f"{type(runs).__name__}")
    if not runs:
        raise P5AcceptanceError("at least one run declaration is required")
    declarations: list[dict] = []
    roles: set[str] = set()
    for index, entry in enumerate(runs):
        if not isinstance(entry, Mapping):
            raise P5AcceptanceError(
                f"run declaration {index} is not a mapping, got "
                f"{type(entry).__name__}")
        unknown = sorted(str(key) for key in entry
                         if str(key) not in DECLARATION_KEYS)
        if unknown:
            raise P5AcceptanceError(
                f"run declaration {index} carries unknown key(s) {unknown}; a "
                "declaration is exactly role/run_dir/compare_run/artifacts")
        role = entry.get("role")
        if not isinstance(role, str) or not role.strip():
            raise P5AcceptanceError(
                f"run declaration {index} has no role: {role!r}")
        role = role.strip()
        if role not in LEGAL_ROLES:
            raise P5AcceptanceError(
                f"run declaration {index} declares role {role!r}, which is not "
                f"a legal role; legal roles: {sorted(LEGAL_ROLES)}")
        if role in roles:
            raise P5AcceptanceError(
                f"duplicate role {role!r} in run declaration {index}; every "
                "declared run must carry its own role")
        roles.add(role)
        run_dir = entry.get("run_dir")
        if isinstance(run_dir, os.PathLike):
            run_dir = os.fspath(run_dir)
        if not isinstance(run_dir, str) or not run_dir.strip():
            raise P5AcceptanceError(
                f"run declaration {index} ({role}) has no run_dir: {run_dir!r}")
        if not Path(run_dir).is_dir():
            raise P5AcceptanceError(
                f"run directory does not exist: {run_dir}")
        compare_run = entry.get("compare_run")
        if isinstance(compare_run, os.PathLike):
            compare_run = os.fspath(compare_run)
        if compare_run is not None:
            if not isinstance(compare_run, str) or not compare_run.strip():
                raise P5AcceptanceError(
                    f"run declaration {index} ({role}) has an empty "
                    f"compare_run: {compare_run!r}")
            if not Path(compare_run).is_dir():
                raise P5AcceptanceError(
                    f"comparison run directory does not exist: {compare_run}")
            if Path(compare_run).resolve() == Path(run_dir).resolve():
                raise P5AcceptanceError(
                    f"run declaration {index} ({role}) names the same directory "
                    f"as run_dir and compare_run ({run_dir})")
        artifacts = entry.get("artifacts") or {}
        if not isinstance(artifacts, Mapping):
            raise P5AcceptanceError(
                f"run declaration {index} ({role}) has a non-mapping artifacts "
                f"field: {type(artifacts).__name__}")
        for key, value in artifacts.items():
            if key not in ARTIFACT_NAMES:
                raise P5AcceptanceError(
                    f"run declaration {index} ({role}) declares unknown artifact "
                    f"key {key!r}")
            if value is not None and not isinstance(value, (str, os.PathLike)):
                raise P5AcceptanceError(
                    f"run declaration {index} ({role}) artifact {key!r} is not a "
                    f"path: {value!r}")
        declarations.append({
            "role": role, "run_dir": run_dir.strip(),
            "compare_run": (compare_run.strip() if compare_run else None),
            "artifacts": {str(key): (None if value is None else os.fspath(value))
                          for key, value in artifacts.items()}})
    return declarations


# ------------------------------------------------------- artifact resolution


def _search_locations(run_dir: Path) -> list[tuple[Path, bool]]:
    """The fixed search order for one key: (location, is_shared_store).

    The run directory and its own ``*-logs`` sibling are run-specific by
    construction.  The shared evidence stores are searched last and only for
    artifacts that carry their own run binding (see :data:`ARTIFACT_BINDINGS`),
    so a bare ``replay.log`` or ``report.json`` of another run can never be
    attached to this one.
    """
    stem = run_dir.name
    for suffix in ("-online", "-replay-cache"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    candidates = [
        (run_dir, False),
        (run_dir.parent / f"{stem}-logs", False),
        (run_dir.parent / f"{run_dir.name}-logs", False),
    ]
    candidates.extend((run_dir.parent / store, True) for store in EVIDENCE_STORES)
    seen: set[str] = set()
    ordered: list[tuple[Path, bool]] = []
    for candidate, is_store in candidates:
        resolved = os.path.realpath(candidate)
        if resolved in seen:
            continue
        seen.add(resolved)
        ordered.append((candidate, is_store))
    return ordered


def _bound_to_run(document: object, key: str, run_dir: Path) -> tuple[bool, str | None]:
    """Whether an artifact's own declared run binding names ``run_dir``."""
    fields = ARTIFACT_BINDINGS.get(key)
    if not fields or not isinstance(document, Mapping):
        return True, None
    wanted = os.path.realpath(run_dir)
    declared = []
    for field in fields:
        value = _field(document, field)
        if value is None:
            continue
        path = _normalized_path(value)
        declared.append((field, value))
        if path == wanted:
            return True, None
    if not declared:
        return True, None
    field, value = declared[0]
    return False, (f"the candidate declares {field}={value!r}, which is not the "
                   f"declared run {run_dir.as_posix()}")


def _resolve_artifact(key: str, *, run_dir: Path, explicit: str | None,
                      compare_run: Path | None = None) -> dict:
    """The artifact record for one key, searched in a fixed, reported order."""
    record = {"key": key, "path": None, "resolved": None, "sha256": None,
              "available": False, "notes": [], "searched": []}
    if explicit is not None:
        path = Path(explicit)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.is_file():
            record["notes"].append(
                f"the declared --artifact path does not exist: {explicit}")
            record["searched"] = [explicit]
            return record
        bound, reason = _bound_to_run(_load_json(path), key, run_dir)
        if not bound:
            # An explicitly declared artifact that names another run is a
            # declaration error, not evidence for this run.
            record["notes"].append(
                f"the declared artifact {explicit} is refused: {reason}")
            record["searched"] = [explicit]
            return record
        record.update({"path": explicit, "resolved": str(path),
                       "sha256": _sha256_file(path), "available": True})
        return record
    # Only the declared run's own directories are searched: the comparison run's
    # artifacts are read through ``_Context.document_of`` for the few items that
    # are explicitly about it (the reproduce summary, the cold-start arm), so the
    # compare run can never stand in for the declared run's own evidence.
    for root in (run_dir,):
        for location, is_store in _search_locations(root):
            for name in ARTIFACT_NAMES[key]:
                candidate = location / name
                if not candidate.is_file():
                    continue
                if is_store and key not in ARTIFACT_BINDINGS:
                    record["notes"].append(
                        f"skipped {candidate.as_posix()}: a shared evidence store "
                        f"serves only artifacts with their own run binding, and "
                        f"{key} carries none")
                    continue
                document = _load_json(candidate)
                bound, reason = _bound_to_run(document, key, run_dir)
                if not bound:
                    record["notes"].append(
                        f"skipped {candidate.as_posix()}: {reason}")
                    continue
                expected = ARTIFACT_SCHEMAS.get(key)
                if expected and (not isinstance(document, Mapping)
                                 or document.get("schema_version") not in expected):
                    got = (document.get("schema_version")
                           if isinstance(document, Mapping) else None)
                    record["notes"].append(
                        f"skipped {candidate.as_posix()}: schema_version {got!r} "
                        f"is not one of {list(expected)}")
                    continue
                record.update({"path": candidate.as_posix(),
                               "resolved": str(candidate.resolve()),
                               "sha256": _sha256_file(candidate),
                               "available": True})
                return record
    searched = [f"{location.as_posix()}/{name}"
                for location, _ in _search_locations(run_dir)
                for name in ARTIFACT_NAMES[key]]
    record["searched"] = searched
    record["notes"].append(
        f"no {key} artifact found for {run_dir.as_posix()}; searched "
        f"{len(searched)} path(s), for example "
        + ", ".join(searched[:3]))
    return record


# ---------------------------------------------------------------- the context


class _Context:
    """Every artifact one declared run may read, resolved once and reported."""

    def __init__(self, declaration: Mapping, *,
                 invoke_assertion_classes: bool = False,
                 scratch_dir: Path | None = None) -> None:
        self.role = declaration["role"]
        self.run_dir = Path(declaration["run_dir"])
        self.compare_run = (None if declaration.get("compare_run") is None
                            else Path(declaration["compare_run"]))
        self.declared_artifacts = dict(declaration.get("artifacts") or {})
        self.scratch_dir = scratch_dir
        self.records: dict[str, dict] = {}
        self._documents: dict[str, object] = {}
        self.notes: list[str] = []
        if invoke_assertion_classes and ARTIFACT_ASSERTION_CLASSES not in \
                self.declared_artifacts:
            # A saved report is preferred: the shipped CLI is only run when the
            # artifact cannot be resolved at all, so a declare-and-judge pass
            # never rescans a trace that already has a report.
            saved = _resolve_artifact(ARTIFACT_ASSERTION_CLASSES,
                                      run_dir=self.run_dir, explicit=None,
                                      compare_run=self.compare_run)
            self.records[ARTIFACT_ASSERTION_CLASSES] = saved
            if not saved["available"]:
                produced = self._invoke_assertion_classes()
                if produced is not None:
                    self.declared_artifacts[ARTIFACT_ASSERTION_CLASSES] = produced
                    self.records.pop(ARTIFACT_ASSERTION_CLASSES, None)
                    self.notes.append(
                        f"the assertion-class artifact was produced by the "
                        f"shipped CLI during this run: {produced}")

    # -- artifacts ---------------------------------------------------------
    def artifact(self, key: str) -> dict:
        if key not in self.records:
            produced = self._scratch_artifact(key)
            if produced is not None:
                self.records[key] = produced
                return self.records[key]
            # A cold-start arm names its continuous run inside report.json; the
            # continuous arm's report is then a declared artifact of this run.
            if key == ARTIFACT_CONTINUED_REPORT:
                self.records[key] = self._resolve_continued_report()
            else:
                self.records[key] = _resolve_artifact(
                    key, run_dir=self.run_dir,
                    explicit=self.declared_artifacts.get(key),
                    compare_run=self.compare_run)
            self.notes.extend(self.records[key]["notes"])
        return self.records[key]

    def _resolve_continued_report(self) -> dict:
        report = self.document(ARTIFACT_REPORT)
        recorded = report.get("continuous_run_dir") if isinstance(report, Mapping) else None
        if not isinstance(recorded, str) or not recorded:
            return {"key": ARTIFACT_CONTINUED_REPORT, "path": None,
                    "resolved": None, "sha256": None, "available": False,
                    "notes": [f"{ARTIFACT_REPORT} carries no continuous_run_dir, "
                              "so this arm names no continuous run"]}
        directory = Path(recorded)
        if not directory.is_absolute():
            directory = ROOT / directory
        return _resolve_artifact(ARTIFACT_REPORT, run_dir=directory,
                                 explicit=None, compare_run=None)

    def document(self, key: str) -> object:
        if key not in self._documents:
            record = self.artifact(key)
            self._documents[key] = (_load_json(Path(record["resolved"]))
                                    if record["available"] else None)
        return self._documents[key]

    def document_of(self, key: str, run_dir: Path) -> object:
        """One artifact of another declared run (used for ``compare_run``)."""
        cache_key = f"{key}@{run_dir.as_posix()}"
        if cache_key not in self._documents:
            record = _resolve_artifact(key, run_dir=run_dir, explicit=None,
                                       compare_run=None)
            self._documents[cache_key] = (_load_json(Path(record["resolved"]))
                                          if record["available"] else None)
        return self._documents[cache_key]

    def artifact_of(self, key: str, run_dir: Path) -> dict:
        cache_key = f"{key}@{run_dir.as_posix()}"
        if cache_key not in self.records:
            self.records[cache_key] = _resolve_artifact(
                key, run_dir=run_dir, explicit=None, compare_run=None)
        return self.records[cache_key]

    def _scratch_artifact(self, key: str) -> dict | None:
        """An assertion-class document a previous invocation wrote to scratch.

        It is accepted only when it parses, self-identifies as this run and
        carries the shipped schema; the item additionally binds its recomputed
        trace semantic sha256 to the run identity, so a stale report of a
        changed run cannot pass.
        """
        if key != ARTIFACT_ASSERTION_CLASSES or self.scratch_dir is None:
            return None
        candidate = (Path(self.scratch_dir)
                     / f"assertion_classes-{self.run_dir.name}.json")
        if not candidate.is_file():
            return None
        document = _load_json(candidate)
        expected = ARTIFACT_SCHEMAS[key]
        if not isinstance(document, Mapping) or \
                document.get("schema_version") not in expected:
            return None
        bound, _ = _bound_to_run(document, key, self.run_dir)
        if not bound:
            return None
        return {"key": key, "path": candidate.as_posix(),
                "resolved": str(candidate.resolve()),
                "sha256": _sha256_file(candidate), "available": True,
                "notes": ["read from the scratch directory of a previous "
                          "invocation of the shipped assertion-class CLI"],
                "searched": [candidate.as_posix()]}

    # -- side effects ------------------------------------------------------
    def _invoke_assertion_classes(self) -> str | None:
        """Run the shipped read-only CLI; a failure is a reported note."""
        cli = ROOT / "scripts/report_p5_assertion_classes.py"
        if not cli.is_file():
            self.notes.append(f"the shipped assertion-class CLI is missing: {cli}")
            return None
        directory = self.scratch_dir or (ROOT / "runs" /
                                         "p5-acceptance-suite-20261008-logs")
        out = Path(directory) / f"assertion_classes-{self.run_dir.name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [sys.executable, cli.as_posix(), "--run",
                 self.run_dir.as_posix(), "--out", out.as_posix()],
                cwd=ROOT.as_posix(), capture_output=True, text=True,
                timeout=7200, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            self.notes.append(
                f"the assertion-class CLI could not run: {error}")
            return None
        if result.returncode != 0 or not out.is_file():
            self.notes.append(
                f"the assertion-class CLI exited {result.returncode} for "
                f"{self.run_dir.as_posix()}: "
                f"{(result.stderr or '').strip()[:300] or 'no stderr'}")
            return None
        return out.as_posix()


# ------------------------------------------------------------- item judges


def _judge_assertion_classes(ctx: _Context) -> dict:
    record = ctx.artifact(ARTIFACT_ASSERTION_CLASSES)
    evidence = [_evidence(record)]
    if not record["available"]:
        return _item(
            ITEM_ASSERTION_CLASSES, measured=False, met=None, value=None,
            evidence=evidence,
            reason=(_notes_text(record) or
                    "no p5_assertion_classes.v1 artifact") +
            "; produce it with the shipped read-only CLI "
            "scripts/report_p5_assertion_classes.py or declare it with "
            f"--artifact {ctx.role}={ARTIFACT_ASSERTION_CLASSES}=PATH")
    document = ctx.document(ARTIFACT_ASSERTION_CLASSES)
    if not isinstance(document, Mapping):
        return _item(ITEM_ASSERTION_CLASSES, measured=False, met=None, value=None,
                     evidence=evidence,
                     reason=f"{record['path']} is not a JSON object")
    from .assertion_classes import (CLASS_CPU_IP, CLASS_CROSS_COMPONENT,
                                    CLASS_PROTOCOL_CHECKER)
    required = (CLASS_PROTOCOL_CHECKER, CLASS_CROSS_COMPONENT, CLASS_CPU_IP)
    classes = document.get("assertion_classes")
    classes = classes if isinstance(classes, Mapping) else {}
    summary: dict[str, dict] = {}
    separate = True
    null_with_reason: list[str] = []
    for section_key in required:
        section = classes.get(section_key)
        if not isinstance(section, Mapping):
            separate = False
            summary[section_key] = {"present": False}
            continue
        count = section.get("finding_count")
        reason = section.get("finding_count_reason")
        valid = (_integer(count) is not None
                 or (count is None and isinstance(reason, str) and reason.strip()))
        # The section stored under a class key must self-identify as that key:
        # the comparison is between the document's own key and its own field,
        # never a guess about what an opaque name means.
        if not valid or section.get("assertion_class") != section_key:
            separate = False
        if count is None:
            null_with_reason.append(section_key)
        summary[section_key] = {
            "present": True, "finding_count": count,
            "finding_count_reason": reason,
            "data_present": section.get("data_present"),
            "observed_record_count": section.get("observed_record_count")}
    census = document.get("not_silently_filtered")
    census = census if isinstance(census, Mapping) else {}
    gate = census.get("gate") if isinstance(census.get("gate"), Mapping) else {}
    unrepresented = census.get("unrepresented")
    unrepresented = unrepresented if isinstance(unrepresented, list) else None
    abnormal = _integer(census.get("abnormal_record_count"))
    represented = _integer(census.get("represented_record_count"))
    engine = _field(document, "engine.module") or {}
    shipped = _module_identity("myfuzz.scenario.assertion_classes")
    identity = ctx.document(ARTIFACT_IDENTITY)
    identity_trace_sha = _field(identity or {}, "identity.trace.semantic_sha256")
    report_trace_sha = _field(document, "trace.semantic_sha256")
    trace_binding = None
    if isinstance(identity_trace_sha, str) and isinstance(report_trace_sha, str):
        trace_binding = identity_trace_sha == report_trace_sha
    engine_matches = bool(shipped) and engine.get("sha256") == shipped["sha256"]
    cli = ROOT / "scripts/report_p5_assertion_classes.py"
    value = {
        "schema_version": document.get("schema_version"),
        "run_dir": document.get("run_dir"),
        "classes": summary,
        "separate_sections": separate,
        "null_counts_with_reason": sorted(null_with_reason),
        "census": {"abnormal_record_count": abnormal,
                   "represented_record_count": represented,
                   "unrepresented_count": (None if unrepresented is None
                                           else len(unrepresented)),
                   "gate_passed": gate.get("passed"),
                   "gate_exit_code": gate.get("exit_code"),
                   "gate_reason": gate.get("reason")},
        "engine": {"module": engine.get("module"), "sha256": engine.get("sha256"),
                   "shipped_sha256": (shipped or {}).get("sha256"),
                   "matches_shipped_module": engine_matches},
        "trace_sha256": {"report": report_trace_sha,
                         "run_identity": identity_trace_sha,
                         "binding": trace_binding},
    }
    reasons: list[str] = []
    if document.get("schema_version") != "p5_assertion_classes.v1":
        reasons.append("the artifact is not a p5_assertion_classes.v1 document "
                       f"(schema_version={document.get('schema_version')!r})")
    if not separate:
        reasons.append("the three assertion classes are not reported as separate, "
                       "self-identifying sections (each needs an integer "
                       "finding_count or null plus finding_count_reason)")
    if gate.get("passed") is not True or gate.get("exit_code") != 0:
        reasons.append("the fail-closed abnormal-record census gate did not pass "
                       f"(passed={gate.get('passed')!r}, "
                       f"exit_code={gate.get('exit_code')!r}, "
                       f"reason={gate.get('reason')!r})")
    if unrepresented:
        reasons.append(f"{len(unrepresented)} abnormal record(s) are not "
                       "represented in the document")
    if abnormal is None or represented is None or abnormal != represented:
        reasons.append("the census is not self-consistent "
                       f"(abnormal={abnormal!r}, represented={represented!r})")
    if not engine_matches:
        reasons.append("the report engine sha256 "
                       f"{engine.get('sha256')!r} does not match the shipped "
                       f"myfuzz.scenario.assertion_classes "
                       f"{(shipped or {}).get('sha256')!r}")
    if trace_binding is False:
        reasons.append("the report was computed over trace semantic_sha256 "
                       f"{report_trace_sha}, which is not the declared run's "
                       f"{identity_trace_sha}")
    if not cli.is_file():
        reasons.append(f"the shipped CLI is missing: {cli.as_posix()}")
    evidence.append({"key": "cli", "path": cli.as_posix(),
                     "resolved": str(cli), "sha256": _sha256_file(cli),
                     "available": cli.is_file()})
    return _item(ITEM_ASSERTION_CLASSES, measured=True,
                 met=(not reasons), value=value, evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _fault_findings(document: object) -> list[str]:
    if not isinstance(document, Mapping):
        return []
    findings = document.get("findings")
    if not isinstance(findings, list):
        return []
    detected = []
    for entry in findings:
        if isinstance(entry, Mapping) and isinstance(entry.get("detected_by"), str):
            detected.append(entry["detected_by"])
    return sorted(set(detected))


def _expected_findings(document: object) -> list[str]:
    if not isinstance(document, Mapping):
        return []
    faults = document.get("faults")
    if not isinstance(faults, list):
        return []
    expected = []
    for fault in faults:
        if isinstance(fault, Mapping) and isinstance(fault.get("expected_finding"), str):
            expected.append(fault["expected_finding"])
    return sorted(set(expected))


def _judge_controlled_fault(ctx: _Context) -> dict:
    replay_record = ctx.artifact(ARTIFACT_MINIMAL_REPLAY)
    family_record = ctx.artifact(ARTIFACT_FAULT_FAMILY_CALIBRATION)
    if not replay_record["available"] and not family_record["available"]:
        return _item(
            ITEM_CONTROLLED_FAULT, measured=False, met=None, value=None,
            evidence=[_evidence(replay_record), _evidence(family_record)],
            reason=(f"neither {ARTIFACT_MINIMAL_REPLAY} nor "
                    f"{ARTIFACT_FAULT_FAMILY_CALIBRATION} was found for "
                    f"{ctx.run_dir.as_posix()}; the item needs a controlled-fault "
                    "calibration root (minimal_replay.json with "
                    "calibration_only / observation_boundary) and, for the "
                    "reproduction half, a declared compare_run of the reproduce "
                    "root"))
    if replay_record["available"]:
        return _judge_single_fault(ctx, replay_record)
    return _judge_fault_family(ctx, family_record)


def _judge_single_fault(ctx: _Context, replay_record: dict) -> dict:
    replay = ctx.document(ARTIFACT_MINIMAL_REPLAY)
    summary = ctx.document(ARTIFACT_FAULT_RUN_SUMMARY)
    fault_document = ctx.document(ARTIFACT_FAULT_DOCUMENT)
    report = ctx.document(ARTIFACT_REPORT)
    summary = summary if isinstance(summary, Mapping) else {}
    report = report if isinstance(report, Mapping) else {}
    evidence = [_evidence(replay_record), _evidence(ctx.artifact(
        ARTIFACT_FAULT_RUN_SUMMARY)), _evidence(ctx.artifact(
            ARTIFACT_FAULT_DOCUMENT)), _evidence(ctx.artifact(ARTIFACT_REPORT))]
    if not isinstance(replay, Mapping):
        return _item(ITEM_CONTROLLED_FAULT, measured=False, met=None, value=None,
                     evidence=evidence,
                     reason=f"{replay_record['path']} is not a JSON object")
    calibration_only = replay.get("calibration_only")
    boundary = replay.get("observation_boundary")
    detected = _fault_findings(replay)
    expected = _expected_findings(fault_document)
    violations = summary.get("violations")
    violations = [value for value in violations
                  if isinstance(value, str)] if isinstance(violations, list) else []
    statuses = report.get("statuses") if isinstance(report.get("statuses"), Mapping) else {}
    reasons: list[str] = []
    if calibration_only is not True:
        reasons.append("the calibration marker calibration_only is not true")
    if boundary != "checker_input_copy":
        reasons.append("the calibration marker observation_boundary is "
                       f"{boundary!r}, not 'checker_input_copy'")
    if not detected:
        reasons.append("the minimal replay names no detected finding")
    if detected and not set(detected) <= set(violations):
        reasons.append("the run's own violations "
                       f"{sorted(set(violations))} do not contain the detected "
                       f"finding(s) {detected}")
    if _integer(statuses.get("dut_violation")) is None or \
            statuses.get("dut_violation", 0) < 1:
        reasons.append("the fault run holds no dut_violation status "
                       f"(statuses={dict(statuses)})")
    if report.get("session_status") != "finding":
        reasons.append("the fault run's session_status is "
                       f"{report.get('session_status')!r}, not 'finding'")
    if expected and not set(detected) <= set(expected):
        reasons.append(f"the detected finding(s) {detected} are not the ones the "
                       f"fault document declares ({expected})")
    reproduce_value = None
    if ctx.compare_run is None:
        reasons.append("no compare_run reproduce root is declared, so the "
                       "fresh-process reproduction half is not measured")
    else:
        reproduce_value, reproduce_reasons = _reproduce_check(ctx, replay,
                                                              summary)
        reasons.extend(reproduce_reasons)
    value = {
        "calibration_only": calibration_only,
        "observation_boundary": boundary,
        "detected_by": detected,
        "expected_findings": expected,
        "violations": sorted(set(violations)),
        "statuses": dict(statuses),
        "session_status": report.get("session_status"),
        "fault_document_sha256": replay.get("fault_document_sha256"),
        "reproduced_by": reproduce_value,
        "shape": "single_fault_calibration_root",
    }
    return _item(ITEM_CONTROLLED_FAULT, measured=True, met=(not reasons),
                 value=value, evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _reproduce_check(ctx: _Context, replay: Mapping,
                     summary: Mapping) -> tuple[dict, list[str]]:
    record = _resolve_artifact(ARTIFACT_REPRODUCTION_SUMMARY,
                               run_dir=ctx.compare_run, explicit=None,
                               compare_run=None)
    report_record = _resolve_artifact(ARTIFACT_REPORT, run_dir=ctx.compare_run,
                                      explicit=None, compare_run=None)
    report = _load_json(Path(report_record["resolved"])) \
        if report_record["available"] else None
    document = ctx.document_of(ARTIFACT_REPRODUCTION_SUMMARY, ctx.compare_run)
    report = report if isinstance(report, Mapping) else {}
    value = {"run_dir": ctx.compare_run.as_posix(),
             "artifact": record["path"],
             "state": "unreadable"}
    reasons: list[str] = []
    if not isinstance(document, Mapping):
        return ({**value, "state": "no reproduction_summary.json"},
                [f"the compare_run {ctx.compare_run.as_posix()} carries no "
                 "reproduction_summary.json, so the reproduction half is not "
                 "measured"])
    faults = document.get("violations")
    faults = [item for item in faults if isinstance(item, str)] \
        if isinstance(faults, list) else []
    detected = _fault_findings(replay)
    replay_sha = replay.get("fault_document_sha256")
    reproduce_sha = document.get("fault_document_sha256")
    statuses = report.get("statuses") if isinstance(report.get("statuses"), Mapping) else {}
    value = {"run_dir": ctx.compare_run.as_posix(), "artifact": record["path"],
             "state": "measured", "violations": sorted(set(faults)),
             "fault_document_sha256": reproduce_sha,
             "fault_document_sha256_matches": reproduce_sha == replay_sha,
             "statuses": dict(statuses),
             "tests": document.get("tests")}
    if not set(detected) <= set(faults):
        reasons.append(f"the reproduce root's violations {sorted(set(faults))} do "
                       f"not contain the detected finding(s) {detected}")
    if replay_sha is None or reproduce_sha != replay_sha:
        reasons.append("the reproduce root's fault_document_sha256 "
                       f"{reproduce_sha!r} does not match the minimal replay's "
                       f"{replay_sha!r}")
    if _integer(statuses.get("dut_violation")) is None or \
            statuses.get("dut_violation", 0) < 1:
        reasons.append("the reproduce run holds no dut_violation status "
                       f"(statuses={dict(statuses)})")
    if isinstance(summary.get("tests"), int) and \
            isinstance(document.get("tests"), int) and \
            summary.get("tests") != document.get("tests"):
        reasons.append(f"the reproduce root ran {document.get('tests')} case(s), "
                       f"the fault root {summary.get('tests')}")
    return value, reasons


def _judge_fault_family(ctx: _Context, family_record: dict) -> dict:
    family = ctx.document(ARTIFACT_FAULT_FAMILY_CALIBRATION)
    verify_record = ctx.artifact(ARTIFACT_FAULT_FAMILY_VERIFY)
    verify = ctx.document(ARTIFACT_FAULT_FAMILY_VERIFY)
    evidence = [_evidence(family_record), _evidence(verify_record)]
    if not isinstance(family, Mapping):
        return _item(ITEM_CONTROLLED_FAULT, measured=False, met=None, value=None,
                     evidence=evidence,
                     reason=f"{family_record['path']} is not a JSON object")
    variants = family.get("variants")
    variants = [variant for variant in variants if isinstance(variant, Mapping)] \
        if isinstance(variants, list) else []
    calibrated = [variant for variant in variants
                  if variant.get("status") == "calibrated"]
    detected: list[str] = []
    for variant in calibrated:
        observed = variant.get("observed_findings")
        if isinstance(observed, list):
            detected.extend(item for item in observed if isinstance(item, str))
        if isinstance(variant.get("expected_finding"), str):
            detected.append(variant["expected_finding"])
    detected = sorted(set(detected))
    verify_ok = None
    checked_variants = 0
    failed_checks: list[str] = []
    if isinstance(verify, Mapping):
        checked_variants = len(verify.get("variants") or [])
        for variant in (verify.get("variants") or []):
            if not isinstance(variant, Mapping):
                failed_checks.append("a variant entry is not an object")
                continue
            if variant.get("ok") is not True:
                failed_checks.append(f"{variant.get('variant')!r} is not ok")
            for check in (variant.get("checks") or []):
                if isinstance(check, Mapping) and check.get("ok") is not True:
                    failed_checks.append(
                        f"{variant.get('variant')!r}:{check.get('name')!r}")
    reasons: list[str] = []
    if family.get("calibration_only") is not True:
        reasons.append("the family calibration marker calibration_only is not true")
    if family.get("observation_boundary") != "checker_input_copy":
        reasons.append("the family calibration marker observation_boundary is "
                       f"{family.get('observation_boundary')!r}, not "
                       "'checker_input_copy'")
    if not calibrated:
        reasons.append("the family calibration holds no calibrated variant")
    if not isinstance(verify, Mapping):
        reasons.append("no fault_family_calibration_verify.json was found, so the "
                       "independent read-only verification is not measured")
    else:
        if verify.get("ok") is not True:
            reasons.append("the independent verifier reports ok is not true")
        if verify.get("failures"):
            reasons.append(f"the independent verifier reports "
                           f"{len(verify['failures'])} failure(s)")
        if failed_checks:
            reasons.append("the independent verifier reports failing checks: "
                           + ", ".join(sorted(set(failed_checks))[:6]))
    reproduce_value = None
    if ctx.compare_run is None:
        reasons.append("no compare_run reproduce root is declared; the shipped "
                       "family verifier's own limit is that it is read-only over "
                       "saved artifacts and does not re-run RTL or prove a "
                       "fresh-process reproduction")
    else:
        reproduce_value, reproduce_reasons = _family_reproduce_check(
            ctx, detected, family)
        reasons.extend(reproduce_reasons)
    value = {
        "shape": "fault_family_calibration_root",
        "calibration_only": family.get("calibration_only"),
        "observation_boundary": family.get("observation_boundary"),
        "variants_total": len(variants),
        "variants_calibrated": len(calibrated),
        "detected_by": detected,
        "verify": {"available": isinstance(verify, Mapping),
                   "ok": (verify or {}).get("ok") if isinstance(verify, Mapping) else None,
                   "failures": len(verify.get("failures") or [])
                   if isinstance(verify, Mapping) else None,
                   "variants_checked": checked_variants,
                   "failed_checks": sorted(set(failed_checks))},
        "reproduced_by": reproduce_value,
    }
    return _item(ITEM_CONTROLLED_FAULT, measured=True, met=(not reasons),
                 value=value, evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _family_reproduce_check(ctx: _Context, detected: list[str],
                            family: Mapping) -> tuple[dict, list[str]]:
    document = ctx.document_of(ARTIFACT_REPRODUCTION_SUMMARY, ctx.compare_run)
    if not isinstance(document, Mapping):
        return ({"run_dir": ctx.compare_run.as_posix(), "state": "no artifact"},
                [f"the compare_run {ctx.compare_run.as_posix()} carries no "
                 "reproduction_summary.json"])
    faults = document.get("violations")
    faults = [item for item in faults if isinstance(item, str)] \
        if isinstance(faults, list) else []
    # The reproduce root must name a fault document the family itself
    # calibrated, so a reproduction of an unrelated fault cannot be counted.
    family_shas: set[str] = set()
    for variant in (family.get("variants") or []):
        if not isinstance(variant, Mapping):
            continue
        fault_document = variant.get("fault_document")
        if isinstance(fault_document, Mapping) and \
                isinstance(fault_document.get("sha256"), str):
            family_shas.add(fault_document["sha256"])
    reproduce_sha = document.get("fault_document_sha256")
    value = {"run_dir": ctx.compare_run.as_posix(), "state": "measured",
             "violations": sorted(set(faults)),
             "fault_document_sha256": reproduce_sha,
             "fault_document_sha256_in_family": reproduce_sha in family_shas}
    reasons: list[str] = []
    if not set(faults) & set(detected):
        reasons.append(f"the reproduce root reproduces {sorted(set(faults))}, "
                       f"which does not intersect the family's calibrated "
                       f"findings {detected}")
    if family_shas and reproduce_sha not in family_shas:
        value["state"] = "sha256_not_in_family"
        reasons.append("the reproduce root's fault_document_sha256 "
                       f"{reproduce_sha!r} is not any family variant's calibrated "
                       "fault document")
    return value, reasons


def _read_receipts(path: Path) -> tuple[dict | None, str | None]:
    """Stream one receipts.jsonl; a partially readable file measures nothing."""
    statuses: dict[str, int] = {}
    violations: set[str] = set()
    try:
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    return None, (f"receipts.jsonl line {number} is not JSON "
                                  f"({error.msg}); nothing is counted from a "
                                  "partially readable receipts file")
                if not isinstance(row, Mapping):
                    return None, (f"receipts.jsonl line {number} is not a "
                                  "receipt object")
                status = row.get("status")
                if isinstance(status, str):
                    statuses[status] = statuses.get(status, 0) + 1
                for value in (row.get("violations") or []):
                    if isinstance(value, str):
                        violations.add(value)
    except (OSError, UnicodeDecodeError) as error:
        return None, f"receipts.jsonl could not be read: {error}"
    return {"statuses": statuses, "violations": sorted(violations)}, None


def _resolved_session_status(report: Mapping) -> tuple[object, str | None, str | None]:
    """Where one report declares its run status, and why it cannot be used.

    ``session_status`` always wins.  Only a report that does not carry the key
    at all may fall back to the status field its own schema declares (for
    example ``first_step_cold_start_run_report.v1:execution_status``); a report
    that carries an explicit ``null`` states that it has no session status, so
    the null is reported as such instead of being papered over by another field.
    Returns ``(status, source, reason)`` with ``reason`` set whenever no usable
    status could be resolved.
    """
    if "session_status" in report:
        status = report.get("session_status")
        source = f"{REPORT_FILE}:session_status"
        if status is None:
            return None, source, (f"{source} is null, so the report declares no "
                                  "session status")
        if not isinstance(status, str) or not status:
            return None, source, (f"{source} is {status!r}, not a non-empty "
                                  "status string")
        return status, source, None
    schema = report.get("schema_version")
    field = DECLARED_SESSION_STATUS_FIELDS.get(schema) if isinstance(schema, str) else None
    if field is None:
        known = ", ".join(sorted(DECLARED_SESSION_STATUS_FIELDS)) or "none"
        return None, None, (
            f"the report carries no {REPORT_FILE}:session_status and its schema "
            f"{schema!r} declares no run-status field (schemas read this way: {known})")
    source = f"{REPORT_FILE}:{field} (declared by schema {schema})"
    value = report.get(field)
    if not isinstance(value, str) or not value:
        return None, source, (f"{source} is {value!r}, not a non-empty status "
                              "string")
    return value, source, None


def _receipt_session_status(receipts: Mapping) -> tuple[str | None, str | None]:
    """The session status the per-case receipts prove, else ``None`` + reason."""
    statuses = receipts.get("statuses")
    statuses = statuses if isinstance(statuses, Mapping) else {}
    if not statuses:
        return None, ("the receipts hold no per-case row, so no session status "
                      "can be derived from them")
    if set(statuses) == CONTROL_STATUSES:
        return "complete", None
    return None, (f"the per-case receipts carry status(es) "
                  f"{dict(sorted(statuses.items()))}, so the session is not "
                  "complete")


def _family_control_evidence(ctx: _Context, expected_findings: Sequence[str]
                             ) -> dict | None:
    """The control-run proof a fault-family calibration root carries.

    The family root holds no receipts of its own: each variant ran in its own
    session, and the shipped independent verifier records a ``control_run_clean``
    check per variant against the control run the variant was selected from.
    That check plus the control run's own receipts is the control evidence.
    """
    calibration = ctx.document(ARTIFACT_FAULT_FAMILY_CALIBRATION)
    verify = ctx.document(ARTIFACT_FAULT_FAMILY_VERIFY)
    if not isinstance(calibration, Mapping) or not isinstance(verify, Mapping):
        return None
    variants = [variant for variant in (verify.get("variants") or [])
                if isinstance(variant, Mapping)]
    if not variants:
        return None
    family_findings = set(expected_findings)
    for variant in (calibration.get("variants") or []):
        if not isinstance(variant, Mapping):
            continue
        observed = variant.get("observed_findings")
        if isinstance(observed, list):
            family_findings.update(item for item in observed
                                   if isinstance(item, str))
        if isinstance(variant.get("expected_finding"), str):
            family_findings.add(variant["expected_finding"])
    control_checks: list[dict] = []
    reasons: list[str] = []
    for variant in variants:
        checks = [check for check in (variant.get("checks") or [])
                  if isinstance(check, Mapping)]
        names = {check.get("name") for check in checks}
        clean = [check for check in checks
                 if check.get("name") == "control_run_clean"]
        ok = (variant.get("ok") is True
              and bool(clean) and all(check.get("ok") is True for check in clean)
              and names >= {"control_run_clean", "control_trace_unchanged"})
        control_checks.append({"variant": variant.get("variant"), "clean": ok,
                               "checks": sorted(name for name in names
                                                if isinstance(name, str))})
        if not ok:
            reasons.append(f"variant {variant.get('variant')!r} has no passing "
                           "control_run_clean / control_trace_unchanged check")
    control_runs = sorted({variant.get("source_run", {}).get("path")
                           for variant in (calibration.get("variants") or [])
                           if isinstance(variant, Mapping)
                           and isinstance(variant.get("source_run"), Mapping)
                           and isinstance(variant["source_run"].get("path"), str)})
    scanned: list[dict] = []
    for control in control_runs:
        directory = Path(control)
        if not directory.is_absolute():
            directory = ROOT / control
        receipts_path = directory / "receipts.jsonl"
        if not receipts_path.is_file():
            scanned.append({"run_dir": control, "state": "no receipts.jsonl"})
            continue
        receipts, error = _read_receipts(receipts_path)
        if receipts is None:
            reasons.append(f"control run {control}: {error}")
            scanned.append({"run_dir": control, "state": "unreadable"})
            continue
        present = sorted(set(receipts["violations"]) & family_findings)
        scanned.append({"run_dir": control,
                        "state": "scanned",
                        "receipts": sum(receipts["statuses"].values()),
                        "statuses": dict(receipts["statuses"]),
                        "violations": receipts["violations"],
                        "carries_a_family_finding": present})
        if present:
            reasons.append(f"the control run {control} carries the family "
                           f"finding(s) {present}")
    return {"source": "fault_family_calibration_verify.json control checks",
            "control_checks": control_checks,
            "control_runs": scanned,
            "family_findings": sorted(family_findings),
            "clean": not reasons,
            "reasons": reasons}


def _judge_normal_control(ctx: _Context, expected_findings: Sequence[str]) -> dict:
    report_record = ctx.artifact(ARTIFACT_REPORT)
    receipts_record = ctx.artifact(ARTIFACT_RECEIPTS)
    failures = ctx.run_dir / "failures"
    evidence = [_evidence(report_record), _evidence(receipts_record)]
    report = ctx.document(ARTIFACT_REPORT)
    if not report_record["available"] or not receipts_record["available"]:
        family = _family_control_evidence(ctx, expected_findings)
        if family is not None:
            evidence.extend([_evidence(ctx.artifact(
                ARTIFACT_FAULT_FAMILY_VERIFY)),
                _evidence(ctx.artifact(ARTIFACT_FAULT_FAMILY_CALIBRATION))])
            return _item(ITEM_NORMAL_CONTROL, measured=True,
                         met=family["clean"], value=family, evidence=evidence,
                         reason=(None if family["clean"]
                                 else "; ".join(family["reasons"])))
        return _item(
            ITEM_NORMAL_CONTROL, measured=False, met=None, value=None,
            evidence=evidence,
            reason=("the run carries no readable report.json / receipts.jsonl, so "
                    "its control signature cannot be measured ("
                    + "; ".join(_notes_text(record)
                                for record in (report_record, receipts_record)
                                if record["notes"]) + ")"))
    if not isinstance(report, Mapping):
        return _item(ITEM_NORMAL_CONTROL, measured=False, met=None, value=None,
                     evidence=evidence,
                     reason=f"{report_record['path']} is not a JSON object")
    receipts, error = _read_receipts(Path(receipts_record["resolved"]))
    if receipts is None:
        return _item(ITEM_NORMAL_CONTROL, measured=False, met=None, value=None,
                     evidence=evidence, reason=error)
    statuses = report.get("statuses") if isinstance(report.get("statuses"), Mapping) else {}
    session_status, session_status_source, session_status_reason = (
        _resolved_session_status(report))
    receipts_status, receipts_status_reason = _receipt_session_status(receipts)
    exceptions = [name for name in statuses if name not in CONTROL_STATUSES]
    failure_records = sorted(path.name for path in failures.glob("*.json")) \
        if failures.is_dir() else []
    offending = sorted(set(receipts["violations"]) | set(expected_findings))
    reasons: list[str] = []
    if session_status_reason:
        reasons.append(session_status_reason)
    if exceptions:
        reasons.append(f"the run reports non-control status(es) "
                       f"{sorted(exceptions)} (statuses={dict(statuses)})")
    if session_status not in CONTROL_STATUSES:
        reasons.append(
            f"session_status is {session_status!r}, not 'complete'"
            + (f" ({session_status_source})" if session_status_source else ""))
    elif receipts_status != "complete":
        # A declared complete session still needs the per-case rows to agree:
        # the declaration alone can never turn a non-complete case into a clean
        # control.
        reasons.append("the run declares a complete session, but "
                       + (receipts_status_reason or "its receipts do not agree"))
    reported_statuses = {str(name): count for name, count in statuses.items()}
    if reported_statuses and reported_statuses != dict(receipts["statuses"]):
        reasons.append(
            f"{REPORT_FILE}:statuses {dict(statuses)} contradicts the per-case "
            f"receipts {dict(receipts['statuses'])}")
    if failure_records:
        reasons.append(f"the run holds {len(failure_records)} failure record(s): "
                       f"{failure_records[:4]}")
    if receipts["violations"]:
        reasons.append("the receipts carry violation string(s) "
                       f"{receipts['violations']}")
    if expected_findings:
        present = sorted(set(receipts["violations"]) & set(expected_findings))
        if present:
            reasons.append(f"the control run carries the injected finding(s) "
                           f"{present}, so it is not a clean control")
    value = {"statuses": dict(statuses), "session_status": session_status,
             "session_status_source": session_status_source,
             "receipt_derived_session_status": receipts_status,
             "violations": receipts["violations"],
             "failure_records": failure_records,
             "receipts": sum(receipts["statuses"].values()),
             "expected_findings_checked": sorted(set(expected_findings)),
             "clean": not reasons}
    return _item(ITEM_NORMAL_CONTROL, measured=True, met=(not reasons),
                 value=value, evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _saved_refusal_artifact() -> dict:
    """The saved evidence that a real identity mismatch was refused.

    The refusal logs are repository-level artifacts of the paired run's
    cold-group replays; they are cited with that subject and never presented as
    a refusal of the declared run.
    """
    artifacts: list[dict] = []
    message = None
    matches = None
    failed = None
    for relative, kind in IDENTITY_REFUSAL_ARTIFACTS:
        path = ROOT / relative
        if not path.is_file():
            continue
        artifacts.append({"path": relative, "kind": kind,
                          "sha256": _sha256_file(path)})
        if kind == "refusal log" and message is None:
            try:
                first = path.read_text(encoding="utf-8",
                                       errors="replace").strip().splitlines()
            except OSError:
                first = []
            if first:
                message = first[0][:400]
        elif kind == "replay summary":
            document = _load_json(path)
            if isinstance(document, Mapping):
                if _integer(document.get("matches")) is not None and matches is None:
                    matches = document.get("matches")
                if _integer(document.get("cold_replay_failed")) is not None:
                    failed = document.get("cold_replay_failed")
    return {"available": bool(artifacts), "subject": IDENTITY_REFUSAL_SUBJECT,
            "declared_run_itself": False, "artifacts": artifacts,
            "matches": matches, "cold_replay_failed": failed,
            "message": message}


def _judge_complete_prefix(ctx: _Context) -> dict:
    identity_record = ctx.artifact(ARTIFACT_IDENTITY)
    replay_record = ctx.artifact(ARTIFACT_REPLAY)
    report = ctx.document(ARTIFACT_REPORT)
    report = report if isinstance(report, Mapping) else {}
    evidence = [_evidence(identity_record), _evidence(replay_record),
                _evidence(ctx.artifact(ARTIFACT_PLAN)),
                _evidence(ctx.artifact(ARTIFACT_MANIFEST)),
                _evidence(ctx.artifact(ARTIFACT_TRACE_META))]
    if not identity_record["available"]:
        return _item(
            ITEM_COMPLETE_PREFIX, measured=False, met=None, value=None,
            evidence=evidence,
            reason=(_notes_text(identity_record) or
                    "no online_run_identity.json") +
            "; without the saved identity envelope the raw/plan/trace/manifest "
            "prefix cannot be checked")
    envelope = ctx.document(ARTIFACT_IDENTITY)
    if not isinstance(envelope, Mapping):
        return _item(ITEM_COMPLETE_PREFIX, measured=False, met=None, value=None,
                     evidence=evidence,
                     reason=f"{identity_record['path']} is not a JSON object")
    identity = envelope.get("identity")
    identity = identity if isinstance(identity, Mapping) else {}
    artifacts = identity.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, Mapping) else {}
    genome = identity.get("genome") if isinstance(identity.get("genome"), Mapping) else {}
    trace = identity.get("trace") if isinstance(identity.get("trace"), Mapping) else {}
    session = identity.get("session") if isinstance(identity.get("session"), Mapping) else {}
    reasons: list[str] = []

    def bound(name: str, record: dict) -> bool:
        declared = artifacts.get(name)
        if not record["available"]:
            reasons.append(f"the {name} file is missing or was not found")
            return False
        if not _is_digest(declared):
            reasons.append(f"identity.artifacts[{name!r}] is not a sha256")
            return False
        if record["sha256"] != declared:
            reasons.append(f"the {name} file sha256 {record['sha256']} does not "
                           f"match identity.artifacts[{name!r}]={declared}")
            return False
        return True

    receipts_record = ctx.artifact(ARTIFACT_RECEIPTS)
    plan_record = ctx.artifact(ARTIFACT_PLAN)
    manifest_record = ctx.artifact(ARTIFACT_MANIFEST)
    seed_record = ctx.artifact(ARTIFACT_SEED)
    raw_ok = bound("receipts.jsonl", receipts_record)
    raw_ok = bound("seed.bin", seed_record) and raw_ok
    corpus = [name for name in artifacts
              if isinstance(name, str)
              and set(PurePosixPath(name).parts) & CORPUS_COMPONENTS]
    if not corpus:
        reasons.append("identity.artifacts carries no corpus/entry_* raw input")
    plan_ok = bound("online_plan.json", plan_record)
    if _is_digest(genome.get("plan_sha256")) and \
            genome.get("plan_sha256") != artifacts.get("online_plan.json"):
        reasons.append("identity.genome.plan_sha256 "
                       f"{genome.get('plan_sha256')} does not match "
                       f"identity.artifacts['online_plan.json'] "
                       f"{artifacts.get('online_plan.json')}")
        plan_ok = False
    if not _is_digest(genome.get("plan_sha256")):
        reasons.append("identity.genome.plan_sha256 is not a sha256")
        plan_ok = False
    manifest_ok = bound("online_session_manifest.json", manifest_record)
    trace_ok = True
    if not _is_digest(trace.get("semantic_sha256")):
        reasons.append("identity.trace.semantic_sha256 is not a sha256")
        trace_ok = False
    if trace.get("manifest_sha256") != session.get("manifest_sha256"):
        reasons.append("identity.trace.manifest_sha256 "
                       f"{trace.get('manifest_sha256')!r} does not match "
                       f"identity.session.manifest_sha256 "
                       f"{session.get('manifest_sha256')!r}")
        trace_ok = False
    trace_file = identity.get("trace_file")
    trace_path = ctx.run_dir / str(trace_file) if isinstance(trace_file, str) else None
    if trace_path is None or not trace_path.exists():
        reasons.append(f"the declared trace file {trace_file!r} does not exist")
        trace_ok = False
    meta = ctx.document(ARTIFACT_TRACE_META)
    meta_binding = "no meta document (monolithic json.v1 trace)"
    if isinstance(meta, Mapping):
        meta_binding = "meta"
        if meta.get("semantic_sha256") != trace.get("semantic_sha256") or \
                meta.get("manifest_sha256") != trace.get("manifest_sha256") or \
                meta.get("genome_sha256") != trace.get("genome_sha256"):
            reasons.append("online_final_trace.meta.json disagrees with "
                           "identity.trace on semantic/manifest/genome sha256")
            trace_ok = False
    envelope_binding = None
    if report:
        envelope_binding = (report.get("online_run_identity_sha256")
                            == envelope.get("sha256"))
        if not envelope_binding:
            reasons.append("report.json online_run_identity_sha256 "
                           f"{report.get('online_run_identity_sha256')!r} does not "
                           f"match the identity envelope sha256 "
                           f"{envelope.get('sha256')!r}")
    replay_ok = False
    replay_value = None
    if not replay_record["available"]:
        reasons.append("no fresh-replay document (replay.json / replay.log) was "
                       "found, so matches=true is not measured")
    else:
        replay = ctx.document(ARTIFACT_REPLAY)
        if not isinstance(replay, Mapping):
            reasons.append(f"{replay_record['path']} is not a JSON object")
        else:
            replay_ok = (replay.get("matches") is True
                         and replay.get("first_difference") is None)
            replay_value = {"matches": replay.get("matches"),
                            "first_difference": replay.get("first_difference"),
                            "difference_context": replay.get("difference_context"),
                            "artifact": replay_record["path"]}
            if replay.get("matches") is not True:
                reasons.append("the fresh-replay document does not report "
                               f"matches=true (matches={replay.get('matches')!r})")
            if replay.get("first_difference") is not None:
                reasons.append("the fresh-replay document reports a first "
                               f"difference {replay.get('first_difference')!r}")
    refusal = None
    for mechanism in IDENTITY_REFUSAL_MECHANISMS:
        module = _module_identity(mechanism["module"])
        if module is None:
            continue
        citation = ROOT / mechanism["citation"]
        refusal = {"mechanism": f"{mechanism['module']}.{mechanism['symbol']}",
                   "refusal": mechanism["refusal"],
                   "stage": mechanism["stage"],
                   "module": module,
                   "citation": mechanism["citation"],
                   "citation_available": citation.is_file()}
        break
    saved_refusal = _saved_refusal_artifact()
    if refusal is None:
        reasons.append("no shipped identity-refusal mechanism could be resolved, "
                       "so 'refused before start' is not cited")
    elif not refusal["citation_available"] and not saved_refusal["available"]:
        reasons.append("the identity-refusal mechanism is cited but neither its "
                       "shipped report nor a saved refusal artifact exists")
    value = {
        "identities": {"raw": raw_ok, "plan": plan_ok, "trace": trace_ok,
                       "manifest": manifest_ok},
        "envelope_sha256": envelope.get("sha256"),
        "report_binding": envelope_binding,
        "trace_binding": meta_binding,
        "run_id": (identity.get("run_config") or {}).get("run_id")
        if isinstance(identity.get("run_config"), Mapping) else None,
        "replay": replay_value,
        "identity_refusal": refusal,
        "saved_refusal_artifact": saved_refusal,
    }
    return _item(ITEM_COMPLETE_PREFIX, measured=True, met=(not reasons),
                 value=value, evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _judge_long_search(ctx: _Context, expected_findings: Sequence[str]) -> dict:
    record = ctx.artifact(ARTIFACT_FIRST_STEP_ACCEPTANCE)
    replay_record = ctx.artifact(ARTIFACT_REPLAY)
    report = ctx.document(ARTIFACT_REPORT)
    report = report if isinstance(report, Mapping) else {}
    evidence = [_evidence(record), _evidence(replay_record)]
    if not record["available"]:
        return _item(
            ITEM_LONG_SEARCH, measured=False, met=None, value=None,
            evidence=evidence,
            reason=(_notes_text(record) or
                    "no first_step_acceptance_report.v1 artifact") +
            "; the chain count, chain/s and natural-finding count are only in "
            "that report (produced by scripts/run_first_step_acceptance.py)")
    document = ctx.document(ARTIFACT_FIRST_STEP_ACCEPTANCE)
    if not isinstance(document, Mapping):
        return _item(ITEM_LONG_SEARCH, measured=False, met=None, value=None,
                     evidence=evidence,
                     reason=f"{record['path']} is not a JSON object")
    chains = document.get("certified_chains")
    chains = chains if isinstance(chains, Mapping) else {}
    seconds = _finite(document.get("effective_search_seconds"))
    per_second = _finite(document.get("certified_chains_per_second"))
    total = _integer(chains.get("total"))
    findings = document.get("invalid_or_timeout_detail")
    findings = findings if isinstance(findings, Mapping) else {}
    natural = _integer(findings.get("findings"))
    trace_evidence = document.get("trace_evidence")
    trace_evidence = trace_evidence if isinstance(trace_evidence, Mapping) else {}
    reasons: list[str] = []
    if seconds is None:
        reasons.append("effective_search_seconds is not a finite number")
    elif seconds < MINIMUM_LONG_SEARCH_SECONDS:
        reasons.append(f"effective_search_seconds {seconds} is below the ten-minute "
                       f"floor {MINIMUM_LONG_SEARCH_SECONDS}")
    if total is None:
        reasons.append("certified_chains.total is not an integer")
    elif total < 1:
        reasons.append("the run certified no chain (certified_chains.total=0)")
    if chains.get("cap_reached") is True:
        reasons.append("certified_chains.cap_reached is true, so the count is a "
                       "lower bound")
    if per_second is None:
        reasons.append("certified_chains_per_second is not a finite number")
    if natural is None:
        reasons.append("invalid_or_timeout_detail.findings is not an integer, so "
                       "the natural-finding count is not stated")
    if trace_evidence.get("semantic_sha256_verified") is not True:
        reasons.append("trace_evidence.semantic_sha256_verified is not true")
    report_seconds = _finite(report.get("effective_search_seconds"))
    binding = None
    if report_seconds is None:
        binding = "no run report to bind"
        reasons.append("the run's own report.json is missing or carries no "
                       "effective_search_seconds, so the acceptance report is not "
                       "bound to the run")
    else:
        binding = report_seconds == seconds
        if not binding:
            reasons.append("the acceptance report's effective_search_seconds "
                           f"{seconds} does not match the run report's "
                           f"{report_seconds}")
    replay_value = None
    replay_ok = False
    embedded = document.get("replay")
    if isinstance(embedded, Mapping) and embedded.get("matches") is not None:
        replay_ok = (embedded.get("matches") is True
                     and embedded.get("first_difference") is None)
        replay_value = {"source": record["path"],
                        "matches": embedded.get("matches"),
                        "first_difference": embedded.get("first_difference")}
    elif replay_record["available"]:
        replay = ctx.document(ARTIFACT_REPLAY)
        if isinstance(replay, Mapping):
            replay_ok = (replay.get("matches") is True
                         and replay.get("first_difference") is None)
            replay_value = {"source": replay_record["path"],
                            "matches": replay.get("matches"),
                            "first_difference": replay.get("first_difference")}
    if replay_value is None:
        reasons.append("no fresh-replay result (neither the acceptance report's "
                       "replay field nor a replay.json/replay.log artifact)")
    elif not replay_ok:
        reasons.append("the fresh-replay result does not report matches=true "
                       f"(matches={replay_value.get('matches')!r}, "
                       f"first_difference={replay_value.get('first_difference')!r})")
    value = {
        "run_dir": document.get("run_dir"),
        "effective_search_seconds": seconds,
        "certified_chains": total,
        "certified_chains_cap_reached": chains.get("cap_reached"),
        "certified_chains_by_direction": dict(chains.get("by_direction") or {})
        if isinstance(chains.get("by_direction"), Mapping) else {},
        "certified_chains_per_second": per_second,
        "incomplete_certificates": _integer(chains.get("incomplete_total")),
        "natural_findings": natural,
        "findings_statement": ("0 natural findings is the run's own reported "
                               "count" if natural == 0 else
                               f"{natural} finding(s) reported"),
        "replay": replay_value,
        "report_binding": binding,
        "trace_semantic_sha256_verified": trace_evidence.get(
            "semantic_sha256_verified"),
        "reported_tests": _integer(document.get("reported_tests")),
        "limits": list(document.get("limits") or [])[:4],
    }
    return _item(ITEM_LONG_SEARCH, measured=True, met=(not reasons), value=value,
                 evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _case_ids_from_receipts(path: Path) -> tuple[list[str] | None, str | None]:
    ids: list[str] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    return None, (f"receipts.jsonl line {number} is not JSON "
                                  f"({error.msg})")
                if not isinstance(row, Mapping) or not isinstance(
                        row.get("case_id"), str):
                    return None, (f"receipts.jsonl line {number} carries no "
                                  "case_id")
                ids.append(row["case_id"])
    except (OSError, UnicodeDecodeError) as error:
        return None, f"receipts.jsonl could not be read: {error}"
    return ids, None


def _paired_sides(ctx: _Context) -> tuple[dict | None, dict | None, list[str]]:
    """Return the (continuous, cold_start) arms of one paired declaration.

    Either side may be the declared run: a cold-start arm names its continuous
    run in ``report.json:continuous_run_dir``, and a continuous arm names the
    cold-start run as its ``compare_run``.
    """
    own_report = ctx.document(ARTIFACT_REPORT)
    own_report = own_report if isinstance(own_report, Mapping) else {}
    own_cold = ctx.document(ARTIFACT_COLD_START)
    own_cold_record = ctx.artifact(ARTIFACT_COLD_START)
    compare_report = None
    compare_cold = None
    compare_cold_record = None
    if ctx.compare_run is not None:
        compare_report = ctx.document_of(ARTIFACT_REPORT, ctx.compare_run)
        compare_cold = ctx.document_of(ARTIFACT_COLD_START, ctx.compare_run)
        compare_cold_record = ctx.artifact_of(ARTIFACT_COLD_START, ctx.compare_run)
    continuous: dict | None = None
    cold: dict | None = None
    if isinstance(own_cold, Mapping):
        continuous = {"run_dir": ctx.run_dir.as_posix(),
                      "source": "continued_report",
                      "report": ctx.document(ARTIFACT_CONTINUED_REPORT)
                      if isinstance(ctx.document(ARTIFACT_CONTINUED_REPORT),
                                    Mapping) else {},
                      "cold": own_cold,
                      "cold_artifact": own_cold_record["path"]}
        cold = continuous
    if isinstance(compare_cold, Mapping):
        cold = {"run_dir": ctx.compare_run.as_posix(),
                "source": "compare_run",
                "report": compare_report if isinstance(compare_report, Mapping) else {},
                "cold": compare_cold,
                "cold_artifact": (compare_cold_record or {}).get("path")}
        continuous = {"run_dir": ctx.run_dir.as_posix(), "source": "declared_run",
                      "report": own_report, "cold": None, "cold_artifact": None}
    if cold is None:
        return None, None, [
            "no per-case cold-start arm could be resolved: neither the declared "
            f"run nor its compare_run carries {ARTIFACT_COLD_START}"]
    return continuous, cold, []


def _judge_paired_budget(ctx: _Context, expected_findings: Sequence[str]) -> dict:
    continuous, cold, problems = _paired_sides(ctx)
    if continuous is None or cold is None:
        return _item(
            ITEM_PAIRED_BUDGET, measured=False, met=None, value=None,
            evidence=[_evidence(ctx.artifact(ARTIFACT_REPORT)),
                      _evidence(ctx.artifact(ARTIFACT_COLD_START))],
            reason=("; ".join(problems) +
                    "; the paired item needs both arms of one same-budget pair "
                    f"(declare it as --run ROLE=CONTINUOUS@{ctx.run_dir.as_posix()}"
                    " or the reverse)"))
    report = continuous["report"] if isinstance(continuous["report"], Mapping) else {}
    cold_report = cold["report"] if isinstance(cold["report"], Mapping) else {}
    cold_document = cold["cold"] if isinstance(cold["cold"], Mapping) else {}
    continuous_seconds = _finite(report.get("elapsed_seconds"))
    continuous_effective = _finite(report.get("effective_search_seconds"))
    continuous_cases = _integer(report.get("tests"))
    cold_wall = _finite(cold_report.get("wall_clock_seconds")) or \
        _finite(cold_document.get("elapsed_seconds"))
    cold_cases = _integer(cold_document.get("case_count")) or \
        _integer(cold_report.get("case_count")) or _integer(cold_report.get("tests"))
    verified = _integer(cold_document.get("verified_case_count")) or \
        _integer(cold_report.get("verified_case_count"))
    init_total = _finite(cold_document.get("init_seconds_total"))
    total_total = _finite(cold_document.get("total_seconds_total"))
    reasons: list[str] = []
    if continuous_seconds is None:
        reasons.append("the continuous arm carries no elapsed_seconds")
    if cold_wall is None:
        reasons.append("the cold-start arm carries no wall clock "
                       "(wall_clock_seconds / cold_start.elapsed_seconds)")
    speedup = None
    if continuous_seconds and cold_wall:
        if continuous_seconds <= 0:
            reasons.append("the continuous arm's elapsed_seconds is not positive")
        else:
            speedup = cold_wall / continuous_seconds
            if speedup <= 1.0:
                reasons.append("the per-case cold start is not slower than the "
                               f"continuous session (speedup={speedup})")
    if continuous_cases is None:
        reasons.append("the continuous arm reports no case count")
    if cold_cases is None:
        reasons.append("the cold-start arm reports no case count")
    if continuous_cases is not None and cold_cases is not None and \
            continuous_cases != cold_cases:
        reasons.append(f"the arms ran different case counts "
                       f"({continuous_cases} vs {cold_cases})")
    if verified is not None and cold_cases is not None and verified != cold_cases:
        reasons.append(f"only {verified}/{cold_cases} cold-start cases verified")
    mismatch = _integer(cold_report.get("status_mismatch_count"))
    if mismatch not in (None, 0):
        reasons.append(f"the cold-start arm reports {mismatch} status mismatch(es)")
    failures = _integer(cold_report.get("verification_failure_count"))
    if failures not in (None, 0):
        reasons.append(f"the cold-start arm reports {failures} verification "
                       "failure(s)")
    ids_continuous, ids_error = _case_ids_from_receipts(
        ctx.run_dir / "receipts.jsonl")
    cold_ids = [case.get("case_id") for case in (cold_document.get("cases") or [])
                if isinstance(case, Mapping) and isinstance(case.get("case_id"), str)]
    matched = None
    if ids_error:
        reasons.append(ids_error)
    elif cold_ids:
        matched = sorted(ids_continuous or []) == sorted(cold_ids)
        if not matched:
            reasons.append("the two arms do not carry the same case ids")
    scope = cold_document.get("comparison_scope")
    paired_record = ctx.artifact(ARTIFACT_PAIRED_REPORT)
    paired = ctx.document(ARTIFACT_PAIRED_REPORT)
    paired = paired if isinstance(paired, Mapping) else None
    equivalence = _chain_equivalence(ctx, cold, paired, scope)
    same_budget_source = None
    if paired is None:
        # Without the shipped comparator the pair's own cold_start.json must at
        # least declare that every case matched on the five compatibility axes;
        # the absence of the comparator is stated in the value, never hidden.
        axes = ("raw_compatible_count", "genome_compatible_count",
                "path_compatible_count", "source_compatible_count",
                "status_compatible_count")
        counts = {axis: _integer(cold_document.get(axis)) for axis in axes}
        same_budget_source = {
            "source": "cold_start.json compatibility counts (no shipped "
                      "paired_efficiency_report.v1 was found)",
            "counts": counts,
            "cases": cold_cases,
        }
        for axis, count in counts.items():
            if count is None or cold_cases is None or count != cold_cases:
                reasons.append(f"the pair's own cold_start.json reports "
                               f"{axis}={count!r} for {cold_cases!r} case(s), so "
                               "the arms are not shown to share the same input, "
                               "genome, path, source and status")
    else:
        validity = paired.get("comparison_validity") if isinstance(
            paired.get("comparison_validity"), Mapping) else {}
        same_budget_source = {"source": paired_record["path"],
                              "comparable": validity.get("comparable"),
                              "status": validity.get("status")}
        if validity.get("comparable") is not True:
            reasons.append("the shipped comparator does not declare the pair "
                           f"comparable (status={validity.get('status')!r}, "
                           f"failed={validity.get('failed_prerequisites')!r}, "
                           f"unverified={validity.get('unverified_prerequisites')!r})")
    value = {
        "continuous": {"run_dir": continuous["run_dir"],
                       "elapsed_seconds": continuous_seconds,
                       "effective_search_seconds": continuous_effective,
                       "cases": continuous_cases,
                       "mean_effective_seconds_per_case":
                           (continuous_effective / continuous_cases
                            if continuous_effective is not None and continuous_cases
                            else None)},
        "cold_start": {"run_dir": cold["run_dir"],
                       "wall_clock_seconds": cold_wall,
                       "cases": cold_cases,
                       "verified_cases": verified,
                       "init_seconds_total": init_total,
                       "total_seconds_total": total_total,
                       "mean_init_seconds_per_case":
                           (init_total / cold_cases
                            if init_total is not None and cold_cases else None),
                       "comparison_scope": scope},
        "speedup": speedup,
        "case_identity_matched": matched,
        "chain_per_second_equivalence": equivalence,
        "cold_start_document": cold["cold_artifact"],
        "same_budget_source": same_budget_source,
        "paired_report": _paired_validity(paired),
    }
    if not isinstance(scope, str):
        reasons.append("the pair states no comparison_scope, so the equivalence "
                       "boundary is not declared")
    evidence = [_evidence(ctx.artifact(ARTIFACT_REPORT)),
                _evidence(paired_record),
                {"key": ARTIFACT_COLD_START, "path": cold["cold_artifact"],
                 "resolved": cold["cold_artifact"], "available": True,
                 "sha256": (_sha256_file(Path(cold["cold_artifact"]))
                            if cold["cold_artifact"] else None)},
                _evidence(ctx.artifact(ARTIFACT_RECEIPTS))]
    return _item(ITEM_PAIRED_BUDGET, measured=True, met=(not reasons), value=value,
                 evidence=evidence,
                 reason=("; ".join(reasons) if reasons else None))


def _paired_validity(paired: Mapping | None) -> dict | None:
    """The shipped comparator's own same-budget verdict, or ``None``."""
    if not isinstance(paired, Mapping):
        return None
    validity = paired.get("comparison_validity")
    validity = validity if isinstance(validity, Mapping) else {}
    prerequisites = [entry for entry in (validity.get("prerequisites") or [])
                     if isinstance(entry, Mapping)]
    return {
        "schema_version": paired.get("schema_version"),
        "comparable": validity.get("comparable"),
        "status": validity.get("status"),
        "failed_prerequisites": list(validity.get("failed_prerequisites") or []),
        "unverified_prerequisites": list(
            validity.get("unverified_prerequisites") or []),
        "prerequisites": [{"name": entry.get("name"),
                           "satisfied": entry.get("satisfied")}
                          for entry in prerequisites],
        "comparison_scope": paired.get("comparison_scope"),
    }


def _chain_equivalence(ctx: _Context, cold: Mapping, paired: Mapping | None,
                       scope: object) -> dict:
    """Whether chain/s equivalence is measurable, with the exact statement.

    Preference order: the shipped ``paired_efficiency_report.v1`` comparator
    (which computes both arms' certified chain rates itself), then a
    ``first_step_acceptance_report.v1`` on either arm.
    """
    if isinstance(paired, Mapping):
        groups = paired.get("groups") if isinstance(paired.get("groups"), Mapping) else {}
        continuous = groups.get("continuous") if isinstance(
            groups.get("continuous"), Mapping) else {}
        cold_group = groups.get("cold") if isinstance(
            groups.get("cold"), Mapping) else {}
        continuous_rate = _finite(continuous.get("certified_chains_per_second"))
        cold_rate = _finite(cold_group.get("certified_chains_per_second"))
        ratio = paired.get("paired") if isinstance(paired.get("paired"), Mapping) else {}
        ratio_row = ratio.get("certified_chains_per_second_ratio_cold_over_continuous")
        ratio_reason = ratio_row.get("reason") if isinstance(ratio_row, Mapping) else None
        cold_reason = cold_group.get("certified_chains_per_second_reason")
        measurable = continuous_rate is not None and cold_rate is not None
        return {
            "measured_from": "paired_efficiency_report.v1",
            "measurable": measurable,
            "continuous_certified_chains": continuous.get("certified_chains"),
            "continuous_certified_chains_per_second": continuous_rate,
            "cold_start_certified_chains": cold_group.get("certified_chains"),
            "cold_start_certified_chains_per_second": cold_rate,
            "ratio_cold_over_continuous":
                (ratio_row.get("value") if isinstance(ratio_row, Mapping) else None),
            "reason": None if measurable else (
                "chain/s equivalence is not measurable from this pair: "
                + (str(cold_reason) if isinstance(cold_reason, str)
                   else "the cold-start arm carries no certified chain rate")
                + (f" [{ratio_reason}]" if isinstance(ratio_reason, str) else "")
                + (f"; the pair's own comparison_scope is {scope!r}"
                   if isinstance(scope, str) else "")),
        }
    continuous_chain = _chain_evidence(ctx, ctx.run_dir)
    cold_chain = _chain_evidence(ctx, Path(cold["run_dir"]))
    measurable = continuous_chain is not None and cold_chain is not None
    return {
        "measured_from": "first_step_acceptance_report.v1",
        "measurable": measurable,
        "continuous_certified_chains": continuous_chain,
        "cold_start_certified_chains": cold_chain,
        "reason": None if measurable else (
            "chain/s equivalence is not measurable from this pair: "
            "neither arm carries a first_step_acceptance_report.v1 with a "
            "certified chain count"
            + (f", and the pair's own comparison_scope is {scope!r}"
               if isinstance(scope, str) else "")),
    }


def _chain_evidence(ctx: _Context, run_dir: Path) -> dict | None:
    """The certified-chain tuple of one arm, or ``None`` when it has none."""
    record = _resolve_artifact(ARTIFACT_FIRST_STEP_ACCEPTANCE, run_dir=run_dir,
                               explicit=None, compare_run=None)
    if not record["available"]:
        return None
    document = _load_json(Path(record["resolved"]))
    if not isinstance(document, Mapping):
        return None
    chains = document.get("certified_chains")
    if not isinstance(chains, Mapping) or _integer(chains.get("total")) is None:
        return None
    return {"artifact": record["path"], "total": chains.get("total"),
            "per_second": _finite(document.get("certified_chains_per_second")),
            "effective_search_seconds":
                _finite(document.get("effective_search_seconds"))}


# ------------------------------------------------------------- the per-run API


def p5_acceptance_report(run_dir, *, role: str = "supporting",
                         compare_run=None, artifacts: Mapping | None = None,
                         expected_findings: Sequence[str] = (),
                         invoke_assertion_classes: bool = False,
                         scratch_dir=None) -> dict:
    """Judge one declared run against the six P5 critical items."""
    declaration = _declarations([{
        "role": role, "run_dir": (os.fspath(run_dir) if isinstance(
            run_dir, os.PathLike) else run_dir),
        "compare_run": (os.fspath(compare_run) if isinstance(
            compare_run, os.PathLike) else compare_run),
        "artifacts": dict(artifacts or {})}])[0]
    context = _Context(
        declaration,
        invoke_assertion_classes=invoke_assertion_classes,
        scratch_dir=(None if scratch_dir is None else Path(scratch_dir)))
    findings = [value for value in expected_findings if isinstance(value, str)]
    items = [
        _judge_assertion_classes(context),
        _judge_controlled_fault(context),
        _judge_normal_control(context, findings),
        _judge_complete_prefix(context),
        _judge_long_search(context, findings),
        _judge_paired_budget(context, findings),
    ]
    critical = [row for row in items if row["critical"]]
    unmet = [row["key"] for row in critical
             if not (row["measured"] is True and row["met"] is True)]
    role_required = ROLE_REQUIREMENTS[role]
    missing = sorted(key for key in role_required
                     if not context.artifact(key)["available"])
    role_evidence = {
        "role": role,
        "run_dir": declaration["run_dir"],
        "required_artifacts": sorted(role_required),
        "missing": missing,
        "matched": not missing,
        "reason": None if not missing else
        (f"the declared role {role!r} needs {missing}, which this run does not "
         "carry; the run is reported, not skipped, and its items are judged on "
         "the artifacts it really has"),
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "role": role,
        "run_dir": declaration["run_dir"],
        "compare_run": declaration["compare_run"],
        "run_identity": {
            "run_id": _field(context.document(ARTIFACT_IDENTITY) or {},
                             "identity.run_config.run_id"),
            "envelope_sha256": (_field(context.document(ARTIFACT_IDENTITY) or {},
                                       "sha256")),
            "report_identity_sha256": (_field(
                context.document(ARTIFACT_REPORT) or {},
                "online_run_identity_sha256")),
        },
        "role_evidence": role_evidence,
        "items": items,
        "critical_items": list(CRITICAL_ITEMS),
        "critical_total": len(critical),
        "critical_met": len(critical) - len(unmet),
        "critical_unmet": unmet,
        "exit_code": EXIT_READY if not unmet else EXIT_NOT_READY,
        "exit_code_semantics": (
            "0 = this run alone measured and met every P5 critical item; "
            "2 = at least one critical item is unmeasured or unmet by this run; "
            "the suite unions runs, so a per-run 2 is not a stage failure"),
        "resolved_artifacts": {
            key: {"path": record["path"], "available": record["available"],
                  "sha256": record["sha256"]}
            for key, record in sorted(context.records.items())
            if "@" not in key},
        "resolution_notes": sorted(set(context.notes)),
        "limits": [
            "a role is a declaration, not a measurement: the suite reports a "
            "role/artifact mismatch but cannot prove what a run was for",
            "an item counts as met only when measured and met are both true; an "
            "unmeasured item is null plus a reason, never a fabricated 0",
        ],
    }
    return report


# ----------------------------------------------------------------- the union


def _union_reason(key: str, rows: list[dict]) -> str | None:
    met_rows = [row for row in rows if row["measured"] and row["met"]]
    if met_rows:
        return None
    measured_rows = [row for row in rows if row["measured"]]
    if measured_rows:
        return measured_rows[0]["reason"] or (
            f"{key} is measured but not met by any declared run")
    return rows[0]["reason"] if rows else f"no declared run could measure {key}"


def _aggregate_item(key: str, reports: Sequence[Mapping], *,
                    fleet_findings: Sequence[str]) -> dict:
    rows = []
    for report in reports:
        for item in report["items"]:
            if item["key"] == key:
                rows.append({"role": report["role"], "run_dir": report["run_dir"],
                             "item": item})
    rows.sort(key=lambda row: (row["role"], row["run_dir"]))
    proofs = [row for row in rows
              if row["item"]["measured"] and row["item"]["met"]]
    measured = [row for row in rows if row["item"]["measured"]]
    not_met = [row for row in measured if not row["item"]["met"]]
    unmeasured = [row for row in rows if not row["item"]["measured"]]
    proving_runs = sorted({row["role"] for row in proofs})
    evidence: list = []
    seen: set[str] = set()
    for row in (proofs or measured or rows):
        for entry in row["item"]["evidence"]:
            marker = f"{entry.get('key')}|{entry.get('path')}"
            if marker in seen or entry.get("path") is None:
                continue
            seen.add(marker)
            evidence.append(entry)
    truncated = len(evidence) > MAX_UNION_EVIDENCE
    evidence = evidence[:MAX_UNION_EVIDENCE]
    if key == ITEM_NORMAL_CONTROL:
        # The union statement is cross-run: a clean control run only means
        # something once some declared run proves the injected finding it must
        # not carry.
        if not fleet_findings:
            return {"key": key, "critical": True,
                    "criterion": ITEM_CRITERIA[key], "measured": False,
                    "met": None, "value": {
                        "antecedent_findings": [],
                        "controls_checked": sorted({row["role"] for row in
                                                    measured}),
                        "clean_controls": proving_runs,
                    },
                    "evidence": evidence, "proving_runs": [],
                    "measured_by": sorted({row["role"] for row in measured}),
                    "not_met_by": sorted({row["role"] for row in not_met}),
                    "unmeasured_by": sorted({row["role"] for row in unmeasured}),
                    "evidence_truncated": False,
                    "reason": ("no declared run proves an injected finding, so "
                               "'the control run has no such finding' has no "
                               "antecedent to test; the control signature itself "
                               f"was measured by {sorted({row['role'] for row in measured})}")}
        # A run whose own control item is not met carries a finding or a
        # non-clean status; a clean control is exactly a run that proved the
        # item, and the per-run judge already refused every antecedent finding
        # for those runs.
        dirty = [(row["role"], sorted(
            set((row["item"]["value"] or {}).get("violations") or [])
            & set(fleet_findings)))
            for row in not_met
            if set((row["item"]["value"] or {}).get("violations") or [])
            & set(fleet_findings)]
        clean = [row for row in proofs]
        met = bool(clean)
        value = {"antecedent_findings": sorted(set(fleet_findings)),
                 "controls_checked": sorted({row["role"] for row in measured}),
                 "clean_controls": proving_runs,
                 "controls_carrying_a_finding": [f"{role}: {present}"
                                                 for role, present in dirty]}
        if not met and not dirty and not clean:
            return {"key": key, "critical": True,
                    "criterion": ITEM_CRITERIA[key], "measured": True,
                    "met": False, "value": value, "evidence": evidence,
                    "proving_runs": [],
                    "measured_by": sorted({row["role"] for row in measured}),
                    "not_met_by": sorted({row["role"] for row in not_met}),
                    "unmeasured_by": sorted({row["role"] for row in unmeasured}),
                    "evidence_truncated": truncated,
                    "reason": ("every declared run that carries the control "
                               "signature carries a finding or a non-clean "
                               "status, so no clean control exists")}
        return {"key": key, "critical": True, "criterion": ITEM_CRITERIA[key],
                "measured": True, "met": met, "value": value,
                "evidence": evidence, "proving_runs": proving_runs,
                "measured_by": sorted({row["role"] for row in measured}),
                "not_met_by": sorted({row["role"] for row in not_met}),
                "unmeasured_by": sorted({row["role"] for row in unmeasured}),
                "evidence_truncated": truncated,
                "reason": None if met else
                ("the control run carries the injected finding(s): "
                 + "; ".join(f"{role}: {present}" for role, present in dirty)
                 if dirty else _union_reason(key, [row["item"] for row in rows]))}
    met = bool(proofs)
    return {"key": key, "critical": True, "criterion": ITEM_CRITERIA[key],
            "measured": bool(measured), "met": (True if met else
                                                (False if measured else None)),
            "value": (proofs[0]["item"]["value"] if proofs else
                      (measured[0]["item"]["value"] if measured else None)),
            "evidence": evidence, "proving_runs": proving_runs,
            "measured_by": sorted({row["role"] for row in measured}),
            "not_met_by": sorted({row["role"] for row in not_met}),
            "unmeasured_by": sorted({row["role"] for row in unmeasured}),
            "evidence_truncated": truncated,
            "reason": (None if met else
                       _union_reason(key, [row["item"] for row in rows]))}


def p5_acceptance_suite(runs: Sequence, *,
                        invoke_assertion_classes: bool = False,
                        scratch_dir=None) -> dict:
    """Union the per-run verdicts; exit 0 only when every critical item is met."""
    declarations = _declarations(runs)
    context_kwargs = {"invoke_assertion_classes": invoke_assertion_classes,
                      "scratch_dir": scratch_dir}
    first_pass = [p5_acceptance_report(
        declaration["run_dir"], role=declaration["role"],
        compare_run=declaration["compare_run"],
        artifacts=declaration["artifacts"], **context_kwargs)
        for declaration in declarations]
    fleet_findings: set[str] = set()
    for report in first_pass:
        for item in report["items"]:
            if item["key"] != ITEM_CONTROLLED_FAULT or not item["measured"]:
                continue
            value = item["value"] or {}
            detected = value.get("detected_by")
            if isinstance(detected, list):
                fleet_findings.update(
                    value for value in detected if isinstance(value, str))
    reports = [p5_acceptance_report(
        declaration["run_dir"], role=declaration["role"],
        compare_run=declaration["compare_run"],
        artifacts=declaration["artifacts"],
        expected_findings=sorted(fleet_findings), **context_kwargs)
        for declaration in declarations]
    items = [_aggregate_item(key, reports, fleet_findings=sorted(fleet_findings))
             for key in CRITICAL_ITEMS]
    critical = [item for item in items if item["critical"]]
    unmet = [item["key"] for item in critical
             if not (item["measured"] is True and item["met"] is True)]
    boundaries: list[str] = []
    proving_roles = {role for item in items for role in item["proving_runs"]}
    for declaration in sorted(declarations, key=lambda row: row["role"]):
        role = declaration["role"]
        if role in proving_roles:
            continue
        boundaries.append(
            f"the declared {role} run {declaration['run_dir']} proves no P5 "
            "critical item; it is reported in runs/role_evidence with its exact "
            "reason and is not silently dropped")
    roles = {declaration["role"] for declaration in declarations}
    long_item = next(item for item in items if item["key"] == ITEM_LONG_SEARCH)
    if "heterogeneous_uart" in roles and \
            "heterogeneous_uart" not in long_item["proving_runs"]:
        boundaries.append(
            "the declared heterogeneous_uart run proves no >=600 effective-second "
            "chain run, so P5's sub-claim about a second, different-protocol real "
            "peripheral is not covered by a long session in this union; the "
            "ten-minute item is proven by "
            + (", ".join(long_item["proving_runs"]) or "no run"))
    assertion_item = next(item for item in items
                          if item["key"] == ITEM_ASSERTION_CLASSES)
    if assertion_item["unmeasured_by"]:
        boundaries.append(
            "no p5_assertion_classes.v1 report exists for "
            + ", ".join(assertion_item["unmeasured_by"]) +
            "; the shipped read-only CLI "
            "scripts/report_p5_assertion_classes.py can produce one per run "
            "(--invoke-assertion-classes), which rescans that run's saved trace")
    boundaries.append(
        "the union proves each critical item has at least one run that measured "
        "and met it; it does not prove one single run satisfies the whole P5 "
        "checklist")
    boundaries.append(
        "every finding in the controlled-fault item is an injected calibration, "
        "not a natural RTL defect")
    gate = {
        "exit_code": EXIT_READY if not unmet else EXIT_NOT_READY,
        "ready": not unmet,
        "critical_total": len(critical),
        "critical_met": len(critical) - len(unmet),
        "critical_unmet": unmet,
        "no_proving_run": unmet,
    }
    document = {
        "schema_version": SUITE_SCHEMA_VERSION,
        "declarations": [
            {"role": declaration["role"], "run_dir": declaration["run_dir"],
             "compare_run": declaration["compare_run"],
             "artifacts": dict(declaration["artifacts"])}
            for declaration in declarations],
        "runs": reports,
        "role_evidence": [report["role_evidence"] for report in reports],
        "items": items,
        "critical_items": list(CRITICAL_ITEMS),
        "critical_total": len(critical),
        "critical_met": len(critical) - len(unmet),
        "critical_unmet": unmet,
        "no_proving_run": unmet,
        "gate": gate,
        "exit_code": gate["exit_code"],
        "exit_code_semantics": (
            "0 = every P5 critical item has at least one declared run that "
            "measured and met it; 2 = a critical item has no proving run (or is "
            "measured without being met); 1 = the command could not run at all "
            "(bad declaration, missing directory, unwritable output)"),
        "antecedent_findings": sorted(fleet_findings),
        "boundaries": boundaries,
        "limits": [
            "the suite reads saved artifacts only: it never renders a harness, "
            "never starts an RTL process and never writes inside a saved run",
            "an item is a union statement about evidence, not a claim about the "
            "DUT beyond what each cited artifact measured",
            "a per-run exit_code of 2 means that run alone is not a full P5 "
            "pass; it does not invalidate the union",
        ],
        "engine": {
            "p5_acceptance": _module_identity("myfuzz.scenario.p5_acceptance"),
            "assertion_classes": _module_identity(
                "myfuzz.scenario.assertion_classes"),
            "suite": _module_identity(__name__),
        },
    }
    return document


def item_document(report: Mapping, key: str) -> Mapping | None:
    """One item row of a report or suite document, or ``None``."""
    for item in report.get("items") or []:
        if isinstance(item, Mapping) and item.get("key") == key:
            return item
    return None


def _cell(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(suite: Mapping) -> str:
    """The union as a small evidence table (deterministic, ASCII)."""
    lines = [
        f"# {suite.get('schema_version')}",
        "",
        f"exit_code: {suite.get('exit_code')} "
        f"(critical {suite.get('critical_met')}/{suite.get('critical_total')})",
        "",
        "| item | measured | met | proving runs | reason |",
        "|---|---|---|---|---|",
    ]
    for item in suite.get("items") or []:
        lines.append(
            f"| {_cell(item.get('key'))} | {_cell(item.get('measured'))} | "
            f"{_cell(item.get('met'))} | "
            f"{_cell(', '.join(item.get('proving_runs') or []) or None)} | "
            f"{_cell(item.get('reason'))} |")
    lines.extend(["", "## declared runs", "",
                  "| role | run_dir | role matched | missing artifacts | "
                  "critical met | exit_code |",
                  "|---|---|---|---|---|---|"])
    run_rows = sorted(suite.get("runs") or [],
                      key=lambda row: (str(row.get("role")),
                                       str(row.get("run_dir"))))
    for report in run_rows:
        role_evidence = report.get("role_evidence") or {}
        lines.append(
            f"| {_cell(report.get('role'))} | {_cell(report.get('run_dir'))} | "
            f"{_cell(role_evidence.get('matched'))} | "
            f"{_cell(', '.join(role_evidence.get('missing') or []) or None)} | "
            f"{_cell(report.get('critical_met'))}/"
            f"{_cell(report.get('critical_total'))} | "
            f"{_cell(report.get('exit_code'))} |")
    if suite.get("boundaries"):
        lines.extend(["", "## boundaries", ""])
        lines.extend(f"* {entry}" for entry in suite["boundaries"])
    return "\n".join(lines) + "\n"
