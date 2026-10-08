#!/usr/bin/env python3
"""Read-only P4 slot immutability sweep over a declared list of saved runs.

Requirement under test: "真实 Store/取指后的程序字节不能被后例变异" -- a program
byte that a real Store or instruction fetch already determined must not be given
or read back a different value by a later case.

This script does not implement a checker of its own.  It runs the **shipped**
per-run verdict of ``myfuzz.scenario.slot_immutability`` over every declared run
directory and aggregates it into one versioned document
(``p4_slot_immutability_sweep.v1``).  Nothing is compiled, rendered or started:
no Verilator, no RTL elaboration, no fuzz job, and no write inside any run
directory.  Traces are read with the shipped readers only.

Per-run verdicts and how they are obtained
------------------------------------------
``shipped_cli_path``
    The run has ``online_events.jsonl``, so the shipped CLI's own path
    (``report_for_run``, the function ``main()`` calls) produces the verdict.
    Recorded as ``verdict_reader == "shipped_cli_path"``.
``shipped_stream_path``
    The run has no ``online_events.jsonl`` but does declare a streamable
    artifact (``online_final_trace.json`` / ``online_final_trace.meta.json`` +
    ``online_events.jsonl`` / ``online_events.zlib``).  The shipped bounded
    reader ``acceptance_metrics.TraceEventStream`` streams the declared events
    and the shipped ``slot_immutability.analyze_events`` judges them with the
    run's declared reservation (``program_range_from_run``).  The document
    labels this reader explicitly and still records that the *default* shipped
    CLI invocation cannot read such a run (it exits 3, argument error).
``unavailable``
    Neither path produced a verdict (missing directory, missing decoder
    manifest, missing trace artifact, malformed trace, ...).  The run is
    reported with the exact reasons, ``null`` slot counts and a non-zero sweep
    exit.  It is never reported as ``immutable`` and never as ``0 slots``.

Fail-closed rules
-----------------
* a verdict is only ever copied from a shipped report object; the sweep never
  fabricates one;
* the stream reader is used only when ``online_events.jsonl`` is **absent**.
  A present-but-unreadable JSONL fails closed as ``unavailable`` -- it is never
  silently replaced by another artifact;
* any exception while judging a run is caught and becomes ``unavailable`` with
  the exception type and message, never a pass;
* exit codes keep the shipped semantics (0 immutable / 1 violated /
  2 insufficient_evidence / 3 argument error) and add ``unavailable`` at 2, so
  "no verdict" can never read as a pass.

Determinism
-----------
The document carries no clock, no host name, no absolute path that was not
declared, and no iteration over unordered containers without ``sort_keys``:
the same declared runs over the same frozen artifacts produce byte-identical
JSON.

Example:
    PYTHONPATH=src python3 scripts/report_p4_slot_immutability_sweep.py \
        runs/current-dataflow-p4-path-switch-off-20261007-online \
        runs/current-dataflow-p4-path-switch-on-20261007-online \
        --json-out docs/reports/current-dataflow-p4-slot-immutability-sweep-20261008/p4_slot_immutability_sweep.v1.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from myfuzz.scenario.acceptance_metrics import TraceEventStream, TraceUnavailable
from myfuzz.scenario.slot_immutability import (
    ARGUMENT_ERROR_EXIT_CODE, EVENTS_FILE_NAME, EXIT_CODES, RUN_CONCLUSIONS,
    SLOT_IMMUTABILITY_SCHEMA_VERSION, SlotImmutabilityError, analyze_events,
    program_range_from_run, report_for_run)


SWEEP_SCHEMA_VERSION = "p4_slot_immutability_sweep.v1"
SHIPPED_GATE_SCHEMA_VERSION = SLOT_IMMUTABILITY_SCHEMA_VERSION
REQUIREMENT = "真实 Store/取指后的程序字节不能被后例变异"
UNAVAILABLE = "unavailable"
#: Verdicts of one run: the shipped three plus the sweep's "no verdict".
RUN_VERDICTS = (*RUN_CONCLUSIONS, UNAVAILABLE)
#: Sweep exit codes: the shipped 0/1/2 semantics, with an unavailable run landing
#: on 2 ("not immutable and not violated") so it can never read as a pass.
SWEEP_EXIT_CODES = {**EXIT_CODES, UNAVAILABLE: EXIT_CODES["insufficient_evidence"]}
READER_CLI_PATH = "shipped_cli_path"
READER_STREAM_PATH = "shipped_stream_path"
SESSION_MANIFEST_FILE_NAME = "online_session_manifest.json"
RUN_IDENTITY_FILE_NAME = "online_run_identity.json"
_HASH_CHUNK_BYTES = 1 << 20
NULL_COUNTS_REASON = (
    "this run produced no shipped verdict, so it has no slot counts: an "
    "unavailable run is never reported as immutable and never as 0 slots")

LIMITS = (
    "只读已保存运行目录：不编译、不渲染、不启动 RTL/Verilator，也不运行任何 fuzz 作业"
    "（proof_scope.rtl_executed_by_checker=false）。",
    "结论只覆盖每个被判定运行的这一份 trace 的 slot 全集，即声明程序区内至少被一个事件"
    "物化或读取过的字节；未被任何事件触及的声明字节只报计数"
    "（unobserved_program_bytes），不报通过。",
    "unavailable 的运行没有判定：slot 计数为 null，绝不计入 immutable、绝不当 0；只要声明"
    "清单里有任何 unavailable，sweep 结论就不可能是 immutable。",
    "本 sweep 不证明声明清单之外的运行，不证明其它 trace 格式，也不证明声明程序区之外的"
    "字节；更不声称 RTL 层面保证 slot 不可变性。",
    "jsonl.v1 运行走 shipped CLI 路径（report_for_run），该路径按 shipped 门自己的界不校验"
    "online_final_trace.meta.json 的 semantic_sha256；本文件另外记录 trace 与 decoder/session"
    " manifest 的 sha256 作为身份证据。",
    "monolithic json.v1 运行走 shipped 流式读取器（TraceEventStream，校验声明事件数）加"
    "shipped 判定函数（analyze_events），并在每例中显式记录 shipped CLI 默认调用读不到该运行"
    "（退出码 3）——该结论不是 CLI 默认路径的结论。",
    "本 sweep 只对调用者声明的目录清单负责：清单内缺失的目录只报 unavailable，不做任何"
    "推断或替代路径搜索。",
    "判定前后各 stream 一次同一 trace（第二遍为常量内存）：声明的 event_count 与声明的"
    "canonical semantic_sha256 与 shipped 读取器的复算不一致时，该例结论被拒绝为 unavailable"
    "（记录 trace_integrity 拒绝原因），不会写成 immutable；若 trace 本身不声明摘要，则记录"
    "为缺失（null），这只是证据强度更弱，不等于失败。",
)


# ---------------------------------------------------------------------------
# read-only artifact identity
# ---------------------------------------------------------------------------

def sha256_file(path: str | Path, *, chunk_bytes: int = _HASH_CHUNK_BYTES) -> str:
    """Stream one file through sha256; never holds it in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def artifact_identity(path: str | Path) -> dict:
    """Size and sha256 of one declared artifact, read-only and tolerant."""
    path = Path(path)
    if not path.is_file():
        return {"path": str(path), "present": False, "bytes": None,
                "sha256": None, "unreadable": None}
    size = path.stat().st_size
    try:
        digest = sha256_file(path)
    except OSError as error:
        return {"path": str(path), "present": True, "bytes": size,
                "sha256": None, "unreadable": f"{type(error).__name__}: {error}"}
    return {"path": str(path), "present": True, "bytes": size, "sha256": digest,
            "unreadable": None}


def run_identity(directory: Path) -> dict:
    """The declared identity evidence of one run directory (no verdict)."""
    return {
        "decoder_manifest": artifact_identity(directory / "decoder_manifest.json"),
        "session_manifest": artifact_identity(
            directory / SESSION_MANIFEST_FILE_NAME),
        "run_identity": artifact_identity(
            directory / RUN_IDENTITY_FILE_NAME),
    }


def trace_identity(directory: Path) -> dict:
    """The trace artifact this run declares, discovered with a shipped reader."""
    descriptor: Mapping | None
    stream_reason: str | None = None
    try:
        descriptor = TraceEventStream(directory).descriptor
    except (TraceUnavailable, ValueError, OSError) as error:
        descriptor = None
        stream_reason = f"{type(error).__name__}: {error}"
    if descriptor is not None:
        identity = artifact_identity(descriptor["path"])
        identity.update({
            "format": descriptor.get("format"),
            "events_file": descriptor.get("events_file"),
            "declared_event_count": descriptor.get("declared_event_count"),
            "declared_status": descriptor.get("declared_status"),
            "discovered_by": "myfuzz.scenario.acceptance_metrics.TraceEventStream",
            "stream_reader_declares_no_artifact": None,
        })
        return identity
    jsonl = directory / EVENTS_FILE_NAME
    identity = artifact_identity(jsonl)
    identity.update({
        "format": ("jsonl.v1" if identity["present"] else None),
        "events_file": (EVENTS_FILE_NAME if identity["present"] else None),
        "declared_event_count": None,
        "declared_status": None,
        "discovered_by": (
            "myfuzz.scenario.slot_immutability.EVENTS_FILE_NAME (fallback: the "
            "shipped stream reader declares no streamable artifact here)"),
        "stream_reader_declares_no_artifact": stream_reason,
    })
    return identity


# ---------------------------------------------------------------------------
# per-run verdicts
# ---------------------------------------------------------------------------

def _base_row(index: int, declared: str) -> dict:
    directory = Path(declared)
    present = directory.is_dir()
    identity = run_identity(directory)
    identity["trace"] = (trace_identity(directory) if present else {
        "path": str(directory / EVENTS_FILE_NAME), "present": False,
        "bytes": None, "sha256": None, "unreadable": None, "format": None,
        "events_file": None, "declared_event_count": None,
        "declared_status": None,
        "discovered_by": "declared directory does not exist",
        "stream_reader_declares_no_artifact": "declared directory does not exist"})
    return {
        "declared_index": index,
        "run_directory": declared,
        "declared_directory_exists": present,
        "verdict": None,
        "verdict_reader": None,
        "run_conclusion": None,
        "slot_count": None,
        "immutable": None,
        "violated": None,
        "insufficient_evidence": None,
        "conflicts_by_kind": None,
        "insufficient_by_reason": None,
        "materializations_by_kind": None,
        "reads_by_kind": None,
        "read_evidence_event_count": None,
        "malformed_event_ids": None,
        "reassertion_count": None,
        "unobserved_program_bytes": None,
        "event_count": None,
        "program_range": None,
        "proof_scope": None,
        "gate_line": None,
        "violated_slots": [],
        "insufficient_slots": [],
        "identity": identity,
        "shipped_cli_path": {"attempted": False, "verdict": None, "reason": None},
        "shipped_stream_path": {"attempted": False, "verdict": None,
                                "reason": None, "blocking_reasons": []},
        "trace_integrity": None,
        "unavailable_reasons": [],
        "null_counts_reason": None,
        "exit_code": {"shipped_gate_conclusion": None,
                      "shipped_cli_default_invocation": None,
                      "sweep_per_run": None},
    }


def _violated_slot_document(slot) -> dict:
    return {"memory_id": slot.memory_id, "address": slot.address,
            "region_id": slot.region_id,
            "conflict_kind": slot.conflict_kind,
            "conflicting_event_id": slot.conflict_event_id,
            "materialized_value": slot.value,
            "conflicting_value": slot.conflict_value,
            "first_materialization_event_id": slot.first_event_id,
            "first_materialization_kind": slot.first_kind,
            "first_materialization_case_id": slot.first_case_id,
            "first_materialization_generation": slot.first_generation}


def _insufficient_slot_document(slot) -> dict:
    return {"memory_id": slot.memory_id, "address": slot.address,
            "region_id": slot.region_id, "reason": slot.reason,
            "early_read_event_id": slot.early_read_event_id,
            "first_materialization_event_id": slot.first_event_id,
            "read_event_ids": list(slot.read_event_ids)}


def _judged_row(row: dict, report, *, reader: str,
                shipped_cli_default_invocation: int,
                trace_integrity: Mapping | None = None) -> dict:
    """Attach one shipped ``SlotImmutabilityReport`` verdict to a run row."""
    summary = report.summary()
    conclusion = report.run_conclusion
    row.update({
        "trace_integrity": (dict(trace_integrity)
                            if trace_integrity is not None else None),
        "verdict": conclusion,
        "verdict_reader": reader,
        "run_conclusion": conclusion,
        "slot_count": summary["slot_count"],
        "immutable": summary["immutable"],
        "violated": summary["violated"],
        "insufficient_evidence": summary["insufficient_evidence"],
        "conflicts_by_kind": summary["conflicts_by_kind"],
        "insufficient_by_reason": summary["insufficient_by_reason"],
        "materializations_by_kind": summary["materializations_by_kind"],
        "reads_by_kind": summary["reads_by_kind"],
        "read_evidence_event_count": summary["read_evidence_event_count"],
        "malformed_event_ids": summary["malformed_event_ids"],
        "reassertion_count": summary["reassertion_count"],
        "unobserved_program_bytes": report.unobserved_program_bytes,
        "event_count": report.event_count,
        "program_range": {"start": report.program_range[0],
                          "end": report.program_range[1],
                          "source": report.range_source},
        "proof_scope": report.document(include_slots=False)["proof_scope"],
        "gate_line": report.gate_line(),
        "violated_slots": [_violated_slot_document(slot)
                           for slot in report.slots
                           if slot.verdict == "violated"],
        "insufficient_slots": [_insufficient_slot_document(slot)
                               for slot in report.slots
                               if slot.verdict == "insufficient_evidence"],
        "unavailable_reasons": [],
        "null_counts_reason": None,
        "exit_code": {
            "shipped_gate_conclusion": EXIT_CODES[conclusion],
            "shipped_cli_default_invocation": shipped_cli_default_invocation,
            "sweep_per_run": SWEEP_EXIT_CODES[conclusion]},
    })
    return row


def _unavailable_row(row: dict, reasons: Sequence[Mapping],
                     trace_integrity: Mapping | None = None) -> dict:
    """Fail closed: no verdict, no counts, an explicit reason per path."""
    row.update({
        "trace_integrity": (dict(trace_integrity)
                            if trace_integrity is not None
                            else row.get("trace_integrity")),
        "verdict": UNAVAILABLE,
        "verdict_reader": None,
        "run_conclusion": None,
        "slot_count": None,
        "immutable": None,
        "violated": None,
        "insufficient_evidence": None,
        "conflicts_by_kind": None,
        "insufficient_by_reason": None,
        "materializations_by_kind": None,
        "reads_by_kind": None,
        "read_evidence_event_count": None,
        "malformed_event_ids": None,
        "reassertion_count": None,
        "unobserved_program_bytes": None,
        "event_count": None,
        "program_range": None,
        "proof_scope": None,
        "gate_line": None,
        "violated_slots": [],
        "insufficient_slots": [],
        "unavailable_reasons": [dict(reason) for reason in reasons],
        "null_counts_reason": NULL_COUNTS_REASON,
        "exit_code": {
            "shipped_gate_conclusion": None,
            "shipped_cli_default_invocation": ARGUMENT_ERROR_EXIT_CODE,
            "sweep_per_run": SWEEP_EXIT_CODES[UNAVAILABLE]},
    })
    return row


def _failure_reason(stage: str, error: BaseException) -> dict:
    if isinstance(error, SlotImmutabilityError):
        text = str(error)
    elif isinstance(error, TraceUnavailable):
        text = str(error)
    else:
        text = f"{type(error).__name__}: {error}"
    return {"stage": stage, "reason": text}


def verify_trace_integrity(stream: TraceEventStream, *,
                           events_judged: int | None) -> dict:
    """Recompute the shipped canonical trace digest of an exhausted stream.

    The stream must already have been consumed.  ``semantic_sha256_verified``
    is the shipped reader's own comparison of the artifact's declared digest
    against the recomputed one; ``None`` means the artifact declares no digest,
    which is recorded but is not by itself a failure.
    """
    declared = stream.descriptor.get("declared_event_count")
    return {
        "status": "verified",
        "available": True,
        "format": stream.descriptor.get("format"),
        "events_file": stream.descriptor.get("events_file"),
        "events_streamed": stream.event_count,
        "events_judged": events_judged,
        "declared_event_count": declared,
        "event_count_matches_declared": (
            None if declared is None else stream.event_count == declared),
        "event_count_matches_judged": (
            None if events_judged is None else stream.event_count == events_judged),
        "declared_semantic_sha256": stream.declared_semantic_sha256(),
        "semantic_sha256_verified": stream.semantic_sha256_verified(),
        "reason": None,
    }


def unavailable_trace_integrity(reason: str, *,
                                status: str = "unavailable") -> dict:
    """No integrity metadata could be read at all; recorded, never assumed.

    ``status`` is ``"unavailable"`` when the shipped stream reader declares no
    artifact for this run (no digest metadata exists to check) and ``"failed"``
    when the artifact it does declare could not be streamed or verified -- the
    latter refuses the verdict.
    """
    return {"status": status, "available": False, "format": None,
            "events_file": None, "events_streamed": None, "events_judged": None,
            "declared_event_count": None,
            "event_count_matches_declared": None,
            "event_count_matches_judged": None,
            "declared_semantic_sha256": None,
            "semantic_sha256_verified": None, "reason": reason}


def trace_integrity_refusals(integrity: Mapping) -> list[str]:
    """Explicit mismatches that refuse a verdict; a missing metadata field is not one."""
    refusals = []
    if integrity.get("status") == "failed":
        refusals.append(
            f"trace_integrity_unreadable: the declared trace could not be "
            f"streamed or verified: {integrity.get('reason')}")
    if integrity.get("event_count_matches_declared") is False:
        refusals.append(
            f"declared_event_count_mismatch: the trace declares "
            f"{integrity['declared_event_count']} event(s) but "
            f"{integrity['events_streamed']} were streamed")
    if integrity.get("event_count_matches_judged") is False:
        refusals.append(
            f"judged_event_count_mismatch: the shipped verdict covers "
            f"{integrity['events_judged']} event(s) but "
            f"{integrity['events_streamed']} were streamed")
    if integrity.get("semantic_sha256_verified") is False:
        refusals.append(
            "semantic_sha256_mismatch: the trace declares "
            f"{integrity['declared_semantic_sha256']} but the shipped canonical "
            "digest of its events differs")
    return refusals


def stream_trace_for_integrity(directory: Path) -> dict:
    """One constant-memory streaming pass with the shipped reader, no analysis.

    A run whose shipped reader declares no streamable artifact (for example a
    bare ``online_events.jsonl`` with no metadata sidecar) is recorded as
    ``unavailable`` integrity metadata; an artifact that *is* declared but
    cannot be streamed or verified is recorded as ``failed`` and refuses the
    verdict.
    """
    try:
        stream = TraceEventStream(directory)
    except TraceUnavailable as error:
        return unavailable_trace_integrity(
            f"{type(error).__name__}: {error}", status="unavailable")
    except Exception as error:
        return unavailable_trace_integrity(_failure_reason(
            "trace_integrity", error)["reason"], status="failed")
    try:
        for _ in stream.events():
            pass
    except Exception as error:
        return unavailable_trace_integrity(_failure_reason(
            "trace_integrity", error)["reason"], status="failed")
    return verify_trace_integrity(stream, events_judged=None)


def evaluate_run(declared: str, *, index: int = 0,
                 stream_reader: bool = True) -> dict:
    """Run the shipped per-run verdict over one declared run, read-only."""
    row = _base_row(index, declared)
    directory = Path(declared)
    if not directory.is_dir():
        return _unavailable_row(row, [{
            "stage": "declaration",
            "reason": f"declared run directory does not exist: {declared}"}])

    # 1) The shipped CLI's own path: online_events.jsonl through report_for_run.
    try:
        report = report_for_run(directory)
    except Exception as error:  # fail closed on any failure of the shipped gate
        row["shipped_cli_path"] = {"attempted": True, "verdict": UNAVAILABLE,
                                   "reason": _failure_reason(
                                       READER_CLI_PATH, error)["reason"]}
        cli_error = error
    else:
        row["shipped_cli_path"] = {"attempted": True,
                                   "verdict": report.run_conclusion,
                                   "reason": None}
        row["shipped_stream_path"] = {"attempted": False, "verdict": None,
                                      "reason": None, "blocking_reasons": []}
        # The shipped CLI path does not itself compare the artifact's declared
        # digest, so the sweep streams the same trace once with the shipped
        # reader (constant memory): a declared count or digest that does not
        # hold refuses the verdict instead of being reported as immutable.
        integrity = stream_trace_for_integrity(directory)
        integrity["events_judged"] = report.event_count
        integrity["event_count_matches_judged"] = (
            None if integrity["events_streamed"] is None
            else integrity["events_streamed"] == report.event_count)
        refusals = trace_integrity_refusals(integrity)
        if refusals:
            row["shipped_cli_path"]["refused_by_trace_integrity"] = True
            return _unavailable_row(
                row, [{"stage": "trace_integrity", "reason": refusal}
                      for refusal in refusals], trace_integrity=integrity)
        return _judged_row(
            row, report, reader=READER_CLI_PATH,
            shipped_cli_default_invocation=EXIT_CODES[report.run_conclusion],
            trace_integrity=integrity)

    # 2) The shipped streaming reader, only when the JSONL artifact is absent:
    #    a present-but-broken JSONL must fail closed, never be re-read elsewhere.
    if not stream_reader:
        return _unavailable_row(row, [_failure_reason(READER_CLI_PATH, cli_error), {
            "stage": READER_STREAM_PATH,
            "reason": "stream reader disabled by --no-stream-reader"}])
    if (directory / EVENTS_FILE_NAME).is_file():
        return _unavailable_row(row, [_failure_reason(READER_CLI_PATH, cli_error), {
            "stage": READER_STREAM_PATH,
            "reason": (f"{EVENTS_FILE_NAME} exists, so the shipped CLI path is the "
                       "only judged path; a present trace is never replaced by "
                       "another artifact")}])

    row["shipped_stream_path"] = {"attempted": True, "verdict": None,
                                  "reason": None, "blocking_reasons": []}
    # Two independent declarations are needed before the shipped streaming
    # reader can judge: a streamable trace artifact and a declared program
    # reservation.  Report every missing one, not just the first.
    blocking: list[dict] = []
    stream = None
    program_range = None
    range_source = None
    try:
        stream = TraceEventStream(directory)
    except Exception as error:
        blocking.append({"stage": "trace_artifact",
                         "reason": _failure_reason("trace_artifact", error)["reason"]})
    try:
        program_range, range_source = program_range_from_run(directory)
    except Exception as error:
        blocking.append({"stage": "program_range",
                         "reason": _failure_reason("program_range", error)["reason"]})
    if blocking:
        row["shipped_stream_path"] = {
            "attempted": True, "verdict": UNAVAILABLE,
            "reason": "; ".join(item["reason"] for item in blocking),
            "blocking_reasons": blocking}
        return _unavailable_row(
            row,
            [_failure_reason(READER_CLI_PATH, cli_error),
             {"stage": READER_STREAM_PATH,
              "reason": row["shipped_stream_path"]["reason"]}])
    try:
        report = analyze_events(
            stream.events(), program_range=program_range,
            range_source=range_source, events_path=str(stream.path),
            run_directory=str(directory))
    except Exception as error:  # fail closed on any failure of the shipped reader
        row["shipped_stream_path"] = {"attempted": True, "verdict": UNAVAILABLE,
                                      "reason": _failure_reason(
                                          READER_STREAM_PATH, error)["reason"],
                                      "blocking_reasons": [
                                          _failure_reason(READER_STREAM_PATH,
                                                          error)]}
        return _unavailable_row(row, [_failure_reason(READER_CLI_PATH, cli_error),
                                      _failure_reason(READER_STREAM_PATH, error)])
    integrity = verify_trace_integrity(stream, events_judged=report.event_count)
    refusals = trace_integrity_refusals(integrity)
    row["shipped_stream_path"] = {"attempted": True,
                                  "verdict": report.run_conclusion,
                                  "reason": None, "blocking_reasons": []}
    if refusals:
        row["shipped_stream_path"]["refused_by_trace_integrity"] = True
        return _unavailable_row(
            row, [{"stage": "trace_integrity", "reason": refusal}
                  for refusal in refusals], trace_integrity=integrity)
    return _judged_row(
        row, report, reader=READER_STREAM_PATH,
        shipped_cli_default_invocation=ARGUMENT_ERROR_EXIT_CODE,
        trace_integrity=integrity)


# ---------------------------------------------------------------------------
# the sweep document
# ---------------------------------------------------------------------------

def _totals(rows: Sequence[Mapping]) -> dict:
    verdicts = {verdict: 0 for verdict in RUN_VERDICTS}
    for row in rows:
        verdicts[row["verdict"]] += 1
    judged = [row for row in rows if row["verdict"] != UNAVAILABLE]

    def total(field: str) -> int | None:
        return sum(row[field] for row in judged) if judged else None

    return {
        "declared_runs": len(rows),
        "verdicts": verdicts,
        "runs_with_a_shipped_verdict": len(judged),
        "runs_without_a_verdict": verdicts[UNAVAILABLE],
        "unavailable_run_directories": [
            row["run_directory"] for row in rows
            if row["verdict"] == UNAVAILABLE],
        "slot_count": total("slot_count"),
        "immutable_slots": total("immutable"),
        "violated_slots": total("violated"),
        "insufficient_slots": total("insufficient_evidence"),
        "runs_with_verified_trace_semantic_sha256": sum(
            1 for row in judged
            if (row.get("trace_integrity") or {}).get(
                "semantic_sha256_verified") is True),
        "runs_without_declared_trace_digest": sum(
            1 for row in judged
            if not (row.get("trace_integrity") or {}).get("available")
            or (row.get("trace_integrity") or {}).get(
                "declared_semantic_sha256") is None),
        "counts_note": (
            "unavailable runs contribute null (never 0) to every slot total; "
            "these totals add only the runs that produced a shipped verdict"),
    }


def _conclusion(rows: Sequence[Mapping]) -> str:
    verdicts = {row["verdict"] for row in rows}
    if "violated" in verdicts:
        return "violated"
    if UNAVAILABLE in verdicts:
        return UNAVAILABLE
    if "insufficient_evidence" in verdicts:
        return "insufficient_evidence"
    return "immutable"


def build_sweep(run_directories: Iterable[str], *,
                declaration_source: str = "command line",
                stream_reader: bool = True) -> dict:
    """Judge every declared run read-only and aggregate one versioned document."""
    declared = [str(directory) for directory in run_directories]
    rows = []
    for index, directory in enumerate(declared):
        try:
            rows.append(evaluate_run(directory, index=index,
                                     stream_reader=stream_reader))
        except Exception as error:  # never lose the document to one run
            row = _base_row(index, directory)
            rows.append(_unavailable_row(row, [{
                "stage": "sweep_internal_error",
                "reason": f"{type(error).__name__}: {error}"}]))
    conclusion = _conclusion(rows)
    return {
        "schema_version": SWEEP_SCHEMA_VERSION,
        "requirement": REQUIREMENT,
        "shipped_gate_schema_version": SHIPPED_GATE_SCHEMA_VERSION,
        "declaration": {
            "source": declaration_source,
            "run_directories": declared,
            "stream_reader_enabled": stream_reader,
            "verdict_source": ("myfuzz.scenario.slot_immutability"
                               " (shipped per-run verdict; no sweep-local rule)"),
        },
        "verdict_vocabulary": {
            "immutable": ("a shipped verdict: every judged program byte was "
                          "materialized and never given or read back a "
                          "different value in this run"),
            "violated": ("a shipped verdict: at least one program byte was "
                         "later given or read back a different value"),
            "insufficient_evidence": ("a shipped verdict: no byte was violated "
                                      "but at least one byte lacks evidence"),
            UNAVAILABLE: ("no shipped verdict could be produced; slot counts "
                          "are null and this run is never counted as immutable"),
        },
        "reader_modes": {
            READER_CLI_PATH: {
                "used_when": f"the run has {EVENTS_FILE_NAME}",
                "implementation": ("myfuzz.scenario.slot_immutability."
                                   "report_for_run (the shipped CLI's own path)"),
                "verifies": "the shipped gate's own contract only",
            },
            READER_STREAM_PATH: {
                "used_when": (f"the run has no {EVENTS_FILE_NAME} but does "
                              "declare a streamable trace artifact"),
                "implementation": ("myfuzz.scenario.acceptance_metrics."
                                   "TraceEventStream -> myfuzz.scenario."
                                   "slot_immutability.analyze_events"),
                "verifies": ("the declared event count of the stream plus the "
                             "shipped verdict rules"),
                "not_the_cli_default": (
                    "the shipped CLI invocation on such a run exits "
                    f"{ARGUMENT_ERROR_EXIT_CODE} (argument error) because its "
                    f"default artifact is {EVENTS_FILE_NAME}"),
            },
        },
        "trace_integrity": {
            "rule": ("every trace that produced a verdict is streamed once with "
                     "the shipped reader and its declared event count and "
                     "declared canonical semantic_sha256 are checked"),
            "refuses_the_verdict_when": [
                "the declared event count differs from the streamed count",
                "the streamed count differs from the event count the verdict "
                "was computed over",
                "the declared semantic_sha256 differs from the recomputed "
                "shipped canonical digest",
            ],
            "absence_of_metadata": ("a trace that declares no digest is "
                                    "recorded as such (available/reason and "
                                    "null fields); it is not by itself a "
                                    "failure, because the shipped gate does not "
                                    "require that metadata"),
        },
        "exit_code_semantics": {
            "shipped_gate": dict(EXIT_CODES),
            "shipped_gate_argument_error": ARGUMENT_ERROR_EXIT_CODE,
            "shipped_gate_rule": ("per run: immutable=0, violated=1, "
                                  "insufficient_evidence=2; a run the gate "
                                  "cannot read is an argument error (3)"),
            "sweep": {**SWEEP_EXIT_CODES,
                      "argument_error": ARGUMENT_ERROR_EXIT_CODE},
            "sweep_rule": ("immutable=0 only when every declared run is "
                           "immutable; violated=1 if any run is violated; "
                           "insufficient_evidence=2 or unavailable=2 when no "
                           "run is violated but at least one run is not "
                           "immutable; 3 when the declaration itself is empty"),
        },
        "runs": rows,
        "totals": _totals(rows),
        "sweep_conclusion": conclusion,
        "sweep_exit_code": SWEEP_EXIT_CODES[conclusion],
        "limits": list(LIMITS),
    }


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 scripts/report_p4_slot_immutability_sweep.py",
        description=("Read-only sweep of the shipped per-run slot immutability "
                     "verdict over a declared list of saved runs."))
    parser.add_argument("run_directories", nargs="*",
                        help="declared saved run directories, in declaration order")
    parser.add_argument("--runs-file", type=Path, default=None,
                        help=("file with one declared run directory per line; "
                              "blank lines and lines starting with '#' are ignored"))
    parser.add_argument("--json-out", type=Path, default=None,
                        help=f"write the {SWEEP_SCHEMA_VERSION} document here")
    parser.add_argument("--no-stream-reader", action="store_true",
                        help=(f"do not judge runs without {EVENTS_FILE_NAME} "
                              "through the shipped streaming reader"))
    return parser


def _declared_runs(arguments: argparse.Namespace) -> tuple[list[str], str]:
    declared = [str(directory) for directory in arguments.run_directories]
    source = "command line" if declared else "declaration"
    if arguments.runs_file is not None:
        lines = []
        for line in arguments.runs_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
        declared.extend(lines)
        source = (f"command line + runs file {arguments.runs_file}" if
                  arguments.run_directories else
                  f"runs file {arguments.runs_file}")
    return declared, source


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        declared, source = _declared_runs(arguments)
    except OSError as error:
        print(f"slot immutability sweep: {error}", file=sys.stderr)
        return ARGUMENT_ERROR_EXIT_CODE
    if not declared:
        print("slot immutability sweep: no declared run directory; pass run "
              "directories or --runs-file", file=sys.stderr)
        return ARGUMENT_ERROR_EXIT_CODE
    document = build_sweep(declared, declaration_source=source,
                           stream_reader=not arguments.no_stream_reader)
    text = json.dumps(document, sort_keys=True, indent=2) + "\n"
    if arguments.json_out is not None:
        arguments.json_out.parent.mkdir(parents=True, exist_ok=True)
        arguments.json_out.write_text(text, encoding="utf-8")
    for row in document["runs"]:
        if row["verdict"] == UNAVAILABLE:
            reasons = "; ".join(f"{item['stage']}: {item['reason']}"
                                for item in row["unavailable_reasons"])
            print(f"{SWEEP_SCHEMA_VERSION} {row['run_directory']}: "
                  f"verdict={UNAVAILABLE} ({reasons})", file=sys.stderr)
            continue
        print(row["gate_line"])
    totals = document["totals"]
    print(f"{SWEEP_SCHEMA_VERSION}: conclusion={document['sweep_conclusion']} "
          f"exit={document['sweep_exit_code']} "
          f"declared={totals['declared_runs']} "
          f"immutable_runs={totals['verdicts']['immutable']} "
          f"violated_runs={totals['verdicts']['violated']} "
          f"insufficient_runs={totals['verdicts']['insufficient_evidence']} "
          f"unavailable_runs={totals['verdicts'][UNAVAILABLE]} "
          f"slots={totals['slot_count']} "
          f"immutable_slots={totals['immutable_slots']} "
          f"violated_slots={totals['violated_slots']} "
          f"insufficient_slots={totals['insufficient_slots']}")
    return document["sweep_exit_code"]


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
