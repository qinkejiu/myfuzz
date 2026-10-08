#!/usr/bin/env python3
"""Read-only routing / consumption witness table for one SAVED UART online run.

Why this exists
---------------
The heterogeneous UART run ``runs/p5-uart-waveform-gate-20261008-online`` was
produced before ``report.json:source_target_transactions`` existed, so its own
report says nothing about the routing it really did.  The evidence, however, is
already on disk: the run's ``receipts.jsonl`` holds the per-candidate admission
decisions, and its trace holds the UART register accesses and the target
consumption witnesses that answered them.

This script derives that table **from the saved artifacts only**.  It starts no
RTL, renders no harness, writes nothing inside the run directory, and never
materializes the monolithic 274 MB trace: events are streamed with the shipped
bounded reader (``myfuzz.scenario.acceptance_metrics.TraceEventStream``) and
only the handful of witness-kind events are kept.

What it does *not* pretend
--------------------------
The saved run does not carry the A1 key, so this document is a **derivation**,
not a reading of the run's own conclusion.  Every quantity therefore states
where it came from:

``report.json``
    read; if it ever carries ``source_target_transactions`` that document is
    reported verbatim beside this derivation and cross-checked against it.
``receipts.jsonl``
    read; per-case identity, status, candidate disposition and the gate
    decision as the frozen receipt recorded it.
``trace``
    streamed; per-case register accesses and consumption witnesses, attributed
    to a case by the event's own ``provenance.observed_case`` /
    ``source_admission.case_id`` / ``action_id`` case prefix.
``re-derived``
    the in-window accesses a *refused* candidate declared are not in the saved
    receipts; they are re-derived here from the receipt's own candidate words
    with the shipped decoder and labelled as re-derived.

Exit codes: ``0`` the table was derived; ``2`` the run directory cannot be used
(missing receipts, unreadable/absent trace, malformed report).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.scenario.acceptance_metrics import TraceEventStream  # noqa: E402
from myfuzz.scenario.uart_routing_witness import (  # noqa: E402
    CONSUMPTION_WITNESS_KINDS,
    REGISTER_ACCESS_KINDS,
    SCHEMA_VERSION,
    UartRoutingWitnessRecorder,
)

DOC_SCHEMA_VERSION = "p5_uart_routing_witness_report.v1"
REPORT_NAME = "report.json"
RECEIPTS_NAME = "receipts.jsonl"
GATE_KEY = "source_action_gate"
TRANSACTIONS_KEY = "source_target_transactions"

WITNESS_KINDS = frozenset(REGISTER_ACCESS_KINDS + CONSUMPTION_WITNESS_KINDS)

EXIT_OK = 0
EXIT_INPUT_ERROR = 2

DEFAULT_MAX_BUFFERED_EVENTS_PER_CASE = 4096


class WitnessReportError(RuntimeError):
    """The run directory cannot be used for a witness derivation."""


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def _read_json_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise WitnessReportError(f"invalid JSON in {path}: {error.msg}") from error
    if not isinstance(document, dict):
        raise WitnessReportError(f"{path} is not a JSON object")
    return document


def read_receipts(path: Path) -> list[dict]:
    """Stream one ``receipts.jsonl``; a partial file is refused, not counted."""
    rows: list[dict] = []
    try:
        with Path(path).open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise WitnessReportError(
                        f"{path}: line {number} is not JSON: {error.msg}") from error
                if not isinstance(row, dict):
                    raise WitnessReportError(
                        f"{path}: line {number} is not a receipt object")
                rows.append(row)
    except OSError as error:
        raise WitnessReportError(f"{path} could not be read: {error}") from error
    return rows


def case_of_event(event: dict) -> str | None:
    """The case an event belongs to, from the event's own recorded identity.

    Preference order is the event's own provenance, then the source admission it
    names, then the case prefix of its ``action_id``.  Nothing is guessed from
    position in the stream.
    """
    provenance = event.get("provenance")
    if isinstance(provenance, dict):
        observed = provenance.get("observed_case")
        if isinstance(observed, dict):
            case_id = observed.get("case_id")
            if isinstance(case_id, str) and case_id:
                return case_id
    admission = event.get("source_admission")
    if isinstance(admission, dict):
        case_id = admission.get("case_id")
        if isinstance(case_id, str) and case_id:
            return case_id
    action_id = event.get("action_id")
    if isinstance(action_id, str) and ":" in action_id:
        prefix = action_id.split(":", 1)[0]
        if prefix:
            return prefix
    return None


def collect_case_events(run_dir: Path, *, max_buffered_per_case: int) -> dict:
    """Stream the trace once; keep only witness-kind events, grouped by case."""
    stream = TraceEventStream(run_dir, verify_semantic=True)
    by_case: dict[str, list[dict]] = {}
    totals = {"events": 0, "witness_events": 0, "events_without_a_case": 0,
              "buffered_events_omitted": 0}
    for event in stream.events():
        totals["events"] += 1
        if event.get("kind") not in WITNESS_KINDS:
            continue
        totals["witness_events"] += 1
        case_id = case_of_event(event)
        if case_id is None:
            totals["events_without_a_case"] += 1
            continue
        buffered = by_case.setdefault(case_id, [])
        if len(buffered) >= max_buffered_per_case:
            totals["buffered_events_omitted"] += 1
            continue
        buffered.append(event)
    return {"by_case": by_case, "totals": totals, "stream": stream}


def _declared_window_accesses(report: dict, action_document: dict) -> tuple:
    """Re-derive a candidate's in-window accesses from its own saved words."""
    gate = report.get(GATE_KEY)
    gate = gate if isinstance(gate, dict) else {}
    document = gate.get("gate")
    document = document if isinstance(document, dict) else {}
    window = document.get("window")
    if (not isinstance(window, dict) or type(window.get("base")) is not int
            or type(window.get("size")) is not int):
        return None, ("the saved report.json carries no source_action_gate.gate."
                      "window, so the declared UART window is unknown")
    payload = action_document.get("payload")
    words_hex = payload.get("words_hex") if isinstance(payload, dict) else None
    if not isinstance(words_hex, str):
        return None, ("the saved candidate carries no payload.words_hex, so its "
                      "declared accesses cannot be re-derived")
    from myfuzz.scenario import uart_waveform_gate

    try:
        decoded = uart_waveform_gate.fragment_mmio_accesses(bytes.fromhex(words_hex))
    except ValueError as error:
        return None, f"the saved candidate words are not decodable: {error}"
    base, size = window["base"], window["size"]
    return ([dict(item) for item in decoded
             if base <= item["address"] < base + size],
            f"re-derived from the saved payload.words_hex with "
            f"{uart_waveform_gate.__name__}.fragment_mmio_accesses "
            f"(sha256 {_sha256_file(Path(uart_waveform_gate.__file__))}); the "
            "saved receipt does not carry this list")


def gate_decisions_from_receipts(report: dict, receipts: list[dict]) -> dict:
    """The gate's per-candidate decisions exactly as the saved receipts hold them."""
    gate = report.get(GATE_KEY)
    gate = gate if isinstance(gate, dict) else {}
    gate_document = gate.get("gate")
    gate_document = gate_document if isinstance(gate_document, dict) else {}
    records: list[dict] = []
    re_derived_count = 0
    for row in receipts:
        source_action = row.get("source_action")
        source_action = source_action if isinstance(source_action, dict) else {}
        action_document = source_action.get("action")
        action_document = (action_document if isinstance(action_document, dict)
                           else {})
        evaluation = source_action.get("evaluation")
        evaluation = evaluation if isinstance(evaluation, dict) else {}
        missing = evaluation.get("missing")
        missing = (missing if isinstance(missing, list) and missing else [None])[0]
        missing = missing if isinstance(missing, dict) else {}
        refusal = source_action.get("refusal")
        refusal = refusal if isinstance(refusal, dict) else {}
        detail = refusal.get("detail")
        detail = detail if isinstance(detail, dict) else {}
        gate_component = gate_document.get("component")
        component = action_document.get("component")
        disposition = row.get("candidate_disposition")
        not_judged_reason = None
        if (isinstance(gate_component, str) and gate_component
                and isinstance(component, str) and component != gate_component):
            # The saved gate declares which component it binds; a candidate of
            # another component was never judged by it, so borrowing the
            # receipt's own disposition here would invent a decision.
            decision = "not_judged"
            not_judged_reason = (
                f"the saved gate declares component {gate_component!r}; this "
                f"candidate is component {component!r}, so the gate never judged it")
        elif disposition == "admitted":
            decision = "admitted"
        elif disposition == "rejected":
            decision = "refused"
        else:
            decision = disposition if isinstance(disposition, str) else "unknown"
        accesses, basis = _declared_window_accesses(report, action_document)
        if accesses is not None:
            re_derived_count += 1
        records.append({
            "case_id": row.get("case_id"),
            "gate_component": gate_component,
            "action_id": action_document.get("action_id"),
            "component": action_document.get("component"),
            "decision": decision,
            "candidate_disposition": disposition,
            "reason": (not_judged_reason
                       or detail.get("evaluation_reason") or refusal.get("reason")
                       or evaluation.get("reason")),
            "evidence_ref": missing.get("evidence_ref"),
            "prerequisite_kind": missing.get("kind"),
            "subject": missing.get("subject"),
            "window": gate_document.get("window"),
            "declared_window_accesses": accesses,
            "declared_accesses_basis": basis,
        })
    refused = sum(1 for row in records if row["decision"] == "refused")
    admitted = sum(1 for row in records if row["decision"] == "admitted")
    not_judged = sum(1 for row in records if row["decision"] == "not_judged")
    return {
        "schema_version": "uart_waveform_admission_decisions.v1",
        "source": (f"{RECEIPTS_NAME}:source_action + candidate_disposition, as the "
                   "frozen receipt recorded them (the saved gate itself is gone)"),
        "gate_report": gate_document or None,
        "gate_component": (gate_document.get("component")
                           if isinstance(gate_document.get("component"), str)
                           else None),
        "count": len(records),
        "admitted": admitted,
        "refused": refused,
        "not_judged": not_judged,
        "records": records,
        "limit": len(records),
        "truncated": False,
        "omitted": 0,
        "declared_accesses_re_derived": re_derived_count,
        "basis": ("one record per saved candidate; a refusal's declared in-window "
                  "accesses are re-derived from the candidate's own saved words "
                  "and labelled as re-derived"),
    }


def _case_identity(row: dict) -> dict:
    """Per-case identity from the receipt, with a declared-action fallback.

    A candidate refused before any RTL command carries the raw decoded input in
    ``online_source`` (component, address, data) and no ``kind``; the kind it
    did declare is in ``source_action.action.kind``, so that is used instead of
    reporting a null the receipt does not actually have.
    """
    source = row.get("online_source")
    source = source if isinstance(source, dict) else {}
    action = row.get("source_action")
    action = action if isinstance(action, dict) else {}
    declared = action.get("action")
    declared = declared if isinstance(declared, dict) else {}
    kind = source.get("kind")
    if not isinstance(kind, str) or not kind:
        kind = declared.get("kind")
    component = source.get("component")
    if not isinstance(component, str) or not component:
        component = declared.get("component")
    return {
        "case_id": row.get("case_id"),
        "component": component if isinstance(component, str) else None,
        "source_kind": kind if isinstance(kind, str) else None,
        "source_id": row.get("source_id"),
        "status": row.get("status"),
        "candidate_disposition": row.get("candidate_disposition"),
    }


def derive_document(run_dir: Path, *, case_limit: int, access_limit: int,
                    witness_limit: int,
                    max_buffered_per_case: int) -> dict:
    """Derive the per-case witness table from the saved receipts and trace."""
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise WitnessReportError(f"run directory does not exist: {run_dir}")
    report = _read_json_object(run_dir / REPORT_NAME) or {}
    receipts_path = run_dir / RECEIPTS_NAME
    if not receipts_path.is_file():
        raise WitnessReportError(f"run directory has no {RECEIPTS_NAME}")
    receipts = read_receipts(receipts_path)
    if not receipts:
        raise WitnessReportError(f"{receipts_path} holds no case")
    collected = collect_case_events(run_dir, max_buffered_per_case=max_buffered_per_case)
    by_case = collected["by_case"]
    stream = collected["stream"]

    recorder = UartRoutingWitnessRecorder(case_limit=case_limit,
                                          access_limit=access_limit,
                                          witness_limit=witness_limit)
    seen: set[str] = set()
    for row in receipts:
        identity = _case_identity(row)
        case_id = identity["case_id"]
        if not isinstance(case_id, str) or not case_id:
            raise WitnessReportError(
                f"{RECEIPTS_NAME} holds a row without a case_id")
        seen.add(case_id)
        if case_id in by_case:
            events = by_case[case_id]
        elif identity["status"] == "complete":
            # The case ran; the trace simply holds no witness-kind event for it.
            events = ()
        else:
            # A pre-RTL refusal produced no event slice at all.
            events = None
        recorder.observe_case(case_id=case_id, component=identity["component"],
                              source_kind=identity["source_kind"],
                              source_id=identity["source_id"], events=events)
    unattributed = sorted(set(by_case) - seen)
    for case_id in unattributed:
        # A case the trace names but the receipts do not (for example the fixed
        # bootstrap warmup): keep it, and take its component from the witness
        # events' own component field instead of guessing from the id.
        component = next((event.get("component") for event in by_case[case_id]
                          if isinstance(event.get("component"), str)), None)
        recorder.observe_case(case_id=case_id, component=component,
                              source_kind="not_in_receipts",
                              events=by_case[case_id])

    document = recorder.document()
    recorded = report.get(TRANSACTIONS_KEY)
    recorded = recorded if isinstance(recorded, dict) else None
    return {
        "schema_version": DOC_SCHEMA_VERSION,
        "run_dir": str(run_dir),
        "witness_schema_version": (recorded or document).get("schema_version",
                                                            SCHEMA_VERSION),
        "witness_source": ("report.json:source_target_transactions"
                           if recorded is not None else "derived_by_this_script"),
        "recorded_by_the_run": recorded,
        "derived": document,
        "agreement_with_recorded": (_compare(recorded, document)
                                    if recorded is not None else None),
        "gate_decisions": gate_decisions_from_receipts(report, receipts),
        "provenance": {
            "report.json": {
                "sha256": _sha256_file(run_dir / REPORT_NAME),
                "carries_source_target_transactions": recorded is not None,
                "session_status": report.get("session_status"),
                "execution_status": report.get("execution_status"),
                "schema_version": report.get("schema_version"),
                "statuses": report.get("statuses"),
            },
            "receipts.jsonl": {
                "sha256": _sha256_file(receipts_path),
                "rows": len(receipts),
                "statuses": _status_counts(receipts),
            },
            "trace": {
                "path": str(stream.path),
                "bytes": stream.descriptor.get("bytes"),
                "format": stream.descriptor.get("format"),
                "events_read": stream.event_count,
                "semantic_sha256": stream.semantic_sha256(),
                "semantic_sha256_verified": stream.semantic_sha256_verified(),
                "declared_status": stream.declared_status(),
                "witness_events": collected["totals"]["witness_events"],
                "events_without_a_case": collected["totals"]["events_without_a_case"],
                "buffered_events_omitted":
                    collected["totals"]["buffered_events_omitted"],
            },
            "cases_in_receipts": len(receipts),
            "cases_seen_in_trace": len(by_case),
            "cases_in_trace_not_in_receipts": unattributed,
        },
        "save_semantics": {
            "saved_artifact_quantities": [
                "receipts.jsonl per-case identity, status, candidate_disposition "
                "and the source_action gate decision document",
                "trace per-case register accesses and target consumption "
                "witnesses, and the trace's own semantic digest",
                "report.json statuses, schema and the gate's construction document",
            ],
            "future_run_only": [
                "report.json:source_target_transactions written by the run itself "
                "(this run predates it, so this table is a derivation)",
                "the gate's own decision log, including the declared in-window "
                "accesses it decoded before any RTL command (re-derived here)",
                "the decoder's own source_id/source_kind per case as selected at "
                "run time (read here from the receipt instead)",
            ],
            "never_claimed": [
                "no RTL was started, no trace was materialized, and nothing in "
                "the run directory was modified",
                "a witness that joins to no recorded access is reported "
                "matched=false, not dropped",
            ],
        },
    }


def _status_counts(receipts: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for row in receipts:
        status = row.get("status")
        if isinstance(status, str):
            counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _compare(recorded: dict | None, derived: dict) -> dict:
    """Compare a run-written witness table with this script's derivation."""
    if recorded is None:
        return {"comparable": False,
                "reason": "the run wrote no source_target_transactions key"}
    recorded_totals = recorded.get("totals")
    recorded_totals = recorded_totals if isinstance(recorded_totals, dict) else {}
    derived_totals = derived.get("totals") or {}
    keys = ("register_accesses", "cases_with_register_access",
            "target_consumption_witnesses",
            "cases_with_target_consumption_witness",
            "matched_consumption_witnesses")
    differences = [{"quantity": key, "recorded": recorded_totals.get(key),
                    "derived": derived_totals.get(key)}
                   for key in keys
                   if recorded_totals.get(key) != derived_totals.get(key)]
    return {"comparable": True, "differences": differences,
            "agrees": not differences and
                      recorded.get("schema_version") == derived.get("schema_version")}


def render_markdown(document: dict) -> str:
    derived = document["derived"]
    totals = derived["totals"]
    gate = document["gate_decisions"]
    provenance = document["provenance"]
    lines = [
        "# 已保存 UART 运行的真实路由见证（只读推导）", "",
        f"- 运行目录：`{document['run_dir']}`",
        f"- 见证文档 schema：`{document['witness_schema_version']}`",
        f"- 来源：`{document['witness_source']}`",
        f"- 报告 schema：`{provenance['report.json']['schema_version']}`，"
        f"`source_target_transactions` "
        f"{'存在' if provenance['report.json']['carries_source_target_transactions'] else '不存在（本表为推导）'}",
        "", "## 逐例路由/消费见证", "",
        f"- 观测到的用例数：{totals['cases']}"
        f"（保留 {totals['case_records_retained']}，省略 {totals['case_records_omitted']}）",
        f"- 产生 UART 寄存器访问的用例：{totals['cases_with_register_access']}"
        f"，访问总数：{totals['register_accesses']}",
        f"- 产生目标消费见证的用例：{totals['cases_with_target_consumption_witness']}"
        f"，见证总数：{totals['target_consumption_witnesses']}",
        f"- 已 join 的消费见证：{totals['matched_consumption_witnesses']}，"
        f"未 join：{totals['unmatched_consumption_witnesses']}",
        f"- 无任何见证的用例：{totals['cases_without_any_witness']}",
        f"- 见证点名的来源用例（source_admission）去重数："
        f"{totals['distinct_origin_cases']}（来源动作 {totals['distinct_origin_actions']}）",
        f"- 无事件切片（预 RTL 拒绝，null+原因）：{totals['event_slices_unavailable']}",
        "", "## 门的逐候选决策（来自 receipts.jsonl）", "",
        f"- 记录数：{gate['count']}（admitted {gate['admitted']}／refused {gate['refused']}）",
        f"- 其中声明式窗口访问经本脚本重新推导：{gate['declared_accesses_re_derived']}",
        "", "| case_id | 决策 | 原因 | 证据 | 前置类型 |", "|---|---|---|---|---|",
    ]
    for row in gate["records"]:
        if row["decision"] == "admitted" and not row["evidence_ref"]:
            continue
        lines.append(f"| `{row['case_id']}` | {row['decision']} | "
                     f"{row['reason'] or ''} | `{row['evidence_ref'] or ''}` | "
                     f"{row['prerequisite_kind'] or ''} |")
    lines += ["", "## 追溯（哪些数字来自已保存产物）", ""]
    for name, entry in provenance.items():
        if isinstance(entry, dict) and "sha256" in entry:
            lines.append(f"- `{name}`：sha256 `{entry['sha256']}`")
    trace = provenance["trace"]
    lines += [
        f"- trace：{trace['events_read']} 事件，语义 sha256 "
        f"`{trace['semantic_sha256']}`，声明一致="
        f"{trace['semantic_sha256_verified']}",
        "", "### 只会在未来运行里出现的量", "",
    ]
    lines += [f"- {item}" for item in document["save_semantics"]["future_run_only"]]
    return "\n".join(lines) + "\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", type=Path, required=True,
                        help="saved online run directory to read (never written)")
    parser.add_argument("--json-out", type=Path,
                        help="write the witness report JSON here")
    parser.add_argument("--markdown-out", type=Path,
                        help="write a markdown summary here")
    parser.add_argument("--case-limit", type=int, default=256)
    parser.add_argument("--access-limit", type=int, default=16)
    parser.add_argument("--witness-limit", type=int, default=16)
    parser.add_argument("--max-buffered-events-per-case", type=int, default=4096)
    args = parser.parse_args(argv)
    try:
        document = derive_document(
            args.run_dir, case_limit=args.case_limit,
            access_limit=args.access_limit, witness_limit=args.witness_limit,
            max_buffered_per_case=args.max_buffered_events_per_case)
    except WitnessReportError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return EXIT_INPUT_ERROR
    if args.json_out is not None:
        _write(args.json_out, json.dumps(document, sort_keys=True, indent=1) + "\n")
    if args.markdown_out is not None:
        _write(args.markdown_out, render_markdown(document))
    totals = document["derived"]["totals"]
    print(json.dumps({
        "run_dir": document["run_dir"],
        "witness_source": document["witness_source"],
        "cases": totals["cases"],
        "cases_with_register_access": totals["cases_with_register_access"],
        "register_accesses": totals["register_accesses"],
        "target_consumption_witnesses": totals["target_consumption_witnesses"],
        "matched_consumption_witnesses": totals["matched_consumption_witnesses"],
        "unmatched_consumption_witnesses": totals["unmatched_consumption_witnesses"],
        "cases_without_any_witness": totals["cases_without_any_witness"],
        "event_slices_unavailable": totals["event_slices_unavailable"],
        "distinct_origin_cases": totals["distinct_origin_cases"],
        "gate_decisions": document["gate_decisions"]["count"],
        "gate_refusals": document["gate_decisions"]["refused"],
        "json_out": None if args.json_out is None else str(args.json_out),
    }, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
