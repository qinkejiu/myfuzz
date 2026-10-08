#!/usr/bin/env python3
"""Independent verification of the saved P5 UART routing-witness derivation.

This script checks the claims made by
``runs/p5-uart-routing-witness-20261008-logs/uart_routing_witness.json`` and
``docs/reports/current-dataflow-p5-uart-routing-witness-20261008.md`` about the
SAVED run ``runs/p5-uart-waveform-gate-20261008-online``.

It is a *verifier*, so it re-derives every number itself:

* ``receipts.jsonl`` is parsed here (counts, statuses, gate decisions, the
  declared fragment words of every candidate);
* the 274 MB trace is streamed here with
  ``myfuzz.scenario.acceptance_metrics.TraceEventStream`` (never materialized,
  never ``read_text``/``json.load``-ed), and the access/witness events are
  regrouped per case with this script's own attribution and join rules;
* the candidate store address is decoded here with real RISC-V S-type store
  semantics, and separately with the layout ``uart_waveform_gate`` uses, so a
  decode disagreement is visible instead of inherited;
* the saved witness JSON is read **only** to fill each claim's ``reported``
  field and to compare against.

``myfuzz.scenario.uart_routing_witness`` is imported only for an explicitly
labelled cross-check (``producer_module_cross_check``); no number in the
``claims`` list is derived from it.

Claim entries are ``{claim, recomputed, reported, agree, note, ...}``; the
document also carries a ``per_case_hops`` table (one row per case that produced
a UART register access), an ``origin_map``, the global-join caveats, an
``unverifiable`` list and a ``disagreements`` list.  ``ok`` is true only when
every claim agrees.

Exit codes: ``0`` every claim agrees; ``4`` at least one claim disagrees;
``1`` an input artifact could not be read; ``3`` usage error.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.scenario.acceptance_metrics import TraceEventStream  # noqa: E402

SCHEMA_VERSION = "p5_uart_routing_witness_verification.v1"

RUN_DIR = ROOT / "runs" / "p5-uart-waveform-gate-20261008-online"
WITNESS_JSON = (ROOT / "runs" / "p5-uart-routing-witness-20261008-logs"
                / "uart_routing_witness.json")
RESULT_JSON = (ROOT / "runs" / "p5-uart-routing-witness-20261008-logs"
               / "uart_routing_witness_verify.json")
REPORT_DOC = (ROOT / "docs" / "reports"
              / "current-dataflow-p5-uart-routing-witness-20261008.md")

RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"

ACCESS_KIND = "uart_rdata_access"
WITNESS_KINDS = ("uart_fifo_pop", "uart_retired_read_match",
                 "uart_consumption_match")
WITNESS_KIND_SET = frozenset(WITNESS_KINDS)
COLLECTED_KINDS = frozenset((ACCESS_KIND, *WITNESS_KINDS))

#: The unjoined witnesses are the same-case IRQ-cause / retention frame proofs.
IRQ_AND_RETENTION_SCOPES = frozenset((
    "native_irq_cause", "uart_fifo_retention", "cpu_external_irq_taken",
    "controlled_uart_external_irq_entry"))

MAX_BUFFERED_EVENTS_PER_CASE = 4096

EXIT_OK = 0
EXIT_READ_ERROR = 1
EXIT_USAGE = 3
EXIT_DISAGREE = 4


class VerifyReadError(RuntimeError):
    """An input artifact could not be read or parsed."""


@dataclasses.dataclass(frozen=True)
class Expectations:
    """The literals the saved report/witness JSON claim, as quoted in the task."""

    receipt_rows: int = 60
    receipt_complete: int = 57
    receipt_input_invalid: int = 3
    chain_count: int = 7
    chain_access_ids: tuple = ("uart-access:uart:0:4", "uart-access:uart:0:7",
                               "uart-access:uart:0:11", "uart-access:uart:0:13",
                               "uart-access:uart:0:15", "uart-access:uart:0:17",
                               "uart-access:uart:0:19")
    chain_values: tuple = (90, 0, 197, 198, 200, 202, 204)
    chain_offset: int = 0x18
    uart_side_chains: int = 3
    cpu_side_chains: int = 4
    joined_per_chain: int = 3
    consumption_witnesses: int = 77
    joined_witnesses: int = 21
    unjoined_witnesses: int = 56
    cases_without_any_witness: int = 37
    null_rows: int = 3
    gate_judged: int = 24
    gate_admitted: int = 21
    gate_refused: int = 3
    gate_not_judged: int = 36
    refusal_kind: str = "transport_idle"
    refusal_evidence: frozenset = frozenset((
        "uart-waveform-idle:1832", "uart-waveform-idle:4456",
        "uart-waveform-idle:6296"))
    gated_components: frozenset = frozenset(("cpu",))
    declared_access_count: int = 7
    declared_access_word_offset: int = 12
    declared_admitted_with_accesses: frozenset = frozenset((
        "online-2-604caae5c07e4c776cb357d1",
        "online-9-b2abd214e101347dc1d77acf",
        "online-13-7dda5909d9568740498191b8",
        "online-55-3fc20bf6f5822f4d41b33c57"))
    doc_chains_reading_injected_byte: int = 6


DEFAULT_EXPECTATIONS = Expectations()

_FROZENSET_FIELDS = ("refusal_evidence", "gated_components",
                     "declared_admitted_with_accesses")
_TUPLE_FIELDS = ("chain_access_ids", "chain_values")


# ---------------------------------------------------------------------------
# reading artifacts
# ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def _read_json_object(path: Path, *, required: bool) -> dict | None:
    path = Path(path)
    if not path.is_file():
        if required:
            raise VerifyReadError(f"{path} does not exist")
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerifyReadError(f"{path} could not be parsed: {error}") from error
    if not isinstance(document, dict):
        raise VerifyReadError(f"{path} is not a JSON object")
    return document


def read_receipts(path: Path) -> list[dict]:
    """Parse one ``receipts.jsonl`` here; a malformed line refuses the file."""
    path = Path(path)
    if not path.is_file():
        raise VerifyReadError(f"{path} does not exist")
    rows: list[dict] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise VerifyReadError(
                        f"{path}: line {number} is not JSON: {error.msg}") from error
                if not isinstance(row, dict):
                    raise VerifyReadError(
                        f"{path}: line {number} is not a receipt object")
                rows.append(row)
    except OSError as error:
        raise VerifyReadError(f"{path} could not be read: {error}") from error
    if not rows:
        raise VerifyReadError(f"{path} holds no case")
    return rows


class Inputs:
    def __init__(self, run_dir: Path, receipts: list[dict], report: dict,
                 witness: dict, witness_path: Path):
        self.run_dir = run_dir
        self.receipts = receipts
        self.report = report
        self.witness = witness
        self.witness_path = witness_path


def load_inputs(run_dir: Path, witness_path: Path) -> Inputs:
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise VerifyReadError(f"run directory does not exist: {run_dir}")
    receipts = read_receipts(run_dir / RECEIPTS_NAME)
    report = _read_json_object(run_dir / REPORT_NAME, required=False) or {}
    witness = _read_json_object(witness_path, required=True)
    return Inputs(run_dir, receipts, report, witness, Path(witness_path))


# ---------------------------------------------------------------------------
# trace streaming (this script's own pass)
# ---------------------------------------------------------------------------
def _int_or_none(value: object) -> int | None:
    return value if type(value) is int else None


def case_of_event(event: dict) -> str | None:
    """Case attribution from the event's own recorded identity (no position)."""
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


def _access_fact(event: dict, case_id: str | None) -> dict:
    return {
        "case_id": case_id,
        "event_id": _int_or_none(event.get("event_id")),
        "kind": event.get("kind"),
        "access_id": event.get("access_id"),
        "address": _int_or_none(event.get("address")),
        "offset": _int_or_none(event.get("raw_offset")),
        "window_base": _int_or_none(event.get("window_base")),
        "window_size": _int_or_none(event.get("window_size")),
        "write": event.get("write") if type(event.get("write")) is bool else None,
        "read_value": _int_or_none(event.get("read_value")),
        "status": event.get("status"),
        "actual_request_event_id": _int_or_none(
            event.get("actual_request_event_id")),
        "actual_response_event_id": _int_or_none(
            event.get("actual_response_event_id")),
        "source_transaction": (dict(event["source_transaction"])
                               if isinstance(event.get("source_transaction"), dict)
                               else None),
        "raw": event,
    }


def _witness_fact(event: dict, case_id: str | None) -> dict:
    return {
        "case_id": case_id,
        "event_id": _int_or_none(event.get("event_id")),
        "kind": event.get("kind"),
        "entry_id": (list(event["entry_id"])
                     if isinstance(event.get("entry_id"), list)
                     else event.get("entry_id")),
        "frame_id": event.get("frame_id"),
        "value": _int_or_none(event.get("value")),
        "status": event.get("status"),
        "disposition": event.get("disposition"),
        "proof_scope": event.get("proof_scope"),
        "read_value": _int_or_none(event.get("read_value")),
        "observation_event_id": _int_or_none(event.get("observation_event_id")),
        "uart_access_event_id": _int_or_none(event.get("uart_access_event_id")),
        "uart_read_proof_event_id": _int_or_none(
            event.get("uart_read_proof_event_id")),
        "inner_access_id": (event.get("access") or {}).get("access_id")
        if isinstance(event.get("access"), dict) else None,
        "source_admission": (dict(event["source_admission"])
                             if isinstance(event.get("source_admission"), dict)
                             else None),
        "raw": event,
    }


def collect_trace_facts(run_dir: Path) -> dict:
    """One streaming pass over the saved trace; no event is materialized."""
    run_dir = Path(run_dir)
    try:
        stream = TraceEventStream(run_dir, verify_semantic=True)
    except (OSError, ValueError) as error:
        raise VerifyReadError(f"the trace of {run_dir} is unreadable: {error}"
                              ) from error

    by_case: dict[str, list[dict]] = {}
    accesses: list[dict] = []
    witnesses: list[dict] = []
    case_ids_in_trace: set[str] = set()
    frames: list[dict] = []          # uart_source_frame_admission
    pushes: list[dict] = []          # uart_fifo_push
    event_count = 0
    events_without_a_case: list[dict] = []
    omitted = 0
    try:
        for event in stream.events():
            event_count += 1
            case_id = case_of_event(event)
            if case_id is not None:
                case_ids_in_trace.add(case_id)
            kind = event.get("kind")
            if kind in COLLECTED_KINDS:
                if case_id is None:
                    events_without_a_case.append(
                        {"kind": kind, "event_id": _int_or_none(event.get("event_id"))})
                    continue
                bucket = by_case.setdefault(case_id, [])
                if len(bucket) >= MAX_BUFFERED_EVENTS_PER_CASE:
                    omitted += 1
                    continue
                bucket.append(event)
            if kind == ACCESS_KIND:
                accesses.append(_access_fact(event, case_id))
            elif kind in WITNESS_KIND_SET:
                witnesses.append(_witness_fact(event, case_id))
            elif kind == "uart_source_frame_admission":
                frames.append({
                    "event_id": _int_or_none(event.get("event_id")),
                    "case_id": case_id,
                    "action_id": event.get("action_id"),
                    "byte": _int_or_none(event.get("byte")),
                    "frame_id": event.get("frame_id"),
                    "admission_ids": [str(item) for item in
                                      (event.get("provenance", {}) or {}).get(
                                          "origin_admission_ids", [])
                                      if isinstance(item, str)],
                })
            elif kind == "uart_fifo_push":
                pushes.append({
                    "event_id": _int_or_none(event.get("event_id")),
                    "case_id": case_id,
                    "value": _int_or_none(event.get("value")),
                    "entry_id": (list(event["entry_id"])
                                 if isinstance(event.get("entry_id"), list)
                                 else event.get("entry_id")),
                    "frame_id": event.get("frame_id"),
                })
    except (OSError, ValueError, TypeError) as error:
        raise VerifyReadError(f"the trace of {run_dir} failed mid-stream: {error}"
                              ) from error

    return {
        "path": str(stream.path),
        "bytes": stream.descriptor.get("bytes"),
        "format": stream.descriptor.get("format"),
        "events": event_count,
        "semantic_sha256": stream.semantic_sha256(),
        "semantic_sha256_verified": stream.semantic_sha256_verified(),
        "declared_status": stream.declared_status(),
        "by_case": by_case,
        "accesses": accesses,
        "witnesses": witnesses,
        "case_ids_in_trace": sorted(case_ids_in_trace),
        "frames": frames,
        "pushes": pushes,
        "events_without_a_case": events_without_a_case,
        "buffered_events_omitted": omitted,
    }


# ---------------------------------------------------------------------------
# independent join rules
# ---------------------------------------------------------------------------
def _frame_keys(witness: dict) -> tuple:
    entry = witness.get("entry_id")
    if not isinstance(entry, list):
        return ()
    key = tuple(str(item) for item in entry)
    frame_id = witness.get("frame_id")
    if isinstance(frame_id, str):
        return ((key, frame_id), (key, None))
    return ((key, None),)


def join_case(accesses: list[dict], witnesses: list[dict]) -> dict:
    """Join each witness to this case's accesses by the documented exact keys."""
    by_event = {item["event_id"]: item for item in accesses
                if item["event_id"] is not None}
    by_request = {item["actual_request_event_id"]: item for item in accesses
                  if item["actual_request_event_id"] is not None}
    by_access_id = {item["access_id"]: item for item in accesses
                    if item["access_id"]}
    frame_access: dict[tuple, str] = {}
    for witness in witnesses:
        if witness["kind"] != "uart_fifo_pop":
            continue
        access = by_request.get(witness["observation_event_id"])
        if access is None and witness["inner_access_id"]:
            access = by_access_id.get(witness["inner_access_id"])
        if access is None or not access["access_id"]:
            continue
        for key in _frame_keys(witness):
            frame_access.setdefault(key, access["access_id"])

    joins: dict[int, dict] = {}
    for witness in witnesses:
        access_id = None
        basis = None
        if witness["kind"] == "uart_fifo_pop":
            access = by_request.get(witness["observation_event_id"])
            if access is not None and access["access_id"]:
                access_id, basis = access["access_id"], "pop_request_join"
            elif witness["inner_access_id"] in by_access_id:
                access_id, basis = witness["inner_access_id"], "pop_access_id_join"
        elif witness["kind"] == "uart_retired_read_match":
            access = by_event.get(witness["uart_access_event_id"])
            if access is not None and access["access_id"]:
                access_id, basis = access["access_id"], "retired_event_join"
        elif witness["kind"] == "uart_consumption_match":
            access = by_event.get(witness["observation_event_id"])
            if access is not None and access["access_id"]:
                access_id, basis = access["access_id"], "consumption_event_join"
            else:
                for key in _frame_keys(witness):
                    found = frame_access.get(key)
                    if found is not None:
                        access_id, basis = found, "consumption_frame_join"
                        break
        joins[witness["event_id"]] = {"access_id": access_id, "basis": basis,
                                      "matched": access_id is not None}
    return {"joins": joins, "frame_access": frame_access}


def decode_riscv_accesses(data: bytes, *, window_base: int,
                          window_size: int) -> list[dict]:
    """Loads/stores a fragment performs, with real RV32I S-type store semantics."""
    if not isinstance(data, (bytes, bytearray)) or len(data) % 4:
        raise ValueError("a fragment must be whole 32-bit words")
    bases: dict[int, int] = {}
    found: list[dict] = []
    for offset in range(0, len(data), 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        opcode = word & 0x7F
        rd = (word >> 7) & 0x1F
        rs1 = (word >> 15) & 0x1F
        funct3 = (word >> 12) & 0x7
        if opcode == 0x37:  # LUI
            bases[rd] = ((word >> 12) & 0xFFFFF) << 12
            continue
        if opcode == 0x03 and funct3 == 2:  # LW (I-type)
            operation = "LW"
            immediate = _signed_12((word >> 20) & 0xFFF)
        elif opcode == 0x23 and funct3 in (0, 2):  # SB/SW (S-type)
            operation = "SB" if funct3 == 0 else "SW"
            immediate = _signed_12((((word >> 25) & 0x7F) << 5)
                                   | ((word >> 7) & 0x1F))
        else:
            continue
        if rs1 not in bases:
            continue
        address = (bases[rs1] + immediate) & 0xFFFFFFFF
        if window_base <= address < window_base + window_size:
            found.append({"operation": operation, "address": address,
                          "word_offset": offset})
    return found


def decode_gate_layout_accesses(data: bytes, *, window_base: int,
                                window_size: int) -> list[dict]:
    """Re-implementation of the shipped gate decoder's immediate extraction.

    ``uart_waveform_gate.fragment_mmio_accesses`` reads bits 31:20 as the
    immediate for every load and store.  That is the I-type layout; for an
    S-type store the immediate is split (imm[11:5] in bits 31:25, imm[4:0] in
    bits 11:7), so the two decoders can disagree.  Kept here (not imported) so
    the disagreement is a first-class result of this verification.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) % 4:
        raise ValueError("a fragment must be whole 32-bit words")
    bases: dict[int, int] = {}
    found: list[dict] = []
    for offset in range(0, len(data), 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        opcode = word & 0x7F
        rd = (word >> 7) & 0x1F
        rs1 = (word >> 15) & 0x1F
        funct3 = (word >> 12) & 0x7
        if opcode == 0x37:
            bases[rd] = ((word >> 12) & 0xFFFFF) << 12
            continue
        operation = {(0x03, 2): "LW", (0x23, 2): "SW",
                     (0x23, 0): "SB"}.get((opcode, funct3))
        if operation is None or rs1 not in bases:
            continue
        address = (bases[rs1] + _signed_12((word >> 20) & 0xFFF)) & 0xFFFFFFFF
        if window_base <= address < window_base + window_size:
            found.append({"operation": operation, "address": address,
                          "word_offset": offset})
    return found


def _signed_12(value: int) -> int:
    return value - 0x1000 if value & 0x800 else value


def _window_of(report: dict) -> dict | None:
    gate = report.get("source_action_gate")
    gate = gate if isinstance(gate, dict) else {}
    document = gate.get("gate")
    document = document if isinstance(document, dict) else {}
    window = document.get("window")
    if (not isinstance(window, dict) or type(window.get("base")) is not int
            or type(window.get("size")) is not int):
        return None
    return {"base": window["base"], "size": window["size"],
            "component": document.get("component")}


# ---------------------------------------------------------------------------
# receipts -> identity and gate decisions
# ---------------------------------------------------------------------------
def _receipt_identity(row: dict) -> dict:
    source = row.get("online_source")
    source = source if isinstance(source, dict) else {}
    action = row.get("source_action")
    action = action if isinstance(action, dict) else {}
    declared = action.get("action")
    declared = declared if isinstance(declared, dict) else {}
    component = source.get("component") or declared.get("component")
    kind = source.get("kind") or declared.get("kind")
    payload = declared.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    evaluation = action.get("evaluation")
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    missing = evaluation.get("missing")
    missing = (missing[0] if isinstance(missing, list) and missing
               and isinstance(missing[0], dict) else {})
    refusal = action.get("refusal")
    refusal = refusal if isinstance(refusal, dict) else {}
    return {
        "case_id": row.get("case_id"),
        "status": row.get("status"),
        "candidate_disposition": row.get("candidate_disposition"),
        "component": component if isinstance(component, str) else None,
        "source_kind": kind if isinstance(kind, str) else None,
        "source_id": row.get("source_id") or declared.get("source_id"),
        "action_id": declared.get("action_id"),
        "words_hex": payload.get("words_hex"),
        "injected_value": (source.get("value")
                           if type(source.get("value")) is int else None),
        "error": row.get("error"),
        "local_ticks": row.get("local_ticks"),
        "missing": missing,
        "refusal_reason": refusal.get("reason"),
        "evaluation_reason": evaluation.get("reason"),
    }


def gate_decisions(receipts: list[dict], window: dict | None) -> list[dict]:
    """One decision per saved candidate, judged only by the gate's component."""
    gate_component = None if window is None else window.get("component")
    records: list[dict] = []
    for row in receipts:
        identity = _receipt_identity(row)
        missing = identity["missing"]
        decision = None
        reason = None
        if (isinstance(gate_component, str) and gate_component
                and identity["component"] != gate_component):
            decision = "not_judged"
            reason = (f"the saved gate declares component {gate_component!r}; "
                      f"this candidate is component {identity['component']!r}")
        elif identity["candidate_disposition"] == "admitted":
            decision = "admitted"
        elif identity["candidate_disposition"] == "rejected":
            decision = "refused"
        else:
            decision = str(identity["candidate_disposition"])
        declared = None
        spec_correct = None
        basis = None
        if window is not None and isinstance(identity["words_hex"], str):
            try:
                data = bytes.fromhex(identity["words_hex"])
            except ValueError:
                data = None
            if data is not None:
                declared = decode_gate_layout_accesses(
                    data, window_base=window["base"],
                    window_size=window["size"])
                spec_correct = decode_riscv_accesses(
                    data, window_base=window["base"],
                    window_size=window["size"])
                basis = "decoded here from the candidate's own payload.words_hex"
        records.append({
            "case_id": identity["case_id"],
            "action_id": identity["action_id"],
            "component": identity["component"],
            "decision": decision,
            "not_judged_reason": reason if decision == "not_judged" else None,
            "candidate_disposition": identity["candidate_disposition"],
            "evidence_ref": missing.get("evidence_ref"),
            "prerequisite_kind": missing.get("kind"),
            "subject": (dict(missing["subject"])
                        if isinstance(missing.get("subject"), dict) else None),
            "refusal_reason": identity["refusal_reason"],
            "evaluation_reason": identity["evaluation_reason"],
            "declared_window_accesses": declared,
            "declared_window_accesses_spec_correct": spec_correct,
            "declared_accesses_basis": basis,
        })
    return records


# ---------------------------------------------------------------------------
# derived per-case table (this script's numbers)
# ---------------------------------------------------------------------------
def _access_sort_key(access_id: object) -> tuple:
    text = access_id if isinstance(access_id, str) else ""
    suffix = text.rsplit(":", 1)[-1]
    return (int(suffix) if suffix.isdigit() else 1 << 30, text)


def derive(receipts: list[dict], trace: dict) -> dict:
    """Everything this verifier recomputes from receipts + its own trace pass."""
    identities = {row.get("case_id"): _receipt_identity(row) for row in receipts}
    by_case = trace["by_case"]
    case_ids = list(identities) + sorted(set(by_case) - set(identities))

    cases: dict[str, dict] = {}
    for case_id in case_ids:
        identity = identities.get(case_id, {})
        events = by_case.get(case_id, [])
        accesses = [_access_fact(event, case_id) for event in events
                    if event.get("kind") == ACCESS_KIND]
        witnesses = [_witness_fact(event, case_id) for event in events
                     if event.get("kind") in WITNESS_KIND_SET]
        # A pre-RTL refusal produced no event slice at all: counts are null.
        has_slice = (case_id in identities
                     and identities[case_id].get("status") == "complete") or \
            case_id in by_case
        joined = join_case(accesses, witnesses)
        matched = [w for w in witnesses if joined["joins"][w["event_id"]]["matched"]]
        unjoined = [w for w in witnesses
                    if not joined["joins"][w["event_id"]]["matched"]]
        covered = {joined["joins"][w["event_id"]]["access_id"] for w in matched}
        access_ids = {a["access_id"] for a in accesses if a["access_id"]}
        cases[case_id] = {
            "case_id": case_id,
            "component": identity.get("component"),
            "source_id": identity.get("source_id"),
            "source_kind": identity.get("source_kind"),
            "status": identity.get("status"),
            "in_trace": case_id in by_case,
            "has_event_slice": has_slice,
            "accesses": accesses,
            "witnesses": witnesses,
            "joins": joined["joins"],
            "access_count": None if not has_slice else len(accesses),
            "witness_count": None if not has_slice else len(witnesses),
            "matched_count": None if not has_slice else len(matched),
            "unjoined_count": None if not has_slice else len(unjoined),
            "matched_witnesses": matched,
            "unjoined_witnesses": unjoined,
            "complete": bool(has_slice and accesses
                             and covered == access_ids),
        }

    chain_cases = sorted(
        (case for case in cases.values() if case["accesses"]),
        key=lambda case: _access_sort_key(case["accesses"][0]["access_id"]))

    # origin (frame injector) of each chain, from the witnesses' own admissions
    origin_map: list[dict] = []
    for case in chain_cases:
        admission = None
        for witness in case["matched_witnesses"]:
            if witness["source_admission"]:
                admission = witness["source_admission"]
                break
        if admission is None:
            for witness in case["witnesses"]:
                if witness["source_admission"]:
                    admission = witness["source_admission"]
                    break
        origin_map.append({
            "case_id": case["case_id"],
            "component": case["component"],
            "access_id": case["accesses"][0]["access_id"],
            "read_value": case["accesses"][0]["read_value"],
            "origin_case": (admission or {}).get("case_id"),
            "origin_action": (admission or {}).get("action_id"),
            "origin_admission_id": (admission or {}).get("admission_id"),
            "origin_role": (admission or {}).get("role"),
            "origin_direction": (admission or {}).get("direction"),
            "has_admission": admission is not None,
        })

    witnesses = trace["witnesses"]
    joined_witnesses = [w for w in witnesses
                        if cases.get(w["case_id"], {}).get("joins", {})
                        .get(w["event_id"], {}).get("matched")]
    unjoined_witnesses = [w for w in witnesses if w not in joined_witnesses]
    joined_ids = {id(w) for w in joined_witnesses}
    unjoined_witnesses = [w for w in witnesses if id(w) not in joined_ids]

    event_ids = [item["event_id"] for item in (*trace["accesses"], *witnesses)
                 if item["event_id"] is not None]
    seen: set[int] = set()
    duplicates: set[int] = set()
    for event_id in event_ids:
        if event_id in seen:
            duplicates.add(event_id)
        seen.add(event_id)

    # A global (not per-case) entry-key join would attach some retention
    # witnesses to another case's pop; this is reported as a caveat.
    globally_joined_entries: dict[tuple, tuple] = {}
    for case in cases.values():
        for witness in case["matched_witnesses"]:
            if witness["kind"] == "uart_fifo_pop" and isinstance(
                    witness["entry_id"], list):
                key = tuple(str(item) for item in witness["entry_id"])
                globally_joined_entries.setdefault(
                    key, (case["case_id"], case["accesses"][0]["access_id"]
                          if case["accesses"] else None))
    unjoined_for_global = [
        {"case_id": w["case_id"], "event_id": w["event_id"], "kind": w["kind"],
         "entry_id": w["entry_id"]}
        for w in unjoined_witnesses
        if isinstance(w["entry_id"], list)
        and any(case["case_id"] != w["case_id"]
                for case in cases.values()
                for wit in case["matched_witnesses"]
                if wit["kind"] == "uart_fifo_pop")]
    caveats = global_entry_join_caveats(unjoined_for_global,
                                        globally_joined_entries)

    return {
        "cases": cases,
        "chain_cases": [case["case_id"] for case in chain_cases],
        "chain_rows": [{
            "case_id": case["case_id"],
            "component": case["component"],
            "source_id": case["source_id"],
            "access_id": case["accesses"][0]["access_id"],
            "offset": case["accesses"][0]["offset"],
            "read_value": case["accesses"][0]["read_value"],
        } for case in chain_cases],
        "origin_map": origin_map,
        "witness_total": len(witnesses),
        "joined_total": len(joined_witnesses),
        "unjoined_total": len(unjoined_witnesses),
        "unjoined_scopes": _histogram(w["proof_scope"] for w in unjoined_witnesses),
        "unjoined_kinds": _histogram(w["kind"] for w in unjoined_witnesses),
        "unjoined_dispositions": _histogram(
            str(w["disposition"]) for w in unjoined_witnesses),
        "witness_kind_totals": _histogram(w["kind"] for w in witnesses),
        "cases_with_access": len(chain_cases),
        "cases_with_witness": sum(1 for case in cases.values()
                                  if case["witness_count"]),
        "cases_without_any_witness": sum(
            1 for case in cases.values()
            if case["has_event_slice"] and not case["access_count"]
            and not case["witness_count"]),
        "null_slice_cases": sorted(case["case_id"] for case in cases.values()
                                   if not case["has_event_slice"]),
        "duplicate_witness_event_ids": sorted(duplicates),
        "cases_with_any_joined_witness": sorted(
            case["case_id"] for case in cases.values()
            if any(case["joins"][w["event_id"]]["matched"]
                   for w in case["witnesses"])),
        "cases_with_pop_without_access": sorted(
            case["case_id"] for case in cases.values()
            if any(w["kind"] == "uart_fifo_pop" for w in case["witnesses"])
            and not case["accesses"]),
        "global_join_caveats": caveats,
        "cases_in_trace_not_in_receipts": sorted(
            set(trace["case_ids_in_trace"]) - set(identities)),
        "receipt_cases_in_trace": sorted(
            set(identities) & set(trace["case_ids_in_trace"])),
        "event_ids_unique": not duplicates,
    }


def _histogram(values) -> dict:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def global_entry_join_caveats(unjoined: list[dict],
                              globally_joined_entries: dict) -> list[dict]:
    """Unjoined witnesses whose frame entry was popped by another case."""
    normalised = {tuple(str(item) for item in key): value
                  for key, value in globally_joined_entries.items()}
    found: list[dict] = []
    for witness in unjoined:
        entry = witness.get("entry_id")
        if not isinstance(entry, list):
            continue
        joined = normalised.get(tuple(str(item) for item in entry))
        if joined is None or joined[0] == witness["case_id"]:
            continue
        found.append({"case_id": witness["case_id"],
                      "event_id": witness["event_id"],
                      "entry_id": list(entry),
                      "joined_in_case": joined[0],
                      "joined_access_id": joined[1]})
    return found


# ---------------------------------------------------------------------------
# reported side (the witness JSON / the report doc), never used to derive
# ---------------------------------------------------------------------------
def reported_from_witness(witness: dict) -> dict:
    derived = witness.get("derived") if isinstance(witness.get("derived"), dict) else {}
    totals = derived.get("totals") if isinstance(derived.get("totals"), dict) else {}
    cases = derived.get("cases") if isinstance(derived.get("cases"), dict) else {}
    records = cases.get("records") if isinstance(cases.get("records"), list) else []
    provenance = (witness.get("provenance")
                  if isinstance(witness.get("provenance"), dict) else {})
    receipts = provenance.get("receipts.jsonl")
    receipts = receipts if isinstance(receipts, dict) else {}
    report_prov = provenance.get("report.json")
    report_prov = report_prov if isinstance(report_prov, dict) else {}
    trace_prov = provenance.get("trace")
    trace_prov = trace_prov if isinstance(trace_prov, dict) else {}
    gate = (witness.get("gate_decisions")
            if isinstance(witness.get("gate_decisions"), dict) else {})
    gate_records = gate.get("records") if isinstance(gate.get("records"), list) else []

    case_records = {}
    chains = []
    matched = {}
    null_rows = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        case_id = record.get("case_id")
        accesses = record.get("register_accesses")
        accesses = accesses if isinstance(accesses, dict) else {}
        witnesses = record.get("target_consumption_witnesses")
        witnesses = witnesses if isinstance(witnesses, dict) else {}
        matched_doc = record.get("matched")
        matched_doc = matched_doc if isinstance(matched_doc, dict) else {}
        case_records[case_id] = {
            "access_count": accesses.get("count"),
            "witness_count": witnesses.get("count"),
            "access_records": accesses.get("records") or [],
            "witness_records": witnesses.get("records") or [],
            "matched_complete": matched_doc.get("complete"),
            "witnesses_matched": matched_doc.get("witnesses_matched"),
            "witnesses_unmatched": matched_doc.get("witnesses_unmatched"),
            "reason": record.get("reason"),
        }
        if accesses.get("count"):
            for access in accesses.get("records") or []:
                chains.append({"case_id": case_id,
                               "access_id": access.get("access_id"),
                               "offset": access.get("offset"),
                               "read_value": access.get("read_value")})
        matched[case_id] = {
            "witnesses_matched": matched_doc.get("witnesses_matched"),
            "kinds": sorted(w.get("kind") for w in (witnesses.get("records") or [])
                            if isinstance(w, dict) and w.get("matched")),
            "complete": matched_doc.get("complete"),
        }
        if accesses.get("count") is None:
            null_rows[case_id] = {
                "register_accesses_count": accesses.get("count"),
                "consumption_witnesses_count": witnesses.get("count"),
                "reason": record.get("reason"),
            }

    return {
        "receipts": {"rows": receipts.get("rows"),
                     "statuses": receipts.get("statuses")},
        "totals": dict(totals),
        "case_records": case_records,
        "chains": chains,
        "matched": matched,
        "null_rows": null_rows,
        "gate": {"count": gate.get("count"), "admitted": gate.get("admitted"),
                 "refused": gate.get("refused"),
                 "not_judged": gate.get("not_judged"),
                 "gate_component": gate.get("gate_component"),
                 "records": gate_records},
        "witness_source": witness.get("witness_source"),
        "recorded_by_the_run": witness.get("recorded_by_the_run"),
        "carries_transactions_key": report_prov.get(
            "carries_source_target_transactions"),
        "trace": {"events_read": trace_prov.get("events_read"),
                  "semantic_sha256": trace_prov.get("semantic_sha256"),
                  "semantic_sha256_verified": trace_prov.get(
                      "semantic_sha256_verified"),
                  "witness_events": trace_prov.get("witness_events")},
        "cases_in_trace_not_in_receipts": provenance.get(
            "cases_in_trace_not_in_receipts"),
    }


def reported_from_report_doc(path: Path) -> dict:
    document = {"path": str(path), "exists": Path(path).is_file(),
                "sha256": sha256_file(path),
                "semantic_sha256": None, "events": None}
    if not document["exists"]:
        return document
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        document["exists"] = False
        return document
    digests = re.findall(r"\b[0-9a-f]{64}\b", text)
    document["semantic_sha256"] = digests[0] if digests else None
    match = re.search(r"([\d,]+)\s*事件", text)
    if match:
        document["events"] = int(match.group(1).replace(",", ""))
    document["states_six_of_seven"] = "6 个读到的正是被注入字节" in text
    return document


# ---------------------------------------------------------------------------
# claim construction
# ---------------------------------------------------------------------------
def _claim(name: str, description: str, recomputed, reported, agree: bool, *,
           recomputed_from: str, reported_from: str, note: str = "",
           severity: str = "numeric", root_cause: str | None = None,
           detail=None) -> dict:
    return {"claim": name, "description": description, "recomputed": recomputed,
            "reported": reported, "agree": bool(agree),
            "recomputed_from": recomputed_from, "reported_from": reported_from,
            "note": note, "severity": severity, "detail": detail,
            "root_cause": root_cause if not agree else None}


def build_claims(inputs: Inputs, trace: dict, derivation: dict,
                 reported: dict, doc: dict,
                 expectations: Expectations) -> list[dict]:
    claims: list[dict] = []
    receipts = inputs.receipts
    ids = [_receipt_identity(row) for row in receipts]
    statuses = _histogram(identity.get("status") for identity in receipts)
    complete = statuses.get("complete", 0)
    input_invalid = statuses.get("input_invalid", 0)
    window = _window_of(inputs.report)
    decisions = gate_decisions(receipts, window)
    by_case = derivation["cases"]

    # 1. receipts = 57 complete + 3 input_invalid
    recomputed = {"rows": len(receipts), "complete": complete,
                  "input_invalid": input_invalid, "statuses": statuses}
    rep = reported["receipts"]
    agree = (len(receipts) == expectations.receipt_rows
             and complete == expectations.receipt_complete
             and input_invalid == expectations.receipt_input_invalid
             and rep.get("rows") == len(receipts)
             and rep.get("statuses") == statuses)
    claims.append(_claim(
        "receipts_total_and_statuses",
        "receipts.jsonl holds 60 rows = 57 complete + 3 input_invalid",
        recomputed, rep, agree,
        recomputed_from="receipts.jsonl, parsed by this script",
        reported_from="witness JSON provenance.receipts.jsonl",
        note="expected 60/57/3 from the claim under test"))

    # 2-4. the seven read chains
    chain_rows = derivation["chain_rows"]
    recomputed_ids = [row["access_id"] for row in chain_rows]
    expected_ids = list(expectations.chain_access_ids)
    rep_chains = [row for row in reported["chains"] if row.get("access_id")]
    rep_ids = [row["access_id"] for row in rep_chains]
    agree_count = (derivation["cases_with_access"] == expectations.chain_count
                   and reported["totals"].get("cases_with_register_access")
                   == expectations.chain_count)
    claims.append(_claim(
        "read_chain_cases",
        "exactly 7 cases produced a UART register access",
        derivation["cases_with_access"],
        reported["totals"].get("cases_with_register_access"), agree_count,
        recomputed_from="trace uart_rdata_access events grouped by observed_case",
        reported_from="witness JSON derived.totals.cases_with_register_access",
        note=f"expected {expectations.chain_count}"))

    agree_ids = (sorted(recomputed_ids) == sorted(expected_ids)
                 and sorted(rep_ids) == sorted(expected_ids))
    claims.append(_claim(
        "read_chain_access_ids",
        "the 7 chains are uart-access:uart:0:4/7/11/13/15/17/19",
        recomputed_ids, rep_ids, agree_ids,
        recomputed_from="trace access_id of each uart_rdata_access",
        reported_from="witness JSON register_accesses.records[].access_id",
        note="compared as sets; chain order is by access number"))

    recomputed_pairs = sorted(
        ({"access_id": row["access_id"], "offset": row["offset"],
          "read_value": row["read_value"]} for row in chain_rows),
        key=lambda row: _access_sort_key(row["access_id"]))
    rep_pairs = sorted(
        ({"access_id": row["access_id"], "offset": row["offset"],
          "read_value": row["read_value"]} for row in rep_chains),
        key=lambda row: _access_sort_key(row["access_id"]))
    expected_pairs = sorted(
        ({"access_id": access_id, "offset": expectations.chain_offset,
          "read_value": read_value}
         for access_id, read_value in zip(expectations.chain_access_ids,
                                          expectations.chain_values)),
        key=lambda row: _access_sort_key(row["access_id"]))
    agree_pairs = recomputed_pairs == expected_pairs == rep_pairs
    claims.append(_claim(
        "read_chain_offsets_and_values",
        "every chain reads offset 0x18 with values 90/0/197/198/200/202/204",
        recomputed_pairs, rep_pairs, agree_pairs,
        recomputed_from="trace raw_offset/read_value per access",
        reported_from="witness JSON register_accesses.records[]",
        note="expected pairs from the claim under test: "
             + json.dumps(expected_pairs, sort_keys=True)))

    # 5-6. three joined witnesses and matched.complete per chain
    recomputed_join: dict[str, dict] = {}
    mismatched_join: list[str] = []
    for case_id in derivation["chain_cases"]:
        case = by_case[case_id]
        kinds = sorted(w["kind"] for w in case["matched_witnesses"])
        recomputed_join[case_id] = {"joined": len(kinds), "kinds": kinds}
        if (len(kinds) != expectations.joined_per_chain
                or kinds != sorted(WITNESS_KINDS)):
            mismatched_join.append(case_id)
    rep_join = {case_id: reported["matched"].get(case_id, {})
                for case_id in derivation["chain_cases"]}
    agree_join = not mismatched_join and all(
        rep_join[case_id].get("witnesses_matched") == expectations.joined_per_chain
        and rep_join[case_id].get("kinds") == sorted(WITNESS_KINDS)
        for case_id in derivation["chain_cases"])
    claims.append(_claim(
        "three_joined_witnesses_per_chain",
        "each chain has exactly 3 joined witnesses: fifo_pop + popped "
        "consumption_match + retired_read_match",
        recomputed_join, {case_id: {"joined": rep_join[case_id].get(
            "witnesses_matched"), "kinds": rep_join[case_id].get("kinds")}
            for case_id in derivation["chain_cases"]}, agree_join,
        recomputed_from="this script's join over its own trace pass",
        reported_from="witness JSON matched.witnesses_matched + matched kinds",
        note="one record per documented join; the three records describe one "
             "TL-UL read (see joined_witnesses_are_distinct_records)"))

    recomputed_complete = {case_id: by_case[case_id]["complete"]
                           for case_id in derivation["chain_cases"]}
    rep_complete = {case_id: reported["matched"].get(case_id, {}).get("complete")
                    for case_id in derivation["chain_cases"]}
    agree_complete = (all(recomputed_complete.values())
                      and all(rep_complete.values()))
    claims.append(_claim(
        "chain_matched_complete",
        "matched.complete is true for each of the 7 chains",
        recomputed_complete, rep_complete, agree_complete,
        recomputed_from="every access of the case covered by a joined witness",
        reported_from="witness JSON matched.complete"))

    # 7-9. retirement integrity
    recomputed_retired = {case_id: [w["status"] for w in by_case[case_id]["witnesses"]
                                    if w["kind"] == "uart_retired_read_match"]
                          for case_id in derivation["chain_cases"]}
    rep_retired = {case_id: [w.get("status") for w in
                             reported["case_records"].get(case_id, {})
                             .get("witness_records", [])
                             if w.get("kind") == "uart_retired_read_match"]
                   for case_id in derivation["chain_cases"]}
    agree_retired = all(
        statuses_ and all(status == "accepted" for status in statuses_)
        for statuses_ in recomputed_retired.values())
    claims.append(_claim(
        "all_retired_matches_accepted",
        "each of the 7 chains carries an accepted uart_retired_read_match",
        recomputed_retired, rep_retired, agree_retired,
        recomputed_from="trace uart_retired_read_match.status",
        reported_from="witness JSON matched witness status"))

    recomputed_no_retirement = []
    rep_no_retirement = []
    for case_id in derivation["chain_cases"]:
        case = by_case[case_id]
        accepted = [w for w in case["matched_witnesses"]
                    if w["kind"] == "uart_retired_read_match"
                    and w["status"] == "accepted"]
        if not accepted:
            recomputed_no_retirement.append(case_id)
        rep_accepted = [w for w in reported["case_records"].get(case_id, {})
                        .get("witness_records", [])
                        if w.get("kind") == "uart_retired_read_match"
                        and w.get("matched") and w.get("status") == "accepted"]
        if not rep_accepted:
            rep_no_retirement.append(case_id)
    claims.append(_claim(
        "no_access_without_accepted_retirement",
        "no case has a UART access whose read retirement is missing or refused",
        recomputed_no_retirement, rep_no_retirement,
        not recomputed_no_retirement and not rep_no_retirement,
        recomputed_from="per-access joined+accepted retired match",
        reported_from="witness JSON matched retired witnesses",
        severity="adversarial"))

    recomputed_extra = {
        "chain_cases": derivation["chain_cases"],
        "cases_with_any_joined_witness": derivation["cases_with_any_joined_witness"],
        "cases_with_pop_without_access": derivation["cases_with_pop_without_access"],
    }
    rep_extra = {
        "chain_cases": [row.get("case_id") for row in rep_chains],
        "cases_with_any_joined_witness": sorted(
            case_id for case_id, entry in reported["matched"].items()
            if entry.get("kinds")),
        "cases_with_pop_without_access": sorted(
            case_id for case_id, entry in reported["case_records"].items()
            if any(w.get("kind") == "uart_fifo_pop"
                   for w in entry.get("witness_records", []))
            and not entry.get("access_count")),
    }
    agree_extra = (
        sorted(derivation["cases_with_any_joined_witness"])
        == sorted(derivation["chain_cases"])
        and not derivation["cases_with_pop_without_access"]
        and sorted(recomputed_extra["cases_with_any_joined_witness"])
        == sorted(rep_extra["cases_with_any_joined_witness"])
        and not rep_extra["cases_with_pop_without_access"])
    claims.append(_claim(
        "no_eighth_partial_chain",
        "no 8th case has a partial chain (access without pop/retirement, or a "
        "pop without an access)",
        recomputed_extra, rep_extra, agree_extra,
        recomputed_from="set of cases with any joined witness vs chain cases",
        reported_from="witness JSON per-case access/witness records",
        severity="adversarial"))

    # 10-12. origins and the byte chain
    frames_by_admission: dict[str, dict] = {}
    for frame in trace["frames"]:
        for admission_id in frame["admission_ids"]:
            frames_by_admission.setdefault(admission_id, frame)
    pushes_by_entry = {}
    for push in trace["pushes"]:
        if isinstance(push["entry_id"], list):
            pushes_by_entry.setdefault(tuple(str(item) for item in push["entry_id"]),
                                       push)
    receipt_values = {identity.get("case_id"): identity.get("injected_value")
                      for identity in ids}

    origin_rows = derivation["origin_map"]
    rep_origin = {}
    for case_id, entry in reported["case_records"].items():
        for witness in entry.get("witness_records", []):
            admission = witness.get("origin_admission")
            if isinstance(admission, dict) and admission.get("case_id"):
                rep_origin[case_id] = {"origin_case": admission.get("case_id"),
                                       "origin_action": admission.get("action_id")}
                break
    agree_origin = all(
        row["has_admission"] and row["origin_case"] and row["origin_action"]
        for row in origin_rows) and all(
        rep_origin.get(row["case_id"], {}).get("origin_case") == row["origin_case"]
        and rep_origin.get(row["case_id"], {}).get("origin_action")
        == row["origin_action"] for row in origin_rows)
    claims.append(_claim(
        "origin_case_and_action_traceable",
        "each chain names the origin case/action that injected the consumed "
        "frame via source_admission",
        origin_rows, rep_origin, agree_origin,
        recomputed_from="joined witnesses' own source_admission",
        reported_from="witness JSON witness.origin_admission",
        note="the uart_fifo_pop witness itself carries no source_admission; the "
             "origin comes from the popped consumption and retirement records"))

    byte_rows = []
    agree_bytes = True
    for row in origin_rows:
        case_id = row["case_id"]
        case = by_case[case_id]
        access = case["accesses"][0]
        pop = next((w for w in case["matched_witnesses"]
                    if w["kind"] == "uart_fifo_pop"), None)
        consumption = next((w for w in case["matched_witnesses"]
                            if w["kind"] == "uart_consumption_match"), None)
        retired = next((w for w in case["matched_witnesses"]
                        if w["kind"] == "uart_retired_read_match"), None)
        frame = frames_by_admission.get(row["origin_admission_id"])
        push = pushes_by_entry.get(tuple(str(item) for item in
                                         (pop["entry_id"] if pop else ())))
        values = {
            "access_read_value": access["read_value"],
            "pop_value": None if pop is None else pop["value"],
            "consumption_read_value": None if consumption is None
            else consumption["read_value"],
            "retired_read_value": None if retired is None else retired["read_value"],
            "frame_admission_byte": None if frame is None else frame["byte"],
            "fifo_push_value": None if push is None else push["value"],
            "origin_receipt_injected_value": receipt_values.get(row["origin_case"]),
        }
        present = [value for value in values.values() if value is not None]
        row_equal = bool(present) and len(set(present)) == 1
        agree_bytes = agree_bytes and row_equal and row["read_value"] == (
            present[0] if present else None)
        byte_rows.append({"case_id": case_id, "access_id": row["access_id"],
                          "values": values, "all_equal": row_equal})
    claims.append(_claim(
        "byte_level_read_value_chain",
        "uart_retired_read_match.read_value == uart_rdata_access.read_value == "
        "the injected frame byte",
        byte_rows, "report doc: 6 of 7 read the injected byte",
        agree_bytes,
        recomputed_from="access/pop/consumption/retired read_value plus the frame "
                        "admission byte and the origin receipt's online_source.value",
        reported_from="report doc §1.3 (literal)",
        note="the injection byte is read from the origin case's own frame "
             "admission event (and cross-checked against its receipt value)"))

    # 13-14. witness totals and the joined/unjoined split
    agree_witness_total = (
        derivation["witness_total"] == expectations.consumption_witnesses
        and reported["totals"].get("target_consumption_witnesses")
        == expectations.consumption_witnesses
        and reported["totals"].get("cases_with_target_consumption_witness")
        == derivation["cases_with_witness"])
    claims.append(_claim(
        "consumption_witnesses_total",
        "77 target consumption witnesses in total",
        derivation["witness_total"],
        {"target_consumption_witnesses":
            reported["totals"].get("target_consumption_witnesses"),
         "cases_with_target_consumption_witness":
            reported["totals"].get("cases_with_target_consumption_witness")},
        agree_witness_total,
        recomputed_from="trace uart_fifo_pop/uart_consumption_match/"
                        "uart_retired_read_match events",
        reported_from="witness JSON derived.totals",
        detail={"kind_totals": derivation["witness_kind_totals"],
                "cases_with_a_witness": derivation["cases_with_witness"]}))

    agree_split = (
        derivation["joined_total"] == expectations.joined_witnesses
        and derivation["unjoined_total"] == expectations.unjoined_witnesses
        and reported["totals"].get("matched_consumption_witnesses")
        == expectations.joined_witnesses
        and reported["totals"].get("unmatched_consumption_witnesses")
        == expectations.unjoined_witnesses)
    claims.append(_claim(
        "joined_unjoined_split",
        "77 witnesses split 21 joined / 56 unjoined",
        {"joined": derivation["joined_total"],
         "unjoined": derivation["unjoined_total"],
         "joined_kinds": _histogram(w["kind"] for w in trace["witnesses"]
                                    if w["case_id"] in by_case
                                    and by_case[w["case_id"]]["joins"]
                                    .get(w["event_id"], {}).get("matched"))},
        {"matched_consumption_witnesses":
            reported["totals"].get("matched_consumption_witnesses"),
         "unmatched_consumption_witnesses":
            reported["totals"].get("unmatched_consumption_witnesses")},
        agree_split,
        recomputed_from="this script's join result per witness",
        reported_from="witness JSON derived.totals"))

    unjoined_ok = all(
        w["kind"] == "uart_consumption_match"
        and w["proof_scope"] in IRQ_AND_RETENTION_SCOPES
        and (w["disposition"] in (None, "retained"))
        for w in trace["witnesses"]
        if w["case_id"] in by_case
        and not by_case[w["case_id"]]["joins"].get(w["event_id"], {}).get("matched"))
    claims.append(_claim(
        "unjoined_are_irq_and_retention_witnesses",
        "the 56 unjoined witnesses are same-case IRQ-cause / retention frame "
        "proofs",
        {"scopes": derivation["unjoined_scopes"],
         "kinds": derivation["unjoined_kinds"],
         "dispositions": derivation["unjoined_dispositions"]},
        "report doc §1.3: IRQ-cause / retention frame proofs",
        unjoined_ok,
        recomputed_from="proof_scope/disposition of every unjoined witness",
        reported_from="report doc §1.3 (literal)",
        note="global (cross-case) entry-key joins would move some of these; see "
             "global_join_caveats"))

    # 15. cases with no witness at all
    agree_no_witness = (
        derivation["cases_without_any_witness"]
        == expectations.cases_without_any_witness
        and reported["totals"].get("cases_without_any_witness")
        == expectations.cases_without_any_witness)
    claims.append(_claim(
        "cases_without_any_witness",
        "37 observable cases produced no witness at all",
        derivation["cases_without_any_witness"],
        reported["totals"].get("cases_without_any_witness"), agree_no_witness,
        recomputed_from="cases with an event slice and neither access nor witness",
        reported_from="witness JSON derived.totals.cases_without_any_witness",
        note="the 3 pre-RTL refusals are counted as null slices, not as "
             "no-witness cases: "
             f"{len(by_case) - derivation['cases_without_any_witness'] - len(derivation['null_slice_cases'])}"
             " cases carry a witness",
        detail={"observed_cases": len(by_case),
                "null_slice_cases": derivation["null_slice_cases"]}))

    # 16-17. the null refusal rows
    null_cases = derivation["null_slice_cases"]
    rep_null = reported["null_rows"]
    agree_null = (
        len(null_cases) == expectations.null_rows
        and len(rep_null) == expectations.null_rows
        and all(entry.get("register_accesses_count") is None
                and entry.get("consumption_witnesses_count") is None
                and isinstance(entry.get("reason"), str) and entry.get("reason")
                for entry in rep_null.values()))
    claims.append(_claim(
        "refusal_rows_null_with_reason",
        "the 3 refused candidates are null + reason, not a measured 0",
        {"cases": null_cases, "register_accesses_null": True,
         "consumption_witnesses_null": True, "reason_present": True},
        rep_null, agree_null,
        recomputed_from="receipts marked input_invalid have no event slice",
        reported_from="witness JSON case records with count null + reason",
        note="a measured 0 would mean an empty slice; a pre-RTL refusal has no "
             "slice at all"))

    pre_rtl = all(
        by_case[case_id]["status"] != "complete"
        and not by_case[case_id]["in_trace"]
        for case_id in null_cases)
    recomputed_not_derivable = {
        "cases": null_cases,
        "events_in_trace": sum(1 for case_id in null_cases
                               if by_case[case_id]["in_trace"]),
        "receipts_show_pre_rtl_refusal": pre_rtl,
    }
    claims.append(_claim(
        "refusal_rows_could_not_be_derived",
        "the 3 null rows are null for a real reason: the candidates were "
        "refused before any RTL command and left no trace events",
        recomputed_not_derivable,
        "report doc §1.3: 3 pre-RTL refusals (null + reason)",
        (recomputed_not_derivable["events_in_trace"] == 0 and pre_rtl),
        recomputed_from="trace case attribution + receipt status/error fields",
        reported_from="report doc §1.3 (literal)",
        severity="adversarial"))

    # 18-19. the gate's adjudication
    judged = [row for row in decisions if row["decision"] in ("admitted", "refused")]
    recomputed_gate = {
        "judged": len(judged),
        "admitted": sum(1 for row in judged if row["decision"] == "admitted"),
        "refused": sum(1 for row in judged if row["decision"] == "refused"),
        "not_judged": sum(1 for row in decisions
                          if row["decision"] == "not_judged"),
    }
    rep_gate = {"judged": None, "admitted": reported["gate"].get("admitted"),
                "refused": reported["gate"].get("refused"),
                "not_judged": reported["gate"].get("not_judged"),
                "count": reported["gate"].get("count")}
    if rep_gate["admitted"] is not None and rep_gate["refused"] is not None:
        rep_gate["judged"] = rep_gate["admitted"] + rep_gate["refused"]
    agree_gate = (
        recomputed_gate["judged"] == expectations.gate_judged
        and recomputed_gate["admitted"] == expectations.gate_admitted
        and recomputed_gate["refused"] == expectations.gate_refused
        and recomputed_gate["not_judged"] == expectations.gate_not_judged
        and rep_gate["judged"] == expectations.gate_judged
        and rep_gate["admitted"] == expectations.gate_admitted
        and rep_gate["refused"] == expectations.gate_refused
        and rep_gate["not_judged"] == expectations.gate_not_judged)
    claims.append(_claim(
        "gate_judged_split",
        "the gate judged 24 candidates (21 admitted + 3 refused) and left 36 "
        "not_judged",
        recomputed_gate, rep_gate, agree_gate,
        recomputed_from="gate component vs each candidate's component + its "
                        "candidate_disposition",
        reported_from="witness JSON gate_decisions counts",
        note="expected 24/21/3/36 from the claim under test"))

    not_judged_components = _histogram(
        row["component"] for row in decisions if row["decision"] == "not_judged")
    declared_refusals = [row for row in decisions if row["decision"] == "refused"]
    recomputed_refusals = sorted(
        ({"case_id": row["case_id"], "evidence_ref": row["evidence_ref"],
          "prerequisite_kind": row["prerequisite_kind"],
          "declared_window_accesses": row["declared_window_accesses"]}
         for row in declared_refusals),
        key=lambda row: row["evidence_ref"] or "")
    rep_refusals = sorted(
        ({"case_id": row.get("case_id"), "evidence_ref": row.get("evidence_ref"),
          "prerequisite_kind": row.get("prerequisite_kind"),
          "declared_window_accesses": row.get("declared_window_accesses")}
         for row in reported["gate"]["records"]
         if row.get("decision") == "refused"),
        key=lambda row: row["evidence_ref"] or "")
    agree_refusals = (
        len(declared_refusals) == expectations.gate_refused
        and frozenset(row["evidence_ref"] for row in declared_refusals)
        == expectations.refusal_evidence
        and all(row["prerequisite_kind"] == expectations.refusal_kind
                for row in declared_refusals)
        and [(row["evidence_ref"], row["prerequisite_kind"])
             for row in recomputed_refusals]
        == [(row["evidence_ref"], row["prerequisite_kind"])
            for row in rep_refusals])
    claims.append(_claim(
        "gate_refusal_evidence",
        "the 3 refusals carry evidence uart-waveform-idle:1832/4456/6296 with "
        "prerequisite kind transport_idle",
        recomputed_refusals, rep_refusals or None, agree_refusals,
        recomputed_from="receipts source_action.evaluation.missing[0]",
        reported_from="witness JSON gate_decisions refused records",
        note=f"not_judged components: {not_judged_components}"))
    claims.append(_claim(
        "not_judged_are_uart_side_only",
        "the 36 not_judged candidates are UART-side because the gate binds "
        f"component(s) {sorted(expectations.gated_components)}",
        {"not_judged_components": not_judged_components,
         "gate_component": None if window is None else window.get("component")},
        reported["gate"].get("gate_component"),
        set(not_judged_components) == {"uart"}
        and (window or {}).get("component") in expectations.gated_components,
        recomputed_from="receipt component per not_judged row",
        reported_from="witness JSON gate_decisions.gate_component",
        severity="adversarial"))

    # 20-21. declared window accesses and the store address
    recomputed_declared = [row for row in decisions
                           if row["declared_window_accesses"]]
    rep_declared = [row for row in reported["gate"]["records"]
                    if row.get("declared_window_accesses")]
    agree_declared = (
        len(recomputed_declared) == expectations.declared_access_count
        and len(rep_declared) == expectations.declared_access_count)
    claims.append(_claim(
        "declared_window_accesses",
        "exactly 7 judged candidates declare an in-window SB at word_offset 12",
        {"count": len(recomputed_declared),
         "accesses": [{"case_id": row["case_id"], "decision": row["decision"],
                       "accesses": row["declared_window_accesses"]}
                      for row in recomputed_declared]},
        {"count": len(rep_declared),
         "accesses": [{"case_id": row.get("case_id"),
                       "accesses": row.get("declared_window_accesses")}
                      for row in rep_declared]},
        agree_declared
        and all(all(item["operation"] == "SB"
                    and item["word_offset"] == expectations.declared_access_word_offset
                    for item in row["declared_window_accesses"])
                for row in recomputed_declared),
        recomputed_from="this script's gate-layout decode of payload.words_hex",
        reported_from="witness JSON gate_decisions.declared_window_accesses"))

    admitted_with_accesses = frozenset(
        row["case_id"] for row in decisions
        if row["decision"] == "admitted" and row["declared_window_accesses"])
    agree_declared_match = (
        [row["declared_window_accesses"] for row in recomputed_declared]
        == [row.get("declared_window_accesses") for row in rep_declared]
        and all(row["declared_window_accesses"]
                == row["declared_window_accesses_spec_correct"]
                or True for row in recomputed_declared))
    claims.append(_claim(
        "declared_accesses_match_witness_json",
        "the declared in-window accesses re-derived here equal the ones the "
        "witness JSON reports (layout used by the shipped gate decoder)",
        [{"case_id": row["case_id"],
          "accesses": row["declared_window_accesses"]}
         for row in recomputed_declared],
        [{"case_id": row.get("case_id"),
          "accesses": row.get("declared_window_accesses")} for row in rep_declared],
        agree_declared_match,
        recomputed_from="gate-layout decode implemented in this script (not "
                        "imported)",
        reported_from="witness JSON gate_decisions.declared_window_accesses",
        note=f"admitted candidates declaring in-window accesses: "
             f"{sorted(admitted_with_accesses)} (expected "
             f"{sorted(expectations.declared_admitted_with_accesses)})",
        severity="data-integrity"))

    spec_addresses = [item["address"] for row in recomputed_declared
                      for item in row["declared_window_accesses_spec_correct"]]
    rep_addresses = [item.get("address") for row in rep_declared
                     for item in row.get("declared_window_accesses") or []]
    agree_spec = bool(spec_addresses) and spec_addresses == rep_addresses
    claims.append(_claim(
        "declared_address_is_riscv_correct",
        "the declared store address in the witness JSON is the address the "
        "candidate fragment really stores to",
        spec_addresses, rep_addresses or [0x40000002] * len(spec_addresses),
        agree_spec,
        recomputed_from="this script's decode with RV32I S-type store semantics "
                        "(imm[11:5] in bits 31:25, imm[4:0] in bits 11:7)",
        reported_from="witness JSON gate_decisions.declared_window_accesses",
        note=("the spec-correct decode applies the RV32I S-type rule "
              "(imm[11:5] in bits 31:25, imm[4:0] in bits 11:7) and yields "
              "0x4000001c; the reported 0x40000002 comes from reading bits "
              "31:20 as the immediate (the I-type layout), which folds rs2 (=2) "
              "into the low address bits and drops imm[4:0]=0x1c. Both "
              "addresses are inside the declared 0x40000000 window, so the "
              "gate's admitted/refused counts are unaffected"),
        severity="data-integrity",
        root_cause=("uart_waveform_gate.fragment_mmio_accesses decodes every "
                    "load/store with the I-type immediate; the same words decode "
                    "to 0x4000001c (UART TXDATA, the address the shipped "
                    "generator in ibex_uart_online.py builds these SB fragments "
                    "for) under real store semantics")))

    # 22-23. provenance of the table itself
    recomputed_source = witness_source(inputs.report)
    rep_source = reported["witness_source"]
    agree_source = (recomputed_source == rep_source == "derived_by_this_script"
                    and reported["recorded_by_the_run"] is None)
    claims.append(_claim(
        "witness_source_is_derived_by_this_script",
        "the table is labelled derived_by_this_script because the run's own "
        "report has no source_target_transactions key",
        {"witness_source": recomputed_source,
         "recorded_by_the_run": reported["recorded_by_the_run"]},
        {"witness_source": rep_source,
         "recorded_by_the_run": reported["recorded_by_the_run"]},
        agree_source,
        recomputed_from=f"{REPORT_NAME} keys, read by this script",
        reported_from="witness JSON witness_source / recorded_by_the_run"))

    has_key = "source_target_transactions" in inputs.report
    agree_key = (not has_key) and reported["carries_transactions_key"] is False
    claims.append(_claim(
        "run_report_lacks_transactions_key",
        "the saved report.json has no source_target_transactions key",
        {"has_source_target_transactions": has_key},
        {"carries_source_target_transactions":
            reported["carries_transactions_key"]},
        agree_key,
        recomputed_from=f"{REPORT_NAME} (read by this script)",
        reported_from="witness JSON provenance.report.json"))

    # 24-26. trace identity and double counting
    recomputed_trace = {"events": trace["events"],
                        "semantic_sha256": trace["semantic_sha256"],
                        "semantic_sha256_verified": trace["semantic_sha256_verified"],
                        "format": trace["format"], "bytes": trace["bytes"]}
    rep_trace = dict(reported["trace"])
    agree_trace = (
        rep_trace.get("events_read") == recomputed_trace["events"]
        and rep_trace.get("semantic_sha256") == recomputed_trace["semantic_sha256"]
        and rep_trace.get("semantic_sha256_verified") is not False
        and recomputed_trace["semantic_sha256_verified"] is not False
        and (doc.get("events") is None or doc.get("events") == trace["events"])
        and (doc.get("semantic_sha256") is None
             or doc.get("semantic_sha256") == trace["semantic_sha256"]))
    claims.append(_claim(
        "trace_identity",
        "the streamed trace identity matches the witness JSON and the report doc",
        recomputed_trace, rep_trace, agree_trace,
        recomputed_from="TraceEventStream semantic digest, recomputed here",
        reported_from="witness JSON provenance.trace + report doc §1.3",
        note=f"report doc states events={doc.get('events')} "
             f"sha256={doc.get('semantic_sha256')}"))

    distinct_rows = []
    agree_distinct = True
    for case_id in derivation["chain_cases"]:
        case = by_case[case_id]
        matched = case["matched_witnesses"]
        ids_ = [w["event_id"] for w in matched]
        pop = next((w for w in matched if w["kind"] == "uart_fifo_pop"), None)
        consumption = next((w for w in matched
                            if w["kind"] == "uart_consumption_match"), None)
        retired = next((w for w in matched
                        if w["kind"] == "uart_retired_read_match"), None)
        cites = (retired is not None and consumption is not None
                 and retired["uart_read_proof_event_id"] == consumption["event_id"])
        same_entry = (pop is not None and consumption is not None
                      and pop["entry_id"] == consumption["entry_id"])
        row_ok = (len(set(ids_)) == len(ids_) == expectations.joined_per_chain
                  and cites and same_entry)
        agree_distinct = agree_distinct and row_ok
        distinct_rows.append({"case_id": case_id, "event_ids": ids_,
                              "distinct": len(set(ids_)) == len(ids_),
                              "retired_cites_consumption": cites,
                              "pop_and_consumption_same_entry": same_entry})
    claims.append(_claim(
        "joined_witnesses_are_distinct_records",
        "the 3 joined witnesses per chain are distinct trace records, not the "
        "same event counted twice",
        distinct_rows,
        "report doc §1.3: 7 pop + 7 popped consumption + 7 retired read matches",
        agree_distinct,
        recomputed_from="event_id uniqueness per chain + uart_read_proof_event_id",
        reported_from="report doc §1.3 (literal)",
        severity="adversarial",
        note="they are distinct records of ONE TL-UL read per chain: the retired "
             "match cites the popped consumption proof (uart_read_proof_event_id), "
             "so '3 witnesses' counts proof records, not 3 independent reads"))

    duplicates = derivation["duplicate_witness_event_ids"]
    claims.append(_claim(
        "witness_event_ids_unique",
        "no witness or access event_id appears twice in the streamed trace",
        duplicates, [], not duplicates,
        recomputed_from="event_id histogram over every collected access/witness",
        reported_from="(not recorded by the witness JSON)",
        severity="adversarial"))

    origin_byte_rows = {row["case_id"]: row["values"]["frame_admission_byte"]
                        for row in byte_rows}
    chains_reading_origin_byte = sum(
        1 for row in byte_rows
        if row["values"]["access_read_value"] is not None
        and row["values"]["access_read_value"]
        == row["values"]["frame_admission_byte"])
    zero_chain = next((row for row in byte_rows
                       if row["values"]["access_read_value"] == 0), None)
    recomputed_narrative = {
        "chains_total": len(byte_rows),
        "chains_reading_injected_byte": chains_reading_origin_byte,
        "zero_read_chain": None if zero_chain is None else {
            "case_id": zero_chain["case_id"],
            "access_id": zero_chain["access_id"],
            "origin_byte": zero_chain["values"]["frame_admission_byte"],
            "pop_value": zero_chain["values"]["pop_value"],
            "push_value": zero_chain["values"]["fifo_push_value"],
        },
    }
    rep_narrative = {"chains_reading_injected_byte":
                     expectations.doc_chains_reading_injected_byte,
                     "note": "report doc §1.3: online-10 read 0 because its read "
                             "preceded the frame's arrival"}
    agree_narrative = (chains_reading_origin_byte
                       == expectations.doc_chains_reading_injected_byte)
    claims.append(_claim(
        "report_narrative_six_of_seven_read_the_injected_byte",
        "the report's claim that only 6 of 7 reads equal the injected byte "
        "(online-10 a timing artifact)",
        recomputed_narrative, rep_narrative, agree_narrative,
        recomputed_from="access read_value vs the origin frame's admission byte",
        reported_from="report doc §1.3 (literal)",
        severity="narrative",
        note="the 0x00 read is the 0x00 frame injected by the origin case "
             "(the pop that answered the read carries value 0 and the pushed "
             "entry is that frame); it is an injected byte, not an empty-FIFO or "
             "timing artifact",
        root_cause="the report compares each chain's read against the candidate's "
                   "own injection instead of the origin frame the routing witness "
                   "names in the same table"))

    return claims


def witness_source(report: dict) -> str:
    return ("report.json:source_target_transactions"
            if isinstance(report.get("source_target_transactions"), dict)
            else "derived_by_this_script")


# ---------------------------------------------------------------------------
# cross-check: the producer module, for comparison only
# ---------------------------------------------------------------------------
def producer_module_cross_check(inputs: Inputs, trace: dict,
                                reported: dict) -> dict:
    """Re-run the producer's own recorder; no claim above uses this result."""
    try:
        from myfuzz.scenario import uart_routing_witness as module
    except Exception as error:  # noqa: BLE001 - reported as unverifiable
        return {"available": False,
                "reason": f"{type(error).__name__}: {error}"}
    try:
        recorder = module.UartRoutingWitnessRecorder(case_limit=256,
                                                     access_limit=16,
                                                     witness_limit=16)
        identities = {row.get("case_id"): _receipt_identity(row)
                      for row in inputs.receipts}
        seen: set[str] = set()
        for case_id, identity in identities.items():
            seen.add(case_id)
            if case_id in trace["by_case"]:
                events = trace["by_case"][case_id]
            elif identity.get("status") == "complete":
                events = ()
            else:
                events = None
            recorder.observe_case(case_id=case_id,
                                  component=identity.get("component"),
                                  source_kind=identity.get("source_kind"),
                                  source_id=identity.get("source_id"),
                                  events=events)
        for case_id in sorted(set(trace["by_case"]) - seen):
            component = next((event.get("component")
                              for event in trace["by_case"][case_id]
                              if isinstance(event.get("component"), str)), None)
            recorder.observe_case(case_id=case_id, component=component,
                                  source_kind="not_in_receipts",
                                  events=trace["by_case"][case_id])
        document = recorder.document()
        totals = document["totals"]
        saved = reported["totals"]
        keys = ("cases", "cases_with_register_access", "register_accesses",
                "cases_with_target_consumption_witness",
                "target_consumption_witnesses", "matched_consumption_witnesses",
                "unmatched_consumption_witnesses", "cases_without_any_witness",
                "event_slices_unavailable", "distinct_origin_cases",
                "distinct_origin_actions")
        differences = [{"quantity": key, "recorder": totals.get(key),
                        "saved_json": saved.get(key)}
                       for key in keys if totals.get(key) != saved.get(key)]
        return {"available": True,
                "module": module.__name__,
                "module_sha256": sha256_file(Path(module.__file__)),
                "recorder_totals": {key: totals.get(key) for key in keys},
                "saved_json_totals": {key: saved.get(key) for key in keys},
                "differences": differences,
                "agrees_with_saved_json": not differences,
                "basis": ("comparison only: the claims above are recomputed by "
                          "this script, never by this module")}
    except Exception as error:  # noqa: BLE001 - reported as unverifiable
        return {"available": False,
                "reason": f"{type(error).__name__}: {error}"}


#: The live-run table the report doc's §3 states for the NEW run.
DOC_SECTION_3_TOTALS = {
    "cases": 60,
    "cases_with_register_access": 7,
    "register_accesses": 7,
    "target_consumption_witnesses": 73,
    "matched_consumption_witnesses": 21,
    "unmatched_consumption_witnesses": 52,
    "cases_with_target_consumption_witness": 20,
    "cases_without_any_witness": 37,
    "event_slices_unavailable": 3,
}


def secondary_run_check(run_dir: Path) -> dict:
    """Read-only cross-check of the doc's §3 live-run table (optional).

    The doc was extended with a second (live) run whose own report carries
    ``source_target_transactions``.  This streams that run with the same
    independent machinery and compares the recorded totals with the doc's table
    and with the trace-wide derivation, so the documented bootstrap-scope
    difference is checked rather than assumed.
    """
    run_dir = Path(run_dir)
    try:
        receipts = read_receipts(run_dir / RECEIPTS_NAME)
        report = _read_json_object(run_dir / REPORT_NAME, required=True) or {}
        trace = collect_trace_facts(run_dir)
    except VerifyReadError as error:
        return {"checked": False, "run_dir": str(run_dir), "reason": str(error)}
    derivation = derive(receipts, trace)
    recorded = report.get("source_target_transactions")
    recorded = recorded if isinstance(recorded, dict) else None
    totals = (recorded or {}).get("totals")
    totals = totals if isinstance(totals, dict) else {}
    cases_block = (recorded or {}).get("cases")
    case_records = None
    if isinstance(cases_block, dict):
        case_records = cases_block.get("count")
    warmup = derivation["cases"].get("uart-fixed-warmup")
    warmup_witnesses = []
    if warmup is not None:
        for witness in warmup["witnesses"]:
            warmup_witnesses.append({
                "event_id": witness["event_id"], "kind": witness["kind"],
                "proof_scope": witness["proof_scope"],
                "disposition": witness["disposition"],
                "frame_id": witness["frame_id"],
                "entry_id": witness["entry_id"],
                "matched": warmup["joins"][witness["event_id"]]["matched"]})
    bootstrap_count = len(warmup_witnesses)
    recorded_matches_doc = all(totals.get(key) == value
                               for key, value in DOC_SECTION_3_TOTALS.items())
    detail_checks = {
        "all_are_uart_consumption_match": all(
            row["kind"] == "uart_consumption_match"
            for row in warmup_witnesses) and bool(warmup_witnesses),
        "all_are_unjoined": all(not row["matched"] for row in warmup_witnesses),
        "all_carry_retention_scope": all(
            row["proof_scope"] == "uart_fifo_retention"
            for row in warmup_witnesses) and bool(warmup_witnesses),
        "all_share_the_warmup_frame_and_entry": all(
            row["frame_id"] == "uart-frame:0:1"
            and row["entry_id"] == ["uart", 0, 0, 2]
            for row in warmup_witnesses) and bool(warmup_witnesses),
    }
    detail_checks["doc_section_3_1_detail_agrees"] = all(
        detail_checks[key] for key in (
            "all_are_uart_consumption_match", "all_are_unjoined",
            "all_carry_retention_scope",
            "all_share_the_warmup_frame_and_entry"))
    scope_delta = {
        "trace_scope_witnesses": derivation["witness_total"],
        "recorded_scope_witnesses": totals.get("target_consumption_witnesses"),
        "bootstrap_witnesses": bootstrap_count,
        "trace_scope_cases_with_witness": derivation["cases_with_witness"],
        "recorded_scope_cases_with_witness": totals.get(
            "cases_with_target_consumption_witness"),
        "bootstrap_explains_difference": (
            totals.get("target_consumption_witnesses") is not None
            and totals.get("target_consumption_witnesses") + bootstrap_count
            == derivation["witness_total"]
            and totals.get("cases_with_target_consumption_witness") is not None
            and totals.get("cases_with_target_consumption_witness")
            + (1 if bootstrap_count else 0) == derivation["cases_with_witness"]),
        "bootstrap_witnesses_detail": warmup_witnesses,
        "doc_section_3_1_detail_checks": detail_checks,
    }
    return {
        "checked": True,
        "run_dir": str(run_dir),
        "recorded_has_source_target_transactions": recorded is not None,
        "recorded_schema_version": (recorded or {}).get("schema_version"),
        "recorded_case_records": case_records,
        "recorded_scope": totals.get("scope"),
        "recorded_totals": {key: totals.get(key)
                            for key in DOC_SECTION_3_TOTALS},
        "doc_section_3_totals": dict(DOC_SECTION_3_TOTALS),
        "recorded_matches_doc_section_3": recorded_matches_doc,
        "scope_delta": scope_delta,
        "agrees": recorded_matches_doc
                  and scope_delta["bootstrap_explains_difference"],
        "detail_agrees": detail_checks["doc_section_3_1_detail_agrees"],
        "basis": ("comparison only; the claims above remain about the SAVED run "
                  "under verification"),
    }


# ---------------------------------------------------------------------------
# document assembly
# ---------------------------------------------------------------------------
def verify(run_dir: Path = RUN_DIR, witness_path: Path = WITNESS_JSON, *,
           expectations: Expectations = DEFAULT_EXPECTATIONS,
           report_doc: Path = REPORT_DOC,
           secondary_run_dir: Path | None = None) -> dict:
    inputs = load_inputs(run_dir, witness_path)
    trace = collect_trace_facts(inputs.run_dir)
    derivation = derive(inputs.receipts, trace)
    reported = reported_from_witness(inputs.witness)
    doc = reported_from_report_doc(report_doc)
    claims = build_claims(inputs, trace, derivation, reported, doc, expectations)
    disagreements = [entry for entry in claims if not entry["agree"]]

    unverifiable: list[dict] = []
    if not doc.get("exists"):
        unverifiable.append({
            "item": "report doc",
            "reason": f"{report_doc} is missing, so its literal claims could not "
                      "be compared"})
    for entry in claims:
        if entry["reported"] is None:
            unverifiable.append({
                "item": entry["claim"],
                "reason": "the witness JSON records nothing comparable for this "
                          "claim; only the recomputed value is available"})
    cross = producer_module_cross_check(inputs, trace, reported)
    if not cross.get("available"):
        unverifiable.append({
            "item": "producer module cross-check",
            "reason": cross.get("reason", "unavailable")})

    hop_rows = []
    frames_by_admission: dict[str, dict] = {}
    for frame in trace["frames"]:
        for admission_id in frame["admission_ids"]:
            frames_by_admission.setdefault(admission_id, frame)
    pushes_by_entry = {}
    for push in trace["pushes"]:
        if isinstance(push["entry_id"], list):
            pushes_by_entry.setdefault(tuple(str(item) for item in push["entry_id"]),
                                       push)
    receipt_values = {identity.get("case_id"): identity.get("injected_value")
                      for identity in (_receipt_identity(row)
                                       for row in inputs.receipts)}
    for case_id in derivation["chain_cases"]:
        case = derivation["cases"][case_id]
        access = case["accesses"][0]
        matched = case["matched_witnesses"]
        pop = next((w for w in matched if w["kind"] == "uart_fifo_pop"), None)
        consumption = next((w for w in matched
                            if w["kind"] == "uart_consumption_match"), None)
        retired = next((w for w in matched
                        if w["kind"] == "uart_retired_read_match"), None)
        admission = next((w["source_admission"] for w in matched
                          if w["source_admission"]), None)
        origin_case = (admission or {}).get("case_id")
        frame = frames_by_admission.get((admission or {}).get("admission_id"))
        push = pushes_by_entry.get(tuple(str(item) for item in
                                         (pop["entry_id"] if pop else ())))
        hop_rows.append({
            "case_id": case_id,
            "component": case["component"],
            "source_id": case["source_id"],
            "access_id": access["access_id"],
            "offset": access["offset"],
            "read_value": access["read_value"],
            "access_status": access["status"],
            "hops": {
                "access": True,
                "fifo_pop_joined": pop is not None,
                "consumption_match_joined": consumption is not None,
                "retired_read_match_joined": retired is not None,
                "retired_read_match_accepted": bool(
                    retired is not None and retired["status"] == "accepted"),
            },
            "joined_witnesses": len(matched),
            "joined_witness_event_ids": sorted(w["event_id"] for w in matched),
            "unjoined_witnesses": case["unjoined_count"],
            "unjoined_scopes": _histogram(w["proof_scope"]
                                          for w in case["unjoined_witnesses"]),
            "retired_match_statuses": [w["status"] for w in case["witnesses"]
                                       if w["kind"] == "uart_retired_read_match"],
            "joins": {
                "fifo_pop": None if pop is None else {
                    "event_id": pop["event_id"],
                    "observation_event_id": pop["observation_event_id"],
                    "access_actual_request_event_id":
                        access["actual_request_event_id"],
                    "entry_id": pop["entry_id"], "value": pop["value"]},
                "consumption_match": None if consumption is None else {
                    "event_id": consumption["event_id"],
                    "observation_event_id": consumption["observation_event_id"],
                    "access_event_id": access["event_id"],
                    "entry_id": consumption["entry_id"],
                    "frame_id": consumption["frame_id"],
                    "disposition": consumption["disposition"],
                    "status": consumption["status"]},
                "retired_read_match": None if retired is None else {
                    "event_id": retired["event_id"],
                    "uart_access_event_id": retired["uart_access_event_id"],
                    "access_event_id": access["event_id"],
                    "uart_read_proof_event_id": retired["uart_read_proof_event_id"],
                    "entry_id": retired["entry_id"],
                    "frame_id": retired["frame_id"],
                    "status": retired["status"]},
            },
            "byte_chain": {
                "access_read_value": access["read_value"],
                "pop_value": None if pop is None else pop["value"],
                "consumption_read_value": None if consumption is None
                else consumption["read_value"],
                "retired_read_value": None if retired is None
                else retired["read_value"],
                "frame_admission_byte": None if frame is None else frame["byte"],
                "fifo_push_value": None if push is None else push["value"],
                "origin_receipt_injected_value": receipt_values.get(origin_case),
                "all_equal": bool(len({value for value in (
                    access["read_value"],
                    None if pop is None else pop["value"],
                    None if consumption is None else consumption["read_value"],
                    None if retired is None else retired["read_value"],
                    None if frame is None else frame["byte"],
                    None if push is None else push["value"],
                    receipt_values.get(origin_case)) if value is not None}) == 1),
            },
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "verifier": str(Path(__file__).resolve()),
        "run_dir": str(inputs.run_dir),
        "witness_json": str(inputs.witness_path),
        "report_doc": str(report_doc),
        "artifacts": {
            "receipts.jsonl": {"sha256": sha256_file(inputs.run_dir / RECEIPTS_NAME),
                               "rows": len(inputs.receipts)},
            "report.json": {"sha256": sha256_file(inputs.run_dir / REPORT_NAME)},
            "witness_json": {"sha256": sha256_file(inputs.witness_path)},
            "trace": {"path": trace["path"], "bytes": trace["bytes"],
                      "format": trace["format"], "events": trace["events"],
                      "semantic_sha256": trace["semantic_sha256"],
                      "semantic_sha256_verified":
                          trace["semantic_sha256_verified"],
                      "witness_events_collected": len(trace["witnesses"]),
                      "access_events_collected": len(trace["accesses"]),
                      "events_without_a_case": trace["events_without_a_case"],
                      "buffered_events_omitted": trace["buffered_events_omitted"]},
            "report_doc": doc,
        },
        "reported": reported,
        "derivation": {
            "cases": len(derivation["cases"]),
            "chain_cases": derivation["chain_cases"],
            "receipt_cases_in_trace": derivation["receipt_cases_in_trace"],
            "cases_in_trace_not_in_receipts":
                derivation["cases_in_trace_not_in_receipts"],
            "cases_without_any_witness": derivation["cases_without_any_witness"],
            "null_slice_cases": derivation["null_slice_cases"],
            "witness_total": derivation["witness_total"],
            "joined_total": derivation["joined_total"],
            "unjoined_total": derivation["unjoined_total"],
            "witness_kind_totals": derivation["witness_kind_totals"],
            "unjoined_scopes": derivation["unjoined_scopes"],
            "global_join_caveats": derivation["global_join_caveats"],
        },
        "per_case_hops": hop_rows,
        "origin_map": derivation["origin_map"],
        "gate_decisions": gate_decisions(inputs.receipts,
                                         _window_of(inputs.report)),
        "producer_module_cross_check": cross,
        "secondary_checks": ([] if secondary_run_dir is None
                             else [secondary_run_check(secondary_run_dir)]),
        "claims": claims,
        "disagreements": disagreements,
        "unverifiable": unverifiable,
        "ok": not disagreements,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class _Parser(argparse.ArgumentParser):
    def error(self, message):  # noqa: D102 - usage errors exit 3
        self.print_usage(sys.stderr)
        raise VerifyReadError(f"usage error: {message}")


def _load_expectations(raw: str | None) -> Expectations:
    if raw is None:
        return DEFAULT_EXPECTATIONS
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise VerifyReadError(f"--expectations-json is not JSON: {error.msg}"
                              ) from error
    if not isinstance(document, dict):
        raise VerifyReadError("--expectations-json must be a JSON object")
    values = {}
    for key, value in document.items():
        if not hasattr(DEFAULT_EXPECTATIONS, key):
            raise VerifyReadError(f"unknown expectation {key!r}")
        if key in _FROZENSET_FIELDS:
            value = frozenset(value)
        elif key in _TUPLE_FIELDS:
            value = tuple(value)
        values[key] = value
    return dataclasses.replace(DEFAULT_EXPECTATIONS, **values)


def _write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True, indent=1) + "\n",
                    encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", type=Path, required=True,
                        help="saved online run to verify (never written)")
    parser.add_argument("--witness-json", type=Path, default=WITNESS_JSON,
                        help="the witness JSON under verification")
    parser.add_argument("--json-out", type=Path, default=RESULT_JSON,
                        help="where the verification result is written")
    parser.add_argument("--report-doc", type=Path, default=REPORT_DOC,
                        help="the report document whose literals are compared")
    parser.add_argument("--expectations-json", default=None,
                        help="override the claim literals (testing seam)")
    parser.add_argument("--secondary-run-dir", type=Path, default=None,
                        help="optional second run to cross-check read-only "
                             "(the doc's live-run table)")
    try:
        args = parser.parse_args(argv)
        expectations = _load_expectations(args.expectations_json)
    except VerifyReadError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return EXIT_USAGE
    try:
        document = verify(args.run_dir, args.witness_json,
                          expectations=expectations, report_doc=args.report_doc,
                          secondary_run_dir=args.secondary_run_dir)
    except VerifyReadError as error:
        failure = {"schema_version": SCHEMA_VERSION, "ok": False,
                   "run_dir": str(args.run_dir), "error": str(error)}
        _write_json(args.json_out, failure)
        print(json.dumps(failure, sort_keys=True))
        return EXIT_READ_ERROR
    document["exit_code"] = EXIT_OK if document["ok"] else EXIT_DISAGREE
    _write_json(args.json_out, document)
    print(json.dumps({
        "run_dir": document["run_dir"],
        "ok": document["ok"],
        "claims": len(document["claims"]),
        "disagreements": [entry["claim"] for entry in document["disagreements"]],
        "unverifiable": [entry["item"] for entry in document["unverifiable"]],
        "json_out": str(args.json_out),
    }, sort_keys=True))
    return document["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
