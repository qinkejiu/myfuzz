#!/usr/bin/env python3
"""Report the ISR GPIO A writeback endpoint of one saved run as JSON.

One streaming pass over the run's saved terminal trace with bounded readers
(:class:`myfuzz.scenario.acceptance_metrics.TraceEventStream`) feeds two
independent consumers:

* the shipped, unmodified :class:`myfuzz.scenario.chain_certificates.ChainCertificates`
  producer, whose certified chains are re-read read-only, and
* the additive :class:`myfuzz.scenario.isr_writeback_certificate.IsrWritebackCertificates`
  consumer, which certifies the handler's own GPIO A ``PADOUT`` write and the
  A->B reflow it drives by exact identity.

No RTL, no fuzz job, no mutation of any existing certificate or verdict. The
report answers, per run, the question the P5 boundary leaves open: can a
certified chain be extended to the ISR's write back to GPIO A by an exact
identity? ``chains_extended`` is the count that did; ``join_attempts`` carries
every candidate key with its relation (``exact``, ``mismatch``, ``absent``,
``adjacency_only``, ``classification_only``) and ``missing_identity`` names the
single absent field.

Exit codes:

``0``
    the report was produced. ``--require-extension`` is off.
``1``
    the run holds no streamable trace, its artifacts contradict the frozen hop
    contract, or ``--require-extension`` was set and no chain could be extended.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.acceptance_metrics import (  # noqa: E402
    TraceEventStream,
    TraceUnavailable,
)
from myfuzz.scenario.chain_certificates import (  # noqa: E402
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    ChainCertificates,
)
from myfuzz.scenario.isr_writeback_certificate import (  # noqa: E402
    HANDLER_HOP_SEQUENCE,
    NOT_PROOF_OF,
    PROOF_SCOPE,
    IsrWritebackCertificates,
    audit_chain_extension,
    declared_handler_hop_sequence,
    missing_chain_extension_identity,
)


REPORT_SCHEMA = "isr_writeback_run_report.v1"
DEFAULT_RUN_DIR = ("runs/current-dataflow-p5-chain-600s-20261007-online")
DEFAULT_HANDLER_IMAGE_ID = "cpu.stream.isr"


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-dir", type=Path, default=Path(DEFAULT_RUN_DIR),
                        help="saved run directory holding a streamable trace")
    parser.add_argument("--output", type=Path, default=None,
                        help="write the same JSON report to this path")
    parser.add_argument("--handler-image-id", default=DEFAULT_HANDLER_IMAGE_ID,
                        help="initial_image id whose span classifies the "
                             "handler writer (observation, never a join)")
    parser.add_argument("--handler-span", default=None,
                        help="explicit ADDRESS:LENGTH handler span override")
    parser.add_argument("--max-pending", type=int, default=128)
    parser.add_argument("--max-event-gap", type=int, default=4096)
    parser.add_argument("--max-writebacks", type=int, default=256)
    parser.add_argument("--max-audits", type=int, default=64,
                        help="per-run cap on retained chain audits")
    parser.add_argument("--require-extension", action="store_true",
                        help="exit 1 when no certified chain could be extended")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the JSON report, no stderr summary")


def _span(value: str) -> tuple[int, int]:
    address, _, length = value.partition(":")
    try:
        parsed = (int(address, 0), int(length, 0))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"handler span must be ADDRESS:LENGTH, got {value!r}") from exc
    if parsed[1] < 1:
        raise argparse.ArgumentTypeError("handler span length must be positive")
    return parsed


def _chain_counts(certificates) -> dict:
    certified: Counter = Counter()
    total: Counter = Counter()
    statuses: Counter = Counter()
    for certificate in certificates:
        direction = certificate.get("direction")
        key = (direction if direction in (CPU_TO_IP_TO_CPU, IP_TO_CPU_TO_IP)
               else "other")
        total[key] += 1
        if certificate.get("status") == "certified":
            certified[key] += 1
        statuses[certificate.get("status")] += 1
    return {"certified_by_direction": dict(certified),
            "total_by_direction": dict(total), "by_status": dict(statuses),
            "certified_total": sum(certified.values()),
            "total": len(certificates)}


def _writeback_summary(certificates) -> dict:
    by_status: Counter = Counter()
    by_first_missing: Counter = Counter()
    by_reason: Counter = Counter()
    for certificate in certificates:
        by_status[certificate["status"]] += 1
        by_reason[certificate.get("settled_reason")] += 1
        missing = certificate.get("missing_hops") or []
        if missing:
            by_first_missing[missing[0]] += 1
    return {"total": len(certificates), "by_status": dict(by_status),
            "by_settled_reason": dict(by_reason),
            "first_missing_hop_counts": dict(by_first_missing),
            "declared_hop_sequence": list(declared_handler_hop_sequence())}


def build_report(run_dir: Path, *, handler_image_id: str,
                 handler_span: tuple[int, int] | None, max_pending: int,
                 max_event_gap: int, max_writebacks: int,
                 max_audits: int) -> dict:
    """Stream one run and return the frozen ``isr_writeback_run_report.v1``."""
    stream = TraceEventStream(run_dir, verify_semantic=True)
    chains = ChainCertificates(max_pending=max_pending,
                               max_event_gap=max_event_gap,
                               require_native_receipts=True)
    writebacks = IsrWritebackCertificates(
        max_pending=max_pending, max_event_gap=max_event_gap,
        handler_span=handler_span, handler_image_id=handler_image_id,
        max_writebacks=max_writebacks)
    chain_certificates = []
    writeback_certificates = []
    events = 0
    for event in stream.events():
        events += 1
        chain_certificates.extend(chains.ingest((event,)))
        writeback_certificates.extend(writebacks.ingest((event,)))
    chain_certificates.extend(chains.flush())
    writeback_certificates.extend(writebacks.flush())

    certified = [item for item in chain_certificates
                 if item.get("status") == "certified"]
    records = writebacks.writeback_records()
    audits = []
    for certificate in certified[:max_audits]:
        audits.append(audit_chain_extension(certificate, records))
    audit_status: Counter = Counter(item["status"] for item in audits)
    joinable = [item for item in audits if item["status"] == "joined"]
    extended = sum(len(item["extended_hops"]) for item in joinable)

    handler_records = []
    for record in records:
        handler_records.append({
            key: record.get(key) for key in (
                "certificate_id", "status", "missing_hops", "writer_pc",
                "insn", "order", "retire_event_id", "retirement_event_id",
                "delivery_event_id", "acceptance_event_id",
                "apb_access_event_id", "commit_event_id", "transaction",
                "target_access_id", "registered_origin_status",
                "registered_origins", "source_refs", "irq_take_identity",
                "second_irq")})

    return {
        "schema_version": REPORT_SCHEMA,
        "run_dir": run_dir.as_posix(),
        "trace_evidence": {
            "format": stream.descriptor["format"],
            "events_file": stream.descriptor["events_file"],
            "bytes": stream.descriptor["bytes"],
            "declared_event_count": stream.descriptor["declared_event_count"],
            "declared_semantic_sha256": stream.descriptor[
                "declared_semantic_sha256"],
            "semantic_sha256_recomputed": stream.semantic_sha256(),
            "semantic_sha256_verified": stream.semantic_sha256_verified(),
            "events_ingested": events,
        },
        "bounds": {"max_pending": max_pending, "max_event_gap": max_event_gap,
                   "max_writebacks": max_writebacks, "max_audits": max_audits,
                   "handler_image_id": handler_image_id,
                   "handler_span": list(writebacks.handler_span)
                   if writebacks.handler_span is not None else None},
        "p5_chain_certificates": _chain_counts(chain_certificates),
        "chain_producer": {
            "module": "myfuzz.scenario.chain_certificates",
            "mutated": False,
            "pending_after_flush": chains.pending_count,
        },
        "handler_writeback_certificates": _writeback_summary(
            writeback_certificates),
        "handler_writeback_counters": writebacks.counters(),
        "handler_writeback_identities": handler_records,
        "handler_writeback_identities_listed": len(handler_records),
        "chain_extension_audits": audits,
        "summary": {
            "chains_certified": len(certified),
            "chains_audited": len(audits),
            "chains_extended": extended,
            "chains_extended_by_direction": dict(Counter(
                item["direction"] for item in joinable)),
            "chains_not_joinable": audit_status.get("not_joinable", 0),
            "chains_without_anchor_hop": audit_status.get("no_anchor", 0),
            "audit_truncated": max(0, len(certified) - len(audits)),
            "handler_writebacks_exactly_certified": len([
                item for item in writeback_certificates
                if item["status"] == "certified"]),
            "handler_writebacks_incomplete": len([
                item for item in writeback_certificates
                if item["status"] == "incomplete"]),
            "adjacency_fallbacks_used": writebacks.counters()[
                "adjacency_fallbacks_used"],
            "chain_extension_verdict": ("extended" if extended
                                        else "not_joinable"),
            "missing_identity": None if extended else (
                missing_chain_extension_identity()),
        },
        "hop_contract": {"declared_handler_hop_sequence":
                         list(HANDLER_HOP_SEQUENCE)},
        "proof_scope": PROOF_SCOPE,
        "not_proof_of": list(NOT_PROOF_OF),
        "limits": [
            {"quantity": "chain_extension",
             "reason": "extending a certified chain to the handler write needs "
                       "an identity no event in these artifacts carries; only "
                       "the handler write's own downstream reflow is certified"},
            {"quantity": "handler_execution_attribution",
             "reason": "the handler image span classifies the writer by "
                       "program-counter range and is never used as a join"},
            {"quantity": "handler_hop_completeness",
             "reason": "the declared hop order is journal order; a candidate "
                       "that ages out or is evicted settles incomplete and no "
                       "later event restores its credit"},
        ],
    }


def render_summary(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"run: {report['run_dir']}",
        f"trace: {report['trace_evidence']['format']} "
        f"{report['trace_evidence']['events_ingested']} events, "
        f"semantic_sha256_verified="
        f"{report['trace_evidence']['semantic_sha256_verified']}",
        f"chains certified: {summary['chains_certified']} "
        f"({report['p5_chain_certificates']['certified_by_direction']} of "
        f"{report['p5_chain_certificates']['total']} certificates)",
        f"handler writebacks: observed="
        f"{report['handler_writeback_counters']['handler_writes_observed']} "
        f"certified={summary['handler_writebacks_exactly_certified']} "
        f"incomplete={summary['handler_writebacks_incomplete']}",
        f"chain extension: {summary['chain_extension_verdict']} "
        f"(extended={summary['chains_extended']}, "
        f"not_joinable={summary['chains_not_joinable']})",
        f"adjacency fallbacks used: {summary['adjacency_fallbacks_used']}",
    ]
    missing = summary.get("missing_identity")
    if missing is not None:
        lines.append(f"missing identity: {missing['record']}."
                     f"{missing['field']} observed={missing['observed']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    configure_parser(parser)
    args = parser.parse_args(argv)
    handler_span = _span(args.handler_span) if args.handler_span else None
    try:
        report = build_report(args.run_dir, handler_image_id=(
            args.handler_image_id), handler_span=handler_span,
            max_pending=args.max_pending, max_event_gap=args.max_event_gap,
            max_writebacks=args.max_writebacks, max_audits=args.max_audits)
    except (TraceUnavailable, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(report, sort_keys=True, ensure_ascii=False,
                      allow_nan=False)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    if not args.quiet:
        print(render_summary(report), file=sys.stderr)
    if args.require_extension and report["summary"]["chains_extended"] == 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
