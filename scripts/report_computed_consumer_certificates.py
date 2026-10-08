#!/usr/bin/env python3
"""Read-only report of ``computed_consumer_certificate.v1`` over frozen runs.

Every run directory is streamed through the shipped bounded view
(``TraceEventStream``) exactly like the acceptance metrics do; nothing is
executed and no RTL is started.  The report is deterministic: the same frozen
artifacts always produce byte-identical JSON.

Fail-closed rules:

* a run without a streamable artifact, with an unreadable artifact, with a
  mismatching ``semantic_sha256``, or without any RVFI retirement is reported as
  ``status == "unknown"`` with a precise ``reason``, ``null`` counts and a
  non-zero process exit -- never a fabricated 0;
* a declared witness kind the artifact does not carry is reported as
  ``absent_from_artifact`` (an honest 0 with a reason), not as a certificate
  claim and not as ``null``;
* only exact-identity joins produce a certificate; every other settlement is an
  explicit refusal naming the first missing hop and the first missing identity.

Example:
    PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py \
        runs/p3-capacity-probe-paired-20261007 \
        runs/current-dataflow-p5-fault-calibration-20261007-online \
        --sample 2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from myfuzz.scenario.acceptance_metrics import TraceEventStream, TraceUnavailable
from myfuzz.scenario.computed_consumer_certificates import (
    ABSENT_WITNESS_KINDS,
    NOT_PROOF_OF,
    PROOF_SCOPE,
    SCHEMA_VERSION,
    WITNESS_REGISTRY,
    ComputedConsumerCertificates,
    witness_kind_table,
)

EXIT_OK = 0
EXIT_UNKNOWN_EVIDENCE = 3


def _compact_certificate(certificate: dict) -> dict:
    return {
        "witness_kind": certificate["witness_kind"],
        "witness_event_id": certificate["witness_event_id"],
        "witnesses": [{"kind": witness["kind"], "event_id": witness["event_id"]}
                      for witness in certificate.get("witnesses", [])],
        "device": certificate["device"],
        "event_ids": certificate["event_ids"],
        "transaction": certificate["transaction"],
        "execution": certificate["execution"],
        "computed_event_id": certificate["computed"]["event_id"],
        "computed_operation": certificate["computed"]["operation"],
        "computed_value": certificate["computed"]["computed_value"],
        "enabled_lanes": certificate["enabled_lanes"],
        "lane_values": certificate["lane_values"],
        "store_value": certificate["store_value"],
        "identity_joins": certificate["identity_joins"],
        "event_gap": certificate["event_gap"],
        "proof_scope": certificate["proof_scope"],
        "not_proof_of": certificate["not_proof_of"],
    }


def _compact_settlement(record: dict) -> dict:
    return {
        "status": record["status"],
        "reason": record["reason"],
        "missing_hop": record["missing_hop"],
        "missing_identity": record["missing_identity"],
        "device": record["device"],
        "event_id": record["event_id"],
        "transaction": record["transaction"],
        "computed_event_id": (record["computed"] or {}).get("event_id"),
    }


def _witness_rows(consumer: ComputedConsumerCertificates) -> dict:
    rows: dict[str, dict] = {}
    refusals_by_hop = consumer.refusal_reasons
    certificates_by_kind: dict[str, int] = {}
    for certificate in consumer.certificates:
        kind = certificate["witness_kind"]
        certificates_by_kind[kind] = certificates_by_kind.get(kind, 0) + 1
    for kind in WITNESS_REGISTRY:
        evidence = consumer.witness_evidence_row(kind.name)
        hop = f"device_consumption:{kind.name}"
        refused = refusals_by_hop.get(hop, 0)
        refused_by_identity = (dict(consumer.refusal_identities) if refused else {})
        rows[kind.name] = {
            "event_kind": kind.event_kind,
            "shape": kind.shape,
            "components": list(kind.components),
            "value_fields": [list(path) for path in
                             (value.path for value in kind.value_paths)],
            "identity_keys": [
                {"name": identity.name, "field_path": list(identity.field_path),
                 "join": identity.join, "required": identity.required,
                 "when": identity.when} for identity in kind.identity_keys],
            "joinable": kind.joinable,
            "unjoinable_reason": kind.unjoinable_reason,
            "priority": kind.priority,
            "allowed_statuses": list(kind.allowed_statuses),
            "observed_in_studied_artifacts": kind.observed_in_studied_artifacts,
            "events_seen": evidence["events"],
            "certified": certificates_by_kind.get(kind.name, 0),
            "witnesses_joined": evidence["certified"],
            "join_failures": evidence["join_failures"],
            "join_failures_by_identity": evidence["joined_by_key"],
            "status_rejections": evidence["status_rejections"],
            "gate_rejections": evidence["gate_rejections"],
            "unjoinable_rejections": evidence["unjoinable_rejections"],
            "events_without_pending_chain": evidence["without_pending_chain"],
            "refused": refused,
            "refused_by_identity": refused_by_identity,
            "status": evidence["status"],
            "reason": (None if evidence["events"]
                       else "declared_witness_kind_absent_from_artifact"),
            "note": kind.note,
        }
    return rows


def _unknown_witness_rows(reason: str) -> dict:
    rows: dict[str, dict] = {}
    for kind in WITNESS_REGISTRY:
        rows[kind.name] = {
            "event_kind": kind.event_kind,
            "shape": kind.shape,
            "components": list(kind.components),
            "value_fields": [list(value.path) for value in kind.value_paths],
            "identity_keys": [
                {"name": identity.name, "field_path": list(identity.field_path),
                 "join": identity.join, "required": identity.required,
                 "when": identity.when} for identity in kind.identity_keys],
            "joinable": kind.joinable,
            "unjoinable_reason": kind.unjoinable_reason,
            "priority": kind.priority,
            "allowed_statuses": list(kind.allowed_statuses),
            "observed_in_studied_artifacts": kind.observed_in_studied_artifacts,
            "events_seen": None,
            "certified": None,
            "witnesses_joined": None,
            "join_failures": None,
            "join_failures_by_identity": {},
            "status_rejections": None,
            "gate_rejections": None,
            "unjoinable_rejections": None,
            "events_without_pending_chain": None,
            "refused": None,
            "refused_by_identity": {},
            "status": "unknown",
            "reason": reason,
            "note": kind.note,
        }
    return rows


def _unknown_summary(run_dir: Path, reason: str) -> dict:
    return {
        "run_dir": str(run_dir),
        "schema_version": SCHEMA_VERSION,
        "proof_scope": PROOF_SCOPE,
        "not_proof_of": list(NOT_PROOF_OF),
        "status": "unknown",
        "reason": reason,
        "events": None,
        "declared_event_count": None,
        "semantic_sha256_matches": None,
        "rvfi_retirements": None,
        "certified": None,
        "refused": None,
        "unknown": None,
        "witness_kinds": _unknown_witness_rows(reason),
        "refusals_by_missing_hop": None,
        "refusals_by_missing_identity": None,
        "unknown_by_reason": None,
        "pipeline_refusals": None,
        "counters": None,
        "rejections": None,
        "rejected_retirements": None,
        "peak_pending": None,
        "bounds": None,
        "certificates": [],
        "refusal_samples": [],
        "unknown_samples": [],
    }


def summarize_run(run_dir: Path, *, max_pending: int = 64, max_event_gap: int = 4096,
                  max_value_history: int = 256, max_records: int = 256,
                  sample: int = 4, max_certificates: int = 200) -> dict:
    """Stream one frozen run read-only and summarise the consumer outcome."""
    run_dir = Path(run_dir)
    try:
        stream = TraceEventStream(run_dir)
    except (TraceUnavailable, ValueError, OSError) as exc:
        return _unknown_summary(run_dir, f"artifact_unavailable:{exc}")
    consumer = ComputedConsumerCertificates(
        max_pending=max_pending, max_event_gap=max_event_gap,
        max_value_history=max_value_history, max_records=max_records)
    records: list[dict] = []
    events = 0
    peak = 0
    try:
        for event in stream.events():
            events += 1
            records.extend(consumer.ingest((event,)))
            peak = max(peak, consumer.pending_count)
        records.extend(consumer.flush())
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return _unknown_summary(
            run_dir, f"artifact_unreadable:{type(exc).__name__}:{exc}")
    verified = stream.semantic_sha256_verified()
    if verified is False:
        return _unknown_summary(run_dir, "semantic_sha256_mismatch")
    if consumer.rvfi_retirement_count == 0:
        return _unknown_summary(run_dir, "no_rvfi_retirement_events")

    certificates = list(consumer.certificates)
    refusals = list(consumer.refusals)
    unknowns = list(consumer.unknowns)
    pipeline_hops = ("rvfi_compute", "mmio_store_route")
    return {
        "run_dir": str(run_dir),
        "schema_version": SCHEMA_VERSION,
        "proof_scope": PROOF_SCOPE,
        "not_proof_of": list(NOT_PROOF_OF),
        "status": "ok",
        "reason": None,
        "events": events,
        "events_file": stream.descriptor["events_file"],
        "declared_event_count": stream.descriptor["declared_event_count"],
        "semantic_sha256_matches": verified,
        "rvfi_retirements": consumer.rvfi_retirement_count,
        "certified": consumer.certified_count,
        "refused": consumer.refused_count,
        "unknown": consumer.unknown_count,
        "witness_kinds": _witness_rows(consumer),
        "refusals_by_missing_hop": dict(sorted(consumer.refusal_reasons.items())),
        "refusals_by_missing_identity": dict(sorted(consumer.refusal_identities.items())),
        "unknown_by_reason": dict(sorted(consumer.unknown_reasons.items())),
        "pipeline_refusals": {hop: count for hop, count in
                              sorted(consumer.refusal_reasons.items())
                              if hop in pipeline_hops},
        "counters": dict(sorted(consumer.counters.items())),
        "rejections": dict(sorted(consumer.rejections.items())),
        "rejected_retirements": {
            "discarded_zero_register_write":
                consumer.rejections.get("discarded_zero_register_write", 0),
            "unsupported_instruction_observation_only":
                consumer.rejections.get("unsupported_instruction_observation_only", 0),
            "illegal_computed_value":
                consumer.rejections.get("illegal_computed_value", 0),
            "retirement_trap_observation_only":
                consumer.rejections.get("retirement_trap_observation_only", 0),
        },
        "peak_pending": peak,
        "bounds": {"max_pending": consumer.max_pending,
                   "max_event_gap": consumer.max_event_gap,
                   "max_value_history": consumer.max_value_history,
                   "max_records": consumer.max_records},
        "certified_kinds": sorted({certificate["witness_kind"]
                                   for certificate in certificates}),
        "certificates": [_compact_certificate(certificate)
                         for certificate in certificates[:max_certificates]],
        "certificates_truncated": max(0, len(certificates) - max_certificates),
        "refusal_samples": [_compact_settlement(record) for record in refusals[:sample]],
        "unknown_samples": [_compact_settlement(record) for record in unknowns[:sample]],
    }


def build_report(run_dirs, *, max_pending: int = 64, max_event_gap: int = 4096,
                 max_value_history: int = 256, max_records: int = 256,
                 sample: int = 4, max_certificates: int = 200) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "proof_scope": PROOF_SCOPE,
        "not_proof_of": list(NOT_PROOF_OF),
        "witness_registry": witness_kind_table(),
        "absent_witness_kinds": [
            {"name": kind.name, "reason": kind.reason, "note": kind.note}
            for kind in ABSENT_WITNESS_KINDS],
        "bounds": {"max_pending": max_pending, "max_event_gap": max_event_gap,
                   "max_value_history": max_value_history,
                   "max_records": max_records},
        "runs": [summarize_run(run_dir, max_pending=max_pending,
                               max_event_gap=max_event_gap,
                               max_value_history=max_value_history,
                               max_records=max_records, sample=sample,
                               max_certificates=max_certificates)
                 for run_dir in run_dirs],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dirs", nargs="*", type=Path)
    parser.add_argument("--sample", type=int, default=4,
                        help="refusal/unknown samples kept per run")
    parser.add_argument("--max-certificates", type=int, default=200,
                        help="certificates listed verbatim per run")
    parser.add_argument("--max-pending", type=int, default=64)
    parser.add_argument("--max-event-gap", type=int, default=4096)
    parser.add_argument("--max-value-history", type=int, default=256)
    parser.add_argument("--max-records", type=int, default=256)
    parser.add_argument("--registry-only", action="store_true",
                        help="print the declared witness registry without reading runs")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.registry_only and not args.run_dirs:
        parser.error("at least one run directory is required")

    if args.registry_only:
        report = {"schema_version": SCHEMA_VERSION, "proof_scope": PROOF_SCOPE,
                  "not_proof_of": list(NOT_PROOF_OF),
                  "witness_registry": witness_kind_table(),
                  "absent_witness_kinds": [
                      {"name": kind.name, "reason": kind.reason, "note": kind.note}
                      for kind in ABSENT_WITNESS_KINDS]}
    else:
        report = build_report(args.run_dirs, max_pending=args.max_pending,
                              max_event_gap=args.max_event_gap,
                              max_value_history=args.max_value_history,
                              max_records=args.max_records, sample=args.sample,
                              max_certificates=args.max_certificates)
    text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
    sys.stdout.write(text)

    unknown_runs = [run for run in report.get("runs", [])
                    if run["status"] != "ok"]
    for run in unknown_runs:
        sys.stderr.write(
            f"unknown evidence for {run['run_dir']}: {run['reason']}\n")
    return EXIT_UNKNOWN_EVIDENCE if unknown_runs else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
