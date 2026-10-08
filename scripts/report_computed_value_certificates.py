#!/usr/bin/env python3
"""Recompute ``computed_value_certificate.v1`` statistics over frozen runs.

Read-only streaming: every run directory is read through
``TraceEventStream`` exactly like the acceptance metrics do, and no RTL is
started.  The output is one JSON document with per-run certificate statistics
and a bounded sample of representative hop sequences.

Example:
    PYTHONPATH=src python3 scripts/report_computed_value_certificates.py \
        runs/p3-lane-selectivity2-20261007-online \
        runs/p4-shift-fuzz-20261007-online \
        runs/current-dataflow-p4-uart-sb-real-online \
        --sample 2
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.computed_value_certificates import ComputedValueCertificates


def summarize(run_dir: Path, *, max_pending: int, max_event_gap: int,
              max_value_history: int, sample: int) -> dict:
    consumer = ComputedValueCertificates(
        max_pending=max_pending, max_event_gap=max_event_gap,
        max_value_history=max_value_history)
    stream = TraceEventStream(run_dir)
    certificates = []
    events = 0
    peak = 0
    for event in stream.events():
        events += 1
        certificates.extend(consumer.ingest((event,)))
        peak = max(peak, consumer.pending_count)
    certificates.extend(consumer.flush())
    certified = [c for c in certificates if c["status"] == "certified"]
    incomplete = [c for c in certificates if c["status"] != "certified"]

    def compact(certificate: dict) -> dict:
        return {
            "status": certificate["status"],
            "transaction": certificate["transaction"],
            "computed": {key: certificate["computed"][key] for key in
                         ("event_id", "pc", "insn", "operation", "rd_addr",
                          "computed_value", "alternative_event_ids")},
            "enabled_lanes": certificate["enabled_lanes"],
            "lane_values": certificate["lane_values"],
            "store_value": certificate["store_value"],
            "device": certificate["device"],
            "hops": [{"hop_id": hop["hop_id"], "kind": hop["kind"],
                      "event_id": hop["event_id"]} for hop in certificate["hops"]],
            "consumption": (None if certificate["consumption"] is None else
                            {key: value for key, value in certificate["consumption"].items()
                             if key != "probes"}),
            "event_gap": certificate["event_gap"],
            "proof_scope": certificate["proof_scope"],
            "not_proof_of": certificate["not_proof_of"],
        }

    return {
        "run_dir": str(run_dir),
        "events": events,
        "declared_event_count": stream.descriptor["declared_event_count"],
        "semantic_sha256_matches": stream.semantic_sha256_verified(),
        "certified": len(certified),
        "incomplete": len(incomplete),
        "rejections": consumer.rejections,
        "counters": consumer.counters,
        "peak_pending": peak,
        "max_pending": consumer.max_pending,
        "devices": sorted({c["device"] for c in certificates if c["device"]}),
        "terminal_kinds": sorted({c["consumption"]["kind"] for c in certified}),
        "certificate_samples": [compact(c) for c in certified[:sample]],
        "incomplete_samples": [compact(c) for c in incomplete[:sample]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--sample", type=int, default=1)
    parser.add_argument("--max-pending", type=int, default=64)
    parser.add_argument("--max-event-gap", type=int, default=4096)
    parser.add_argument("--max-value-history", type=int, default=256)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {"runs": [summarize(run_dir, max_pending=args.max_pending,
                                 max_event_gap=args.max_event_gap,
                                 max_value_history=args.max_value_history,
                                 sample=args.sample)
                       for run_dir in args.run_dirs]}
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.output is not None:
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
