#!/usr/bin/env python3
"""Stream saved online traces through the appended persistent_state edges.

Reads only saved artifacts: no RTL, no harness, no new fuzz. For each run the
script renders the run's own legacy report and the extended report (current
wiring declaration plus the appended ``persistent_state`` edges) from one
streaming pass, then writes a compact JSON document.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from myfuzz.scenario.persistent_state_provenance import persistent_state_report


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", action="append", required=True, type=Path,
                        help="saved run directory holding a compiled session manifest")
    parser.add_argument("--out", required=True, type=Path,
                        help="JSON evidence document to write")
    parser.add_argument("--max-event-gap", type=int, default=65536)
    parser.add_argument("--max-pending", type=int, default=4096)
    parser.add_argument("--keep-edges", action="store_true",
                        help="keep every per-edge row for every run in --out")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    documents = []
    for run_dir in args.run:
        if not run_dir.is_dir():
            parser.error(f"run directory does not exist: {run_dir}")
        report = persistent_state_report(run_dir, max_pending=args.max_pending,
                                         max_event_gap=args.max_event_gap)
        summary = {
            "run_dir": str(run_dir),
            "join": report["join"],
            "legacy_edges_unchanged": report["legacy_edges_unchanged"],
            "legacy_counts": report["legacy"]["counts"],
            "extended_counts": report["extended"]["counts"],
            "events_observed": report["extended"]["events_observed"],
            "events_rejected": report["extended"]["events_rejected"],
            "persistent_state_edges": [
                {"rule_index": row["rule_index"], "status": row["status"],
                 "reason": row["reason"], "missing": row["missing"],
                 "persistent_state": row["persistent_state"],
                 "hops": [{"hop_id": hop["hop_id"], "event_id": hop["event_id"],
                           "key": hop.get("key")} for hop in row["hops"]],
                 "references": row["references"]}
                for row in report["extended"]["edges"]
                if row["relation"] == "persistent_state"],
            "legacy_edges": [
                {"rule_index": row["rule_index"], "relation": row["relation"],
                 "status": row["status"], "reason": row["reason"],
                 "missing": row["missing"],
                 "hops": [{"hop_id": hop["hop_id"], "event_id": hop["event_id"]}
                          for hop in row["hops"]]}
                for row in report["extended"]["edges"]
                if row["relation"] != "persistent_state"],
        }
        if args.keep_edges:
            summary["legacy_report"] = report["legacy"]
            summary["extended_report"] = report["extended"]
        documents.append(summary)
        print(f"{run_dir}: legacy={report['legacy']['counts']} "
              f"extended={report['extended']['counts']} "
              f"unchanged={report['legacy_edges_unchanged']}")
        for row in summary["persistent_state_edges"]:
            block = row["persistent_state"]
            print(f"  edge {row['rule_index']}: {row['status']} ({row['reason']}) "
                  f"writers={block['writer_records']} readers={block['reader_records']} "
                  f"forms={block['reader_reference_forms']} "
                  f"missing_fields={block['missing_fields']}")
    document = {"schema_version": "persistent_state_provenance_evidence.v1",
                "runs": documents}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
