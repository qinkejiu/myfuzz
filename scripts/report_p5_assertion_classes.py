#!/usr/bin/env python3
"""Write the P5 assertion-class report of one saved run as JSON.

The report is recomputed read-only from the run's saved artifacts by
:func:`myfuzz.scenario.assertion_classes.assertion_class_report`: one streaming
pass over the saved terminal trace feeds the shipped edge-provenance consumer
and the shipped chain-certificate producer, while the receipt stream is scanned
for the run's own checker findings. No RTL, no harness, no new fuzz.

Exit codes:

``0``
    the report was written and the fail-closed gate passed: every abnormal
    record the run holds is represented in the document.
``2``
    the report was written but the gate failed: at least one abnormal record
    (an unclassifiable receipt, an unclassified record status, or a finding
    dropped by ``--max-findings-per-class``) is not represented. The document
    still enumerates it under ``not_silently_filtered.unrepresented`` with a
    precise reason; the gate never passes on a partial list.
``1``
    the run directory holds no streamable trace, or an artifact contradicts its
    frozen contract; nothing is written.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from myfuzz.scenario.acceptance_metrics import TraceUnavailable
from myfuzz.scenario.assertion_classes import (
    ASSERTION_CLASSES,
    CLASS_CPU_IP,
    CLASS_CROSS_COMPONENT,
    CLASS_PROTOCOL_CHECKER,
    assertion_class_report,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_GATE_FAILED = 2


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", required=True, type=Path,
                        help="saved run directory to read (read-only)")
    parser.add_argument("--out", required=True, type=Path,
                        help="JSON assertion-class report to write")
    parser.add_argument("--max-findings-per-class", type=int, default=None,
                        help="keep at most this many findings per assertion "
                             "class; a truncated finding is not represented, "
                             "so the gate then fails with its exact key")
    parser.add_argument("--max-pending", type=int, default=128,
                        help="chain certificate pending bound")
    parser.add_argument("--max-event-gap", type=int, default=4096,
                        help="chain certificate event gap bound")
    parser.add_argument("--edge-max-pending", type=int, default=4096,
                        help="edge provenance pending bound")
    parser.add_argument("--edge-max-event-gap", type=int, default=65536,
                        help="edge provenance event gap bound")
    parser.add_argument("--ingest-batch-size", type=int, default=2048,
                        help="trace events per producer batch")
    parser.add_argument("--no-verify-semantic", action="store_true",
                        help="skip the declared trace semantic digest check")


def _class_line(name: str, section: dict) -> str:
    count = section["finding_count"]
    rendered = "null" if count is None else str(count)
    reason = section["finding_count_reason"]
    suffix = f" ({reason})" if reason else ""
    return (f"  {name}: findings={rendered} "
            f"data_present={section['data_present']} "
            f"observed={section['observed_record_count']}{suffix}")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not args.run.is_dir():
        parser.error(f"run directory does not exist: {args.run}")
    try:
        report = assertion_class_report(
            args.run,
            max_pending=args.max_pending,
            max_event_gap=args.max_event_gap,
            edge_max_pending=args.edge_max_pending,
            edge_max_event_gap=args.edge_max_event_gap,
            ingest_batch_size=args.ingest_batch_size,
            verify_semantic=not args.no_verify_semantic,
            max_findings_per_class=args.max_findings_per_class)
    except (TraceUnavailable, ValueError, OSError) as exc:
        print(f"no assertion-class report for {args.run}: {exc}",
              file=sys.stderr)
        return EXIT_ERROR

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")

    classes = report["assertion_classes"]
    section = report["not_silently_filtered"]
    print(f"{args.run}: {report['schema_version']} "
          f"(trace events {report['trace']['events_ingested']})")
    for name in ASSERTION_CLASSES:
        print(_class_line(name, classes[name]))
    cross = classes[CLASS_CROSS_COMPONENT]
    edge_status = cross["edge_status"]
    print(f"  edges: total={edge_status['total']} "
          f"certified={edge_status['certified']} "
          f"incomplete={edge_status['incomplete']} "
          f"unknown={edge_status['unknown']} "
          f"not_a_runtime_edge={edge_status['not_a_runtime_edge_count']}")
    print(f"  chain certificates: "
          f"certified={cross['chain_certificates']['certified_count']} "
          f"incomplete={cross['chain_certificates']['incomplete_count']}")
    print(f"  abnormal records: {section['abnormal_record_count']} "
          f"represented={section['represented_record_count']} "
          f"unrepresented={len(section['unrepresented'])}")
    print(f"  cases refused before any RTL command: "
          f"{len(section['cases_refused_before_rtl'])}")
    print(f"  protocol checker findings: "
          f"{classes[CLASS_PROTOCOL_CHECKER]['finding_count']}")
    print(f"  cpu_ip_behaviour findings: "
          f"{classes[CLASS_CPU_IP]['finding_count']} "
          f"(records {classes[CLASS_CPU_IP]['observed_record_count']})")
    print(f"wrote {args.out}")

    if not section["gate"]["passed"]:
        print(f"gate failed: {section['gate']['reason']}", file=sys.stderr)
        return EXIT_GATE_FAILED
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
