#!/usr/bin/env python3
"""Write the cross-case chain report of one saved run as JSON.

The report is recomputed read-only from the run's saved terminal trace by
:func:`myfuzz.scenario.cross_case_chains.cross_case_chain_report`: one streaming
pass through the frozen chain certificate producer, no RTL, no new fuzz.

Exit codes:

``0``
    at least one certified chain crossed a case boundary. The per-direction
    summary is printed, and a note goes to stderr when a declared direction has
    no cross-case chain (the certification gap P3 has to close) or when
    ``--max-gap-cases`` truncated chain details.
``2``
    no certified chain crossed a case boundary. The JSON report is still
    written; stderr names each direction's certified same-case count and the
    first gap (``missing_hops[0]``) of its incomplete chains.
``1``
    the run holds no streamable trace, or its artifacts contradict the frozen
    ``runtime_chain_certificate.v1`` contract; nothing is written.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from myfuzz.scenario.acceptance_metrics import TraceUnavailable
from myfuzz.scenario.cross_case_chains import (
    DIRECTIONS,
    cross_case_chain_report,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_CROSS_CASE = 2


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", required=True, type=Path,
                        help="saved run directory holding a streamable online trace")
    parser.add_argument("--out", required=True, type=Path,
                        help="JSON cross-case chain report to write")
    parser.add_argument("--max-gap-cases", type=int, default=None,
                        help="keep the hop detail of certified cross-case chains "
                             "reaching at most this many cases past their source "
                             "case; larger gaps stay counted but truncated")


def _direction_line(direction: str, row: dict) -> str:
    gap = row["case_gap"]
    return (f"  {direction}: certified={row['certified_count']} "
            f"cross_case={row['cross_case_count']} "
            f"same_case={row['same_case_count']} "
            f"incomplete={row['incomplete_count']} "
            f"case_gap(p50={gap['p50']}, max={gap['max']}) "
            f"first_missing_hop={row['first_missing_hop']}")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not args.run.is_dir():
        parser.error(f"run directory does not exist: {args.run}")
    try:
        report = cross_case_chain_report(args.run,
                                         max_gap_cases=args.max_gap_cases)
    except (TraceUnavailable, ValueError) as exc:
        print(f"no cross-case chain report for {args.run}: {exc}",
              file=sys.stderr)
        return EXIT_ERROR

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")

    print(f"{args.run}: {report['certified_count']} certified chain(s), "
          f"{report['cross_case_count']} cross-case, "
          f"{report['same_case_count']} same-case, "
          f"{report['incomplete_count']} incomplete "
          f"(trace events {report['events_ingested']})")
    for direction in DIRECTIONS:
        print(_direction_line(direction, report["by_direction"][direction]))
    print(f"wrote {args.out}")

    for direction in report["directions_without_cross_case"]:
        row = report["by_direction"][direction]
        print(f"warning: {direction} has no cross-case chain in {args.run}: "
              f"cross_case=0, same_case={row['same_case_count']}, "
              f"incomplete={row['incomplete_count']}, first_missing_hop="
              f"{row['first_missing_hop']}", file=sys.stderr)
    if report["truncated"]:
        print(f"warning: max_gap_cases={report['max_gap_cases']} truncated "
              f"{report['truncated_certificate_count']} certified cross-case "
              f"chain(s); they stay counted in cross_case_count="
              f"{report['cross_case_count']} but keep no hop detail "
              f"(max_case_gap_seen={report['max_case_gap_seen']})",
              file=sys.stderr)
    if report["cross_case_count"] == 0:
        print(f"no cross-case chain in {args.run}: "
              f"{report['certified_count']} certified chain(s), every one "
              f"inside a single case", file=sys.stderr)
        for direction in DIRECTIONS:
            row = report["by_direction"][direction]
            print(f"  {direction}: same_case={row['same_case_count']}, "
                  f"incomplete={row['incomplete_count']}, "
                  f"first_missing_hops={row['first_missing_hops']}",
                  file=sys.stderr)
        return EXIT_NO_CROSS_CASE
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
