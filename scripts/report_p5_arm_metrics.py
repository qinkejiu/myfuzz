#!/usr/bin/env python3
"""Emit one ``p5_arm_metrics.v1`` document for one or more saved run arms.

The P5 fixed-budget checklist requires one place that states, per arm: the
one-time compilation/initialization cost, the per-case admission statistics,
the real RTL transactions, the Router/Scheduler breakdown, the incremental
feedback, the log/evidence footprint, the p50/p95 latencies, the effective
cases/second, the complete real chains/second, the coverage-novelty rates and
the invalid/timeout ratio.  Those numbers are produced by different shipped
modules (``myfuzz.scenario.acceptance_metrics``, ``paired_efficiency``, the
run's own ``report.json`` phase timings and the chain-certificate producer);
this CLI aggregates them into one document per arm.

It is strictly read-only: it never starts Verilator, RTL, cargo or the fuzz
client, it never writes inside a run directory, and it streams
``receipts.jsonl`` and the trace container instead of loading them.

Every emitted leaf is ``{"value", "source", "reason"}``: ``source`` names the
artifact key the number came from and a quantity an arm genuinely lacks is
``null`` with a reason, never ``0``.

Exit codes
----------

``0``  aggregated - the document is written and printed as markdown.
``1``  error - a run directory is missing or an artifact cannot be read.
``3``  usage error - no run directory, or a label count that does not match.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
SRC = ROOT / "src"
for entry in (str(ROOT), str(SRC)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from myfuzz.scenario.acceptance_metrics import (  # noqa: E402
    DEFAULT_MAX_CERTIFICATES,
)
from myfuzz.scenario.p5_arm_metrics import (  # noqa: E402
    DEFAULT_MAX_TIMING_SAMPLES,
    SCHEMA_VERSION,
    P5ArmMetricsInputError,
    aggregate_arms,
    render_markdown,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Schema: " + SCHEMA_VERSION)
    parser.add_argument("run_dirs", nargs="*",
                        help="saved run directories, one per arm")
    parser.add_argument("--labels", nargs="+", default=None,
                        help="arm labels, one per run directory (default: the "
                             "directory names)")
    parser.add_argument("--max-certificates", type=int,
                        default=DEFAULT_MAX_CERTIFICATES,
                        help="chain certificate cap forwarded to "
                             f"acceptance_metrics.analyze_run (default: "
                             f"{DEFAULT_MAX_CERTIFICATES})")
    parser.add_argument("--max-timing-samples", type=int,
                        default=DEFAULT_MAX_TIMING_SAMPLES,
                        help="bound on retained per-case timing samples "
                             f"(default: {DEFAULT_MAX_TIMING_SAMPLES})")
    parser.add_argument("--json-out", default=None,
                        help="write the p5_arm_metrics.v1 document here")
    parser.add_argument("--markdown-out", default=None,
                        help="write the rendered markdown view here")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the markdown view to stdout")
    return parser


def _write_text(path: str | None, text: str) -> None:
    if path is None:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.run_dirs:
        print("usage error: at least one saved run directory is required",
              file=sys.stderr)
        return EXIT_USAGE
    if args.labels is not None and len(args.labels) != len(args.run_dirs):
        print(f"usage error: {len(args.labels)} labels were given for "
              f"{len(args.run_dirs)} run directories", file=sys.stderr)
        return EXIT_USAGE
    try:
        document = aggregate_arms(
            args.run_dirs, labels=args.labels,
            max_certificates=args.max_certificates,
            max_timing_samples=args.max_timing_samples)
    except P5ArmMetricsInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    json_text = json.dumps(document, sort_keys=True, indent=2,
                           ensure_ascii=False, allow_nan=False) + "\n"
    markdown = render_markdown(document)
    _write_text(args.json_out, json_text)
    _write_text(args.markdown_out, markdown + "\n")
    if not args.quiet:
        print(markdown)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
