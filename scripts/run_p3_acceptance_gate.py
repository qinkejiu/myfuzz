#!/usr/bin/env python3
"""P3 acceptance gate: judge a saved run against the plan's P3 conditions.

``analyze`` streams one saved online run directory into a
``p3_acceptance_report.v1`` document and prints it.  Every quantity the
artifacts cannot prove stays ``null`` with a reason, so the exit code is the
gate: ``0`` means every critical key was measured **and** its criterion holds,
``2`` means evidence is missing or a criterion is not met, ``1`` means the
command could not run at all.

``--compare-run`` points at the companion run that reproduced a finding in a
fresh harness; without it the ``finding_stops_and_replays`` criterion can only
use an in-run replay artifact (``minimal_replay.json``).

This entry point never renders a harness, never starts an RTL process and never
touches a simulator; it reads saved artifacts plus declaration-only checks.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.acceptance_metrics import (  # noqa: E402
    DEFAULT_INGEST_BATCH_SIZE,
)
from myfuzz.scenario.p3_acceptance import (  # noqa: E402
    DEFAULT_MAX_CASE_IDS,
    DEFAULT_MAX_GAP_CASES,
    DEFAULT_MAX_MEMORY_LANES,
    EXIT_NOT_READY,
    EXIT_READY,
    p3_acceptance_report,
    render_markdown,
)

#: The command could not run at all (bad arguments, missing run directory).
EXIT_USAGE = 1


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors are hard errors, not 'not ready'.

    argparse exits 2 on a usage error by default, which is indistinguishable
    from the gate's own "evidence missing" exit code, so usage errors are
    raised and mapped to ``EXIT_USAGE`` with the same error document as every
    other hard failure.
    """

    def error(self, message: str):  # type: ignore[override]
        raise ValueError(f"argument error: {message}")


def _dump(document: object) -> str:
    return json.dumps(document, sort_keys=True, allow_nan=False)


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _analyze(args: argparse.Namespace) -> int:
    report = p3_acceptance_report(
        args.run_dir, compare_run=args.compare_run,
        max_gap_cases=args.max_gap_cases, max_pending=args.max_pending,
        max_event_gap=args.max_event_gap,
        require_native_receipts=args.require_native_receipts,
        ingest_batch_size=args.ingest_batch_size,
        verify_semantic=args.verify_semantic,
        max_memory_lanes=args.max_memory_lanes,
        max_case_ids=args.max_case_ids)
    payload = _dump(report)
    print(payload)
    if args.json_out is not None:
        _write_text(Path(args.json_out), payload + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_markdown(report))
    gate = report["gate"]
    print(f"p3 gate: exit={gate['exit_code']} ready={gate['ready']} "
          f"{gate['summary']}", file=sys.stderr)
    return EXIT_READY if gate["exit_code"] == EXIT_READY else EXIT_NOT_READY


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser(
        "analyze", help="judge one saved run directory and print the report")
    analyze.add_argument("--run-dir", type=Path, required=True)
    analyze.add_argument("--compare-run", type=Path,
                         help="companion run that reproduced a finding in a "
                              "fresh harness (same case_id and violations)")
    analyze.add_argument("--json-out", type=Path)
    analyze.add_argument("--markdown-out", type=Path)
    analyze.add_argument("--max-gap-cases", type=int,
                         default=DEFAULT_MAX_GAP_CASES,
                         help="bound on retained certified cross-case chains")
    analyze.add_argument("--max-pending", type=int, default=128,
                         help="chain-certificate producer pending bound")
    analyze.add_argument("--max-event-gap", type=int, default=4096,
                         help="chain-certificate producer event gap")
    analyze.add_argument("--max-memory-lanes", type=int,
                         default=DEFAULT_MAX_MEMORY_LANES,
                         help="bound on the per-byte memory writer table")
    analyze.add_argument("--max-case-ids", type=int, default=DEFAULT_MAX_CASE_IDS,
                         help="bound on the case and receipt tables")
    analyze.add_argument("--ingest-batch-size", type=int,
                         default=DEFAULT_INGEST_BATCH_SIZE)
    analyze.add_argument("--no-require-native-receipts",
                         dest="require_native_receipts", action="store_false")
    analyze.add_argument("--no-verify-semantic", dest="verify_semantic",
                         action="store_false")
    analyze.set_defaults(require_native_receipts=True, verify_semantic=True)

    try:
        args = parser.parse_args(argv)
    except ValueError as exc:
        print(_dump({"schema_version": "p3_acceptance_gate_error.v1",
                     "command": None, "run_dir": None,
                     "error_type": type(exc).__name__, "error": str(exc)}))
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return _analyze(args)
    except (ValueError, OSError) as exc:
        print(_dump({"schema_version": "p3_acceptance_gate_error.v1",
                     "command": args.command,
                     "run_dir": str(args.run_dir),
                     "error_type": type(exc).__name__, "error": str(exc)}))
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
