#!/usr/bin/env python3
"""P2 acceptance gate: judge a saved run against the plan's P2 conditions.

``analyze`` streams one saved online run directory into a
``p2_acceptance_report.v1`` document and prints it. Every quantity the artifacts
cannot prove stays ``null`` (or ``unknown``) with a reason, so the exit code is
the gate: ``0`` means every critical key was measured **and** its criterion
holds, ``2`` means evidence is missing or a criterion is not met, ``1`` means the
command could not run at all.

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
    DEFAULT_CHUNK_CHARS,
    DEFAULT_INGEST_BATCH_SIZE,
    DEFAULT_MAX_CERTIFICATES,
)
from myfuzz.scenario.p2_acceptance import (  # noqa: E402
    DEFAULT_EDGE_MAX_EVENT_GAP,
    DEFAULT_EDGE_MAX_PENDING,
    DEFAULT_MAX_ACCEPTANCE_KEYS,
    DEFAULT_MAX_IRQ_INSTANCES,
    EXIT_NOT_READY,
    EXIT_READY,
    p2_acceptance_report,
    render_markdown,
)

#: The command could not run at all (bad arguments, missing run directory).
EXIT_USAGE = 1


def _dump(document: object) -> str:
    return json.dumps(document, sort_keys=True, allow_nan=False)


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _analyze(args: argparse.Namespace) -> int:
    report = p2_acceptance_report(
        args.run_dir, run_dir_b=args.compare_run, authority=args.authority,
        max_certificates=args.max_certificates, max_pending=args.max_pending,
        max_event_gap=args.max_event_gap,
        edge_max_pending=args.edge_max_pending,
        edge_max_event_gap=args.edge_max_event_gap,
        require_native_receipts=args.require_native_receipts,
        ingest_batch_size=args.ingest_batch_size,
        verify_semantic=args.verify_semantic,
        max_irq_instances=args.max_irq_instances,
        max_acceptance_keys=args.max_acceptance_keys)
    payload = _dump(report)
    print(payload)
    if args.json_out is not None:
        _write_text(Path(args.json_out), payload + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_markdown(report))
    gate = report["gate"]
    print(f"p2 gate: exit={gate['exit_code']} ready={gate['ready']} "
          f"{gate['summary']}", file=sys.stderr)
    return EXIT_READY if gate["exit_code"] == EXIT_READY else EXIT_NOT_READY


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser(
        "analyze", help="judge one saved run directory and print the report")
    analyze.add_argument("--run-dir", type=Path, required=True)
    analyze.add_argument("--compare-run", type=Path,
                         help="comparison run: same declaration for a fresh-replay "
                              "trace comparison, or same graph with a different "
                              "edge identity for the mutual-recognition criterion")
    analyze.add_argument("--json-out", type=Path)
    analyze.add_argument("--markdown-out", type=Path)
    analyze.add_argument("--authority", choices=("online", "genome"),
                         default="online",
                         help="declaration authority of the negative gates")
    analyze.add_argument("--max-certificates", type=int,
                         default=DEFAULT_MAX_CERTIFICATES)
    analyze.add_argument("--max-pending", type=int, default=128,
                         help="chain-certificate analyzer pending bound")
    analyze.add_argument("--max-event-gap", type=int, default=4096,
                         help="chain-certificate analyzer event gap")
    analyze.add_argument("--edge-max-pending", type=int,
                         default=DEFAULT_EDGE_MAX_PENDING,
                         help="declared-edge consumer pending bound")
    analyze.add_argument("--edge-max-event-gap", type=int,
                         default=DEFAULT_EDGE_MAX_EVENT_GAP,
                         help="declared-edge consumer event gap")
    analyze.add_argument("--max-irq-instances", type=int,
                         default=DEFAULT_MAX_IRQ_INSTANCES)
    analyze.add_argument("--max-acceptance-keys", type=int,
                         default=DEFAULT_MAX_ACCEPTANCE_KEYS)
    analyze.add_argument("--ingest-batch-size", type=int,
                         default=DEFAULT_INGEST_BATCH_SIZE)
    analyze.add_argument("--no-require-native-receipts",
                         dest="require_native_receipts", action="store_false")
    analyze.add_argument("--no-verify-semantic", dest="verify_semantic",
                         action="store_false")
    analyze.set_defaults(require_native_receipts=True, verify_semantic=True)

    args = parser.parse_args(argv)
    try:
        return _analyze(args)
    except (ValueError, OSError) as exc:
        print(_dump({"schema_version": "p2_acceptance_gate_error.v1",
                     "command": args.command,
                     "run_dir": str(args.run_dir),
                     "error_type": type(exc).__name__, "error": str(exc)}))
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
