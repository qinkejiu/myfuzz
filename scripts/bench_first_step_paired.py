#!/usr/bin/env python3
"""Compare paired first-step efficiency: continuous session vs per-case cold start.

``compare`` reads two already-produced run directories and prints
``paired_efficiency_report.v1`` as JSON, optionally writing the JSON and a
Markdown summary whose first section is the evidence boundary (measured values
first, then every ``null`` with its reason, then the limits and the
non-extrapolable boundaries).

Relationship to the existing cold-start baseline
------------------------------------------------
``scripts/bench_ibex_pulp_cold_start.py`` owns cold-start *measurement*: it
starts one fresh runtime per saved input and writes an
``ibex_pulp_cold_baseline.v1`` document (``cold_start.json``) with per-case
``init_seconds``, ``total_seconds``, ``raw_hex``, ``original_status`` and
``cold_status``. This entry point never starts RTL and never re-implements that
measurement; it consumes the run directories, and
:func:`myfuzz.scenario.paired_efficiency.compare_runs` reads the cold baseline
document that script produced for the initialization cost. Per-group summary
metrics reuse ``acceptance_metrics.analyze_run`` (the same streaming analyzer as
``scripts/run_first_step_acceptance.py``).

Exit codes
----------
``0``  report produced;
``2``  data insufficient to compare (unequal case counts, missing receipts,
       empty receipt stream, unusable cold baseline document);
``1``  any other error (missing directory, malformed artifact).
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
    ChainProducerUnavailable,
)
from myfuzz.scenario.paired_efficiency import (  # noqa: E402
    DEFAULT_MAX_CASE_DETAILS,
    DEFAULT_MAX_ITEMS,
    PairedEfficiencyInputError,
    compare_runs,
    render_paired_markdown,
)


def _refuse_chain_producer(**_kwargs: object) -> object:
    """Force the "no producer" path so chains/s is null with an explicit reason."""
    raise ChainProducerUnavailable(
        "--no-chain-producer was requested, so no chain certificate producer was "
        "resolved and certified chains/s stays null")


def _dump(document: object) -> str:
    return json.dumps(document, sort_keys=True, allow_nan=False)


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _compare_command(args: argparse.Namespace) -> int:
    # analyze_run resolves the frozen producer lazily when chain_producer is None;
    # its absence is reported as a limit, never as 0.
    chain_producer = _refuse_chain_producer if args.no_chain_producer else None
    report = compare_runs(
        args.continuous, args.cold, chain_producer=chain_producer,
        max_items=args.max_items, max_case_details=args.max_case_details,
        max_certificates=args.max_certificates, max_pending=args.max_pending,
        max_event_gap=args.max_event_gap,
        require_native_receipts=not args.no_require_native_receipts,
        ingest_batch_size=args.ingest_batch_size,
        continuous_replay_dir=args.continuous_replay_dir,
        cold_replay_dir=args.cold_replay_dir)
    payload = _dump(report)
    print(payload)
    if args.json_out is not None:
        _write_text(Path(args.json_out), payload + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_paired_markdown(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    compare = commands.add_parser(
        "compare", help="compare a continuous run directory with a cold-start one",
        description=__doc__.splitlines()[0])
    compare.add_argument("--continuous", type=Path, required=True,
                         help="run directory of one initialised session (many cases)")
    compare.add_argument("--cold", type=Path, required=True,
                         help="run directory of per-case restart runs")
    compare.add_argument("--json-out", type=Path)
    compare.add_argument("--markdown-out", type=Path)
    compare.add_argument("--continuous-replay-dir", type=Path,
                         help="fresh replay directory/comparison JSON of the "
                              "continuous group")
    compare.add_argument("--cold-replay-dir", type=Path,
                         help="fresh replay directory/comparison JSON of the cold group")
    compare.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    compare.add_argument("--max-case-details", type=int,
                         default=DEFAULT_MAX_CASE_DETAILS)
    compare.add_argument("--max-certificates", type=int, default=200_000)
    compare.add_argument("--max-pending", type=int, default=128)
    compare.add_argument("--max-event-gap", type=int, default=4096)
    compare.add_argument("--no-require-native-receipts",
                         dest="no_require_native_receipts", action="store_true",
                         help="do not require native receipts in chain certificates")
    compare.add_argument("--ingest-batch-size", type=int, default=256)
    compare.add_argument("--no-chain-producer", action="store_true",
                         help="do not resolve the default chain certificate "
                              "producer; certified chains/s stays null with a reason")
    args = parser.parse_args(argv)

    if args.command != "compare":  # pragma: no cover - argparse enforces the set
        parser.error(f"unknown command {args.command!r}")
    try:
        return _compare_command(args)
    except PairedEfficiencyInputError as exc:
        print(f"paired-efficiency-insufficient-data: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"paired-efficiency-error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
