#!/usr/bin/env python3
"""Read-only same-budget benefit comparison for the P4 legal operators.

Given one or more ON/OFF arm pairs of *saved* run directories (ON = operator
enabled, OFF = operator disabled), this CLI writes one ``p4_operator_benefit.v1``
document reporting, per pair:

* the same-budget evidence (tests/statuses, ``effective_search_seconds`` and the
  shared raw-input prefix the arms actually have in common);
* per-target coverage hit counts derived from ``coverage_hex`` (with the counter
  order/width stated as found) and ``new_target_bits_per_second`` computed by the
  shipped ``acceptance_metrics`` / ``paired_efficiency`` rule;
* certified / incomplete chain certificate counts and the chains-per-second
  rate from the shipped chain-certificate analysis;
* per-direction ``runtime_edge_provenance`` witness counts from the shipped
  edge-provenance analysis.

It never starts RTL, Verilator, cargo or the fuzz client.  A metric the artifacts
cannot support is ``null`` plus a precise reason, never ``0``.  If a *required*
metric family is unmeasurable on either arm the comparison fails closed: the
document is still written, the precise reasons go to stderr, and the exit code
is ``2``.

Exit codes
----------

``0``  measurable - every required metric family is supported by the artifacts.
``2``  refused - a required metric family is unmeasurable (fail closed).
``1``  error - a core artifact is missing/unreadable, so no comparison exists.
``3``  usage error.
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

from myfuzz.scenario.p4_operator_benefit import (  # noqa: E402
    DEFAULT_REQUIRED_FAMILIES,
    METRIC_FAMILIES,
    P4OperatorBenefitEvidenceError,
    compare_pairs,
    render_markdown,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2
EXIT_USAGE = 3


def _parse_families(value: str) -> tuple[str, ...]:
    text = value.strip().lower()
    if text in ("all", ""):
        return tuple(METRIC_FAMILIES)
    if text == "none":
        return ()
    names = tuple(part.strip() for part in text.split(",") if part.strip())
    unknown = [name for name in names if name not in METRIC_FAMILIES]
    if unknown:
        raise ValueError(
            f"unknown metric family/families {unknown}; known: "
            f"{list(METRIC_FAMILIES)} or all/none")
    return names


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Metric families: " + ", ".join(METRIC_FAMILIES))
    parser.add_argument(
        "--pair", nargs="+", action="append", metavar="DIR",
        required=True,
        help="operator-OFF arm directory, operator-ON arm directory and an "
             "optional operator label; repeat for several pairs")
    parser.add_argument(
        "--operator-label", default=None,
        help="default label of the operator under test (for example "
             "path_switch) for --pair entries without their own label")
    parser.add_argument(
        "--require", default="all",
        help="comma-separated metric families that must be measurable, or "
             "'all'/'none' (default: all)")
    parser.add_argument("--json-out", default=None,
                        help="write the p4_operator_benefit.v1 document here")
    parser.add_argument("--markdown-out", default=None,
                        help="write the rendered markdown document here")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the markdown document to stdout")
    parser.add_argument("--edge-max-pending", type=int, default=4096)
    parser.add_argument("--edge-max-event-gap", type=int, default=65536)
    parser.add_argument("--max-prefix-items", type=int, default=100_000,
                        help="bound on the per-case raw-prefix window per arm")
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
    try:
        required_families = _parse_families(args.require)
    except ValueError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        pairs = []
        for entry in args.pair:
            if len(entry) not in (2, 3):
                print("usage error: --pair takes OFF_DIR ON_DIR [LABEL]",
                      file=sys.stderr)
                return EXIT_USAGE
            off, on = entry[0], entry[1]
            label = entry[2] if len(entry) == 3 else args.operator_label
            pairs.append({"off": off, "on": on, "operator": label})
    except ValueError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        document = compare_pairs(
            pairs, required_families=required_families,
            edge_max_pending=args.edge_max_pending,
            edge_max_event_gap=args.edge_max_event_gap,
            max_prefix_items=args.max_prefix_items)
    except P4OperatorBenefitEvidenceError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    json_text = json.dumps(document, sort_keys=True, indent=2,
                           ensure_ascii=False, allow_nan=False) + "\n"
    markdown = render_markdown(document)
    _write_text(args.json_out, json_text)
    _write_text(args.markdown_out, markdown + "\n")

    if document["evidence_status"] == "refused":
        print("refused: the required metric families are not fully measurable "
              "from these artifacts:", file=sys.stderr)
        for item in document["refusals"]:
            print(f"  - [{item['metric_family']}] {item['arm']} arm / "
                  f"{item['quantity']}: {item['reason']}", file=sys.stderr)
        if not args.quiet and args.markdown_out is None:
            print(markdown)
        return EXIT_REFUSED
    if not args.quiet:
        print(markdown)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
