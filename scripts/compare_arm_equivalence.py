#!/usr/bin/env python3
"""Read-only same-condition equivalence between two saved run arms.

Given two *saved* run directories that were produced under the same declared
condition except for one factor (operator ON/OFF, continuous vs per-case cold
start, JSONL vs zlib trace container, ...), this CLI writes one
``arm_equivalence.v1`` document that answers, inside the shared raw-input
window only:

* which per-case declared fields are ``equal`` / ``unequal`` / missing, with
  per-field counts and the exact case indexes (never a single boolean);
* which field families are ``equivalent`` / ``not_equivalent`` / ``unknown``,
  each with a precise reason;
* whether output equivalence may be claimed at all, listing every condition
  that is required and every reason it is not claimed.

It never starts RTL, Verilator, cargo or the fuzz client, and it never opens a
trace container: only ``receipts.jsonl`` (streamed line by line),
``report.json``, ``online_run_identity.json`` and ``decoder_manifest.json``.
The comparison fails closed when the arms do not share a decodable identity
(different decoder manifest, different source identity, no receipts, no cases,
or a zero-length shared raw-input prefix).

Exit codes
----------

``0``  compared - the document reports the per-family verdicts (which may well
       be ``not_equivalent`` or ``unknown``).
``2``  refused - the window is not comparable; the precise reason is on stderr
       and in the document's ``refusal`` block.
``1``  error - a core artifact is unreadable (invalid JSON), so no comparison
       exists.
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

from myfuzz.scenario.arm_equivalence import (  # noqa: E402
    DEFAULT_MAX_DETAIL_INDEXES,
    DEFAULT_MAX_UNDECLARED_FIELDS,
    DEFAULT_MAX_WINDOW_CASES,
    SCHEMA_VERSION,
    ArmEquivalenceInputError,
    compare_arms,
    render_markdown,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2
EXIT_USAGE = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Schema: " + SCHEMA_VERSION)
    parser.add_argument("left", nargs="?", default=None,
                        help="left arm: a saved run directory (for example "
                             "the operator-OFF or JSONL arm)")
    parser.add_argument("right", nargs="?", default=None,
                        help="right arm: the other saved run directory")
    parser.add_argument("--left-label", default=None,
                        help="label of the left arm (default: directory name)")
    parser.add_argument("--right-label", default=None,
                        help="label of the right arm (default: directory name)")
    parser.add_argument("--max-window-cases", type=int,
                        default=DEFAULT_MAX_WINDOW_CASES,
                        help="bound on the compared shared-prefix cases "
                             f"(default: {DEFAULT_MAX_WINDOW_CASES})")
    parser.add_argument("--max-detail-indexes", type=int,
                        default=DEFAULT_MAX_DETAIL_INDEXES,
                        help="bound on the reported unequal/missing case "
                             f"indexes per field (default: "
                             f"{DEFAULT_MAX_DETAIL_INDEXES})")
    parser.add_argument("--max-undeclared-fields", type=int,
                        default=DEFAULT_MAX_UNDECLARED_FIELDS,
                        help="bound on the tracked receipt fields outside the "
                             "declared projection (default: "
                             f"{DEFAULT_MAX_UNDECLARED_FIELDS})")
    parser.add_argument("--json-out", default=None,
                        help="write the arm_equivalence.v1 document here")
    parser.add_argument("--markdown-out", default=None,
                        help="write the rendered markdown document here")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the markdown document to stdout")
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
    if args.left is None or args.right is None:
        print("usage error: two saved run directories are required "
              "(LEFT RIGHT)", file=sys.stderr)
        return EXIT_USAGE
    try:
        document = compare_arms(
            args.left, args.right,
            left_label=args.left_label, right_label=args.right_label,
            max_window_cases=args.max_window_cases,
            max_detail_indexes=args.max_detail_indexes,
            max_undeclared_fields=args.max_undeclared_fields)
    except ArmEquivalenceInputError as exc:
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

    if document["evidence_status"] == "refused":
        refusal = document["refusal"]
        print(f"refused: [{refusal['code']}] {refusal['reason']}",
              file=sys.stderr)
        if not args.quiet:
            print(markdown)
        return EXIT_REFUSED
    if not args.quiet:
        print(markdown)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
