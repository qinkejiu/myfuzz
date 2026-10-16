#!/usr/bin/env python3
"""Emit one ``capability_report.v1`` document for a compiled composition.

P7-D's entry point: it reads the P7-C ``compiled_paths.v1`` document (required)
plus whatever real evidence exists -- the P7-B ``harness_set.v1``, a saved online
session directory, a fresh-verification document, checker findings and an
explicit ``capability_unavailable.v1`` declaration -- and writes one graded
report per flow path and per component.

Every awarded tier carries the artifact and the fact that establish it; a tier
without evidence is reported as *grade not claimed* with a reason, and P7-C's
``unsupported`` reasons are carried through verbatim.  The document always
carries ``generated: false`` and a ``not_claimed`` list, and its build-cost and
throughput sections reuse the shipped ``p5_arm_metrics.v1`` grouping, reporting
an absent measurement as a named absence rather than as a zero.

Exit codes
----------

``0``  graded - the report is written and one JSON summary line is printed.
``1``  refused - an input is unusable; one JSON line carries ``code`` +
       ``pointer`` and no report is written.
``2``  usage error (raised by ``argparse``).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.scenario.capability_report import (  # noqa: E402
    CAPABILITY_REPORT_SCHEMA, CapabilityReportRefused, build_capability_report)


def _write(document: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, sort_keys=True, indent=2,
                                 ensure_ascii=False, allow_nan=False) + '\n',
                      encoding='utf-8')


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--compiled-paths', type=Path, required=True,
                        help='the P7-C compiled_paths.v1 document (required)')
    parser.add_argument('--harness-set', type=Path,
                        help='the P7-B harness_set.v1 document')
    parser.add_argument('--session', type=Path,
                        help='a saved online session output directory')
    parser.add_argument('--fresh-verification', type=Path,
                        help='a fresh replay conclusion document')
    parser.add_argument('--checker-findings', type=Path,
                        help='a checker findings document (classification per '
                             'finding: natural / injected / calibration)')
    parser.add_argument('--unavailable', type=Path,
                        help='a capability_unavailable.v1 declaration of the '
                             'components that could not be executed locally')
    parser.add_argument('--label', default=None, help='a label for this report')
    parser.add_argument('--output', type=Path, required=True,
                        help='where to write capability-report.json')
    parser.add_argument('--base-dir', type=Path, default=ROOT,
                        help='repository root relative paths resolve against')


def run(args: argparse.Namespace) -> int:
    try:
        document = build_capability_report(
            args.compiled_paths, harness_set=args.harness_set,
            session=args.session, fresh_verification=args.fresh_verification,
            checker_findings=args.checker_findings,
            unavailable=args.unavailable, label=args.label,
            base_dir=args.base_dir.resolve())
    except CapabilityReportRefused as error:
        print(json.dumps({'status': 'refused', 'code': error.code,
                          'pointer': error.pointer, 'detail': error.detail},
                         sort_keys=True, ensure_ascii=False, default=str))
        return 1
    _write(document, args.output)
    print(json.dumps({
        'status': 'graded',
        'schema_version': CAPABILITY_REPORT_SCHEMA,
        'output': str(args.output),
        'paths': {'executable': document['counts']['executable'],
                  'unsupported': document['counts']['unsupported']},
        'components': document['counts']['components'],
        'skipped_unavailable': document['counts']['skipped_unavailable'],
        'tier_awards': document['counts']['tier_awards'],
        'not_claimed': document['not_claimed']},
        sort_keys=True, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
