#!/usr/bin/env python3
"""Review component declarations before any harness is generated (P7-A).

    PYTHONPATH=src python3 scripts/review_component_declarations.py \
        --profile configs/peripherals/pulp_gpio/component_profile.json

Prints one conclusion per component and, for every row that did not pass, its
``code`` and the JSON ``pointer`` into the profile that has to change.  Writes
the full ``declaration_review.v1`` document with ``--output``.  Exit status is 0
only when every reviewed component is ok; a refused component exits non-zero, so
this can gate generation in a shell pipeline.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.declaration_review import (  # noqa: E402
    review_document_json, review_profiles,
)

#: How much of a row's detail is echoed on stdout. The full detail stays in the
#: JSON document; the console line only has to name the place to look.
_DETAIL_LIMIT = 240


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Review component profiles and refuse before generating.')
    parser.add_argument('--profile', action='append', required=True, metavar='PATH',
                        help='component profile to review; repeat for several')
    parser.add_argument('--base-dir', default=str(ROOT), metavar='DIR',
                        help='root the profiles and their source closures resolve '
                             'against (default: this repository)')
    parser.add_argument('--output', metavar='PATH',
                        help='write the declaration_review.v1 document here')
    return parser


def _detail_text(detail) -> str:
    if detail in (None, {}, []):
        return ''
    text = json.dumps(detail, sort_keys=True, ensure_ascii=False)
    return ' ' + (text if len(text) <= _DETAIL_LIMIT
                  else text[:_DETAIL_LIMIT - 3] + '...')


def main(argv=None) -> int:
    arguments = _parser().parse_args(argv)
    document = review_profiles(arguments.profile, base_dir=Path(arguments.base_dir))
    if arguments.output:
        output = Path(arguments.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(review_document_json(document), encoding='utf-8')
    for component in document['components']:
        failed = [row for row in component['rows'] if row['status'] != 'ok']
        print(f"{component['status']:<9s} {component['component_id']}"
              f"  ({len(component['rows']) - len(failed)}/"
              f"{len(component['rows'])} checks ok)  {component['profile_path']}")
        for row in failed:
            pointer = row['pointer'] or '<root>'
            print(f"    {row['status']:<9s} {row['code']} at {pointer}"
                  f"{_detail_text(row['detail'])}")
    print(f"declaration-review: {document['status']}"
          f"  admitted={len(document['admitted'])}"
          f"  refused={len(document['refused'])}")
    if document['refused']:
        print('refused: ' + ', '.join(document['refused']))
    return 0 if document['status'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
