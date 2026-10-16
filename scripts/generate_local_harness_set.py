#!/usr/bin/env python3
"""Generate one independent harness per declared component, or refuse the set.

P7-B's entry point: a closed composition declaration names the CPU, the devices
and the address window of each; this script produces one harness per component
plus the declared wiring contract, and refuses the whole set when any declared
protocol endpoint matches no registered template.

It never claims more than it did: the emitted `harness_set.json` records the
`generated` tier and lists the tiers it does *not* claim.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.declaration_review import (  # noqa: E402
    review_document_json, review_profiles)
from myfuzz.local_harness.harness_set import (  # noqa: E402
    HarnessSetRefused, generate_harness_set, load_compose)


def _review(compose, *, repository, compose_base):
    """Review every declared component before anything is generated.

    Two directories are in play and conflating them is a real defect: the
    request files live next to the compose document, while the profiles they
    name are resolved against the trusted repository. Passing the compose
    directory as the profile root made every profile look unreadable.
    """
    paths = [row['request'] for row in [compose] + list(compose['devices'])]
    documents = []
    for request_path in paths:
        document = json.loads((compose_base / request_path).read_text(encoding='utf-8'))
        documents.append(document['profile_path'])
    return review_profiles(documents, base_dir=repository)


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--compose', type=Path, required=True,
                        help='harness_compose.v1 declaration')
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory for the generated harness set')
    parser.add_argument('--build-cache', type=Path,
                        help='also compile every harness into this cache')
    parser.add_argument('--skip-review', action='store_true',
                        help='do not run the P7-A declaration review first')
    parser.add_argument('--base-dir', type=Path, default=ROOT,
                        help='repository root that holds the trusted profiles')


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    base_dir = args.base_dir.resolve()
    compose_path = args.compose if args.compose.is_absolute() else Path.cwd() / args.compose
    compose = load_compose(compose_path, base_dir=base_dir)
    review = (None if args.skip_review
              else _review(compose, repository=base_dir,
                           compose_base=compose_path.parent))
    if review is not None and review['status'] != 'ok':
        # The review is the first refusal point, so its report is printed even
        # though no harness will be produced.
        print(review_document_json(review), end='')
        print(json.dumps({'status': 'refused', 'stage': 'declaration_review',
                          'refused': review['refused']},
                         sort_keys=True, ensure_ascii=False))
        return 1
    try:
        document = generate_harness_set(
            compose, base_dir=base_dir, output_root=args.output.resolve(),
            compose_base=compose_path.parent, build_cache=args.build_cache,
            review=review)
    except HarnessSetRefused as error:
        print(json.dumps({'status': 'refused', 'code': error.code,
                          'pointer': error.pointer, 'detail': error.detail},
                         sort_keys=True, ensure_ascii=False, default=str))
        return 1
    print(json.dumps({'status': 'generated', 'tier': document['tier'],
                      'output': str(args.output),
                      'components': [row['instance_id']
                                     for row in document['components']],
                      'not_claimed': document['not_claimed']},
                     sort_keys=True, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == '__main__':
    raise SystemExit(main())
