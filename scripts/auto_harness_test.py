#!/usr/bin/env python3
"""P7-E: one command from trusted declarations to a graded capability report.

``auto_harness_test.py`` chains the accepted P7 stages over a real composition
and, when a runtime family and a client binary are named, runs one real RFuzz
session plus a fresh replay of its authenticated prefix:

    D1 ``declaration-review.json``   per-component declaration verdicts
    D2 ``generated/``                one harness per component + wiring contract
    D3 ``compiled_paths.v1.json``    per-path executable / unsupported + reasons
    D4 ``capability-report.json``    per-path and per-component tiers
       ``session/``                  per-case receipts, trace, checker findings
       ``bundle/``                   the authenticated prefix, for fresh replay
       ``fresh-verification.json``   the fresh replay conclusion

The runtime family is **never guessed**: ``--runtime`` selects one of the
families this repository can really start, and the composition is validated
against that family's own declared requirements (component ids, instance ids,
MMIO windows and memory regions, read from its wiring declaration) before
anything is generated.  A mismatch is refused with a ``code`` and a JSON
``pointer``, never adapted.

Exit codes
----------

``0``  every requested stage completed (``--skip-session`` is the explicit way
       to request a software-only run, which is a success and not a dropped
       stage);
``1``  any stage refused or is absent - the run is marked ``.incomplete`` and
       its ``run-summary.json`` says which stage stopped it; without a runtime
       family (or a client binary) D1..D3 and ``capability-report.json`` are
       still written, and the missing session is a named absence;
``2``  a fresh replay really ran and reported a difference;
``3``  usage error (raised by ``argparse``).

The last line of stdout is the single machine-readable JSON summary.

Known boundaries
----------------
The composition shape both shipped runtime families wire - one CPU plus *two
instances of one IP profile* - really does compile end to end.  D3 keys its
input layout by instance id, so the second PULP GPIO instance is not read as a
duplicate declaration, and the chain reaches the live session, the bundle and
the fresh replay of the authenticated prefix.

Nothing beyond that is claimed.  A path the composition cannot walk is reported
by D3 as ``unsupported`` with a reason (for the shipped dual-GPIO composition:
F5 ``interrupt-delivery-missing`` and F6 ``dma-master-not-declared``) and stops
at ``Catalog`` in the report; the live session starts only when ``--runtime``
*and* ``--client-binary`` are both named; and the runtime family is never
guessed - ``cvw-ahb-pulp-gpio`` is registered, but its session stage still stops
with ``cvw-online-assembly-undeclared``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.auto_harness_test import (  # noqa: E402
    DEFAULT_CACHE_DIR, run_auto_harness_test)


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--cpu', type=Path, required=True,
                        help='the CPU component_profile.json under review')
    parser.add_argument('--ip', type=Path, action='append', default=[],
                        required=True,
                        help='an IP component_profile.json under review; repeatable')
    parser.add_argument('--ip-capability', type=Path, action='append', default=[],
                        help='an ip_test_capability sidecar for a reviewed IP; '
                             'matched by the component_id it declares')
    parser.add_argument('--compose', type=Path, required=True,
                        help='the harness_compose.v1 declaration to generate')
    parser.add_argument('--output', type=Path, required=True,
                        help='a NEW directory for this run (an existing one is refused)')
    parser.add_argument('--budget-seconds', type=float, default=60.0,
                        help='wall-clock budget of the live session')
    parser.add_argument('--runtime', default=None,
                        help='the runtime family that will start the RTL; the '
                             'composition is validated against it before generation')
    parser.add_argument('--client-binary', type=Path, default=None,
                        help='the RFuzz client binary used by the live session')
    parser.add_argument('--cache-dir', type=Path, default=None,
                        help='the shared identity-keyed local harness build cache; '
                             'defaults to <base-dir>/' + DEFAULT_CACHE_DIR)
    parser.add_argument('--build-cache', type=Path, default=None,
                        help='also compile every generated harness into this cache')
    parser.add_argument('--max-tests', type=int, default=200,
                        help='maximum online cases for the live session')
    parser.add_argument('--search-seed', type=int, default=None,
                        help='the u64 search seed of the live session')
    parser.add_argument('--max-runs-per-batch', type=int, default=1,
                        help='RFuzz runs per batch, 1..8')
    parser.add_argument('--skip-session', action='store_true',
                        help='explicitly request D1..D3 + the report only; a '
                             'named runtime family is still validated')
    parser.add_argument('--label', default=None,
                        help='a label for this run (defaults to the output name)')
    parser.add_argument('--base-dir', type=Path, default=ROOT,
                        help='the trusted repository root holding the profiles')


def run(args: argparse.Namespace) -> int:
    summary = run_auto_harness_test(
        cpu=args.cpu, ips=list(args.ip), compose=args.compose,
        output=args.output, base_dir=args.base_dir.resolve(),
        runtime=args.runtime, client_binary=args.client_binary,
        cache_dir=args.cache_dir, build_cache=args.build_cache,
        budget_seconds=args.budget_seconds, max_tests=args.max_tests,
        search_seed=args.search_seed,
        max_runs_per_batch=args.max_runs_per_batch,
        skip_session=args.skip_session, label=args.label,
        ip_capabilities=list(args.ip_capability))
    print(json.dumps(summary, sort_keys=True, ensure_ascii=False,
                     default=str))
    return summary['exit_code']


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
