#!/usr/bin/env python3
"""P7-E: one command from trusted declarations to a graded capability report.

``auto_harness_test.py`` chains the accepted P7 stages over a real composition.
When a runtime family is named it also starts that family's real session: an
RFuzz live session when a client binary is supplied, or the family's own
directed session when it declares one.  Either way the session is replayed fresh
and the report is graded from the documents on disk:

    D1 ``declaration-review.json``   per-component declaration verdicts
    D2 ``generated/``                one harness per component + wiring contract
    D3 ``compiled_paths.v1.json``    per-path executable / unsupported + reasons
    D4 ``capability-report.json``    per-path and per-component tiers
       ``session/``                  real receipts, the session report and trace
       ``bundle/``                   second view of the saved session, for review
       ``fresh-verification.json``   the fresh replay conclusion

The runtime family is **never guessed**: ``--runtime`` selects one of the
families this repository can really start, and the composition is validated
against that family's own declared requirements (component ids, instance ids,
MMIO windows and memory regions, read from its wiring declaration) before
anything is generated.  A mismatch is refused with a ``code`` and a JSON
``pointer``, never adapted.

``--executor compiled-f4-rfuzz`` or ``--executor compiled-f2-rfuzz`` selects the code-owned compiled route instead
of a family.  It is accepted only for its selected executable D3 F2/F4 target and
``--client-binary`` are both named; it cannot be combined with ``--runtime`` and
it never falls back to a family.  ``--rounds-per-case`` (default 128, 1..4096)
bounds the compiled route's local advance rounds per candidate case; a
non-default value is refused without a compiled executor.  That route writes
the usual stages plus
``compiled_f4_prefix.json``, ``compiled_f4_replay.json`` (F4),
``compiled_f2_prefix.json``, ``compiled_f2_replay.json``,
``compiled_f2_build_join.v1.json``, ``compiled_f2_receipt_join.v1.json`` (F2),
``compiled_receipt_join.v1.json`` and the same ``fresh-verification.json`` from
the selected runtime replay on fresh native processes. F2 also writes
``compiled_assertion_results.v1.json`` and ``compiled_assertion_evidence.v1.json``.

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
The composition shape both shipped PULP runtime families wire - one CPU plus
*two instances of one IP profile* - really does compile end to end.  D3 keys its
input layout by instance id, so the second PULP GPIO instance is not read as a
duplicate declaration, and the chain reaches the live session, the bundle and
the fresh replay of the authenticated prefix.

A family may instead declare its own **directed** session assembly.  When it
does, the session stage starts that real chain without a client binary: the
``cvw-ahb-pulp-gpio`` family ships a boot image supplied through the AHB-Lite
memory service, a declared fixed-image instruction source and a real CVW + PULP
GPIO runner factory, so its stage runs one bounded directed case and its fresh
isolated re-run, writes ``session/``, ``bundle/`` and ``fresh-verification.json``
and grades the F4 receipt it really produced.  That is a directed fixed-image
session, not an RFuzz online campaign; naming ``--client-binary`` for such a
family is refused by name instead of pretending the RFuzz transport exists.

Nothing beyond that is claimed.  A path the composition cannot walk is reported
by D3 as ``unsupported`` with a reason (for the shipped dual-GPIO composition:
F5 ``interrupt-delivery-missing`` and F6 ``dma-master-not-declared``) and stops
at ``Catalog`` in the report; the RFuzz live session starts only when
``--runtime`` *and* ``--client-binary`` are both named; and the runtime family
is never guessed - an unknown family id is refused with the known ids.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.auto_harness_test import (  # noqa: E402
    DEFAULT_CACHE_DIR, run_auto_harness_test)
from myfuzz.local_harness.session import record_local_commands
from myfuzz.runtime.recorded_commands import recorded_command_documents


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
                        help='wall-clock budget of the live or directed session')
    parser.add_argument('--runtime', default=None,
                        help='the runtime family that will start the RTL; the '
                             'composition is validated against it before generation')
    parser.add_argument('--executor', default=None,
                        help='a code-owned compiled executor instead of a runtime '
                             'family (compiled-f4-rfuzz, compiled-f2-rfuzz or compiled-f6-rfuzz). It is selected '
                             'only for its explicitly selected executable F2/F4 target '
                             'and --client-binary are both named; it never falls '
                             'back to a runtime family and cannot be combined with '
                             '--runtime')
    parser.add_argument('--f6-deliveries', type=Path, default=None,
                        help='explicit generic PathDelivery array for F6 IRQ wiring')
    parser.add_argument('--f6-execution', type=Path, default=None,
                        help='explicit closed Task1 F6 execution marker JSON')
    parser.add_argument('--client-binary', type=Path, default=None,
                        help='the RFuzz client binary used by an RFuzz live session; '
                             'a family whose own directed session assembly is '
                             'declared refuses it by name')
    parser.add_argument('--cache-dir', type=Path, default=None,
                        help='the shared identity-keyed local harness build cache; '
                             'defaults to <base-dir>/' + DEFAULT_CACHE_DIR)
    parser.add_argument('--build-cache', type=Path, default=None,
                        help='also compile every generated harness into this cache')
    parser.add_argument('--max-tests', type=int, default=200,
                        help='maximum online cases for the RFuzz live session; a '
                             'directed session runs its own bounded case')
    parser.add_argument('--search-seed', type=int, default=None,
                        help='the u64 search seed of the RFuzz live session')
    parser.add_argument('--rounds-per-case', type=int, default=128,
                        help='compiled route only: local advance rounds per '
                             'candidate case (1..4096); the family route keeps '
                             'its own 128 and refuses a non-default value')
    parser.add_argument('--max-runs-per-batch', type=int, default=1,
                        help='RFuzz runs per batch, 1..8')
    parser.add_argument('--record-local-commands', action='store_true',
                        help='record F4 original and fresh component commands for offline coverage')
    parser.add_argument('--record-max-commands', type=int, default=4096,
                        help='maximum captured commands per component execution')
    parser.add_argument('--skip-session', action='store_true',
                        help='explicitly request D1..D3 + the report only; a '
                             'named runtime family is still validated')
    parser.add_argument('--label', default=None,
                        help='a label for this run (defaults to the output name)')
    parser.add_argument('--base-dir', type=Path, default=ROOT,
                        help='the trusted repository root holding the profiles')


def run(args: argparse.Namespace) -> int:
    recording = (record_local_commands(max_commands=args.record_max_commands)
                 if args.record_local_commands else nullcontext(None))
    with recording as trace:
        summary = run_auto_harness_test(
            cpu=args.cpu, ips=list(args.ip), compose=args.compose,
            output=args.output, base_dir=args.base_dir.resolve(),
            runtime=args.runtime, client_binary=args.client_binary,
            cache_dir=args.cache_dir, build_cache=args.build_cache,
            budget_seconds=args.budget_seconds, max_tests=args.max_tests,
            search_seed=args.search_seed,
            max_runs_per_batch=args.max_runs_per_batch,
            skip_session=args.skip_session, label=args.label,
            ip_capabilities=list(args.ip_capability), executor=args.executor,
            rounds_per_case=args.rounds_per_case, f6_execution=args.f6_execution,
            f6_deliveries=args.f6_deliveries)
    if trace is not None and summary['exit_code'] == 0:
        try:
            save_command_recordings(args.output, trace)
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(json.dumps({'status': 'recording_failed', 'reason': str(error)}))
            return 1
    print(json.dumps(summary, sort_keys=True, ensure_ascii=False,
                     default=str))
    return summary['exit_code']


def save_command_recordings(output, trace):
    output = Path(output)
    join = json.loads((output / 'compiled_f4_build_join.v1.json').read_text())
    executions = {phase: join[phase]['execution_audit']['identities']
                  for phase in ('original', 'fresh')}
    documents = recorded_command_documents(trace.export_sessions(), executions=executions,
                                            scope='RFuzz F4', audited=True)
    for phase, name in (('original', 'local_commands.json'),
                        ('fresh', 'fresh_local_commands.json')):
        with (output / name).open('x', encoding='utf8') as stream:
            json.dump(documents[phase], stream, indent=2, sort_keys=True)
            stream.write('\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    args = parser.parse_args(argv)
    if args.record_local_commands and args.executor != 'compiled-f4-rfuzz':
        parser.error('--record-local-commands requires --executor compiled-f4-rfuzz')
    if not 1 <= args.record_max_commands <= 4096:
        parser.error('--record-max-commands must be between 1 and 4096')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
