#!/usr/bin/env python3
"""Standalone CPU-only CLI for one pinned CPU, host RAM and assertions.

Examples:

  python3 scripts/run_cpu_only.py --records 0x1,0x2,0x3
  python3 scripts/run_cpu_only.py --fuzz 16 --seed 7
  python3 scripts/run_cpu_only.py --fault
  python3 scripts/run_cpu_only.py --max-ticks 1        # bus/env timeout shape

The stable Python API is in scripts/inprocess_cpu_only.py:
``build_cpu_only(config_path, cache, output=None, *, assertions=False)`` and
``run_cpu_only(config_path, cache, output, ...)``.  The unified entry should call
those functions rather than this CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from inprocess_cpu_only import (  # noqa: E402
    CpuOnlyError, DEFAULT_CONFIG, build_cpu_only, load_cpu_only_config, run_cpu_only,
)


def _records(values):
    if values is None:
        return None
    words = []
    for item in values.split(','):
        item = item.strip()
        if item:
            words.append(int(item, 0))
    return words


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG,
                        help='p0_cpu_only.v1 scenario (default: %(default)s)')
    parser.add_argument('--cache', type=Path, default=ROOT / 'runs/p0-cpu-only/cache',
                        help='CPU-only model/host cache owned by this route')
    parser.add_argument('--output', type=Path, default=ROOT / 'runs/p0-cpu-only/last',
                        help='run directory for logs/result.json')
    parser.add_argument('--records', type=str, default=None,
                        help='comma-separated 32-bit mailbox words (0x.. or decimal)')
    parser.add_argument('--fuzz', type=int, default=None,
                        help='number of deterministic random records instead of --records')
    parser.add_argument('--seed', type=int, default=1, help='fuzz seed')
    parser.add_argument('--max-ticks', type=int, default=None,
                        help='per-case host tick bound (scenario default otherwise)')
    parser.add_argument('--assertions', choices=('on', 'off'), default=None,
                        help='run-time assertion control (fault defaults to on)')
    parser.add_argument('--fault', action='store_true',
                        help='run the scenario declared assertion fault case')
    parser.add_argument('--build-only', action='store_true',
                        help='build/reuse the model and host, do not execute')
    parser.add_argument('--json', action='store_true', help='print the full result document')
    parser.add_argument('--quiet', action='store_true', default=True,
                        help='suppress per-tick detail (always quiet in this entry)')


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    assertions = None if args.assertions is None else args.assertions == 'on'
    if args.build_only:
        result = build_cpu_only(args.config, args.cache, args.output,
                                assertions=bool(assertions))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    fuzz = None if args.fuzz is None else {'cases': args.fuzz, 'seed': args.seed}
    result = run_cpu_only(
        args.config, args.cache, args.output,
        records=_records(args.records), fuzz=fuzz,
        max_ticks=args.max_ticks, assertions=assertions,
        fault=args.fault)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        summary = result.get('summary') or {}
        print('status      :', result['status'])
        print('input mode  :', result['input_mode'])
        print('model       :', result['model_kind'], 'module', result['model_module'])
        print('assertions  :', 'on' if result['assertions'] else 'off')
        print('signals     : retirement=%s trap=%s' %
              (result['signal_status']['retirement'], result['signal_status']['trap']))
        print('cases       :', result.get('case_count'), 'summary', summary.get('status'))
        print('archive     :', result['model_archive'])
        print('wall seconds:', round(result['wall_seconds'], 6))
        if result['assertion_events']:
            print('assertions  :')
            for event in result['assertion_events']:
                print('  %s:%s %s' % (event['file'], event['line'], event['scope']))
        if result['environment_events']:
            print('environment :', result['environment_events'])
        print('output      :', result['output'])
    return {'observations_passed': 0, 'assertion_failed': 3,
            'environment_failed': 4}.get(result['status'], 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    configure_parser(parser)
    args = parser.parse_args(argv)
    try:
        load_cpu_only_config(args.config)
        return run(args, parser)
    except CpuOnlyError as error:
        print('cpu-only-refused:', error, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
