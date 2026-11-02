#!/usr/bin/env python3
"""Attach verified offline DUT line/block measurements to a new search summary."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))
from scripts.compare_local_harness_coverage import load_run
from scripts.measure_local_coverage import select_recorded_session
from myfuzz.local_harness.coverage import coverage_budget,requested_coverage_overrides


def attach(search, component, measurement, cache, *, max_commands=512,max_input_bytes=64*1024*1024,
           max_output_bytes=64*1024*1024,max_wall_seconds=60):
    options=requested_coverage_overrides(coverage_budget(max_commands=max_commands,max_input_bytes=max_input_bytes,
        max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds))
    search = Path(search).resolve()
    summary_path = ((search / 'search-summary.json') if (search / 'search-summary.json').exists()
                    else search / 'summary.json') if search.is_dir() else search
    trace_path = summary_path.parent / 'local_commands.json'
    if not trace_path.exists():
        trace_path = summary_path.parent / 'local-commands.json'
    summary = json.loads(summary_path.read_text(encoding='utf8'))
    trace = json.loads(trace_path.read_text(encoding='utf8'))
    cache, measurement = Path(cache).resolve(), Path(measurement).resolve()
    # The existing validator checks every saved hash, original cache identity,
    # instrumentation, normalized point set and replay protocol/ticks.
    measured = load_run(measurement, cache=cache,**options)
    if measured.get('cache_verified') is not True:
        raise ValueError('original-cache-unverified')
    commands, replies, binary = select_recorded_session(trace, component, measured['build_digest'],**options)
    identity = trace['sessions'][component]['identity']
    if identity.get('component') != component or binary != measured['binary_sha256']:
        raise ValueError('component-or-binary-mismatch')
    # Preserve the exact original nonce and sequence; semantic equivalence is
    # insufficient to bind this replay to the recorded component execution.
    if (measurement / 'commands.txt').read_text(encoding='ascii') != '\n'.join([*commands, 'END', '']):
        raise ValueError('measurement-command-trace-mismatch')
    results = [line for line in (measurement / 'replies.txt').read_text(encoding='utf8').splitlines()
               if line.startswith('RESULT ')]
    if results != replies:
        raise ValueError('measurement-reply-trace-mismatch')
    points = measured['dut_points']
    if not points:
        raise ValueError('empty-dut-point-universe')
    canonical = json.dumps(sorted(points), separators=(',', ':'), ensure_ascii=True)
    coverage = {
        'status': 'available', 'attestation': 'recorded-prefix-replay.v1', 'metric': f'verilator-line-block:{component}:dut',
        'denominator_sha256': sha256(canonical.encode('ascii')).hexdigest(),
        'total': len(points), 'covered': sum(count > 0 for count in points.values()),
        'component': component, 'online': False,
        'scope': 'offline full executed component prefix including startup/reset and any budget overrun',
        'includes_startup_reset': True, 'includes_budget_overrun': True,
        'fixed_time_coverage': False, 'coverage_auc_available': False,
        'budget_overrun_seconds': summary.get('budget_overrun_seconds'),
        'original_build_digest': measured['build_digest'],
        'original_binary_sha256': binary,
        'measurement': str(measurement), 'original_cache': str(cache),
        'search_summary': str(summary_path),
        'search_summary_sha256': sha256(summary_path.read_bytes()).hexdigest(),
        'trace_sha256': sha256(trace_path.read_bytes()).hexdigest(),
        'coverage_data_sha256': sha256((measurement / 'coverage.dat').read_bytes()).hexdigest(),
        'limitations': ['Offline prefix coverage is not online coverage or fixed-time-point coverage.',
                       'Saved artifact consistency does not authenticate the original execution or grant native authority.']}
    summary['coverage'] = coverage
    summary.setdefault('metrics', {})['coverage'] = coverage
    summary['native_authority'] = False
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--search', type=Path, required=True, help='search summary JSON or its directory')
    parser.add_argument('--component', required=True)
    parser.add_argument('--measurement', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True, help='original content-addressed component cache')
    parser.add_argument('--output', type=Path, required=True, help='new summary JSON; must not exist')
    parser.add_argument('--max-commands',type=int,default=512)
    parser.add_argument('--max-input-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-output-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-wall-seconds',type=float,default=60)
    args = parser.parse_args(argv)
    try:
        summary = attach(args.search, args.component, args.measurement, args.cache,
            max_commands=args.max_commands,max_input_bytes=args.max_input_bytes,
            max_output_bytes=args.max_output_bytes,max_wall_seconds=args.max_wall_seconds)
        with args.output.open('x', encoding='utf8') as stream:
            json.dump(summary, stream, indent=2, sort_keys=True)
            stream.write('\n')
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}))
        return 2
    print(json.dumps({'status': 'attached', 'output': str(args.output),
                      'covered': summary['coverage']['covered'], 'total': summary['coverage']['total']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
