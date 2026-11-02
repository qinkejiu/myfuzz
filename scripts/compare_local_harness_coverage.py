#!/usr/bin/env python3
"""Compare two saved local-harness Verilator line/block coverage measurements.

The result describes points observed in explicit command replays. It does not
establish equal fuzzing budgets, equal seed policy, or statistical superiority.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.coverage import (coverage_argv, instrument_driver,
                                            parse_verilator_coverage,
                                            validate_replay_replies,coverage_budget,validate_wire_budget,
                                            dut_source_paths)
from myfuzz.local_harness.build import _validate_cache
from myfuzz.local_harness.renderer import _sha


def parse_commands(text, *, max_commands=512,max_input_bytes=64*1024*1024,
                   max_output_bytes=64*1024*1024,max_wall_seconds=60):
    coverage_budget(max_commands=max_commands,max_input_bytes=max_input_bytes,
                    max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds)
    if not isinstance(text, str) or not text.isascii() or not text.endswith('\n') or '\r' in text:
        raise ValueError('invalid-command-file')
    if len(text)>max_input_bytes: raise ValueError('coverage-input-byte-budget')
    lines = text.splitlines()
    if not lines or lines[-1] != 'END' or not 1 <= len(lines) - 1 <= max_commands:
        raise ValueError('invalid-command-count')
    rows = [line.split(' ') for line in lines[:-1]]
    if any(len(line) > 4096 or len(row) < 4 or row[0] != 'CMD'
           or not re.fullmatch(r'[0-9a-f]{32}', row[1])
           or row[1] != rows[0][1] or row[2] != f'{index:x}'
           for index, (line, row) in enumerate(zip(lines, rows), 1)):
        raise ValueError('invalid-command-sequence')
    validate_wire_budget(lines[:-1],max_input_bytes=max_input_bytes,max_output_bytes=max_output_bytes)
    return rows


def _hash(path):
    return sha256(path.read_bytes()).hexdigest()


def _required_hash(value):
    if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('invalid-identity-hash')
    return value


def load_run(directory, *, cache=None,max_commands=512,max_input_bytes=64*1024*1024,
             max_output_bytes=64*1024*1024,max_wall_seconds=60):
    """Check saved file hashes and decode original Verilator rows, including zeros."""
    requested=coverage_budget(max_commands=max_commands,max_input_bytes=max_input_bytes,
                             max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds)
    run = Path(directory).resolve()
    meta = json.loads((run / 'coverage.json').read_text(encoding='utf-8'))
    saved=coverage_budget(**meta.get('replay_budget',{}))
    effective={key:min(value,saved[key]) for key,value in requested.items()}
    times=meta.get('replay_seconds')
    if times is not None and (type(times) is not dict or set(times)!={'plain','instrumented'}
            or any(type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=effective['max_wall_seconds'] for v in times.values())):
        raise ValueError('coverage-replay-wall-budget')
    if meta.get('schema_version') != 'local_harness_verilator_coverage.v1':
        raise ValueError('unsupported-coverage-schema')
    if meta.get('coverage_kind') != 'verilator-line-block':
        raise ValueError('unsupported-coverage-kind')
    for key, path in (
        ('coverage_data_sha256', run / 'coverage.dat'),
        ('coverage_binary_sha256', run / 'obj/harness'),
        ('instrumented_driver_sha256', run / 'inputs/generated/driver.cpp'),
    ):
        if _required_hash(meta[key]) != _hash(path):
            raise ValueError('file-hash-mismatch:' + key)
    build_digest = _required_hash(meta['original_build_digest'])
    binary_digest = _required_hash(meta['original_binary_sha256'])
    argv = meta['build_argv']
    if (type(argv) is not list or not argv or any(type(a) is not str for a in argv)
            or [a for a in argv if a.startswith('--coverage')] != ['--coverage-line']):
        raise ValueError('unsupported-coverage-instrumentation')
    cache_verified = False
    if cache is not None:
        cache = Path(cache).resolve()
        identity = json.loads((cache / 'manifest.json').read_text(encoding='utf-8'))['identity']
        unsigned = dict(identity)
        if (unsigned.pop('build_digest') != build_digest or _sha(unsigned) != build_digest
                or cache.name != build_digest):
            raise ValueError('original-build-identity-mismatch')
        original = _validate_cache(cache, identity)
        if _hash(original) != binary_digest or coverage_argv(identity['build_argv'], str(run)) != argv:
            raise ValueError('original-build-or-instrumentation-mismatch')
        for row in identity['inputs']:
            relative = row['path']
            if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
                    or any(part in ('', '.', '..') for part in relative.split('/'))):
                raise ValueError('invalid-cache-input-path')
            saved = run / 'inputs' / relative
            if relative == 'generated/driver.cpp':
                expected = instrument_driver((cache / 'inputs' / relative).read_text(encoding='utf-8'))
                if saved.read_text(encoding='utf-8') != expected:
                    raise ValueError('instrumented-driver-mismatch')
            elif _hash(saved) != row['sha256']:
                raise ValueError('saved-input-mismatch:' + relative)
        cache_verified = True
    normalized_argv = [a.replace(str(run), '{RUN}') for a in argv]
    if (run/'commands.txt').stat().st_size>effective['max_input_bytes']:
        raise ValueError('coverage-input-byte-budget')
    command_text = (run / 'commands.txt').read_text(encoding='ascii')
    commands = parse_commands(command_text,**effective)
    replay = meta['replay']
    if replay.get('identical_stdout') is not True or type(replay.get('result_count')) is not int \
            or replay['result_count'] != len(commands):
        raise ValueError('recorded-replay-mismatch')
    artifact = json.loads((run / 'inputs/generated/artifact.json').read_text(encoding='utf-8'))
    if (run/'replies.txt').stat().st_size>effective['max_output_bytes']:
        raise ValueError('coverage-output-byte-budget')
    replies = (run / 'replies.txt').read_text(encoding='utf-8').splitlines()
    tick = validate_replay_replies(replies, commands, artifact)
    if type(replay.get('local_ticks')) is not int or replay['local_ticks'] != tick:
        raise ValueError('replay-tick-mismatch')
    points = {}
    dut_points = {}
    sources = {}
    parsed_points = []
    inputs = (run / 'inputs').resolve()
    recorded_sources = artifact.get('structural_build', {}).get('source_files', [])
    if (not isinstance(recorded_sources, list)
            or any(not isinstance(x, str) for x in recorded_sources)):
        raise ValueError('invalid-dut-source-list')
    try:
        dut_sources = dut_source_paths(recorded_sources) if recorded_sources else []
    except ValueError:
        raise ValueError('invalid-dut-source-list') from None
    for point in parse_verilator_coverage((run / 'coverage.dat').read_text(encoding='utf-8')):
        fields = dict(point['fields'])
        path = Path(fields['f'])
        if not path.is_absolute():
            raise ValueError('coverage-source-not-absolute')
        try:
            relative = path.resolve().relative_to(inputs).as_posix()
        except ValueError:
            raise ValueError('coverage-source-outside-snapshot') from None
        fields['f'] = relative
        identity = json.dumps(fields, sort_keys=True, separators=(',', ':'))
        if identity in points:
            raise ValueError('duplicate-normalized-point')
        points[identity] = point['count']
        sources[relative] = _hash(inputs / relative)
        parsed_points.append({**point, 'normalized_source': relative,
                              'source_sha256': sources[relative]})
        if relative in dut_sources:
            dut_points[identity] = point['count']
    points_hash = meta.get('coverage_points_sha256')
    if points_hash is not None:
        points_path = run / 'coverage-points.json'
        if _required_hash(points_hash) != _hash(points_path):
            raise ValueError('file-hash-mismatch:coverage_points_sha256')
        saved_points = json.loads(points_path.read_text(encoding='utf-8'))
        expected_dut = [p for p in parsed_points if p['normalized_source'] in dut_sources]
        if (saved_points.get('schema_version') != 'local_verilator_points.v1'
                or saved_points.get('all_points') != parsed_points
                or saved_points.get('selected_source_files') != dut_sources
                or saved_points.get('dut_points') != expected_dut):
            raise ValueError('saved-coverage-points-mismatch')
    return {'build_digest': build_digest, 'binary_sha256': binary_digest,
            'coverage_kind': meta['coverage_kind'], 'build_argv': normalized_argv,
            'source_sha256': sources, 'points': points, 'dut_points': dut_points,
            'dut_sources': dut_sources, 'cache_verified': cache_verified,
            'replay_budget':effective,
            'commands': {'count': len(commands),
                'lengths_bytes': [len(line.encode('ascii')) for line in command_text.splitlines()[:-1]],
                'local_ticks': tick}}


def compare_runs(left, right):
    """Compare point identities; missing seed/budget evidence remains unknown."""
    reasons = [key for key in ('build_digest', 'binary_sha256', 'coverage_kind',
                               'build_argv', 'source_sha256', 'dut_sources')
               if not left.get(key) or not right.get(key) or left[key] != right[key]]
    if left.get('cache_verified') is False or right.get('cache_verified') is False:
        reasons.append('original_cache_unverified')
    lp, rp = left.get('points'), right.get('points')
    if not isinstance(lp, dict) or not isinstance(rp, dict) or not lp or set(lp) != set(rp):
        reasons.append('points')
    ld, rd = left.get('dut_points'), right.get('dut_points')
    if not isinstance(ld, dict) or not isinstance(rd, dict) or not ld or set(ld) != set(rd):
        reasons.append('dut_points')
    coverage = None
    dut_coverage = None
    if not reasons:
        def summarize(a, b):
            lh = {key for key, count in a.items() if count > 0}
            rh = {key for key, count in b.items() if count > 0}
            return {'total_points': len(a), 'left_hit_points': len(lh),
                    'right_hit_points': len(rh), 'hit_delta': len(rh) - len(lh),
                    'left_only_points': len(lh - rh), 'right_only_points': len(rh - lh)}
        coverage = summarize(lp, rp)
        dut_coverage = summarize(ld, rd)
    lc, rc = left['commands'], right['commands']
    return {'schema_version': 'local_harness_coverage_comparison.v1',
        'status': 'incomparable' if reasons else 'comparable_points', 'reasons': reasons,
        'coverage': coverage, 'dut_coverage': dut_coverage,
        'dut_scope': 'points in declared structural-build DUT source files, all retained hierarchy instances',
        'scope': 'whole generated local harness including startup/reset',
        'conditions': {'left': lc, 'right': rc,
            'same_command_count': lc['count'] == rc['count'],
            'same_local_ticks': lc['local_ticks'] == rc['local_ticks'],
            'seed': 'unknown', 'time_budget': 'unknown', 'execution_budget': 'unknown',
            'process_independence': 'unknown', 'fairness': 'unknown'},
        'limitations': ['Line/block coverage, not source-branch coverage or a SoC metric.',
            'The original cache binds the recorded build and input files; the uninstrumented stdout is not included in the measurement.',
            'Saved commands and replies are not cryptographically bound to the coverage data; process identities were not recorded.',
            'Equal command counts do not establish equivalent workloads or budgets.',
            'A single pair of replays does not establish tool superiority.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    parser.add_argument('--cache', type=Path, required=True,
                        help='original content-addressed local harness cache directory')
    parser.add_argument('--max-commands',type=int,default=512)
    parser.add_argument('--max-input-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-output-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-wall-seconds',type=float,default=60)
    args = parser.parse_args()
    try:
        options=coverage_budget(max_commands=args.max_commands,max_input_bytes=args.max_input_bytes,
            max_output_bytes=args.max_output_bytes,max_wall_seconds=args.max_wall_seconds)
        result = compare_runs(load_run(args.left, cache=args.cache,**options),
                              load_run(args.right, cache=args.cache,**options))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        print(json.dumps({'status': 'unavailable', 'reason': str(error)}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result['reasons'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
