#!/usr/bin/env python3
"""Per-run DUT line/block coverage and own-prefix comparability, from saved files.

Every number comes from an already saved offline measurement and is re-verified
by :func:`scripts.compare_local_harness_coverage.load_run` through
:func:`scripts.measure_new_path_coverage.measure`; this script adds no parser of
its own.  A ``coverage-*`` directory that is not a complete measurement is
reported as unavailable with the exact missing files and *no* coverage figure.

The report also records the SHA256 of every input file it read, so the same
source tree can reproduce it offline.  Nothing is built, replayed or simulated.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.measure_new_path_coverage import measure, resolve_trace

SCHEMA = 'declared_f5_new_path_coverage_report.v1'
DEFAULT_RUNS = 'research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030'
REPORT_PATH = 'docs/reports/new-path-coverage-20261030.json'
# Files that would make a saved directory a measurement; their presence is
# recorded per scope so an unavailable scope states what it is missing.
SCOPE_FILES = ('coverage.json', 'coverage.dat', 'coverage-points.json',
               'commands.txt', 'replies.txt', 'build.log', 'obj/harness',
               'inputs/generated/driver.cpp', 'inputs/generated/artifact.json')
RUN_FILES = ('prefix.json', 'summary.json', 'config.json')
LIMITATIONS = [
    'Offline saved-prefix Verilator line/block coverage is not online, fixed-time-point or AUC coverage.',
    'Only the original prefix of each run was instrumented; the fresh prefix reproduces the commands but contributes no coverage number.',
    'Line/block coverage of one generated component is not a source-branch, SoC or native-authority metric.',
    'Per-component denominators differ and are not summed into one figure.',
    'Input SHA256s make the report reproducible, not the original processes authenticated.',
]


def _sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _relative(path):
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _files(directory, names):
    directory = Path(directory)
    saved = {}
    for name in names:
        path = directory / name
        saved[name] = ({'present': True, 'sha256': _sha256(path)}
                       if path.is_file() else {'present': False, 'sha256': None})
    return saved


def _display(value):
    """Rewrite repo-absolute paths inside an embedded document to repo-relative."""
    text = json.dumps(value, sort_keys=True)
    text = text.replace(str(ROOT.resolve()) + '/', '')
    return json.loads(text)


def _run_inputs(original, fresh, scope_dirs):
    inputs = {}
    for side in (original, fresh):
        for name in RUN_FILES:
            path = side / name
            if path.is_file():
                inputs[_relative(path)] = _sha256(path)
        trace = resolve_trace(side)
        if trace is not None:
            inputs[_relative(trace)] = _sha256(trace)
    for scope in scope_dirs:
        for name in SCOPE_FILES:
            path = scope / name
            if path.is_file():
                inputs[_relative(path)] = _sha256(path)
    return inputs


def _run_summary(original):
    summary = json.loads((Path(original) / 'summary.json').read_text(encoding='utf-8'))
    processes = {}
    for row in summary.get('processes', []):
        if isinstance(row, dict) and isinstance(row.get('component'), str):
            processes[row['component']] = row
    return summary, processes


def _scope_component(scope, processes, target):
    suffix = scope.name[len('coverage-'):] if scope.name.startswith('coverage-') else scope.name
    return suffix if suffix in processes else target


def _measure_command(run_root, scope_name, component, cache):
    root = _relative(run_root)
    return ('PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py '
            f'--run {root}/original '
            f'--measurement {root}/{scope_name} '
            f'--cache {cache} --component {component} '
            f'--original-prefix {root}/original '
            f'--fresh-prefix {root}/fresh')


def run_document(run_root, *, name):
    run_root = Path(run_root)
    original, fresh = run_root / 'original', run_root / 'fresh'
    if not (original / 'summary.json').is_file():
        return {'run': name, 'status': 'unavailable',
                'reason': 'missing-run-summary',
                'missing_inputs': ['original/summary.json'],
                'coverage': None, 'comparability': None, 'scopes': [],
                'inputs': {}, 'reproduction': []}
    summary, processes = _run_summary(original)
    target = summary.get('target')
    scope_dirs = sorted(path for path in run_root.glob('coverage-*') if path.is_dir())
    scopes, commands = [], []
    for scope in scope_dirs:
        component = _scope_component(scope, processes, target)
        cache = None
        row = processes.get(component)
        if row is not None and isinstance(row.get('binary_path'), str):
            cache = Path(row['binary_path']).parent
        if cache is None:
            cache = run_root / 'absent-cache'
        document = measure(original, measurement=scope, cache=cache,
                           component=component, original_prefix=original,
                           fresh_prefix=fresh)
        document = _display(document)
        entry = {'scope': scope.name, 'measurement': _relative(scope),
                 'component': component, 'original_cache': _relative(cache),
                 'status': document['status'],
                 'reason': document.get('reason'),
                 'missing_inputs': document.get('missing_inputs'),
                 'files': _files(scope, SCOPE_FILES),
                 'document': document}
        scopes.append(entry)
        commands.append(_measure_command(run_root, scope.name, component,
                                         _relative(cache)))
    preferred = (next((entry for entry in scopes if entry['status'] == 'available'
                       and entry['component'] == target), None)
                 or next((entry for entry in scopes if entry['status'] == 'available'),
                         None))
    document = {
        'run': name,
        'status': 'available' if preferred is not None else 'unavailable',
        'target_component': target,
        'original_prefix': _relative(original),
        'fresh_prefix': _relative(fresh),
        'scopes': scopes,
        'coverage': preferred['document']['coverage'] if preferred else None,
        'comparability': (preferred['document']['comparability']
                          if preferred else None),
        'inputs': _run_inputs(original, fresh, scope_dirs),
        'reproduction': commands,
    }
    if preferred is None:
        first = scopes[0] if scopes else {}
        document['reason'] = first.get('reason') or 'missing-coverage-measurement'
        document['missing_inputs'] = first.get('missing_inputs') or []
    return document


def build_report(runs_root):
    runs_root = Path(runs_root)
    names = sorted(path.name for path in runs_root.iterdir() if path.is_dir())
    runs = [run_document(runs_root / name, name=name) for name in names]
    measured, unavailable = [], []
    for run in runs:
        if run['status'] == 'available':
            measured.append({'run': run['run'], 'component': run['coverage']['component'],
                             'measurement': run['coverage']['measurement'],
                             'covered': run['coverage']['covered'],
                             'total': run['coverage']['total'],
                             'local_ticks': run['coverage']['local_ticks'],
                             'comparability': run['comparability']['status']})
        else:
            unavailable.append({'run': run['run'], 'reason': run['reason'],
                                'missing_inputs': run['missing_inputs']})
        for scope in run['scopes']:
            if scope['status'] != 'available':
                unavailable.append({'run': run['run'], 'scope': scope['scope'],
                                    'component': scope['component'],
                                    'reason': scope['reason'],
                                    'missing_inputs': scope['missing_inputs']})
    inputs = {}
    for run in runs:
        inputs.update(run['inputs'])
    report = {
        'schema_version': SCHEMA,
        'generated_by': 'scripts/report_declared_f5_coverage.py',
        'root': _relative(runs_root),
        'scope': ('offline Verilator line/block DUT coverage of already saved original '
                  'component prefixes, plus own original/fresh prefix identity'),
        'coverage_kind': 'verilator-line-block',
        'online': False,
        'fixed_time_coverage': False,
        'coverage_auc_available': False,
        'native_authority': False,
        'aggregate': None,
        'aggregate_reason': ('per-component denominators differ and no two runs are '
                             'compared on coverage, so no total is formed'),
        'reproduction': {
            'report': f'PYTHONPATH=src:. python3 scripts/report_declared_f5_coverage.py --runs-root {DEFAULT_RUNS} --output {REPORT_PATH}',
            'tests': 'PYTHONPATH=src:. python3 -m pytest tests/integration/test_new_path_coverage_measurement.py -q',
            'per_run': [command for run in runs for command in run['reproduction']],
        },
        'runs': runs,
        'measured': measured,
        'unavailable': unavailable,
        'inputs': dict(sorted(inputs.items())),
        'limitations': LIMITATIONS,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-root', type=Path, default=ROOT / DEFAULT_RUNS)
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    report = build_report(args.runs_root)
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    print(json.dumps({'status': 'reported',
                      'runs_measured': len(report['measured']),
                      'unavailable': len(report['unavailable']),
                      'inputs': len(report['inputs'])}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
