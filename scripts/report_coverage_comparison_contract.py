#!/usr/bin/env python3
"""Fixed comparison contract for the saved declared-IRQ coverage measurements.

This script reports what already measured numbers describe and what a second
tool would have to match before a same-budget comparison is legal:

* the DUT source files and the saved point set / canonical denominator;
* the recorded command sequence (execution nonce normalised) as the workload;
* the replay budget actually in force plus the explicitly unknown search budget;
* the coverage mode (only ``offline`` recorded-prefix replay exists here).

Each scope is re-derived by :func:`scripts.measure_new_path_coverage.measure`
(which reuses the verified saved-measurement loader) and then turned into a
``coverage_comparison_contract.v1`` document.  A missing input, a missing point
map or a non-instrumented prefix never becomes a comparison: the scope is
reported as unavailable with the exact reason.  Nothing is built, replayed or
simulated; the CPU number in this package was produced earlier by
``scripts/measure_local_coverage.py`` and is re-verified here from its files.

The output is deterministic: no timestamps, sorted keys, repo-relative paths.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.measure_new_path_coverage import (CONTRACT_ID, compare_under_contract,
                                               measure, resolve_trace)
from scripts.report_declared_f5_coverage import (_files, _measure_command,
                                                 _relative, _run_summary,
                                                 _scope_component)

SCHEMA = 'coverage_comparison_contract_report.v1'
DEFAULT_RUNS = 'research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030'
DEFAULT_CPU_MEASUREMENT = ('research/input-strategy-audit-20261027/runs/'
                           'declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu')
DEFAULT_SHARED_SIX = ('research/input-strategy-audit-20261027/runs/'
                      'cv32e40p-irq-20261030/shared-six-v6')
DEFAULT_OUTPUT = 'docs/reports/coverage-comparison-contract-20261030.json'
CPU_MEASUREMENT_COMMAND = (
    'PYTHONPATH=src:. python3 scripts/measure_local_coverage.py '
    f'--trace {DEFAULT_RUNS}/wb-timer/original/original/local-command-trace.json '
    '--component cpu '
    '--cache runs/config-driven-20261028/cache/'
    'a06ff3b42591ca1097f9b8c3a471080d4346199501245baeb66edd0fe718c8fc '
    f'--output {DEFAULT_CPU_MEASUREMENT} --max-commands 2048 --build-jobs 4')
SCOPE_FILES = ('coverage.json', 'coverage.dat', 'coverage-points.json',
               'commands.txt', 'replies.txt', 'build.log', 'obj/harness',
               'inputs/generated/artifact.json', 'inputs/generated/driver.cpp')
RUN_FILES = ('prefix.json', 'summary.json', 'config.json')
TRACE_NAMES = ('local-command-trace.json', 'local-commands.json',
               'local_commands.json')
LIMITATIONS = [
    'Every measured number is offline Verilator line/block coverage of a saved recorded prefix; it is not online, fixed-time or AUC coverage.',
    'A contract match establishes identical DUT sources, point set, workload and replay budget in the same mode; it does not establish equal search budgets or tool superiority.',
    'The fresh prefix of every run reproduces the commands but was not instrumented, so it contributes no covered/total and is never compared.',
    'Per-component denominators differ and are not additive; this package publishes no aggregate coverage.',
    'Input SHA256s make the package reproducible, not the original processes authenticated.',
]


def _sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _display(value):
    """Rewrite repo-absolute paths inside a document to repo-relative."""
    text = json.dumps(value, sort_keys=True)
    text = text.replace(str(ROOT.resolve()) + '/', '')
    return json.loads(text)


def _present(directory, names):
    return {name: _sha256(Path(directory) / name) for name in names
            if (Path(directory) / name).is_file()}


def _coverage_summary(document):
    if document.get('status') != 'available':
        return None
    coverage = document['coverage']
    return {
        'metric': coverage['metric'],
        'component': coverage['component'],
        'covered': coverage['covered'],
        'total': coverage['total'],
        'denominator_sha256': coverage['denominator_sha256'],
        'point_set_sha256': coverage['point_set_sha256'],
        'coverage_data_sha256': coverage['coverage_data_sha256'],
        'original_build_digest': coverage['original_build_digest'],
        'original_binary_sha256': coverage['original_binary_sha256'],
        'local_ticks': coverage['local_ticks'],
        'reply_results': coverage['reply_results'],
        'includes_startup_reset': coverage['includes_startup_reset'],
        'includes_budget_overrun': coverage['includes_budget_overrun'],
        'by_kind': coverage['by_kind'],
        'files': coverage['files'],
    }


def _comparability_summary(document):
    comparability = document.get('comparability')
    if not isinstance(comparability, dict):
        return None
    return {
        'status': comparability.get('status'),
        'mode': comparability.get('mode'),
        'reasons': comparability.get('reasons'),
        'coverage_comparison_available': comparability.get(
            'coverage_comparison_available'),
        'coverage_comparison_reason': comparability.get(
            'coverage_comparison_reason'),
        'conditions': comparability.get('conditions'),
        'prefixes': ({key: comparability['prefixes'].get(key) for key in (
            'component', 'build_digest', 'binary_sha256', 'commands',
            'local_ticks', 'config_sha256', 'admission_sha256')}
                     if isinstance(comparability.get('prefixes'), dict) else None),
    }


def _entry(run_name, scope_name, measurement, component, cache, original, fresh):
    document = measure(original, measurement=measurement, cache=cache,
                       component=component, original_prefix=original,
                       fresh_prefix=fresh, contract=True)
    entry = {
        'run': run_name,
        'scope': scope_name,
        'component': component,
        'measurement': _relative(measurement),
        'original_cache': _relative(cache),
        'status': document['status'],
        'reason': document.get('reason'),
        'missing_inputs': document.get('missing_inputs'),
        'files': _files(measurement, SCOPE_FILES),
        'coverage': _coverage_summary(document),
        'comparability': _comparability_summary(document),
        'contract': document.get('comparison_contract'),
    }
    return entry


def _measurement_trace(run_root):
    return resolve_trace(run_root)


def _run_entries(runs_root):
    entries, commands = [], []
    runs_root = Path(runs_root)
    for run_root in sorted(path for path in runs_root.iterdir() if path.is_dir()):
        original, fresh = run_root / 'original', run_root / 'fresh'
        if not (original / 'summary.json').is_file():
            entries.append({
                'run': run_root.name, 'scope': None, 'component': None,
                'measurement': None, 'original_cache': None,
                'status': 'unavailable', 'reason': 'missing-run-summary',
                'missing_inputs': ['original/summary.json'], 'files': {},
                'coverage': None, 'comparability': None, 'contract': None})
            continue
        summary, processes = _run_summary(original)
        target = summary.get('target')
        for scope in sorted(path for path in run_root.glob('coverage-*')
                            if path.is_dir()):
            component = _scope_component(scope, processes, target)
            row = processes.get(component)
            cache = (Path(row['binary_path']).parent
                     if row is not None and isinstance(row.get('binary_path'), str)
                     else run_root / 'absent-cache')
            entries.append(_entry(run_root.name, scope.name, scope, component,
                                  cache, original, fresh))
            commands.append(_measure_command(run_root, scope.name, component,
                                             _relative(cache)) + ' --contract')
    return entries, commands


def _cpu_entry(runs_root, cpu_measurement):
    """The CPU side of the wb-timer run, measured in its own new directory."""
    run_root = Path(runs_root) / 'wb-timer'
    original, fresh = run_root / 'original', run_root / 'fresh'
    measurement = Path(cpu_measurement)
    if not (original / 'summary.json').is_file() or not measurement.is_dir():
        return None
    summary, processes = _run_summary(original)
    row = processes.get('cpu')
    if row is None or not isinstance(row.get('binary_path'), str):
        return None
    entry = _entry('wb-timer', 'coverage-cpu-replay-20261030', measurement, 'cpu',
                   Path(row['binary_path']).parent, original, fresh)
    command = (
        'PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py '
        f'--run {_relative(original)} --measurement {_relative(measurement)} '
        f'--cache {_relative(Path(row["binary_path"]).parent)} --component cpu '
        f'--original-prefix {_relative(original)} '
        f'--fresh-prefix {_relative(fresh)} --contract')
    return entry, command


def _shared_six_entry(shared_six):
    """The CV32E40P six-flow run: no per-component trace was saved."""
    root = Path(shared_six)
    original, fresh = root / 'original', root / 'fresh'
    if not (original / 'summary.json').is_file():
        return None
    found = {}
    for side, directory in (('original', original), ('fresh', fresh)):
        trace = _measurement_trace(directory)
        found[side] = {
            'trace': _relative(trace) if trace is not None else None,
            'coverage_dirs': sorted(path.name for path in directory.glob('coverage-*')
                                    if path.is_dir()),
        }
    missing = []
    for side in ('original', 'fresh'):
        if found[side]['trace'] is None:
            missing.extend(f'{side}/{name}' for name in TRACE_NAMES)
    return {
        'run': root.name,
        'root': _relative(root),
        'status': 'unavailable',
        'reason': 'missing-per-component-command-trace',
        'missing_inputs': missing,
        'searched_inputs': list(TRACE_NAMES),
        'found': found,
        'coverage': None,
        'contract': None,
        'enable_with': ('scripts/run_shared_all_flows.py --record-local-commands '
                        '--descriptor configs/scenarios/'
                        'compiled-f1-f6-cv32e40p-rvfi-gpio-dma-shared/generic_scenario.json '
                        '--mode original|fresh --output NEW_DIR --native'),
        'note': ('The shared-slot entry path now forwards an active '
                 'record_local_commands() trace to run_descriptor; a future run '
                 'writes local_commands.json and fresh_local_commands.json. '
                 'No RTL session was started to produce this record.'),
    }


def build_report(runs_root=DEFAULT_RUNS, cpu_measurement=DEFAULT_CPU_MEASUREMENT,
                 shared_six=DEFAULT_SHARED_SIX):
    runs_root = Path(runs_root).resolve()
    cpu_measurement = Path(cpu_measurement).resolve()
    entries, commands = _run_entries(runs_root)
    cpu = _cpu_entry(runs_root, cpu_measurement)
    if cpu is not None:
        entries.append(cpu[0])
        commands.append(cpu[1])
    measured = [entry for entry in entries if entry['status'] == 'available']
    available_contracts = [entry for entry in measured
                           if isinstance(entry.get('contract'), dict)
                           and entry['contract'].get('status') == 'available']
    pairs = []
    for index, left in enumerate(available_contracts):
        for right in available_contracts[index + 1:]:
            result = compare_under_contract(left['contract'], right['contract'])
            pairs.append({
                'left': {'run': left['run'], 'scope': left['scope']},
                'right': {'run': right['run'], 'scope': right['scope']},
                'status': result['status'],
                'reasons': result['reasons'],
                'comparison': result['comparison'],
            })
    inputs = {}
    for entry in entries:
        if entry.get('measurement') is None:
            continue
        measurement = ROOT / entry['measurement']
        inputs.update({_relative(measurement / name): row['sha256']
                       for name, row in entry['files'].items()
                       if row.get('sha256') is not None})
        run_root = runs_root / entry['run']
        for side in ('original', 'fresh'):
            directory = run_root / side
            inputs.update({_relative(directory / name): digest
                           for name, digest in _present(directory, RUN_FILES).items()})
            trace = _measurement_trace(directory)
            if trace is not None:
                inputs[_relative(trace)] = _sha256(trace)
    shared = _shared_six_entry(Path(shared_six).resolve())
    unavailable = [{'run': entry['run'], 'scope': entry['scope'],
                    'component': entry['component'], 'reason': entry['reason'],
                    'missing_inputs': entry['missing_inputs']}
                   for entry in entries if entry['status'] != 'available']
    if shared is not None:
        unavailable.append({'run': shared['run'], 'scope': None,
                            'component': None, 'reason': shared['reason'],
                            'missing_inputs': shared['missing_inputs']})
    contracts = [entry['contract'] for entry in measured
                 if isinstance(entry.get('contract'), dict)]
    report = {
        'schema_version': SCHEMA,
        'generated_by': 'scripts/report_coverage_comparison_contract.py',
        'contract': CONTRACT_ID,
        'scope': ('saved offline Verilator line/block DUT measurements of recorded '
                  'component prefixes, reported under one fixed comparison contract'),
        'coverage_mode': 'offline',
        'online': False,
        'fixed_time_coverage': False,
        'coverage_auc_available': False,
        'native_authority': False,
        'aggregate': None,
        'aggregate_reason': ('per-component denominators differ and no two scopes '
                             'share a contract, so no total is formed'),
        'contract_rules': (contracts[0]['rules'] if contracts else []),
        'measurements': entries,
        'measured': [{'run': entry['run'], 'scope': entry['scope'],
                      'component': entry['component'],
                      'covered': entry['coverage']['covered'],
                      'total': entry['coverage']['total'],
                      'metric': entry['coverage']['metric'],
                      'local_ticks': entry['coverage']['local_ticks'],
                      'comparability': (entry['comparability'] or {}).get('status'),
                      'contract': (entry['contract'] or {}).get('status')}
                     for entry in measured],
        'same_contract_pairs': pairs,
        'own_prefix_comparability': [
            {'run': entry['run'], 'component': entry['component'],
             'status': entry['comparability']['status'],
             'mode': entry['comparability']['mode'],
             'coverage_comparison_available':
                 entry['comparability']['coverage_comparison_available'],
             'coverage_comparison_reason':
                 entry['comparability']['coverage_comparison_reason']}
            for entry in measured if entry['comparability'] is not None],
        'external_comparison': {
            'status': 'unavailable',
            'reason': 'no-second-tool-measurement-under-this-contract',
            'requirements': (contracts[0]['rules'] if contracts else []),
            'missing_inputs': [
                "a second tool's offline line/block measurement of the same DUT source files and point set",
                "that tool's replay of the identical recorded command sequence (workload.commands_sha256)",
                "evidence of the identical replay budget and executed command count",
                'an explicit coverage-mode declaration (only offline replay exists in this harness; online is false)',
                "an instrumented measurement of the runs' fresh prefixes (they reproduce the commands but carry no coverage)",
            ],
            'missing_search_budget': ('no scope records a fuzzing/search budget: the replay budget '
                                      'is fixed by the measurement, the search budget stays unknown'),
        },
        'unavailable': unavailable,
        'shared_six': shared,
        'inputs': dict(sorted(inputs.items())),
        'reproduction': {
            'report': ('PYTHONPATH=src:. python3 scripts/report_coverage_comparison_contract.py '
                       f'--runs-root {DEFAULT_RUNS} '
                       f'--cpu-measurement {DEFAULT_CPU_MEASUREMENT} '
                       f'--output {DEFAULT_OUTPUT}'),
            'cpu_measurement': CPU_MEASUREMENT_COMMAND,
            'per_scope': commands,
            'tests': ('PYTHONPATH=src:. python3 -m pytest '
                      'tests/integration/test_coverage_comparison_contract.py '
                      'tests/integration/test_new_path_coverage_measurement.py -q'),
        },
        'limitations': LIMITATIONS,
    }
    return _display(report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-root', type=Path, default=ROOT / DEFAULT_RUNS)
    parser.add_argument('--cpu-measurement',
                        type=Path, default=ROOT / DEFAULT_CPU_MEASUREMENT)
    parser.add_argument('--shared-six', type=Path, default=ROOT / DEFAULT_SHARED_SIX)
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    report = build_report(args.runs_root, args.cpu_measurement, args.shared_six)
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    print(json.dumps({'status': 'reported',
                      'measured': len(report['measured']),
                      'unavailable': len(report['unavailable']),
                      'contracts': sum(1 for row in report['measured']
                                       if row['contract'] == 'available'),
                      'comparable_pairs': sum(1 for row in report['same_contract_pairs']
                                               if row['status'] == 'comparable_contract')},
                     sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
