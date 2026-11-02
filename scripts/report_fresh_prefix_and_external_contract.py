#!/usr/bin/env python3
"""Fresh-prefix coverage comparison and the external-contract package.

This is the deterministic report generator for
``docs/reports/coverage-fresh-prefix-and-external-contract-20261030.json``.
For every declared-IRQ F5 scope it:

1. re-verifies the saved **original** instrumented measurement and the run's own
   original/fresh prefixes (same verified loader as the contract package);
2. re-verifies the **fresh** instrumented measurement against the converted
   ``local_command_trace.v1`` document produced by
   ``scripts/normalize_fresh_local_commands.py`` (its provenance sidecar records
   the converter SHA, the input SHA and the output SHA);
3. compares the two instrumented sides with
   :func:`scripts.measure_new_path_coverage.compare_under_contract` under
   ``dut-line-block/offline-recorded-prefix.v1``: same DUT source set, same
   normalised point set and canonical denominator, identical nonce-normalised
   command sequence, identical command count/local ticks/replies, identical
   replay budget and an explicit offline mode.  A scope that cannot be compared
   is reported ``unavailable`` with the exact reason and no covered/total pair.

It then embeds the strict external-measurement schema and runs the synthetic
self-tests of ``scripts/check_external_coverage_contract.py`` against every
measured scope.  Nothing is built, replayed or simulated here, no network access
is performed, and no external tool measurement is claimed: the external
comparison stays ``unavailable`` with the exact reason and the steps a third
party must take.

The output is deterministic: no timestamps, sorted keys, repo-relative paths.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.check_external_coverage_contract import (EXTERNAL_SCHEMA,
                                                      EXTERNAL_SCHEMA_VERSION,
                                                      self_test)
from scripts.measure_new_path_coverage import (BUDGET_RECORD_SCHEMA, CONTRACT_ID,
                                               compare_under_contract, measure)
from scripts.report_declared_f5_coverage import (_files, _relative, _run_summary)

SCHEMA = 'coverage_fresh_prefix_and_external_contract_report.v1'
DEFAULT_RUNS = 'research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030'
DEFAULT_FRESH = ('research/input-strategy-audit-20261027/runs/'
                 'declared-irq-f5-fresh-20261030')
DEFAULT_CPU_MEASUREMENT = ('research/input-strategy-audit-20261027/runs/'
                           'declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu')
DEFAULT_OUTPUT = ('docs/reports/'
                  'coverage-fresh-prefix-and-external-contract-20261030.json')
SCOPE_FILES = ('coverage.json', 'coverage.dat', 'coverage-points.json',
               'commands.txt', 'replies.txt', 'build.log', 'obj/harness',
               'inputs/generated/artifact.json', 'inputs/generated/driver.cpp')
RUN_FILES = ('prefix.json', 'summary.json', 'config.json', 'admission.json')
VERIFICATION_FILES = ('summary.json', 'coverage.json', 'comparability.json',
                      'contract.json')
SCOPES = (
    {'id': 'wb-timer/coverage-target', 'run': 'wb-timer', 'scope': 'coverage-target',
     'component': 'wb_timer_active', 'original': 'declared'},
    {'id': 'wb-timer/coverage-cpu', 'run': 'wb-timer', 'scope': 'coverage-cpu',
     'component': 'cpu', 'original': 'cpu'},
    {'id': 'apb-spi/coverage-target', 'run': 'apb-spi', 'scope': 'coverage-target',
     'component': 'spi_active', 'original': 'declared'},
    {'id': 'ahb-sha/coverage-target', 'run': 'ahb-sha', 'scope': 'coverage-target',
     'component': 'sha_active', 'original': 'declared'},
)
CANONICAL_RULES = {
    'source_set': {
        'rule': ('rows of {"path", "sha256"} for the declared structural-build DUT '
                 'source files in declared order, path relative to the build '
                 'inputs/ root; digest = sha256(json.dumps(rows, sort_keys=True, '
                 'separators=(",", ":")))'),
        'published_as': 'dut.source_files_sha256',
    },
    'point_identity': {
        'rule': ('one identity per Verilator point: the saved field map with the '
                 'source path made relative to the build inputs/ root, serialised '
                 'as json.dumps(fields, sort_keys=True, separators=(",", ":"))'),
        'published_as': 'dut.point_set_normalized_sha256 (DUT points) and '
                        'dut.point_universe_sha256 (whole harness)',
    },
    'denominator': {
        'rule': ('sha256(json.dumps(sorted(point identities), separators=(",", ":"), '
                 'ensure_ascii=True)) over the DUT points only'),
        'published_as': 'dut.denominator_sha256',
    },
    'workload': {
        'rule': ('recorded command lines with the 32-hex execution nonce replaced by '
                 '{NONCE}; digest = sha256("\\n".join(lines) + "\\n") over ASCII'),
        'published_as': 'workload.commands_sha256',
    },
    'budget': {
        'rule': ('the replay bounds actually in force (max_commands, '
                 'max_input_bytes, max_output_bytes, max_wall_seconds) plus the '
                 'executed command count; a search budget is never inferred'),
        'published_as': 'budget (coverage documents: budget_record)',
    },
}
LIMITATIONS = [
    'The fresh-prefix numbers are offline Verilator line/block coverage of a replay of the same recorded commands on the same pinned build; they are not a second independent fuzz campaign.',
    'A hit_delta of zero between the original and fresh replay of the same commands is the expected identity check; it is not evidence of tool superiority or of search quality.',
    'The saved point-map hash embeds each measurement build directory; the normalised point identity set plus the canonical denominator is the compared identity, and both are published.',
    'Per-component denominators differ and are not additive; this package publishes no aggregate coverage.',
    'No external tool measurement exists: the external comparison is unavailable and synthetic self-test documents are not measurements.',
    'Input SHA256s make the package reproducible, not the original or fresh processes authenticated.',
]


def _sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _display(value):
    """Rewrite repo-absolute paths inside the report to repo-relative."""
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
    record = coverage.get('budget_record')
    measurement = Path(coverage['measurement'])
    saved = (_read_json(measurement / 'coverage.json')
             if (measurement / 'coverage.json').is_file() else {})
    def normalized(argv):
        if not isinstance(argv, list):
            return None
        return [str(token).replace(str(measurement), '{RUN}') for token in argv]

    build_argv = normalized(saved.get('build_argv'))
    executed_argv = normalized(saved.get('build_executed_argv')) or build_argv
    return {
        'metric': coverage['metric'],
        'component': coverage['component'],
        'covered': coverage['covered'],
        'total': coverage['total'],
        'denominator_sha256': coverage['denominator_sha256'],
        'point_set_sha256': coverage['point_set_sha256'],
        'point_set_normalized_sha256': coverage.get('point_set_normalized_sha256'),
        'point_universe_sha256': coverage.get('point_universe_sha256'),
        'coverage_data_sha256': coverage['coverage_data_sha256'],
        'build_digest': coverage['original_build_digest'],
        'binary_sha256': coverage['original_binary_sha256'],
        'build_argv': build_argv,
        'build_executed_argv': executed_argv,
        'build_jobs': saved.get('build_jobs'),
        'by_kind': coverage['by_kind'],
        'files': coverage['files'],
        'commands': coverage['commands']['count'],
        'local_ticks': coverage['local_ticks'],
        'reply_results': coverage['reply_results'],
        'includes_startup_reset': coverage['includes_startup_reset'],
        'includes_budget_overrun': coverage['includes_budget_overrun'],
        'measurement': coverage['measurement'],
        'trace': coverage['trace'],
        'trace_sha256': coverage['trace_sha256'],
        'budget_record': record,
    }


def _contract_summary(contract):
    if not isinstance(contract, dict) or contract.get('status') != 'available':
        return None
    return {
        'contract': contract['contract'],
        'component': contract['component'],
        'metric': contract['metric'],
        'dut': contract['dut'],
        'workload': contract['workload'],
        'budget': contract['budget'],
        'mode': contract['mode'],
        'measurement': contract['measurement'],
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


def _read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _time_log(path):
    path = Path(path)
    if not path.is_file():
        return None
    match = re.search(r'wall_s=(?P<wall>[0-9.]+).*?rss_kb=(?P<rss>[0-9]+)',
                      path.read_text(encoding='utf-8'))
    if match is None:
        return None
    return {'wall_seconds': float(match.group('wall')),
            'peak_rss_kb': int(match.group('rss'))}


def _builds(fresh_root, scopes):
    """The recorded one-at-a-time build/replay commands with exit and RSS."""
    commands = Path(fresh_root) / 'commands'
    rows = []
    for scope in scopes:
        name = f"{scope['run']}-{scope['component']}"
        prefix = commands / name
        if not (prefix.with_name(prefix.name + '.command')).is_file():
            continue
        command_text = prefix.with_name(prefix.name + '.command').read_text(
            encoding='utf-8').splitlines()
        exit_path = prefix.with_name(prefix.name + '.exit')
        rows.append({
            'scope': scope['id'],
            'command': command_text[0] if command_text else None,
            'lock': command_text[1] if len(command_text) > 1 else None,
            'exit_code': (int(exit_path.read_text(encoding='utf-8').strip())
                          if exit_path.is_file() else None),
            'time': _time_log(prefix.with_name(prefix.name + '.time')),
            'stdout': (prefix.with_name(prefix.name + '.out').read_text(
                encoding='utf-8').strip()
                if prefix.with_name(prefix.name + '.out').is_file() else None),
        })
    return rows


def _fresh_traces(fresh_root, runs):
    rows = {}
    for run in runs:
        directory = Path(fresh_root) / run
        trace = directory / 'normalized-local-command-trace.json'
        provenance_path = trace.with_name(trace.name + '.provenance.json')
        if not provenance_path.is_file():
            rows[run] = {'status': 'unavailable',
                         'reason': 'normalized-trace-provenance-missing',
                         'trace': _relative(trace) if trace.is_file() else None,
                         'provenance': _relative(provenance_path)}
            continue
        provenance = _read_json(provenance_path)
        rows[run] = {
            'status': 'available',
            'trace': _relative(trace),
            'trace_sha256': _sha256(trace),
            'provenance': _relative(provenance_path),
            'provenance_sha256': _sha256(provenance_path),
            'converter': provenance['converter'],
            'converter_version': provenance['converter_version'],
            'converter_sha256': provenance['converter_sha256'],
            'source': provenance['input'],
            'components': provenance['components'],
            'normalization': provenance['normalization'],
        }
    return rows


def _scope_entry(scope, *, runs_root, fresh_root, cpu_measurement):
    run_root = Path(runs_root) / scope['run']
    original_prefix = run_root / 'original'
    fresh_prefix = run_root / 'fresh'
    fresh_dir = Path(fresh_root) / scope['run']
    fresh_measurement = fresh_dir / scope['scope']
    trace = fresh_dir / 'normalized-local-command-trace.json'
    if not (original_prefix / 'summary.json').is_file():
        return {'id': scope['id'], 'status': 'unavailable',
                'reason': 'missing-original-prefix-summary',
                'missing_inputs': ['original/summary.json'],
                'component': scope['component'], 'original': None, 'fresh': None,
                'comparison': None, 'coverage_comparison_available': False}
    summary, processes = _run_summary(original_prefix)
    row = processes.get(scope['component'])
    if row is None or not isinstance(row.get('binary_path'), str):
        return {'id': scope['id'], 'status': 'unavailable',
                'reason': 'missing-component-process-row',
                'missing_inputs': ['original/summary.json'],
                'component': scope['component'], 'original': None, 'fresh': None,
                'comparison': None, 'coverage_comparison_available': False}
    cache = Path(row['binary_path']).parent
    original_measurement = (Path(cpu_measurement) if scope['original'] == 'cpu'
                            else run_root / scope['scope'])
    original = measure(original_prefix, measurement=original_measurement,
                       cache=cache, component=scope['component'],
                       original_prefix=original_prefix, fresh_prefix=fresh_prefix,
                       contract=True, extended_identity=True)
    fresh = measure(trace, measurement=fresh_measurement, cache=cache,
                    component=scope['component'], contract=True,
                    extended_identity=True)
    verification = {}
    suffix = '' if scope['scope'] != 'coverage-cpu' else '-cpu'
    for side, directory in (('original', fresh_dir / ('verification-original' + suffix)),
                            ('fresh', fresh_dir / ('verification-fresh' + suffix))):
        verification[side] = {
            'root': _relative(directory),
            'files': _present(directory, VERIFICATION_FILES),
        }
    entry = {
        'id': scope['id'],
        'run': scope['run'],
        'scope': scope['scope'],
        'component': scope['component'],
        'original_cache': _relative(cache),
        'original_measurement': _relative(original_measurement),
        'fresh_measurement': _relative(fresh_measurement),
        'fresh_trace': _relative(trace),
        'status': 'available',
        'reason': None,
        'original': {
            'status': original['status'],
            'reason': original.get('reason'),
            'missing_inputs': original.get('missing_inputs'),
            'files': _present(original_measurement, SCOPE_FILES),
            'coverage': _coverage_summary(original),
            'contract': _contract_summary(original.get('comparison_contract')),
            'comparability': _comparability_summary(original),
        },
        'fresh': {
            'status': fresh['status'],
            'reason': fresh.get('reason'),
            'missing_inputs': fresh.get('missing_inputs'),
            'files': _present(fresh_measurement, SCOPE_FILES),
            'coverage': _coverage_summary(fresh),
            'contract': _contract_summary(fresh.get('comparison_contract')),
        },
        'verification': verification,
        'comparison': None,
    }
    entry['coverage_comparison_available'] = False
    if (original['status'] == 'available' and fresh['status'] == 'available'):
        result = compare_under_contract(original['comparison_contract'],
                                        fresh['comparison_contract'])
        entry['comparison'] = {
            'status': result['status'],
            'reasons': result['reasons'],
            'conditions': result['conditions'],
            'comparison': result['comparison'],
            'point_set_identity': result.get('point_set_identity'),
        }
        entry['status'] = ('comparable' if result['status'] == 'comparable_contract'
                           else 'not_comparable')
        entry['coverage_comparison_available'] = entry['status'] == 'comparable'
        if entry['status'] != 'comparable':
            entry['reason'] = 'contract-comparison-' + result['status']
    else:
        entry['status'] = 'unavailable'
        entry['reason'] = ('original-measurement-' + str(original.get('reason'))
                           if original['status'] != 'available'
                           else 'fresh-measurement-' + str(fresh.get('reason')))
    return entry


def _inputs(runs_root, fresh_root, scopes, cpu_measurement):
    inputs = {}
    runs_root, fresh_root = Path(runs_root), Path(fresh_root)
    cpu_measurement = Path(cpu_measurement)
    for scope in scopes:
        run_root = runs_root / scope['run']
        for side in ('original', 'fresh'):
            directory = run_root / side
            for name, digest in _present(directory, RUN_FILES).items():
                inputs[_relative(directory / name)] = digest
            trace = directory / 'local-command-trace.json'
            if trace.is_file():
                inputs[_relative(trace)] = _sha256(trace)
            raw = (directory / 'fresh' / 'local_commands.json'
                   if side == 'fresh' else directory / 'local_commands.json')
            if raw.is_file():
                inputs[_relative(raw)] = _sha256(raw)
        fresh_dir = fresh_root / scope['run']
        for name in ('normalized-local-command-trace.json',
                     'normalized-local-command-trace.json.provenance.json'):
            path = fresh_dir / name
            if path.is_file():
                inputs[_relative(path)] = _sha256(path)
        for directory in (
                (cpu_measurement if scope['original'] == 'cpu'
                 else run_root / scope['scope']),
                fresh_dir / scope['scope']):
            for name, digest in _present(directory, SCOPE_FILES).items():
                inputs[_relative(directory / name)] = digest
        for side in ('original', 'fresh'):
            directory = fresh_dir / (f'verification-{side}'
                                     + ('-cpu' if scope['scope'] == 'coverage-cpu'
                                        else ''))
            for name, digest in _present(directory, VERIFICATION_FILES).items():
                inputs[_relative(directory / name)] = digest
    commands = fresh_root / 'commands'
    if commands.is_dir():
        for path in sorted(commands.iterdir()):
            if path.is_file():
                inputs[_relative(path)] = _sha256(path)
    return dict(sorted(inputs.items()))


def build_report(runs_root=DEFAULT_RUNS, fresh_root=DEFAULT_FRESH,
                 cpu_measurement=DEFAULT_CPU_MEASUREMENT):
    runs_root = Path(runs_root).resolve()
    fresh_root = Path(fresh_root).resolve()
    cpu_measurement = Path(cpu_measurement).resolve()
    entries = [_scope_entry(scope, runs_root=runs_root, fresh_root=fresh_root,
                            cpu_measurement=cpu_measurement) for scope in SCOPES]
    cache_digests = {}
    for scope in SCOPES:
        original = runs_root / scope['run'] / 'original'
        if not (original / 'summary.json').is_file():
            continue
        _, processes = _run_summary(original)
        row = processes.get(scope['component'])
        if row is not None and isinstance(row.get('binary_path'), str):
            cache_digests[scope['id']] = Path(row['binary_path']).parent.name
    comparable = [entry for entry in entries if entry['status'] == 'comparable']
    fresh_traces = _fresh_traces(fresh_root, sorted({scope['run'] for scope in SCOPES}))
    self_tests, cases = [], []
    for entry in entries:
        contract = (entry['fresh'] or {}).get('contract')
        if entry.get('fresh') is None or contract is None:
            continue
        result = self_test({'contract': contract, 'name': entry['id']})
        self_tests.append({'scope': entry['id'], 'ok': result['ok'],
                           'checked': result['checked'],
                           'comparable': result['comparable'],
                           'not_comparable': result['not_comparable']})
        cases.extend({'scope': entry['id'], 'case': row['case'],
                      'expected': row['expected_status'],
                      'observed': row['observed_status'],
                      'expected_reason': row['expected_reason'],
                      'ok': row['ok']} for row in result['cases'])
    external = {
        'status': 'unavailable',
        'reason': 'no-external-tool-measurement',
        'claim': ('No second tool produced a measurement under this contract; the '
                  'synthetic documents below are validator self-tests, not '
                  'measurements, and no external covered/total is published.'),
        'harness': 'scripts/check_external_coverage_contract.py',
        'harness_sha256': _sha256(ROOT / 'scripts/check_external_coverage_contract.py'),
        'schema_version': EXTERNAL_SCHEMA_VERSION,
        'schema': EXTERNAL_SCHEMA,
        'canonical_rules': CANONICAL_RULES,
        'self_tests': {
            'ok': bool(self_tests) and all(row['ok'] for row in self_tests),
            'scopes': len(self_tests),
            'checked': sum(row['checked'] for row in self_tests),
            'comparable': sum(row['comparable'] for row in self_tests),
            'not_comparable': sum(row['not_comparable'] for row in self_tests),
            'per_scope': self_tests,
            'cases': cases,
            'note': ('Each scope runs the same synthetic case set: one document that '
                     'reproduces the measured identity exactly (must be comparable) '
                     'and mismatching ones that must be rejected for the named reason.'),
        },
        'requirements': [
            'the other tool\'s offline line/block measurement of the same DUT source files (dut.source_files_sha256), same normalised point set (dut.point_set_sha256) and same canonical denominator (dut.denominator_sha256)',
            'that tool\'s replay of the identical recorded command sequence (workload.commands_sha256) with its command count and local ticks',
            'the identical replay budget in force and the executed command count',
            'an explicit mode declaration (only offline recorded-prefix replay is comparable here; online and fixed_time are rejected)',
            'raw artifact SHA256s and the exact reproduction command',
        ],
        'steps_for_third_party': [
            'read one scope record from this package and from docs/reports/coverage-comparison-contract-20261030.json: it names the component, the declared DUT source files (dut.source_files_sha256) and the canonical denominator (dut.denominator_sha256)',
            'build the same DUT from the same pinned cache inputs and instrument line/block points with Verilator --coverage-line exactly as described by the scope measurement\'s coverage.json (build_argv carries --coverage-line; point kinds line/branch, all hierarchy instances retained)',
            'replay the identical recorded command sequence, normalise the 32-hex execution nonce and publish workload.commands_sha256, workload.commands and workload.local_ticks',
            'publish the replay budget that was actually enforced and the executed command count; never report a covered count without its total',
            'fill external_coverage_measurement.v1 (schema in this package: external_contract.schema) and publish it with the raw artifacts and the reproduction command',
            'run: PYTHONPATH=src:. python3 scripts/check_external_coverage_contract.py --scope <scope> --external <document.json> --output <dir> and publish the resulting comparable/not_comparable verdict with its per-field reasons',
        ],
        'network_required': False,
        'what_a_comparable_verdict_would_and_would_not_prove': {
            'would': ('both numbers describe the same DUT points, the same recorded '
                      'workload and the same replay bounds in the same offline mode'),
            'would_not': ('equal search budgets, seeds, process independence, online '
                          'or fixed-time coverage, or tool superiority'),
        },
    }
    unavailable = []
    for entry in entries:
        if entry['status'] != 'comparable':
            unavailable.append({'scope': entry['id'], 'status': entry['status'],
                                'reason': entry['reason']})
    report = {
        'schema_version': SCHEMA,
        'generated_by': 'scripts/report_fresh_prefix_and_external_contract.py',
        'contract': CONTRACT_ID,
        'budget_record_schema': BUDGET_RECORD_SCHEMA,
        'scope': ('offline Verilator line/block coverage of the instrumented fresh '
                  'prefix of the declared-IRQ F5 runs, compared with the instrumented '
                  'original prefix under one fixed contract, plus the external '
                  'same-budget comparison contract and its validator self-tests'),
        'coverage_mode': 'offline',
        'online': False,
        'fixed_time_coverage': False,
        'coverage_auc_available': False,
        'native_authority': False,
        'aggregate': None,
        'aggregate_reason': ('per-component denominators differ and no cross-scope '
                             'total is formed'),
        'runs_root': _relative(runs_root),
        'fresh_root': _relative(fresh_root),
        'fresh_comparisons': {
            'checked': len(entries),
            'comparable': len(comparable),
            'not_comparable': sum(1 for entry in entries
                                  if entry['status'] == 'not_comparable'),
            'unavailable': sum(1 for entry in entries
                               if entry['status'] == 'unavailable'),
            'coverage_comparison_available': (len(entries) > 0
                                              and len(comparable) == len(entries)),
            'note': ('each comparison is original vs fresh instrumented replay of the '
                     'same nonce-normalised command sequence on the same pinned build'),
        },
        'normalized_traces': fresh_traces,
        'scopes': entries,
        'measured': [{'scope': entry['id'], 'component': entry['component'],
                      'original': {'covered': entry['original']['coverage']['covered'],
                                   'total': entry['original']['coverage']['total']},
                      'fresh': {'covered': entry['fresh']['coverage']['covered'],
                                'total': entry['fresh']['coverage']['total']},
                      'comparison': (entry['comparison'] or {}).get('status'),
                      'hit_delta': ((entry['comparison'] or {}).get('comparison')
                                    or {}).get('hit_delta')}
                     for entry in entries if entry['status'] == 'comparable'],
        'builds': _builds(fresh_root, SCOPES),
        'external_contract': external,
        'what_stays_unavailable': [
            {'item': 'external-tool-measurement',
             'reason': 'no-external-tool-measurement',
             'detail': external['claim']},
            {'item': 'search-budget',
             'reason': 'search-budget-not-recorded',
             'detail': ('no fuzzing/search/time budget is recorded for any scope; '
                        'the replay bounds are not a search budget and stay unknown')},
            {'item': 'legacy-per-scope-comparability-documents',
             'reason': 'fresh-prefix-not-instrumented',
             'detail': ('the recorded comparability.json files were generated before '
                        'the fresh prefix was instrumented; they are left unchanged '
                        'and are superseded for these four scopes by this package')},
        ],
        'unavailable': unavailable,
        'inputs': _inputs(runs_root, fresh_root, SCOPES, cpu_measurement),
        'reproduction': {
            'convert': [
                ('PYTHONPATH=src:. python3 scripts/normalize_fresh_local_commands.py '
                 f'--input {_relative(runs_root / scope["run"] / "fresh")} '
                 f'--output {_relative(fresh_root / scope["run"] / "normalized-local-command-trace.json")}')
                for scope in SCOPES if scope['scope'] == 'coverage-target'],
            'measure': [
                ('PYTHONPATH=src:. python3 scripts/measure_local_coverage.py '
                 f'--trace {_relative(fresh_root / scope["run"] / "normalized-local-command-trace.json")} '
                 f'--component {scope["component"]} '
                 f'--cache runs/config-driven-20261028/cache/{cache_digests[scope["id"]]} '
                 f'--output {_relative(fresh_root / scope["run"] / scope["scope"])} '
                 '--max-commands 2048 --build-jobs 4')
                for scope in SCOPES],
            'verify': [
                ('PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py '
                 f'--run {_relative(fresh_root / scope["run"] / "normalized-local-command-trace.json")} '
                 f'--measurement {_relative(fresh_root / scope["run"] / scope["scope"])} '
                 f'--cache runs/config-driven-20261028/cache/{cache_digests[scope["id"]]} '
                 f'--component {scope["component"]} --contract --extended-identity '
                 f'--output {_relative(fresh_root / scope["run"] / ("verification-fresh" + ("" if scope["scope"] != "coverage-cpu" else "-cpu")))}')
                for scope in SCOPES],
            'external_self_test': [
                'PYTHONPATH=src:. python3 scripts/check_external_coverage_contract.py '
                f'--scope {scope["id"]} --self-test' for scope in SCOPES],
            'report': ('PYTHONPATH=src:. python3 '
                       'scripts/report_fresh_prefix_and_external_contract.py '
                       f'--runs-root {DEFAULT_RUNS} --fresh-root {DEFAULT_FRESH} '
                       f'--cpu-measurement {DEFAULT_CPU_MEASUREMENT} '
                       f'--output {DEFAULT_OUTPUT}'),
            'tests': ('PYTHONPATH=src:. python3 -m pytest '
                      'tests/integration/test_fresh_prefix_coverage.py '
                      'tests/integration/test_external_coverage_contract.py '
                      'tests/integration/test_new_path_coverage_measurement.py '
                      'tests/integration/test_coverage_comparison_contract.py -q'),
        },
        'limitations': LIMITATIONS,
    }
    return _display(report)



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-root', type=Path, default=ROOT / DEFAULT_RUNS)
    parser.add_argument('--fresh-root', type=Path, default=ROOT / DEFAULT_FRESH)
    parser.add_argument('--cpu-measurement', type=Path,
                        default=ROOT / DEFAULT_CPU_MEASUREMENT)
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    report = build_report(args.runs_root, args.fresh_root, args.cpu_measurement)
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    print(json.dumps({'status': 'reported',
                      'comparisons': report['fresh_comparisons'],
                      'external': report['external_contract']['status'],
                      'self_tests_ok': report['external_contract']['self_tests']['ok'],
                      'inputs': len(report['inputs'])}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
