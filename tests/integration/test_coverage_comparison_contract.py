"""The fixed comparison contract: identical DUT, point set, workload, budget, mode.

The contract only permits a covered/total comparison when both sides are
instrumented offline replays of the same DUT source set and point set, the same
recorded command sequence and the same replay budget.  Everything else is
``not_comparable``/``unavailable`` with no number.  The real CPU measurement of
the wb-timer run is checked as a concrete contract, and the committed package is
re-derived to keep it deterministic.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.measure_new_path_coverage import (CONTRACT_ID, _comparison_contract,
                                               compare_under_contract, measure)
from scripts.report_coverage_comparison_contract import (DEFAULT_CPU_MEASUREMENT,
                                                         DEFAULT_RUNS,
                                                         build_report)

SCRIPT = ROOT / 'scripts/report_coverage_comparison_contract.py'
DECLARED = ROOT / DEFAULT_RUNS
CPU_MEASUREMENT = ROOT / DEFAULT_CPU_MEASUREMENT
COMMITTED = ROOT / 'docs/reports/coverage-comparison-contract-20261030.json'


def _contract(covered=10, *, total=100, source='a' * 64, point='b' * 64,
              denominator='c' * 64, commands='d' * 64, count=5, ticks=5,
              replies='e' * 64, budget=None, coverage_mode='offline',
              online=False, instrumented=True, component='dut'):
    return {
        'schema_version': 'coverage_comparison_contract.v1',
        'contract': CONTRACT_ID,
        'status': 'available',
        'component': component,
        'metric': f'verilator-line-block:{component}:dut',
        'coverage_kind': 'verilator-line-block',
        'dut': {'component': component, 'source_file_count': 1,
                'source_files_sha256': source, 'point_set_sha256': point,
                'denominator_sha256': denominator, 'total_points': total,
                'covered_points': covered,
                'scope': 'points in declared structural-build DUT source files'},
        'workload': {'identity': 'recorded-command-sequence.v1', 'commands': count,
                     'commands_sha256': commands, 'replies_sha256': replies,
                     'local_ticks': ticks, 'reset_epochs': 0,
                     'includes_startup_reset': True,
                     'scope': 'every command accepted by the recorded session, in order'},
        'budget': {'replay': budget if budget is not None else {
                       'max_commands': 2048, 'max_input_bytes': 67108864,
                       'max_output_bytes': 67108864, 'max_wall_seconds': 60},
                   'executed_commands': count, 'search_budget': 'unknown',
                   'same_budget_rule': 'identical replay_budget keys and identical recorded command sequence'},
        'mode': {'coverage': coverage_mode, 'online': online,
                 'fixed_time_coverage': False, 'instrumented': instrumented,
                 'attestation': 'recorded-prefix-replay.v1'},
        'measurement': {'coverage_data_sha256': 'f' * 64, 'point_set_sha256': point,
                        'trace': 'trace.json', 'trace_sha256': '0' * 64},
        'rules': [],
        'limitations': [],
    }


def test_equal_contracts_compare_the_same_denominator():
    result = compare_under_contract(_contract(10), _contract(30))
    assert result['status'] == 'comparable_contract'
    assert result['reasons'] == []
    assert result['comparison']['total_points'] == 100
    assert result['comparison']['hit_delta'] == 20
    assert 'not a superiority claim' in result['comparison']['note']
    assert all(result['conditions'].values())


@pytest.mark.parametrize('change, reason', [
    ({'source': '1' * 64}, 'dut-source-set-mismatch'),
    ({'point': '2' * 64}, 'point-set-mismatch'),
    ({'denominator': '3' * 64}, 'denominator-mismatch'),
    ({'commands': '4' * 64}, 'workload-mismatch'),
    ({'count': 6}, 'workload-length-mismatch'),
    ({'ticks': 6}, 'workload-tick-mismatch'),
    ({'replies': '5' * 64}, 'replies-mismatch'),
    ({'budget': {'max_commands': 1024, 'max_input_bytes': 67108864,
                 'max_output_bytes': 67108864, 'max_wall_seconds': 60}},
     'budget-mismatch'),
    ({'online': True, 'coverage_mode': 'online'}, 'coverage-mode-mismatch'),
    ({'instrumented': False}, 'non-instrumented-prefix'),
])
def test_any_identity_difference_blocks_the_comparison(change, reason):
    result = compare_under_contract(_contract(10), _contract(30, **change))
    assert result['status'] == 'not_comparable'
    assert reason in result['reasons']
    assert result['comparison'] is None


def test_different_components_never_compare():
    result = compare_under_contract(_contract(10), _contract(30, component='other'))
    assert result['status'] == 'not_comparable'
    assert 'component-mismatch' in result['reasons']
    assert result['comparison'] is None


def test_unavailable_contract_never_becomes_a_number():
    missing = _contract(10)
    missing['status'] = 'unavailable'
    missing['dut'] = None
    result = compare_under_contract(missing, _contract(30))
    assert result['status'] == 'unavailable'
    assert 'contract-unavailable:left' in result['reasons']
    assert result['comparison'] is None


def test_missing_point_map_makes_the_contract_unavailable():
    coverage = {'point_set_sha256': None}
    contract = _comparison_contract('cpu', coverage, {'dut_sources': []}, [], [],
                                    measurement=ROOT, trace_path=ROOT)
    assert contract['status'] == 'unavailable'
    assert contract['reason'] == 'missing-point-set'
    assert contract['missing_inputs'] == ['coverage-points.json']
    assert contract['dut'] is None and 'covered' not in json.dumps(contract['dut'])


def _wb_timer_paths():
    original = DECLARED / 'wb-timer' / 'original'
    fresh = DECLARED / 'wb-timer' / 'fresh'
    summary_path = original / 'summary.json'
    if (not summary_path.is_file() or not CPU_MEASUREMENT.is_dir()
            or not (CPU_MEASUREMENT / 'coverage.json').is_file()):
        pytest.skip('measured CPU replay or saved prefixes unavailable')
    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    caches = {row['component']: Path(row['binary_path']).parent
              for row in summary['processes']}
    return original, fresh, caches


def test_real_cpu_measurement_has_a_complete_contract():
    original, fresh, caches = _wb_timer_paths()
    document = measure(original, measurement=CPU_MEASUREMENT, cache=caches['cpu'],
                       component='cpu', original_prefix=original,
                       fresh_prefix=fresh, contract=True)
    assert document['status'] == 'available'
    coverage = document['coverage']
    assert (coverage['covered'], coverage['total']) == (616, 1782)
    assert coverage['denominator_sha256'] == (
        '3611450ec1a63cccfd8f393d17875dc70f39a8bd7dc9314fc1d31777550c5280')
    assert coverage['point_set_sha256'] == (
        '568adb352f8d46a13e8fb9b4356a1864fe6cefc8ceba80e8707b681d48f0aaaa')
    assert coverage['coverage_data_sha256'] == (
        'eb75992b89e9af9b90c56a664aa0ed4ec201d4b94f5b5d13055942e2579f86ed')
    saved = json.loads((CPU_MEASUREMENT / 'coverage.json').read_text(encoding='utf-8'))
    assert saved['build_jobs'] == 4
    assert saved['build_executed_argv'][saved['build_executed_argv'].index('-j') + 1] == '4'
    assert saved['build_argv'][saved['build_argv'].index('-j') + 1] == '8'
    contract = document['comparison_contract']
    assert contract['status'] == 'available'
    assert contract['contract'] == CONTRACT_ID
    assert contract['component'] == 'cpu'
    assert contract['metric'] == 'verilator-line-block:cpu:dut'
    assert contract['dut']['source_file_count'] == 45
    assert contract['dut']['denominator_sha256'] == coverage['denominator_sha256']
    assert contract['dut']['point_set_sha256'] == coverage['point_set_sha256']
    assert contract['dut']['total_points'] == coverage['total']
    assert contract['dut']['covered_points'] == coverage['covered']
    assert contract['workload']['commands'] == coverage['commands']['count'] == 105
    assert contract['workload']['local_ticks'] == coverage['local_ticks'] == 105
    assert len(contract['workload']['commands_sha256']) == 64
    assert contract['budget']['replay']['max_commands'] == 2048
    assert contract['budget']['replay']['max_wall_seconds'] == 60
    assert contract['budget']['search_budget'] == 'unknown'
    assert contract['mode'] == {'coverage': 'offline', 'online': False,
                                'fixed_time_coverage': False, 'instrumented': True,
                                'attestation': 'recorded-prefix-replay.v1'}
    assert contract['measurement']['coverage_data_sha256'] == \
        coverage['coverage_data_sha256']
    # The same contract compares to itself; a different component never does.
    assert compare_under_contract(contract, copy.deepcopy(contract))['status'] == \
        'comparable_contract'
    assert document['comparability']['status'] == 'comparable_prefix'


def test_cpu_contract_never_matches_the_timer_contract():
    original, fresh, caches = _wb_timer_paths()
    cpu = measure(original, measurement=CPU_MEASUREMENT, cache=caches['cpu'],
                  component='cpu', original_prefix=original, fresh_prefix=fresh,
                  contract=True)['comparison_contract']
    timer = measure(original, measurement=DECLARED / 'wb-timer' / 'coverage-target',
                    cache=caches['wb_timer_active'], component='wb_timer_active',
                    original_prefix=original, fresh_prefix=fresh,
                    contract=True)['comparison_contract']
    assert cpu['status'] == timer['status'] == 'available'
    result = compare_under_contract(cpu, timer)
    assert result['status'] == 'not_comparable'
    assert result['comparison'] is None
    assert 'component-mismatch' in result['reasons']
    assert 'dut-source-set-mismatch' in result['reasons']


def test_committed_contract_report_matches_a_fresh_derivation():
    if not COMMITTED.is_file():
        pytest.skip('committed contract package unavailable')
    committed = json.loads(COMMITTED.read_text(encoding='utf-8'))
    assert committed == build_report()
    assert committed['schema_version'] == 'coverage_comparison_contract_report.v1'
    assert committed['contract'] == CONTRACT_ID
    assert committed['coverage_mode'] == 'offline'
    assert committed['online'] is False
    assert len(committed['measured']) == 4
    assert {row['run'] for row in committed['measured']} == {
        'wb-timer', 'apb-spi', 'ahb-sha'}
    assert all(row['contract'] == 'available' for row in committed['measured'])
    assert all(row['comparability'] == 'comparable_prefix'
               for row in committed['measured'])
    assert all(pair['status'] == 'not_comparable'
               for pair in committed['same_contract_pairs'])
    assert committed['external_comparison']['status'] == 'unavailable'
    assert committed['external_comparison']['reason'] == \
        'no-second-tool-measurement-under-this-contract'
    assert committed['aggregate'] is None
    reasons = {row['reason'] for row in committed['unavailable']}
    assert reasons == {'incomplete-saved-measurement',
                       'missing-per-component-command-trace'}
    assert committed['shared_six']['enable_with'].endswith('--native')
    assert len(committed['inputs']) > 50
    assert all(len(digest) == 64 for digest in committed['inputs'].values())


def test_contract_report_cli_writes_the_same_document(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--output', str(tmp_path / 'report.json')],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    printed = json.loads(completed.stdout)
    assert printed['status'] == 'reported'
    assert printed['measured'] == 4
    written = json.loads((tmp_path / 'report.json').read_text(encoding='utf-8'))
    if COMMITTED.is_file():
        assert written == json.loads(COMMITTED.read_text(encoding='utf-8'))
