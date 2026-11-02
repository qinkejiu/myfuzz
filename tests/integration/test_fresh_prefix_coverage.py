"""Instrumented fresh-prefix coverage and the original-vs-fresh comparison.

The four declared-IRQ F5 scopes (three target scopes plus the wb-timer CPU side)
are measured a second time: the run's own saved *fresh* command prefix is
converted to ``local_command_trace.v1`` by an explicit converter, replayed on the
same pinned build with the same instrumentation, and compared with the
instrumented original prefix under ``dut-line-block/offline-recorded-prefix.v1``.

Every positive case re-reads real saved artifacts read-only; nothing is rebuilt
here.  The negative cases are the contract this package exists for: a fresh
measurement that is missing, or a comparison whose point set, workload, budget,
mode or instrumentation differs, is never turned into a covered/total pair.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.measure_new_path_coverage import (compare_under_contract, measure)
from scripts.normalize_fresh_local_commands import (normalize, validate_raw_sessions,
                                                    Refused, find_raw_commands)
from scripts.report_fresh_prefix_and_external_contract import (DEFAULT_CPU_MEASUREMENT,
                                                              DEFAULT_FRESH,
                                                              DEFAULT_RUNS,
                                                              SCOPES,
                                                              build_report)

DECLARED = ROOT / DEFAULT_RUNS
FRESH = ROOT / DEFAULT_FRESH
CPU_MEASUREMENT = ROOT / DEFAULT_CPU_MEASUREMENT
COMMITTED = ROOT / 'docs/reports/coverage-fresh-prefix-and-external-contract-20261030.json'
EXPECTED = {
    'wb-timer/coverage-target': ('wb_timer_active', 37, 39, 116),
    'wb-timer/coverage-cpu': ('cpu', 616, 1782, 105),
    'apb-spi/coverage-target': ('spi_active', 85, 271, 112),
    'ahb-sha/coverage-target': ('sha_active', 359, 614, 146),
}
CONDITIONS = ('same_component', 'same_metric', 'same_dut_sources', 'same_point_set',
              'same_denominator', 'same_workload', 'same_command_count',
              'same_local_ticks', 'same_replies', 'same_replay_budget',
              'same_coverage_mode', 'both_instrumented')


def _summary(run):
    original = DECLARED / run / 'original'
    summary = json.loads((original / 'summary.json').read_text(encoding='utf-8'))
    return original, {row['component']: Path(row['binary_path']).parent
                      for row in summary['processes']}


def _original_measurement(scope):
    if scope['original'] == 'cpu':
        return CPU_MEASUREMENT
    return DECLARED / scope['run'] / scope['scope']


def _contracts(scope):
    original, caches = _summary(scope['run'])
    cache = caches[scope['component']]
    fresh_trace = FRESH / scope['run'] / 'normalized-local-command-trace.json'
    original_document = measure(original, measurement=_original_measurement(scope),
                                cache=cache, component=scope['component'],
                                original_prefix=original,
                                fresh_prefix=DECLARED / scope['run'] / 'fresh',
                                contract=True, extended_identity=True)
    fresh_document = measure(fresh_trace,
                             measurement=FRESH / scope['run'] / scope['scope'],
                             cache=cache, component=scope['component'],
                             contract=True, extended_identity=True)
    return original_document, fresh_document


def _available(scope):
    original, caches = _summary(scope['run'])
    fresh_trace = FRESH / scope['run'] / 'normalized-local-command-trace.json'
    if (not (FRESH / scope['run'] / scope['scope'] / 'coverage.json').is_file()
            or not fresh_trace.is_file() or not _original_measurement(scope).is_dir()):
        pytest.skip('fresh or original instrumented measurement unavailable')
    return original, caches


# --- converter -------------------------------------------------------------

def _raw_session(component, nonce, records=2):
    return {
        'component': component, 'complete': True,
        'identity': {'component': component, 'execution_nonce': nonce,
                     'build_digest': 'b' * 64, 'binary_sha256': 'c' * 64,
                     'artifact_digest': 'a' * 64},
        'records': [{'sequence': index, 'reset_epoch': 0, 'tick_before': index - 1,
                     'tick_after': index,
                     'command': f'CMD {nonce} {index:x} STEP 0',
                     'reply': f'RESULT {nonce} {index:x} 0 1 00'}
                    for index in range(1, records + 1)],
    }


def test_real_fresh_raw_list_converts_with_recorded_provenance(tmp_path):
    raw = find_raw_commands(DECLARED / 'wb-timer' / 'fresh')
    provenance = normalize(raw, tmp_path / 'trace.json', tmp_path / 'provenance.json')
    trace = json.loads((tmp_path / 'trace.json').read_text(encoding='utf-8'))
    assert trace['schema_version'] == 'local_command_trace.v1'
    assert sorted(trace['sessions']) == ['cpu', 'wb_timer_active', 'wb_timer_idle']
    assert provenance['schema_version'] == 'local_command_trace_normalization.v1'
    assert len(provenance['input']['sha256']) == 64
    assert len(provenance['output']['sha256']) == 64
    assert len(provenance['converter_sha256']) == 64
    assert provenance['components']['wb_timer_active']['records'] == 110
    assert provenance['components']['wb_timer_active']['local_ticks'] == 116
    # Deterministic: a second conversion is byte-identical.
    normalize(raw, tmp_path / 'again.json', tmp_path / 'again.provenance.json')
    assert ((tmp_path / 'trace.json').read_bytes()
            == (tmp_path / 'again.json').read_bytes())


def test_converter_refuses_already_normalized_input(tmp_path):
    document = {'schema_version': 'local_command_trace.v1', 'sessions': {}}
    path = tmp_path / 'trace.json'
    path.write_text(json.dumps(document), encoding='utf-8')
    with pytest.raises(Refused, match='already-normalized'):
        normalize(path, tmp_path / 'out.json', tmp_path / 'prov.json')


@pytest.mark.parametrize('mutation, reason', [
    (lambda row: row.pop('component'), 'session-component-invalid'),
    (lambda row: row.update(complete=False), 'session-incomplete:wb_timer_active'),
    (lambda row: row['identity'].update(execution_nonce='not-a-nonce'),
     'session-nonce-invalid:wb_timer_active'),
    (lambda row: row['records'][1].update(sequence=7), 'record-invalid:wb_timer_active:2'),
    (lambda row: row['records'][1].update(tick_after='3'),
     'record-invalid:wb_timer_active:2'),
    (lambda row: row['records'][1].update(command='CMD 0' + '0' * 31 + ' 2 X'),
     'record-invalid:wb_timer_active:2'),
])
def test_converter_refuses_malformed_rows(tmp_path, mutation, reason):
    row = _raw_session('wb_timer_active', '1' * 32)
    mutation(row)
    path = tmp_path / 'raw.json'
    path.write_text(json.dumps([row]), encoding='utf-8')
    with pytest.raises(Refused, match=reason):
        normalize(path, tmp_path / 'out.json', tmp_path / 'prov.json')
    assert not (tmp_path / 'out.json').exists()


def test_converter_refuses_duplicate_components(tmp_path):
    row = _raw_session('wb_timer_active', '1' * 32)
    with pytest.raises(Refused, match='session-component-duplicate'):
        validate_raw_sessions([row, copy.deepcopy(row)])


# --- measured fresh coverage and the original-vs-fresh contract ------------

@pytest.mark.parametrize('scope_id', sorted(EXPECTED))
def test_fresh_prefix_is_measured_on_the_same_build(scope_id):
    scope = next(item for item in SCOPES if item['id'] == scope_id)
    _available(scope)
    original_document, fresh_document = _contracts(scope)
    component, covered, total, ticks = EXPECTED[scope_id]
    assert original_document['status'] == fresh_document['status'] == 'available'
    for document, label in ((original_document, 'original'), (fresh_document, 'fresh')):
        coverage = document['coverage']
        assert coverage['component'] == component
        assert (coverage['covered'], coverage['total']) == (covered, total)
        assert coverage['local_ticks'] == ticks
        assert coverage['metric'] == f'verilator-line-block:{component}:dut'
        assert coverage['online'] is False and coverage['fixed_time_coverage'] is False
        assert coverage['includes_startup_reset'] is True
        # Extended identity: explicit budget record and normalised point set.
        record = coverage['budget_record']
        assert record['schema_version'] == 'offline_replay_budget.v1'
        assert record['mode'] == 'offline'
        assert record['commands'] == record['executed_commands']
        assert record['search_budget'] == 'unknown'
        assert record['tool_version']['name'] == 'verilator'
        assert record['tool_version']['identity_source'] == 'cache-manifest'
        assert record['build_digest'] == coverage['original_build_digest']
        assert set(record['replay_bounds']) == {'max_commands', 'max_input_bytes',
                                                'max_output_bytes', 'max_wall_seconds'}
        assert coverage['point_set_normalized_sha256'] == coverage['denominator_sha256']
        assert len(coverage['point_universe_sha256']) == 64
        contract = document['comparison_contract']
        assert contract['status'] == 'available'
        assert contract['dut']['point_set_normalized_sha256'] == coverage['denominator_sha256']
        assert contract['budget']['build_digest'] == coverage['original_build_digest']
        assert contract['budget']['local_ticks'] == ticks
        assert contract['budget']['tool_version']['name'] == 'verilator'


@pytest.mark.parametrize('scope_id', sorted(EXPECTED))
def test_original_and_fresh_compare_as_the_same_contract(scope_id):
    scope = next(item for item in SCOPES if item['id'] == scope_id)
    _available(scope)
    original_document, fresh_document = _contracts(scope)
    result = compare_under_contract(original_document['comparison_contract'],
                                    fresh_document['comparison_contract'])
    assert result['status'] == 'comparable_contract'
    assert result['reasons'] == []
    assert all(result['conditions'][name] is True for name in CONDITIONS)
    comparison = result['comparison']
    component, covered, total, _ = EXPECTED[scope_id]
    assert comparison['total_points'] == total
    assert comparison['left'] == {'covered': covered, 'total': total}
    assert comparison['right'] == {'covered': covered, 'total': total}
    assert comparison['hit_delta'] == 0
    assert 'not a superiority claim' in comparison['note']
    identity = result['point_set_identity']
    assert identity['basis'] == 'normalized-point-identities'
    assert identity['left'] == identity['right']
    saved = identity['saved_point_map_sha256']
    # The saved maps embed their own build directory, so they differ by design.
    assert saved['left'] != saved['right']
    assert len(saved['note']) > 0


_CONDITION_REASONS = (
    ('dut', 'point_universe_sha256', '0' * 64, 'point-set-mismatch'),
    ('dut', 'denominator_sha256', '1' * 64, 'denominator-mismatch'),
    ('dut', 'source_files_sha256', '2' * 64, 'dut-source-set-mismatch'),
    ('workload', 'commands_sha256', '3' * 64, 'workload-mismatch'),
    ('workload', 'commands', 1, 'workload-length-mismatch'),
    ('workload', 'local_ticks', 0, 'workload-tick-mismatch'),
    ('workload', 'replies_sha256', '4' * 64, 'replies-mismatch'),
    ('budget', 'replay', {'max_commands': 1, 'max_input_bytes': 1,
                          'max_output_bytes': 1, 'max_wall_seconds': 1},
     'budget-mismatch'),
    ('mode', 'instrumented', False, 'non-instrumented-prefix'),
    ('mode', 'coverage', 'online', 'coverage-mode-mismatch'),
)


@pytest.mark.parametrize('section, key, value, reason', _CONDITION_REASONS)
def test_any_identity_difference_blocks_the_fresh_comparison(section, key, value, reason):
    scope = next(item for item in SCOPES if item['id'] == 'wb-timer/coverage-target')
    _available(scope)
    original_document, fresh_document = _contracts(scope)
    changed = copy.deepcopy(fresh_document['comparison_contract'])
    changed[section][key] = value
    result = compare_under_contract(original_document['comparison_contract'], changed)
    assert result['status'] == 'not_comparable'
    assert reason in result['reasons']
    assert result['comparison'] is None


def test_missing_fresh_measurement_never_compares(tmp_path):
    scope = next(item for item in SCOPES if item['id'] == 'wb-timer/coverage-target')
    _available(scope)
    original, caches = _summary(scope['run'])
    document = measure(FRESH / scope['run'] / 'normalized-local-command-trace.json',
                       measurement=tmp_path / 'absent', cache=caches[scope['component']],
                       component=scope['component'], contract=True,
                       extended_identity=True)
    assert document['status'] == 'unavailable'
    assert document['reason'] == 'incomplete-saved-measurement'
    assert document['coverage'] is None
    assert 'covered' not in json.dumps(document.get('coverage'))


def test_extended_identity_is_off_by_default():
    scope = next(item for item in SCOPES if item['id'] == 'wb-timer/coverage-target')
    _available(scope)
    original, caches = _summary(scope['run'])
    document = measure(original, measurement=DECLARED / scope['run'] / scope['scope'],
                       cache=caches[scope['component']],
                       component=scope['component'], contract=True)
    coverage = document['coverage']
    assert 'budget_record' not in coverage
    assert 'point_universe_sha256' not in coverage
    assert 'point_set_normalized_sha256' not in coverage
    contract = document['comparison_contract']
    assert 'point_universe_sha256' not in contract['dut']
    assert 'tool_version' not in contract['budget']


# --- the package -----------------------------------------------------------

@pytest.fixture(scope='module')
def report():
    if not FRESH.is_dir():
        pytest.skip('fresh-prefix measurements unavailable')
    return build_report()


def test_report_records_four_comparable_fresh_comparisons(report):
    assert report['schema_version'] == (
        'coverage_fresh_prefix_and_external_contract_report.v1')
    assert report['contract'] == 'dut-line-block/offline-recorded-prefix.v1'
    assert report['coverage_mode'] == 'offline'
    assert report['online'] is False and report['fixed_time_coverage'] is False
    assert report['coverage_auc_available'] is False
    assert report['native_authority'] is False
    assert report['aggregate'] is None and report['aggregate_reason']
    comparisons = report['fresh_comparisons']
    assert comparisons['checked'] == 4
    assert comparisons['comparable'] == 4
    assert comparisons['not_comparable'] == 0 and comparisons['unavailable'] == 0
    assert comparisons['coverage_comparison_available'] is True
    measured = {row['scope']: row for row in report['measured']}
    assert set(measured) == set(EXPECTED)
    for scope_id, (component, covered, total, _) in EXPECTED.items():
        row = measured[scope_id]
        assert row['component'] == component
        assert row['original'] == {'covered': covered, 'total': total}
        assert row['fresh'] == {'covered': covered, 'total': total}
        assert row['comparison'] == 'comparable_contract'
        assert row['hit_delta'] == 0
    for scope in report['scopes']:
        assert scope['status'] == 'comparable'
        assert scope['coverage_comparison_available'] is True
        assert scope['reason'] is None
        assert scope['comparison']['status'] == 'comparable_contract'
        assert scope['comparison']['reasons'] == []
        assert scope['original']['coverage']['point_set_sha256'] != \
            scope['fresh']['coverage']['point_set_sha256']
        assert scope['original']['coverage']['point_set_normalized_sha256'] == \
            scope['fresh']['coverage']['point_set_normalized_sha256']


def test_report_records_the_converter_and_build_evidence(report):
    assert set(report['normalized_traces']) == {'wb-timer', 'apb-spi', 'ahb-sha'}
    for run, row in report['normalized_traces'].items():
        assert row['status'] == 'available'
        assert row['converter'] == 'scripts/normalize_fresh_local_commands.py'
        assert len(row['converter_sha256']) == 64
        assert len(row['trace_sha256']) == 64
        assert len(row['source']['sha256']) == 64
        assert row['source']['path'].endswith('fresh/fresh/local_commands.json')
        assert row['components']
    builds = {row['scope']: row for row in report['builds']}
    assert set(builds) == set(EXPECTED)
    for row in builds.values():
        assert row['exit_code'] == 0
        assert '--build-jobs 4' in row['command']
        assert 'flock /tmp/myfuzz-native.lock' in row['lock']
        assert row['time']['wall_seconds'] > 0
        assert row['time']['peak_rss_kb'] > 0
        assert row['stdout'] and '"status": "measured"' in row['stdout']


def test_report_keeps_the_external_comparison_unavailable(report):
    external = report['external_contract']
    assert external['status'] == 'unavailable'
    assert external['reason'] == 'no-external-tool-measurement'
    assert external['network_required'] is False
    assert external['harness'] == 'scripts/check_external_coverage_contract.py'
    assert external['schema_version'] == 'external_coverage_measurement.v1'
    assert external['schema']['additionalProperties'] is False
    assert external['self_tests']['ok'] is True
    assert external['self_tests']['scopes'] == 4
    assert external['self_tests']['checked'] == 76
    assert external['self_tests']['comparable'] == 4
    assert external['self_tests']['not_comparable'] == 72
    assert external['steps_for_third_party']
    assert 'no external covered/total is published' in external['claim']
    assert report['what_stays_unavailable']
    reasons = {row['reason'] for row in report['what_stays_unavailable']}
    assert 'no-external-tool-measurement' in reasons
    assert 'search-budget-not-recorded' in reasons


def test_report_records_real_input_hashes(report):
    assert report['inputs']
    for relative, digest in report['inputs'].items():
        path = ROOT / relative
        assert path.is_file(), relative
        assert len(digest) == 64
        assert sha256(path.read_bytes()).hexdigest() == digest, relative
    for scope in report['scopes']:
        for side in ('original', 'fresh'):
            name = f"{scope[side]['coverage']['measurement']}/coverage.dat"
            assert name in report['inputs']


def test_report_without_fresh_measurements_publishes_no_number(tmp_path):
    if not DECLARED.is_dir():
        pytest.skip('declared-IRQ F5 saved runs unavailable')
    report = build_report(DEFAULT_RUNS, tmp_path / 'absent-fresh', DEFAULT_CPU_MEASUREMENT)
    assert report['fresh_comparisons']['checked'] == 4
    assert report['fresh_comparisons']['comparable'] == 0
    assert report['fresh_comparisons']['unavailable'] == 4
    assert report['fresh_comparisons']['coverage_comparison_available'] is False
    assert report['measured'] == []
    for scope in report['scopes']:
        assert scope['status'] == 'unavailable'
        assert scope['coverage_comparison_available'] is False
        assert scope['fresh']['status'] == 'unavailable'
        assert scope['fresh']['reason'] in ('incomplete-saved-measurement',
                                            'missing-local-command-trace')
        assert scope['fresh']['coverage'] is None
        assert scope['comparison'] is None
    unavailable = {row['scope'] for row in report['unavailable']}
    assert len(unavailable) == 4
    assert report['external_contract']['self_tests']['checked'] == 0
    assert report['external_contract']['self_tests']['ok'] is False


def test_committed_twin_matches_a_fresh_derivation(report):
    if not COMMITTED.is_file():
        pytest.skip('committed fresh-prefix package unavailable')
    assert json.loads(COMMITTED.read_text(encoding='utf-8')) == report


def test_report_cli_writes_the_same_document(tmp_path):
    completed = subprocess.run(
        [sys.executable,
         str(ROOT / 'scripts/report_fresh_prefix_and_external_contract.py'),
         '--output', str(tmp_path / 'report.json')],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    printed = json.loads(completed.stdout)
    assert printed['status'] == 'reported'
    assert printed['comparisons']['comparable'] == 4
    assert printed['external'] == 'unavailable'
    written = json.loads((tmp_path / 'report.json').read_text(encoding='utf-8'))
    if COMMITTED.is_file():
        assert written == json.loads(COMMITTED.read_text(encoding='utf-8'))
