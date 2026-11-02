"""New-path coverage measurement: unavailable beats an invented number.

The positive cases reuse a real saved offline measurement and its original
cache read-only; nothing is rebuilt or replayed here.  The negative cases are
the contract this script exists for: a missing input must yield ``unavailable``
with an exact reason and no coverage figure at all.

The declared-IRQ F5 cases add the second contract: the comparability document is
derived from the run's *own* original/fresh prefixes, so a reply or tick
mismatch makes the comparability unavailable while the measured coverage of the
original prefix stays measured -- and the fresh prefix never becomes a number.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/measure_new_path_coverage.py'
REPORT_SCRIPT = ROOT / 'scripts/report_declared_f5_coverage.py'
DECLARED = (ROOT / 'research/input-strategy-audit-20261027/runs/'
            'declared-irq-f5-20261030')
NOT_RUN = ('available',)
_EXPECTED = {
    'wb-timer': {'component': 'wb_timer_active', 'covered': 37, 'total': 39,
                 'local_ticks': 116, 'results': 110},
    'apb-spi': {'component': 'spi_active', 'covered': 85, 'total': 271,
                'local_ticks': 112, 'results': 106},
    'ahb-sha': {'component': 'sha_active', 'covered': 359, 'total': 614,
                'local_ticks': 146, 'results': 134},
}
_COVERAGE_KEYS = {'covered', 'total', 'hit_delta', 'left_hit_points',
                  'right_hit_points', 'total_points'}


def _measure(run, **kwargs):
    sys.path.insert(0, str(ROOT))
    from scripts.measure_new_path_coverage import measure
    return measure(run, **kwargs)


def _build_report():
    sys.path.insert(0, str(ROOT))
    from scripts.report_declared_f5_coverage import build_report
    return build_report(DECLARED)


def _keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _keys(item)


def _assert_no_coverage_number(document):
    assert document.get('coverage') is None
    assert not (_COVERAGE_KEYS & set(_keys(document)))


def _assert_unavailable(document, reason):
    assert document['status'] == 'unavailable'
    assert document['reason'] == reason or document['reason'].startswith(reason)
    assert document['coverage'] is None and document['comparability'] is None
    assert 'covered' not in document and 'total' not in document
    assert document['native_authority'] is False


def test_missing_run_directory_is_unavailable(tmp_path):
    measurement = tmp_path / 'measurement'
    measurement.mkdir()
    document = _measure(tmp_path / 'absent', measurement=measurement,
                        cache=tmp_path / 'cache')
    _assert_unavailable(document, 'missing-local-command-trace')
    assert document['missing_inputs'] == ['local_commands.json']


def test_missing_measurement_files_are_unavailable(tmp_path):
    run = tmp_path / 'run'
    run.mkdir()
    (run / 'local_commands.json').write_text('{}', encoding='utf-8')
    measurement = tmp_path / 'measurement'
    measurement.mkdir()
    (measurement / 'coverage.json').write_text('{}', encoding='utf-8')
    document = _measure(run, measurement=measurement, cache=tmp_path / 'cache')
    _assert_unavailable(document, 'incomplete-saved-measurement')
    assert 'coverage.dat' in document['missing_inputs']
    assert 'obj/harness' in document['missing_inputs']


def test_missing_original_cache_is_unavailable(tmp_path):
    run = tmp_path / 'run'
    run.mkdir()
    (run / 'local_commands.json').write_text('{}', encoding='utf-8')
    measurement = tmp_path / 'measurement'
    for name in ('coverage.json', 'coverage.dat', 'commands.txt', 'replies.txt',
                 'obj/harness', 'inputs/generated/driver.cpp',
                 'inputs/generated/artifact.json'):
        path = measurement / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('', encoding='utf-8')
    document = _measure(run, measurement=measurement, cache=tmp_path / 'cache')
    _assert_unavailable(document, 'missing-original-cache')
    assert document['missing_inputs'] == ['manifest.json']


def test_unverifiable_saved_measurement_is_unavailable(tmp_path):
    run = tmp_path / 'run'
    run.mkdir()
    (run / 'local_commands.json').write_text('{"sessions": {}}', encoding='utf-8')
    measurement = tmp_path / 'measurement'
    for name in ('coverage.json', 'coverage.dat', 'commands.txt', 'replies.txt',
                 'obj/harness', 'inputs/generated/driver.cpp',
                 'inputs/generated/artifact.json'):
        path = measurement / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}', encoding='utf-8')
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / 'manifest.json').write_text('{"identity": {}}', encoding='utf-8')
    document = _measure(run, measurement=measurement, cache=cache)
    _assert_unavailable(document, 'saved-measurement-unverified')
    assert document['coverage'] is None


def test_cli_reports_unavailable_and_exits_nonzero(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--run', str(tmp_path / 'absent'),
         '--measurement', str(tmp_path / 'absent-measurement'),
         '--cache', str(tmp_path / 'absent-cache'), '--output', str(tmp_path / 'out')],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 1
    printed = json.loads(completed.stdout)
    assert printed['status'] == 'unavailable'
    saved = json.loads((tmp_path / 'out/summary.json').read_text(encoding='utf-8'))
    assert saved['status'] == 'unavailable' and saved['coverage'] is None
    assert not (tmp_path / 'out/coverage.json').exists()


def _case_paths():
    """Real saved measurement, trace and original cache, or None."""
    measurement = (ROOT / 'research/input-strategy-audit-20261027/runs/'
                   'adapter-matrix-20261029/spi-cv32e20-v1/seed-7-state-none')
    pipeline = measurement / 'coverage-measurement/coverage-pipeline.json'
    if not pipeline.is_file():
        return None
    document = json.loads(pipeline.read_text(encoding='utf-8'))
    cache = Path(document['original_cache'])
    run = measurement / 'original'
    saved = measurement / 'coverage-measurement/measurement'
    if ((cache / 'manifest.json').is_file() is False
            or (run / 'local_commands.json').is_file() is False):
        return None
    return {'run': run, 'measurement': saved, 'cache': cache}


def test_real_saved_measurement_yields_line_block_coverage():
    case = _case_paths()
    if case is None:
        pytest.skip('saved coverage measurement/cache unavailable')
    document = _measure(case['run'], measurement=case['measurement'],
                        cache=case['cache'], focus='spi_master_controller')
    assert document['status'] == 'available'
    coverage = document['coverage']
    assert coverage['metric'] == 'verilator-line-block:peripheral:dut'
    assert coverage['attestation'] == 'recorded-prefix-replay.v1'
    assert 0 < coverage['covered'] <= coverage['total']
    assert coverage['online'] is False and coverage['fixed_time_coverage'] is False
    assert coverage['includes_startup_reset'] is True
    assert sum(row['covered'] for row in coverage['files'].values()) == coverage['covered']
    assert sum(row['total'] for row in coverage['files'].values()) == coverage['total']
    # The new declared-IRQ path is exercised inside the SPI controller.
    assert document['focus']['files']
    assert all('spi_master_controller' in name for name in document['focus']['files'])
    assert 0 < document['focus']['covered'] <= document['focus']['total']
    assert document['comparability']['status'] == 'not_comparable'
    assert document['comparability']['reasons'] == ['no-baseline-measurement']
    assert document['native_authority'] is False


def test_real_pair_produces_an_honest_comparability_document():
    parent = (ROOT / 'research/input-strategy-audit-20261027/runs/'
              'automatic-coverage-20261028/compare')
    current_root = parent / 'seed-7-state-none'
    baseline_root = parent / 'seed-7-uniform-none'
    current_pipeline = current_root / 'coverage-measurement/coverage-pipeline.json'
    baseline_pipeline = baseline_root / 'coverage-measurement/coverage-pipeline.json'
    if (not current_pipeline.is_file() or not baseline_pipeline.is_file()
            or not (baseline_root / 'original/local_commands.json').is_file()):
        pytest.skip('saved paired coverage measurements unavailable')
    current = json.loads(current_pipeline.read_text(encoding='utf-8'))
    document = _measure(current_root / 'original',
                        measurement=current_root / 'coverage-measurement/measurement',
                        cache=Path(current['original_cache']),
                        baseline_measurement=(baseline_root
                                              / 'coverage-measurement/measurement'),
                        baseline_run=baseline_root / 'original')
    assert document['status'] == 'available'
    comparability = document['comparability']
    assert comparability['status'] in ('comparable_points', 'incomparable')
    conditions = comparability['conditions']
    for name in ('seed', 'time_budget', 'execution_budget',
                 'process_independence', 'fairness'):
        assert conditions[name] == 'unknown'
    if comparability['status'] == 'comparable_points':
        assert comparability['comparison']['coverage']['total_points'] > 0
        assert comparability['comparison']['dut_coverage']['total_points'] > 0
        block = comparability['comparison']
        assert 'superior' not in json.dumps(block).lower()
        assert 'winner' not in json.dumps(block).lower()
    else:
        assert comparability['reasons']


def test_cli_prints_the_measured_ratio_without_native_authority(tmp_path):
    case = _case_paths()
    if case is None:
        pytest.skip('saved coverage measurement/cache unavailable')
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--run', str(case['run']),
         '--measurement', str(case['measurement']), '--cache', str(case['cache']),
         '--output', str(tmp_path)],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    printed = json.loads(completed.stdout)
    assert printed['status'] == 'available'
    assert 0 < printed['covered'] <= printed['total']
    summary = json.loads((tmp_path / 'summary.json').read_text(encoding='utf-8'))
    assert summary['native_authority'] is False
    assert summary['coverage']['covered'] == printed['covered']
    assert (tmp_path / 'comparability.json').is_file()


# --- declared-IRQ F5: own original/fresh prefixes, real saved artifacts -----

def _declared_case(name):
    """Saved original/fresh prefixes plus the verified target measurement."""
    run = DECLARED / name
    original, fresh = run / 'original', run / 'fresh'
    summary_path = original / 'summary.json'
    if not summary_path.is_file():
        return None
    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    component = summary.get('target')
    row = next((process for process in summary.get('processes', [])
                if process.get('component') == component), None)
    if row is None or not isinstance(row.get('binary_path'), str):
        return None
    cache = Path(row['binary_path']).parent
    measurement = run / 'coverage-target'
    if not (cache / 'manifest.json').is_file() or not measurement.is_dir():
        return None
    return {'run': original, 'measurement': measurement, 'cache': cache,
            'component': component, 'original': original, 'fresh': fresh}


def test_declared_f5_own_prefix_pair_is_comparable_and_measured():
    case = _declared_case('apb-spi')
    if case is None:
        pytest.skip('declared-IRQ F5 saved prefixes unavailable')
    document = _measure(case['run'], measurement=case['measurement'],
                        cache=case['cache'], component=case['component'],
                        original_prefix=case['original'],
                        fresh_prefix=case['fresh'])
    assert document['status'] == 'available'
    coverage = document['coverage']
    expected = _EXPECTED['apb-spi']
    assert coverage['metric'] == 'verilator-line-block:spi_active:dut'
    assert coverage['coverage_kind'] == 'verilator-line-block'
    assert (coverage['covered'], coverage['total']) == (expected['covered'],
                                                        expected['total'])
    assert coverage['local_ticks'] == expected['local_ticks']
    assert coverage['reply_results'] == coverage['commands']['count']
    assert coverage['includes_startup_reset'] is True
    comparability = document['comparability']
    assert comparability['status'] == 'comparable_prefix'
    assert comparability['mode'] == 'own-original-fresh-prefix'
    assert comparability['reasons'] == []
    assert comparability['comparison'] is None
    assert comparability['coverage_comparison_available'] is False
    assert comparability['coverage_comparison_reason'] == 'fresh-prefix-not-instrumented'
    conditions = comparability['conditions']
    for name in ('same_config', 'same_admission', 'same_artifacts', 'same_case',
                 'same_group', 'same_build_digest', 'same_binary',
                 'same_command_count', 'same_commands', 'same_replies',
                 'same_local_ticks', 'both_exit_zero', 'matches_measured_prefix'):
        assert conditions[name] is True, name
    for name in ('seed', 'time_budget', 'execution_budget', 'fairness'):
        assert conditions[name] == 'unknown'
    assert conditions['process_independence'] == 'separate-invocations'
    prefixes = comparability['prefixes']
    assert prefixes['build_digest'] == coverage['original_build_digest']
    assert prefixes['binary_sha256'] == coverage['original_binary_sha256']
    assert prefixes['local_ticks'] == coverage['local_ticks']
    assert prefixes['commands'] == coverage['commands']['count']
    assert prefixes['original']['process_exit_codes'][case['component']] == 0
    assert prefixes['fresh']['process_exit_codes'][case['component']] == 0
    assert len(prefixes['fresh']['trace_sha256']) == 64
    # No coverage comparison exists, so no superiority statement can exist.
    assert comparability['comparison'] is None
    assert 'dut_coverage' not in comparability


@pytest.mark.parametrize('name', ('wb-timer', 'apb-spi', 'ahb-sha'))
def test_declared_f5_each_run_measures_the_expected_ratio(name):
    case = _declared_case(name)
    if case is None:
        pytest.skip('declared-IRQ F5 saved prefixes unavailable')
    document = _measure(case['run'], measurement=case['measurement'],
                        cache=case['cache'], component=case['component'],
                        original_prefix=case['original'],
                        fresh_prefix=case['fresh'])
    assert document['status'] == 'available'
    coverage = document['coverage']
    expected = _EXPECTED[name]
    assert coverage['component'] == expected['component']
    assert coverage['covered'] == expected['covered']
    assert coverage['total'] == expected['total']
    assert coverage['source_selection']['dut_points'] == expected['total']
    assert coverage['source_selection']['dut_lit_points'] == expected['covered']
    assert sum(row['covered'] for row in coverage['files'].values()) == coverage['covered']
    assert sum(row['total'] for row in coverage['files'].values()) == coverage['total']
    assert sum(row['covered'] for row in coverage['by_kind'].values()) == coverage['covered']
    assert sum(row['total'] for row in coverage['by_kind'].values()) == coverage['total']
    assert document['comparability']['status'] == 'comparable_prefix'


def test_declared_f5_missing_coverage_json_is_unavailable_with_reason():
    run = DECLARED / 'wb-timer'
    scope = run / 'coverage-cpu'
    if not scope.is_dir():
        pytest.skip('declared-IRQ F5 coverage-cpu artifact unavailable')
    summary = json.loads((run / 'original/summary.json').read_text(encoding='utf-8'))
    row = next(process for process in summary['processes']
               if process.get('component') == 'cpu')
    document = _measure(run / 'original', measurement=scope,
                        cache=Path(row['binary_path']).parent, component='cpu')
    _assert_unavailable(document, 'incomplete-saved-measurement')
    assert 'coverage.json' in document['missing_inputs']
    assert 'commands.txt' in document['missing_inputs']
    assert 'replies.txt' in document['missing_inputs']
    assert document['searched_inputs'] == []
    _assert_no_coverage_number(document)


# --- declared-IRQ F5: synthetic own-prefix pairs (mismatch contract) --------

_DUT = 'dut'
_ARTIFACT = 'f' * 64
_BUILD = 'b' * 64
_BINARY = 'c' * 64
_CONFIG = 'd' * 64
_ADMISSION = 'e' * 64
_EXPECTED_PREFIX = {'build_digest': _BUILD, 'binary_sha256': _BINARY,
                    'commands': 2, 'local_ticks': 7}


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def _side(root, *, mode, nonce, pid, trace_list=False, ticks=(3, 7),
          replies=('61', '62'), steps=('STEP 0', 'STEP 0')):
    _write_json(root / 'prefix.json', {
        'schema_version': 'declared_irq_f5_prefix.v1', 'mode': mode,
        'admission_sha256': _ADMISSION, 'config_sha256': _CONFIG,
        'artifacts': {_DUT: _ARTIFACT},
        'case': {'schema_version': 'synthetic.case.v1', 'target': _DUT},
        'group': {'schema_version': 'synthetic.group.v1', 'group_id': 'g',
                  'members': [_DUT]}})
    _write_json(root / 'config.json', {'schema_version': 'synthetic.config.v1',
                                       'value': 1})
    _write_json(root / 'summary.json', {
        'schema_version': 'declared_irq_f5_summary.v1', 'mode': mode,
        'status': 'verified', 'refusals': [],
        'processes': [{'component': _DUT, 'exit_code': 0, 'pid': pid,
                       'build_digest': _BUILD, 'binary_sha256': _BINARY}]})
    records = []
    for index, (step, reply, tick) in enumerate(zip(steps, replies, ticks), 1):
        records.append({'sequence': index, 'reset_epoch': 0,
                        'tick_before': ticks[index - 2] if index > 1 else 0,
                        'tick_after': tick,
                        'command': f'CMD {nonce} {index:x} {step}',
                        'reply': f'RESULT {nonce} {index:x} 0 1 {reply}'})
    session = {'component': _DUT, 'complete': True,
               'identity': {'artifact_digest': _ARTIFACT,
                            'build_digest': _BUILD,
                            'binary_sha256': _BINARY,
                            'execution_nonce': nonce},
               'records': records}
    if trace_list:
        _write_json(root / mode / 'local_commands.json', [session])
    else:
        _write_json(root / mode / 'local-command-trace.json',
                    {'schema_version': 'local_command_trace.v1',
                     'sessions': {_DUT: session}})


def _pair(tmp_path, **fresh_overrides):
    from scripts.measure_new_path_coverage import own_prefix_comparability
    original, fresh = tmp_path / 'original', tmp_path / 'fresh'
    _side(original, mode='original', nonce='1' * 32, pid=101)
    _side(fresh, mode='fresh', nonce='2' * 32, pid=202, trace_list=True,
          **fresh_overrides)
    return own_prefix_comparability(original, fresh, component=_DUT,
                                    expected=_EXPECTED_PREFIX)


def test_synthetic_own_prefix_pair_with_list_trace_is_comparable(tmp_path):
    document = _pair(tmp_path)
    assert document['status'] == 'comparable_prefix'
    assert document['reasons'] == []
    assert document['conditions']['process_independence'] == 'separate-invocations'
    assert document['prefixes']['commands'] == 2
    assert document['prefixes']['fresh']['summary_mode'] == 'fresh'


def test_own_prefix_reply_mismatch_is_unavailable(tmp_path):
    document = _pair(tmp_path, replies=('61', '63'))
    assert document['status'] == 'unavailable'
    assert 'prefix-replies-mismatch' in document['reasons']
    assert document['comparison'] is None
    assert document['coverage_comparison_available'] is False
    _assert_no_coverage_number(document)


def test_own_prefix_tick_mismatch_is_unavailable(tmp_path):
    document = _pair(tmp_path, ticks=(3, 9))
    assert document['status'] == 'unavailable'
    assert 'prefix-local-ticks-mismatch' in document['reasons']
    assert 'prefix-replies-mismatch' not in document['reasons']
    assert document['comparison'] is None
    _assert_no_coverage_number(document)


def test_own_prefix_command_mismatch_is_unavailable(tmp_path):
    document = _pair(tmp_path, steps=('STEP 0', 'STEP 1'))
    assert document['status'] == 'unavailable'
    assert 'prefix-commands-mismatch' in document['reasons']
    _assert_no_coverage_number(document)


def test_missing_fresh_prefix_is_unavailable(tmp_path):
    from scripts.measure_new_path_coverage import own_prefix_comparability
    original = tmp_path / 'original'
    _side(original, mode='original', nonce='1' * 32, pid=101)
    document = own_prefix_comparability(original, tmp_path / 'absent',
                                        component=_DUT, expected=_EXPECTED_PREFIX)
    assert document['status'] == 'unavailable'
    assert document['reasons'] == ['fresh-prefix-missing']
    _assert_no_coverage_number(document)


def test_original_prefix_not_matching_the_measurement_is_unavailable(tmp_path):
    from scripts.measure_new_path_coverage import own_prefix_comparability
    original, fresh = tmp_path / 'original', tmp_path / 'fresh'
    _side(original, mode='original', nonce='1' * 32, pid=101)
    _side(fresh, mode='fresh', nonce='2' * 32, pid=202, trace_list=True)
    document = own_prefix_comparability(
        original, fresh, component=_DUT,
        expected={'build_digest': _BUILD, 'binary_sha256': _BINARY,
                  'commands': 2, 'local_ticks': 8})
    assert document['status'] == 'unavailable'
    assert 'original-prefix-measurement-mismatch' in document['reasons']


# --- declared-IRQ F5: the report derivation --------------------------------

@pytest.fixture(scope='module')
def report_document():
    if not DECLARED.is_dir():
        pytest.skip('declared-IRQ F5 saved runs unavailable')
    return _build_report()


def test_report_measures_three_runs_and_marks_the_cpu_scope_unavailable(report_document):
    report = report_document
    assert report['schema_version'] == 'declared_f5_new_path_coverage_report.v1'
    assert report['aggregate'] is None and report['aggregate_reason']
    assert report['online'] is False
    assert report['fixed_time_coverage'] is False
    assert report['coverage_auc_available'] is False
    assert report['native_authority'] is False
    measured = {row['run']: row for row in report['measured']}
    assert set(measured) == set(_EXPECTED)
    for name, expected in _EXPECTED.items():
        row = measured[name]
        assert row['component'] == expected['component']
        assert (row['covered'], row['total']) == (expected['covered'], expected['total'])
        assert row['local_ticks'] == expected['local_ticks']
        assert row['comparability'] == 'comparable_prefix'
    cpu = [entry for entry in report['unavailable']
           if entry.get('scope') == 'coverage-cpu']
    assert len(cpu) == 1
    assert cpu[0]['run'] == 'wb-timer'
    assert cpu[0]['reason'] == 'incomplete-saved-measurement'
    assert 'coverage.json' in cpu[0]['missing_inputs']
    _assert_no_coverage_number(cpu[0])
    for run in report['runs']:
        for scope in run['scopes']:
            if scope['status'] != 'available':
                _assert_no_coverage_number(scope['document'])


def test_report_records_real_input_hashes_and_reproduction_commands(report_document):
    report = report_document
    assert report['inputs']
    for relative, digest in report['inputs'].items():
        path = ROOT / relative
        assert path.is_file(), relative
        assert sha256(path.read_bytes()).hexdigest() == digest, relative
    assert len(report['reproduction']['per_run']) >= len(_EXPECTED)
    for command in report['reproduction']['per_run']:
        assert 'scripts/measure_new_path_coverage.py' in command
        assert '--original-prefix' in command and '--fresh-prefix' in command
    assert 'scripts/report_declared_f5_coverage.py' in report['reproduction']['report']
    assert 'new-path-coverage-20261030.json' in report['reproduction']['report']
    # Both the measurement inputs and the point map of every measured scope.
    for name in _EXPECTED:
        assert f'{report["root"]}/{name}/coverage-target/coverage.json' in report['inputs']
        assert f'{report["root"]}/{name}/coverage-target/coverage-points.json' in report['inputs']


def test_committed_report_matches_a_fresh_derivation(report_document):
    path = ROOT / 'docs/reports/new-path-coverage-20261030.json'
    if not path.is_file():
        pytest.skip('committed report document unavailable')
    saved = json.loads(path.read_text(encoding='utf-8'))
    assert saved['schema_version'] == report_document['schema_version']
    assert saved['measured'] == report_document['measured']
    assert saved['unavailable'] == report_document['unavailable']
    assert saved['inputs'] == report_document['inputs']


def test_report_cli_writes_the_same_document(report_document, tmp_path):
    if not DECLARED.is_dir():
        pytest.skip('declared-IRQ F5 saved runs unavailable')
    completed = subprocess.run(
        [sys.executable, str(REPORT_SCRIPT), '--runs-root', str(DECLARED),
         '--output', str(tmp_path / 'report.json')],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    written = json.loads((tmp_path / 'report.json').read_text(encoding='utf-8'))
    assert written == report_document
