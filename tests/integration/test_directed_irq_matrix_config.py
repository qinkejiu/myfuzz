"""The directed IRQ matrix declaration and the native script's preflight.

This file validates declarations and preparation only.  It never claims a
native result: the executable cases are checked through the real saved
journals of the earlier declared-IRQ runs, and the cross-protocol admission
matrix is a software preparation gate (no DUT run, no Verilator build).
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / 'configs/scenarios/directed-irq-matrix.json'
NATIVE = ROOT / 'scripts/run_directed_irq_native.py'
GATE = ROOT / 'scripts/check_irq_protocol_matrix.py'
LAYERS = frozenset((
    'source_verification', 'declared_output_mapping', 'irq_group_unique_attribution',
    'irq_group_joint_attribution', 'cpu_native_sample', 'cpu_native_take',
    'cpu_retirement_serial', 'irq_serial_certificate', 'reset_barrier',
    'post_reset_fresh_epoch', 'no_lineage_after_reset', 'no_lineage_from_sync_exception',
    'debug_nmi_diversion_refused', 'unknown_origin_no_credit', 'no_delivery_frame_no_join',
    'overrun_or_cancelled_no_credit', 'peripheral_prefix_coverage',
    'comparability_document'))
NO_CLAIM = ('native_authority', 'grants_F5', 'grants_F6', 'reward_eligible')


def _matrix():
    document = json.loads(MATRIX.read_text(encoding='utf-8'))
    assert document['schema_version'] == 'directed_irq_matrix.v1'
    return document


def test_matrix_declares_its_layers_and_scopes_honestly():
    document = _matrix()
    assert document['software_scope'] == 'pure-reducer-and-preparation-gates-only'
    assert 'native' in document['native_scope']
    assert set(document['evidence_layers']) == LAYERS
    ids = [case['id'] for case in document['cases']]
    assert len(ids) == len(set(ids)) and len(ids) >= 8
    ready = [case for case in document['cases'] if case['native_ready']]
    refused = [case for case in document['cases'] if not case['native_ready']]
    assert len(ready) == 8 and len(refused) == 0
    for case in document['cases']:
        claimed = set(case['claimed_layers'])
        measurable = set(case['measurable_layers'])
        assert claimed and claimed <= measurable, case['id']
        assert set(case['required_evidence_layers']) <= measurable
        assert measurable <= LAYERS and claimed <= LAYERS
        assert 'native_authority' not in json.dumps(case.get('claimed_layers'))
    for case in refused:
        refusal = case['native_refusal']
        assert refusal['code'] and refusal['detail']
        assert case['required_evidence_layers']
        assert case['unavailable'], case['id']
    for case in ready:
        assert case['runner'] and (ROOT / case['runner']).is_file()
        assert (ROOT / case['real_config']).is_file()
        assert case['required_evidence_layers']


def test_matrix_references_only_real_configs_and_scenarios():
    document = _matrix()
    profiles = {adapter['profile'] for adapter in document['cpu_adapters']}
    requests = {target['request'] for target in document['target_protocols']}
    for relative in profiles | requests:
        assert (ROOT / relative).is_file(), relative
    for adapter in document['cpu_adapters']:
        assert adapter['id'] and adapter['protocol'] in ('obi', 'wishbone', 'ahb-lite')
        if adapter.get('native_irq_receipt_contract'):
            module = adapter['native_irq_receipt_contract']
            assert module.startswith('myfuzz.local_harness.')
    for name in ('real_config', 'declared_scenario', 'secondary_scenario',
                 'saved_evidence'):
        for case in document['cases']:
            value = case.get(name)
            if value:
                assert (ROOT / value).exists(), (case['id'], name, value)
    coverage = document['coverage']
    for key, row in coverage['measurable'].items():
        assert row['tool'] == 'scripts/measure_new_path_coverage.py'
        if row.get('saved_measurement'):
            assert (ROOT / row['saved_measurement']).is_dir()
        if row.get('saved_trace'):
            assert (ROOT / row['saved_trace']).is_file()
        if row.get('original_cache'):
            assert (ROOT / row['original_cache']).is_dir()
    assert 'cpu_irq_receipt_prefix_coverage' in coverage['unavailable']


def _preflight(output, *extra):
    completed = subprocess.run(
        [sys.executable, str(NATIVE), '--config', str(MATRIX), '--native',
         '--output', str(output), *extra],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode in (0, 2), completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def test_native_script_preflight_accepts_every_declared_expectation(tmp_path):
    code, report = _preflight(tmp_path, '--case', 'cross-protocol.apb-spi-cv32e20',
                              '--preflight')
    assert code == 0, report
    assert report['scope'].startswith('declaration-validation-only')
    assert report['native_run'] is False
    for name in NO_CLAIM:
        assert report[name] is False
    assert report['counts'] == {'ready': 8, 'refused': 0, 'error': 0}
    by_id = {row['case']: row for row in report['cases']}
    document = _matrix()
    for case in document['cases']:
        row = by_id[case['id']]
        assert row['status'] == ('ready' if case['native_ready'] else 'refused')
        assert not row['problems'], (case['id'], row['problems'])
        if not case['native_ready']:
            assert row['refusal']['code'] == case['native_refusal']['code']
            assert row['refusal']['detail'] == case['native_refusal']['detail']


@pytest.mark.parametrize('case_id, runner, configs', [
    ('reset-then-irq', 'scripts/run_irq_reset_native.py',
     ('configs/scenarios/directed-irq-reset/ibex-wb-timer.json',)),
    ('exception-does-not-mint', 'scripts/run_irq_exception_native.py',
     ('configs/scenarios/directed-exception/ibex.json',
      'configs/scenarios/directed-exception/cv32e40p.json')),
    ('two-source-ambiguous', 'scripts/run_irq_group_native.py',
     ('configs/scenarios/directed-irq-group/joint-two-targets-ibex.json',)),
    ('unique-two-source-each', 'scripts/run_irq_group_native.py',
     ('configs/scenarios/directed-irq-group/unique-wb-timer-ibex.json',
      'configs/scenarios/directed-irq-group/unique-apb-spi-ibex.json'))])
def test_directed_cases_declare_their_own_native_runner(case_id, runner, configs):
    """The four directed cases own a public runner; the delegate only covers
    the single-take transport cases, so the matrix must name the real runner."""
    document = _matrix()
    case, = [row for row in document['cases'] if row['id'] == case_id]
    assert case['native_ready'] is True
    assert case['runner'] == runner and (ROOT / runner).is_file()
    declared = [case['real_config']]
    for name in ('secondary_real_config', 'declared_scenario', 'secondary_scenario'):
        if case.get(name):
            declared.append(case[name])
    for relative in declared:
        assert (ROOT / relative).exists(), (case_id, relative)
    for relative in configs:
        assert (ROOT / relative).is_file(), (case_id, relative)


def test_native_script_requires_the_native_flag_and_a_case():
    completed = subprocess.run(
        [sys.executable, str(NATIVE), '--config', str(MATRIX)],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode != 0
    assert '--native' in completed.stderr


@lru_cache(maxsize=1)
def _gate_document():
    sys.path.insert(0, str(ROOT))
    from scripts.check_irq_protocol_matrix import evaluate_matrix, load_matrix
    document = evaluate_matrix(load_matrix(MATRIX),
                               cache_dir=ROOT / '.pytest-directed-irq-matrix-cache')
    return document


def _adapter_admits(adapter):
    """Whether the declaration says this adapter can be admitted today."""
    import importlib.util
    expected = adapter['expectation']['status']
    if expected == 'admitted':
        return True
    if expected == 'admitted_when_contract_module_present':
        return importlib.util.find_spec(adapter['native_irq_receipt_contract']) is not None
    return False


def test_cross_protocol_gate_admits_only_source_backed_cpu_adapters():
    document = _gate_document()
    assert document['schema_version'] == 'irq_protocol_matrix.v1'
    assert document['status'] == 'complete'
    assert document['scope'] == 'software-preparation-admission-only'
    assert document['native_run'] is False
    for name in NO_CLAIM:
        assert document[name] is False
    matrix = _matrix()
    targets = len(matrix['target_protocols'])
    expected_admitted = sum(1 for adapter in matrix['cpu_adapters']
                            if _adapter_admits(adapter)) * targets
    assert document['counts'] == {'admitted': expected_admitted,
                                  'refused': len(matrix['cpu_adapters']) * targets
                                             - expected_admitted,
                                  'error': 0}
    assert document['dishonest'] == []
    rows = {row['combination']: row for row in document['rows']}
    assert len(rows) == len(matrix['cpu_adapters']) * len(matrix['target_protocols'])
    adapters = {adapter['id']: adapter for adapter in matrix['cpu_adapters']}
    for adapter_id, adapter in adapters.items():
        for target in matrix['target_protocols']:
            row = rows['cross-protocol:' + adapter_id + ':' + target['id']]
            if not _adapter_admits(adapter):
                assert row['status'] == 'refused'
                assert row['refusal']['code'] == 'unregistered-native-IRQ-CPU-adapter'
                assert row['refusal']['stage'] == 'cpu-source-contract'
                assert row['cpu']['profile_id'] in json.dumps(row['refusal'])
                assert row['admission'] is None
            else:
                assert row['status'] == 'admitted', (adapter_id, target['id'])
                admission = row['admission']
                assert admission['cpu_source_verification']['source_status'] == \
                    'source_verified'
                mapping = admission['declared_output_mapping']
                assert mapping['adapter_id'] == 'declared-output.v1'
                assert mapping['physical_port'] == target['source_port']
                assert mapping['transport_only'] is True
                assert mapping['cause'] == 'unknown'
                from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup
                group = IrqDeliveryGroup.from_document(admission['group_document'])
                assert group.identity_sha256 == admission['group_sha256']
                assert len(admission['group_document']['members']) == 1
                assert admission['target_irq_export']['direction'] == 'output'
            if adapter['expectation']['status'] != 'admitted_when_contract_module_present':
                assert row['expectation']['honest'] is True, row['combination']


def test_matrix_cross_protocol_cases_match_the_gate():
    document = _matrix()
    gate = _gate_document()
    admitted = {row['combination'] for row in gate['rows']
                if row['status'] == 'admitted'}
    for case in document['cases']:
        if case['kind'] != 'cross-protocol':
            continue
        combination = 'cross-protocol:' + case['cpu_adapter'] + ':' + case['target_protocol']
        assert combination in admitted, combination
        row = next(row for row in gate['rows'] if row['combination'] == combination)
        adapter_id = row['cpu_adapter']
        adapter = next(item for item in document['cpu_adapters']
                       if item['id'] == adapter_id)
        assert adapter['expectation']['status'] != 'refused'
        assert 'source_verification' in case['required_evidence_layers']
        assert 'declared_output_mapping' in case['required_evidence_layers']


@pytest.mark.parametrize('case_id', [
    'cross-protocol.apb-spi-cv32e20', 'cross-protocol.apb-spi-ibex',
    'cross-protocol.wb-timer-ibex', 'cross-protocol.ahb-sha-cv32e20'])
def test_native_evidence_derivation_replays_saved_journals(case_id):
    """Software replay of the native script's derivation over real saved runs.

    These journals were produced by the public runner in an earlier native
    window.  Re-deriving the declared layers from them checks the script's
    joins; it is not a new native result.
    """
    sys.path.insert(0, str(ROOT))
    from scripts.run_directed_irq_native import case_by_id, derive_evidence, load_matrix
    document = load_matrix(MATRIX)
    case = case_by_id(document, case_id)
    runner_output = (ROOT / case['real_config']).parent
    if not (runner_output / 'original/events.json').is_file():
        pytest.skip('saved native run unavailable: ' + str(runner_output))
    evidence, missing, extra = derive_evidence(case, runner_output=runner_output,
                                               matrix_config=str(MATRIX))
    assert missing == []
    assert set(evidence) >= set(case['required_evidence_layers'])
    assert evidence['irq_group_unique_attribution']['attribution_status'] == 'unique'
    assert evidence['irq_serial_certificate']['decision_serial'] > 0
    assert extra['processes'] and all(row['exit_code'] == 0 for row in extra['processes'])
    assert extra['runner_result']['status'] == 'verified'
