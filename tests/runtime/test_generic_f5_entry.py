"""F5 CLI delegates to one existing GPIO session and its fresh replay."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.runtime import generic_campaign as campaign
from myfuzz.scenario.session_runtime import OnlineCaseReceipt

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = ROOT / 'configs/scenarios/compiled-f5-ibex-pulp-gpio/generic_scenario.json'


def test_f5_descriptor_preserves_ordered_eight_byte_inputs():
    descriptor = campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT)
    assert descriptor.flow_ids == ('F5',)
    assert campaign.select_case_records(descriptor, flow='F5', records=[
        'F5:0000000000000000', 'F5:0000000100000000']) == (
            ('F5', '0000000000000000'), ('F5', '0000000100000000'))


@pytest.mark.parametrize('execution_mode,mode,replay_expected', [
    (None,'original',True), ('search','original',False), ('develop','original',False),
    ('acceptance','original',True), ('search','fresh',True)])
def test_f5_entry_uses_existing_runtime_and_closes_preparation(tmp_path, monkeypatch, execution_mode, mode, replay_expected):
    from myfuzz.integration import ibex_pulp_online
    calls = []
    context = SimpleNamespace(assert_current=lambda: calls.append('current'),
                              close=lambda: calls.append('close'))
    trace = SimpleNamespace(genome_sha256='a' * 64, status='complete', events=[],
        local_ticks={'cpu': 32}, semantic_sha256='b' * 64, manifest_sha256='c' * 64)
    session = SimpleNamespace(finish=lambda: trace, encode_plan=lambda: b'{}',
                              _begun=True, _finished=True)
    runtime = SimpleNamespace(session=session, compiled_f5_crosswalk={'scope': 'topology'},
        submit_f5=lambda raw: (calls.append(raw) or OnlineCaseReceipt(
            'pin', 0, 0, (), {}, {}, 'running')),
        replay=lambda reference: calls.append('replay') or SimpleNamespace(matches=True, verification_scope='full',
            first_difference=None, expected_event=None, actual_event=None,
            difference_context=None, actual_trace=trace))
    def make(**kwargs):
        assert kwargs['preparation_context'] is context and kwargs['f5_only'] is True
        assert kwargs['ip_cross_case'] is False and kwargs['initial_ram_data'] is False
        return runtime
    monkeypatch.setattr(campaign, 'create_preparation', lambda **kwargs: context)
    monkeypatch.setattr(ibex_pulp_online, 'make_ibex_pulp_online_runtime', make)
    result = campaign.run_descriptor(campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT),
        flow='F5', mode=mode, execution_mode=execution_mode, case_root=tmp_path / 'run', base_dir=ROOT)
    assert result['replay_matches'] is (True if replay_expected else None)
    assert ('replay' in calls) is replay_expected
    assert result['backend'] == 'compiled_f5_gpio_standalone'
    assert result['replay_scope'] == 'within_invocation'
    assert bytes.fromhex('0000000100000000') in calls
    assert calls[-1] == 'close'
    assert (tmp_path / 'run' / mode / 'events.json').is_file()
    import json
    receipts = json.loads((tmp_path / 'run' / mode / 'receipts.json').read_text())
    assert 'events' not in receipts[0]
    raw = (tmp_path / 'run' / mode / 'receipts.jsonl').read_text().splitlines()
    assert len(raw) == 1 and json.loads(raw[0])['case_id'] == 'pin'


@pytest.mark.parametrize('rounds, records', [(31, None), (32, ['F5:01'])])
def test_f5_invalid_budget_or_shape_refused_before_preparation(tmp_path, monkeypatch, rounds, records):
    monkeypatch.setattr(campaign, 'create_preparation', lambda **kwargs: pytest.fail('prepared'))
    with pytest.raises(campaign.GenericScenarioRefused):
        campaign.run_descriptor(campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT),
            flow='F5', mode='original', case_root=tmp_path / 'run', base_dir=ROOT,
            rounds=rounds, sequence=records)
    assert not (tmp_path / 'run').exists()


def test_f5_cleanup_failure_does_not_hide_primary_refusal(tmp_path, monkeypatch):
    from myfuzz.integration import ibex_pulp_online
    calls = []
    context = SimpleNamespace(assert_current=lambda: None,
                              close=lambda: calls.append('closed'))
    def submit(raw):
        raise ValueError('input-refused')
    def finish():
        raise RuntimeError('cleanup-refused')
    runtime = SimpleNamespace(session=SimpleNamespace(
        _begun=True, _finished=False, finish=finish),
        compiled_f5_crosswalk={}, submit_f5=submit)
    monkeypatch.setattr(campaign, 'create_preparation', lambda **kwargs: context)
    monkeypatch.setattr(ibex_pulp_online, 'make_ibex_pulp_online_runtime', lambda **kwargs: runtime)
    with pytest.raises(campaign.GenericScenarioRefused) as caught:
        campaign.run_descriptor(campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT),
            flow='F5', mode='original', case_root=tmp_path / 'run', base_dir=ROOT)
    assert caught.value.detail['reason'] == 'input-refused'
    assert any('cleanup-refused' in note for note in caught.value.__notes__)
    assert calls == ['closed']


@pytest.mark.parametrize('receipt_status,trace_status,fresh_status,matches,difference', [
    ('failed', 'complete', 'complete', True, None),
    ('running', 'failed', 'failed', True, None),
    ('running', 'complete', 'failed', True, None),
    ('running', 'complete', 'complete', 1, None),
    ('running', 'complete', 'complete', True, 3),
])
def test_matching_failure_never_reports_success(tmp_path, monkeypatch, receipt_status,
        trace_status, fresh_status, matches, difference):
    from myfuzz.integration import ibex_pulp_online
    context = SimpleNamespace(assert_current=lambda: None, close=lambda: None)
    def trace(status):
        return SimpleNamespace(genome_sha256='a' * 64, status=status, events=[],
            local_ticks={}, semantic_sha256='b' * 64, manifest_sha256='c' * 64)
    runtime = SimpleNamespace(session=SimpleNamespace(_begun=True, _finished=True,
        finish=lambda: trace(trace_status), encode_plan=lambda: b'{}'),
        compiled_f5_crosswalk={}, submit_f5=lambda raw: OnlineCaseReceipt(
            'pin', 0, 0, (), {}, {}, receipt_status),
        replay=lambda reference: SimpleNamespace(matches=matches, verification_scope='full',
            first_difference=difference, expected_event=None, actual_event=None,
            difference_context=None, actual_trace=trace(fresh_status)))
    monkeypatch.setattr(campaign, 'create_preparation', lambda **kwargs: context)
    monkeypatch.setattr(ibex_pulp_online, 'make_ibex_pulp_online_runtime', lambda **kwargs: runtime)
    try:
        result = campaign.run_descriptor(campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT),
            flow='F5', mode='original', case_root=tmp_path / 'run', base_dir=ROOT)
    except campaign.GenericScenarioRefused:
        return
    assert result['replay_matches'] is False


def test_f5_trace_export_selects_actual_execution_and_keeps_incomplete():
    original = {'component': 'cpu', 'identity': {'execution_nonce': 'a' * 32},
                'complete': True, 'records': [{'sequence': 1}]}
    fresh = {'component': 'cpu', 'identity': {'execution_nonce': 'b' * 32},
             'complete': False, 'records': []}
    document = campaign._f5_recorded_trace((original, fresh),
        expected={'cpu': 'b' * 32}, scope='fresh')
    assert document['sessions']['cpu']['identity']['execution_nonce'] == 'b' * 32
    assert document['sessions']['cpu']['complete'] is False
    assert document['schema_version'] == 'local_command_trace.v1'


@pytest.mark.parametrize('rows', [(), (
    {'component': 'cpu', 'identity': {'execution_nonce': 'a' * 32},
     'complete': True, 'records': []},) * 2])
def test_f5_trace_export_refuses_missing_or_ambiguous_execution(rows):
    with pytest.raises(ValueError):
        campaign._f5_recorded_trace(rows, expected={'cpu': 'a' * 32}, scope='original')


def test_f5_finalize_guard_failure_reaps_saved_children_and_preserves_primary(tmp_path, monkeypatch):
    from myfuzz.integration import ibex_pulp_online
    calls = []
    process = SimpleNamespace(returncode=None)
    process.poll = lambda: process.returncode
    def end_case():
        calls.append('reaped')
        process.returncode = 0
    local = SimpleNamespace(process=process, end_case=end_case)
    runner = SimpleNamespace(sessions={'cpu': local})
    context = SimpleNamespace(close=lambda: calls.append('closed'))
    def finish():
        # Finish may revoke its session mapping before an early guard fails.
        runner.sessions.clear()
        raise RuntimeError('finalize guard failed')
    def submit(raw):
        raise ValueError('input-refused')
    runtime = SimpleNamespace(session=SimpleNamespace(
        _begun=True, _finished=False, finish=finish, runner=runner),
        compiled_f5_crosswalk={}, submit_f5=submit)
    monkeypatch.setattr(campaign, 'create_preparation', lambda **kwargs: context)
    monkeypatch.setattr(ibex_pulp_online, 'make_ibex_pulp_online_runtime', lambda **kwargs: runtime)
    with pytest.raises(campaign.GenericScenarioRefused) as caught:
        campaign.run_descriptor(campaign.load_descriptor(DESCRIPTOR, base_dir=ROOT),
            flow='F5', mode='original', case_root=tmp_path / 'run', base_dir=ROOT)
    assert caught.value.detail['reason'] == 'input-refused'
    assert any('F5 cleanup:' in note and 'finalize guard failed' in note
               for note in caught.value.__notes__)
    assert calls == ['reaped', 'closed']
    assert process.poll() == 0


def test_incremental_f5_catalog_may_exceed_case_budget(tmp_path, monkeypatch):
    seen=[]
    def run(descriptor, **kwargs):
        seen.append(kwargs)
        return {'case_count':1}
    monkeypatch.setattr(campaign,'_run_f5_descriptor',run)
    descriptor=campaign.load_descriptor(DESCRIPTOR,base_dir=ROOT)
    selector=object()
    records=[f'F5:{value:016x}' for value in range(17)]
    campaign.run_descriptor(descriptor,flow='F5',mode='original',case_root=tmp_path,
        base_dir=ROOT,sequence=records,execution_case_capacity=1,
        record_selector=selector,selected_count=1)
    assert len(seen[0]['cases'])==17
    assert seen[0]['selected_count']==1
    assert seen[0]['record_selector'] is selector
