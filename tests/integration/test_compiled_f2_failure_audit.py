"""Failure accounting through the actual F2 entry points; no native builds."""
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.integration.compiled_f2 import CompiledF2Runtime, derive_f2_execution_binding
from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
from tests.integration.test_compiled_f2_read_response import f2_parts
from tests.integration.test_compiled_f4_storage_producer import ROOT, timer_loaded


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('f2-failure-audit'))


def runtime_for_submit(generated):
    artifacts, inputs = generated
    parts = f2_parts(generated)
    runtime = CompiledF2Runtime.__new__(CompiledF2Runtime)
    runtime.path = parts['row']; runtime.layout = compile_f2_candidate_layout(runtime.path)
    runtime._stable = lambda **kw: None
    runtime.artifacts = artifacts; runtime.inputs = inputs
    runtime.records = []; runtime.attempts = []; runtime._failed_attempt = None
    runtime._attempt = None; runtime._pending = None; runtime._checked = None
    runtime.max_cases = 4; runtime.rounds = 1; runtime.run_id = 'failure-test'
    runtime.image = parts['image']; runtime.stream = parts['stream']
    runtime.cursor = parts['cursor']; runtime.result = parts['result']
    runtime.target_id = parts['access']['target_component']
    runtime.cpu_id = parts['access']['source_component']
    runtime.register_name = parts['access']['register']; runtime.authority = object()
    runtime.execution_binding = derive_f2_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    runtime.compiled_digest = runtime.execution_binding.document()['compiled_document_sha256']
    runtime.runtime_path_admission = SimpleNamespace(
        runtime_path_id=runtime.execution_binding.document()['runtime_path_id'],
        instruction_binding=SimpleNamespace(source_id=runtime.image['source_id']))
    runtime.runner = SimpleNamespace(sessions={
        runtime.cpu_id: SimpleNamespace(), runtime.target_id: SimpleNamespace(reset_epoch=0)})
    runtime.session = SimpleNamespace(submit_case=lambda case: None)
    return runtime, parts['access']['address'].to_bytes(4, 'little')


def assertions(runtime):
    return {row['expectation_id']: row for row in runtime.assertion_results()['cases'][-1]['assertions']}


def test_version_capture_failure_keeps_admitted_case_missing_and_terminal(generated):
    runtime, raw = runtime_for_submit(generated)
    failure = RuntimeError('live version unavailable')
    with patch('myfuzz.integration.compiled_f2.capture_f2_read_version', side_effect=failure):
        with pytest.raises(RuntimeError) as caught:
            runtime.submit(raw)
        assert caught.value is failure
        rows = assertions(runtime)
        assert {row['status'] for row in rows.values()} == {'missing'}
        assert runtime.records == []
        with pytest.raises(ValueError, match='failed-attempt'):
            runtime.submit(raw)
    assert len(runtime.attempts) == 1


def test_rejected_candidate_does_not_invent_case(generated):
    runtime, _ = runtime_for_submit(generated)
    with pytest.raises(ValueError, match='candidate-'):
        runtime.submit(b'\0' * 4)
    assert runtime.assertion_results()['cases'] == []


@pytest.mark.parametrize('mode', ['timeout', 'violation', 'missing', 'contradiction'])
def test_failed_submission_exports_each_expectation_independently(generated, mode):
    runtime, raw = runtime_for_submit(generated)
    before = SimpleNamespace(document=lambda: {'write_count': 0, 'reset_epoch': 0})
    receipt = SimpleNamespace(status='running', violations=(), events=())
    if mode == 'violation':
        receipt.violations = ('observed-bus-violation',)
    elif mode == 'timeout':
        receipt.status = 'timeout'
    def submit(case):
        if mode == 'timeout':
            raise TimeoutError('no receipt obtained')
        findings = runtime._check_receipt(receipt)
        return SimpleNamespace(status='finding' if findings else 'running', violations=findings)
    runtime.session.submit_case = submit
    runtime.authority = SimpleNamespace(issue=lambda **kw: object())
    error = ValueError('compiled-F2-dependent-RAM-missing' if mode == 'missing'
                       else 'compiled-F2-read-state-changed')
    with patch('myfuzz.integration.compiled_f2.capture_f2_read_version', return_value=before), \
            patch('myfuzz.integration.compiled_f2.check_f2_read_observation', side_effect=error):
        with pytest.raises((ValueError, TimeoutError)):
            runtime.submit(raw)
    rows = assertions(runtime)
    assert len(rows) == 2
    expected_protocol = 'missing' if mode == 'timeout' else 'failed'
    expected_edge = {'contradiction': 'failed'}.get(mode, 'missing')
    assert rows['protocol_checker.receipt_violations']['status'] == expected_protocol
    assert rows['cross_component.declared_edge_hops']['status'] == expected_edge
    assert runtime._pending is None
    assert runtime.assertion_case_evidence()[0]['case_id'] == 'failure-test:0'
    # Returned evidence is a private copy, not authority the caller can mutate.
    copy = runtime.assertion_case_evidence(); copy[0]['observations'].clear()
    assert runtime.assertion_case_evidence()[0]['observations'] or mode == 'timeout'


def test_checker_input_without_final_receipt_does_not_grant_protocol_pass(generated):
    runtime, raw = runtime_for_submit(generated)
    before = SimpleNamespace(document=lambda: {'write_count': 0, 'reset_epoch': 0})
    runtime.authority = SimpleNamespace(issue=lambda **kw: object())
    def submit(case):
        runtime._check_receipt(SimpleNamespace(status='running', violations=(), events=()))
        raise OSError('final receipt unavailable')
    runtime.session.submit_case = submit
    with patch('myfuzz.integration.compiled_f2.capture_f2_read_version', return_value=before), \
            patch('myfuzz.integration.compiled_f2.check_f2_read_observation',
                  side_effect=ValueError('compiled-F2-dependent-RAM-missing')):
        with pytest.raises(OSError, match='final receipt unavailable'):
            runtime.submit(raw)
    rows = assertions(runtime)
    assert rows['protocol_checker.receipt_violations']['status'] == 'missing'
    assert rows['cross_component.declared_edge_hops']['status'] == 'missing'


def test_failure_export_saves_assertions_after_another_export_fails(tmp_path):
    from myfuzz.integration.compiled_execution_files import _save_runtime_failure
    expected = {'schema': 'compiled_assertion_results.v1', 'cases': [{'case_id': 'attempt'}]}
    runtime = SimpleNamespace(
        runner=SimpleNamespace(events_since=lambda _: (_ for _ in ()).throw(OSError('events unavailable'))),
        execution_audit=lambda: {'exits': {}}, assertion_results=lambda: deepcopy(expected))
    failures = _save_runtime_failure(tmp_path, runtime)
    assert failures == {'partial_events': 'events unavailable'}
    assert json.loads((tmp_path / 'assertions.json').read_text()) == expected


def test_finish_preserves_primary_failure_and_keeps_assertion_diagnostic(generated):
    runtime, _ = runtime_for_submit(generated)
    runtime.finished = False
    primary = ValueError('source identity changed')
    runtime._stable = lambda **kw: (_ for _ in ()).throw(primary)
    runtime.session.finish = lambda: (_ for _ in ()).throw(OSError('cleanup failed'))
    with pytest.raises(ValueError) as caught:
        runtime.finish()
    assert caught.value is primary
    assert any('cleanup failed' in note for note in primary.__notes__)
    assert runtime.finish_diagnostic['assertions']['cases'] == []


def replay_runtime():
    plan = dict(records=[], semantic_hash='same', online_plan={})
    class SoftwareRuntime(CompiledF2Runtime):
        def __init__(self, **kw):
            self.finished = False
            self._process_identities = {'cpu': dict(component='cpu', role='cpu', pid=101,
                execution_nonce='2' * 32, artifact_digest='artifact')}
            self.runner = SimpleNamespace(events_since=lambda index: [])
        def _stable(self, **kw): pass
        def execution_audit(self):
            return {'identities': self._process_identities, 'exits': {}}
        def finish(self): self.finished = True; return deepcopy(plan)
    original = SoftwareRuntime()
    original._process_identities = {'cpu': dict(component='cpu', role='cpu', pid=100,
        execution_nonce='1' * 32, artifact_digest='artifact')}
    original._replay_identities = []; original.artifacts = {}; original.inputs = {}
    original.base_dir = '.'; original.cache_dir = '.'; original.run_id = 'unit'
    original.rounds = 1; original.max_cases = 1; original._built_receipts = {}
    return original, plan


def test_replay_success_fails_when_required_export_fails():
    original, plan = replay_runtime()
    with pytest.raises(OSError, match='audit export failed'):
        original.replay(plan, audit_sink=lambda _: (_ for _ in ()).throw(OSError('audit export failed')))


def test_replay_primary_failure_keeps_export_failure_as_note():
    original, plan = replay_runtime()
    original._process_identities['cpu']['pid'] = 101
    with pytest.raises(ValueError, match='fresh-process-identity-reused') as caught:
        original.replay(plan, audit_sink=lambda _: (_ for _ in ()).throw(OSError('audit export failed')))
    assert any('audit export failed' in note for note in caught.value.__notes__)


@pytest.mark.parametrize('message', [
    'compiled-F2-read-command-gap',
    'compiled-F4-storage-CPU-acceptance-join',
    'compiled-F4-storage-native-transfer-missing',
    'compiled-F4-storage-native-post-sample-missing',
])
def test_unavailable_consumer_observations_are_missing(generated, message):
    runtime, _ = runtime_for_submit(generated)
    receipt = SimpleNamespace(events=())
    assert runtime._observation_error_status(ValueError(message), receipt,
        {'result_address': runtime.result}) == 'missing'


def selected_read_phase_fixture(generated):
    """A selected command plus unrelated and same-command idle tick samples."""
    runtime, _ = runtime_for_submit(generated)
    parts = f2_parts(generated); declaration = parts['declaration']
    access = declaration['candidate']['access']
    signals = runtime.artifacts[runtime.target_id].runtime_document['base_protocol_trace']['signals']
    selected_tick = 103
    def sample(phase, tick, producer=40, epoch=0, accepted=False):
        backend = {signals['psel']: int(accepted), signals['penable']: int(accepted),
            signals['pready']: 1, signals['pwrite']: 0, signals['paddr']: access['register_offset']}
        return dict(kind='local_tick_sample', component=runtime.target_id,
            producer_event_id=producer, reset_epoch=epoch, phase=phase, local_tick=tick,
            outputs={'backend': backend, 'storage_probes': {}})
    selected_pre = sample('pre', selected_tick, accepted=True)
    selected_post = sample('post', selected_tick)
    idle = [sample(phase, tick, producer) for phase in ('pre', 'post')
        for tick, producer in ((101, 39), (102, 40), (104, 40))]
    delivery = dict(kind='mmio_delivery', component=runtime.cpu_id,
        device_id=access['device_id'], address=access['address'],
        offset=access['register_offset'], write=False, producer_event_id=40)
    command = dict(target_epoch=0, command_sequence=2, operation='ACCESS_APB3_REG',
        fields=[0, access['register_offset'], 0, 15], status='parsed_complete',
        parsed_receipt_projection={'payload': {'samples': [
            {'local_tick': 3, 'pre': deepcopy(selected_pre['outputs'])}]}})
    runtime.runner.sessions[runtime.target_id] = SimpleNamespace(reset_epoch=0,
        _sequence=2, _tick_base=100, native_reset_observation_commands=lambda: [command])
    runtime._pending = (declaration, SimpleNamespace(document=lambda: {
        'reset_epoch': 0, 'command_sequence': 1}), 0)
    return runtime, declaration, delivery, selected_pre, selected_post, idle


@pytest.mark.parametrize('phase', ['pre', 'post'])
@pytest.mark.parametrize('stale', ['idle', 'other_producer', 'other_tick', 'other_epoch'])
def test_selected_read_phase_absence_stays_missing_despite_unrelated_samples(generated, phase, stale):
    runtime, declaration, delivery, pre, post, idle = selected_read_phase_fixture(generated)
    selected = pre if phase == 'pre' else post
    if stale != 'idle':
        borrowed = deepcopy(selected)
        borrowed[{'other_producer': 'producer_event_id', 'other_tick': 'local_tick',
                  'other_epoch': 'reset_epoch'}[stale]] += 1
        idle.append(borrowed)
    events = [delivery, *idle, *([post] if phase == 'pre' else [pre])]
    message = ('compiled-F4-storage-native-transfer-missing' if phase == 'pre'
               else 'compiled-F4-storage-native-post-sample-missing')
    assert runtime._observation_error_status(ValueError(message),
        SimpleNamespace(events=events), declaration) == 'missing'


@pytest.mark.parametrize('phase', ['pre', 'post'])
@pytest.mark.parametrize('kind', ['duplicate', 'bad_values'])
def test_selected_read_phase_contradictions_stay_failed(generated, phase, kind):
    runtime, declaration, delivery, pre, post, idle = selected_read_phase_fixture(generated)
    selected = pre if phase == 'pre' else post
    extra = []
    if kind == 'duplicate':
        extra.append(deepcopy(selected))
    else:
        selected['outputs'] = {'backend': {'bad': 1}, 'storage_probes': {}}
    message = ('compiled-F4-storage-native-transfer-missing' if phase == 'pre'
               else 'compiled-F4-storage-native-post-sample-missing')
    assert runtime._observation_error_status(ValueError(message),
        SimpleNamespace(events=[delivery, pre, post, *idle, *extra]), declaration) == 'failed'
