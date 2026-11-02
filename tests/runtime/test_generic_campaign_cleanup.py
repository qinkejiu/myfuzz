"""Software-only ownership checks for the shared descriptor entry."""
from types import SimpleNamespace

import pytest

from myfuzz.runtime import generic_campaign as campaign
from myfuzz.local_harness import generated_execution_admission as admission


@pytest.fixture
def shared(monkeypatch, tmp_path):
    calls = []
    context = SimpleNamespace(artifacts={}, input_digests={},
        compiled_inputs=lambda: {}, close=lambda: calls.append('context'),
        attach_runtime=lambda **kw: None, register_prepared_paths=lambda **kw: None)
    plan = SimpleNamespace(document=lambda: {}, document_bytes=b'{}', identity_sha256='a'*64)
    bound = SimpleNamespace(documentary=lambda: {}, close=lambda: calls.append('bound'))
    session = SimpleNamespace(_begun=True, _finished=False)
    def settle():
        calls.append('settle')
        session._finished = True
    session.finish = settle
    runtime = SimpleNamespace(runner=SimpleNamespace(sessions={}), session=session,
        runtime_path_admission=SimpleNamespace(prepared=SimpleNamespace(runtime_paths=(), graph={})),
        finished=False, close=lambda: calls.append('runtime'))
    monkeypatch.setattr(campaign, 'select_case_records', lambda *a, **kw: [('F4', '00')])
    monkeypatch.setattr(campaign, 'resolve_rounds', lambda *a: 32)
    monkeypatch.setattr(campaign, 'create_preparation', lambda **kw: context)
    monkeypatch.setattr(campaign, 'plan_bindings', lambda c: ())
    monkeypatch.setattr(campaign, 'compile_execution_plan', lambda *a, **kw: plan)
    monkeypatch.setattr(campaign, 'case_sequence_for_plan', lambda **kw: {})
    monkeypatch.setattr(admission, 'create_compiled_execution', lambda **kw: runtime)
    monkeypatch.setattr(campaign, 'bind_execution_plan', lambda *a, **kw: bound)
    monkeypatch.setattr(campaign, 'StorageFlowBackend', lambda **kw: None)
    error = ValueError('campaign failed')
    def fail(**kw):
        raise error
    monkeypatch.setattr(campaign, 'run_directed_campaign', fail)
    descriptor = SimpleNamespace(compose='compose', capability='cap', supplement=None,
        flow_ids=('F4',), executors={'F4': 'test'}, shared_slots=False, scenario_id='test', executor=lambda flow: 'test')
    def run():
        return campaign.run_descriptor(descriptor, flow='F4', mode='original',
            case_root=tmp_path/'case', base_dir=tmp_path)
    return SimpleNamespace(calls=calls, context=context, bound=bound, runtime=runtime,
        session=session, error=error, run=run)


def test_preparation_is_released_when_plan_compilation_fails(shared, monkeypatch):
    def fail(*a, **kw): raise shared.error
    monkeypatch.setattr(campaign, 'compile_execution_plan', fail)
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ['context']


def test_active_session_and_all_owners_are_released(shared):
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ['settle', 'bound', 'context', 'runtime']


def test_finished_session_is_not_finished_again(shared):
    shared.session._finished = True
    shared.runtime.finished = True
    with pytest.raises(ValueError): shared.run()
    assert shared.calls == ['bound', 'context', 'runtime']


def test_cleanup_failures_preserve_primary_and_drain_other_owners(shared):
    def fail():
        shared.calls.append('bound')
        raise RuntimeError('close failed')
    shared.bound.close = fail
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ['settle', 'bound', 'context', 'runtime']
    assert any('close failed' in note for note in caught.value.__notes__)


def completed_body(shared, monkeypatch, tmp_path):
    """Reach export/cleanup without native work or filesystem copy fixtures."""
    monkeypatch.setattr(campaign, 'run_directed_campaign', lambda **kw: {'sequence_case_count': 1})
    def finish():
        shared.calls.append('finish')
        shared.session._finished = True
        shared.runtime.finished = True
        return {}
    shared.runtime.finish = finish
    shared.runtime.trace = SimpleNamespace(events=())
    shared.runtime.execution_audit = lambda: {}
    shared.runtime.replay = lambda prefix: {'matches': True}
    monkeypatch.setattr(campaign.shutil, 'copytree', lambda *a, **kw: shared.calls.append('copy'))
    monkeypatch.setattr(campaign.shutil, 'move', lambda *a, **kw: shared.calls.append('archive'))


def test_success_keeps_cleanup_before_archive(shared, monkeypatch, tmp_path):
    completed_body(shared, monkeypatch, tmp_path)
    result = shared.run()
    assert result['replay_matches'] is True
    assert shared.calls == ['finish', 'copy', 'bound', 'context', 'runtime', 'archive']


def test_only_cleanup_errors_drain_every_owner_and_raise_first(shared, monkeypatch, tmp_path):
    completed_body(shared, monkeypatch, tmp_path)
    first = RuntimeError('bound close failed')
    def bound_close():
        shared.calls.append('bound')
        raise first
    def context_close():
        shared.calls.append('context')
        raise RuntimeError('context close failed')
    shared.bound.close = bound_close
    shared.context.close = context_close
    with pytest.raises(RuntimeError) as caught: shared.run()
    assert caught.value is first
    assert shared.calls == ['finish', 'copy', 'bound', 'context', 'runtime']
    assert any('context close failed' in note for note in first.__notes__)


@pytest.mark.parametrize('stage', ['finish', 'replay', 'export'])
def test_post_finish_failures_never_repeat_native_finish(shared, monkeypatch, tmp_path, stage):
    completed_body(shared, monkeypatch, tmp_path)
    def fail(*args, **kwargs):
        raise shared.error
    if stage == 'finish':
        original = shared.runtime.finish
        def finish():
            original()
            raise shared.error
        shared.runtime.finish = finish
    elif stage == 'replay':
        shared.runtime.replay = fail
    else:
        monkeypatch.setattr(campaign.shutil, 'copytree', fail)
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ['finish', 'bound', 'context', 'runtime']


def test_failed_session_finish_still_releases_every_owner(shared):
    def finish():
        shared.calls.append('settle')
        raise RuntimeError('settle failed')
    shared.session.finish = finish
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ['settle', 'bound', 'context', 'runtime']
    assert any('settle failed' in note for note in shared.error.__notes__)


@pytest.mark.parametrize('partial_begin', [False, True])
def test_live_children_are_reaped_when_session_cannot_settle(shared, partial_begin):
    shared.session._begun = not partial_begin
    def finish():
        shared.calls.append('settle')
        raise RuntimeError('early finalize guard failed')
    shared.session.finish = finish
    def child(name, returncode):
        process = SimpleNamespace(returncode=returncode)
        process.poll = lambda: process.returncode
        def end_case():
            shared.calls.append(name)
            process.returncode = 0
        return SimpleNamespace(process=process, end_case=end_case)
    shared.runtime.runner.sessions = {'cpu': child('cpu', None),
        'device': child('device', None), 'reaped': child('reaped', 0)}
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ([] if partial_begin else ['settle']) + [
        'cpu', 'device', 'bound', 'context', 'runtime']
    assert all(s.process.poll() == 0 for s in shared.runtime.runner.sessions.values())


def test_child_reap_failure_does_not_skip_remaining_live_children(shared):
    def failed_end():
        shared.calls.append('cpu')
        raise RuntimeError('cpu reap failed')
    shared.runtime.runner.sessions = {
        'cpu': SimpleNamespace(process=SimpleNamespace(poll=lambda: None), end_case=failed_end),
        'device': SimpleNamespace(process=SimpleNamespace(poll=lambda: None),
            end_case=lambda: shared.calls.append('device'))}
    with pytest.raises(ValueError) as caught: shared.run()
    assert caught.value is shared.error
    assert shared.calls == ['settle', 'cpu', 'device', 'bound', 'context', 'runtime']
    assert any('cpu reap failed' in note for note in shared.error.__notes__)

@pytest.mark.parametrize('execution_mode,mode,expected', [
    ('search','original',0), ('develop','original',0),
    ('acceptance','original',1), ('search','fresh',1), (None,'original',1)])
def test_execution_policy_keeps_finish_and_skips_only_optional_replay(shared, monkeypatch, tmp_path, execution_mode, mode, expected):
    completed_body(shared, monkeypatch, tmp_path)
    replays = []
    shared.runtime.replay = lambda prefix: replays.append(prefix) or {'matches': True}
    descriptor = SimpleNamespace(compose='compose', capability='cap', supplement=None,
        flow_ids=('F4',), executors={'F4': 'test'}, shared_slots=False, scenario_id='test', executor=lambda flow: 'test')
    result = campaign.run_descriptor(descriptor, flow='F4', mode=mode,
        case_root=tmp_path/'case', base_dir=tmp_path, execution_mode=execution_mode)
    assert len(replays) == expected
    assert shared.calls.count('finish') == 1
    assert result['replay_matches'] is (True if expected else None)
    assert result['verification']['within_invocation']['status'] == ('verified' if expected else 'not-requested')
