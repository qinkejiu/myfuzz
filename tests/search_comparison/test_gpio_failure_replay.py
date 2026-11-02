from types import SimpleNamespace
import pytest
from myfuzz.search import gpio_search as gpio


@pytest.fixture(autouse=True)
def forbid_native(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('native/child forbidden')
    monkeypatch.setattr(gpio, 'create_r1_session', forbidden)
    monkeypatch.setattr(gpio.subprocess, 'run', forbidden)
    from myfuzz.search import failure_replay, r1_session
    monkeypatch.setattr(failure_replay, 'launch_failure_replay', forbidden)
    monkeypatch.setattr(r1_session, 'r1_replay_factories', forbidden)


def test_missing_terminal_export_is_explicitly_refused(tmp_path):
    result = gpio.export_gpio_failure_specimen(tmp_path, RuntimeError('observed failure'))
    assert result['status'] == 'refused'
    assert result['accepted'] is False and result['dut_bug'] is False


def test_gpio_failure_replay_refuses_unready_specimen_before_factory(tmp_path):
    result = gpio.replay_gpio_failure_specimen({'status': 'refused'}, tmp_path/'replay', tmp_path/'cache')
    assert result['status'] == 'refused'


@pytest.fixture
def specimen_fixture(tmp_path, monkeypatch):
    from hashlib import sha256
    from myfuzz.search.journal import Journal
    from myfuzz.scenario import session_runtime
    output = tmp_path/'original'
    output.mkdir()
    source = tmp_path/'source.py'
    source.write_text('fixture source\n')
    sources = [{'base': 'project', 'path': str(source), 'sha256': sha256(source.read_bytes()).hexdigest()}]
    journal = Journal(output/'decisions.jsonl')
    journal.append({'kind': 'decision', 'case_id': 'failure-case'})
    summary = {'status': 'failed', 'source_files': sources, 'journal_head': journal.head,
        'elaboration_mode': 'direct', 'controller_execution_nonce': 'independent-original',
        'verification': {'session_boundary': {'status': 'verified', 'matches': True}}}
    config = {'advance_rounds': 96}
    plan = {'schema_version': 17, 'register_programs': {'configuration': config},
            'terminal_failure': {'phase': 'step', 'case_id': 'failure-case',
                'error_type': 'RuntimeError', 'error_message': 'observed execution failure'}}
    encoded = gpio.canonical(plan)
    trace = {'genome_sha256': sha256(encoded).hexdigest(), 'status': 'failed', 'events': [],
             'local_ticks': {}, 'manifest_sha256': 'a'*64}
    trace['semantic_sha256'] = sha256(gpio.canonical({'status': 'failed', 'events': [], 'local_ticks': {}})).hexdigest()
    launches = {'gpio_b': [{'execution_nonce': 'old-native', 'reaped': True, 'binary_sha256': 'same-binary'}]}
    for name, doc in [('summary.json', summary), ('search-summary.json', summary),
        ('failure.json', {'failure_phase': 'submit', 'journal_head': journal.head,
            'signature': {'type': 'RuntimeError', 'message': 'observed execution failure'}}),
        ('configuration.json', {**config, 'elaboration_mode': 'direct'}),
        ('failure-trace.json', trace), ('failure-launches.json', launches)]:
        gpio.save(output/name, doc)
    (output/'failure-plan.json').write_bytes(encoded)
    monkeypatch.setattr(session_runtime, 'validate_register_program_plan', lambda document: None)
    specimen = gpio.export_gpio_failure_specimen(output, RuntimeError('observed execution failure'))
    assert specimen['status'] == 'ready', specimen
    return specimen, output, trace


def test_export_complete_failure_and_refuse_changed_plan(specimen_fixture, tmp_path):
    specimen, original, trace = specimen_fixture
    (original/'failure-plan.json').write_text('{}')
    result = gpio.replay_gpio_failure_specimen(specimen, tmp_path/'replay', tmp_path/'cache')
    assert result['status'] == 'refused'
    assert result['accepted'] is False


@pytest.mark.parametrize('same_nonce,matches,expected', [(False, True, 'reproduced'),
    (True, True, 'not-reproduced'), (False, False, 'not-reproduced')])
def test_replay_requires_full_trace_and_fresh_native_identity(specimen_fixture, tmp_path, monkeypatch,
                                                            same_nonce, matches, expected):
    from myfuzz.search import r1_session
    from myfuzz.scenario import session_runtime
    from myfuzz.scenario.replay import ScenarioTrace
    specimen, original, trace = specimen_fixture
    launch = {'execution_nonce': 'old-native' if same_nonce else 'fresh-native',
              'reaped': True, 'binary_sha256': 'same-binary'}
    runner = SimpleNamespace(sessions={'gpio_b': SimpleNamespace(built_executable_launch_observations=lambda: [launch])})
    monkeypatch.setattr(r1_session, 'r1_replay_factories', lambda *args, **kwargs: (lambda: runner, lambda session: None))
    def replay(plan, factory, reference, **kwargs):
        assert factory() is runner
        return SimpleNamespace(matches=matches, first_difference=None, difference_context=None,
                               verification_scope='full', actual_trace=ScenarioTrace(**trace))
    monkeypatch.setattr(session_runtime, 'replay_online_session', replay)
    result = gpio.replay_gpio_failure_specimen(specimen, tmp_path/'replay', tmp_path/'cache')
    assert result['status'] == expected, result
    assert result['accepted'] is False and result['dut_bug'] is False


@pytest.mark.parametrize('export_fails', [False, True])
def test_submit_failure_exports_finalized_trace_or_explicit_unavailable(tmp_path, monkeypatch, export_fails):
    from myfuzz.scenario.replay import ScenarioTrace
    trace = ScenarioTrace('p', 'uncertain_effect', (), {}, 's', 'm')
    session = SimpleNamespace(_begun=False, _finished=False, encode_plan=lambda: b'{"prefix":true}')
    def finish_export():
        if export_fails:
            raise ValueError('terminal export fixture refused')
        session._finished = True
        return b'{"terminal":true}', trace
    session.finish_export = finish_export
    launch = SimpleNamespace(process=None, built_executable_launch_observations=lambda: [])
    runner = SimpleNamespace(sessions={'gpio_b': launch}, events_since=lambda cursor: [])
    decision = SimpleNamespace(document=lambda: {}, id='decision')
    def submit(*args, **kwargs):
        raise RuntimeError('observed execution failure')
    assembly = SimpleNamespace(session=session, runner=runner,
        space=SimpleNamespace(document=lambda: {}, catalog=SimpleNamespace(identity='catalog')),
        registers=SimpleNamespace(configuration=lambda: {}), begin=lambda: setattr(session, '_begun', True),
        field_state=lambda: {}, submit=submit, close=lambda error: None)
    monkeypatch.setattr(gpio, 'create_r1_session', lambda **kwargs: assembly)
    monkeypatch.setattr(gpio, 'source_files', lambda: [])
    monkeypatch.setattr(gpio, 'Policy', lambda **kwargs: SimpleNamespace(choose=lambda *args: decision))
    monkeypatch.setattr(gpio, 'GpioCredit', lambda *args, **kwargs: None)
    monkeypatch.setattr(gpio, 'live_report', lambda assembly: {})
    monkeypatch.setattr(gpio, 'search_view', lambda *args, **kwargs: (None, None))
    monkeypatch.setattr(gpio, 'frontier', lambda *args: [])
    output = tmp_path/'run'
    with pytest.raises(RuntimeError, match='observed execution failure'):
        gpio._execute(mode='original', policy='state', cases=1, seconds=1, seed=1,
                      cache=tmp_path/'cache', output=output)
    if export_fails:
        assert (output/'failure-export-unavailable.json').exists()
        assert not (output/'failure-trace.json').exists()
    else:
        assert (output/'failure-plan.json').read_bytes() == b'{"terminal":true}'
        assert gpio._load(output/'failure-trace.json')['status'] == 'uncertain_effect'
        assert session._finished


@pytest.mark.parametrize('preexisting', [False, True])
def test_public_failure_launches_only_new_ready_specimen(tmp_path, monkeypatch, preexisting):
    from myfuzz.search import failure_replay
    output = tmp_path/'run'
    if preexisting:
        output.mkdir()
    def boundary(path, run, **kwargs):
        path.mkdir(exist_ok=True)
        raise RuntimeError('observed failure')
    monkeypatch.setattr(gpio, 'run_boundary', boundary)
    calls = []
    def export(path, error, **kwargs):
        calls.append('export')
        return {'status': 'ready'}
    monkeypatch.setattr(gpio, 'export_gpio_failure_specimen', export)
    monkeypatch.setattr(failure_replay, 'launch_failure_replay',
                        lambda *args, **kwargs: calls.append('launch') or {'status': 'not-reproduced'})
    with pytest.raises(RuntimeError, match='observed failure'):
        gpio.execute(mode='original', policy='state', cases=1, seconds=1, seed=1,
                     cache=tmp_path/'cache', output=output, execution_mode='search', elaboration_mode='direct')
    assert calls == ([] if preexisting else ['export', 'launch'])
    if not preexisting:
        assert gpio._load(output/'failure-replay.json')['status'] == 'not-reproduced'


def test_replay_constructs_artifacts_inside_validation_and_elaboration_scope(specimen_fixture, tmp_path, monkeypatch):
    from myfuzz.search import r1_session
    from myfuzz.scenario import session_runtime
    from myfuzz.scenario.replay import ScenarioTrace
    from myfuzz.local_harness.execution_validation import execution_validation_active
    from myfuzz.composition.component_profile import _ELABORATION_MODE
    specimen, original, trace = specimen_fixture
    launch = {'execution_nonce': 'fresh-native', 'reaped': True, 'binary_sha256': 'same-binary'}
    runner = SimpleNamespace(sessions={'gpio_b': SimpleNamespace(built_executable_launch_observations=lambda: [launch])})
    def factories(*args, **kwargs):
        assert execution_validation_active(), 'artifact construction escaped static validation scope'
        assert _ELABORATION_MODE.get() == 'direct', 'artifact construction escaped pinned elaboration scope'
        return lambda: runner, lambda session: None
    monkeypatch.setattr(r1_session, 'r1_replay_factories', factories)
    def replay(plan, factory, reference, **kwargs):
        factory()
        return SimpleNamespace(matches=True, first_difference=None, difference_context=None,
                               verification_scope='full', actual_trace=ScenarioTrace(**trace))
    monkeypatch.setattr(session_runtime, 'replay_online_session', replay)
    result = gpio.replay_gpio_failure_specimen(specimen, tmp_path/'replay', tmp_path/'cache')
    assert result['status'] == 'reproduced', result
