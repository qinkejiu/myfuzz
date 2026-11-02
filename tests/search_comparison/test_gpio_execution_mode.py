import json
import pytest
from pathlib import Path

from myfuzz.search import gpio_search


@pytest.fixture(autouse=True)
def forbid_real_native_and_child(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('real native or child execution forbidden in this module')
    monkeypatch.setattr(gpio_search.subprocess, 'run', forbidden)
    monkeypatch.setattr(gpio_search, 'create_r1_session', forbidden)


def test_gpio_acceptance_runs_a_fresh_controller(tmp_path, monkeypatch):
    output = tmp_path / 'original'
    summary = {'status': 'completed', 'completed_targets': 0, 'submitted_cases': 1,
               'e2e_seconds': 3.0, 'workflow_wall_seconds': 4.0,
               'verification': {'cross_invocation': {'status': 'pending', 'matches': None}}}
    def execute(**kwargs):
        output.mkdir()
        gpio_search.save(output/'summary.json', summary)
        return summary
    monkeypatch.setattr(gpio_search, 'execute', execute)
    calls = []
    def run(argv, **kwargs):
        assert kwargs.get('capture_output') is True
        assert kwargs.get('text') is True
        calls.append(argv)
        fresh = Path(argv[argv.index('--output')+1])
        fresh.mkdir()
        gpio_search.save(fresh/'summary.json', {'status': 'completed', 'mode': 'fresh',
            'replay_matches': True, 'verification': {'cross_invocation': {'status': 'verified', 'matches': True}}})
        from types import SimpleNamespace
        return SimpleNamespace(returncode=0)
    import subprocess
    monkeypatch.setattr(subprocess, 'run', run)
    assert gpio_search.main(['--mode', 'original', '--execution-mode', 'acceptance',
        '--cases', '1', '--seconds', '1', '--seed', '2', '--output', str(output), '--cache', str(tmp_path/'cache')]) == 0
    assert (output/'acceptance-fresh-stdout.txt').read_text() == ''
    assert (output/'acceptance-fresh-stderr.txt').read_text() == ''
    assert summary['automatic_replay_seconds'] >= 0
    assert summary['e2e_seconds'] == 3.0 + summary['automatic_replay_seconds']
    assert summary['workflow_wall_seconds'] == 4.0 + summary['automatic_replay_seconds']
    assert len(calls) == 1
    assert calls[0][calls[0].index('--mode')+1] == 'fresh'
    assert json.loads((output/'summary.json').read_text())['verification']['cross_invocation']['status'] == 'verified'


def test_gpio_search_records_no_within_invocation_replay(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr(gpio_search, 'source_files', lambda: [])
    def unavailable(**kwargs):
        raise RuntimeError('fixture stops before native execution')
    monkeypatch.setattr(gpio_search, 'create_r1_session', unavailable)
    output = tmp_path/'search'
    with pytest.raises(RuntimeError, match='fixture stops'):
        gpio_search.execute(mode='original', execution_mode='search', policy='state',
            cases=1, seconds=1, seed=1, output=output, cache=tmp_path/'cache')
    result = json.loads((output/'summary.json').read_text())
    assert result['verification']['within_invocation'] == {'status': 'not-requested', 'matches': None}
    assert result['verification']['cross_invocation'] == {'status': 'not-requested', 'matches': None}
    assert result['replay_matches'] is None


def test_explicit_gpio_execute_owns_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(gpio_search, 'source_files', lambda: [])
    def forbid_native(**kwargs):
        raise AssertionError('native creation forbidden')
    monkeypatch.setattr(gpio_search, 'create_r1_session', forbid_native)
    calls = []
    monkeypatch.setattr(gpio_search, '_execute', lambda **kwargs: {'raw': kwargs['execution_mode']}, raising=False)
    def boundary(output, run, **kwargs):
        calls.append(output)
        return {**run(), 'boundary': True}
    monkeypatch.setattr(gpio_search, 'run_boundary', boundary, raising=False)
    kwargs = dict(mode='original', policy='state', cases=1, seconds=1,
                  seed=1, output=tmp_path/'out', cache=tmp_path/'cache')
    assert gpio_search.execute(**kwargs, execution_mode='search') == {'raw': 'search', 'boundary': True}
    assert gpio_search.execute(**kwargs) == {'raw': None}
    assert calls == [kwargs['output']]


@pytest.mark.parametrize('mode,hits,expected', [
    ('search', 1, True), ('search', 0, False), ('develop', 1, False),
    ('acceptance', 0, True)])
def test_gpio_selective_replay_policy(tmp_path, monkeypatch, mode, hits, expected):
    output = tmp_path/'original'
    summary = {'status': 'completed', 'completed_targets': hits, 'submitted_cases': 1,
               'verification': {'cross_invocation': {'status': 'not-requested', 'matches': None}}}
    def execute(**kwargs):
        output.mkdir()
        gpio_search.save(output/'summary.json', summary)
        return summary
    monkeypatch.setattr(gpio_search, 'execute', execute)
    calls = []
    monkeypatch.setattr(gpio_search, '_acceptance_fresh', lambda args, row: calls.append(dict(row)))
    gpio_search.main(['--mode', 'original', '--execution-mode', mode,
        '--cases', '1', '--seconds', '1', '--seed', '2', '--output', str(output), '--cache', str(tmp_path/'cache')])
    assert bool(calls) is expected
    if mode == 'search' and expected:
        assert calls[0]['replay_reason'] == 'new-certified-relation'


def test_gpio_records_and_reuses_mode_before_boundary(tmp_path, monkeypatch):
    from myfuzz.composition import component_profile as cp
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (False, 'fixture'))
    calls = []
    def run(**kwargs):
        calls.append(kwargs['elaboration_mode'])
        return {'elaboration_mode': kwargs['elaboration_mode']}
    monkeypatch.setattr(gpio_search, '_execute', run)
    monkeypatch.setattr(gpio_search, 'run_boundary', lambda output, run, **kwargs: run())
    kwargs = dict(policy='state', cases=1, seconds=1, seed=1, cache=tmp_path/'cache', execution_mode='search')
    original = tmp_path/'original'
    original.mkdir()
    row = gpio_search.execute(**kwargs, mode='original', output=tmp_path/'unused')
    gpio_search.save(original/'summary.json', row)
    gpio_search.save(original/'configuration.json', row)
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (True, ''))
    gpio_search.execute(**kwargs, mode='fresh', output=tmp_path/'fresh', original=original)
    assert calls == ['direct', 'direct']
    with pytest.raises(ValueError, match='elaboration mode'):
        gpio_search.execute(**kwargs, mode='fresh', output=tmp_path/'bad', original=original, elaboration_mode='supervised')


def test_gpio_rejects_tampered_mode_configuration_before_native(tmp_path):
    original = tmp_path/'original'
    original.mkdir()
    gpio_search.save(original/'summary.json', {'elaboration_mode': 'direct'})
    gpio_search.save(original/'configuration.json', {'elaboration_mode': 'supervised'})
    with pytest.raises(ValueError, match='configuration mismatch'):
        gpio_search.execute(mode='fresh', policy='state', cases=1, seconds=1, seed=1,
            cache=tmp_path/'cache', output=tmp_path/'fresh', original=original,
            execution_mode='search')


def test_gpio_still_compares_entire_runtime_binding(tmp_path, monkeypatch):
    from types import SimpleNamespace
    original = tmp_path/'original'
    original.mkdir()
    reference = {'status': 'completed', 'controller_execution_nonce': 'other-controller',
        'source_files': [], 'journal_head': 'fixture', 'policy': 'state', 'requested_cases': 1,
        'fixed_seconds': 1, 'seed': 1, 'ablation': 'none'}
    gpio_search.save(original/'summary.json', reference)
    gpio_search.save(original/'selected_cases.json', [])
    gpio_search.save(original/'configuration.json', {'current_binding': {'binding_hash': 'original'}})
    monkeypatch.setattr(gpio_search, 'source_files', lambda: [])
    monkeypatch.setattr(gpio_search, 'verify_journal', lambda *args, **kwargs: None)
    space = SimpleNamespace(document=lambda: {}, catalog=SimpleNamespace(identity='fixture'))
    assembly = SimpleNamespace(space=space, runner=SimpleNamespace(sessions={}, events_since=lambda cursor: []),
        registers=SimpleNamespace(configuration=lambda: {'current_binding': {'binding_hash': 'tampered'}}),
        close=lambda error: None)
    monkeypatch.setattr(gpio_search, 'create_r1_session', lambda **kwargs: assembly)
    monkeypatch.setattr(gpio_search, '_prefix', lambda assembly: b'{}')
    with pytest.raises(ValueError, match='fresh runtime configuration differs'):
        gpio_search._execute(mode='fresh', policy='state', cases=1, seconds=1, seed=1,
            cache=tmp_path/'cache', output=tmp_path/'fresh', original=original)
