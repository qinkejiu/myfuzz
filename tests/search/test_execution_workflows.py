import json
from contextlib import contextmanager

import pytest


@pytest.mark.parametrize('interesting, expected', [(False, False), (True, True)])
def test_search_replays_only_selected_real_findings(interesting, expected):
    from myfuzz.search.workflow import requires_replay
    assert requires_replay('search', 'original', interesting=interesting) is expected
    assert requires_replay('develop', 'original', interesting=interesting) is False
    assert requires_replay('acceptance', 'original', interesting=interesting) is True


def test_candidate_summary_stays_pending_until_boundary_exit():
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.search.workflow import candidate_summary
    original = {'status': 'completed', 'verification': {'within_invocation': {'status': 'not-requested'}}}
    with execution_validation_scope():
        candidate = candidate_summary(original)
        assert candidate['verification']['session_boundary'] == {'status': 'pending', 'matches': None}
        assert 'session_boundary' not in original['verification']
    assert candidate_summary(original) == original


def test_cross_invocation_can_verify_search_against_acceptance():
    from myfuzz.search.descriptor_search import validate_execution_prefixes
    def row(nonce):
        return dict(component='cpu', execution_nonce=nonce * 32, reaped=True,
                    exit_code=0, pid=1, **{k: 'a' * 64 for k in
                    ('build_digest', 'binary_sha256', 'artifact_digest', 'manifest_sha256')})
    validate_execution_prefixes([row('1')], [row('2'), row('3')], original_replay=False)
    with pytest.raises(ValueError, match='nonce'):
        validate_execution_prefixes([row('1')], [row('1'), row('3')], original_replay=False)
    with pytest.raises(ValueError):
        validate_execution_prefixes([row('1')], [row('2')])


def test_public_boundary_cannot_publish_inside_pending_outer_scope(tmp_path):
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.search.workflow import run_boundary
    output = tmp_path/'run'
    def run():
        output.mkdir()
        return {'status': 'completed'}
    with execution_validation_scope():
        with pytest.raises(ValueError, match='nested'):
            run_boundary(output, run)
    assert not output.exists()


def test_workflow_total_includes_boundary_revalidation(tmp_path, monkeypatch):
    from myfuzz.search import workflow
    from myfuzz.local_harness import execution_validation
    clock = [0.0]
    @contextmanager
    def boundary(**kwargs):
        yield
        clock[0] += 5
    monkeypatch.setattr(workflow, 'monotonic', lambda: clock[0], raising=False)
    monkeypatch.setattr(execution_validation, 'execution_validation_scope', boundary)
    output = tmp_path/'run'
    def run():
        output.mkdir()
        clock[0] += 2
        return {'status': 'completed'}
    result = workflow.run_boundary(output, run)
    assert result['workflow_wall_seconds'] == 7
    assert result['boundary_revalidation_seconds'] == 5


def test_runtime_failure_retains_successful_static_boundary(tmp_path):
    from myfuzz.search.workflow import run_boundary
    output = tmp_path/'run'
    def run():
        output.mkdir()
        raise ValueError('execution failed')
    with pytest.raises(ValueError, match='execution failed'):
        run_boundary(output, run)
    result = json.loads((output/'search-summary.json').read_text())
    assert result['status'] == 'failed'
    assert result['verification']['session_boundary'] == {'status': 'verified', 'matches': True}


def test_existing_search_output_never_triggers_failure_reproduction(tmp_path, monkeypatch):
    from myfuzz.search import descriptor_search
    output = tmp_path/'run'
    (output/'original').mkdir(parents=True)
    calls = []
    monkeypatch.setattr(descriptor_search, '_reproduce_failure', lambda *args: calls.append(args))
    with pytest.raises(ValueError, match='existing output'):
        descriptor_search.execute(descriptor_path=tmp_path/'unused.json', base_dir=tmp_path,
            output=output, execution_mode='search')
    assert calls == []


def cli_args(tmp_path):
    return ['--scenario', 'configs/search/timer-ibex.json', '--mode', 'original',
            '--cases', '1', '--seed', '7', '--output', str(tmp_path/'run'),
            '--cache', str(tmp_path/'cache')]


@pytest.mark.parametrize('fail_boundary', [False, True])
def test_cli_publishes_only_successful_execution_boundary(tmp_path, monkeypatch, fail_boundary):
    from myfuzz.search import cli, descriptor_search
    from myfuzz.local_harness import execution_validation
    calls = []
    @contextmanager
    def boundary(**kwargs):
        calls.append('start')
        yield
        calls.append('end')
        if fail_boundary:
            raise execution_validation.ExecutionValidationError('source drift')
    # Public descriptor.execute owns its boundary; exercise it with its real
    # wrapper and a non-native implementation that writes provisional output.
    def execute(**kwargs):
        calls.append(kwargs['execution_mode'])
        output = kwargs['output']/kwargs['mode']
        output.mkdir(parents=True)
        result = dict(status='completed', mode=kwargs['mode'], replay_matches=None,
                      verification={'within_invocation': {'status': 'not-requested', 'matches': None}})
        (output/'summary.json').write_text(json.dumps(result))
        return result
    monkeypatch.setattr(execution_validation, 'execution_validation_scope', boundary)
    monkeypatch.setattr(descriptor_search, '_execute', execute)
    if fail_boundary:
        with pytest.raises(SystemExit):
            cli.main(cli_args(tmp_path))
    else:
        assert cli.main(cli_args(tmp_path)) == 0
    report = json.loads((tmp_path/'run/original/search-summary.json').read_text())
    assert report['status'] == ('failed' if fail_boundary else 'completed')
    assert report['verification']['session_boundary']['status'] == ('failed' if fail_boundary else 'verified')
    assert calls == ['start', 'search', 'end']


@pytest.mark.parametrize('execution_mode, mode, expected_calls', [
    ('search', 'original', 1), ('develop', 'original', 1),
    ('acceptance', 'original', 2), ('search', 'fresh', 2),
])
def test_static_validation_policy_matches_workflow(tmp_path, execution_mode, mode, expected_calls):
    from myfuzz.search.workflow import run_boundary
    from myfuzz.local_harness.execution_validation import static_validation
    output = tmp_path/'run'
    calls = []
    def validate():
        calls.append(1)
        return 'source'
    def run():
        output.mkdir()
        static_validation('source', validate)
        static_validation('source', validate)
        return {'status': 'completed'}
    result = run_boundary(output, run, execution_mode=execution_mode, mode=mode)
    assert len(calls) == expected_calls
    assert result['static_validation_policy'] == ('entry-and-exit' if expected_calls == 2 else 'entry-only')


def test_failed_search_records_entry_only_policy(tmp_path):
    from myfuzz.search.workflow import run_boundary
    output = tmp_path/'run'
    def run():
        output.mkdir()
        raise RuntimeError('case failed')
    with pytest.raises(RuntimeError, match='case failed'):
        run_boundary(output, run, execution_mode='search')
    result = json.loads((output/'search-summary.json').read_text())
    assert result['status'] == 'failed'
    assert result['static_validation_policy'] == 'entry-only'
