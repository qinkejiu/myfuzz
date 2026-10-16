"""Actual software Runner resets in the online Session command timeline."""
import json
import pytest
from tests.scenario.test_online_session_partial_replay import _factory, _template
from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase, replay_online_session
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent


def factory():
    runner = _factory()
    local = runner.sessions['cpu']
    local.reset_local = lambda: {'cancelled_responses': 0}
    return runner


def case(index):
    return OnlineCase(f'case-{index}', 'CPU_TO_IP', 'unit',
        BatchSourceEvent(f'source-{index}', 'cpu', 'source', 2),
        (BatchAdvance(('cpu',)),))


def test_warm_and_cold_resets_preserve_case_order_and_replay():
    session = ScenarioSession(_template(), factory())
    session.begin(); session.submit_case(case(0))
    session.reset('warm_all'); session.submit_case(case(1)); session.reset('cold_all')
    trace = session.finish(); plan = session.encode_plan()
    document = json.loads(plan)
    assert document['schema_version'] == 14
    assert document['reset_operations'] == [dict(after_cases=1, policy='warm_all'),
                                           dict(after_cases=2, policy='cold_all')]
    comparison = replay_online_session(plan, factory, trace)
    assert comparison.matches, comparison.difference_context
    assert [e['policy'] for e in comparison.actual_trace.events
            if e.get('kind') == 'reset_barrier'] == ['warm_all', 'cold_all']


def test_unrecorded_runner_reset_cannot_encode_a_replayable_plan():
    session = ScenarioSession(_template(), factory());session.begin()
    session.runner.reset_all('warm_all')
    with pytest.raises(ValueError, match='unrecorded reset'):
        session.encode_plan()
    with pytest.raises(ValueError, match='unrecorded reset'):
        session.finish()
    assert session._finished


@pytest.mark.parametrize('operation', [dict(after_cases=True, policy='warm_all'),
    dict(after_cases=0, policy='warm_all'), dict(after_cases=2, policy='warm_all'),
    dict(after_cases=1, policy='guessed_reset'), dict(after_cases=1, policy='cold_all', extra=True)])
def test_malformed_reset_timeline_rejects_before_factory(operation):
    import hashlib
    from dataclasses import replace
    session=ScenarioSession(_template(),factory());session.begin();session.submit_case(case(0))
    session.reset('warm_all');trace=session.finish();doc=json.loads(session.encode_plan())
    doc['reset_operations']=[operation];plan=json.dumps(doc).encode()
    reference=replace(trace,genome_sha256=hashlib.sha256(plan).hexdigest())
    def forbidden():pytest.fail('malformed reset plan reached factory')
    with pytest.raises(ValueError,match='reset operation timeline'):
        replay_online_session(plan,forbidden,reference)


def test_failed_reset_does_not_produce_replayable_success_prefix():
    runner=factory();session=ScenarioSession(_template(),runner)
    session.begin();session.submit_case(case(0))
    def partial_reset():raise RuntimeError('partial reset failure')
    runner.sessions['cpu'].reset_local=partial_reset
    with pytest.raises(RuntimeError,match='partial reset failure'):session.reset('warm_all')
    with pytest.raises(ValueError,match='uncertain'):session.encode_plan()
    assert session._halted and session._reset_operations==[]
    with pytest.raises(ValueError,match='uncertain'):session.finish()


def test_terminal_case_failure_after_reset_replays_schema_fifteen():
    from dataclasses import replace
    session=ScenarioSession(_template(),factory());session.begin();session.submit_case(case(0))
    session.reset('cold_all')
    failing=case(1);failing=replace(failing,source=replace(failing.source,value=7))
    with pytest.raises(RuntimeError,match='local step failed'):session.submit_case(failing)
    trace=session.finish();plan=session.encode_plan()
    assert json.loads(plan)['schema_version']==15
    comparison=replay_online_session(plan,factory,trace)
    assert comparison.matches,comparison.difference_context


def test_replay_reset_failure_finishes_all_components():
    session=ScenarioSession(_template(),factory());session.begin();session.submit_case(case(0))
    session.reset('warm_all');trace=session.finish();plan=session.encode_plan()
    ended=[]
    def failing_factory():
        runner=factory()
        def fail():raise RuntimeError('replay reset failed')
        runner.sessions['cpu'].reset_local=fail
        runner.sessions['cpu'].end_case=lambda:ended.append('cpu')
        return runner
    with pytest.raises(RuntimeError,match='replay reset failed'):
        replay_online_session(plan,failing_factory,trace)
    assert ended==['cpu']
