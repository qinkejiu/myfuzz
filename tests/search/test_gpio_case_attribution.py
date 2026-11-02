"""Case attribution copies exact completed intervals from the actual runner."""
from dataclasses import replace

from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.search.gpio_relations import _bind_case_session, _read_case_attribution
from tests.scenario.test_session_runtime_paths import configured, case


def test_case_attribution_never_copies_unrelated_event_suffix():
    session = configured()
    session.begin()
    try:
        first = case(session)
        one = session.submit_case(first)
        second = replace(first, case_id='two', source=replace(first.source, action_id='two:s'))
        two = session.submit_case(second)
        intervals = {(one.event_start, one.event_end), (two.event_start, two.event_end)}
        calls = []

        def bounded_reader(runner, start, *, stop=None):
            assert (start, stop) in intervals, 'attribution copied an unrelated suffix'
            calls.append((start, stop))
            return ScenarioRunner.events_since(runner, start, stop=stop)

        ids = {one.events[0]['event_id'], two.events[-1]['event_id']}
        found = _read_case_attribution(_bind_case_session(session, session.runner),
            session.runner, {'events_since': bounded_reader}, ids)
        assert found == {one.events[0]['event_id']: {'case_id': 'one', 'case_index': 0},
                         two.events[-1]['event_id']: {'case_id': 'two', 'case_index': 1}}
        assert calls == [(one.event_start, one.event_end), (two.event_start, two.event_end)]
    finally:
        session.finish()
