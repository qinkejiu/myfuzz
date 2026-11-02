"""Trusted synchronous event borrowing does not weaken public isolation."""
import pytest
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.event_journal import EventJournal


@pytest.mark.parametrize('journal', [False, True])
def test_borrowed_interval_and_public_isolation(journal):
    runner = object.__new__(ScenarioRunner)
    runner._events = EventJournal(chunk_size=2) if journal else []
    try:
        for i in range(5):
            runner._events.append({'event_id': i+1, 'versions': [[0, i]]})
        borrowed = runner._event_refs_since(1, stop=4)
        assert isinstance(borrowed, tuple)
        assert [r['event_id'] for r in borrowed] == [2, 3, 4]
        assert runner._event_refs_since(5, stop=5) == ()
        detached = runner.events_since(1, stop=4)
        detached[0]['versions'][0][1] = -1
        assert borrowed[0]['versions'][0][1] == 1
        runner._event_refs_since = lambda *a, **kw: ({'forged': True},)
        assert runner.events_since(1, stop=2)[0]['event_id'] == 2
    finally:
        if journal: runner._events.close()


@pytest.mark.parametrize('index,stop', [(True, 1), (-1, 1), (0, True), (1, 0), (0, 2)])
def test_borrowed_interval_rejects_invalid_bounds(index, stop):
    runner = object.__new__(ScenarioRunner)
    runner._events = [{'event_id': 1}]
    with pytest.raises(ValueError): runner._event_refs_since(index, stop=stop)
