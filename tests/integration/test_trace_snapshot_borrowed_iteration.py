"""The borrowed trace iteration must hash and compare exactly like the detaching one."""
import json

import pytest

from myfuzz.integration.compiled_f6 import (
    _borrowed_trace_events, _canonical, _journal_matches_trace_events)
from myfuzz.scenario.event_journal import EventJournal, EventJournalSnapshot
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.session_runtime import _trace_semantic_sha256


def _events(count=6):
    return [{'event_id': index, 'kind': 'cpu_retire' if index % 2 else 'data_accept',
             'component': 'cpu', 'tick': index, 'nested': {'bytes': [index, 2, 3]}}
            for index in range(1, count + 1)]


def _snapshot(rows):
    journal = EventJournal(chunk_size=2, chunk_cache_size=2)
    for row in rows:
        journal.append(dict(row))
    return journal.snapshot()


def test_borrowed_iteration_yields_the_same_rows_without_detaching():
    rows = _events()
    snapshot = _snapshot(rows)
    assert isinstance(snapshot, EventJournalSnapshot)
    trace = type('Trace', (), {'events': snapshot})()
    borrowed = list(_borrowed_trace_events(trace))
    assert borrowed == rows
    # Detaching iteration returns equal but distinct objects.
    detached = list(snapshot)
    assert detached == rows
    assert all(left is not right for left, right in zip(borrowed, detached))


def test_semantic_hash_is_identical_for_borrowed_and_detached_iteration():
    rows = _events(8)
    snapshot = _snapshot(rows)
    ticks = {'cpu': 3, 'dma': 4}
    detached_hash = _trace_semantic_sha256('complete', snapshot, ticks)
    expected = _trace_semantic_sha256('complete', list(rows), ticks)
    assert detached_hash == expected
    # The snapshot path must equal the plain-list path for the same values,
    # which is what the borrowed iterator is now used for.
    assert _trace_semantic_sha256('complete', snapshot, ticks) == expected
    json.dumps(expected)


def test_journal_trace_comparison_matches_canonical_equality():
    rows = _events(10)
    trace = type('Trace', (), {'events': _snapshot(rows)})()
    unchanged = json.loads(json.dumps(rows))
    mutated = json.loads(json.dumps(rows))
    mutated[4]['tick'] = 99
    assert _journal_matches_trace_events(trace, unchanged) is True
    assert _journal_matches_trace_events(trace, mutated) is False
    assert _journal_matches_trace_events(trace, tuple(unchanged)) is None
