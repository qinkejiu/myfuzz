"""Cheap negative readiness must avoid scanning the growing Runner history."""
import pytest

from myfuzz.integration.compiled_f6 import CompiledF6Runtime
from tests.integration.test_compiled_f6_runtime import (
    _case_stop_ready, _completed_case,
)


@pytest.mark.parametrize('conflict', [False, True], ids=['missing-latch', 'conflicting-latch'])
def test_unavailable_fetch_latch_does_not_scan_journal(tmp_path, monkeypatch, conflict):
    runtime, attempt, _material = _completed_case(tmp_path, monkeypatch)
    runtime.response_fault = None
    assert _case_stop_ready(runtime, attempt) is True
    assert type(runtime.observer_view) is list
    runtime._f6_pending_fetch_sample = {} if conflict else None
    runtime._f6_pending_fetch_sample_conflict = conflict
    journal_calls = []

    def reject_journal(start):
        journal_calls.append(start)
        raise AssertionError('readiness must reject unavailable latch before history scan')

    runtime.runner.events_since = reject_journal
    assert CompiledF6Runtime._case_boundary_stop_ready(runtime, attempt) is False
    # The predicate catches journal exceptions, so count calls as well.
    assert journal_calls == []
