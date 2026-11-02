"""Local command timing is diagnostic and never changes command semantics."""

import pytest

from myfuzz.local_harness.session import GeneratedLocalSession, observe_local_command_timings


def test_command_observer_records_success_and_failure_without_swallowing(monkeypatch):
    session = object.__new__(GeneratedLocalSession)
    # ``object.__new__`` bypasses ``__init__``; mirror the state slot it installs
    # so this session looks like a normally built one that never configured a
    # native-reset observation, which is what the diagnostic path must accept.
    session._native_reset_observation = None
    session._native_reset_build_issuance = None
    calls = []

    def execute(self, operation, fields):
        # The real ``_command_impl`` clears the retained wire reply before it
        # drives anything, so the stand-in does the same.
        self._last_wire_reply = None
        if operation == "BAD":
            raise RuntimeError("driver failed")
        return "receipt"

    monkeypatch.setattr(GeneratedLocalSession, "_command_impl", execute)
    with observe_local_command_timings(lambda operation, seconds: calls.append((operation, seconds))):
        assert session.command("GOOD", ()) == "receipt"
        with pytest.raises(RuntimeError, match="driver failed"):
            session.command("BAD", ())
    assert [operation for operation, _ in calls] == ["GOOD", "BAD"]
    assert all(seconds >= 0 for _, seconds in calls)
    assert session.command("GOOD", ()) == "receipt"
    assert len(calls) == 2
