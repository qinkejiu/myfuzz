"""Opt-in full dependency drift refuses preparation and cached retry before effects."""
import pytest
from tests.scenario.test_ordinary_apb_access_session import actual_factory, session, adapter
from tests.scenario.test_register_program_runtime import request
import myfuzz.scenario.session_runtime as session_module


def drift_sources(monkeypatch):
    actual = session_module._ordinary_apb_access_source_files
    def drift(paths=None):
        rows = actual(paths)
        rows[0]['sha256'] = 'f' * 64
        return rows
    monkeypatch.setattr(session_module, '_ordinary_apb_access_source_files', drift)


def test_dependency_drift_rejects_prepare_before_any_reservation(actual_factory, monkeypatch):
    current = session(actual_factory)
    current.configure_ordinary_apb_access_evidence(max_records=2)
    runtime = adapter(current)
    current.begin()
    memory = current.runner.sessions['cpu'].memory
    before = memory.state_summary(), current.prerequisite_gate.document(), runtime.snapshot()
    drift_sources(monkeypatch)
    with pytest.raises(ValueError, match='ordinary-apb-session-source-drift'):
        runtime.prepare(request(target_instance='gpio_a'))
    assert (memory.state_summary(), current.prerequisite_gate.document(), runtime.snapshot()) == before


def test_dependency_drift_rejects_successful_cached_retry(actual_factory, monkeypatch):
    current = session(actual_factory)
    current.configure_ordinary_apb_access_evidence(max_records=2)
    runtime = adapter(current)
    current.begin()
    original = request(target_instance='gpio_a')
    runtime.submit(original)
    memory = current.runner.sessions['cpu'].memory
    before = memory.state_summary(), current.prerequisite_gate.document(), runtime.snapshot()
    drift_sources(monkeypatch)
    with pytest.raises(ValueError, match='ordinary-apb-session-source-drift'):
        runtime.submit(original)
    assert (memory.state_summary(), current.prerequisite_gate.document(), runtime.snapshot()) == before
