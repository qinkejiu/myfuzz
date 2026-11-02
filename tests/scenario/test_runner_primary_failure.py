"""Cleanup diagnostics must not replace the failing native operation."""
import pytest
from myfuzz.scenario.ownership import OwnershipMap
from myfuzz.scenario.runner import ScenarioRunner


def test_revoked_fetch_drain_preserves_primary_failure(monkeypatch):
    primary=ValueError('MRET has no current logical case')
    class Session:
        def begin_case(self,case):pass
        def step_local(self,inputs):raise primary
    runner=ScenarioRunner(sessions={'cpu':Session()},ownership=OwnershipMap({}),bindings=())
    runner.begin_test('case')
    def drain(*args):raise RuntimeError('unregistered F6 instruction fetch issuer')
    monkeypatch.setattr(runner,'_drain_tick_samples',drain)
    with pytest.raises(ValueError) as caught:
        runner._step_once('cpu')
    assert caught.value is primary
    assert any('unregistered F6 instruction fetch issuer' in note for note in primary.__notes__)
    assert runner.failure_status=='uncertain_effect'


def test_normal_drain_failure_still_rejects_step(monkeypatch):
    class Session:
        def begin_case(self,case):pass
        def step_local(self,inputs):return {}
    runner=ScenarioRunner(sessions={'cpu':Session()},ownership=OwnershipMap({}),bindings=())
    runner.begin_test('case')
    def drain(*args):raise RuntimeError('unregistered F6 instruction fetch issuer')
    monkeypatch.setattr(runner,'_drain_tick_samples',drain)
    with pytest.raises(RuntimeError,match='unregistered F6'):
        runner._step_once('cpu')
