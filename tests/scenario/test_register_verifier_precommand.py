"""Independent precommand guards: capacity limits new operations, not replay/export."""
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session
from tests.scenario.test_register_program_verifier import read_result_factory
from tests.scenario.test_register_program_runtime import request


def saturated(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result = session(read_result_factory(actual_factory))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result)
    verifier = RegisterProgramVerifier(runtime, max_records=1)
    result.begin()
    original = request(target_instance='gpio_a', operation='register_read', value=None,
        result_address=0x10004, allow_side_effect=False)
    submitted = runtime.submit(original)
    assert len(verifier.report()['historical_certificates']) == 1
    return result, runtime, verifier, original, submitted


def test_full_capacity_allows_legal_remaining_physical_tick_and_history_export(actual_factory):
    result, runtime, verifier, _, _ = saturated(actual_factory)
    runner = result.runner; cpu = runner.sessions['cpu']; calls = []
    def stepped(inputs):
        calls.append(inputs)
        cpu.local_ticks += 1
        return {}
    cpu.step_local = stepped
    before = dict(runner.local_ticks)
    history = verifier.report()['historical_certificates']
    runner._step_once('cpu')
    assert len(calls) == 1
    assert runner.local_ticks['cpu'] == before['cpu'] + 1
    assert verifier.report()['historical_certificates'] == history
    assert result.encode_plan()


def test_full_capacity_rejects_new_prepare_before_any_admission_mutation(actual_factory):
    result, runtime, verifier, _, _ = saturated(actual_factory)
    runner = result.runner; gate = result.prerequisite_gate
    before = (runner.event_count, dict(runner.local_ticks), gate.document(),
        runner.sessions['cpu'].memory.state_summary(), runtime.snapshot())
    with pytest.raises(ValueError, match='capacity'):
        runtime.prepare(request(case_id='second-case', action_id='second-action',
            target_instance='gpio_a', operation='register_read', value=None,
            result_address=0x10008, allow_side_effect=False))
    assert (runner.event_count, dict(runner.local_ticks), gate.document(),
        runner.sessions['cpu'].memory.state_summary(), runtime.snapshot()) == before
    assert len(verifier.report()['historical_certificates']) == 1


def test_full_capacity_cached_submit_remains_idempotent(actual_factory):
    result, runtime, verifier, original, first = saturated(actual_factory)
    before = (result.runner.event_count, result.prerequisite_gate.document(), runtime.snapshot())
    again = runtime.submit(original)
    assert again == first
    assert (result.runner.event_count, result.prerequisite_gate.document(), runtime.snapshot()) == before
    assert len(verifier.report()['historical_certificates']) == 1


@pytest.mark.parametrize('entry', ['runner_step', 'runtime_prepare', 'session_reset'])
def test_instance_guard_override_is_rejected_before_any_actual_command(actual_factory, entry):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result = session(read_result_factory(actual_factory))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result); RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', operation='register_read', value=None,
        result_address=0x10004, allow_side_effect=False))
    runner = result.runner; cpu = runner.sessions['cpu']; calls = []
    runner._guard_register_program_verifier = lambda **kwargs: None
    def stepped(inputs):
        calls.append(inputs)
        cpu.local_ticks += 1
        return {}
    cpu.step_local = stepped
    runner.reset_all = lambda policy: calls.append(policy)
    before = (runner.event_count, dict(runner.local_ticks), cpu.memory.generation,
        result.prerequisite_gate.document(), list(result._reset_operations), runtime.snapshot())
    with pytest.raises(ValueError, match='guard.*drift|method.*drift'):
        if entry == 'runner_step': runner._step_once('cpu')
        elif entry == 'session_reset': result.reset('warm_all')
        else: runtime.prepare(request(target_instance='gpio_a', allow_side_effect=False))
    assert calls == []
    assert (runner.event_count, dict(runner.local_ticks), cpu.memory.generation,
        result.prerequisite_gate.document(), list(result._reset_operations), runtime.snapshot()) == before
