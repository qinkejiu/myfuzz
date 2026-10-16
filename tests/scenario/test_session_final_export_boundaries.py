"""Independent actual-object export boundaries, software transport only."""
import hashlib
import json
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session, observed_factory
from tests.scenario.test_register_program_runtime import request


@pytest.mark.parametrize('method', ['encode_plan', 'trace'])
def test_actual_final_export_rejects_instance_method_substitution(actual_factory, method):
    result = session(actual_factory)
    runtime = adapter(result)
    result.begin()
    runtime.submit(request(target_instance='gpio_a'))
    if method == 'encode_plan':
        result.encode_plan = lambda: b'{"caller_saved_authority":true}'
    else:
        result.trace = lambda **kwargs: {'caller_saved_trace': True}
    with pytest.raises((ValueError, RuntimeError), match='drift|method|export'):
        result.finish_export()


def test_actual_final_export_includes_finalize_drained_cpu_commit(actual_factory):
    result = session(observed_factory(actual_factory))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result)
    result.configure_register_program_verifier(max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', operation='register_read', value=None,
                           result_address=0x10004, allow_side_effect=False))
    cpu = result.runner.sessions['cpu']
    assert cpu._pending_data[0] == 17
    before = result.runner.event_count
    # Execute a genuine software MemoryService callback at finalization, then
    # drain its actual issued token through the production Runner hook.
    def finalize():
        cpu._pending_data = None
        cpu._serve('data', 1, 0x10004, 17, 15)
        result.runner._append_external_events('cpu', 1)
    result.runner.finalize = finalize
    plan, trace = result.finish_export()
    document = json.loads(plan)
    assert document['schema_version'] == 16
    assert result.runner.event_count > before
    assert trace.events == result.runner.events
    assert trace.genome_sha256 == hashlib.sha256(plan).hexdigest()
    wrapper = document['register_programs']['register_program_verifier']
    # The late actual result is outside the submitted case's sealed span.
    # Export the real final event without upgrading it to a case certificate.
    assert wrapper['state']['historical_certificates'] == []
    assert wrapper == json.loads(json.dumps(result._register_verifier.session_document()))
    wrapper['state']['historical_certificates'].clear()
    assert result._register_verifier.report()['historical_certificates'] == []


@pytest.mark.parametrize('method', ['encode_plan', 'trace'])
def test_actual_final_export_rejects_class_method_substitution(actual_factory, monkeypatch, method):
    from myfuzz.scenario.session_runtime import ScenarioSession
    result = session(actual_factory)
    runtime = adapter(result)
    result.begin()
    runtime.submit(request(target_instance='gpio_a'))
    if method == 'encode_plan':
        monkeypatch.setattr(ScenarioSession, method, lambda self: b'{"caller_saved_authority":true}')
    else:
        monkeypatch.setattr(ScenarioSession, method, lambda self, **kwargs: {'caller_saved_trace': True})
    with pytest.raises((ValueError, RuntimeError), match='drift|method|export'):
        result.finish_export()


@pytest.mark.parametrize('method', ['encode_plan', 'trace'])
def test_actual_final_export_rechecks_methods_after_finalizer(actual_factory, method):
    result = session(actual_factory)
    runtime = adapter(result)
    result.begin()
    runtime.submit(request(target_instance='gpio_a'))
    entered = []
    def finalize():
        entered.append(True)
        if method == 'encode_plan':
            result.encode_plan = lambda: b'{"caller_saved_authority":true}'
        else:
            result.trace = lambda **kwargs: {'caller_saved_trace': True}
    result.runner.finalize = finalize
    with pytest.raises((ValueError, RuntimeError), match='drift|method|export'):
        result.finish_export()
    assert entered == [True]


@pytest.mark.parametrize('mutation', ['sidecar_bytes', 'same_count_memory_slots'])
def test_actual_final_export_rechecks_context_after_finalizer(actual_factory, tmp_path, mutation):
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from tests.scenario.test_register_program_replay import SIDECAR
    result = session(actual_factory)
    sidecar = tmp_path / 'actual-sidecar.json'
    sidecar.write_bytes(SIDECAR.read_bytes())
    runtime = RegisterProgramRuntime(result, cpu_component='cpu',
        sidecars={'gpio_a': sidecar}, advance_rounds=1)
    result.begin()
    runtime.submit(request(target_instance='gpio_a'))
    entered = []
    def finalize():
        entered.append(True)
        if mutation == 'sidecar_bytes':
            # Same parsed JSON, different actually pinned source bytes.
            sidecar.write_bytes(sidecar.read_bytes() + b'\n')
        else:
            memory = result.runner.sessions['cpu'].service.memory
            previous = set(memory._instruction_slots)
            key = next(iter(previous))
            memory._instruction_slots.remove(key)
            memory._instruction_slots.add((key[0], key[1] + 0x1000))
            assert len(memory._instruction_slots) == len(previous)
            assert memory._instruction_slots != previous
    result.runner.finalize = finalize
    with pytest.raises(ValueError, match='drift|configuration|memory'):
        result.finish_export()
    assert entered == [True]
