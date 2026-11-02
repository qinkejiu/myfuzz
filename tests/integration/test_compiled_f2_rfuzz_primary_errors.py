"""Controlled software faults through real F2 executor/live/wrapper seams.

The inner transport and identity writer are explicit software doubles. No
client, DUT, native preparation or native authority is supplied by these tests.
"""
import json
import time
from types import SimpleNamespace

import pytest

from myfuzz.integration.compiled_f2 import CompiledF2Runtime
from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.scenario.replay import ScenarioTrace
from tests.integration.f2_rfuzz_support import transport_case, f2_transport_inputs


def fail(error):
    def raise_error(*args, **kwargs):
        raise error
    return raise_error


def live_case(transport_case, tmp_path, monkeypatch, *, execute=True,
              transport_error=None, context=True, writer_fault=None):
    from myfuzz.integration import scenario_rfuzz_live as live
    executor, runtime, valid = transport_case
    calls = []
    runtime.finished = False
    runtime.runner.events = []
    runtime.runner.events_since = lambda start: iter(runtime.trace.events)
    runtime.trace = ScenarioTrace('synthetic', 'synthetic_transport_only',
        [{'synthetic_transport_only': True}], {}, 'synthetic', 'synthetic')
    runtime.session.runner = runtime.runner
    runtime.session.manifest_document = {}
    runtime.session.dma_binding_document = lambda: None
    runtime.session.encode_plan = lambda: b'{}'
    finish = runtime.finish
    def finish_runtime():
        runtime.finished = True
        return finish()
    runtime.finish = finish_runtime
    original_artifact = live._write_online_artifact
    original_trace = live._write_online_trace
    fault = OSError('controlled-' + str(writer_fault))
    def artifact(path, payload):
        calls.append(path.name)
        if path.name == writer_fault:
            raise fault
        return original_artifact(path, payload)
    def trace(path, value):
        calls.append(path.name)
        if path.name == writer_fault:
            raise fault
        return original_trace(path, value)
    def identity(output, **kwargs):
        calls.append('identity')
        if writer_fault == 'identity':
            raise fault
        # Deliberate software-only identity double, never native evidence.
        return 'synthetic-identity'
    def inner(**kwargs):
        output = kwargs['output_dir']
        output.mkdir(parents=True, exist_ok=True)
        if context:
            executor._live_context = dict(output=output,
                frozen_inputs={'client': {'synthetic_transport_only': True},
                               'source_files': []},
                checker_identity={'synthetic_transport_only': True},
                binary=kwargs['client_binary'], decoder_manifest_sha256='synthetic',
                started=time.monotonic(), exchanges=1, client_returncode=0,
                effective_search_seconds=0.0)
        if execute:
            executor.execute_batch(InputBatch(81, 8, ((valid,),)))
        if transport_error is not None:
            raise transport_error
        return SimpleNamespace(client_returncode=0)
    monkeypatch.setattr(live, '_run_scenario_rfuzz_live', inner)
    monkeypatch.setattr(live, '_write_online_artifact', artifact)
    monkeypatch.setattr(live, '_write_online_trace', trace)
    monkeypatch.setattr(live, '_write_online_run_identity', identity)
    args = dict(executor=executor, client_binary=tmp_path/'software-client',
        output_dir=tmp_path/'live', duration_seconds=1, seed_records=(valid,),
        max_tests=1)
    return live, args, calls, fault


@pytest.mark.parametrize('phase', ['before', 'after', 'certificate', 'feedback'])
def test_execution_primary_survives_successful_or_failed_finish(
        transport_case, monkeypatch, phase):
    from myfuzz.integration import compiled_f2_rfuzz as module
    executor, runtime, valid = transport_case
    primary = RuntimeError('controlled-' + phase)
    submit = runtime.submit
    def faulty_submit(raw):
        if phase == 'before':
            raise primary
        result = submit(raw)
        if phase == 'after':
            runtime._failed_attempt = runtime.attempts[-1]['case_id']
            raise primary
        return result
    runtime.submit = faulty_submit
    if phase == 'certificate':
        monkeypatch.setattr(executor, '_validate_certificate', fail(primary))
    if phase == 'feedback':
        monkeypatch.setattr(module, 'f2_observation_hits', fail(primary))
    assert executor.execute_batch(InputBatch(80, 8, ((valid,),))) == (
        bytes(executor.counter_count),)
    assert executor.receipts[-1].status == 'environment_error'
    assert executor.online_decisions[-1]['case_ids'] == [
        row['case_id'] for row in runtime.attempts]
    if phase == 'after':
        runtime.finished = True
        runtime.finish = lambda: CompiledF2Runtime._finish(runtime)
    with pytest.raises(RuntimeError) as caught:
        executor._finish_online_session()
    assert caught.value is primary
    assert executor._online_primary_error is primary
    pair = executor._finish_online_session()
    assert pair == (runtime.trace, b'synthetic-plan'.hex())
    assert type(pair) is tuple


def test_execution_primary_keeps_failure_file_and_partial_export_notes(
        transport_case, tmp_path):
    executor, runtime, valid = transport_case
    primary = RuntimeError('controlled-submit')
    runtime.submit = fail(primary)
    executor.evidence_dir = tmp_path/'absent'
    executor.execute_batch(InputBatch(82, 8, ((valid,),)))
    cleanup = OSError('controlled-finish')
    trace = OSError('controlled-partial-trace')
    runtime.finish = fail(cleanup)
    runtime.session.trace = fail(trace)
    with pytest.raises(RuntimeError) as caught:
        executor._finish_online_session()
    assert caught.value is primary
    notes = '\n'.join(primary.__notes__)
    assert all(text in notes for text in [
        'F2 failure export:', 'controlled-finish', 'controlled-partial-trace'])
    assert executor._finish_online_session() == (None, b'synthetic-plan'.hex())


def test_partial_plan_failure_retains_trace_and_finish_primary(transport_case):
    executor, runtime, _ = transport_case
    primary = OSError('controlled-first-finish')
    secondary = OSError('controlled-partial-plan')
    runtime.finish = fail(primary)
    runtime.session.encode_plan = fail(secondary)
    with pytest.raises(OSError) as caught:
        executor._finish_online_session()
    assert caught.value is primary
    assert executor._online_primary_error is None
    assert 'controlled-partial-plan' in '\n'.join(primary.__notes__)
    assert executor._finish_online_session() == (runtime.trace, None)


@pytest.mark.parametrize('writer', [None, 'online_plan.json',
    'online_final_trace.json', 'identity', 'report.json'])
def test_real_live_finalizer_keeps_execution_primary_and_attempts_exports(
        transport_case, tmp_path, monkeypatch, writer):
    executor, runtime, _ = transport_case
    primary = RuntimeError('controlled-submit')
    runtime.submit = fail(primary)
    live, args, calls, _ = live_case(transport_case, tmp_path, monkeypatch,
        writer_fault=writer)
    with pytest.raises(RuntimeError) as caught:
        live.run_scenario_rfuzz_live(**args)
    assert caught.value is primary
    assert 'online_plan.json' in calls and 'online_final_trace.json' in calls
    assert 'report.json' in calls
    if writer in ('online_plan.json', 'online_final_trace.json'):
        assert 'identity' not in calls
        assert (args['output_dir']/'incomplete_run_identity.json').is_file()
    if writer is not None:
        assert ('controlled-' + writer) in '\n'.join(primary.__notes__)
    if writer != 'report.json':
        report = json.loads((args['output_dir']/'report.json').read_text())
        assert report['execution_status'] in ('failed', 'incomplete')
    assert runtime.finish_calls == 1
    assert type(executor._finish_online_session()) is tuple


@pytest.mark.parametrize('context', [True, False])
@pytest.mark.parametrize('submit_first', [True, False])
def test_transport_and_finish_chronology(transport_case, tmp_path, monkeypatch,
                                         context, submit_first):
    executor, runtime, _ = transport_case
    execution = RuntimeError('controlled-first-submit')
    transport = OSError('controlled-transport')
    finish_error = OSError('controlled-later-finish')
    runtime.submit = fail(execution)
    live, args, _, _ = live_case(transport_case, tmp_path, monkeypatch,
        execute=submit_first, transport_error=transport, context=context)
    runtime.finish = fail(finish_error)
    with pytest.raises(Exception) as caught:
        live.run_scenario_rfuzz_live(**args)
    primary = execution if submit_first else transport
    assert caught.value is primary
    assert 'controlled-later-finish' in '\n'.join(primary.__notes__)
    if submit_first:
        assert 'controlled-transport' in '\n'.join(primary.__notes__)
    else:
        assert executor._online_primary_error is None


def test_finish_first_survives_writer_fault_without_becoming_execution_primary(
        transport_case, tmp_path, monkeypatch):
    executor, runtime, _ = transport_case
    live, args, calls, _ = live_case(transport_case, tmp_path, monkeypatch,
        execute=False, writer_fault='online_plan.json')
    primary = OSError('controlled-first-finish')
    runtime.finish = fail(primary)
    with pytest.raises(OSError) as caught:
        live.run_scenario_rfuzz_live(**args)
    assert caught.value is primary
    assert executor._online_primary_error is None
    assert 'controlled-online_plan.json' in '\n'.join(primary.__notes__)
    assert 'online_final_trace.json' in calls and 'report.json' in calls


def test_successful_live_path_and_repeat_finish_remain_tuple(
        transport_case, tmp_path, monkeypatch):
    executor, runtime, _ = transport_case
    live, args, calls, _ = live_case(transport_case, tmp_path, monkeypatch)
    result = live.run_scenario_rfuzz_live(**args)
    assert result.client_returncode == 0 and 'identity' in calls
    assert executor._online_primary_error is None
    pair = executor._finish_online_session()
    assert type(pair) is tuple and pair == (runtime.trace, b'{}'.hex())
    assert runtime.finish_calls == 1


def test_actual_executor_live_wrapper_preserves_primary_and_all_failure_exports(
        transport_case, tmp_path, monkeypatch):
    from tests.integration.test_compiled_f2_rfuzz_session import software_session
    executor, runtime, _ = transport_case
    mod, wrapper_args, wrapper_calls, output = software_session(tmp_path, monkeypatch)
    primary = RuntimeError('controlled-connected-submit')
    runtime.submit = fail(primary)
    live, _, _, _ = live_case(transport_case, tmp_path, monkeypatch,
        writer_fault='online_plan.json')
    executor.evidence_dir = tmp_path/'absent'
    runtime.execution_binding.document = lambda: {'path_id': 'F2', 'runtime_path_id': 'runtime'}
    runtime.assertion_results = lambda: {'cases': []}
    runtime.assertion_case_evidence = lambda: []
    runtime.run_id = 'run'
    monkeypatch.setattr(mod, 'CompiledF2Runtime', lambda **kwargs: runtime)
    monkeypatch.setattr(mod, 'build_compiled_f2_rfuzz_executor', lambda *a, **kw: executor)
    monkeypatch.setattr(mod, 'run_scenario_rfuzz_live', live.run_scenario_rfuzz_live)
    exports = []
    writer = mod.write_pinned_json
    def export(path, value, pins):
        exports.append(path.name)
        if path.name == 'compiled_f2_partial_events.json':
            raise OSError('controlled-wrapper-export')
        return writer(path, value, pins)
    monkeypatch.setattr(mod, 'write_pinned_json', export)
    joins = []
    build_join = mod.build_compiled_f2_build_join
    def join(**kwargs):
        joins.append(kwargs)
        return build_join(**kwargs)
    monkeypatch.setattr(mod, 'build_compiled_f2_build_join', join)
    with pytest.raises(RuntimeError) as caught:
        mod.run_f2_live_and_fresh(**wrapper_args)
    assert caught.value is primary
    assert joins[-1]['error'] is primary
    assert not any(row[0] == 'replay' for row in wrapper_calls)
    assert set(exports) == {'compiled_f2_build_join.v1.json',
        'compiled_f2_partial_events.json', 'compiled_assertion_results.v1.json',
        'compiled_assertion_evidence.v1.json', 'compiled_f2_execution_audit.json'}
    notes = '\n'.join(primary.__notes__)
    assert all(text in notes for text in ['F2 failure export:',
        'controlled-online_plan.json', 'controlled-wrapper-export'])
    assert executor._finish_online_session() == (runtime.trace, b'{}'.hex())


@pytest.mark.parametrize('context', [True, False])
@pytest.mark.parametrize('partial', ['trace', 'plan'])
def test_transport_primary_promotes_finish_and_partial_notes(
        transport_case, tmp_path, monkeypatch, context, partial):
    executor, runtime, _ = transport_case
    transport = OSError('controlled-first-transport')
    finish_error = OSError('controlled-later-finish')
    finish_error.add_note('finish-internal-assertion-diagnostic')
    partial_error = OSError('controlled-partial-' + partial)
    partial_error.add_note('partial-internal-diagnostic')
    live, args, _, _ = live_case(transport_case, tmp_path, monkeypatch,
        execute=False, transport_error=transport, context=context)
    calls = []
    def finish():
        calls.append('finish')
        raise finish_error
    runtime.finish = finish
    def capture_trace():
        calls.append('trace')
        if partial == 'trace':
            raise partial_error
        return runtime.trace
    def capture_plan():
        calls.append('plan')
        if partial == 'plan':
            raise partial_error
        return b'{}'
    runtime.session.trace = capture_trace
    runtime.session.encode_plan = capture_plan
    with pytest.raises(OSError) as caught:
        live.run_scenario_rfuzz_live(**args)
    assert caught.value is transport
    notes = '\n'.join(transport.__notes__)
    assert all(text in notes for text in ['controlled-later-finish',
        'finish-internal-assertion-diagnostic', 'controlled-partial-' + partial,
        'partial-internal-diagnostic'])
    assert calls == ['finish', 'trace', 'plan']
    pair = executor._finish_online_session()
    assert pair == (None if partial == 'trace' else runtime.trace,
                    None if partial == 'plan' else b'{}'.hex())
    assert calls == ['finish', 'trace', 'plan']
    assert executor._online_primary_error is None


@pytest.mark.parametrize('context', [True, False])
def test_execution_primary_promotes_prenoted_finish_and_partial_errors(
        transport_case, tmp_path, monkeypatch, context):
    executor, runtime, _ = transport_case
    primary = RuntimeError('controlled-first-execution')
    finish_error = OSError('controlled-later-finish')
    finish_error.add_note('finish-internal-assertion-diagnostic')
    partial_error = OSError('controlled-partial-plan')
    partial_error.add_note('partial-internal-diagnostic')
    runtime.submit = fail(primary)
    live, args, _, _ = live_case(transport_case, tmp_path, monkeypatch,
        context=context)
    runtime.finish = fail(finish_error)
    runtime.session.encode_plan = fail(partial_error)
    with pytest.raises(RuntimeError) as caught:
        live.run_scenario_rfuzz_live(**args)
    assert caught.value is primary
    notes = '\n'.join(primary.__notes__)
    assert all(text in notes for text in ['controlled-later-finish',
        'finish-internal-assertion-diagnostic', 'controlled-partial-plan',
        'partial-internal-diagnostic'])
    assert notes.count('finish-internal-assertion-diagnostic') == 1
    assert notes.count('partial-internal-diagnostic') == 1
    before = tuple(primary.__notes__)
    assert executor._finish_online_session() == (runtime.trace, None)
    assert tuple(primary.__notes__) == before
    assert executor._online_primary_error is primary


def test_shared_promotion_keeps_secondary_identity_dedup(
        transport_case, tmp_path, monkeypatch):
    executor, runtime, _ = transport_case
    transport = OSError('controlled-first-transport')
    live, args, _, secondary = live_case(transport_case, tmp_path, monkeypatch,
        execute=False, transport_error=transport, writer_fault='online_plan.json')
    secondary.add_note('one-secondary-internal-diagnostic')
    # The same error reaches shared finalization as both finish and writer
    # failure. Its identity must still be promoted only once.
    runtime.finish = fail(secondary)
    with pytest.raises(OSError) as caught:
        live.run_scenario_rfuzz_live(**args)
    assert caught.value is transport
    notes = '\n'.join(transport.__notes__)
    assert notes.count('controlled-online_plan.json') == 1
    assert notes.count('one-secondary-internal-diagnostic') == 1
    assert executor._online_primary_error is None
