"""Fresh replay keeps an exact native source refusal as a terminal prefix."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory_service import _VALIDATE_ISSUED_READ
from myfuzz.scenario.session_runtime import (
    OnlineInstruction,
    _native_source_completion_terminal_grants,
    _validate_native_source_completion_terminal_failure,
    replay_online_session,
)
from myfuzz.scenario.picorv32_native_online import (
    make_picorv32_native_online_decoder,
)

ROOT = Path(__file__).resolve().parents[2]
BASE_DIR = Path(os.environ.get('MYFUZZ_SCENARIO_BASE_DIR', ROOT))
HAS_NATIVE_REFERENCE = all((root / 'third_party/picorv32_upstream_reference/picorv32.v').is_file()
    for root in {ROOT, BASE_DIR})


REAL_NATIVE = pytest.mark.skipif(
    os.environ.get('MYFUZZ_SCENARIO_REAL') != '1' or not HAS_NATIVE_REFERENCE,
    reason='set MYFUZZ_SCENARIO_REAL=1 and provide the pinned PicoRV32 source')


def _terminal_plan():
    return {
        'schema_version': 23,
        'terminal_failure': {
            'phase': 'step', 'case_index': 0, 'case_id': 'case-1',
            'command_index': 0, 'error_type': 'ValueError',
            'error_message': 'native_source_candidate_refused'},
        'cases': [{'case_id': 'case-1',
            'source': {'kind': 'instruction', 'component': 'cpu',
                       'action_id': 'action-1', 'address': 0x200,
                       'data_hex': '13000000'},
            'source_role': 'fuzz_source', 'support_instructions': [],
            'advances': [['cpu', 'gpio0']] * 128}],
    }


def test_schema23_terminal_failure_plan_only_accepts_exact_native_candidate_refusal():
    plan = _terminal_plan()
    assert _validate_native_source_completion_terminal_failure(plan) == plan['terminal_failure']
    mutations = (
        lambda row: row['terminal_failure'].__setitem__('error_message', 'unrelated'),
        lambda row: row['terminal_failure'].__setitem__('error_type', 'RuntimeError'),
        lambda row: row['terminal_failure'].__setitem__('phase', 'source_admission'),
        lambda row: row['terminal_failure'].__setitem__('command_index', 128),
        lambda row: row['cases'][0]['source'].__setitem__('component', 'gpio0'),
        lambda row: row['cases'][0].__setitem__('source_role', 'bootstrap'),
        lambda row: row['cases'][0].__setitem__('support_instructions', [
            {'action_id': 'support', 'component': 'cpu', 'address': 0x200,
             'data_hex': '13000000'}]),
        lambda row: row['cases'][0]['advances'].pop(),
    )
    for mutate in mutations:
        changed = json.loads(json.dumps(plan))
        mutate(changed)
        with pytest.raises(ValueError, match='native source completion terminal failure'):
            _validate_native_source_completion_terminal_failure(changed)


def test_terminal_completion_guard_uses_the_completion_key_field():
    key = TransactionKey('execution', 'case-1', 'cpu', 0, 'memory', 7)
    matching_key_only = dict(kind='native_instruction_bus_completion',
        schema_version='native_instruction_bus_completion.v1',
        key={'execution_id': 'execution', 'testcase_id': 'case-1',
             'source_component': 'cpu', 'source_epoch': 0,
             'channel_id': 'memory', 'source_sequence': 7},
        producer_event_id=999)
    matching_raw_only = dict(kind='native_instruction_bus_completion',
        schema_version='native_instruction_bus_completion.v1',
        key={'execution_id': 'other', 'testcase_id': 'other',
             'source_component': 'cpu', 'source_epoch': 0,
             'channel_id': 'memory', 'source_sequence': 1},
        producer_event_id=15)
    unrelated = dict(kind='native_instruction_bus_completion',
        key={'execution_id': 'other', 'testcase_id': 'other',
             'source_component': 'cpu', 'source_epoch': 0,
             'channel_id': 'memory', 'source_sequence': 2},
        producer_event_id=16)

    assert _native_source_completion_terminal_grants(
        [matching_key_only, matching_raw_only, unrelated], key, 15) == [
            matching_key_only, matching_raw_only]


def _install_source_poison_before_case_tick(runner):
    """Use the real service writer after acceptance/binding, before its first tick."""
    original_step_batch = runner.step_batch
    injected = False

    def step_batch(schedule):
        nonlocal injected
        cpu = runner.sessions['cpu']
        source_events = [event for event in cpu.service.events
            if event.get('kind') == 'instruction_source'
            and event.get('source_event_id', '').startswith(cpu._case_id + ':')]
        if not injected and source_events:
            source_event = source_events[-1]
            key = TransactionKey('local-execution', cpu._case_id, 'cpu',
                                 cpu.reset_epoch, 'native-source-poison', 1)
            cpu.service.write(key, source_event['address'], 0x00000013,
                              width_bytes=4, byte_enable=0xf)
            injected = True
        return original_step_batch(schedule)

    runner.step_batch = step_batch
    return lambda: injected


def _make_runtime(tmp_path: Path, *, poison: bool):
    from myfuzz.integration.picorv32_native_online import (
        make_picorv32_native_online_runtime)

    runtime = make_picorv32_native_online_runtime(
        cache_dir=tmp_path / 'cache',
        base_dir=BASE_DIR,
        max_cases=1,
        native_completion_observation=True, native_source_binding=True,
        native_source_completion=True)
    installers = []

    def install(runner):
        if poison:
            installers.append(_install_source_poison_before_case_tick(runner))

    install(runtime.session.runner)

    def factory():
        runner = runtime.factory()
        install(runner)
        return runner

    return runtime, factory, installers


def _record(tmp_path: Path, *, poison: bool):
    runtime, factory, installers = _make_runtime(tmp_path, poison=poison)
    runtime.begin()
    probe = make_picorv32_native_online_decoder()
    for value in range(4096):
        candidate = value.to_bytes(4, 'little') + bytes(4)
        try:
            selected = probe.decode(candidate)
        except ValueError:
            continue
        if (isinstance(selected.source, OnlineInstruction)
                and selected.source.component == 'cpu'):
            raw = candidate
            break
    else:
        raise AssertionError('decoder search found no CPU instruction candidate')
    assert selected.source.action_id.endswith(':cpu.instructions')
    assert selected.support_instructions == ()
    if poison:
        with pytest.raises(ValueError, match='native_source_candidate_refused'):
            runtime.submit(raw)
        assert installers and installers[0]() is True
        accepted_case = runtime.session.cases[-1]
        assert accepted_case.source == selected.source
        assert runtime.session._case_source_roles[accepted_case.case_id] == 'fuzz_source'
        plan = runtime.session.encode_plan()
        trace = runtime.session.trace()
    else:
        runtime.submit(raw)
        accepted_case = runtime.session.cases[-1]
        assert accepted_case.source == selected.source
        assert runtime.session._case_source_roles[accepted_case.case_id] == 'fuzz_source'
        plan, trace = runtime.finish()
    return runtime, factory, plan, trace


def _replay(runtime, factory, plan, trace):
    cpu = runtime.session.runner.sessions['cpu']
    return replay_online_session(plan, factory, trace,
        native_max_cases=1, native_reference_execution=cpu._execution,
        native_source_binding=True, native_source_completion=True,
        native_reference_session=runtime.session)


def _assert_refused_pre_is_in_runner_journal(session):
    cpu = session.runner.sessions['cpu']
    observer = cpu._native_bus_observer
    pending = observer.pending
    assert pending['state'] == 'response'
    local_tick = pending['response_scope']['local_tick'] + 1
    matches = [event for event in session.runner.events
        if event.get('kind') == 'local_tick_sample'
        and event.get('component') == 'cpu' and event.get('phase') == 'pre'
        and event.get('native_driver_scope', {}).get('local_tick') == local_tick]
    assert len(matches) == 1
    native = observer._native(matches[0]['outputs'])
    assert (native['valid'], native['ready'], native['instruction'], native['addr']) == (
        1, 1, 1, pending['native']['addr'])
    assert matches[0]['outputs']['protocol_taps']
    assert observer.samples == []
    return matches[0]


@REAL_NATIVE
def test_schema23_replays_the_exact_refused_candidate_prefix(tmp_path):
    runtime, factory, plan, trace = _record(tmp_path, poison=True)
    document = json.loads(plan)
    session = runtime.session
    cpu = session.runner.sessions['cpu']
    observer = cpu._native_bus_observer
    assert document['schema_version'] == 23
    assert document['terminal_failure'] == {
        'phase': 'step', 'case_index': 0, 'case_id': session.cases[-1].case_id,
        'command_index': 0, 'error_type': 'ValueError',
        'error_message': 'native_source_candidate_refused'}
    raw_pre = _assert_refused_pre_is_in_runner_journal(session)
    pending = observer.pending
    assert session._halted and session._halt_reason == 'uncertain_effect'
    assert session._packet_terminal and session._packet_cleanup_attempted
    assert session.runner._status == 'finalized' and cpu.process is None
    assert cpu._native_source_completion_session is None
    assert observer.failed and observer._source_completions == []
    with pytest.raises(ValueError):
        _VALIDATE_ISSUED_READ(cpu.service, cpu.memory, pending['key'],
                              pending['read_snapshot'], pending['read_handle'])
    assert raw_pre in trace.events

    comparison = _replay(runtime, factory, plan, trace)
    assert comparison.matches, comparison.difference_context
    assert comparison.actual_trace.status == trace.status
    assert comparison.actual_trace.local_ticks == trace.local_ticks
    assert raw_pre in session.runner.events


@REAL_NATIVE
def test_schema23_rejects_changed_failure_record_and_unclean_pending_state(tmp_path):
    runtime, factory, plan, _ = _record(tmp_path, poison=True)
    session = runtime.session

    def forbidden_factory():
        pytest.fail('invalid terminal failure must be refused before fresh construction')

    session._terminal_failure['error_message'] = 'unrelated_failure'
    changed_plan = session.encode_plan()
    changed_trace = session.trace()
    with pytest.raises(ValueError, match='native source completion terminal failure'):
        _replay(runtime, forbidden_factory, changed_plan, changed_trace)

    session._terminal_failure['error_message'] = 'native_source_candidate_refused'
    session.runner.sessions['cpu']._native_bus_observer.pending['state'] = 'accepted'
    with pytest.raises(ValueError, match='native source completion terminal cleanup'):
        _replay(runtime, forbidden_factory, plan, session.trace())


@REAL_NATIVE
def test_schema22_successful_completion_replay_remains_supported(tmp_path):
    runtime, factory, plan, trace = _record(tmp_path, poison=False)
    assert json.loads(plan)['schema_version'] == 22
    comparison = _replay(runtime, factory, plan, trace)
    assert comparison.matches, comparison.difference_context
    assert comparison.actual_trace.status == 'complete'
