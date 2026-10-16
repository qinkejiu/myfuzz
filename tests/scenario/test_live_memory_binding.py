"""Dynamic bindings from actual current STORE authority, without receipt enrollment."""
from types import SimpleNamespace
import pytest
from tests.scenario.test_live_memory_prerequisites import fixture, write
from tests.scenario.test_source_actions import instruction_action
from myfuzz.scenario.source_actions import TrustedRamByteDeclaration


def binder(gate, **kwargs):
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryDynamicPrerequisiteBinder
    return LiveMemoryDynamicPrerequisiteBinder(gate.tracker,
        TrustedRamByteDeclaration(memory_id='ram', byte_offsets=(0,), writer_kinds=('STORE',)), **kwargs)


def test_actual_drained_store_binds_without_receipt_observation_or_payload_change():
    runner, cpu, gate = fixture()
    write(runner, cpu)
    subject = binder(gate)
    action = instruction_action()
    bound = subject.bind(action, memory_id='ram', byte_offset=0)
    assert bound.action.payload == action.payload
    assert bound.witness.writer_kind == 'STORE'
    subject.verify(bound)
    gate.require(gate.register(bound.action))


def test_pending_actual_commit_and_saved_receipt_never_bind_until_real_drain():
    runner, cpu, gate = fixture()
    event = write(runner, cpu, drain=False)
    subject = binder(gate)
    subject.observe(SimpleNamespace(events=(event,), case_id='saved'))
    with pytest.raises(ValueError):
        subject.bind(instruction_action(), memory_id='ram', byte_offset=0)
    runner._append_external_events('cpu', 1)
    assert subject.bind(instruction_action(), memory_id='ram', byte_offset=0)


def test_equal_value_overwrite_invalidates_saved_binding_before_drain():
    runner, cpu, gate = fixture()
    write(runner, cpu)
    subject = binder(gate)
    bound = subject.bind(instruction_action(), memory_id='ram', byte_offset=0)
    write(runner, cpu, drain=False)
    with pytest.raises(ValueError):
        subject.verify(bound)
    with pytest.raises(ValueError):
        subject.bind(instruction_action(), memory_id='ram', byte_offset=0)


def test_fresh_binder_recomputes_saved_binding_only_from_current_actual_authority():
    runner, cpu, gate = fixture()
    write(runner, cpu)
    bound = binder(gate).bind(instruction_action(), memory_id='ram', byte_offset=0)
    binder(gate).verify(bound)
    cpu.memory.cold_reset()
    with pytest.raises(ValueError):
        binder(gate).verify(bound)


def test_declaration_outside_actual_region_rejected_without_materialization():
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryDynamicPrerequisiteBinder
    _, cpu, gate = fixture()
    before = cpu.memory.state_summary()
    with pytest.raises(ValueError):
        LiveMemoryDynamicPrerequisiteBinder(gate.tracker,
            TrustedRamByteDeclaration(memory_id='ram', byte_offsets=(4096,), writer_kinds=('STORE',)))
    assert cpu.memory.state_summary() == before


@pytest.mark.parametrize('bounds', [{'max_writer_versions': 1}, {'max_event_gap': 1}])
def test_saved_binding_cannot_restore_evicted_or_expired_actual_writer(bounds):
    runner, cpu, gate = fixture(**bounds)
    write(runner, cpu, mask=1)
    subject = binder(gate)
    bound = subject.bind(instruction_action(), memory_id='ram', byte_offset=0)
    if 'max_writer_versions' in bounds:
        cpu._serve('data', 1, 0x20004, 90, 1)
        runner._append_external_events('cpu', 1)
    else:
        for _ in range(2):
            runner._events.append({'event_id': len(runner.events) + 1, 'kind': 'fixture_step'})
    with pytest.raises(ValueError):
        subject.verify(bound)


def test_saved_writer_kind_projection_does_not_override_actual_store():
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    subject = binder(gate)
    event['commit_document']['enabled_byte_cells'][0]['writer_kind'] = 'INITIAL_IMAGE'
    subject.observe(SimpleNamespace(events=(event,), case_id='saved'))
    assert subject.bind(instruction_action(), memory_id='ram', byte_offset=0).witness.writer_kind == 'STORE'


@pytest.mark.parametrize('changes', [{'version': (0, 999)}, {'action_id': 'different-action'}])
def test_rehashed_claim_must_match_actual_version_and_consumer_action(changes):
    from dataclasses import replace
    runner, cpu, gate = fixture()
    write(runner, cpu)
    subject = binder(gate)
    bound = subject.bind(instruction_action(), memory_id='ram', byte_offset=0)
    altered = replace(bound.witness, **changes, bound_witness_id='')
    with pytest.raises(ValueError):
        subject.verify(altered, action=bound.action)


def test_factory_result_slot_load_requires_actual_writer_and_records_binding(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    runner = make_ibex_pulp_dual_source_factory(tmp_path, memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256='a' * 64)()
    cpu = runner.sessions['cpu']
    cpu._case_id = 'software-actual-callback'
    gate = runner.persistent_memory_prerequisite_gate
    action = instruction_action(payload={'address': 0x11000, 'words_hex': 'b700010003a10000'})
    cpu.memory.declare_instruction_slots(0x11000, 2)
    with pytest.raises(ValueError):
        gate.register(action)
    assert gate.action_ids == ()
    cpu._serve('data', 1, 0x10000, 90, 15)
    runner._append_external_events('cpu', 1)
    bound = gate.register(action)
    assert len(bound.prerequisites) == 3
    assert bound.payload == action.payload
    gate.require(bound)
    binding = gate.dynamic_binding_for_action(bound.action_id)
    assert binding['payload_unchanged'] and binding['bound_witness']['writer_kind'] == 'STORE'
    assert runner.identity_document()['persistent_memory_prerequisites']['dynamic_ram_policy']['rule']
    cpu._serve('data', 1, 0x10000, 90, 1)
    with pytest.raises(ValueError):
        gate.require(bound)


def test_executor_records_actual_dynamic_binding_with_admitted_action(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
    from myfuzz.scenario.session_runtime import OnlineInstruction
    runner = make_ibex_pulp_dual_source_factory(tmp_path, memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256='a' * 64)()
    cpu = runner.sessions['cpu']
    cpu._case_id = 'software-actual-callback'
    cpu.memory.declare_instruction_slots(0x11000, 2)
    cpu._serve('data', 1, 0x10000, 90, 15)
    runner._append_external_events('cpu', 1)
    action = instruction_action(payload={'address': 0x11000, 'words_hex': 'b700010003a10000'})
    case = SimpleNamespace(source=OnlineInstruction(action.action_id, 'cpu', 0x11000,
                                                  action.payload['words_hex']), support_instructions=())
    gate = runner.persistent_memory_prerequisite_gate
    document = ScenarioRfuzzExecutor._bind_online_source_action(SimpleNamespace(
        source_action_gate=gate, online_decoder=SimpleNamespace(source_action=lambda _: action)), case, {})
    assert document['dynamic_binding']['action']['action_id'] == document['action']['action_id']
    assert document['dynamic_binding']['payload_unchanged']
