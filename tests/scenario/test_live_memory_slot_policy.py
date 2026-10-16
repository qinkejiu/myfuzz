"""Trusted RAM and declared slots share admission; saved receipts grant neither."""
from types import SimpleNamespace
import pytest
from tests.scenario.test_memory_dependency_runner import wired
from tests.scenario.test_source_actions import instruction_action
from myfuzz.scenario.source_actions import ram_commit_prerequisite


def fixture():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner.configure_persistent_memory_prerequisites(instruction_slot_policy=dict(
        component='cpu', first_address=0x20000, last_address=0x20010,
        reservation_ref_prefix='declared-slot'))
    cpu.memory.declare_instruction_slots(0x20000, 4)
    return runner, cpu, runner.persistent_memory_prerequisite_gate


def test_declared_actual_unmaterialized_slot_is_required_and_current_cell_checked():
    runner, cpu, gate = fixture()
    bound = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert len(bound.prerequisites) == 1
    assert gate.tracker.satisfied(bound)
    cpu.memory.accept_instructions(0x20000, b'\x13\x00\x00\x00', source_event_id='actual-input')
    assert not gate.tracker.satisfied(bound)
    assert runner.identity_document()['persistent_memory_prerequisites']['instruction_slot_policy']['component'] == 'cpu'


def test_saved_slot_reservation_without_physical_declaration_is_not_authority():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner.configure_persistent_memory_prerequisites(instruction_slot_policy=dict(
        component='cpu', first_address=0x20000, last_address=0x20010,
        reservation_ref_prefix='declared-slot'))
    gate = runner.persistent_memory_prerequisite_gate
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert not gate.tracker.satisfied(action)


def test_slot_policy_keeps_actual_ram_prerequisite_on_same_bound_action():
    runner, cpu, gate = fixture()
    cpu._serve('data', 1, 0x20008, 90, 15)
    event = cpu.service.drain_commit_events()[0]
    p = ram_commit_prerequisite('ram', 0, 8, event['commit_id'])
    action = gate.register(instruction_action(prerequisites=(p,),
        payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert len(action.prerequisites) == 2 and not gate.tracker.satisfied(action)
    runner._append_external_events('cpu', 1)
    assert gate.tracker.satisfied(action)


def test_reset_drops_old_slot_reservation_without_erasing_policy():
    runner, _, gate = fixture()
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert gate.tracker.satisfied(action)
    runner._events.append_unchecked({'event_id': 1, 'kind': 'reset_barrier'})
    assert not gate.tracker.satisfied(action)


def test_out_of_window_and_unknown_component_fail_before_registration():
    runner, _, gate = fixture()
    with pytest.raises(ValueError):
        gate.register(instruction_action(payload={'address': 0x21000, 'words_hex': '13000000'}))
    assert gate.action_ids == ()
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    with pytest.raises(ValueError):
        runner.configure_persistent_memory_prerequisites(instruction_slot_policy=dict(
            component='missing', first_address=0x20000, last_address=0x20010,
            reservation_ref_prefix='declared-slot'))
    assert runner.persistent_memory_prerequisite_gate is None


def test_online_startup_selects_runner_gate_before_legacy_factory_policy(tmp_path, monkeypatch):
    from myfuzz.integration import ibex_pulp_online
    from tests.scenario.test_ibex_pulp_source_action_prerequisites import _RecordingSession, _StopBeforeRtl
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    runner, _, gate = fixture()
    created = []
    def factory(): created.append(runner); return runner
    def legacy(): raise AssertionError('trusted runner must keep its installed gate')
    factory.new_source_action_gate = legacy
    recorded = {}
    def session(template, actual, **kwargs):
        recorded['gate'] = kwargs.get('prerequisite_gate')
        return _RecordingSession(template, actual, **kwargs)
    monkeypatch.setattr(ibex_pulp_online, 'ScenarioSession', session)
    with pytest.raises(_StopBeforeRtl):
        ibex_pulp_online.make_pulp_dual_source_online_runtime(
            run_id='trusted-slot', factory=factory,
            bootstrap=make_ibex_pulp_dual_source_stream_bootstrap(),
            decoder=SimpleNamespace(graph=None, runtime_contract=None, runtime_paths=None,
                                    ownership=runner.ownership), source_actions=True)
    assert created == [runner] and recorded['gate'] is gate


def test_slot_window_outside_actual_memory_fails_at_startup():
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    with pytest.raises(ValueError):
        runner.configure_persistent_memory_prerequisites(instruction_slot_policy=dict(
            component='cpu', first_address=0x20000, last_address=0x22000,
            reservation_ref_prefix='declared-slot'))
    assert runner.persistent_memory_prerequisite_gate is None


def test_partial_slot_store_invalidates_reservation_before_commit_drain():
    _, cpu, gate = fixture()
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert gate.tracker.satisfied(action)
    cpu._serve('data', 1, 0x20000, 19, 1)
    assert not gate.tracker.satisfied(action)


def test_actual_cold_reset_cannot_revive_old_slot_before_journal_barrier():
    _, cpu, gate = fixture()
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert gate.tracker.satisfied(action)
    cpu.memory.accept_instructions(0x20000, b'\x13\x00\x00\x00', source_event_id='actual-input')
    assert not gate.tracker.satisfied(action)
    cpu.memory.cold_reset()
    assert cpu.memory.instruction_slot_unmaterialized(0x20000)
    assert not gate.tracker.satisfied(action)
    gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert not gate.tracker.satisfied(action)
    gate.tracker.reset(event_id=gate.tracker.cursor + 1)
    assert not gate.tracker.satisfied(action)
    gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert gate.tracker.satisfied(action)


def test_unmaterialized_old_slot_cannot_cross_actual_generation():
    _, cpu, gate = fixture()
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert gate.tracker.satisfied(action)
    cpu.memory.cold_reset()
    assert not gate.tracker.satisfied(action)


def test_real_factory_installs_fresh_trusted_gate_and_actual_read_authority(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    factory = make_ibex_pulp_dual_source_factory(tmp_path, memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256='a' * 64)
    first, second = factory(), factory()
    assert first.persistent_memory_prerequisite_gate is not second.persistent_memory_prerequisite_gate
    assert first.persistent_memory_prerequisite_gate is not None
    cpu = first.sessions['cpu']
    assert cpu.memory_readback_receipts_enabled
    assert cpu.memory_read_authority is first._memory_read_authority
    assert first.identity_document()['memory_dependency_evidence']['runtime_contract_sha256'] == 'a' * 64
    assert all(s._process is None for s in first.sessions.values())


@pytest.mark.parametrize('options', [
    dict(memory_commit_receipts=False), dict(source_actions=False),
    dict(persistent_memory_runtime_contract_sha256='invalid'),
])
def test_factory_trusted_policy_rejects_incomplete_opt_in_before_render(tmp_path, options):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    kwargs = dict(memory_commit_receipts=True, persistent_memory_runtime_contract_sha256='a' * 64)
    kwargs.update(options)
    with pytest.raises(ValueError):
        make_ibex_pulp_dual_source_factory(tmp_path, **kwargs)
    assert list(tmp_path.iterdir()) == []


def test_online_opt_in_uses_decoder_actual_contract_identity_before_rtl(tmp_path, monkeypatch):
    from tests.scenario.test_ibex_pulp_source_action_prerequisites import _runtime_session
    session = _runtime_session(tmp_path, monkeypatch, memory_commit_receipts=True,
                              persistent_memory_prerequisites=True)
    assert session.prerequisite_gate is session.runner.persistent_memory_prerequisite_gate
    config = session.runner.identity_document()['memory_dependency_evidence']
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    decoder = make_ibex_pulp_dual_source_online_decoder(result_slot_readback=True)
    assert config['runtime_contract_sha256'] == decoder.runtime_contract.identity_sha256


def test_fixed_support_registration_checks_exact_fragment_and_actual_slot():
    from myfuzz.scenario.session_runtime import OnlineInstruction
    _, cpu, gate = fixture()
    fragment = OnlineInstruction('support', 'cpu', 0x20000, '13000000')
    action = gate.register_support_instruction(fragment, flow_id='F3', local_step_budget=1)
    assert action.ownership == 'fixed' and not action.payload
    gate.require_case(SimpleNamespace(source=fragment))
    with pytest.raises(ValueError):
        gate.require_case(SimpleNamespace(source=OnlineInstruction('support', 'cpu', 0x20004, '13000000')))
    cpu.memory.accept_instructions(0x20000, fragment.data, source_event_id='actual-support')
    with pytest.raises(ValueError):
        gate.require_case(SimpleNamespace(source=fragment))


def test_executor_registers_decoder_fixed_support_before_admission(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import (make_ibex_pulp_dual_source_factory,
        make_ibex_pulp_dual_source_online_decoder)
    from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
    decoder = make_ibex_pulp_dual_source_online_decoder(result_slot_readback=True)
    case = next(case for index in range(len(decoder.sources))
        if (case := decoder.decode(bytes((0, 0, index, 7, 0, 0, 0, 0)))).support_instructions)
    runner = make_ibex_pulp_dual_source_factory(tmp_path, memory_commit_receipts=True,
        persistent_memory_runtime_contract_sha256=decoder.runtime_contract.identity_sha256)()
    gate = runner.persistent_memory_prerequisite_gate
    runner.sessions['cpu'].memory.declare_instruction_slots(decoder.instruction_start,
        (decoder.instruction_end - decoder.instruction_start) // 4)
    decision = {}
    ScenarioRfuzzExecutor._bind_online_source_action(SimpleNamespace(
        online_decoder=decoder, source_action_gate=gate), case, decision)
    assert decision['source_action']['support_actions'][0]['ownership'] == 'fixed'
    assert case.support_instructions[0].action_id in gate.action_ids
    assert all(s._process is None for s in runner.sessions.values())


@pytest.mark.parametrize('component,address,data', [
    ('cpu', 0x20000, '93001000'), ('missing', 0x20000, '13000000'),
    ('cpu', 0x20010, '13000000'),
])
def test_fixed_support_refuses_invalid_declaration_without_registration(component, address, data):
    from myfuzz.scenario.session_runtime import OnlineInstruction
    _, _, gate = fixture()
    with pytest.raises(ValueError):
        gate.register_support_instruction(OnlineInstruction('support', component, address, data),
                                          flow_id='F5', local_step_budget=1)
    assert gate.action_ids == () and gate._support_instructions == {}


@pytest.mark.parametrize('kind', ['commit', 'read'])
def test_authority_replacement_revokes_instruction_slot_admission(kind):
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    _, cpu, gate = fixture()
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    assert gate.tracker.satisfied(action)
    consumer = gate.tracker._consumer
    attribute = f'_{kind}_authority'
    original = getattr(consumer, attribute)
    authority_type = MemoryCommitAuthority if kind == 'commit' else MemoryReadAuthority
    setattr(consumer, attribute, authority_type(services={'cpu': cpu.service}))
    assert gate.tracker.document()['degraded'] is True
    assert not gate.tracker.satisfied(action)
    setattr(consumer, attribute, original)
    assert not gate.tracker.satisfied(action)
