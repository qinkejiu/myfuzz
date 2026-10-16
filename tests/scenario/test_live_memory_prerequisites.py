"""Actual retained commit plus current physical host cell, never saved labels."""
from types import SimpleNamespace
import pytest
from tests.scenario.test_memory_dependency_runner import wired
from myfuzz.scenario.source_actions import ram_commit_prerequisite


def fixture(**bounds):
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64, **bounds)
    runner.configure_persistent_memory_prerequisites()
    return runner, cpu, runner.persistent_memory_prerequisite_gate


def write(runner, cpu, *, value=90, mask=15, drain=True):
    cpu._serve('data', 1, 0x20000, value, mask)
    event = cpu.service.drain_commit_events()[-1]
    if drain: runner._append_external_events('cpu', 1)
    return event


def prerequisite(event, lane=0):
    return ram_commit_prerequisite('ram', event['commit_document']['generation'], lane,
                                   event['commit_id'])


def test_actual_retained_commit_satisfies_only_enabled_current_bytes_without_read():
    runner, cpu, gate = fixture()
    event = write(runner, cpu, mask=5)
    before = cpu.memory.state_summary(), len(cpu.service.events)
    assert gate.tracker.satisfied(prerequisite(event, 0))
    assert gate.tracker.satisfied(prerequisite(event, 2))
    assert not gate.tracker.satisfied(prerequisite(event, 1))
    assert before == (cpu.memory.state_summary(), len(cpu.service.events))
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 0


def test_saved_receipt_observe_cannot_enroll_a_commit():
    runner, cpu, gate = fixture()
    event = write(runner, cpu, drain=False)
    assert gate.observe(SimpleNamespace(events=(event,), case_id='saved')) == ()
    assert not gate.tracker.satisfied(prerequisite(event))
    runner._append_external_events('cpu', 1)
    assert gate.tracker.satisfied(prerequisite(event))


def test_overwrite_invalidates_old_byte_even_before_new_commit_is_drained():
    runner, cpu, gate = fixture()
    old = write(runner, cpu)
    new = write(runner, cpu, drain=False)  # equal data still has a new writer/version
    assert not gate.tracker.satisfied(prerequisite(old))
    assert not gate.tracker.satisfied(prerequisite(new))
    runner._append_external_events('cpu', 1)
    assert gate.tracker.satisfied(prerequisite(new))


def test_reset_barrier_clears_active_but_preserves_historical_snapshot_evidence():
    runner, cpu, gate = fixture()
    old = write(runner, cpu)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    runner._events.append_unchecked({'event_id': len(runner.events) + 1, 'kind': 'reset_barrier'})
    assert not gate.tracker.satisfied(prerequisite(old))
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    assert gate.observe(SimpleNamespace(events=tuple(runner.events), case_id='replayed')) == ()
    assert not gate.tracker.satisfied(prerequisite(old))
    assert gate.tracker.satisfied(prerequisite(write(runner, cpu)))


@pytest.mark.parametrize('bounds', [{'max_writer_versions': 1}, {'max_event_gap': 1}])
def test_eviction_or_expiry_is_not_revived_by_saved_history(bounds):
    runner, cpu, gate = fixture(**bounds)
    event = write(runner, cpu)
    if 'max_event_gap' in bounds:
        for _ in range(2):
            runner._events.append({'event_id': len(runner.events) + 1, 'kind': 'fixture_step'})
    assert not gate.tracker.satisfied(prerequisite(event))
    gate.observe(SimpleNamespace(events=(event,), case_id='saved'))
    assert not gate.tracker.satisfied(prerequisite(event))


def test_journal_conflict_permanently_stops_active_claims():
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    assert gate.tracker.satisfied(prerequisite(event))
    runner._events.append({'event_id': 1, 'kind': 'conflicting_saved_annotation'})
    assert not gate.tracker.satisfied(prerequisite(event))
    runner._events.append({'event_id': len(runner.events) + 1, 'kind': 'reset_barrier'})
    assert not gate.tracker.satisfied(prerequisite(write(runner, cpu)))


@pytest.mark.parametrize('kind', ['commit', 'read'])
def test_replacing_authority_instance_cannot_reuse_retained_writer_or_heal(kind):
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    cpu._serve('data', 0, 0x20000, 0, 15);runner._append_external_events('cpu', 1)
    history = runner.memory_dependency_evidence_report()['certificates']
    assert gate.tracker.satisfied(prerequisite(event))
    consumer = gate.tracker._consumer
    attribute = f'_{kind}_authority'
    original = getattr(consumer, attribute)
    authority_type = MemoryCommitAuthority if kind == 'commit' else MemoryReadAuthority
    setattr(consumer, attribute, authority_type(services={'cpu': cpu.service}))
    assert not gate.tracker.satisfied(prerequisite(event))
    setattr(consumer, attribute, original)
    gate.tracker.reset(event_id=0)
    assert not gate.tracker.satisfied(prerequisite(event))
    assert runner.memory_dependency_evidence_report()['certificates'] == history


def test_eviction_revokes_old_writer_without_changing_current_cell_or_history():
    runner, cpu, gate = fixture(max_writer_versions=4)
    event = write(runner, cpu)
    cpu._serve('data', 0, 0x20000, 0, 15);runner._append_external_events('cpu', 1)
    history = runner.memory_dependency_evidence_report()['certificates']
    cell = cpu.memory.inspect_byte('ram', 0)
    assert gate.tracker.satisfied(prerequisite(event))
    cpu._serve('data', 1, 0x20004, 90, 15);runner._append_external_events('cpu', 1)
    assert cpu.memory.inspect_byte('ram', 0) == cell
    assert not gate.tracker.satisfied(prerequisite(event))
    gate.observe(SimpleNamespace(events=tuple(runner.events), case_id='saved-history'))
    assert not gate.tracker.satisfied(prerequisite(event))
    assert runner.memory_dependency_evidence_report()['certificates'] == history


@pytest.mark.parametrize('kind', ['commit', 'read'])
@pytest.mark.parametrize('mutation', ['remove', 'ledger', 'extra_component'])
def test_authority_service_registry_drift_permanently_revokes_old_writer(kind, mutation):
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    assert gate.tracker.satisfied(prerequisite(event))
    authority = getattr(gate.tracker._consumer, f'_{kind}_authority')
    original = dict(authority._installed)
    if mutation == 'remove':
        authority._installed.pop('cpu')
    elif mutation == 'ledger':
        row = authority._installed['cpu']
        authority._installed['cpu'] = (row[0], object(), *row[2:])
    else:
        authority._installed['extra'] = authority._installed['cpu']
    assert not gate.tracker.satisfied(prerequisite(event))
    authority._installed = original
    gate.tracker.reset(event_id=0)
    assert not gate.tracker.satisfied(prerequisite(event))


def test_readonly_current_cell_lookup_never_initializes_unknown_memory():
    runner, cpu, _ = fixture()
    before = cpu.memory.state_summary()
    assert cpu.memory.inspect_byte('ram', 0) is None
    assert cpu.memory.state_summary() == before
    event = write(runner, cpu)
    cell = cpu.memory.inspect_byte('ram', 0)
    assert cell.value == 90 and cell.version == tuple(event['commit_document']['version'])
    object.__setattr__(cell, 'value', 0)
    assert cpu.memory.inspect_byte('ram', 0).value == 90


def test_session_uses_configured_gate_and_cannot_substitute_saved_event_gate():
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.genome import ScenarioGenome
    runner, _, gate = fixture()
    template = ScenarioGenome('paths', 'IP_TO_IP', 'template', ('uart', 'cpu'), 8, ())
    assert ScenarioSession(template, runner).prerequisite_gate is gate
    runner, _, _ = fixture()
    with pytest.raises(ValueError, match='trusted'):
        ScenarioSession(template, runner, prerequisite_gate=SimpleNamespace(
            require_case=lambda case: None, observe=lambda receipt: ()))


def test_replacing_installed_memory_is_permanent_uncertainty_even_if_restored():
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    actual = cpu.service.memory
    cpu.service.memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
        initialization_seed=5, max_initialized_bytes=4096)
    assert not gate.tracker.satisfied(prerequisite(event))
    cpu.service.memory = actual
    gate.tracker.reset(event_id=0)
    assert not gate.tracker.satisfied(prerequisite(event))


def test_current_generation_change_never_matches_previous_commit():
    runner, cpu, gate = fixture()
    old = write(runner, cpu)
    cpu.memory.cold_reset()
    assert not gate.tracker.satisfied(prerequisite(old))
    assert gate.tracker.satisfied(prerequisite(write(runner, cpu)))


def test_query_and_admission_use_exact_registered_action_input():
    from tests.scenario.test_source_action_session_gate import action_for
    from myfuzz.scenario.source_actions import SourceActionPrerequisiteError
    runner, cpu, gate = fixture()
    event = write(runner, cpu, drain=False)
    action = action_for('dependent', prerequisites=(prerequisite(event),))
    gate.register(action)
    case = SimpleNamespace(source=SimpleNamespace(action_id='dependent', component='a',
        port='pin', bit_offset=0, width=1, value=1))
    before = tuple(runner.events), cpu.memory.state_summary()
    with pytest.raises(SourceActionPrerequisiteError): gate.require_case(case)
    assert before == (tuple(runner.events), cpu.memory.state_summary())
    runner._append_external_events('cpu', 1)
    assert gate.require_case(case) is action


def test_public_inspection_rejects_invalid_region_and_offset():
    _, cpu, _ = fixture()
    for region, offset in [('missing', 0), ('ram', True), ('ram', -1), ('ram', 1 << 64)]:
        with pytest.raises(ValueError): cpu.memory.inspect_byte(region, offset)


def test_startup_gate_configuration_and_action_capacity_are_bounded():
    from tests.scenario.test_source_action_session_gate import action_for
    runner, _ = wired()
    with pytest.raises(ValueError): runner.configure_persistent_memory_prerequisites()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner.configure_persistent_memory_prerequisites(max_actions=1)
    gate = runner.persistent_memory_prerequisite_gate
    action = action_for('first'); gate.register(action); gate.register(action)
    with pytest.raises(ValueError, match='capacity'): gate.register(action_for('second'))
    assert runner.identity_document()['persistent_memory_prerequisites']['max_actions'] == 1
    with pytest.raises(ValueError): runner.configure_persistent_memory_prerequisites()


def test_ram_gate_cannot_grant_other_scopes_from_legacy_reservations():
    from myfuzz.scenario.source_actions import instruction_slot_unmaterialized_prerequisite
    _, _, gate = fixture()
    gate.tracker.register_instruction_slot('cpu', 0x20000, 'saved-slot', event_id=1)
    p = instruction_slot_unmaterialized_prerequisite('cpu', 0x20000, 'saved-slot')
    assert not gate.tracker.satisfied(p)


def test_pending_authority_uncertainty_invalidates_active_before_journal_drain():
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    runner._memory_read_authority._bad = True
    assert not gate.tracker.satisfied(prerequisite(event))


def test_explicit_age_horizon_cannot_keep_or_restore_old_live_candidate():
    runner, cpu, gate = fixture(max_event_gap=4)
    event = write(runner, cpu)
    assert gate.tracker.satisfied(prerequisite(event))
    gate.tracker.advance_cursor(gate.tracker.cursor + 5)
    assert not gate.tracker.satisfied(prerequisite(event))
    runner._events.append({'event_id': len(runner.events) + 1, 'kind': 'fixture_step'})
    assert not gate.tracker.satisfied(prerequisite(event))


def test_ambiguous_memory_id_cannot_grant_cross_service_prerequisites():
    from tests.scenario.test_memory_dependency_evidence import fixture as evidence_fixture
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    from myfuzz.scenario.live_memory_prerequisites import PersistentMemoryPrerequisiteGate
    services = {'cpu1': evidence_fixture()[0], 'cpu2': evidence_fixture()[0]}
    consumer = MemoryDependencyEvidenceConsumer(
        memory_commit_authority=MemoryCommitAuthority(services=services),
        memory_read_authority=MemoryReadAuthority(services=services),
        runtime_contract_sha256='a' * 64)
    with pytest.raises(ValueError, match='ambiguous'):
        PersistentMemoryPrerequisiteGate(consumer=consumer)


def test_online_session_refusal_happens_before_runtime_validation_or_commands():
    from tests.scenario.test_source_action_session_gate import action_for
    from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.source_actions import SourceActionPrerequisiteError
    from myfuzz.scenario.batch import BatchSourceEvent, BatchAdvance
    runner, _, gate = fixture()
    p = ram_commit_prerequisite('ram', 0, 0, 'a' * 64)
    gate.register(action_for('dependent', prerequisites=(p,)))
    session = ScenarioSession(ScenarioGenome('paths', 'IP_TO_IP', 'template',
        ('uart', 'cpu'), 8, ()), runner)
    # Use the actual submission method; pre-admission must reject before the
    # later runtime path checks, source injection or any local command.
    session._begun = True; runner._status = 'running'
    case = OnlineCase('dependent-case', 'IP_TO_IP', 'unused-path',
        BatchSourceEvent('dependent', 'a', 'pin', 1, 0, 1), (BatchAdvance(('uart', 'cpu')),))
    before = tuple(runner.events), dict(runner.local_ticks)
    with pytest.raises(SourceActionPrerequisiteError): session.submit_case(case)
    assert before == (tuple(runner.events), dict(runner.local_ticks))
    assert session.cases == ()


def test_gate_installed_after_session_construction_is_used_before_admission():
    from tests.scenario.test_source_action_session_gate import action_for
    from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.source_actions import SourceActionPrerequisiteError
    from myfuzz.scenario.batch import BatchSourceEvent, BatchAdvance
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    session = ScenarioSession(ScenarioGenome('paths', 'IP_TO_IP', 'template',
        ('uart', 'cpu'), 8, ()), runner)
    assert session.prerequisite_gate is None
    runner.configure_persistent_memory_prerequisites()
    gate = runner.persistent_memory_prerequisite_gate
    gate.register(action_for('dependent', prerequisites=(
        ram_commit_prerequisite('ram', 0, 0, 'a' * 64),)))
    assert session.prerequisite_gate is gate
    session._begun = True; runner._status = 'running'
    case = OnlineCase('dependent-case', 'IP_TO_IP', 'unused-path',
        BatchSourceEvent('dependent', 'a', 'pin', 1, 0, 1), (BatchAdvance(('uart', 'cpu')),))
    before = tuple(runner.events), dict(runner.local_ticks)
    with pytest.raises(SourceActionPrerequisiteError): session.submit_case(case)
    assert before == (tuple(runner.events), dict(runner.local_ticks))


def test_support_instruction_prerequisites_are_checked_before_admission():
    from tests.scenario.test_source_action_session_gate import action_for
    from myfuzz.scenario.source_actions import SourceAction, TerminationObservation, SourceActionPrerequisiteError
    from myfuzz.scenario.session_runtime import OnlineInstruction
    _, _, gate = fixture()
    main = action_for('main'); gate.register(main)
    support = SourceAction(action_id='support', kind='instruction', component='cpu',
        source_id='cpu.program', ownership='fuzzable', flow_id='F4',
        payload={'address': 0x20000, 'words_hex': '13000000'},
        termination_observation=TerminationObservation('delivery', 'support:delivery'),
        local_step_budget=8, prerequisites=(ram_commit_prerequisite('ram', 0, 0, 'a' * 64),))
    gate.register(support)
    case = SimpleNamespace(source=SimpleNamespace(action_id='main', component='a',
        port='pin', bit_offset=0, width=1, value=1),
        support_instructions=(OnlineInstruction('support', 'cpu', 0x20000, '13000000'),))
    with pytest.raises(SourceActionPrerequisiteError): gate.require_case(case)
