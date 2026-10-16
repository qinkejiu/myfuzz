"""Runtime qualification is separate from historical certificate storage."""
from copy import deepcopy
import pytest

from tests.scenario.test_live_memory_prerequisites import fixture, write, prerequisite
from tests.scenario.test_memory_dependency_runner import wired
from myfuzz.scenario.source_actions import (
    ip_register_prerequisite, irq_pulse_pending_prerequisite,
    irq_input_delivered_prerequisite, irq_taken_prerequisite,
)


def test_current_query_uses_actual_writer_without_read_or_journal_effects():
    runner, cpu, _ = fixture()
    event = write(runner, cpu)
    before = cpu.memory.state_summary(), tuple(runner.events), tuple(cpu.service.events)
    answer = runner.active_prerequisite_status(prerequisite(event))
    assert answer['status'] == 'satisfied' and answer['satisfied'] is True
    assert answer['proof_scope'] == 'current_installed_host_memory_bytes'
    assert answer['witness']['evidence_ref'] == prerequisite(event).evidence_ref
    assert before == (cpu.memory.state_summary(), tuple(runner.events), tuple(cpu.service.events))
    answer['witness'].clear()
    assert runner.active_prerequisite_status(prerequisite(event))['witness']


def test_history_without_active_provider_cannot_qualify_current_state():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    event = write(runner, cpu)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    answer = runner.active_prerequisite_status(prerequisite(event))
    assert answer['status'] == 'unknown' and answer['satisfied'] is False
    assert answer['reason'] == 'missing_active_provider' and answer['witness'] is None
    report = runner.dependency_lifecycle_report()
    assert report['history']['memory']['counts']['verified'] == 4
    assert report['active']['status'] == 'unknown'
    assert report['history_grants_prerequisites'] is False


@pytest.mark.parametrize('requirement', [
    ip_register_prerequisite('gpio', 'out', 0, 1, 1),
    irq_pulse_pending_prerequisite('uart', 1),
    irq_input_delivered_prerequisite('cpu', 1, 2),
    irq_taken_prerequisite('cpu', 1, 2),
])
def test_historical_only_scopes_are_unknown_even_with_installed_ram_provider(requirement):
    runner, _, _ = fixture()
    answer = runner.active_prerequisite_status(requirement)
    assert answer['status'] == 'unknown' and answer['satisfied'] is False
    assert answer['reason'] == 'missing_active_provider'


@pytest.mark.parametrize('invalidation', ['reset', 'overwrite', 'eviction', 'conflict'])
def test_cached_answer_and_saved_history_never_revive_invalidated_writer(invalidation):
    runner, cpu, gate = fixture(max_writer_versions=4)
    event = write(runner, cpu)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    history = deepcopy(runner.memory_dependency_evidence_report()['certificates'])
    saved_answer = runner.active_prerequisite_status(prerequisite(event))
    assert saved_answer['satisfied'] is True
    if invalidation == 'reset':
        runner._events.append({'event_id': len(runner.events) + 1, 'kind': 'reset_barrier'})
    elif invalidation == 'overwrite':
        write(runner, cpu, drain=False)
    elif invalidation == 'eviction':
        cpu._serve('data', 1, 0x20004, 90, 15)
        runner._append_external_events('cpu', 1)
    else:
        runner._events.append({'event_id': 1, 'kind': 'conflicting_annotation'})
    answer = runner.active_prerequisite_status(prerequisite(event))
    assert answer['status'] == ('incomplete' if invalidation == 'conflict' else 'unsatisfied')
    assert answer['satisfied'] is False and answer['witness'] is None
    assert saved_answer['satisfied'] is True  # detached observation, never re-enrolled
    assert runner.memory_dependency_evidence_report()['certificates'] == history
    for saved in [saved_answer, *history]:
        with pytest.raises(ValueError, match='typed prerequisite'):
            runner.active_prerequisite_status(saved)
    assert not runner.active_prerequisite_status(prerequisite(event))['satisfied']


def test_replaced_provider_is_permanently_incomplete_after_restoring_original():
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    assert runner.active_prerequisite_status(prerequisite(event))['satisfied']
    other, _, other_gate = fixture()
    runner.persistent_memory_prerequisite_gate = other_gate
    assert runner.active_prerequisite_status(prerequisite(event))['status'] == 'incomplete'
    runner.persistent_memory_prerequisite_gate = gate
    assert runner.active_prerequisite_status(prerequisite(event))['status'] == 'incomplete'
    assert runner.dependency_lifecycle_report()['active']['status'] == 'incomplete'


def test_instruction_slot_query_tracks_actual_materialization():
    from tests.scenario.test_live_memory_slot_policy import fixture as slot_fixture
    from tests.scenario.test_source_actions import instruction_action
    runner, cpu, gate = slot_fixture()
    action = gate.register(instruction_action(payload={'address': 0x20000, 'words_hex': '13000000'}))
    p = action.prerequisites[0]
    answer = runner.active_prerequisite_status(p)
    assert answer['satisfied'] and answer['proof_scope'] == 'current_declared_unmaterialized_instruction_slot'
    cpu.memory.accept_instructions(0x20000, b'\x13\x00\x00\x00', source_event_id='actual-input')
    assert runner.active_prerequisite_status(p)['status'] == 'unsatisfied'


def test_lifecycle_reports_are_detached_and_do_not_change_runtime_identity():
    runner, cpu, _ = fixture()
    event = write(runner, cpu)
    identity = runner.identity_document()
    before = tuple(runner.events)
    report = runner.dependency_lifecycle_report()
    assert report['active']['supported_kinds'] == ['ram_byte_version']
    assert 'irq_taken' in report['active']['unknown_kinds']
    assert report['active']['status'] == 'available'
    report['active'].clear()
    report['history']['memory'].clear()
    assert runner.dependency_lifecycle_report()['active']['status'] == 'available'
    assert runner.active_prerequisite_status(prerequisite(event))['satisfied']
    assert runner.identity_document() == identity and tuple(runner.events) == before


def test_rejected_lifecycle_provider_does_not_partially_install_gate():
    from myfuzz.scenario.live_memory_prerequisites import PersistentMemoryPrerequisiteGate
    from myfuzz.scenario.source_actions import CrossCaseEffectTracker
    class IncompatibleGate(PersistentMemoryPrerequisiteGate):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.tracker = CrossCaseEffectTracker()
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    before = runner.identity_document()
    with pytest.raises(ValueError, match='native memory lifecycle provider'):
        runner.configure_persistent_memory_prerequisites(prerequisite_gate_type=IncompatibleGate)
    assert runner.persistent_memory_prerequisite_gate is None
    assert runner.identity_document() == before
    assert runner.dependency_lifecycle_report()['active']['status'] == 'unknown'
    runner.configure_persistent_memory_prerequisites()
    assert runner.dependency_lifecycle_report()['active']['status'] == 'available'


def test_failed_provider_policy_does_not_partially_bind_lifecycle():
    from myfuzz.scenario.live_memory_prerequisites import PersistentMemoryPrerequisiteGate
    class FailedPolicyGate(PersistentMemoryPrerequisiteGate):
        @property
        def instruction_slot_policy(self):
            raise ValueError('policy failed')
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    before = runner.identity_document()
    with pytest.raises(ValueError, match='policy failed'):
        runner.configure_persistent_memory_prerequisites(prerequisite_gate_type=FailedPolicyGate)
    assert runner.persistent_memory_prerequisite_gate is None
    assert runner.identity_document() == before
    assert runner.dependency_lifecycle_report()['active']['status'] == 'unknown'
    runner.configure_persistent_memory_prerequisites()
    assert runner.dependency_lifecycle_report()['active']['status'] == 'available'


@pytest.mark.parametrize('owner', ['tracker', 'runner'])
@pytest.mark.parametrize('replacement', [None, object()])
def test_consumer_identity_drift_reports_incomplete_without_calling_replacement(owner, replacement):
    runner, cpu, gate = fixture()
    event = write(runner, cpu)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.active_prerequisite_status(prerequisite(event))['satisfied']
    consumer_owner = gate.tracker if owner == 'tracker' else runner
    attribute = '_consumer' if owner == 'tracker' else '_memory_dependency_consumer'
    original = getattr(consumer_owner, attribute)
    setattr(consumer_owner, attribute, replacement)
    answer = runner.active_prerequisite_status(prerequisite(event))
    assert answer['status'] == 'incomplete' and answer['witness'] is None
    report = runner.dependency_lifecycle_report()
    assert report['active']['status'] == 'incomplete'
    assert report['history']['memory']['counts']['verified'] == 4
    setattr(consumer_owner, attribute, original)
    assert runner.active_prerequisite_status(prerequisite(event))['status'] == 'incomplete'
