"""Saved action declarations are re-registered against fresh actual authority."""
from types import SimpleNamespace
import copy
import pytest
from tests.scenario.test_source_actions import instruction_action
from myfuzz.scenario.session_runtime import OnlineInstruction


@pytest.fixture(scope='module')
def factory(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    return make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('replay-actions'),
        memory_commit_receipts=True, persistent_memory_runtime_contract_sha256='a' * 64)


def prepared(factory, *, write=True):
    runner = factory()
    cpu = runner.sessions['cpu']
    cpu._case_id = 'software-callback'
    cpu.memory.declare_instruction_slots(0x11000, 4)
    if write:
        cpu._serve('data', 1, 0x10000, 90, 15)
        runner._append_external_events('cpu', 1)
    return runner, cpu, runner.persistent_memory_prerequisite_gate


def recorded(factory):
    _, _, gate = prepared(factory)
    action = instruction_action(payload={'address': 0x11000, 'words_hex': 'b700010003a10000'})
    case = SimpleNamespace(source=OnlineInstruction(action.action_id, 'cpu', 0x11000,
                                                  action.payload['words_hex']), support_instructions=())
    gate.register(action)
    gate.require_case(case)
    return case, gate.replay_case_declaration(case)


def test_fresh_actual_writer_recomputes_saved_action_and_binding(factory):
    case, declaration = recorded(factory)
    assert not declaration['source_action']['prerequisites']
    _, _, gate = prepared(factory)
    gate.register_replay_case(case, declaration)
    gate.require_case(case)
    assert gate.replay_case_declaration(case) == declaration


def test_saved_action_and_binding_cannot_supply_missing_actual_writer(factory):
    case, declaration = recorded(factory)
    _, _, gate = prepared(factory, write=False)
    with pytest.raises(ValueError):
        gate.register_replay_case(case, declaration)
    assert gate.action_ids == ()


def test_changed_saved_expected_binding_is_rejected_before_cpu_commands(factory):
    case, declaration = recorded(factory)
    altered = copy.deepcopy(declaration)
    altered['dynamic_binding']['bound_witness']['value'] = 91
    runner, _, gate = prepared(factory)
    before = runner.event_count
    with pytest.raises(ValueError):
        gate.register_replay_case(case, altered)
    assert runner.event_count == before and all(s._process is None for s in runner.sessions.values())


def test_fixed_support_replay_reregisters_exact_fragment(factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    decoder = make_ibex_pulp_dual_source_online_decoder(result_slot_readback=True)
    case = next(case for index in range(len(decoder.sources))
        if (case := decoder.decode(bytes((0, 0, index, 7, 0, 0, 0, 0)))).support_instructions)
    action = decoder.source_action(case)
    _, _, gate = prepared(factory, write=False)
    gate.register(action)
    for fragment in case.support_instructions:
        gate.register_support_instruction(fragment, flow_id=action.flow_id,
                                          local_step_budget=action.local_step_budget)
    declaration = gate.replay_case_declaration(case)
    _, _, fresh = prepared(factory, write=False)
    fresh.register_replay_case(case, declaration)
    assert fresh.replay_case_declaration(case) == declaration


def test_saved_primary_payload_must_match_case_before_registration(factory):
    from dataclasses import replace
    from myfuzz.scenario.source_actions import SourceAction
    case, declaration = recorded(factory)
    altered = copy.deepcopy(declaration)
    action = SourceAction.from_document(altered['source_action'])
    altered['source_action'] = replace(action, payload=dict(address=0x11004,
        words_hex=action.payload['words_hex']), action_sha256='').document()
    _, _, gate = prepared(factory)
    with pytest.raises(ValueError):
        gate.register_replay_case(case, altered)
    assert gate.action_ids == ()


@pytest.mark.parametrize('failed_admission', [False, True])
def test_session_plan_saves_admission_snapshot_before_case_effects(factory, monkeypatch, failed_admission):
    import json
    from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.batch import BatchAdvance
    runner = factory()
    session = ScenarioSession(ScenarioGenome('saved', 'CPU_TO_IP_TO_CPU', 'manual',
        ('cpu', 'gpio_a', 'gpio_b'), 8, ()), runner)
    cpu = runner.sessions['cpu']; cpu._case_id = 'software-callback'
    cpu.memory.declare_instruction_slots(0x11000, 2)
    cpu._serve('data', 1, 0x10000, 90, 15)
    runner._append_external_events('cpu', 1)
    gate = runner.persistent_memory_prerequisite_gate
    action = instruction_action(payload={'address': 0x11000, 'words_hex': 'b700010003a10000'})
    gate.register(action)
    case = OnlineCase('saved-case', 'CPU_TO_IP_TO_CPU', 'manual',
        OnlineInstruction(action.action_id, 'cpu', 0x11000, action.payload['words_hex']),
        (BatchAdvance(('cpu',)),))
    expected = gate.replay_case_declaration(case)
    session._begun = True; runner._status = 'running'
    # Isolate plan capture from DUT execution; actual admission and memory
    # authority above run unchanged.
    def execute(*args):
        cpu.memory.accept_instructions(0x11000, case.source.data, source_event_id='software-input')
        return SimpleNamespace(events=(), case_id=case.case_id)
    if failed_admission:
        def accept_then_fail(address, data, **kwargs):
            cpu.memory.accept_instructions(address, data, **kwargs)
            raise RuntimeError('partial instruction admission')
        monkeypatch.setattr(cpu, 'accept_instructions', accept_then_fail)
        with pytest.raises(RuntimeError, match='partial instruction admission'):
            session.submit_case(case)
    else:
        monkeypatch.setattr(session, '_execute_case', execute)
        session.submit_case(case)
    encoded = json.loads(session.encode_plan())
    assert encoded['schema_version'] == (13 if failed_admission else 12)
    assert encoded['prerequisite_admissions'] == [expected]
    if failed_admission:
        assert encoded['terminal_failure'] == dict(phase='source_admission', case_index=0,
            case_id=case.case_id, command_index=None, error_type='RuntimeError',
            error_message='partial instruction admission')


def test_replay_accepts_new_schema_before_factory_and_rejects_admission_count():
    import json
    import hashlib
    from myfuzz.scenario.session_runtime import replay_online_session
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.genome import GenomeCodec
    from myfuzz.scenario.replay import ScenarioTrace
    document = dict(schema_version=12,
        template=json.loads(GenomeCodec.encode(ScenarioGenome('saved', 'CPU_TO_IP_TO_CPU', 'manual',
            ('cpu',), 8, ()))), instruction_slots=[], warmup_advances=[], cases=[], prerequisite_admissions=[])
    class StopFactory(Exception): pass
    def stop(): raise StopFactory()
    def run():
        plan = json.dumps(document).encode()
        reference = ScenarioTrace(hashlib.sha256(plan).hexdigest(), 'complete', (), {}, '0' * 64, '0' * 64)
        return replay_online_session(plan, stop, reference)
    with pytest.raises(StopFactory): run()
    document['prerequisite_admissions'] = [{}]
    with pytest.raises(ValueError, match='admission count'): run()
    document['prerequisite_admissions'] = []
    document['provenance_configuration'] = {}
    document['source_admissions'] = []
    with pytest.raises(ValueError, match='provenance requires runtime'): run()


def test_replay_registers_actual_case_before_submit_and_cleans_up_refusal(factory, monkeypatch):
    import json
    import hashlib
    from dataclasses import asdict
    from myfuzz.scenario import session_runtime as module
    from myfuzz.scenario.genome import GenomeCodec, ScenarioGenome
    from myfuzz.scenario.replay import ScenarioTrace
    case, admission = recorded(factory)
    source = dict(asdict(case.source), kind='instruction')
    document = dict(schema_version=12, template=json.loads(GenomeCodec.encode(ScenarioGenome(
        'saved', 'CPU_TO_IP_TO_CPU', 'manual', ('cpu', 'gpio_a', 'gpio_b'), 8, ()))),
        instruction_slots=[], warmup_advances=[], prerequisite_admissions=[admission],
        cases=[dict(case_id='saved-case', direction='CPU_TO_IP_TO_CPU', path_id='manual',
                    source=source, support_instructions=[], advances=[['cpu']])])
    plan = json.dumps(document).encode()
    reference = ScenarioTrace(hashlib.sha256(plan).hexdigest(), 'complete', (), {}, '0' * 64,
                              hashlib.sha256(b'{}').hexdigest())
    calls = []
    class RecordingSession:
        # Isolate replay orchestration from RTL; keep the actual factory gate,
        # memory authority and register_replay_case implementation.
        def __init__(self, template, runner, **kwargs):
            self.runner = runner; self.runtime_path_document = None
            self._terminal_failure = None; self._source_schedule_ticks = {}
        def begin(self): calls.append('begin')
        def submit_case(self, replayed, **kwargs):
            self.runner.persistent_memory_prerequisite_gate.require_case(replayed)
            calls.append('submit')
        def finish(self): calls.append('finish'); return reference
    monkeypatch.setattr(module, 'ScenarioSession', RecordingSession)
    monkeypatch.setattr(module, '_online_manifest', lambda *a, **k: {})
    runner, _, _ = prepared(factory)
    assert module.replay_online_session(plan, lambda: runner, reference).matches
    assert calls == ['begin', 'submit', 'finish']
    calls.clear()
    runner, _, _ = prepared(factory, write=False)
    with pytest.raises(ValueError):
        module.replay_online_session(plan, lambda: runner, reference)
    assert calls == ['begin', 'finish']
    calls.clear()
    def failed_finish(self):
        calls.append('finish')
        raise RuntimeError('cleanup failed')
    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(RecordingSession, 'finish', failed_finish)
        runner, _, _ = prepared(factory, write=False)
        with pytest.raises(ValueError) as refusal:
            module.replay_online_session(plan, lambda: runner, reference)
        assert any('cleanup failed' in note for note in refusal.value.__notes__)
    assert calls == ['begin', 'finish']
    calls.clear()
    document['prerequisite_admissions'][0]['unknown_field'] = True
    plan = json.dumps(document).encode()
    reference = ScenarioTrace(hashlib.sha256(plan).hexdigest(), 'complete', (), {}, '0' * 64,
                              hashlib.sha256(b'{}').hexdigest())
    runner, _, _ = prepared(factory)
    with pytest.raises(ValueError):
        module.replay_online_session(plan, lambda: runner, reference)
    assert calls == []


def test_actual_session_runtime_configuration_preserves_factory_authorities(factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.genome import ScenarioGenome
    runner = factory()
    decoder = make_ibex_pulp_dual_source_online_decoder(result_slot_readback=True)
    session = ScenarioSession(ScenarioGenome('runtime', 'CPU_TO_IP_TO_CPU', 'manual',
        ('cpu', 'gpio_a', 'gpio_b'), 8, ()), runner)
    commits, reads = runner._memory_commit_authority, runner._memory_read_authority
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract, decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    assert runner._memory_commit_authority is commits and runner._memory_read_authority is reads
    assert runner.provenance_enabled
    assert all(s._process is None for s in runner.sessions.values())
    cpu = runner.sessions['cpu']; cpu._case_id = 'software-callback'
    cpu._serve('data', 1, 0x10000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x10000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    assert commits.pending_count == reads.pending_count == 0
