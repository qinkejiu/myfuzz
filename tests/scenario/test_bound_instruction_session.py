"""Bound instructions admit exact graph sources and reserved ranges before effects."""
from dataclasses import replace
import json
import pytest
from myfuzz.scenario.batch import BatchAdvance
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import (ScenarioSession, OnlineCase, OnlineInstruction,
    BoundOnlineInstruction, replay_online_session)
from tests.scenario.test_instruction_image_binding import fixture


class Cpu:
    def __init__(self):
        self.memory = fixture()[2].sessions['cpu'].memory
        self.accepted = []
    def identity_document(self):
        return {'fixture': 'bound-image.v1', 'memory': self.memory.identity_document()}
    def declare_instruction_slots(self, address, count):
        pass
    def begin_case(self, testcase_id):
        pass
    def step_local(self, inputs):
        return {}
    def end_case(self):
        pass
    def accept_instructions(self, address, data, **kwargs):
        self.accepted.append((address, data))


def factory():
    return ScenarioRunner(sessions={'cpu': Cpu()}, ownership=compile_ownership((), ()), bindings=())


def configured():
    binding, prepared, _ = fixture()
    session = ScenarioSession(ScenarioGenome('bound', 'CPU_TO_IP', 'template', ('cpu',), 8, ()), factory())
    session.declare_instruction_slots('cpu', 0x1000, 4)
    session.configure_runtime_paths(prepared.graph, prepared.contract, prepared.runtime_paths,
        instruction_image_bindings=(binding,))
    return session


def candidate(session, address=0x1000):
    return OnlineCase('one', 'CPU_TO_IP', session.runtime_path_ids[0],
        BoundOnlineInstruction('action', 'cpu', address, '13000000', 'image'),
        (BatchAdvance(('cpu',)),))


def test_bound_roundtrip_manifest_and_fresh_replay():
    session = configured()
    session.begin()
    session.submit_case(candidate(session, 0x100c))
    reference = session.finish()
    document = json.loads(session.encode_plan())
    assert document['schema_version'] == 24
    assert document['cases'][0]['source']['kind'] == 'bound_instruction'
    assert document['instruction_image_bindings'] == list(session.instruction_image_binding_documents)
    assert document['instruction_image_bindings'] == session.manifest_document['instruction_image_bindings']
    replay = replay_online_session(session.encode_plan(), factory, reference)
    assert replay.matches, replay.difference_context


@pytest.mark.parametrize('change', ['plain', 'source', 'before', 'after', 'cross', 'slots', 'path'])
def test_bound_refusals_precede_case_effects(change):
    session = configured()
    session.begin()
    case = candidate(session)
    if change == 'plain': case = replace(case, source=OnlineInstruction('action', 'cpu', 0x1000, '13000000'))
    elif change == 'source': case = replace(case, source=replace(case.source, source_id='other'))
    elif change == 'before': case = replace(case, source=replace(case.source, address=0xffc))
    elif change == 'after': case = replace(case, source=replace(case.source, address=0x1010))
    elif change == 'cross': case = replace(case, source=replace(case.source, address=0x100c, data_hex='1300000013000000'))
    elif change == 'slots': session._instruction_slots = [('cpu', 0x1004, 1)]
    elif change == 'path': case = replace(case, path_id='other')
    before = session.runner.event_count
    with pytest.raises(ValueError): session.submit_case(case)
    assert session.runner.event_count == before
    assert session.runner.sessions['cpu'].accepted == []
    assert session.cases == ()


def test_bindings_require_provenance():
    binding, prepared, _ = fixture()
    session = ScenarioSession(ScenarioGenome('bound', 'CPU_TO_IP', 'template', ('cpu',), 8, ()), factory())
    with pytest.raises(ValueError):
        session.configure_runtime_paths(prepared.graph, prepared.contract, prepared.runtime_paths,
            provenance=False, instruction_image_bindings=(binding,))


def test_bound_terminal_failure_schema25_fresh_replay():
    from unittest.mock import patch
    def fail(self, address, data, **kwargs):
        raise ValueError('intentional input failure')
    with patch.object(Cpu, 'accept_instructions', fail):
        session = configured()
        session.begin()
        with pytest.raises(ValueError, match='intentional input failure'):
            session.submit_case(candidate(session))
        reference = session.finish()
        assert json.loads(session.encode_plan())['schema_version'] == 25
        result = replay_online_session(session.encode_plan(), factory, reference)
        assert result.matches, result.difference_context


@pytest.mark.parametrize('change', ['source', 'plain', 'range', 'binding', 'missing_provenance', 'missing_runtime'])
def test_saved_bound_mismatch_refuses_before_factory(change):
    import hashlib
    from unittest.mock import Mock
    session = configured()
    session.begin()
    session.submit_case(candidate(session))
    reference = session.finish()
    document = json.loads(session.encode_plan())
    if change == 'source': document['cases'][0]['source']['source_id'] = 'other'
    elif change == 'plain':
        document['cases'][0]['source']['kind'] = 'instruction'
        document['cases'][0]['source'].pop('source_id')
    elif change == 'range': document['cases'][0]['source']['address'] = 0x1010
    elif change == 'binding': document['instruction_image_bindings'][0]['source_id'] = 'other'
    elif change == 'missing_provenance': document.pop('source_admissions')
    else: document.pop('runtime_paths')
    plan = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    reference = replace(reference, genome_sha256=hashlib.sha256(plan).hexdigest())
    never = Mock(side_effect=AssertionError('must refuse before factory'))
    with pytest.raises(ValueError): replay_online_session(plan, never, reference)
    never.assert_not_called()


def test_plain_instruction_keeps_legacy_serialized_form():
    from tests.scenario.test_session_runtime_paths import configured as old_configured
    session = old_configured()
    session.begin()
    plain = OnlineInstruction('plain', 'a', 0, '13000000')
    session._cases.append(OnlineCase('plain', 'IP_TO_IP', 'old', plain, (BatchAdvance(('a',)),)))
    session._case_source_roles['plain'] = 'fuzz_source'
    document = json.loads(session.encode_plan())
    assert document['schema_version'] == 10
    assert document['cases'][0]['source'] == dict(kind='instruction', action_id='plain',
        component='a', address=0, data_hex='13000000')
    assert 'instruction_image_bindings' not in document


def test_binding_manifest_documents_are_detached_and_tamper_is_refused():
    session = configured()
    documents = session.instruction_image_binding_documents
    documents[0]['base'] = 0
    assert session.instruction_image_binding_documents[0]['base'] == 0x1000
    session._instruction_image_bindings = ()
    with pytest.raises(ValueError, match='configuration drift'): session.begin()


def mixed_factory():
    from myfuzz.scenario.ownership import InputField, InputOwner
    from tests.scenario.test_online_uart_source_events import _SerialHarness
    return ScenarioRunner(sessions={'cpu': Cpu(), 'uart': _SerialHarness()},
        ownership=compile_ownership((InputField('uart', 'rx', 8),),
            (InputOwner('uart', 'rx', 0, 8, 'source', 'external'),)), bindings=())


def mixed_configured():
    import hashlib
    from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
    from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract
    binding, original, _ = fixture()
    graph = DependencyGraph(sources=(*original.graph.sources.values(),
        FuzzableSource('serial.input', 'uart', 'rx', 0, 8, ('IP_TO_CPU',))),
        rules=(*original.graph._ordered_rules,
            DependencyRule('serial.observed', ('serial.input',), 'EVENT_ORDER')))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, (*original.contract.nodes,
        RuntimeNode('serial.input', 'uart', 'physical', 'rx', 0, 8),
        RuntimeNode('serial.observed', 'uart', 'logical')), original.contract.edges)
    paths = tuple((direction, path) for direction, target in (
        ('CPU_TO_IP', 'loaded'), ('IP_TO_CPU', 'serial.observed'))
        for path in graph.edge_paths_to(target, direction=direction))
    image_path_id = graph.path_identity(paths[0][1], direction=paths[0][0])
    session = ScenarioSession(ScenarioGenome('mixed-bound', 'CPU_TO_IP', 'template',
        ('cpu', 'uart'), 8, ()), mixed_factory())
    session.declare_instruction_slots('cpu', 0x1000, 4)
    session.configure_runtime_paths(graph, contract, paths,
        source_ownership=session.runner.ownership,
        instruction_image_bindings=(replace(binding, path_id=image_path_id),))
    return session


@pytest.mark.parametrize('terminal', [False, True])
def test_image_bound_mixed_source_schedules_roundtrip_for_schema24_and25(terminal):
    from unittest.mock import patch
    from myfuzz.scenario.batch import BatchSourceEvent
    session = mixed_configured()
    session.begin()
    for index, value in enumerate((0x5a, 0xa6)):
        session.submit_case(OnlineCase(f'serial-{index}', 'IP_TO_CPU',
            session.runtime_path_ids[1], BatchSourceEvent(f'event-{index}', 'uart', 'rx', value),
            (BatchAdvance(('uart',)),)))
    def fail(self, address, data, **kwargs):
        raise ValueError('mixed terminal instruction failure')
    def finish_and_replay():
        reference = session.finish()
        plan = session.encode_plan()
        document = json.loads(plan)
        assert document['schema_version'] == (25 if terminal else 24)
        assert document['cases'][1]['source']['scheduled_local_tick'] == 2
        result = replay_online_session(plan, mixed_factory, reference)
        assert result.matches, result.difference_context
    if terminal:
        with patch.object(Cpu, 'accept_instructions', fail):
            with pytest.raises(ValueError, match='mixed terminal instruction failure'):
                session.submit_case(candidate(session))
            finish_and_replay()
    else:
        session.submit_case(candidate(session))
        finish_and_replay()
