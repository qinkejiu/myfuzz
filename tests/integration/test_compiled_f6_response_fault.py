"""Software-only parsed PRE receipts exercise the original DMA step path."""
from dataclasses import FrozenInstanceError, asdict, replace
import importlib
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.runtime_edge_index import DmaMasterRouteMatch
from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract


def _api():
    name = 'myfuzz.local_harness.f6_dma_response_fault'
    assert importlib.util.find_spec(name) is not None, 'sealed F6 response fault is missing'
    return importlib.import_module(name)


class Policy:
    state = 'ready'

    def __init__(self, order):
        self.order = order
        self.responses = []

    def identity_document(self):
        return {'schema_version': 'synthetic_f6_policy.v1'}

    def begin_case(self, execution_id, testcase_id):
        pass

    def accepted(self, key, **request):
        self.order.append(('admitted', key))

    def completed(self, key, **response):
        self.responses.append((key, response))
        self.order.append(('completed', key, response['error']))


class Topology:
    identity_sha256 = 'b' * 64

    def __init__(self, routes, order):
        self.routes = routes
        self.order = order
        self.reject = False

    def document(self):
        return {'schema_version': 'synthetic_bound_topology.v1'}

    def validate_topology(self):
        self.order.append(('validated',))

    def match_dma_master_route(self, path_id, **request):
        self.validate_topology()
        if self.reject:
            raise ValueError('synthetic live route rejected')
        route = next(r for r in self.routes if r.operation == request['operation'])
        return DmaMasterRouteMatch(route_sha256=route.identity_sha256,
            edge_key=route.key, source_node_id=route.source_node_id,
            target_node_id=route.target_node_id, path_id=path_id,
            initiator_component=route.initiator_component,
            endpoint_id=route.endpoint_id, target_kind=route.target_kind,
            target_component=route.target_component, target_id=route.target_id,
            base=route.base, size=route.size, operation=route.operation,
            address=request['address'], byte_enable=request['byte_enable'],
            transaction_key=request['transaction_key'],
            target_identity_sha256=route.target_identity_sha256)


@pytest.fixture
def setup_dma(tmp_path, monkeypatch):
    def make(*, execution='synthetic-original', backend_stb=1):
        memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=64,
            regions=(MemoryRegion('ram', 0x1000, 64),))
        memory.preload(0x1000, bytes(64))
        dma = GeneratedWishboneDmaSession(SimpleNamespace(runtime_document={
            'kind': 'wishbone_dma'}), base_dir=tmp_path, cache_dir=tmp_path,
            memory=memory)
        order = []
        routes = tuple(DmaMasterRouteContract(rule_index=i, prerequisite_index=0,
            source_node_id='dma.' + op, target_node_id='ram.' + op,
            initiator_component='dma', endpoint_id=op + '_master',
            endpoint_identity_sha256='c' * 64, target_kind='persistent_memory',
            target_component='cpu', target_id='ram', base=0x1000, size=64,
            operation=op, permissions=('read', 'write'), byte_enable=15,
            readable_offsets=(), writable_offsets=(), accepted_write_values=(),
            target_identity_sha256='d' * 64) for i, op in enumerate(('read', 'write')))
        policy = Policy(order)
        topology = Topology(routes, order)
        admission = DmaMasterRouteAdmission(policy, topology, path_id='f6-test',
            read_route=routes[0], write_route=routes[1])
        dma.configure_dma_route_validator(topology.validate_topology)
        dma.configure_dma_route_admission(admission)
        service_calls = []
        for op in ('read', 'write'):
            original = getattr(dma.memory_service, op)
            def spy(*args, _op=op, _original=original, **kwargs):
                service_calls.append((_op, args[0]))
                order.append(('service', args[0]))
                return _original(*args, **kwargs)
            monkeypatch.setattr(dma.memory_service, op, spy)
        queue, commands = [], []
        def command(op, fields):
            commands.append(fields)
            pre = queue.pop(0) if queue else dict(mwb_cyc=0, mwb_stb=0,
                mwb_we=0, mwb_adr=0, mwb_dat_w=0)
            dma.local_ticks += 1
            return DriverReceipt('result', dma._execution, len(commands),
                dma.local_ticks-1, dma.local_ticks, 1, payload={
                    'pre_backend': pre,
                    'observations': {'backend': {'mwb_stb': backend_stb}}})
        # Only the transport is synthetic. All DMA production methods stay original.
        monkeypatch.setattr(dma, 'command', command)
        def start(fault=None, case_index=0):
            dma._execution, dma._case_id = execution, 'case-' + str(case_index)
            dma._source_sequence = 0
            admission.begin_case(dma._execution, dma._case_id)
            if fault is not None:
                fault.begin_case(case_index)
        def beat(operation='write', index=0, value=0x51):
            queue.append(dict(mwb_cyc=1, mwb_stb=1,
                mwb_we=int(operation == 'write'), mwb_adr=(0x1000+index*4) >> 2,
                mwb_dat_w=value))
            dma.step_local()
        return SimpleNamespace(dma=dma, memory=memory, order=order,
            policy=policy, topology=topology, admission=admission,
            service_calls=service_calls, commands=commands, start=start, beat=beat)
    return make


def _install(env, *, case=0, operation='write', index=0):
    api = _api()
    return api.install_f6_response_fault(env.dma,
        declaration=api.F6ResponseFaultDeclaration(case, operation, index),
        execution_binding_sha256='a' * 64)


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_fault_precedes_target_effect(setup_dma, operation):
    env = setup_dma()
    fault = _install(env, operation=operation)
    env.start(fault)
    env.beat(operation)
    row = env.dma.events[-1]
    key = TransactionKey(**row['accepted']['transaction'])
    receipt = row['environment_error_receipt']
    assert env.admission.route_matches[0]['transaction'] == asdict(key)
    assert env.service_calls == [] and env.dma.memory_service.events == []
    assert receipt['schema_version'] == 'f6_dma_environment_error_receipt.v1'
    assert receipt['source_transaction'] == asdict(key)
    assert receipt['target_effect'] is False and receipt['error'] == 1
    assert receipt['execution_binding_sha256'] == 'a' * 64
    assert receipt['selector'] == dict(case_index=0, operation=operation, word_index=0)
    assert env.dma.memory_service.ledger._entries[key].receipt is receipt
    assert not env.dma.memory_service.ledger.unresolved_keys
    assert fault.document()['selected_transaction'] == asdict(key)
    assert env.policy.responses == [(key, {'rdata': 0, 'error': 1})]
    assert env.order.index(('admitted', key)) < env.order.index(('completed', key, 1))
    env.dma.step_local()
    assert env.commands[-1][6:9] == (0, 0, 1)
    assert env.dma.events[-1]['response']['error'] == 1


def test_logical_selector_preserves_prior_effects_and_is_one_shot(setup_dma):
    env = setup_dma()
    fault = _install(env, index=2)
    env.start(fault)
    for index in range(4):
        env.beat('write', index)
        env.dma.step_local()
    assert [key.source_sequence for _, key in env.service_calls] == [1, 2, 4]
    assert len([r for r in env.dma.events if 'environment_error_receipt' in r]) == 1
    assert env.memory.read(0x1008, 4, transaction_id='assert').value == 0
    assert env.memory.read(0x1004, 4, transaction_id='assert').value == 0x51
    assert fault.document()['selected_transaction']['source_sequence'] == 3
    assert not env.dma.memory_service.ledger.unresolved_keys


def test_other_case_and_operation_do_not_match(setup_dma):
    env = setup_dma()
    fault = _install(env, case=1)
    env.start(fault)
    env.beat('write')
    env.dma.step_local()
    env.start(fault, case_index=1)
    env.beat('read')
    env.dma.step_local()
    assert fault.document()['selected_transaction'] is None
    env.beat('write')
    assert env.dma.events[-1]['environment_error_receipt']['error'] == 1


@pytest.mark.parametrize('index', [0, -1, 1, 2, True, 16])
def test_case_index_cannot_advance_without_new_native_case_scope(setup_dma, index):
    env = setup_dma()
    fault = _install(env, case=1)
    env.start(fault, case_index=0)
    original_scope = (env.dma._execution, env.dma._case_id,
        env.dma.source_component, env.dma.reset_epoch)
    if type(index) is int and index == 1:
        with pytest.raises(ValueError, match='new native testcase scope'):
            fault.begin_case(index)
    else:
        with pytest.raises(ValueError):
            fault.begin_case(index)
    assert (env.dma._execution, env.dma._case_id,
        env.dma.source_component, env.dma.reset_epoch) == original_scope
    assert fault.document()['selected_transaction'] is None


def test_route_rejection_precedes_selector_and_target(setup_dma):
    env = setup_dma()
    fault = _install(env)
    env.start(fault)
    env.topology.reject = True
    with pytest.raises(ValueError, match='live route rejected'):
        env.beat()
    assert env.service_calls == []
    assert fault.document()['selected_transaction'] is None
    assert env.dma.memory_service.ledger._entries == {}


def test_fresh_selects_same_logical_beat_with_a_new_complete_key(setup_dma):
    selected = []
    for execution in ('synthetic-original', 'synthetic-fresh'):
        env = setup_dma(execution=execution)
        fault = _install(env)
        env.start(fault)
        env.beat()
        selected.append(fault.document()['selected_transaction'])
    assert selected[0] != selected[1]
    assert {k: v for k, v in selected[0].items() if k != 'execution_id'} == {
        k: v for k, v in selected[1].items() if k != 'execution_id'}


@pytest.mark.parametrize('case,operation,index', [
    (True, 'write', 0), (-1, 'write', 0), (16, 'write', 0),
    (0, 'callback', 0), (0, 'read', True), (0, 'read', -1), (0, 'read', 4)])
def test_closed_selector_refuses_invalid_fields(case, operation, index):
    api = _api()
    with pytest.raises(ValueError):
        api.F6ResponseFaultDeclaration(case, operation, index)


def test_declaration_is_frozen_and_document_detached():
    api = _api()
    declaration = api.F6ResponseFaultDeclaration(0, 'read', 2)
    with pytest.raises(FrozenInstanceError):
        declaration.word_index = 0
    document = declaration.document()
    document['operation'] = 'write'
    assert declaration.document()['operation'] == 'read'


@pytest.mark.parametrize('change', ['started', 'prepared', 'reinstall', 'method', 'callback', 'binding', 'no_route'])
def test_installation_refuses_unsealed_or_late_authority(setup_dma, monkeypatch, change):
    env = setup_dma()
    api = _api()
    declaration = api.F6ResponseFaultDeclaration(0, 'write', 0)
    binding = 'a' * 64
    if change == 'started':
        env.start()
    elif change == 'prepared':
        env.dma._prepare_attempted = True
    elif change == 'reinstall':
        _install(env)
    elif change == 'method':
        monkeypatch.setattr(env.dma, 'step_local', lambda: None)
    elif change == 'callback':
        declaration = lambda key: True
    elif change == 'binding':
        binding = 'arbitrary-execution-id'
    elif change == 'no_route':
        env.dma._dma_route_admission = None
    with pytest.raises(ValueError):
        api.install_f6_response_fault(env.dma, declaration=declaration,
            execution_binding_sha256=binding)


@pytest.mark.parametrize('field,value', [('execution_id', 'other'), ('testcase_id', 'other'),
    ('source_component', 'other'), ('source_epoch', 1), ('channel_id', 'other'),
    ('source_sequence', 2)])
def test_selector_rejects_keys_without_actual_native_acceptance(setup_dma, field, value):
    env = setup_dma()
    fault = _install(env)
    env.start(fault)
    key = TransactionKey(env.dma._execution, env.dma._case_id, 'dma', 0, 'dma-memory', 1)
    with pytest.raises(ValueError, match='accepted|native|key'):
        fault.select(replace(key, **{field: value}), operation='write', word_index=0)
    assert fault.document()['selected_transaction'] is None


def test_runtime_method_drift_refuses_before_target(setup_dma, monkeypatch):
    env = setup_dma()
    fault = _install(env)
    env.start(fault)
    monkeypatch.setattr(env.dma, '_validate_dma_route_topology', lambda: None)
    with pytest.raises(ValueError, match='method|drift'):
        env.beat()
    assert env.service_calls == []


def test_write_tail_response_latency_is_unchanged(setup_dma):
    env = setup_dma(backend_stb=0)
    fault = _install(env)
    env.start(fault)
    env.beat()
    env.dma.step_local()
    assert env.commands[-1][6:9] == (0, 0, 0)
    env.dma.step_local()
    assert env.commands[-1][6:9] == (0, 0, 1)


def test_selected_error_prevents_new_case_and_selector_state_is_sealed(setup_dma):
    env = setup_dma()
    fault = _install(env)
    env.start(fault)
    env.beat()
    env.dma.step_local()
    selected = fault.document()['selected_transaction']
    with pytest.raises(ValueError, match='next live case'):
        fault.begin_case(1)
    with pytest.raises(AttributeError, match='sealed'):
        fault._binding = 'b' * 64
    with pytest.raises(TypeError):
        fault._counts[0] = 3
    detached = fault.document()
    detached['selector']['word_index'] = 3
    detached['selected_transaction']['source_sequence'] = 99
    assert fault.document()['selected_transaction'] == selected
    assert fault.document()['selector']['word_index'] == 0


@pytest.mark.parametrize('field,value', [('word_index', 1), ('word_index', False),
    ('case_index', False)])
def test_declaration_drift_is_rejected_before_native_step(setup_dma, field, value):
    env = setup_dma()
    fault = _install(env)
    env.start(fault)
    object.__setattr__(fault._declaration, field, value)
    with pytest.raises(ValueError, match='declaration.*drift'):
        env.beat()
    assert env.commands == [] and env.service_calls == []


def test_class_method_drift_cannot_become_installation_baseline(setup_dma, monkeypatch):
    env = setup_dma()
    _api()
    monkeypatch.setattr(GeneratedWishboneDmaSession, 'step_local', lambda self: None)
    with pytest.raises(ValueError, match='method drift'):
        _install(env)


def test_fault_installs_on_pinned_scenario_dma_subclass(setup_dma):
    env = setup_dma()
    env.dma.__class__ = GeneratedWishboneDmaScenarioSession

    fault = _install(env)

    assert type(env.dma) is GeneratedWishboneDmaScenarioSession
    assert _api()._validate_f6_response_fault(env.dma) is fault


def test_fault_install_rejects_scenario_dma_method_override(setup_dma, monkeypatch):
    env = setup_dma()
    env.dma.__class__ = GeneratedWishboneDmaScenarioSession
    monkeypatch.setattr(GeneratedWishboneDmaScenarioSession, 'step_local',
        lambda self, inputs=None, **control: None)

    with pytest.raises(ValueError):
        _install(env)


def test_fault_install_rejects_scenario_dma_class_alias_rebinding(setup_dma, monkeypatch):
    env = setup_dma()
    env.dma.__class__ = GeneratedWishboneDmaScenarioSession
    module = importlib.import_module(
        'myfuzz.local_harness.wishbone_dma_scenario_session')
    monkeypatch.setattr(module, 'GeneratedWishboneDmaScenarioSession',
        GeneratedWishboneDmaSession)

    with pytest.raises(ValueError):
        _install(env)


def test_stalled_pre_is_never_a_second_native_acceptance(setup_dma):
    env = setup_dma(backend_stb=0)
    fault = _install(env, index=1)
    env.start(fault)
    env.beat('write', 0)
    # Pending response stalls the next synthetic PRE; it has no accepted key.
    env.beat('write', 1)
    assert fault.document()['selected_transaction'] is None
    assert len(env.admission.route_matches) == 1
    assert len(env.service_calls) == 1
    env.dma.step_local()
    env.beat('write', 1)
    assert fault.document()['selected_transaction']['source_sequence'] == 2


def test_even_matching_caller_key_has_no_native_selection_authority(setup_dma):
    env = setup_dma()
    fault = _install(env)
    env.start(fault)
    key = TransactionKey(env.dma._execution, env.dma._case_id, 'dma', 0, 'dma-memory', 1)
    with pytest.raises(ValueError, match='actual native accepted key'):
        fault.select(key, operation='write', word_index=0)
    assert fault.document()['selected_transaction'] is None
    env.beat()
    assert fault.document()['selected_transaction'] == asdict(key)


def test_fault_attribute_does_not_install_callback_authority(setup_dma):
    env = setup_dma()
    _api()
    env.dma._f6_response_fault = SimpleNamespace(select=lambda *args, **kwargs: True)
    env.start()
    with pytest.raises(ValueError, match='not installed'):
        env.beat()
    assert env.commands == [] and env.service_calls == []
