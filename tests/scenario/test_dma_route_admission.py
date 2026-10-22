from dataclasses import replace

import pytest

from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.runtime_edge_index import DmaMasterRouteMatch
from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract


PATH_ID = 'dma-route-path-v1'


def _routes():
    read = DmaMasterRouteContract(
        rule_index=0, prerequisite_index=0,
        source_node_id='ram.source', target_node_id='dma.read',
        initiator_component='dma', endpoint_id='read_master',
        endpoint_identity_sha256='a' * 64,
        target_kind='persistent_memory', target_component='cpu',
        target_id='ram', base=0x1000, size=0x1000, operation='read',
        permissions=('read', 'write'), byte_enable=15,
        readable_offsets=(), writable_offsets=(),
        accepted_write_values=(), target_identity_sha256='b' * 64)
    write = DmaMasterRouteContract(
        rule_index=2, prerequisite_index=0,
        source_node_id='dma.write', target_node_id='target.effect',
        initiator_component='dma', endpoint_id='write_master',
        endpoint_identity_sha256='a' * 64,
        target_kind='peripheral', target_component='target',
        target_id='target', base=0x40001000, size=0x1000,
        operation='write', permissions=('write',), byte_enable=15,
        readable_offsets=(), writable_offsets=(12,),
        accepted_write_values=(0x5a,), target_identity_sha256='c' * 64)
    return read, write


class _Policy:
    def __init__(self):
        self.calls = []
        self._state = 'expect_read'

    @property
    def state(self):
        return self._state

    def identity_document(self):
        return {'schema_version': 'test_beat_policy.v1'}

    def begin_case(self, execution_id, testcase_id):
        self.calls.append(('begin_case', execution_id, testcase_id))
        self._state = 'expect_read'

    def accepted(self, key, **kwargs):
        self.calls.append(('accepted', key, kwargs))
        self._state = 'pending'

    def completed(self, key, **kwargs):
        self.calls.append(('completed', key, kwargs))
        self._state = 'complete'


class _TargetBoundPolicy(_Policy):
    def __init__(self, expected_target):
        super().__init__()
        self.expected_target = expected_target

    def accepted(self, key, **kwargs):
        if kwargs['target'] is not self.expected_target:
            raise ValueError('target identity mismatch')
        super().accepted(key, **kwargs)


class _BoundTopology:
    def __init__(self, path_id, routes):
        self._path_id = path_id
        self._routes = routes
        self._tamper = None
        self.queries = []
        self.identity_sha256 = 'd' * 64

    def document(self):
        return {'schema_version': 'bound_dma_intent_topology.v1',
                'identity_sha256': self.identity_sha256}

    def validate_topology(self):
        return None

    def match_dma_master_route(self, path_id, *, initiator_component,
            endpoint_id, target_kind, target_component, target_id, base, size,
            operation, address, byte_enable, transaction_key, value=None):
        self.queries.append((path_id, operation, address, transaction_key, value))
        route = next((row for row in self._routes
            if row.operation == operation
            and row.initiator_component == initiator_component
            and row.endpoint_id == endpoint_id
            and row.target_kind == target_kind
            and row.target_component == target_component
            and row.target_id == target_id
            and row.base == base and row.size == size
            and row.byte_enable == byte_enable
            and row.base <= address <= row.base + row.size - 4
            and (operation != 'write' or value in row.accepted_write_values)), None)
        if route is None:
            return None
        match = DmaMasterRouteMatch(
            route_sha256=route.identity_sha256, edge_key=route.key,
            source_node_id=route.source_node_id,
            target_node_id=route.target_node_id, path_id=path_id,
            initiator_component=route.initiator_component,
            endpoint_id=route.endpoint_id, target_kind=route.target_kind,
            target_component=route.target_component, target_id=route.target_id,
            base=route.base, size=route.size, operation=route.operation,
            address=address, byte_enable=byte_enable,
            transaction_key=transaction_key,
            target_identity_sha256=route.target_identity_sha256)
        return replace(match, **self._tamper) if self._tamper else match


def _key(sequence):
    return TransactionKey('exec-1', 'case-1', 'dma', 0, 'dma-memory', sequence)


def _admission(policy=None):
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission

    routes = _routes()
    policy = policy or _Policy()
    topology = _BoundTopology(PATH_ID, routes)
    admission = DmaMasterRouteAdmission(policy, topology,
        path_id=PATH_ID, read_route=routes[0], write_route=routes[1])
    return admission, policy, topology, routes


def test_exact_read_and_write_routes_are_recorded_after_policy_acceptance():
    admission, policy, topology, _routes_pair = _admission()
    read_key, write_key = _key(1), _key(2)

    admission.accepted(read_key, address=0x1100, write=False, value=0,
                       byte_enable=15, target=None)
    target = object()
    admission.accepted(write_key, address=0x4000100c, write=True, value=0x5a,
                       byte_enable=15, target=target)

    assert [row['transaction'] for row in admission.route_matches] == [
        read_key.__dict__, write_key.__dict__]
    assert [call[0] for call in policy.calls] == ['accepted', 'accepted']
    assert [row[1] for row in topology.queries] == ['read', 'write']


def test_unmatched_route_or_forged_match_does_not_reach_beat_policy():
    admission, policy, topology, _routes_pair = _admission()

    with pytest.raises(ValueError, match='route'):
        admission.accepted(_key(1), address=0x2000, write=False, value=0,
                           byte_enable=15, target=None)
    assert policy.calls == []
    assert admission.route_matches == []

    topology._tamper = {'target_identity_sha256': 'e' * 64}
    with pytest.raises(ValueError, match='exact'):
        admission.accepted(_key(2), address=0x1100, write=False, value=0,
                           byte_enable=15, target=None)
    assert policy.calls == []
    assert admission.route_matches == []


def test_target_policy_rejection_does_not_commit_a_route_match():
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission

    routes = _routes()
    expected_target = object()
    policy = _TargetBoundPolicy(expected_target)
    topology = _BoundTopology(PATH_ID, routes)
    admission = DmaMasterRouteAdmission(policy, topology,
        path_id=PATH_ID, read_route=routes[0], write_route=routes[1])

    with pytest.raises(ValueError, match='target identity mismatch'):
        admission.accepted(_key(1), address=0x4000100c, write=True,
            value=0x5a, byte_enable=15, target=object())

    assert policy.calls == []
    assert policy.state == 'expect_read'
    assert admission.route_matches == []


def test_response_requires_the_same_admitted_transaction_key_and_case_reset_clears_matches():
    admission, policy, _topology, _routes_pair = _admission()
    key = _key(1)
    admission.accepted(key, address=0x1100, write=False, value=0,
                       byte_enable=15, target=None)

    with pytest.raises(ValueError, match='route match'):
        admission.completed(_key(2), rdata=0x5a, error=0)

    admission.completed(key, rdata=0x5a, error=0)
    assert policy.calls[-1] == ('completed', key, {'rdata': 0x5a, 'error': 0})
    admission.begin_case('exec-2', 'case-2')
    assert admission.route_matches == []
    assert admission.state == 'expect_read'
