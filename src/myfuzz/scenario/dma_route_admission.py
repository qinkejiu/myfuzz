"""Protocol-neutral consumption of D4-bound DMA master routes."""
from __future__ import annotations

from dataclasses import asdict
from copy import deepcopy
import json

from .ledger import TransactionKey
from .runtime_edge_index import DmaMasterRouteMatch
from .runtime_path_contract import DmaMasterRouteContract


class DmaMasterRouteAdmission:
    """Match each native beat to one selected D4 route before policy checks."""

    __slots__ = ('_beat_policy', '_bound_topology', '_path_id', '_read_route',
                 '_write_route', '_binding_sha256', '_route_matches',
                 '__weakref__')

    def __init__(self, beat_policy, bound_topology, *, path_id,
                 read_route, write_route):
        if any(not callable(getattr(beat_policy, name, None)) for name in
                ('identity_document', 'begin_case', 'accepted', 'completed')):
            raise ValueError('DMA route admission requires a beat policy')
        if not hasattr(beat_policy, 'state'):
            raise ValueError('DMA route admission beat policy must expose state')
        if any(not callable(getattr(bound_topology, name, None)) for name in
                ('match_dma_master_route', 'document', 'validate_topology')):
            raise ValueError('DMA route admission requires a bound topology')
        if (type(path_id) is not str or not path_id or path_id.strip() != path_id
                or type(read_route) is not DmaMasterRouteContract
                or type(write_route) is not DmaMasterRouteContract
                or read_route.operation != 'read'
                or write_route.operation != 'write'
                or read_route.identity_sha256 == write_route.identity_sha256):
            raise ValueError('DMA route admission requires one selected read/write route pair')
        binding = bound_topology.document()
        binding_sha256 = getattr(bound_topology, 'identity_sha256', None)
        if (type(binding) is not dict or type(binding_sha256) is not str
                or len(binding_sha256) != 64
                or any(ch not in '0123456789abcdef' for ch in binding_sha256)):
            raise ValueError('DMA route admission bound topology identity is invalid')
        self._beat_policy = beat_policy
        self._bound_topology = bound_topology
        self._path_id = path_id
        self._read_route = read_route
        self._write_route = write_route
        self._binding_sha256 = binding_sha256
        self._route_matches = {}

    @property
    def state(self):
        return self._beat_policy.state

    @property
    def route_matches(self):
        """Return detached route-match rows indexed by admitted transaction."""
        return [dict(row, transaction=dict(row['transaction']))
                for row in self._route_matches.values()]

    def identity_document(self):
        return {
            'schema_version': 'dma_master_route_admission.v1',
            'binding_identity_sha256': self._binding_sha256,
            'path_id': self._path_id,
            'read_route_sha256': self._read_route.identity_sha256,
            'write_route_sha256': self._write_route.identity_sha256,
            'beat_policy': deepcopy(self._beat_policy.identity_document()),
        }

    def begin_case(self, execution_id, testcase_id):
        self._route_matches.clear()
        self._beat_policy.begin_case(execution_id, testcase_id)

    @staticmethod
    def _match_document(match):
        row = asdict(match)
        row['transaction'] = row.pop('transaction_key')
        return row

    def accepted(self, key, *, address, write, value, byte_enable, target):
        if (type(key) is not TransactionKey or type(address) is not int
                or address < 0 or address % 4 or type(write) is not bool
                or type(value) is not int or not 0 <= value <= 0xffffffff
                or type(byte_enable) is not int or byte_enable != 15):
            raise ValueError('DMA route admission requires a typed aligned full-word beat')
        if key in self._route_matches:
            raise ValueError('DMA route admission transaction key was already accepted')
        route = self._write_route if write else self._read_route
        if ((route.target_kind == 'persistent_memory' and target is not None)
                or (route.target_kind == 'peripheral' and target is None)):
            raise ValueError('DMA route target object does not match the selected route')
        match = self._bound_topology.match_dma_master_route(
            self._path_id,
            initiator_component=route.initiator_component,
            endpoint_id=route.endpoint_id,
            target_kind=route.target_kind,
            target_component=route.target_component,
            target_id=route.target_id,
            base=route.base, size=route.size,
            operation=route.operation, address=address,
            byte_enable=byte_enable, transaction_key=key,
            value=value if write else None)
        if (type(match) is not DmaMasterRouteMatch
                or type(match.transaction_key) is not TransactionKey
                or match.transaction_key is not key
                or match.route_sha256 != route.identity_sha256
                or match.edge_key != route.key
                or match.source_node_id != route.source_node_id
                or match.target_node_id != route.target_node_id
                or match.path_id != self._path_id
                or match.initiator_component != route.initiator_component
                or match.endpoint_id != route.endpoint_id
                or match.target_kind != route.target_kind
                or match.target_component != route.target_component
                or match.target_id != route.target_id
                or match.base != route.base or match.size != route.size
                or match.operation != route.operation
                or match.address != address or match.byte_enable != byte_enable
                or match.target_identity_sha256 != route.target_identity_sha256):
            raise ValueError('DMA route match does not exactly match the selected route')
        self._beat_policy.accepted(key, address=address, write=write,
            value=value, byte_enable=byte_enable, target=target)
        self._route_matches[key] = self._match_document(match)

    def completed(self, key, *, rdata, error):
        if type(key) is not TransactionKey:
            raise ValueError('DMA route response requires a typed transaction key')
        match = self._route_matches.get(key)
        if match is None or match['transaction'] != asdict(key):
            raise ValueError('DMA route response has no exact admitted route match')
        self._beat_policy.completed(key, rdata=rdata, error=error)
