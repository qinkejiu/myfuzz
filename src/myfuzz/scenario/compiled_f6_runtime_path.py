"""Detached one-word RAM-to-Caliptra F6 runtime path artifact.

The static F6 compiler result remains a refusal.  This reader joins its
existing D3/D4 handoff to a closed source word and two explicit route IDs;
it grants no live topology or transaction authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import math
from collections.abc import Mapping

from myfuzz.local_harness.wishbone_dma_session import (
    MasterTargetWindow, dma_route_endpoint_identity_document,
)

from .compiled_f6_dma_handoff import (
    CompiledF6DmaHandoff, CompiledF6DmaHandoffError,
    bind_compiled_f6_dma_handoff, prepare_compiled_f6_dma_handoff,
    validate_compiled_f6_static,
)
from .compiled_paths import PathWiring, load_path_wiring
from .dependency import DependencyGraph, DependencyRule, FuzzableSource
from .dma_intent_topology_binding import prepare_dma_intent_binding
from .dma_route_intent import parse_dma_master_route_intents
from .ledger import TransactionLedger
from .memory import PersistentMemory
from .memory_service import MemoryService
from .runtime_path_contract import (
    DmaMasterRouteContract, PreparedRuntimePathContract,
    RuntimeEdgeContract, RuntimeNode, RuntimePathContract,
    canonical_runtime_identity_sha256,
    persistent_memory_route_identity_document,
)


_SOURCE_SCHEMA = 'dma_transfer_source_word.v1'
_PAIR_SCHEMA = 'dma_transfer_route_pair.v1'
_PATH_SCHEMA = 'compiled_f6_runtime_path.v1'
_SOURCE_KEYS = {
    'schema_version', 'memory_component', 'resource_id', 'image_id',
    'address', 'word_bytes', 'byte_enable', 'direction',
}
_PAIR_KEYS = {
    'schema_version', 'read_route_id', 'write_route_id', 'relation',
}
_PATH_KEYS = {
    'schema_version', 'source', 'transfer_pair', 'compiled_f6_handoff',
    'identity_sha256',
}
_GRAPH_RULES = [
    {'rule_index': 0, 'target': 'dma.read_data',
     'prerequisites': ['ram.source_word'], 'kind': 'DMA_MASTER_TRANSFER'},
    {'rule_index': 1, 'target': 'dma.write_data',
     'prerequisites': ['dma.read_data'], 'kind': 'EVENT_ORDER'},
    {'rule_index': 2, 'target': 'sha.ctrl_start_effect',
     'prerequisites': ['dma.write_data'], 'kind': 'DMA_MASTER_TRANSFER'},
]
_GRAPH_EDGES = [
    {'rule_index': index, 'prerequisite_index': 0,
     'prerequisite': rule['prerequisites'][0], 'target': rule['target'],
     'kind': rule['kind']}
    for index, rule in enumerate(_GRAPH_RULES)
]
_NODE_SHAPE = {
    'ram.source_word': ('state', 'memory'),
    'dma.read_data': ('logical', 'dma'),
    'dma.write_data': ('logical', 'dma'),
    'sha.ctrl_start_effect': ('state', 'sha'),
}
_LIVE_PROVENANCE = object()


class CompiledF6RuntimePathError(ValueError):
    """Stable refusal code and JSON pointer for a detached artifact."""

    def __init__(self, code: str, pointer: str = '/'):
        self.code = code
        self.pointer = pointer
        super().__init__(f'{code} at {pointer}')


def _fail(code: str, pointer: str = '/') -> None:
    raise CompiledF6RuntimePathError('compiled-f6-runtime-path-' + code, pointer)


def _closed(value: object, keys: set[str], code: str, pointer: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        _fail(code, pointer)
    return value


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and value.strip() == value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CompiledF6RuntimePathError(
            'compiled-f6-runtime-path-invalid-json', '/') from error


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_json(value: object, pointer: str = '/') -> None:
    """Reject Python-only containers and non-finite numbers before hashing."""
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail('invalid-json', pointer)
            token = key.replace('~', '~0').replace('/', '~1')
            _require_json(item, pointer.rstrip('/') + '/' + token)
    elif type(value) is list:
        for index, item in enumerate(value):
            _require_json(item, pointer.rstrip('/') + '/' + str(index))
    elif type(value) is float:
        if not math.isfinite(value):
            _fail('invalid-json', pointer)
    elif type(value) not in (str, int, bool, type(None)):
        _fail('invalid-json', pointer)


@dataclass(frozen=True)
class DmaTransferSourceWord:
    memory_component: str
    resource_id: str
    image_id: str
    address: int
    word_bytes: int
    byte_enable: int
    direction: str

    def __post_init__(self) -> None:
        for name, value in (('memory_component', self.memory_component),
                            ('resource_id', self.resource_id),
                            ('image_id', self.image_id)):
            if not _text(value):
                _fail('source-invalid', '/' + name)
        if (type(self.address) is not int or self.address < 0
                or self.address >= 1 << 64 or self.address % 4):
            _fail('source-invalid', '/address')
        if type(self.word_bytes) is not int or self.word_bytes != 4:
            _fail('source-invalid', '/word_bytes')
        if type(self.byte_enable) is not int or self.byte_enable != 15:
            _fail('source-invalid', '/byte_enable')
        if type(self.direction) is not str or self.direction != 'CPU_TO_IP':
            _fail('source-invalid', '/direction')

    @classmethod
    def from_document(cls, document: object) -> DmaTransferSourceWord:
        row = _closed(document, _SOURCE_KEYS, 'source-schema-invalid', '/')
        if row['schema_version'] != _SOURCE_SCHEMA:
            _fail('source-schema-invalid', '/schema_version')
        for name in ('memory_component', 'resource_id', 'image_id'):
            if not _text(row[name]):
                _fail('source-invalid', '/' + name)
        address = row['address']
        if (type(address) is not int or address < 0
                or address >= 1 << 64 or address % 4):
            _fail('source-invalid', '/address')
        for name, expected in (('word_bytes', 4), ('byte_enable', 15)):
            if type(row[name]) is not int or row[name] != expected:
                _fail('source-invalid', '/' + name)
        if row['direction'] != 'CPU_TO_IP':
            _fail('source-invalid', '/direction')
        return cls(*(row[name] for name in (
            'memory_component', 'resource_id', 'image_id', 'address',
            'word_bytes', 'byte_enable', 'direction')))

    def document(self) -> dict:
        return {
            'schema_version': _SOURCE_SCHEMA,
            'memory_component': self.memory_component,
            'resource_id': self.resource_id,
            'image_id': self.image_id,
            'address': self.address,
            'word_bytes': self.word_bytes,
            'byte_enable': self.byte_enable,
            'direction': self.direction,
        }


@dataclass(frozen=True)
class DmaTransferRoutePair:
    read_route_id: str
    write_route_id: str
    relation: str

    def __post_init__(self) -> None:
        for name, value in (('read_route_id', self.read_route_id),
                            ('write_route_id', self.write_route_id)):
            if not _text(value):
                _fail('pair-invalid', '/' + name)
        if self.write_route_id == self.read_route_id:
            _fail('pair-invalid', '/write_route_id')
        if type(self.relation) is not str or self.relation != 'same_word_value':
            _fail('pair-invalid', '/relation')

    @classmethod
    def from_document(cls, document: object) -> DmaTransferRoutePair:
        row = _closed(document, _PAIR_KEYS, 'pair-schema-invalid', '/')
        if row['schema_version'] != _PAIR_SCHEMA:
            _fail('pair-schema-invalid', '/schema_version')
        for name in ('read_route_id', 'write_route_id'):
            if not _text(row[name]):
                _fail('pair-invalid', '/' + name)
        if row['write_route_id'] == row['read_route_id']:
            _fail('pair-invalid', '/write_route_id')
        if row['relation'] != 'same_word_value':
            _fail('pair-invalid', '/relation')
        return cls(row['read_route_id'], row['write_route_id'], row['relation'])

    def document(self) -> dict:
        return {
            'schema_version': _PAIR_SCHEMA,
            'read_route_id': self.read_route_id,
            'write_route_id': self.write_route_id,
            'relation': self.relation,
        }


def _validate_route_pair(document: dict, source: DmaTransferSourceWord,
                         pair: DmaTransferRoutePair) -> None:
    declaration = document['declaration']
    intents = declaration['wiring']['dma_master_routes']['routes']
    if len(intents) != 2:
        _fail('route-mismatch', '/compiled_f6_handoff/declaration/wiring/dma_master_routes/routes')
    by_id = {intent['route_id']: intent for intent in intents}
    if set(by_id) != {pair.read_route_id, pair.write_route_id}:
        missing = ('read_route_id' if pair.read_route_id not in by_id
                   else 'write_route_id' if pair.write_route_id not in by_id
                   else None)
        _fail('route-mismatch', '/transfer_pair/' + missing if missing else
              '/compiled_f6_handoff/declaration/wiring/dma_master_routes/routes')
    read, write = by_id[pair.read_route_id], by_id[pair.write_route_id]
    read_target = read['target']
    write_target = write['target']
    if (read['operation'] != 'read' or read_target != {
            'kind': 'persistent_memory',
            'component_instance': source.memory_component,
            'resource_id': source.resource_id}):
        _fail('route-mismatch', '/transfer_pair/read_route_id')
    if not (read['base'] <= source.address
            and source.address + source.word_bytes <= read['base'] + read['size']):
        _fail('route-mismatch', '/source/address')
    if (write['operation'] != 'write' or write_target != {
            'kind': 'peripheral', 'component_instance': 'sha',
            'device_id': 'sha', 'endpoint_id': 'sha256.bus'}
            or write['byte_enable'] != 15
            or write['writable_offsets'] != [16]
            or write['accepted_write_values'] != {'kind': 'values', 'values': [5]}):
        _fail('route-mismatch', '/transfer_pair/write_route_id')
    if (read['byte_enable'] != 15
            or (read['initiator_instance'], read['initiator_endpoint_id'])
                != (write['initiator_instance'], write['initiator_endpoint_id'])):
        _fail('route-mismatch', '/transfer_pair')

    links = {row['route_id']: row for row in declaration['route_links']}
    for route_id, key, field_name in (
            (pair.read_route_id, (0, 0), 'read_route_id'),
            (pair.write_route_id, (2, 0), 'write_route_id')):
        row = links.get(route_id)
        if row is None or (row['rule_index'], row['prerequisite_index']) != key:
            _fail('route-mismatch', '/transfer_pair/' + field_name)


def _validate_prepared(document: dict, source: DmaTransferSourceWord,
                       pair: DmaTransferRoutePair) -> None:
    prepared = document['declaration']['prepared_runtime_paths']
    graph = prepared['graph']
    expected_source = {
        'source_id': 'ram.source_word', 'component': source.memory_component,
        'port': source.image_id, 'bit_offset': 0, 'width': 32,
        'directions': [source.direction], 'kind': 'memory_image',
        'image_address': source.address,
    }
    if (graph['schema_version'] != 'dependency_edge_graph.v2'
            or graph['sources'] != [expected_source]
            or graph['rules'] != _GRAPH_RULES
            or graph['edges'] != _GRAPH_EDGES):
        _fail('graph-mismatch', '/compiled_f6_handoff/declaration/prepared_runtime_paths/graph')

    contract_document = prepared['contract']
    try:
        contract = RuntimePathContract.from_document(contract_document)
    except (TypeError, ValueError, AttributeError) as error:
        raise CompiledF6RuntimePathError(
            'compiled-f6-runtime-path-contract-mismatch',
            '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract') from error
    if contract.document() != contract_document:
        _fail('contract-mismatch',
              '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract')
    expected_nodes = [{
        'node_id': node_id,
        'component': (source.memory_component if component == 'memory'
                      else component),
        'kind': kind,
        'port': None,
        'bit_offset': 0,
        'width': None,
    } for node_id, (kind, component) in sorted(_NODE_SHAPE.items())]
    if (contract.graph_sha256 != _sha256(graph)
            or contract_document['nodes'] != expected_nodes):
        _fail('contract-mismatch',
              '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract/nodes')
    expected_contract_edges = [{
        'rule_index': rule_index,
        'prerequisite_index': 0,
        'relation': relation,
        'initiator_component': None,
        'device_id': None,
        'base': None,
        'size': None,
        'resource_component': None,
        'resource_id': None,
    } for rule_index, relation in (
        (0, 'dma_master_route'), (1, 'causal_order'),
        (2, 'dma_master_route'))]
    if contract_document['edges'] != expected_contract_edges:
        _fail('contract-mismatch',
              '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract/edges')

    declaration = document['declaration']
    try:
        intents = parse_dma_master_route_intents(
            declaration['wiring']['dma_master_routes'])
        intents_by_id = {intent.route_id: intent for intent in intents}
        links_by_id = {row['route_id']: row
                       for row in declaration['route_links']}
    except (KeyError, TypeError, ValueError) as error:
        raise CompiledF6RuntimePathError(
            'compiled-f6-runtime-path-contract-mismatch',
            '/compiled_f6_handoff/declaration/wiring/dma_master_routes') from error
    route_keys = {
        pair.read_route_id: (0, 0),
        pair.write_route_id: (2, 0),
    }
    routes_by_key = {(route.rule_index, route.prerequisite_index): route
                     for route in contract.dma_master_routes}
    if (len(contract.dma_master_routes) != 2
            or set(intents_by_id) != set(route_keys)
            or set(links_by_id) != set(route_keys)
            or set(routes_by_key) != set(route_keys.values())):
        _fail('contract-mismatch',
              '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract/dma_master_routes')

    expected_edges = {(0, 0): ('ram.source_word', 'dma.read_data'),
                       (2, 0): ('dma.write_data', 'sha.ctrl_start_effect')}
    for route_id, key in route_keys.items():
        intent = intents_by_id[route_id]
        route = routes_by_key[key]
        route_link = links_by_id[route_id]
        target = intent.target
        expected_route = (
            expected_edges[key][0], expected_edges[key][1],
            intent.initiator_instance,
            route_link['endpoint_link']['runtime_endpoint_id'],
            target['kind'], target['component_instance'],
            target.get('resource_id', target.get('device_id')),
            intent.base, intent.size, intent.operation, intent.permissions,
            intent.byte_enable, intent.readable_offsets,
            intent.writable_offsets, intent.accepted_write_values)
        actual_route = (
            route.source_node_id, route.target_node_id,
            route.initiator_component, route.endpoint_id,
            route.target_kind, route.target_component, route.target_id,
            route.base, route.size, route.operation, route.permissions,
            route.byte_enable, route.readable_offsets,
            route.writable_offsets, route.accepted_write_values)
        if actual_route != expected_route:
            _fail('contract-mismatch',
                  '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract/dma_master_routes')

    try:
        graph_object = DependencyGraph.from_edge_document(graph)
        path, = graph_object.edge_paths_to(
            'sha.ctrl_start_effect', direction=source.direction)
        path_id = graph_object.path_identity(path, direction=source.direction)
    except (TypeError, ValueError) as error:
        raise CompiledF6RuntimePathError(
            'compiled-f6-runtime-path-graph-mismatch',
            '/compiled_f6_handoff/declaration/prepared_runtime_paths/graph') from error
    expected_selection = {
            'direction': source.direction,
            'path_id': path_id,
            'target': 'sha.ctrl_start_effect',
            'source_ids': ['ram.source_word'],
            'edges': _GRAPH_EDGES,
    }
    if prepared['selections'] != [expected_selection]:
        _fail('graph-mismatch',
              '/compiled_f6_handoff/declaration/prepared_runtime_paths/selections')


@dataclass(frozen=True, init=False)
class CompiledF6RuntimePath:
    """Canonical detached artifact retaining its validated D3/D4 handoff."""

    _document_bytes: bytes
    source: DmaTransferSourceWord
    transfer_pair: DmaTransferRoutePair
    handoff: CompiledF6DmaHandoff = field(repr=False, compare=False)
    prepared_runtime_paths: PreparedRuntimePathContract | None = field(
        repr=False, compare=False)
    _provenance: object | None = field(repr=False, compare=False)

    @classmethod
    def _validated(cls, document: dict, source: DmaTransferSourceWord,
                   pair: DmaTransferRoutePair,
                   handoff: CompiledF6DmaHandoff) -> CompiledF6RuntimePath:
        result = object.__new__(cls)
        object.__setattr__(result, '_document_bytes', _canonical(document))
        object.__setattr__(result, 'source', source)
        object.__setattr__(result, 'transfer_pair', pair)
        object.__setattr__(result, 'handoff', handoff)
        object.__setattr__(result, 'prepared_runtime_paths', None)
        object.__setattr__(result, '_provenance', None)
        return result

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    @property
    def identity_sha256(self) -> str:
        return self.document()['identity_sha256']

    @classmethod
    def from_document(cls, document: object) -> CompiledF6RuntimePath:
        row = _closed(document, _PATH_KEYS, 'schema-invalid', '/')
        try:
            _require_json(row)
        except RecursionError as error:
            raise CompiledF6RuntimePathError(
                'compiled-f6-runtime-path-invalid-json', '/') from error
        if row['schema_version'] != _PATH_SCHEMA:
            _fail('schema-invalid', '/schema_version')
        body = {key: value for key, value in row.items()
                if key != 'identity_sha256'}
        if row['identity_sha256'] != _sha256(body):
            _fail('identity-mismatch', '/identity_sha256')
        try:
            source = DmaTransferSourceWord.from_document(row['source'])
        except CompiledF6RuntimePathError as error:
            raise CompiledF6RuntimePathError(
                error.code, '/source' + error.pointer) from error
        try:
            pair = DmaTransferRoutePair.from_document(row['transfer_pair'])
        except CompiledF6RuntimePathError as error:
            raise CompiledF6RuntimePathError(
                error.code, '/transfer_pair' + error.pointer) from error
        try:
            handoff = CompiledF6DmaHandoff.from_document(row['compiled_f6_handoff'])
        except (CompiledF6DmaHandoffError, TypeError, ValueError,
                AttributeError) as error:
            pointer = getattr(error, 'pointer', '/')
            raise CompiledF6RuntimePathError(
                'compiled-f6-runtime-path-handoff-invalid',
                '/compiled_f6_handoff' + pointer) from error
        handoff_document = handoff.document()
        _validate_route_pair(handoff_document, source, pair)
        _validate_prepared(handoff_document, source, pair)
        return cls._validated(row, source, pair, handoff)


def caliptra_route_declarations(runner, *, sha_base, sha_size, memory_component,
                        resource_id):
    sessions = getattr(runner, 'sessions', None)
    if type(sessions) is not dict:
        raise ValueError('runner sessions are required for Caliptra DMA routes')
    dma = sessions.get('dma')
    memory_session = sessions.get(memory_component)
    if dma is None or memory_session is None:
        raise ValueError('DMA and RAM owner sessions are required')
    service = getattr(dma, 'memory_service', None)
    memory = getattr(service, 'memory', None)
    if (not isinstance(service, MemoryService)
            or not isinstance(service.ledger, TransactionLedger)
            or not isinstance(memory, PersistentMemory)
            or getattr(memory_session, 'memory', None) is not memory):
        raise ValueError('Caliptra DMA RAM route requires the exact shared memory service')
    regions = [region for region in memory._regions
               if region.memory_id == resource_id]
    if len(regions) != 1:
        raise ValueError('Caliptra DMA source RAM region is missing or ambiguous')
    region = regions[0]
    if not region.readable:
        raise ValueError('Caliptra DMA source RAM region is not readable')
    ram_base, ram_size = region.base, region.size
    ram_identity = persistent_memory_route_identity_document(
        memory, memory_id=resource_id, base=ram_base, size=ram_size)

    windows = getattr(dma, 'master_targets', None)
    if (type(windows) is not tuple
            or any(type(window) is not MasterTargetWindow for window in windows)):
        raise ValueError('DMA master target windows must be an immutable typed tuple')
    matches = [window for window in windows
               if (window.base, window.size) == (sha_base, sha_size)]
    if len(matches) != 1:
        raise ValueError('Caliptra SHA256 DMA master window is missing or ambiguous')
    window = matches[0]
    target = sessions.get(window.component)
    if (window.component != 'sha' or target is None
            or window.endpoint is not target):
        raise ValueError('Caliptra AHB window endpoint is not the registered SHA session')
    runtime = getattr(getattr(target, 'artifact', None), 'runtime_document', None)
    trace = runtime.get('base_protocol_trace') if type(runtime) is dict else None
    from .dma_intent_topology_binding import _CALIPTRA_AHB_TRACE_WIDTHS
    if (type(runtime) is not dict
            or runtime.get('kind') != 'ahb_lite_register_observe'
            or type(trace) is not dict
            or trace.get('schema_version') != 'ip_protocol_trace.v1'
            or trace.get('protocol') != 'ahb-lite'
            or trace.get('endpoint_id') != 'sha256.bus'
            or trace.get('signals') != {
                role: 'trace_' + role for role in _CALIPTRA_AHB_TRACE_WIDTHS}
            or type(trace.get('signal_widths')) is not dict
            or any(type(width) is not int
                   for width in trace['signal_widths'].values())
            or trace['signal_widths'] != _CALIPTRA_AHB_TRACE_WIDTHS):
        raise ValueError('Caliptra AHB target protocol trace is not pinned')
    provider_identity = getattr(target,
        'dma_master_target_provider_identity_document', None)
    if not callable(provider_identity):
        raise ValueError('Caliptra AHB endpoint lacks its DMA target provider identity')
    if not callable(getattr(target, 'dma_master_target_access', None)):
        raise ValueError('Caliptra AHB endpoint lacks its keyed DMA target provider')
    expected_provider = {
        'schema_version': 'caliptra_sha256_dma_target_provider.v1',
        'api_schema_version': 'dma_master_target_access.v1',
        'implementation_profile': 'caliptra_sha256_ctrl_ahb_write_completion.v1',
        'artifact_digest': target._artifact_document['artifact_digest'],
        'endpoint_id': 'sha256.bus', 'operation': 'write',
        'register': 'CTRL', 'offset': 16,
        'value': 5, 'byte_enable': 15,
        'observation_contract_schema_version': 'ip_protocol_trace.v1',
    }
    if provider_identity() != expected_provider:
        raise ValueError('Caliptra AHB provider identity is unsupported')
    if (window.readable_offsets
            or window.writable_offsets != (16,)
            or window.accepted_write_values != (5,)
            or window.byte_enable != 15):
        raise ValueError('Caliptra DMA window must admit only full-word CTRL start')

    dma_identity = dma_route_endpoint_identity_document(dma)
    dma_sha = canonical_runtime_identity_sha256(dma_identity)
    ram_route = DmaMasterRouteContract(
        rule_index=0, prerequisite_index=0,
        source_node_id='ram.source_word', target_node_id='dma.read_data',
        initiator_component='dma', endpoint_id='read_master',
        endpoint_identity_sha256=dma_sha,
        target_kind='persistent_memory', target_component=memory_component,
        target_id=resource_id, base=ram_base, size=ram_size,
        operation='read',
        permissions=tuple(sorted((['read'] if region.readable else [])
                                 + (['write'] if region.writable else []))),
        byte_enable=15, readable_offsets=(), writable_offsets=(),
        accepted_write_values=(),
        target_identity_sha256=canonical_runtime_identity_sha256(ram_identity))
    target_identity = window.route_identity_document()
    sha_route = DmaMasterRouteContract(
        rule_index=2, prerequisite_index=0,
        source_node_id='dma.write_data', target_node_id='sha.ctrl_start_effect',
        initiator_component='dma', endpoint_id='write_master',
        endpoint_identity_sha256=dma_sha,
        target_kind='peripheral', target_component=window.component,
        target_id=window.component, base=sha_base, size=sha_size,
        operation='write', permissions=('write',),
        byte_enable=window.byte_enable,
        readable_offsets=window.readable_offsets,
        writable_offsets=window.writable_offsets,
        accepted_write_values=window.accepted_write_values,
        target_identity_sha256=canonical_runtime_identity_sha256(target_identity))
    return region, window, (ram_route, sha_route)


def build_caliptra_runtime_graph(runner, source: DmaTransferSourceWord, *,
                                 sha_base: int, sha_size: int):
    """Construct the one supported live graph and retain its prepared object."""
    region, window, routes = caliptra_route_declarations(
        runner, sha_base=sha_base, sha_size=sha_size,
        memory_component=source.memory_component, resource_id=source.resource_id)
    if not (region.base <= source.address
            and source.address + source.word_bytes <= region.base + region.size):
        _fail('source-outside-ram', '/source/address')
    graph = DependencyGraph(
        sources=(FuzzableSource('ram.source_word', source.memory_component,
            source.image_id, 0, 32, (source.direction,), kind='memory_image',
            image_address=source.address),),
        rules=tuple(DependencyRule(row['target'], tuple(row['prerequisites']),
                                   row['kind']) for row in _GRAPH_RULES))
    contract = RuntimePathContract(
        _sha256(graph.edge_document()),
        tuple(RuntimeNode(node_id,
            source.memory_component if component == 'memory' else component,
            kind) for node_id, (kind, component) in sorted(_NODE_SHAPE.items())),
        (RuntimeEdgeContract(0, 0, 'dma_master_route'),
         RuntimeEdgeContract(1, 0, 'causal_order'),
         RuntimeEdgeContract(2, 0, 'dma_master_route')),
        dma_master_routes=routes)
    paths = graph.edge_paths_to('sha.ctrl_start_effect',
                                direction=source.direction, max_depth=8,
                                max_paths=2)
    if len(paths) != 1 or paths[0].source_ids != ('ram.source_word',):
        _fail('graph-mismatch', '/prepared_runtime_paths')
    prepared = PreparedRuntimePathContract(graph, contract,
                                           ((source.direction, paths[0]),))
    return region, window, graph, contract, paths[0], prepared


def _checked_wiring(compiled_paths, wiring):
    if not isinstance(wiring, PathWiring) or not isinstance(compiled_paths, Mapping):
        _fail('wiring-mismatch', '/wiring')
    try:
        parsed = load_path_wiring(wiring.document)
        supplied_routes = sorted((route.document()
                                  for route in wiring.dma_master_routes),
                                 key=lambda row: row['route_id'])
        parsed_routes = sorted((route.document()
                                for route in parsed.dma_master_routes),
                               key=lambda row: row['route_id'])
        if (parsed != replace(wiring, dma_master_routes=parsed.dma_master_routes)
                or supplied_routes != parsed_routes):
            _fail('wiring-mismatch', '/wiring')
        validate_compiled_f6_static(dict(compiled_paths), parsed.document)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        if isinstance(error, CompiledF6RuntimePathError):
            raise
        if isinstance(error, CompiledF6DmaHandoffError):
            raise CompiledF6RuntimePathError(
                'compiled-f6-runtime-path-d3-invalid',
                '/compiled_paths' + error.pointer) from error
        raise CompiledF6RuntimePathError(
            'compiled-f6-runtime-path-wiring-mismatch', '/wiring') from error
    return parsed


def prepare_compiled_f6_runtime_path(compiled_paths, wiring, runner, *,
                                     source, transfer_pair, artifact_links):
    """Generate the post-live F6 path from explicit static route IDs."""
    if not isinstance(source, DmaTransferSourceWord):
        _fail('source-invalid', '/source')
    if not isinstance(transfer_pair, DmaTransferRoutePair):
        _fail('pair-invalid', '/transfer_pair')
    wiring = _checked_wiring(compiled_paths, wiring)
    intents = wiring.dma_master_routes
    by_id = {intent.route_id: intent for intent in intents}
    if (len(intents) != 2 or len(by_id) != 2
            or set(by_id) != {transfer_pair.read_route_id,
                              transfer_pair.write_route_id}):
        _fail('route-mismatch', '/transfer_pair')
    read = by_id[transfer_pair.read_route_id]
    write = by_id[transfer_pair.write_route_id]
    if (read.operation != 'read' or write.operation != 'write'
            or read.initiator_instance != 'dma'
            or write.initiator_instance != 'dma'
            or read.initiator_endpoint_id != write.initiator_endpoint_id
            or read.target != {'kind': 'persistent_memory',
                               'component_instance': source.memory_component,
                               'resource_id': source.resource_id}
            or write.target != {'kind': 'peripheral',
                                'component_instance': 'sha',
                                'device_id': 'sha', 'endpoint_id': 'sha256.bus'}
            or not read.base <= source.address
            or source.address + 4 > read.base + read.size):
        _fail('route-mismatch', '/transfer_pair')
    _, _, _, contract, _, prepared = build_caliptra_runtime_graph(
        runner, source, sha_base=write.base, sha_size=write.size)
    routes = dict(zip((transfer_pair.read_route_id,
                       transfer_pair.write_route_id),
                      contract.dma_master_routes))
    links = []
    for route_id, key in ((transfer_pair.read_route_id, (0, 0)),
                          (transfer_pair.write_route_id, (2, 0))):
        intent = by_id[route_id]
        route = routes[route_id]
        if route.key != key:
            _fail('route-mismatch', '/transfer_pair')
        try:
            link_document = artifact_links[intent.initiator_instance]
            physical, = link_document['links']
            endpoint = dict(
                mode=('exact_id' if intent.initiator_endpoint_id
                      == route.endpoint_id else 'explicit_alias'),
                static_endpoint_id=intent.initiator_endpoint_id,
                runtime_endpoint_id=route.endpoint_id,
                artifact_endpoint_id=physical['endpoint_id'],
                artifact_link_id=physical['link_id'],
                artifact_link_provider_id=link_document['provider_id'],
                operation=route.operation,
                template_binding=physical['template_binding'])
        except (KeyError, TypeError, ValueError) as error:
            raise CompiledF6RuntimePathError(
                'compiled-f6-runtime-path-artifact-link-invalid',
                '/artifact_links') from error
        links.append(dict(route_id=route_id, rule_index=key[0],
                          prerequisite_index=key[1],
                          runtime_route_sha256=route.identity_sha256,
                          endpoint_link=endpoint))
    declaration = prepare_dma_intent_binding(wiring, prepared,
                                             route_links=links)
    handoff = prepare_compiled_f6_dma_handoff(compiled_paths, declaration)
    document = dict(schema_version=_PATH_SCHEMA, source=source.document(),
                    transfer_pair=transfer_pair.document(),
                    compiled_f6_handoff=handoff.document())
    document['identity_sha256'] = _sha256(document)
    _validate_route_pair(handoff.document(), source, transfer_pair)
    _validate_prepared(handoff.document(), source, transfer_pair)
    path = CompiledF6RuntimePath._validated(document, source, transfer_pair,
                                           handoff)
    object.__setattr__(path, 'prepared_runtime_paths', prepared)
    object.__setattr__(path, '_provenance', (_LIVE_PROVENANCE, prepared))
    return path


@dataclass(frozen=True)
class BoundCompiledF6RuntimePath:
    path: CompiledF6RuntimePath
    bound_handoff: object

    @property
    def prepared_runtime_paths(self):
        return self.path.prepared_runtime_paths

    @property
    def handoff(self):
        return self.bound_handoff

    def validate_topology(self):
        self.path.handoff.validate()
        _validate_route_pair(self.path.handoff.document(), self.path.source,
                             self.path.transfer_pair)
        _validate_prepared(self.path.handoff.document(), self.path.source,
                           self.path.transfer_pair)
        return self.bound_handoff.validate_topology()

    def match_dma_master_route(self, *args, **kwargs):
        self.validate_topology()
        return self.bound_handoff.match_dma_master_route(*args, **kwargs)


def bind_compiled_f6_runtime_path(path, runner, *, artifact_links):
    if (not isinstance(path, CompiledF6RuntimePath)
            or type(path._provenance) is not tuple
            or len(path._provenance) != 2
            or path._provenance[0] is not _LIVE_PROVENANCE
            or path._provenance[1] is not path.prepared_runtime_paths
            or path.handoff._declaration._prepared_runtime_paths
                is not path.prepared_runtime_paths):
        _fail('detached', '/')
    bound = bind_compiled_f6_dma_handoff(path.handoff, runner,
                                         artifact_links=artifact_links)
    result = BoundCompiledF6RuntimePath(path, bound)
    result.validate_topology()
    return result

