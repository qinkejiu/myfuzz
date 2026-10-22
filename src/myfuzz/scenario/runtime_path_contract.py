"""Explicit static route declarations; successful compilation is no RTL proof.

Compilation inspects only selected paths and actual topology objects. Admission
checks compare frozen topology references and declarations, without compiling
graphs, scanning source files, querying tools, or issuing harness commands.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any

from .memory import PersistentMemory
from .dependency import DependencyGraph, DependencyPath, DependencyEdge


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def canonical_runtime_identity_sha256(value: object) -> str:
    """Hash an injectively serialized route identity document."""
    return _digest(value)


def _name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value.strip() == value


@dataclass(frozen=True)
class RuntimeNode:
    node_id: str
    component: str
    kind: str
    port: str | None = None
    bit_offset: int = 0
    width: int | None = None

    def __post_init__(self) -> None:
        if not _name(self.node_id) or not _name(self.component) or self.kind not in ('physical', 'logical', 'state') or type(self.bit_offset) is not int:
            raise ValueError('invalid runtime node identity or kind')
        if self.kind == 'physical':
            if (not _name(self.port) or type(self.bit_offset) is not int or self.bit_offset < 0
                    or type(self.width) is not int or not 1 <= self.width <= 65536):
                raise ValueError('physical runtime node requires an explicit valid bit range')
        elif self.port is not None or self.width is not None or self.bit_offset != 0:
            raise ValueError('logical/state node cannot declare a physical endpoint')


@dataclass(frozen=True)
class RuntimeEdgeContract:
    rule_index: int
    prerequisite_index: int
    relation: str
    initiator_component: str | None = None
    device_id: str | None = None
    base: int | None = None
    size: int | None = None
    resource_component: str | None = None
    resource_id: str | None = None

    def __post_init__(self) -> None:
        if (type(self.rule_index) is not int or self.rule_index < 0
                or type(self.prerequisite_index) is not int or self.prerequisite_index < 0
                or self.relation not in ('direct_binding', 'mmio_route', 'causal_order',
                                         'persistent_state', 'dma_master_route')):
            raise ValueError('invalid runtime edge identity or relation')
        route = (self.initiator_component, self.device_id, self.base, self.size)
        resource = (self.resource_component, self.resource_id)
        if self.relation == 'mmio_route':
            if (not _name(self.initiator_component) or not _name(self.device_id)
                    or type(self.base) is not int or self.base < 0
                    or type(self.size) is not int or self.size < 4
                    or self.base + self.size > 1 << 64 or any(v is not None for v in resource)):
                raise ValueError('MMIO relation requires explicit aperture and endpoints')
        elif self.relation == 'persistent_state':
            if not all(_name(v) for v in resource) or any(v is not None for v in route):
                raise ValueError('persistent relation requires a declared memory resource')
        elif any(v is not None for v in (*route, *resource)):
            raise ValueError('unexpected endpoint/resource fields for runtime relation')

    @property
    def key(self) -> tuple[int, int]:
        return self.rule_index, self.prerequisite_index


def _accepted_values_document(values: tuple[int, ...] | range) -> dict:
    if isinstance(values, range):
        return {'kind': 'range', 'start': values.start,
                'stop': values.stop, 'step': values.step}
    return {'kind': 'tuple', 'values': list(values)}


def _accepted_values_from_document(document: object) -> tuple[int, ...] | range:
    if type(document) is not dict:
        raise ValueError('invalid DMA accepted write values')
    if document.get('kind') == 'tuple' and set(document) == {'kind', 'values'}:
        if type(document['values']) is not list:
            raise ValueError('invalid DMA accepted tuple values')
        return tuple(document['values'])
    if document.get('kind') == 'range' and set(document) == {'kind', 'start', 'stop', 'step'}:
        if any(type(document[key]) is not int for key in ('start', 'stop', 'step')):
            raise ValueError('invalid DMA accepted range values')
        return range(document['start'], document['stop'], document['step'])
    raise ValueError('invalid DMA accepted write values')


@dataclass(frozen=True)
class DmaMasterRouteContract:
    """One typed DMA-master dependency edge and its exact route declaration."""

    rule_index: int
    prerequisite_index: int
    source_node_id: str
    target_node_id: str
    initiator_component: str
    endpoint_id: str
    endpoint_identity_sha256: str
    target_kind: str
    target_component: str
    target_id: str
    base: int
    size: int
    operation: str
    permissions: tuple[str, ...]
    byte_enable: int
    readable_offsets: tuple[int, ...]
    writable_offsets: tuple[int, ...]
    accepted_write_values: tuple[int, ...] | range
    target_identity_sha256: str

    def __post_init__(self) -> None:
        if (type(self.rule_index) is not int or self.rule_index < 0
                or type(self.prerequisite_index) is not int or self.prerequisite_index < 0
                or not all(_name(value) for value in (self.source_node_id,
                    self.target_node_id, self.initiator_component, self.endpoint_id,
                    self.target_component, self.target_id))
                or type(self.endpoint_identity_sha256) is not str
                or not re.fullmatch('[0-9a-f]{64}', self.endpoint_identity_sha256)
                or type(self.target_identity_sha256) is not str
                or not re.fullmatch('[0-9a-f]{64}', self.target_identity_sha256)):
            raise ValueError('invalid DMA master route edge or endpoint identity')
        if (self.target_kind not in ('peripheral', 'persistent_memory')
                or self.operation not in ('read', 'write')
                or type(self.base) is not int or self.base < 0 or self.base % 4
                or type(self.size) is not int or self.size < 4 or self.size % 4
                or self.base + self.size > 1 << 64
                or type(self.permissions) is not tuple
                or any(value not in ('read', 'write') for value in self.permissions)
                or len(set(self.permissions)) != len(self.permissions)
                or tuple(sorted(self.permissions)) != self.permissions
                or self.operation not in self.permissions
                or type(self.byte_enable) is not int or self.byte_enable != 15):
            raise ValueError('invalid DMA master route target, aperture, or permission')
        for field_name, offsets in (('readable', self.readable_offsets),
                                    ('writable', self.writable_offsets)):
            if (type(offsets) is not tuple
                    or any(type(offset) is not int or offset < 0 or offset % 4
                           or offset + 4 > self.size for offset in offsets)
                    or len(set(offsets)) != len(offsets)):
                raise ValueError(f'invalid DMA route {field_name} offsets')
        if not isinstance(self.accepted_write_values, (tuple, range)):
            raise ValueError('DMA accepted values must preserve tuple or range type')
        if isinstance(self.accepted_write_values, range):
            values = self.accepted_write_values
            if values.step > 0 and values.start < values.stop:
                last = values.start + ((values.stop - 1 - values.start)
                    // values.step) * values.step
                bounds = (values.start, last)
            elif values.step < 0 and values.start > values.stop:
                step = -values.step
                last = values.start - ((values.start - 1 - values.stop)
                    // step) * step
                bounds = (values.start, last)
            else:
                bounds = ()
            out_of_range = bool(bounds) and not (
                0 <= min(bounds) and max(bounds) <= 0xffffffff)
        else:
            out_of_range = any(type(value) is not int or not 0 <= value <= 0xffffffff
                               for value in self.accepted_write_values)
        if out_of_range:
            raise ValueError('DMA accepted write value is outside 32 bits')
        if self.target_kind == 'peripheral':
            expected_permissions = tuple(sorted(
                (['read'] if self.readable_offsets else [])
                + (['write'] if self.writable_offsets else [])))
            if (self.target_component != self.target_id
                    or not expected_permissions
                    or self.permissions != expected_permissions
                    or bool(self.writable_offsets) != bool(self.accepted_write_values)):
                raise ValueError('peripheral DMA route target identity or permissions mismatch')
            if self.operation == 'read' and not self.readable_offsets:
                raise ValueError('peripheral DMA read route has no readable offset')
            if self.operation == 'write' and not self.writable_offsets:
                raise ValueError('peripheral DMA write route has no writable offset')
        elif (not self.target_id or self.readable_offsets or self.writable_offsets
                or self.accepted_write_values != () or type(self.accepted_write_values) is not tuple):
            raise ValueError('persistent-memory DMA route has peripheral-only fields')

    @property
    def key(self) -> tuple[int, int]:
        return self.rule_index, self.prerequisite_index

    def _identity_document(self) -> dict:
        return {'rule_index': self.rule_index,
            'prerequisite_index': self.prerequisite_index,
            'source_node_id': self.source_node_id,
            'target_node_id': self.target_node_id,
            'initiator_component': self.initiator_component,
            'endpoint_id': self.endpoint_id,
            'endpoint_identity_sha256': self.endpoint_identity_sha256,
            'target_kind': self.target_kind,
            'target_component': self.target_component,
            'target_id': self.target_id,
            'base': self.base, 'size': self.size,
            'operation': self.operation,
            'permissions': list(self.permissions),
            'byte_enable': self.byte_enable,
            'readable_offsets': list(self.readable_offsets),
            'writable_offsets': list(self.writable_offsets),
            'accepted_write_values': _accepted_values_document(self.accepted_write_values),
            'target_identity_sha256': self.target_identity_sha256}

    @property
    def identity_sha256(self) -> str:
        return _digest(self._identity_document())

    def document(self) -> dict:
        return {**self._identity_document(), 'identity_sha256': self.identity_sha256}

    @classmethod
    def from_document(cls, document: dict) -> DmaMasterRouteContract:
        expected = {'rule_index', 'prerequisite_index', 'source_node_id',
            'target_node_id', 'initiator_component', 'endpoint_id',
            'endpoint_identity_sha256', 'target_kind', 'target_component',
            'target_id', 'base', 'size', 'operation', 'permissions',
            'byte_enable', 'readable_offsets', 'writable_offsets',
            'accepted_write_values', 'target_identity_sha256', 'identity_sha256'}
        if type(document) is not dict or set(document) != expected:
            raise ValueError('invalid DMA master route schema')
        try:
            values = _accepted_values_from_document(document['accepted_write_values'])
            route = cls(rule_index=document['rule_index'],
                prerequisite_index=document['prerequisite_index'],
                source_node_id=document['source_node_id'],
                target_node_id=document['target_node_id'],
                initiator_component=document['initiator_component'],
                endpoint_id=document['endpoint_id'],
                endpoint_identity_sha256=document['endpoint_identity_sha256'],
                target_kind=document['target_kind'],
                target_component=document['target_component'],
                target_id=document['target_id'], base=document['base'],
                size=document['size'], operation=document['operation'],
                permissions=tuple(document['permissions']),
                byte_enable=document['byte_enable'],
                readable_offsets=tuple(document['readable_offsets']),
                writable_offsets=tuple(document['writable_offsets']),
                accepted_write_values=values,
                target_identity_sha256=document['target_identity_sha256'])
            if (_canonical(route.document()) != _canonical(document)
                    or document['identity_sha256'] != route.identity_sha256):
                raise ValueError('DMA master route identity is not canonical')
            return route
        except (KeyError, TypeError) as error:
            raise ValueError('invalid DMA master route document') from error


def persistent_memory_route_identity_document(memory: PersistentMemory, *,
        memory_id: str, base: int, size: int) -> dict:
    """Static exact resource identity; excludes mutable byte and commit state."""
    if (not isinstance(memory, PersistentMemory) or type(memory_id) is not str
            or type(base) is not int or type(size) is not int):
        raise ValueError('invalid persistent-memory route target')
    matches = [region for region in memory._regions
        if region.memory_id == memory_id and region.size == size
        and base in (region.base, *region.aliases)]
    if len(matches) != 1:
        raise ValueError('persistent-memory route resource/aperture is ambiguous or missing')
    region = matches[0]
    return {'schema_version': 'persistent_memory_route_target.v1',
        'memory_configuration': {
            'regions': [asdict(value) for value in memory._regions],
            'initialization_seed': memory.initialization_seed,
            'initialization_algorithm': 'memory-init-v1',
            'max_initialized_bytes': memory.max_initialized_bytes},
        'resource': {'memory_id': memory_id, 'base': base, 'size': size,
            'canonical_base': region.base, 'is_alias': base != region.base,
            'readable': region.readable, 'writable': region.writable,
            'region': asdict(region)}}


@dataclass(frozen=True)
class RuntimePathContract:
    graph_sha256: str
    nodes: tuple[RuntimeNode, ...]
    edges: tuple[RuntimeEdgeContract, ...]
    dma_master_routes: tuple[DmaMasterRouteContract, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.graph_sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.graph_sha256):
            raise ValueError('runtime contract requires canonical graph digest')
        if (not isinstance(self.nodes, tuple) or not isinstance(self.edges, tuple)
                or any(not isinstance(v, RuntimeNode) for v in self.nodes)
                or any(not isinstance(v, RuntimeEdgeContract) for v in self.edges)
                or not isinstance(self.dma_master_routes, tuple)
                or any(not isinstance(v, DmaMasterRouteContract)
                       for v in self.dma_master_routes)):
            raise ValueError('runtime declarations must be immutable typed tuples')
        if (len({v.node_id for v in self.nodes}) != len(self.nodes)
                or len({v.key for v in self.edges}) != len(self.edges)
                or len({v.key for v in self.dma_master_routes}) != len(self.dma_master_routes)):
            raise ValueError('duplicate runtime node or edge declaration')
        object.__setattr__(self, 'nodes', tuple(sorted(self.nodes, key=lambda v: v.node_id)))
        object.__setattr__(self, 'edges', tuple(sorted(self.edges, key=lambda v: v.key)))
        object.__setattr__(self, 'dma_master_routes', tuple(sorted(
            self.dma_master_routes, key=lambda v: v.key)))

    def document(self) -> dict:
        document = {'schema_version': ('runtime_path_contract.v2' if self.dma_master_routes
                                       else 'runtime_path_contract.v1'),
                'graph_sha256': self.graph_sha256,
                'nodes': [asdict(v) for v in sorted(self.nodes, key=lambda v: v.node_id)],
                'edges': [asdict(v) for v in sorted(self.edges, key=lambda v: v.key)]}
        if self.dma_master_routes:
            document['dma_master_routes'] = [v.document()
                for v in self.dma_master_routes]
        return document

    @property
    def identity_sha256(self) -> str:
        return _digest(self.document())

    @classmethod
    def from_document(cls, document: dict) -> RuntimePathContract:
        try:
            if type(document) is not dict:
                raise ValueError('invalid runtime path contract schema')
            schema = document.get('schema_version')
            expected = ({'schema_version', 'graph_sha256', 'nodes', 'edges'}
                if schema == 'runtime_path_contract.v1' else
                {'schema_version', 'graph_sha256', 'nodes', 'edges', 'dma_master_routes'}
                if schema == 'runtime_path_contract.v2' else None)
            if (expected is None or set(document) != expected
                    or not isinstance(document['nodes'], list) or not isinstance(document['edges'], list)):
                raise ValueError('invalid runtime path contract schema')
            nodes = tuple(RuntimeNode(**v) for v in document['nodes'])
            edges = tuple(RuntimeEdgeContract(**v) for v in document['edges'])
            routes = ()
            if schema == 'runtime_path_contract.v2':
                if (type(document['dma_master_routes']) is not list
                        or not document['dma_master_routes']):
                    raise ValueError('v2 runtime contract requires DMA master routes')
                routes = tuple(DmaMasterRouteContract.from_document(v)
                               for v in document['dma_master_routes'])
            contract = cls(document['graph_sha256'], nodes, edges, routes)
            if _canonical(contract.document()) != _canonical(document):
                raise ValueError('runtime path contract document is not canonical')
            return contract
        except (KeyError, TypeError) as error:
            raise ValueError('invalid runtime path contract document') from error


_RELATIONS = {'DATA_BINDING': {'direct_binding', 'mmio_route'},
              'EVENT_ORDER': {'direct_binding', 'mmio_route', 'causal_order'},
              'PERSISTENT_STATE_RULE': {'mmio_route', 'persistent_state'},
              'DMA_MASTER_TRANSFER': {'dma_master_route'}}


@dataclass(frozen=True)
class _DmaMasterRouteSnapshot:
    route: DmaMasterRouteContract
    initiator_session: Any = field(repr=False, compare=False)
    endpoint_identity_json: bytes = field(repr=False, compare=False)
    target_identity_json: bytes = field(repr=False, compare=False)
    target_session: Any = field(repr=False, compare=False)
    master_targets: tuple | None = field(repr=False, compare=False)
    window: Any = field(default=None, repr=False, compare=False)
    target_endpoint: Any = field(default=None, repr=False, compare=False)
    memory_service: Any = field(default=None, repr=False, compare=False)
    memory: PersistentMemory | None = field(default=None, repr=False, compare=False)
    ledger: Any = field(default=None, repr=False, compare=False)
    regions: tuple | None = field(default=None, repr=False, compare=False)
    memory_windows_list: Any = field(default=None, repr=False, compare=False)
    memory_windows: tuple | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class CompiledRuntimePathContract:
    """Frozen proof descriptors; topology checks cost the declared topology size."""
    _document_bytes: bytes
    _runner: Any = field(repr=False, compare=False)
    _sessions: tuple = field(repr=False, compare=False)
    _bindings: tuple = field(repr=False, compare=False)
    _ownership: Any = field(repr=False, compare=False)
    _input_bits: tuple = field(repr=False, compare=False)
    _routers: tuple = field(repr=False, compare=False)
    _resources: tuple = field(repr=False, compare=False)
    _dma_routes: tuple[_DmaMasterRouteSnapshot, ...] = field(default=(), repr=False, compare=False)

    _topology_guard: Any = field(default=None, repr=False, compare=False)

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(self._document_bytes).hexdigest()

    @property
    def topology_sha256(self) -> str:
        return self.document()['topology_sha256']

    @property
    def path_ids(self) -> tuple[str, ...]:
        return tuple(v['path_id'] for v in self.document()['paths'])

    @property
    def dma_master_routes(self) -> tuple[DmaMasterRouteContract, ...]:
        return tuple(value.route for value in self._dma_routes)

    def validate_topology(self) -> None:
        if self._topology_guard is not None:
            self._topology_guard()
        runner = self._runner
        if runner.ownership is not self._ownership or runner.bindings is not self._bindings:
            raise ValueError('runtime path topology ownership/Binding changed')
        if any(runner.sessions.get(name) is not session for name, session in self._sessions):
            raise ValueError('runtime path topology session changed')
        if any(runner.ownership._bits.get(key) != bits for key, bits in self._input_bits):
            raise ValueError('runtime path topology input ownership changed')
        for name, router, windows in self._routers:
            if getattr(runner.sessions[name], 'router', None) is not router or router.windows is not windows:
                raise ValueError('runtime path topology Router/window changed')
        for name, memory, regions, windows in self._resources:
            if (getattr(runner.sessions[name], 'memory', None) is not memory
                    or memory._regions != regions or tuple(memory._windows) != windows):
                raise ValueError('runtime path topology memory resource changed')
        for snapshot in self._dma_routes:
            route = snapshot.route
            if (runner.sessions.get(route.initiator_component) is not snapshot.initiator_session
                    or runner.sessions.get(route.target_component) is not snapshot.target_session):
                raise ValueError('DMA route topology endpoint session changed')
            from myfuzz.local_harness.wishbone_dma_session import (
                dma_route_endpoint_identity_document)
            endpoint_identity = dma_route_endpoint_identity_document(
                snapshot.initiator_session)
            if (_canonical(endpoint_identity) != snapshot.endpoint_identity_json
                    or _digest(endpoint_identity) != route.endpoint_identity_sha256):
                raise ValueError('DMA route topology endpoint identity changed')
            if route.target_kind == 'peripheral':
                windows = getattr(snapshot.initiator_session, 'master_targets', None)
                if (windows is not snapshot.master_targets
                        or not isinstance(windows, tuple)
                        or sum(value is snapshot.window for value in windows) != 1
                        or any(value is not snapshot.window
                            and value.base < route.base + route.size
                            and route.base < value.base + value.size
                            for value in windows)
                        or snapshot.window.endpoint is not snapshot.target_endpoint
                        or runner.sessions.get(route.target_component) is not snapshot.target_endpoint):
                    raise ValueError('DMA route topology window/endpoint changed')
                target_identity = snapshot.window.route_identity_document()
                if (_canonical(target_identity) != snapshot.target_identity_json
                        or _digest(target_identity) != route.target_identity_sha256):
                    raise ValueError('DMA route topology window identity changed')
            else:
                windows = getattr(snapshot.initiator_session, 'master_targets', None)
                service = getattr(snapshot.initiator_session, 'memory_service', None)
                target_memory = getattr(snapshot.target_session, 'memory', None)
                if (windows is not snapshot.master_targets or type(windows) is not tuple
                        or service is not snapshot.memory_service
                        or service is None or service.memory is not snapshot.memory
                        or service.ledger is not snapshot.ledger
                        or target_memory is not snapshot.memory
                        or snapshot.memory._regions is not snapshot.regions
                        or snapshot.memory._windows is not snapshot.memory_windows_list
                        or tuple(snapshot.memory._windows) != snapshot.memory_windows):
                    raise ValueError('DMA route topology memory service/resource changed')
                if any(window.base < limit and base < window.base + window.size
                       for window in windows
                       for base, limit, _region in snapshot.memory_windows):
                    raise ValueError('DMA route topology master window shadows persistent memory')
                target_identity = persistent_memory_route_identity_document(
                    snapshot.memory, memory_id=route.target_id,
                    base=route.base, size=route.size)
                if (_canonical(target_identity) != snapshot.target_identity_json
                        or _digest(target_identity) != route.target_identity_sha256):
                    raise ValueError('DMA route topology memory identity changed')


def _runtime_selection(graph, contract: RuntimePathContract, paths: tuple, *,
                       graph_document=None, require_all_routes=True):
    """Compile immutable graph facts before inspecting any runner."""
    if not isinstance(contract, RuntimePathContract) or not isinstance(paths, tuple) or not paths:
        raise ValueError('runtime compilation requires contract and selected path tuples')
    if graph_document is None:
        graph_document = graph.edge_document()
    if _digest(graph_document) != contract.graph_sha256:
        raise ValueError('runtime contract graph digest mismatch')
    graph_edges = {(v['rule_index'], v['prerequisite_index']): v for v in graph_document['edges']}
    graph_nodes = set(graph.sources)
    for edge in graph_edges.values():
        graph_nodes.update((edge['prerequisite'], edge['target']))
    nodes = {v.node_id: v for v in contract.nodes}
    if set(nodes) - graph_nodes:
        raise ValueError('runtime contract declares unknown node')
    contracts = {v.key: v for v in contract.edges}
    for key, declaration in contracts.items():
        if key not in graph_edges:
            raise ValueError('runtime contract declares unknown edge')
        if declaration.relation not in _RELATIONS.get(graph_edges[key]['kind'], set()):
            raise ValueError(f'runtime edge {key} relation incompatible with rule kind')
    route_contracts = {v.key: v for v in contract.dma_master_routes}
    for key, route in route_contracts.items():
        edge = graph_edges.get(key)
        declaration = contracts.get(key)
        if (edge is None or declaration is None
                or edge['kind'] != 'DMA_MASTER_TRANSFER'
                or declaration.relation != 'dma_master_route'):
            raise ValueError(f'DMA route {key} does not reference a typed DMA master edge')
        if (route.source_node_id != edge['prerequisite']
                or route.target_node_id != edge['target']):
            raise ValueError(f'DMA route {key} node IDs differ from selected graph edge')
    selected_nodes, selected_edges, resolved_paths = set(), {}, []
    for selection in paths:
        if not isinstance(selection, tuple) or len(selection) != 2:
            raise ValueError('selected path must be a (direction, path) tuple')
        direction, path = selection
        path_id = graph.path_identity(path, direction=direction)
        resolved_paths.append({'direction': direction, 'path_id': path_id, 'target': path.target})
        selected_nodes.update((path.target, *path.source_ids))
        for edge in path.edges:
            selected_nodes.update((edge.prerequisite, edge.target))
            selected_edges[(edge.rule_index, edge.prerequisite_index)] = edge
        for source_id in path.source_ids:
            source = graph.sources[source_id]
            node = nodes.get(source_id)
            if node is None or node.component != source.component:
                raise ValueError('runtime source node component mismatch')
            if source.kind == 'source':
                if (node.kind, node.port, node.bit_offset, node.width) != ('physical', source.port, source.bit_offset, source.width):
                    raise ValueError('runtime source node endpoint/range mismatch')
            elif node.kind == 'physical':
                raise ValueError('memory/instruction source cannot masquerade as a physical endpoint')
    if selected_nodes - set(nodes):
        raise ValueError('selected path has missing runtime node declaration')
    selected_dma_edges = {key for key, edge in selected_edges.items()
                          if edge.kind == 'DMA_MASTER_TRANSFER'}
    if (selected_dma_edges - set(route_contracts)
            or (require_all_routes and selected_dma_edges != set(route_contracts))):
        raise ValueError('selected DMA master edges and route declarations differ')
    for key, route in route_contracts.items():
        if key not in selected_edges:
            if require_all_routes:
                raise ValueError(f'DMA route {key} is outside selected runtime paths')
            continue
        source_node = nodes[route.source_node_id]
        target_node = nodes[route.target_node_id]
        if route.operation == 'read':
            expected = (target_node.component, source_node.component)
        else:
            expected = (source_node.component, target_node.component)
        if (route.initiator_component, route.target_component) != expected:
            raise ValueError(f'DMA route {key} components disagree with data-flow edge orientation')
    selected_sources = tuple((direction, graph.sources[source_id])
                             for direction, path in paths for source_id in path.source_ids)
    for _direction, source in selected_sources:
        image_address = getattr(source, 'image_address', None)
        if image_address is None:
            continue
        if (source.kind != 'memory_image' or type(image_address) is not int
                or image_address < 0 or image_address % 4):
            raise ValueError('address-bound DMA image source must name an aligned word')
        source_routes = [route for route in route_contracts.values()
            if route.source_node_id == source.source_id
            and route.operation == 'read'
            and route.target_kind == 'persistent_memory']
        if len(source_routes) != 1:
            raise ValueError('address-bound DMA image source needs one RAM read route')
        route = source_routes[0]
        image_bytes = max(4, (source.bit_offset + source.width + 7) // 8)
        if (image_address < route.base
                or image_address + image_bytes > route.base + route.size):
            raise ValueError('DMA image source address is outside its declared RAM route')
    return nodes, contracts, frozenset(selected_nodes), selected_edges, tuple(resolved_paths), selected_sources


def _freeze_runtime_selection(selection):
    """Keep a prepared selection's reusable lookup tables read-only."""
    nodes, contracts, selected_nodes, selected_edges, resolved_paths, sources = selection
    return (MappingProxyType(dict(nodes)), MappingProxyType(dict(contracts)),
            selected_nodes, MappingProxyType(dict(selected_edges)),
            tuple(MappingProxyType(dict(row)) for row in resolved_paths), sources)


def compile_runtime_path_contract(graph, contract: RuntimePathContract, runner, *, paths: tuple,
                                  _selection=None, topology_guard=None) -> CompiledRuntimePathContract:
    """Inspect topology; prepared callers reuse already validated graph facts."""
    if _selection is None:
        _selection = _runtime_selection(graph, contract, paths)
    nodes, contracts, selected_nodes, selected_edges, resolved_paths, selected_sources = _selection
    for direction, source in selected_sources:
        if source.kind == "source":
            runner.ownership.mutation_source(source.component, source.port, source.bit_offset, source.width, direction=direction)
    components = {nodes[v].component for v in selected_nodes}
    if components - set(runner.sessions):
        raise ValueError('selected runtime node component is not registered')
    if not isinstance(runner.bindings, tuple):
        raise ValueError('runtime Bindings must be immutable tuple')
    routers, resources = {}, {}
    dma_route_rows = []
    dma_route_snapshots = []
    input_keys = {(nodes[v].component, nodes[v].port) for v in selected_nodes
                  if nodes[v].kind == 'physical' and (nodes[v].component, nodes[v].port) in runner.ownership._bits}
    for node_id in selected_nodes:
        node = nodes[node_id]
        if node.kind == 'physical' and (node.component, node.port) in input_keys:
            if node.bit_offset + node.width > len(runner.ownership._bits[(node.component, node.port)]):
                raise ValueError('runtime physical input range exceeds declared field')
    for key, edge in selected_edges.items():
        source, target = nodes[edge.prerequisite], nodes[edge.target]
        declaration = contracts.get(key)
        cross_component = source.component != target.component
        if edge.kind in ('ENV_PRECONDITION', 'BASELINE_GROUPING'):
            continue
        if declaration is None:
            if cross_component:
                raise ValueError(f'selected cross-component edge {key} lacks contract')
            continue
        relation = declaration.relation
        if relation == 'direct_binding':
            if source.kind != 'physical' or target.kind != 'physical' or source.width != target.width:
                raise ValueError(f'direct edge {key} requires physical endpoints with equal widths')
            matches = [b for b in runner.bindings if (b.source_component, b.source_port, b.target_component, b.target_port,
                       b.width, b.source_bit_offset, b.target_bit_offset) ==
                       (source.component, source.port, target.component, target.port, source.width, source.bit_offset, target.bit_offset)]
            if len(matches) != 1:
                raise ValueError(f'direct edge {key} Binding matches={len(matches)}')
            binding = matches[0]
            for other in runner.bindings:
                if other is binding:
                    continue
                if ((other.target_component, other.target_port) == (target.component, target.port)
                        and other.target_bit_offset < target.bit_offset + target.width
                        and target.bit_offset < other.target_bit_offset + other.width):
                    raise ValueError(f'direct edge {key} overlapping target drivers')
            if runner.ownership.binding_producer(target.component, target.port, target.bit_offset, target.width) != f'{source.component}.{source.port}':
                raise ValueError(f'direct edge {key} ownership producer mismatch')
        elif relation == 'mmio_route':
            initiator, device = declaration.initiator_component, declaration.device_id
            if initiator not in components or device not in components or {initiator, device} != {source.component, target.component}:
                raise ValueError(f'MMIO edge {key} route components differ from declared edge')
            router = getattr(runner.sessions[initiator], 'router', None)
            windows = getattr(router, 'windows', ())
            if router is None or not isinstance(windows, tuple):
                raise ValueError(f'MMIO edge {key} missing declared Router')
            matches = [w for w in windows if w.device_id == device]
            if len(matches) != 1:
                raise ValueError(f'MMIO edge {key} window matches={len(matches)}')
            window = matches[0]
            if window.target is not runner.sessions[device] or (window.base, window.size) != (declaration.base, declaration.size):
                raise ValueError(f'MMIO edge {key} window aperture/target mismatch')
            routers[initiator] = (router, windows)
        elif relation == 'persistent_state':
            component = declaration.resource_component
            if component not in (source.component, target.component):
                raise ValueError(f'persistent edge {key} resource outside edge')
            memory = getattr(runner.sessions[component], 'memory', None)
            if not isinstance(memory, PersistentMemory) or declaration.resource_id not in memory.memory_ids:
                raise ValueError(f'persistent edge {key} lacks real declared memory resource')
            declared_windows = tuple((base, base + region.size, region)
                                     for region in memory._regions for base in (region.base, *region.aliases))
            if tuple(memory._windows) != declared_windows:
                raise ValueError(f'persistent edge {key} resource address index differs from declaration')
            resources[component] = (memory, memory._regions, declared_windows)
        elif relation == 'dma_master_route':
            # The typed route is resolved below against both the live initiator
            # and the exact target resource/window.
            continue

    from myfuzz.local_harness.wishbone_dma_session import (
        MasterTargetWindow, dma_route_endpoint_identity_document)
    from .ledger import TransactionLedger
    from .memory_service import MemoryService
    configured_validators = {}
    for route in contract.dma_master_routes:
        initiator_session = runner.sessions[route.initiator_component]
        configure_validator = getattr(initiator_session,
            'configure_dma_route_validator', None)
        if not callable(configure_validator):
            raise ValueError('DMA route initiator lacks a pinned topology validator hook')
        endpoint_identity = dma_route_endpoint_identity_document(initiator_session)
        endpoint_identity_json = _canonical(endpoint_identity)
        if _digest(endpoint_identity) != route.endpoint_identity_sha256:
            raise ValueError('DMA route endpoint identity differs from declared profile')
        target_session = runner.sessions[route.target_component]
        target_identity = None
        window = None
        target_endpoint = None
        service = memory = ledger = regions = memory_windows_list = memory_windows = None
        master_targets = getattr(initiator_session, 'master_targets', None)
        if (type(master_targets) is not tuple
                or any(type(value) is not MasterTargetWindow
                       for value in master_targets)):
            raise ValueError('DMA route requires an immutable master target window tuple')
        master_service = getattr(initiator_session, 'memory_service', None)
        master_memory = getattr(master_service, 'memory', None)
        if isinstance(master_memory, PersistentMemory):
            if (type(master_memory._windows) is not list
                    or any(type(entry) is not tuple or len(entry) != 3
                           for entry in master_memory._windows)):
                raise ValueError('DMA master memory index is not a declared window list')
            if any(window.base < limit and base < window.base + window.size
                   for window in master_targets
                   for base, limit, _region in master_memory._windows):
                raise ValueError('DMA master target window overlaps persistent memory')
        if route.target_kind == 'peripheral':
            matches = [value for value in master_targets
                if type(value) is MasterTargetWindow
                and value.component == route.target_id
                and (value.base, value.size) == (route.base, route.size)]
            if len(matches) != 1:
                raise ValueError(f'DMA peripheral route window matches={len(matches)}')
            window = matches[0]
            target_endpoint = runner.sessions[route.target_component]
            overlapping_windows = [value for value in master_targets
                if value.base < route.base + route.size
                and route.base < value.base + value.size]
            if len(overlapping_windows) != 1 or overlapping_windows[0] is not window:
                raise ValueError('DMA peripheral route is shadowed by an overlapping master target window')
            if (route.target_component != route.target_id
                    or window.endpoint is not target_endpoint
                    or window.byte_enable != route.byte_enable
                    or window.readable_offsets != route.readable_offsets
                    or window.writable_offsets != route.writable_offsets
                    or _canonical(_accepted_values_document(
                        window.accepted_write_values))
                        != _canonical(_accepted_values_document(
                            route.accepted_write_values))):
                raise ValueError('DMA peripheral route window identity, endpoint, or permission mismatch')
            actual_permissions = tuple(sorted(
                (['read'] if window.readable_offsets else [])
                + (['write'] if window.writable_offsets else [])))
            if actual_permissions != route.permissions:
                raise ValueError('DMA peripheral route permissions differ from target window')
            target_identity = window.route_identity_document()
        else:
            target_memory = getattr(target_session, 'memory', None)
            service = getattr(initiator_session, 'memory_service', None)
            if (not isinstance(target_memory, PersistentMemory)
                    or not isinstance(service, MemoryService)
                    or service.memory is not target_memory
                    or not isinstance(service.ledger, TransactionLedger)):
                raise ValueError('DMA RAM route requires the exact shared memory service/resource')
            memory = target_memory
            ledger = service.ledger
            regions = memory._regions
            memory_windows_list = memory._windows
            memory_windows = tuple(memory._windows)
            declared_windows = tuple((base, base + region.size, region)
                for region in memory._regions for base in (region.base, *region.aliases))
            if memory_windows != declared_windows:
                raise ValueError('DMA RAM route memory address index differs from regions')
            resources[route.target_component] = (
                memory, memory._regions, declared_windows)
            resource_rows = [region for region in memory._regions
                if region.memory_id == route.target_id and region.size == route.size
                and route.base in (region.base, *region.aliases)]
            if len(resource_rows) != 1:
                raise ValueError('DMA RAM route resource/aperture is ambiguous or missing')
            region = resource_rows[0]
            permissions = tuple(sorted((['read'] if region.readable else [])
                                       + (['write'] if region.writable else [])))
            if permissions != route.permissions:
                raise ValueError('DMA RAM route permissions differ from selected memory region')
            target_identity = persistent_memory_route_identity_document(
                memory, memory_id=route.target_id,
                base=route.base, size=route.size)
            target_session = runner.sessions[route.target_component]
        if _digest(target_identity) != route.target_identity_sha256:
            raise ValueError('DMA route target identity differs from declared resource')
        if route.initiator_component not in components or route.target_component not in components:
            raise ValueError('DMA route components are outside selected runtime path')
        if route.initiator_component not in configured_validators:
            configured_validators[route.initiator_component] = configure_validator
        target_identity_json = _canonical(target_identity)
        route_document = route.document()
        dma_route_rows.append({'route': route_document,
            'route_sha256': route.identity_sha256,
            'endpoint': {'component': route.initiator_component,
                'endpoint_id': route.endpoint_id,
                'identity_sha256': route.endpoint_identity_sha256},
            'target': {'kind': route.target_kind,
                'component': route.target_component, 'id': route.target_id,
                'base': route.base, 'size': route.size,
                'permissions': list(route.permissions),
                'identity_sha256': route.target_identity_sha256,
                'identity': target_identity}})
        dma_route_snapshots.append(_DmaMasterRouteSnapshot(
            route=route, initiator_session=initiator_session,
            endpoint_identity_json=endpoint_identity_json,
            target_identity_json=target_identity_json,
            target_session=target_session, master_targets=master_targets,
            window=window, target_endpoint=target_endpoint,
            memory_service=service, memory=memory, ledger=ledger,
            regions=regions, memory_windows_list=memory_windows_list,
            memory_windows=memory_windows))
    selected_windows = {}
    for snapshot in dma_route_snapshots:
        if snapshot.route.target_kind == 'peripheral':
            windows = selected_windows.setdefault(
                snapshot.route.initiator_component, [])
            if all(value is not snapshot.window for value in windows):
                windows.append(snapshot.window)
    for component in configured_validators:
        actual = getattr(runner.sessions[component], 'master_targets', None)
        expected = selected_windows.get(component, [])
        if (type(actual) is not tuple or len(actual) != len(expected)
                or any(sum(value is target for value in actual) != 1
                       for target in expected)):
            raise ValueError(
                'DMA master target windows and selected peripheral routes differ')
    dma_route_rows.sort(key=lambda value: (value['route']['rule_index'],
                                           value['route']['prerequisite_index']))
    topology = {'components': sorted(components), 'bindings': [asdict(v) for v in runner.bindings],
                'ownership_inputs': [{'component': key[0], 'port': key[1], 'owners': [asdict(v) for v in runner.ownership._bits[key]]}
                                     for key in sorted(input_keys)],
                'routers': [{'initiator': name, 'windows': [{'device_id': w.device_id, 'base': w.base, 'size': w.size}
                                                          for w in windows]} for name, (_, windows) in sorted(routers.items())],
                'resources': [{'component': name, 'regions': [asdict(v) for v in regions]}
                              for name, (_, regions, _) in sorted(resources.items())]}
    if dma_route_rows:
        topology['dma_master_routes'] = dma_route_rows
    document = {'schema_version': ('runtime_path_compilation.v2' if dma_route_rows
                                   else 'runtime_path_compilation.v1'),
                'graph_sha256': contract.graph_sha256,
                'contract_sha256': contract.identity_sha256, 'topology_sha256': _digest(topology),
                'topology': topology, 'paths': resolved_paths,
                'proof_scope': 'selected_declared_topology_only', 'runtime_causality_verified': False,
                'resource_versions_verified': False}
    compiled = CompiledRuntimePathContract(_canonical(document), runner,
        tuple((name, runner.sessions[name]) for name in sorted(components)), runner.bindings,
        runner.ownership, tuple((key, runner.ownership._bits[key]) for key in sorted(input_keys)),
        tuple((name, router, windows) for name, (router, windows) in sorted(routers.items())),
        tuple((name, memory, regions, windows) for name, (memory, regions, windows) in sorted(resources.items())),
        tuple(dma_route_snapshots), topology_guard)
    if dma_route_rows:
        compiled.validate_topology()
        for component, callback in sorted(configured_validators.items()):
            callback(compiled.validate_topology)
    return compiled


class PreparedRuntimePathContract:
    """Validated graph/path selections reusable across fresh runner objects."""

    def __init__(self, graph, contract: RuntimePathContract, paths: tuple):
        if not isinstance(contract, RuntimePathContract) or not isinstance(paths, tuple) or not paths:
            raise ValueError("prepared runtime paths require a contract and selections")
        document = graph.edge_document()
        self.graph = _restore_runtime_graph(document)
        self.contract = contract
        self.runtime_paths = paths
        selection_cache = {}
        resolved_cache = {}
        rows = []
        for direction, path in paths:
            selection = _runtime_selection(self.graph, contract, ((direction, path),),
                graph_document=document, require_all_routes=False)
            path_id = selection[4][0]["path_id"]
            if path_id in selection_cache:
                raise ValueError("duplicate prepared runtime path")
            selection_cache[path_id] = _freeze_runtime_selection(selection)
            resolved_cache[path_id] = (direction, path)
            rows.append({"direction": direction, "path_id": path_id, "target": path.target,
                         "source_ids": list(path.source_ids),
                         "edges": [edge.document() for edge in path.edges]})
        self.path_ids = tuple(resolved_cache)
        selected_dma_edges = {key for selection in selection_cache.values()
            for key, edge in selection[3].items()
            if edge.kind == 'DMA_MASTER_TRANSFER'}
        if selected_dma_edges != {route.key for route in contract.dma_master_routes}:
            raise ValueError('prepared selections and DMA route declarations differ')
        self._selections = MappingProxyType(selection_cache)
        self._resolved = MappingProxyType(resolved_cache)
        self._document_bytes = _canonical({"schema_version": (
                "prepared_runtime_paths.v2" if contract.dma_master_routes
                else "prepared_runtime_paths.v1"),
            "graph": document, "contract": contract.document(), "selections": rows})
        self._sealed = True

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("prepared runtime paths are immutable")
        object.__setattr__(self, name, value)

    def source_nodes_for(self, path_id):
        try:
            return tuple(source for _, source in self._selections[path_id][5])
        except (KeyError, TypeError) as exc:
            raise ValueError("unknown prepared runtime path identity") from exc

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    def validate_cached_identity(self) -> None:
        """Check the reusable in-memory graph/path cache against its document.

        ``document()`` is backed by immutable bytes and selection lookup tables
        are read-only mapping proxies, but the graph object itself is mutable.
        Consumers that reuse this object instead of deserializing it must verify
        that the graph and caches still match those bytes before treating them
        as compiled facts.
        """
        if type(self) is not PreparedRuntimePathContract:
            raise ValueError('prepared runtime paths must use the registered type')
        document = self.document()
        if self._document_bytes != _canonical(document):
            raise ValueError('prepared runtime path bytes are not canonical')
        if type(self.contract) is not RuntimePathContract:
            raise ValueError('prepared runtime contract must use the registered type')
        if self.contract.document() != document.get('contract'):
            raise ValueError('prepared runtime contract cache differs from document')

        from .online_case_decoder import OnlineDependencyGraph, OnlineDependencySource
        from .dependency import DependencyRule, FuzzableSource
        if type(self.graph) is DependencyGraph:
            source_type = FuzzableSource
        elif type(self.graph) is OnlineDependencyGraph:
            source_type = OnlineDependencySource
        else:
            raise ValueError('prepared runtime graph must use a registered type')
        if (type(self.graph.sources) is not dict
                or any(type(source) is not source_type
                       for source in self.graph.sources.values())
                or type(self.graph._ordered_rules) is not tuple
                or any(type(rule) is not DependencyRule
                       for rule in self.graph._ordered_rules)):
            raise ValueError('prepared runtime graph cache contains unknown objects')
        graph_document = self.graph.edge_document()
        if graph_document != document.get('graph'):
            raise ValueError('prepared runtime graph cache differs from document')

        rows = document.get('selections')
        if type(rows) is not list or not rows:
            raise ValueError('prepared runtime selections must be a nonempty array')
        expected_selections = {}
        expected_resolved = {}
        expected_paths = []
        for row in rows:
            if (type(row) is not dict or set(row) != {
                    'direction', 'path_id', 'target', 'source_ids', 'edges'}
                    or type(row['source_ids']) is not list
                    or type(row['edges']) is not list):
                raise ValueError('invalid prepared runtime selection document')
            edges = []
            for edge in row['edges']:
                if type(edge) is not dict or set(edge) != {
                        'rule_index', 'prerequisite_index', 'prerequisite',
                        'target', 'kind'}:
                    raise ValueError('invalid prepared runtime edge document')
                edges.append(DependencyEdge(**edge))
            path = DependencyPath(row['target'], tuple(row['source_ids']),
                                  tuple(edges))
            direction = row['direction']
            selection = _runtime_selection(self.graph, self.contract,
                ((direction, path),), graph_document=document['graph'],
                require_all_routes=False)
            path_id = selection[4][0]['path_id']
            if path_id != row['path_id'] or path_id in expected_selections:
                raise ValueError('prepared runtime path identity differs from selection')
            expected_selections[path_id] = selection
            expected_resolved[path_id] = (direction, path)
            expected_paths.append((direction, path))

        if (type(self.path_ids) is not tuple
                or self.path_ids != tuple(expected_selections)
                or type(self.runtime_paths) is not tuple
                or self.runtime_paths != tuple(expected_paths)
                or type(self._resolved) is not MappingProxyType
                or self._resolved != expected_resolved
                or type(self._selections) is not MappingProxyType
                or set(self._selections) != set(expected_selections)):
            raise ValueError('prepared runtime path caches differ from document')
        for path_id, expected in expected_selections.items():
            cached = self._selections[path_id]
            if (type(cached) is not tuple or len(cached) != 6
                    or type(cached[0]) is not MappingProxyType
                    or any(type(value) is not RuntimeNode
                           for value in cached[0].values())
                    or type(cached[1]) is not MappingProxyType
                    or any(type(value) is not RuntimeEdgeContract
                           for value in cached[1].values())
                    or type(cached[2]) is not frozenset
                    or type(cached[3]) is not MappingProxyType
                    or any(type(value) is not DependencyEdge
                           for value in cached[3].values())
                    or type(cached[4]) is not tuple
                    or any(type(value) is not MappingProxyType
                           for value in cached[4])
                    or type(cached[5]) is not tuple
                    or any(type(item) is not tuple or len(item) != 2
                           or type(item[1]) is not source_type
                           for item in cached[5])
                    or cached != expected):
                raise ValueError('prepared runtime selection cache differs from document')

        selected_dma_edges = {key for selection in expected_selections.values()
            for key, edge in selection[3].items()
            if edge.kind == 'DMA_MASTER_TRANSFER'}
        if selected_dma_edges != {route.key
                                  for route in self.contract.dma_master_routes}:
            raise ValueError('prepared DMA route cache differs from contract')

    def resolve_path_id(self, path_id):
        try:
            return self._resolved[path_id]
        except (KeyError, TypeError) as exc:
            raise ValueError("unknown prepared runtime path identity") from exc

    def bind(self, runner, *, path_ids: tuple[str, ...] | None = None, topology_guard=None):
        selected_ids = self.path_ids if path_ids is None else path_ids
        if (not isinstance(selected_ids, tuple) or not selected_ids
                or any(type(value) is not str for value in selected_ids)
                or len(set(selected_ids)) != len(selected_ids)):
            raise ValueError("selected runtime path identities must be a nonempty unique tuple")
        selections = []
        for path_id in selected_ids:
            if path_id not in self._selections:
                raise ValueError("unknown prepared runtime path identity")
            selections.append(self._selections[path_id])
        selected_dma_edges = {key for value in selections for key, edge in value[3].items()
            if edge.kind == 'DMA_MASTER_TRANSFER'}
        if selected_dma_edges != {route.key for route in self.contract.dma_master_routes}:
            raise ValueError('selected prepared paths omit a DMA master route')
        nodes, contracts = selections[0][:2]
        selected_nodes = frozenset().union(*(value[2] for value in selections))
        selected_edges = {key: edge for value in selections for key, edge in value[3].items()}
        resolved_paths = tuple(dict(path) for value in selections for path in value[4])
        selected_sources = tuple(source for value in selections for source in value[5])
        selection = nodes, contracts, selected_nodes, selected_edges, resolved_paths, selected_sources
        return compile_runtime_path_contract(None, self.contract, runner, paths=(), _selection=selection, topology_guard=topology_guard)

    @classmethod
    def from_document(cls, document):
        if (type(document) is not dict or set(document) != {"schema_version", "graph", "contract", "selections"}
                or document["schema_version"] not in ("prepared_runtime_paths.v1",
                                                       "prepared_runtime_paths.v2")
                or type(document["selections"]) is not list):
            raise ValueError("invalid prepared runtime path document")
        try:
            graph = _restore_runtime_graph(document["graph"])
            contract = RuntimePathContract.from_document(document["contract"])
            if ((document['schema_version'] == 'prepared_runtime_paths.v1'
                    and contract.dma_master_routes)
                    or (document['schema_version'] == 'prepared_runtime_paths.v2'
                    and not contract.dma_master_routes)):
                raise ValueError('prepared runtime schema and route declaration differ')
            paths = []
            for row in document["selections"]:
                if type(row) is not dict or set(row) != {"direction", "path_id", "target", "source_ids", "edges"}:
                    raise ValueError("invalid prepared runtime selection")
                if type(row["source_ids"]) is not list or type(row["edges"]) is not list:
                    raise ValueError("invalid prepared runtime selection fields")
                path = DependencyPath(row["target"], tuple(row["source_ids"]),
                                      tuple(DependencyEdge(**edge) for edge in row["edges"]))
                paths.append((row["direction"], path))
            prepared = cls(graph, contract, tuple(paths))
            if _canonical(prepared.document()) != _canonical(document):
                raise ValueError("prepared runtime path identity mismatch")
            return prepared
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError("invalid prepared runtime path document") from exc


def _restore_runtime_graph(document):
    if any(source.get("kind") == "instruction" for source in document.get("sources", ())):
        from .online_case_decoder import OnlineDependencyGraph, OnlineDependencySource
        return OnlineDependencyGraph.from_edge_document(document, source_factory=OnlineDependencySource)
    return DependencyGraph.from_edge_document(document)
