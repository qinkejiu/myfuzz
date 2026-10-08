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
from typing import Any

from .memory import PersistentMemory
from .dependency import DependencyGraph, DependencyPath, DependencyEdge


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


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
                or self.relation not in ('direct_binding', 'mmio_route', 'causal_order', 'persistent_state')):
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


@dataclass(frozen=True)
class RuntimePathContract:
    graph_sha256: str
    nodes: tuple[RuntimeNode, ...]
    edges: tuple[RuntimeEdgeContract, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.graph_sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.graph_sha256):
            raise ValueError('runtime contract requires canonical graph digest')
        if (not isinstance(self.nodes, tuple) or not isinstance(self.edges, tuple)
                or any(not isinstance(v, RuntimeNode) for v in self.nodes)
                or any(not isinstance(v, RuntimeEdgeContract) for v in self.edges)):
            raise ValueError('runtime declarations must be immutable typed tuples')
        if len({v.node_id for v in self.nodes}) != len(self.nodes) or len({v.key for v in self.edges}) != len(self.edges):
            raise ValueError('duplicate runtime node or edge declaration')
        object.__setattr__(self, 'nodes', tuple(sorted(self.nodes, key=lambda v: v.node_id)))
        object.__setattr__(self, 'edges', tuple(sorted(self.edges, key=lambda v: v.key)))

    def document(self) -> dict:
        return {'schema_version': 'runtime_path_contract.v1', 'graph_sha256': self.graph_sha256,
                'nodes': [asdict(v) for v in sorted(self.nodes, key=lambda v: v.node_id)],
                'edges': [asdict(v) for v in sorted(self.edges, key=lambda v: v.key)]}

    @property
    def identity_sha256(self) -> str:
        return _digest(self.document())

    @classmethod
    def from_document(cls, document: dict) -> RuntimePathContract:
        try:
            if not isinstance(document, dict) or set(document) != {'schema_version', 'graph_sha256', 'nodes', 'edges'} \
                    or document['schema_version'] != 'runtime_path_contract.v1' \
                    or not isinstance(document['nodes'], list) or not isinstance(document['edges'], list):
                raise ValueError('invalid runtime path contract schema')
            nodes = tuple(RuntimeNode(**v) for v in document['nodes'])
            edges = tuple(RuntimeEdgeContract(**v) for v in document['edges'])
            contract = cls(document['graph_sha256'], nodes, edges)
            if _canonical(contract.document()) != _canonical(document):
                raise ValueError('runtime path contract document is not canonical')
            return contract
        except (KeyError, TypeError) as error:
            raise ValueError('invalid runtime path contract document') from error


_RELATIONS = {'DATA_BINDING': {'direct_binding', 'mmio_route'},
              'EVENT_ORDER': {'direct_binding', 'mmio_route', 'causal_order'},
              'PERSISTENT_STATE_RULE': {'mmio_route', 'persistent_state'}}


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

    def validate_topology(self) -> None:
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


def _runtime_selection(graph, contract: RuntimePathContract, paths: tuple, *, graph_document=None):
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
    selected_sources = tuple((direction, graph.sources[source_id])
                             for direction, path in paths for source_id in path.source_ids)
    return nodes, contracts, frozenset(selected_nodes), selected_edges, tuple(resolved_paths), selected_sources


def compile_runtime_path_contract(graph, contract: RuntimePathContract, runner, *, paths: tuple,
                                  _selection=None) -> CompiledRuntimePathContract:
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
    topology = {'components': sorted(components), 'bindings': [asdict(v) for v in runner.bindings],
                'ownership_inputs': [{'component': key[0], 'port': key[1], 'owners': [asdict(v) for v in runner.ownership._bits[key]]}
                                     for key in sorted(input_keys)],
                'routers': [{'initiator': name, 'windows': [{'device_id': w.device_id, 'base': w.base, 'size': w.size}
                                                          for w in windows]} for name, (_, windows) in sorted(routers.items())],
                'resources': [{'component': name, 'regions': [asdict(v) for v in regions]}
                              for name, (_, regions, _) in sorted(resources.items())]}
    document = {'schema_version': 'runtime_path_compilation.v1', 'graph_sha256': contract.graph_sha256,
                'contract_sha256': contract.identity_sha256, 'topology_sha256': _digest(topology),
                'topology': topology, 'paths': resolved_paths,
                'proof_scope': 'selected_declared_topology_only', 'runtime_causality_verified': False,
                'resource_versions_verified': False}
    return CompiledRuntimePathContract(_canonical(document), runner,
        tuple((name, runner.sessions[name]) for name in sorted(components)), runner.bindings,
        runner.ownership, tuple((key, runner.ownership._bits[key]) for key in sorted(input_keys)),
        tuple((name, router, windows) for name, (router, windows) in sorted(routers.items())),
        tuple((name, memory, regions, windows) for name, (memory, regions, windows) in sorted(resources.items())))


class PreparedRuntimePathContract:
    """Validated graph/path selections reusable across fresh runner objects."""

    def __init__(self, graph, contract: RuntimePathContract, paths: tuple):
        if not isinstance(contract, RuntimePathContract) or not isinstance(paths, tuple) or not paths:
            raise ValueError("prepared runtime paths require a contract and selections")
        document = graph.edge_document()
        self.graph = _restore_runtime_graph(document)
        self.contract = contract
        self.runtime_paths = paths
        self._selections = {}
        self._resolved = {}
        rows = []
        for direction, path in paths:
            selection = _runtime_selection(self.graph, contract, ((direction, path),), graph_document=document)
            path_id = selection[4][0]["path_id"]
            if path_id in self._selections:
                raise ValueError("duplicate prepared runtime path")
            self._selections[path_id] = selection
            self._resolved[path_id] = (direction, path)
            rows.append({"direction": direction, "path_id": path_id, "target": path.target,
                         "source_ids": list(path.source_ids),
                         "edges": [edge.document() for edge in path.edges]})
        self.path_ids = tuple(self._resolved)
        self._document_bytes = _canonical({"schema_version": "prepared_runtime_paths.v1",
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

    def resolve_path_id(self, path_id):
        try:
            return self._resolved[path_id]
        except (KeyError, TypeError) as exc:
            raise ValueError("unknown prepared runtime path identity") from exc

    def bind(self, runner, *, path_ids: tuple[str, ...] | None = None):
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
        nodes, contracts = selections[0][:2]
        selected_nodes = frozenset().union(*(value[2] for value in selections))
        selected_edges = {key: edge for value in selections for key, edge in value[3].items()}
        resolved_paths = tuple(path for value in selections for path in value[4])
        selected_sources = tuple(source for value in selections for source in value[5])
        selection = nodes, contracts, selected_nodes, selected_edges, resolved_paths, selected_sources
        return compile_runtime_path_contract(None, self.contract, runner, paths=(), _selection=selection)

    @classmethod
    def from_document(cls, document):
        if (type(document) is not dict or set(document) != {"schema_version", "graph", "contract", "selections"}
                or document["schema_version"] != "prepared_runtime_paths.v1"
                or type(document["selections"]) is not list):
            raise ValueError("invalid prepared runtime path document")
        try:
            graph = _restore_runtime_graph(document["graph"])
            contract = RuntimePathContract.from_document(document["contract"])
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
