"""Pure selected-F2 admission from the original typed D3 compile request.

The immutable document retains the unchanged D3 graph and separates its source
and path identifiers from the logical candidate identifiers. No live authority
is granted until the prepared contract and image binding bind to a Runner.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

from myfuzz.scenario.compiled_paths import compile_paths, compiled_document_sha256
from myfuzz.scenario.dependency import DependencyEdge, DependencyGraph, DependencyPath
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract, RuntimePathContract
from myfuzz.scenario.f2_read_contract import validate_f2_read_contract


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(document):
    return sha256(_canonical(document)).hexdigest()


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-F2-runtime-path-' + reason)


@dataclass(frozen=True)
class CompiledF2RuntimePathAdmission:
    prepared: PreparedRuntimePathContract
    instruction_binding: object
    logical_path_id: str
    runtime_path_id: str
    _document_bytes: bytes

    def document(self):
        return json.loads(self._document_bytes)

    @property
    def digest(self):
        return self.document()['binding_sha256']

    def validate_cached_identity(self):
        from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
        _require(type(self) is CompiledF2RuntimePathAdmission, 'unregistered-admission')
        _require(type(self.prepared) is PreparedRuntimePathContract, 'prepared-type')
        self.prepared.validate_cached_identity()
        document = self.document()
        _require(self._document_bytes == _canonical(document), 'noncanonical-cache')
        content = dict(document)
        digest = content.pop('binding_sha256')
        _require(_digest(content) == digest, 'digest-drift')
        _require(type(self.instruction_binding) is InstructionImageSourceBinding,
                 'source-binding-type')
        _require(self.instruction_binding.document() == document['source_binding'], 'source-cache-drift')
        _require(self.prepared.document() == document['prepared'], 'prepared-cache-drift')
        _require(document['path_mapping'] == {'logical_path_id': self.logical_path_id,
                 'runtime_path_id': self.runtime_path_id}, 'mapping-cache-drift')
        _require(self.prepared.path_ids == (self.runtime_path_id,), 'selected-cache-drift')
        _require(self.instruction_binding.path_id == self.runtime_path_id, 'source-path-drift')
        self.instruction_binding.validate_prepared(self.prepared)
        _require(document['graph_sha256'] == _digest(self.prepared.graph.edge_document()),
                 'graph-digest-drift')
        _require(document['contract_sha256'] == _digest(self.prepared.contract.document()),
                 'contract-digest-drift')
        direction, path = self.prepared.resolve_path_id(self.runtime_path_id)
        _require(document['runtime_path_identity'] == {
            'direction': direction, 'path_id': self.runtime_path_id,
            'source_ids': list(path.source_ids), 'edges': [edge.document() for edge in path.edges]},
            'path-cache-drift')


def admit_compiled_f2_runtime_path(*, request, compiled, path=None):
    """Recompile and authenticate one supported F2 row without native startup."""
    from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
    _require(type(compiled) is dict, 'document-required')
    expected = compile_paths(request)
    _require(_canonical(expected) == _canonical(compiled), 'compiled-document-mismatch')
    rows = [row for row in compiled['paths']
            if row['flow_id'] == 'F2' and row['status'] == 'executable']
    _require(len(rows) == 1, 'one-executable-F2-required')
    row = rows[0]
    _require(path is None or _canonical(path) == _canonical(row), 'selected-row-mismatch')
    read_contract = validate_f2_read_contract(row)
    _require(len(row['sources']) == 2 and
             sorted(source['kind'] for source in row['sources']) ==
             ['cpu_load_stream', 'instruction_image'], 'unmapped-source')
    image = next(source for source in row['sources'] if source['kind'] == 'instruction_image')
    stream = next(source for source in row['sources'] if source['kind'] == 'cpu_load_stream')
    graph = DependencyGraph.from_edge_document(compiled['runtime_dependency_graph'])
    contract = RuntimePathContract.from_document(compiled['runtime_path_contract'])
    _require(_canonical(graph.edge_document()) == _canonical(compiled['runtime_dependency_graph']),
             'graph-roundtrip')
    _require(_canonical(contract.document()) == _canonical(compiled['runtime_path_contract']),
             'contract-roundtrip')
    _require(contract.graph_sha256 == _digest(graph.edge_document()), 'graph-contract-digest')
    identity = row['runtime_path_identity']
    _require(type(identity) is dict and set(identity) == {'direction', 'path_id', 'source_ids', 'edges'},
             'identity-fields')
    _require(identity['direction'] == row['direction'] == 'CPU_TO_IP', 'direction')
    selected = DependencyPath(row['target']['node'], tuple(identity['source_ids']),
                              tuple(DependencyEdge(**edge) for edge in identity['edges']))
    runtime_id = graph.path_identity(selected, direction=row['direction'])
    _require(runtime_id == identity['path_id'], 'identity-mismatch')
    _require(len(selected.source_ids) == 1 and len(selected.edges) == 3, 'path-shape')
    leaf = graph.sources[selected.source_ids[0]]
    first, second, third = selected.edges
    _require(first.kind == 'PERSISTENT_STATE_RULE' and second.kind == 'DATA_BINDING'
             and first.prerequisite == leaf.source_id and first.target == second.prerequisite
             and second.target == third.prerequisite and third.target == selected.target
             and third.kind == 'DATA_BINDING', 'edge-shape')
    size = image['range'][1] - image['range'][0] + 1
    _require(leaf.kind == 'memory_image' and leaf.component == image['component'] == request.cpu.instance_id
             and leaf.port == image['port'] and leaf.bit_offset == image['bit_offset'] == 0
             and leaf.width == image['width'] == size * 8
             and leaf.directions == (row['direction'],)
             and (leaf.image_address is None or leaf.image_address == image['range'][0]), 'image-source-join')
    resources = [resource for resource in request.wiring.resources
                 if resource.component_instance == image['component'] and resource.resource_id == image['port']]
    _require(len(resources) == 1, 'resource-identity')
    resource = resources[0]
    _require(type(resource.base) is int and type(resource.size) is int and resource.size > 0
             and resource.base == image['range'][0] and resource.size == size
             and resource.read is True and resource.write is True and resource.execute is True
             and resource.initialization_policy == 'preload', 'resource-range-permissions')
    edges = {edge.key: edge for edge in contract.edges}
    persistent = edges[(first.rule_index, first.prerequisite_index)]
    route = edges[(second.rule_index, second.prerequisite_index)]
    return_route = edges[(third.rule_index, third.prerequisite_index)]
    access = stream['register_access']
    _require(persistent.relation == 'persistent_state'
             and (persistent.resource_component, persistent.resource_id) == (image['component'], image['port']),
             'resource-edge')
    _require(route.relation == 'mmio_route' and
             (route.initiator_component, route.device_id, route.base, route.size) ==
             (stream['component'], access['device_id'], access['window_base'], access['window_size']),
             'stream-route')
    _require(return_route.relation == 'mmio_route' and
             (return_route.initiator_component, return_route.device_id, return_route.base, return_route.size) ==
             (route.initiator_component, route.device_id, route.base, route.size), 'return-route')
    _require(row['prerequisites'] == [{'kind': 'ip_register_version',
        'basis': 'F2 requires the current live IP register version before reading',
        'subject': {'component': access['target_component'], 'register': access['register']}}],
        'version-prerequisite')
    prepared = PreparedRuntimePathContract(graph, contract, ((row['direction'], selected),))
    binding = InstructionImageSourceBinding(path_id=runtime_id, direction=row['direction'],
        source_id=leaf.source_id, logical_source_id=image['source_id'], component=image['component'],
        memory_id=image['port'], base=resource.base, size=resource.size,
        readable=resource.read, writable=resource.write)
    document = {'schema_version': 'compiled_F2_runtime_path_admission.v1',
        'compiled_document_sha256': compiled_document_sha256(compiled),
        'selected_path': row, 'selected_path_sha256': _digest(row),
        'graph_sha256': _digest(graph.edge_document()), 'contract_sha256': _digest(contract.document()),
        'prepared': prepared.document(), 'runtime_path_identity': identity,
        'path_mapping': {'logical_path_id': row['path_id'], 'runtime_path_id': runtime_id},
        'source_binding': binding.document(), 'instruction_image': image,
        'cpu_load_stream': stream, 'execution_contract': read_contract,
        'instruction_image_sha256': _digest(image), 'cpu_load_stream_sha256': _digest(stream)}
    document['binding_sha256'] = _digest(document)
    admission = CompiledF2RuntimePathAdmission(prepared, binding, row['path_id'], runtime_id,
                                             _canonical(document))
    admission.validate_cached_identity()
    return admission
