"""Pure selected-F4 admission from the original typed D3 compile request.

The immutable document retains the unchanged D3 graph and separates its source
and path identifiers from the logical candidate identifiers. No live authority
is granted until the prepared contract and image binding bind to a Runner.
"""
from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from myfuzz.scenario.compiled_paths import compile_paths, compiled_document_sha256
from myfuzz.scenario.dependency import DependencyEdge, DependencyGraph, DependencyPath
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract, RuntimePathContract
from myfuzz.scenario.target_bus_pins import (
    declaration_identity,
    tlul_declared_bus_pins,
)
from .compiled_candidate_layout import compile_candidate_layout


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(document):
    return sha256(_canonical(document)).hexdigest()


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-F4-runtime-path-' + reason)


@dataclass(frozen=True)
class CompiledF4RuntimePathAdmission:
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

    def external_pin_path(self, source_id):
        rows=[r for r in self.document().get('external_pin_paths',()) if r['source_id']==source_id]
        _require(len(rows)==1,'external-pin-path-unmapped')
        row=rows[0]
        if 'declaration' in row:
            # A target-owned bus input: the generated adapter drives it, so the
            # host only carries the declaration identity and records the value.
            _require(declaration_identity(row['declaration'])==row['path_id'],
                     'external-pin-declaration-drift')
            return row['direction'],row['path_id']
        direction,_=self.prepared.resolve_path_id(rows[0]['path_id'])
        return direction,rows[0]['path_id']

    def validate_cached_identity(self):
        from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
        _require(type(self) is CompiledF4RuntimePathAdmission, 'unregistered-admission')
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
        _require(self.prepared.path_ids == (self.runtime_path_id,)+tuple(
            r['path_id'] for r in document.get('external_pin_paths',())
            if 'declaration' not in r), 'selected-cache-drift')
        self._validate_external_pin_documents(document)
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

    def _validate_external_pin_documents(self, document):
        """Every declared pin row must re-derive from the selected path row."""
        selected = document['selected_path']
        rows = document.get('external_pin_paths', [])
        _require(type(rows) in (list, tuple), 'external-pin-document')
        sources = {source['source_id']: source for source in selected['sources']
                   if source['kind'] == 'external_pin'}
        delivery = document.get('external_pin_delivery')
        _require(delivery in (None, 'shared_f5'), 'external-pin-document')
        if delivery == 'shared_f5':
            # The one shared F5 pin is delivered by the shared binding, not by a
            # per-pin path, so this admission declares no pin row of its own.
            _require(not rows and bool(sources), 'external-pin-document')
            return
        seen = set()
        for row in rows:
            _require(type(row) is dict
                     and set(row) in ({'source_id', 'path_id'},
                                      {'source_id', 'direction', 'path_id'},
                                      {'source_id', 'direction', 'declaration', 'path_id'}),
                     'external-pin-document')
            _require(row['source_id'] in sources and row['source_id'] not in seen,
                     'external-pin-document')
            seen.add(row['source_id'])
            if 'declaration' not in row:
                direction, _ = self.prepared.resolve_path_id(row['path_id'])
                _require(row.get('direction', direction) == selected['direction'],
                         'external-pin-document')
                continue
            pin = row['declaration']
            identity = declaration_identity(pin)
            source = sources[row['source_id']]
            _require(identity == row['path_id']
                     and row['direction'] == selected['direction']
                     and (pin['component'], pin['endpoint_id'], pin['port'],
                          pin['bit_offset'], pin['width']) ==
                         (source['component'], source['endpoint_id'], source['port'],
                          source['bit_offset'], source['width']),
                     'external-pin-declaration-drift')
        _require(seen == set(sources), 'external-pin-document')


def admit_compiled_f4_runtime_path(*, request, compiled, path=None):
    """Recompile and authenticate one supported F4 row without native startup."""
    from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
    _require(type(compiled) is dict, 'document-required')
    expected = compile_paths(request)
    _require(_canonical(expected) == _canonical(compiled), 'compiled-document-mismatch')
    rows = [row for row in compiled['paths']
            if row['flow_id'] == 'F4' and row['status'] == 'executable']
    _require(len(rows) == 1, 'one-executable-F4-required')
    row = rows[0]
    _require(path is None or _canonical(path) == _canonical(row), 'selected-row-mismatch')
    layout = compile_candidate_layout(row)
    primary = [source for source in row['sources'] if source['kind'] != 'external_pin']
    _require(len(primary) == 2 and
             sorted(source['kind'] for source in primary) ==
             ['cpu_mmio_stream', 'instruction_image'], 'unmapped-source')
    external = [source for source in row['sources'] if source['kind'] == 'external_pin']
    if external:
        shared = [source for path in compiled['paths'] if path['flow_id']=='F5'
                  and path['status']=='executable' for source in path['sources']
                  if source['kind']=='external_pin']
        keys = ('source_id','component','endpoint_id','port','bit_offset','width','mask')
        shared_pin=(len(external)==len(shared)==1 and all(external[0][key]==shared[0][key] for key in keys))
    else:
        shared_pin=False
    image = next(source for source in row['sources'] if source['kind'] == 'instruction_image')
    stream = next(source for source in row['sources'] if source['kind'] == 'cpu_mmio_stream')
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
    _require(len(selected.source_ids) == 1 and len(selected.edges) == 2, 'path-shape')
    leaf = graph.sources[selected.source_ids[0]]
    first, second = selected.edges
    _require(first.kind == 'PERSISTENT_STATE_RULE' and second.kind == 'DATA_BINDING'
             and first.prerequisite == leaf.source_id and first.target == second.prerequisite
             and second.target == selected.target, 'edge-shape')
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
    access = stream['register_access']
    _require(persistent.relation == 'persistent_state'
             and (persistent.resource_component, persistent.resource_id) == (image['component'], image['port']),
             'resource-edge')
    _require(route.relation == 'mmio_route' and
             (route.initiator_component, route.device_id, route.base, route.size) ==
             (stream['component'], access['device_id'], access['window_base'], access['window_size']),
             'stream-route')
    pin_paths=[];pin_documents=[]
    if external and not shared_pin:
        target = row['target']['component']
        endpoint = access['target_endpoint']
        # Pins declared on the target's own MMIO endpoint are the target IP's
        # bus inputs: the generated adapter drives them, so the host never
        # writes them.  They become declaration rows instead of graph paths.
        bus_pins=[source for source in external
                  if source.get('component')==target and source.get('endpoint_id')==endpoint]
        host_pins=[source for source in external if source not in bus_pins]
        if bus_pins:
            endpoint_rows=[entry for entry in row['endpoints']
                           if entry.get('instance_id')==target
                           and entry.get('endpoint_id')==endpoint]
            _require(len(endpoint_rows)==1
                     and tuple(endpoint_rows[0].get('protocol') or ())==('tl-ul','1')
                     and endpoint_rows[0].get('function')=='mmio_slave',
                     'unmapped-source')
            try:
                declared=tlul_declared_bus_pins(bus_pins,direction=row['direction'],
                    target_component=target,target_endpoint=endpoint)
            except ValueError:
                raise ValueError('compiled-F4-runtime-path-unmapped-source') from None
            for pin in declared:
                pin_documents.append(dict(source_id=pin['source']['source_id'],
                    direction=row['direction'],declaration=pin['declaration'],
                    path_id=pin['declaration']['identity']))
        for source in host_pins:
            name=source['source_id'];pin_leaf=graph.sources.get(name)
            _require(pin_leaf is not None and pin_leaf.kind=='source' and pin_leaf.directions==(row['direction'],)
                and all(getattr(pin_leaf,key)==source[key] for key in ('component','port','bit_offset','width')),
                'unmapped-source')
            pin_path=DependencyPath(name,(name,),())
            pin_id=graph.path_identity(pin_path,direction=row['direction'])
            pin_paths.append((row['direction'],pin_path))
            pin_documents.append(dict(source_id=name,direction=row['direction'],path_id=pin_id))
    prepared = PreparedRuntimePathContract(graph, contract, ((row['direction'], selected),)+tuple(pin_paths))
    binding = InstructionImageSourceBinding(path_id=runtime_id, direction=row['direction'],
        source_id=leaf.source_id, logical_source_id=image['source_id'], component=image['component'],
        memory_id=image['port'], base=resource.base, size=resource.size,
        readable=resource.read, writable=resource.write)
    document = {'schema_version': 'compiled_F4_runtime_path_admission.v1',
        'compiled_document_sha256': compiled_document_sha256(compiled),
        'selected_path': row, 'selected_path_sha256': _digest(row),
        'graph_sha256': _digest(graph.edge_document()), 'contract_sha256': _digest(contract.document()),
        'prepared': prepared.document(), 'runtime_path_identity': identity,
        'path_mapping': {'logical_path_id': row['path_id'], 'runtime_path_id': runtime_id},
        'source_binding': binding.document(), 'instruction_image': image,
        'cpu_mmio_stream': stream, 'candidate_layout': asdict(layout),
        'instruction_image_sha256': _digest(image), 'cpu_mmio_stream_sha256': _digest(stream)}
    if pin_documents:document['external_pin_paths']=pin_documents
    elif shared_pin:document['external_pin_delivery']='shared_f5'
    document['binding_sha256'] = _digest(document)
    admission = CompiledF4RuntimePathAdmission(prepared, binding, row['path_id'], runtime_id,
                                             _canonical(document))
    admission.validate_cached_identity()
    return admission
