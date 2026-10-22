"""Image admission joins explicit graph identity to one real RAM region."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
import pytest
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.runtime_path_contract import (RuntimeNode, RuntimeEdgeContract,
    RuntimePathContract, PreparedRuntimePathContract)
from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding


def fixture():
    graph = DependencyGraph(sources=(FuzzableSource('image', 'cpu', 'ram', 0, 128,
        ('CPU_TO_IP',), kind='memory_image'),), rules=(
        DependencyRule('loaded', ('image',), 'PERSISTENT_STATE_RULE'),))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, (RuntimeNode('image', 'cpu', 'state'),
        RuntimeNode('loaded', 'cpu', 'state')), (RuntimeEdgeContract(0, 0,
        'persistent_state', resource_component='cpu', resource_id='ram'),))
    paths = tuple(('CPU_TO_IP', p) for p in graph.edge_paths_to('loaded', direction='CPU_TO_IP'))
    prepared = PreparedRuntimePathContract(graph, contract, paths)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 16),),
        initialization_seed=1, max_initialized_bytes=16)
    runner = SimpleNamespace(sessions={'cpu': SimpleNamespace(memory=memory)})
    binding = InstructionImageSourceBinding(prepared.path_ids[0], 'CPU_TO_IP',
        'image', 'F4.program_image', 'cpu', 'ram', 0x1000, 16, True, True)
    return binding, prepared, runner


def test_strict_canonical_document():
    binding, _, _ = fixture()
    assert InstructionImageSourceBinding.from_document(binding.document()) == binding
    for field, value in [('base', True), ('size', 0), ('readable', 1),
                         ('writable', 'yes'), ('source_id', 1), ('direction', 'bad')]:
        with pytest.raises(ValueError):
            replace(binding, **{field: value})
    for mutation in ({'extra': 1}, {'schema_version': 'other'}, {'base': True}):
        with pytest.raises(ValueError):
            InstructionImageSourceBinding.from_document(binding.document() | mutation)


def test_actual_memory_and_exact_selected_graph_binding():
    binding, prepared, runner = fixture()
    binding.validate(prepared, runner)
    for field, value in [('path_id', 'other'), ('direction', 'IP_TO_IP'),
                         ('source_id', 'other'), ('component', 'other'),
                         ('memory_id', 'other'), ('base', 0x1004), ('size', 12),
                         ('readable', False), ('writable', False)]:
        with pytest.raises(ValueError):
            replace(binding, **{field: value}).validate(prepared, runner)
    runner.sessions['cpu'].memory = object()
    with pytest.raises(ValueError):
        binding.validate(prepared, runner)


@pytest.mark.parametrize('change', ['kind', 'port', 'offset', 'width', 'component', 'image_address', 'relation', 'resource'])
def test_graph_source_and_selected_persistent_edge_are_exact(change):
    binding, original, runner = fixture()
    source = original.graph.sources['image']
    rules = original.graph._ordered_rules
    nodes = original.contract.nodes
    edges = original.contract.edges
    if change == 'relation':
        rules = (DependencyRule('loaded', ('image',), 'EVENT_ORDER'),)
        edges = (RuntimeEdgeContract(0, 0, 'causal_order'),)
    elif change == 'resource':
        edges = (replace(edges[0], resource_id='other'),)
    elif change == 'kind': source = replace(source, kind='source')
    elif change == 'port': source = replace(source, port='other')
    elif change == 'offset': source = replace(source, bit_offset=8)
    elif change == 'width': source = replace(source, width=120)
    elif change == 'component': source = replace(source, component='other')
    else: source = replace(source, image_address=0x2000)
    graph = DependencyGraph(sources=(source,), rules=rules)
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, nodes, edges)
    try:
        paths = tuple(('CPU_TO_IP', p) for p in graph.edge_paths_to('loaded', direction='CPU_TO_IP'))
        prepared = PreparedRuntimePathContract(graph, contract, paths)
    except ValueError:
        return  # A malformed selected source can also fail during strict preparation.
    binding = replace(binding, path_id=prepared.path_ids[0])
    with pytest.raises(ValueError): binding.validate(prepared, runner)


@pytest.mark.parametrize('change', ['base', 'size', 'readable', 'writable', 'identity'])
def test_actual_memory_region_changes_refuse(change):
    binding, prepared, runner = fixture()
    values = dict(memory_id='ram', base=0x1000, size=16)
    if change == 'base': values['base'] = 0x1004
    elif change == 'size': values['size'] = 20
    elif change == 'identity': values['memory_id'] = 'other'
    else: values[change] = False
    runner.sessions['cpu'].memory = PersistentMemory(regions=(MemoryRegion(**values),),
        initialization_seed=1, max_initialized_bytes=32)
    with pytest.raises(ValueError): binding.validate(prepared, runner)
