"""Pure same-call F6 runtime-path admission for CPU-programmed RAM DMA.

The D3 compiler output is recompiled and retained unchanged.  This module adds
the two typed runtime RAM route edges needed by D4 and emits the exact
source-to-endpoint alias links; it creates no sessions, processes, or live
topology authority.
"""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

from myfuzz.local_harness.dma_artifact_endpoint_links import (
    PROVIDER_ID as DMA_LINK_PROVIDER_ID, dma_link_provider_contract,
    _artifact_link, _sha as _dma_link_sha)
from myfuzz.scenario.compiled_paths import (
    compile_paths, compiled_document_sha256, _wiring_resource_document)
from myfuzz.scenario.dependency import (
    DependencyEdge, DependencyGraph, DependencyPath, DependencyRule,
    FuzzableSource)
from myfuzz.scenario.dma_intent_topology_binding import prepare_dma_intent_binding
from myfuzz.scenario.f6_execution_contract import (
    compile_f6_execution_contract, validate_f6_execution_contract)
from myfuzz.scenario.memory import MemoryRegion
from myfuzz.scenario.runtime_path_contract import (
    DmaMasterRouteContract, PreparedRuntimePathContract, RuntimeEdgeContract,
    RuntimeNode, RuntimePathContract, canonical_runtime_identity_sha256)


SCHEMA_VERSION = 'compiled_F6_runtime_path_admission.v1'
_DMA_MAX_CONTROL_EDGES = 32
_DMA_MAX_EVENTS = 10000
_COMMAND_TIMEOUT_SECONDS = 10.0


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


def _require(condition, code):
    if not condition:
        raise ValueError('compiled-F6-runtime-path-' + code)


def _artifact_link_document(artifact):
    link = _artifact_link(artifact)
    from myfuzz.local_harness.wishbone_dma_fields import dma_select_modes
    control_selected,master_selected=dma_select_modes(artifact.plan.profile.capabilities)
    document = dict(schema_version='dma_artifact_endpoint_links.v1',
        provider_id=DMA_LINK_PROVIDER_ID, provider_version='1',
        provider_contract_sha256=_dma_link_sha(dma_link_provider_contract(
            control_address_width=artifact.plan.profile.capabilities['address_width'],
            control_selected=control_selected,master_selected=master_selected)),
        runtime_artifact_sha256=_dma_link_sha(artifact.runtime_document),
        runtime_sv_sha256=sha256(artifact.runtime_sv.encode()).hexdigest(),
        cpp_sha256=sha256(artifact.cpp_text.encode()).hexdigest(), links=[link])
    document['identity_sha256'] = _dma_link_sha(document)
    return document


def _dma_endpoint_identity(artifact, instance_id):
    # Match the exact GeneratedWishboneDmaSession constructor defaults used by
    # CompiledF6Runtime.  Keeping this derivation side-effect free lets the
    # admission run before any local session or process is constructed.
    return dict(schema_version='wishbone_dma_route_endpoint.v1',
        runtime_artifact=deepcopy(artifact.runtime_document),
        command_timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        source_component=instance_id,
        max_control_edges=_DMA_MAX_CONTROL_EDGES,
        max_events=_DMA_MAX_EVENTS, address_shift=2,
        byte_enable=('mwb_sel' if artifact.runtime_document['dma_edge_contract'].get('master_byte_enable_signal')
            == 'mwb_sel' else 15), max_outstanding=1)


def _memory_target_identity(resource):
    region = MemoryRegion(resource['resource_id'], resource['base'],
        resource['size'], readable=resource['read'], writable=resource['write'])
    return dict(schema_version='persistent_memory_route_target.v1',
        memory_configuration=dict(regions=[asdict(region)],
            initialization_seed=0, initialization_algorithm='memory-init-v1',
            max_initialized_bytes=resource['size']),
        resource=dict(memory_id=resource['resource_id'], base=resource['base'],
            size=resource['size'], canonical_base=region.base,
            is_alias=False, readable=region.readable, writable=region.writable,
            region=asdict(region)))


def _copy_original_path(row, graph):
    identity = row.get('runtime_path_identity')
    _require(type(identity) is dict and set(identity) == {
        'direction', 'path_id', 'source_ids', 'edges'}, 'd3-path-shape')
    try:
        path = DependencyPath(identity['edges'][-1]['target'],
            tuple(identity['source_ids']),
            tuple(DependencyEdge(**edge) for edge in identity['edges']))
        actual = graph.path_identity(path, direction=identity['direction'])
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise ValueError('compiled-F6-runtime-path-d3-path-invalid') from error
    _require(actual == identity['path_id'], 'd3-path-drift')
    return identity['direction'], path


def _runtime_graph(compiled, contract, artifacts, request, *, base_dir=None):
    from myfuzz.scenario.dependency import DependencyGraph
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract

    d3_graph = DependencyGraph.from_edge_document(compiled['runtime_dependency_graph'])
    d3_contract = RuntimePathContract.from_document(compiled['runtime_path_contract'])
    _require(d3_graph.edge_document() == compiled['runtime_dependency_graph'], 'd3-graph-drift')
    _require(d3_contract.document() == compiled['runtime_path_contract'], 'd3-contract-drift')
    _require(d3_contract.graph_sha256 == _digest(d3_graph.edge_document()), 'd3-contract-graph-hash')
    d3_row = next(row for row in compiled['paths'] if row.get('flow_id') == 'F6')
    direction, original_path = _copy_original_path(d3_row, d3_graph)

    p = contract['program_contract']
    memory = contract['memory']
    resource = memory['resource']
    cpu_id = contract['cpu']['instance_id']
    dma_id = contract['dma']['instance_id']
    source_id = 'F6.runtime_ram_source_words'
    read_id = 'F6.runtime_dma_read_words'
    write_id = 'F6.runtime_dma_write_words'
    destination_id = 'F6.runtime_ram_destination_words'
    instruction_source_id = contract['instruction_source_id']
    instruction_target_id = 'F6.runtime_online_instruction_prefixes'
    added_source_ids = {source_id, read_id, write_id, destination_id,
        instruction_source_id}
    _require(not (added_source_ids & set(d3_graph.sources)),
        'runtime-node-collision')

    source = FuzzableSource(source_id, cpu_id, resource['resource_id'], 0,
        memory['source']['size'] * 8, ('CPU_TO_IP',), kind='memory_image',
        image_address=p['source_address'])
    read_rule_index = 0
    runtime_rules = (
        DependencyRule(read_id, (source_id,), 'DMA_MASTER_TRANSFER'),
        DependencyRule(write_id, (read_id,), 'EVENT_ORDER'),
        DependencyRule(destination_id, (write_id,), 'DMA_MASTER_TRANSFER'),
        DependencyRule(instruction_target_id, (instruction_source_id,),
            'PERSISTENT_STATE_RULE'))
    resource = contract['memory']['resource']
    instruction_source = FuzzableSource(instruction_source_id, cpu_id,
        resource['resource_id'], 0, resource['size'] * 8, ('CPU_TO_IP',),
        kind='memory_image')
    runtime_graph = DependencyGraph(sources=(source, instruction_source),
        rules=runtime_rules)

    endpoint_identity = _dma_endpoint_identity(artifacts[dma_id], dma_id)
    endpoint_sha = canonical_runtime_identity_sha256(endpoint_identity)
    memory_identity = _memory_target_identity(resource)
    memory_sha = canonical_runtime_identity_sha256(memory_identity)
    intents = {route.route_id: route for route in request.wiring.dma_master_routes}
    _require(len(intents) == 2 and {row.operation for row in intents.values()} ==
        {'read', 'write'}, 'route-pair-required')
    by_operation = {row.operation: row for row in intents.values()}
    for route in by_operation.values():
        _require(route.initiator_instance == dma_id
            and route.initiator_endpoint_id == contract['dma']['master_endpoint_link']['endpoint_id']
            and route.target == {'kind': 'persistent_memory',
                'component_instance': cpu_id, 'resource_id': resource['resource_id']}
            and (route.base, route.size, route.byte_enable) ==
                (resource['base'], resource['size'], 15), 'route-intent-contract-mismatch')

    read_intent = by_operation['read']
    write_intent = by_operation['write']
    read_route = DmaMasterRouteContract(
        rule_index=read_rule_index, prerequisite_index=0,
        source_node_id=source_id, target_node_id=read_id,
        initiator_component=dma_id, endpoint_id='read_master',
        endpoint_identity_sha256=endpoint_sha,
        target_kind='persistent_memory', target_component=cpu_id,
        target_id=resource['resource_id'], base=read_intent.base,
        size=read_intent.size, operation='read', permissions=read_intent.permissions,
        byte_enable=15, readable_offsets=(), writable_offsets=(),
        accepted_write_values=(), target_identity_sha256=memory_sha)
    write_route = DmaMasterRouteContract(
        rule_index=read_rule_index + 2, prerequisite_index=0,
        source_node_id=write_id, target_node_id=destination_id,
        initiator_component=dma_id, endpoint_id='write_master',
        endpoint_identity_sha256=endpoint_sha,
        target_kind='persistent_memory', target_component=cpu_id,
        target_id=resource['resource_id'], base=write_intent.base,
        size=write_intent.size, operation='write', permissions=write_intent.permissions,
        byte_enable=15, readable_offsets=(), writable_offsets=(),
        accepted_write_values=(), target_identity_sha256=memory_sha)

    route_links = []
    artifact_link = _artifact_link_document(artifacts[dma_id])['links'][0]
    for intent, route in ((read_intent, read_route), (write_intent, write_route)):
        route_links.append(dict(route_id=intent.route_id,
            rule_index=route.rule_index, prerequisite_index=route.prerequisite_index,
            runtime_route_sha256=route.identity_sha256,
            endpoint_link=dict(mode='explicit_alias',
                static_endpoint_id=intent.initiator_endpoint_id,
                runtime_endpoint_id=route.endpoint_id,
                artifact_endpoint_id=artifact_link['endpoint_id'],
                artifact_link_id=artifact_link['link_id'],
                artifact_link_provider_id=DMA_LINK_PROVIDER_ID,
                operation=route.operation,
                template_binding=deepcopy(artifact_link['template_binding']))))

    path_rows = [
        RuntimeNode(source_id, cpu_id, 'state'),
        RuntimeNode(read_id, dma_id, 'logical'),
        RuntimeNode(write_id, dma_id, 'logical'),
        RuntimeNode(destination_id, cpu_id, 'state'),
        RuntimeNode(instruction_source_id, cpu_id, 'state'),
        RuntimeNode(instruction_target_id, cpu_id, 'logical'),
    ]
    runtime_edge_docs = [
        RuntimeEdgeContract(read_rule_index, 0, 'dma_master_route'),
        RuntimeEdgeContract(read_rule_index + 1, 0, 'causal_order'),
        RuntimeEdgeContract(read_rule_index + 2, 0, 'dma_master_route'),
        RuntimeEdgeContract(read_rule_index + 3, 0, 'persistent_state',
            resource_component=cpu_id, resource_id=resource['resource_id'])]
    runtime_contract = RuntimePathContract(_digest(runtime_graph.edge_document()),
        tuple(path_rows), tuple(runtime_edge_docs),
        (read_route, write_route))
    shared_paths = ()
    if 'shared_slots' in contract['program_contract']:
        from .shared_slot_paths import build_shared_flow_paths
        from .shared_f6_assembly import shared_irq_group, shared_custom_gpio_irq_route
        group = (shared_custom_gpio_irq_route(contract,artifacts,base_dir=base_dir)
                 or shared_irq_group(contract,artifacts,base_dir=base_dir))
        runtime_graph, runtime_contract, shared_paths, _ = build_shared_flow_paths(
            runtime_graph, runtime_contract, compiled, contract['program_contract']['shared_slots']['enabled_flows'],
            irq_group=group)
    transfer_paths = runtime_graph.edge_paths_to(destination_id,
        direction='CPU_TO_IP', max_depth=3, max_paths=2)
    _require(len(transfer_paths) == 1 and transfer_paths[0].source_ids ==
        (source_id,), 'transfer-path-ambiguous')
    instruction_paths = runtime_graph.edge_paths_to(instruction_target_id,
        direction='CPU_TO_IP', max_depth=1, max_paths=2)
    _require(len(instruction_paths) == 1 and instruction_paths[0].source_ids ==
        (instruction_source_id,), 'instruction-path-ambiguous')
    prepared = PreparedRuntimePathContract(runtime_graph, runtime_contract,
        (('CPU_TO_IP', transfer_paths[0]),
         ('CPU_TO_IP', instruction_paths[0])) +
        shared_paths)
    from myfuzz.scenario.dma_intent_topology_binding import PreparedDmaIntentBinding
    declaration = prepare_dma_intent_binding(request.wiring, prepared,
        route_links=route_links)
    return runtime_graph, runtime_contract, prepared, declaration, (read_route, write_route), route_links


def admit_compiled_f6_runtime_path(*, artifacts, compiled_inputs, base_dir) -> dict:
    """Recompile D2/D3 and describe a route-bound F6 runtime graph without effects."""
    from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
    from myfuzz.scenario.compiled_paths import PathCompileRequest

    _require(type(compiled_inputs) is dict and set(compiled_inputs) == {
        'request', 'compiled', 'ownership', 'physical_port_map'}, 'inputs-required')
    request = compiled_inputs['request']
    _require(type(request) is PathCompileRequest, 'request-required')
    _require(type(artifacts) is dict, 'artifact-map-required')
    base_dir = Path(base_dir)
    d3 = compile_paths(request)
    _require(_canonical(d3) == _canonical(compiled_inputs['compiled']), 'd3-recompile-mismatch')
    admission = admit_compiled_artifacts(artifacts=artifacts, request=request,
        compiled=d3, ownership=compiled_inputs['ownership'],
        physical_port_map=compiled_inputs['physical_port_map'])
    _require(admission.get('status') == 'compatible', 'd2-artifacts-incompatible')
    contract = compile_f6_execution_contract(request, base_dir=base_dir)
    validate_f6_execution_contract(contract, request=request, base_dir=base_dir)
    executable = [row for row in d3['paths']
        if row.get('flow_id') == 'F6' and row.get('status') == 'executable']
    _require(len(executable) == 1 and executable[0].get('execution_contract') == contract,
        'one-executable-f6-required')
    row = executable[0]
    if set(contract['program_contract'].get('shared_slots',{}).get('enabled_flows',())) & {'F1','F3'}:
        from myfuzz.runtime.flows.memory import prepare_memory_paths
        prepare_memory_paths(request=request,compiled=d3)
    runtime_graph, runtime_contract, prepared, declaration, routes, route_links = _runtime_graph(
        d3, contract, artifacts, request, base_dir=base_dir)
    program = contract['program_contract']
    sparse = dict(schema_version='compiled_F6_sparse_program_manifest.v1',
        image=deepcopy(program['initial_image']),
        image_sha256=program['initial_image_sha256'],
        slot_base=program['slot_base'], slot_count=program['slot_count'],
        slot_bytes=program['slot_bytes'], online_prefix_bytes=program['online_prefix_bytes'],
        unmaterialized_prefix_bytes=program['online_prefix_bytes'] * program['slot_count'])
    artifacts_identities = {name: dict(instance_id=name,
        component_id=artifact.plan.profile.component_id,
        artifact_digest=artifact.runtime_document['artifact_digest'],
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        source_verification_sha256=_digest(artifact.source_verification),
        runtime_artifact_sha256=_digest(artifact.runtime_document))
        for name, artifact in sorted(artifacts.items())}
    document = dict(schema_version=SCHEMA_VERSION,
        logical_path=deepcopy(row), d3_path=dict(
            logical_path_id=row['path_id'],
            runtime_path_identity=deepcopy(row['runtime_path_identity'])),
        execution_contract=deepcopy(contract),
        compiled_document_sha256=compiled_document_sha256(d3),
        request_sha256=_digest(request.document),
        artifact_identities=artifacts_identities,
        selected_path_sha256=_digest(row),
        runtime_graph=runtime_graph.edge_document(),
        runtime_contract=runtime_contract.document(),
        prepared_runtime_paths=prepared.document(),
        runtime_path_ids=list(prepared.path_ids),
        dma_intent_binding=declaration.document(),
        route_links=route_links,
        selected_dma_routes=[route.document() for route in routes],
        sparse_program_manifest=sparse,
        execution_contract_sha256=_digest(contract),
        static_artifact_admission=admission)
    if 'shared_slots' in contract['program_contract']:
        layout = contract['program_contract']['shared_slots']
        _, selected = prepared.runtime_paths[2]
        row = next(row for row in d3['paths'] if row['flow_id'] == 'F4')
        image = next(source for source in row['sources'] if source['kind'] == 'instruction_image')
        document['shared_storage_path'] = dict(schema_version='shared_storage_runtime_path.v1',
            path_id=prepared.path_ids[2], source_id=selected.source_ids[0],
            logical_source_id=image['source_id'], cpu_component=request.cpu.instance_id,
            component=layout['component'], memory_id=contract['memory']['resource']['resource_id'],
            base=contract['memory']['resource']['base'], size=contract['memory']['resource']['size'])
    if 'shared_slots' in contract['program_contract']:
        from .shared_slot_paths import build_shared_flow_paths
        # Extract the unchanged F6 base before rebuilding the declared extras.
        from .shared_slot_paths import shared_f6_base
        base_graph, base_contract = shared_f6_base(runtime_graph, runtime_contract)
        from .shared_f6_assembly import shared_irq_group, shared_custom_gpio_irq_route
        _, _, _, mappings = build_shared_flow_paths(base_graph, base_contract, d3,
            contract['program_contract']['shared_slots']['enabled_flows'],
            irq_group=(shared_custom_gpio_irq_route(contract,artifacts,base_dir=base_dir)
                       or shared_irq_group(contract,artifacts,base_dir=base_dir)))
        mappings['F6'] = dict(flow_id='F6', path_id=prepared.path_ids[1],
            source_id=contract['instruction_source_id'],logical_source_id=contract['instruction_source_id'],
            cpu_component=request.cpu.instance_id,component=contract['dma']['instance_id'],
            memory_id=contract['memory']['resource']['resource_id'],
            base=contract['memory']['resource']['base'],size=contract['memory']['resource']['size'])
        document['shared_flow_paths'] = mappings
        document['shared_flow_compilation'] = deepcopy(d3)
    if 'shared_flow_paths' in document:
        from .shared_slot_paths import validate_shared_flow_admission
        validate_shared_flow_admission(document)
    document['admission_sha256'] = _digest(document)
    return deepcopy(document)


def restore_prepared_runtime_paths(document):
    """Restore a path only after verifying its canonical admission envelope."""
    _require(type(document) is dict and document.get('schema_version') == SCHEMA_VERSION,
        'admission-required')
    body = deepcopy(document)
    supplied = body.pop('admission_sha256', None)
    _require(type(supplied) is str and supplied == _digest(body), 'admission-digest-mismatch')
    prepared = PreparedRuntimePathContract.from_document(document['prepared_runtime_paths'])
    _require(prepared.document() == document['prepared_runtime_paths'], 'prepared-path-drift')
    return prepared
