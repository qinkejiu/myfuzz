"""Detached reader for one compiled RAM-word to Caliptra CTRL DMA path."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import sys

import pytest

from myfuzz.scenario.compiled_f6_dma_handoff import prepare_compiled_f6_dma_handoff
from myfuzz.scenario.compiled_paths import compiled_document_sha256, load_path_wiring
from myfuzz.scenario.dependency import (
    DependencyEdge, DependencyGraph, DependencyPath, DependencyRule,
    FuzzableSource,
)
from myfuzz.scenario.dma_route_intent import (
    DmaMasterRouteIntent, dma_master_route_intents_document,
)
from myfuzz.scenario.dma_intent_topology_binding import prepare_dma_intent_binding
from myfuzz.scenario.runtime_path_contract import (
    DmaMasterRouteContract, PreparedRuntimePathContract, RuntimeEdgeContract,
    RuntimeNode, RuntimePathContract,
)
from tests.scenario.test_compiled_f6_dma_handoff import _compiled_f6_for

from myfuzz.scenario.compiled_f6_runtime_path import (
    CompiledF6RuntimePath,
    CompiledF6RuntimePathError,
    DmaTransferRoutePair,
    DmaTransferSourceWord,
    prepare_compiled_f6_runtime_path,
    bind_compiled_f6_runtime_path,
    build_caliptra_runtime_graph,
)


def digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False, allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def source_document():
    return dict(schema_version='dma_transfer_source_word.v1',
                memory_component='cpu', resource_id='ram',
                image_id='sha_ctrl_start', address=65792,
                word_bytes=4, byte_enable=15, direction='CPU_TO_IP')


def pair_document():
    return dict(schema_version='dma_transfer_route_pair.v1',
                read_route_id='route.ram-read',
                write_route_id='route.caliptra-ctrl',
                relation='same_word_value')


def artifact_document():
    memory_base, memory_size = 0x10000, 0x10000
    source_address = 0x10100
    sha_base, sha_size = 0x40000000, 0x1000
    binding = dict(profile_endpoint_sha256='1' * 64,
                   template_id='master.wishbone-pipelined',
                   template_version='1', variant_id='dma-full-word-no-select',
                   contract_sha256='2' * 64, selection_sha256='3' * 64)

    graph = DependencyGraph(
        sources=(FuzzableSource(
            'ram.source_word', 'cpu', 'sha_ctrl_start', 0, 32,
            ('CPU_TO_IP',), kind='memory_image', image_address=source_address),),
        rules=(
            DependencyRule('dma.read_data', ('ram.source_word',),
                           'DMA_MASTER_TRANSFER'),
            DependencyRule('dma.write_data', ('dma.read_data',), 'EVENT_ORDER'),
            DependencyRule('sha.ctrl_start_effect', ('dma.write_data',),
                           'DMA_MASTER_TRANSFER'),
        ))
    path, = graph.edge_paths_to('sha.ctrl_start_effect', direction='CPU_TO_IP')
    routes = (
        DmaMasterRouteContract(
            0, 0, 'ram.source_word', 'dma.read_data', 'dma', 'dma.master',
            '4' * 64, 'persistent_memory', 'cpu', 'ram', memory_base,
            memory_size, 'read', ('read', 'write'), 15, (), (), (),
            '5' * 64),
        DmaMasterRouteContract(
            2, 0, 'dma.write_data', 'sha.ctrl_start_effect', 'dma',
            'dma.master', '4' * 64, 'peripheral', 'sha', 'sha', sha_base,
            sha_size, 'write', ('write',), 15, (), (16,), (5,),
            '6' * 64),
    )
    contract = RuntimePathContract(
        digest(graph.edge_document()),
        (RuntimeNode('ram.source_word', 'cpu', 'state'),
         RuntimeNode('dma.read_data', 'dma', 'logical'),
         RuntimeNode('dma.write_data', 'dma', 'logical'),
         RuntimeNode('sha.ctrl_start_effect', 'sha', 'state')),
        (RuntimeEdgeContract(0, 0, 'dma_master_route'),
         RuntimeEdgeContract(1, 0, 'causal_order'),
         RuntimeEdgeContract(2, 0, 'dma_master_route')),
        routes)
    prepared = PreparedRuntimePathContract(
        graph, contract, (('CPU_TO_IP', path),))

    intents = (
        DmaMasterRouteIntent(
            'route.ram-read', 'dma', 'dma.master',
            dict(kind='persistent_memory', component_instance='cpu',
                 resource_id='ram'),
            memory_base, memory_size, 'read', ('read', 'write'), 15,
            (), (), ()),
        DmaMasterRouteIntent(
            'route.caliptra-ctrl', 'dma', 'dma.master',
            dict(kind='peripheral', component_instance='sha', device_id='sha',
                 endpoint_id='sha256.bus'),
            sha_base, sha_size, 'write', ('write',), 15,
            (), (16,), (5,)),
    )
    wrapped = dma_master_route_intents_document(intents)
    wiring_document = dict(
        schema_version='path_wiring.v2', cpu=dict(instance_id='cpu'),
        windows=[dict(device_id='sha', target_instance='sha',
                      endpoint_id='sha256.bus', base=sha_base, size=sha_size)],
        resources=[dict(resource_id='ram', component_instance='cpu',
                        base=memory_base, size=memory_size, read=True, write=True)],
        dma_master_routes=wrapped, dma_master_routes_sha256=digest(wrapped),
        dma_master_route_bindings=[
            dict(route_id='route.caliptra-ctrl', initiator=binding,
                 target=binding),
            dict(route_id='route.ram-read', initiator=binding,
                 target=dict(kind='persistent_memory',
                             owner_profile_fingerprint='sha256:' + '7' * 64,
                             resource_sha256='8' * 64)),
        ])
    wiring = load_path_wiring(wiring_document)
    route_links = []
    for route_id, rule_index, operation, runtime_route in (
            ('route.ram-read', 0, 'read', routes[0]),
            ('route.caliptra-ctrl', 2, 'write', routes[1])):
        route_links.append(dict(
            route_id=route_id, rule_index=rule_index,
            prerequisite_index=0,
            runtime_route_sha256=runtime_route.identity_sha256,
            endpoint_link=dict(
                mode='exact_id', static_endpoint_id='dma.master',
                runtime_endpoint_id='dma.master', artifact_endpoint_id='dma.master',
                artifact_link_id='physical-master',
                artifact_link_provider_id='wishbone-dma-single-master.v1',
                operation=operation, template_binding=binding)))
    declaration = prepare_dma_intent_binding(
        wiring, prepared, route_links=route_links)
    handoff = prepare_compiled_f6_dma_handoff(
        _compiled_f6_for(wiring), declaration)
    document = dict(schema_version='compiled_f6_runtime_path.v1',
                    source=source_document(), transfer_pair=pair_document(),
                    compiled_f6_handoff=handoff.document())
    document['identity_sha256'] = digest(document)
    return document


def test_live_compiler_keeps_one_prepared_graph_and_detached_copy_cannot_bind(tmp_path):
    from unittest.mock import patch
    from myfuzz.scenario.compiled_f6_dma_handoff import bind_compiled_f6_dma_handoff as original_handoff_bind
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
        _caliptra_typed_dma_fixture,
    )
    from tests.integration.test_dma_caliptra_sha256_real import _caliptra_artifact
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    runner, links, _, _ = _caliptra_typed_dma_fixture(
        generated_instance('dma'), _caliptra_artifact(), tmp_path)
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    path = prepare_compiled_f6_runtime_path(
        compiled, request.wiring, runner, source=source,
        transfer_pair=pair, artifact_links=links)
    assert path.document()['schema_version'] == 'compiled_f6_runtime_path.v1'
    reversed_wiring = replace(request.wiring,
        dma_master_routes=tuple(reversed(request.wiring.dma_master_routes)))
    reversed_path = prepare_compiled_f6_runtime_path(
        compiled, reversed_wiring, runner, source=source,
        transfer_pair=pair, artifact_links=links)
    assert reversed_path.document() == path.document()
    assert {row['route_id']: row['rule_index'] for row in
        path.handoff.document()['declaration']['route_links']} == {
            pair.read_route_id: 0, pair.write_route_id: 2}
    assert path.handoff._declaration._prepared_runtime_paths is path.prepared_runtime_paths
    altered_links = []
    bad_links = deepcopy(links)
    bad_links['dma']['links'][0]['link_id'] = 'wrong-physical-link'
    altered_links.append(bad_links)
    bad_links = deepcopy(links)
    bad_links['dma']['provider_id'] = 'wrong-provider'
    altered_links.append(bad_links)
    bad_links = deepcopy(links)
    bad_links['dma']['links'][0]['endpoint_id'] = 'wrong-owner-endpoint'
    altered_links.append(bad_links)
    altered_links.append({'other-owner': deepcopy(links['dma'])})
    for bad_links in altered_links:
        with pytest.raises(ValueError):
            bind_compiled_f6_runtime_path(path, runner, artifact_links=bad_links)
    with patch.object(type(runner.sessions['dma']),
            'dma_route_endpoint_identity_document',
            lambda self: {'schema_version': 'drift'}):
        with pytest.raises(ValueError):
            bind_compiled_f6_runtime_path(path, runner, artifact_links=links)

    detached = CompiledF6RuntimePath.from_document(path.document())
    with patch('myfuzz.scenario.compiled_f6_runtime_path.bind_compiled_f6_dma_handoff') as binder:
        with pytest.raises(CompiledF6RuntimePathError, match='detached'):
            bind_compiled_f6_runtime_path(detached, runner, artifact_links=links)
        binder.assert_not_called()

    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind
    def spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)
    handoffs = []
    def handoff_spy(handoff, *args, **kwargs):
        handoffs.append(handoff)
        return original_handoff_bind(handoff, *args, **kwargs)
    with patch.object(PreparedRuntimePathContract, 'bind', spy), patch(
            'myfuzz.scenario.compiled_f6_runtime_path.bind_compiled_f6_dma_handoff',
            handoff_spy):
        bound = bind_compiled_f6_runtime_path(path, runner, artifact_links=links)
    assert handoffs == [path.handoff]
    assert bound_objects == [path.prepared_runtime_paths]
    assert bound.prepared_runtime_paths is path.prepared_runtime_paths
    bound.validate_topology()


def test_compiler_artifact_round_trip_refuses_before_both_d4_binders(tmp_path):
    from unittest.mock import patch
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
        _caliptra_typed_dma_fixture,
    )
    from tests.integration.test_dma_caliptra_sha256_real import _caliptra_artifact
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    runner, links, _, _ = _caliptra_typed_dma_fixture(
        generated_instance('dma'), _caliptra_artifact(), tmp_path)
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    live = prepare_compiled_f6_runtime_path(
        compiled, request.wiring, runner, source=source,
        transfer_pair=pair, artifact_links=links)
    serialized = json.dumps(live.document(), sort_keys=True)
    detached = CompiledF6RuntimePath.from_document(json.loads(serialized))
    assert detached.document() == live.document()
    assert detached.prepared_runtime_paths is None
    with patch('myfuzz.scenario.compiled_f6_runtime_path.bind_compiled_f6_dma_handoff') as handoff_bind, \
            patch.object(PreparedRuntimePathContract, 'bind') as runtime_bind:
        with pytest.raises(CompiledF6RuntimePathError, match='detached'):
            bind_compiled_f6_runtime_path(detached, runner, artifact_links=links)
        handoff_bind.assert_not_called()
        runtime_bind.assert_not_called()


def test_live_compiler_refuses_static_identity_and_pair_drift_before_graph(tmp_path):
    from unittest.mock import patch
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    changed = deepcopy(compiled)
    changed['identity']['wiring']['dma_master_route_bindings_sha256'] = '0' * 64
    bad_schema = deepcopy(compiled)
    bad_schema['schema_version'] = 'compiled_paths.v0'
    bad_missing = deepcopy(compiled)
    next(row for row in bad_missing['paths'] if row['flow_id'] == 'F6')[
        'reason']['missing'] = []
    bad_graph = deepcopy(compiled)
    bad_graph['runtime_dependency_graph']['rules'][0]['target'] = 'missing-node'
    bad_digest = deepcopy(compiled)
    bad_digest['runtime_path_contract']['graph_sha256'] = '0' * 64
    bad_graph_nodes = deepcopy(compiled)
    bad_graph_nodes['runtime_dependency_graph']['rules'][0]['target'] = 'F1.new-effect'
    bad_graph_nodes['runtime_dependency_graph']['edges'][0]['target'] = 'F1.new-effect'
    bad_graph_nodes['runtime_path_contract']['graph_sha256'] = digest(
        bad_graph_nodes['runtime_dependency_graph'])
    bad_graph_relation = deepcopy(compiled)
    bad_graph_relation['runtime_dependency_graph']['rules'][0]['kind'] = 'EVENT_ORDER'
    bad_graph_relation['runtime_dependency_graph']['edges'][0]['kind'] = 'EVENT_ORDER'
    bad_graph_relation['runtime_path_contract']['graph_sha256'] = digest(
        bad_graph_relation['runtime_dependency_graph'])
    f6_only = deepcopy(compiled)
    f6_only['paths'] = [row for row in f6_only['paths']
                        if row['flow_id'] == 'F6']
    empty_definitions = deepcopy(compiled)
    empty_definitions['flow_definitions'] = {}
    bad_counts = deepcopy(compiled)
    bad_counts['counts']['total'] = 1
    duplicate_flow = deepcopy(compiled)
    duplicate_flow['paths'][1] = deepcopy(duplicate_flow['paths'][0])
    missing_path_field = deepcopy(compiled)
    missing_path_field['paths'][0].pop('flow_name')
    wrong_flow_name = deepcopy(compiled)
    wrong_flow_name['paths'][0]['flow_name'] = 'wrong'
    missing_contract_edge = deepcopy(compiled)
    missing_contract_edge['runtime_path_contract']['edges'].pop(0)
    source_owner_drift = deepcopy(compiled)
    source_owner_drift['runtime_dependency_graph']['sources'][0]['component'] = 'sha'
    source_owner_drift['runtime_path_contract']['graph_sha256'] = digest(
        source_owner_drift['runtime_dependency_graph'])
    contract_owner_drift = deepcopy(compiled)
    source_id = compiled['runtime_dependency_graph']['sources'][0]['source_id']
    next(node for node in contract_owner_drift['runtime_path_contract']['nodes']
         if node['node_id'] == source_id)['component'] = 'sha'
    joined_source_drift = deepcopy(source_owner_drift)
    next(node for node in joined_source_drift['runtime_path_contract']['nodes']
         if node['node_id'] == source_id)['component'] = 'sha'
    incomplete_cpu_identity = deepcopy(compiled)
    incomplete_cpu_identity['identity']['cpu'].pop('component_id')
    extra_device_identity = deepcopy(compiled)
    extra_device_identity['identity']['devices'][0]['unknown'] = 1
    boolean_count = deepcopy(compiled)
    boolean_count['counts']['total'] = True
    extra_input_constraint = deepcopy(compiled)
    extra_input_constraint['input_constraints']['unexpected'] = True
    extra_input_rule_field = deepcopy(compiled)
    extra_input_rule_field['input_constraints']['rules'][0]['unexpected'] = True
    bad_input_layout_field = deepcopy(compiled)
    bad_input_layout_field['input_constraints']['layout']['fields'][0][
        'unexpected'] = True
    bad_layout_constraint = deepcopy(compiled)
    bad_layout_constraint['input_constraints']['layout']['fields'][0][
        'constraint']['unexpected'] = True
    bad_layout_provenance = deepcopy(compiled)
    bad_layout_provenance['input_constraints']['layout']['fields'][0][
        'provenance'] = {'file': 'probe.sv', 'line': 1, 'unexpected': True}
    bad_input_closure = deepcopy(compiled)
    bad_input_closure['input_constraints']['closure'][0] = {'wrong': 'row'}
    def rename_graph_image(new_id):
        changed = deepcopy(compiled)
        old_id = changed['runtime_dependency_graph']['sources'][0]['source_id']
        changed['runtime_dependency_graph']['sources'][0]['source_id'] = new_id
        for rule in changed['runtime_dependency_graph']['rules']:
            rule['prerequisites'] = [new_id if value == old_id else value
                                     for value in rule['prerequisites']]
        for edge in changed['runtime_dependency_graph']['edges']:
            if edge['prerequisite'] == old_id:
                edge['prerequisite'] = new_id
        next(node for node in changed['runtime_path_contract']['nodes']
             if node['node_id'] == old_id)['node_id'] = new_id
        changed['runtime_path_contract']['nodes'].sort(
            key=lambda row: row['node_id'])
        changed['runtime_path_contract']['graph_sha256'] = digest(
            changed['runtime_dependency_graph'])
        return changed
    ghost_image = rename_graph_image('ghost.image')
    wrong_f1_image = rename_graph_image('F1.ghost')
    duplicate_image = deepcopy(compiled)
    duplicate_image['runtime_dependency_graph']['sources'].append({
        **deepcopy(duplicate_image['runtime_dependency_graph']['sources'][0]),
        'source_id': 'F1.ghost',
    })
    duplicate_image['runtime_path_contract']['nodes'].append({
        **deepcopy(next(node for node in compiled['runtime_path_contract']['nodes']
                       if node['node_id'] == source_id)),
        'node_id': 'F1.ghost',
    })
    duplicate_image['runtime_path_contract']['nodes'].sort(
        key=lambda row: row['node_id'])
    duplicate_image['runtime_path_contract']['graph_sha256'] = digest(
        duplicate_image['runtime_dependency_graph'])
    image_direction_drift = deepcopy(compiled)
    image_direction_drift['runtime_dependency_graph']['sources'][0][
        'directions'] = ['IP_TO_CPU']
    image_direction_drift['runtime_path_contract']['graph_sha256'] = digest(
        image_direction_drift['runtime_dependency_graph'])
    read_intent = next(route for route in request.wiring.dma_master_routes
                       if route.operation == 'read')
    cases = [
        (changed, request.wiring, source, pair),
        (bad_schema, request.wiring, source, pair),
        (bad_missing, request.wiring, source, pair),
        (bad_graph, request.wiring, source, pair),
        (bad_digest, request.wiring, source, pair),
        (bad_graph_nodes, request.wiring, source, pair),
        (bad_graph_relation, request.wiring, source, pair),
        (f6_only, request.wiring, source, pair),
        (empty_definitions, request.wiring, source, pair),
        (bad_counts, request.wiring, source, pair),
        (duplicate_flow, request.wiring, source, pair),
        (missing_path_field, request.wiring, source, pair),
        (wrong_flow_name, request.wiring, source, pair),
        (missing_contract_edge, request.wiring, source, pair),
        (source_owner_drift, request.wiring, source, pair),
        (contract_owner_drift, request.wiring, source, pair),
        (joined_source_drift, request.wiring, source, pair),
        (incomplete_cpu_identity, request.wiring, source, pair),
        (extra_device_identity, request.wiring, source, pair),
        (boolean_count, request.wiring, source, pair),
        (extra_input_constraint, request.wiring, source, pair),
        (extra_input_rule_field, request.wiring, source, pair),
        (bad_input_layout_field, request.wiring, source, pair),
        (bad_layout_constraint, request.wiring, source, pair),
        (bad_layout_provenance, request.wiring, source, pair),
        (bad_input_closure, request.wiring, source, pair),
        (ghost_image, request.wiring, source, pair),
        (wrong_f1_image, request.wiring, source, pair),
        (duplicate_image, request.wiring, source, pair),
        (image_direction_drift, request.wiring, source, pair),
        (compiled, request.wiring, source,
         DmaTransferRoutePair('missing', pair.write_route_id, 'same_word_value')),
        (compiled, request.wiring, source,
         DmaTransferRoutePair(pair.write_route_id, pair.read_route_id,
                              'same_word_value')),
        (compiled, request.wiring,
         replace(source, memory_component='other'), pair),
        (compiled, request.wiring,
         replace(source, resource_id='other'), pair),
        (compiled, request.wiring,
         replace(source, address=0x2000), pair),
        (compiled, replace(request.wiring, dma_master_routes=()), source, pair),
        (compiled, replace(request.wiring, dma_master_routes=(
            read_intent,) * 2), source, pair),
        (compiled, replace(request.wiring, dma_master_routes=(
            *request.wiring.dma_master_routes,
            replace(read_intent, route_id='third'))),
         source, pair),
        (compiled, replace(request.wiring, dma_master_routes=tuple(
            replace(route, initiator_instance='second-dma')
              if route.route_id == read_intent.route_id else route
              for route in request.wiring.dma_master_routes)), source, pair),
        (compiled, replace(request.wiring, dma_master_routes=tuple(
            replace(route, target={
                'kind': 'persistent_memory', 'component_instance': 'other',
                'resource_id': 'ram'})
              if route.route_id == read_intent.route_id else route
              for route in request.wiring.dma_master_routes)),
         source, pair),
        (compiled, replace(request.wiring, dma_master_routes=tuple(
            replace(route, operation='write')
              if route.route_id == read_intent.route_id else route
              for route in request.wiring.dma_master_routes)), source, pair),
    ]
    with patch('myfuzz.scenario.compiled_f6_runtime_path.build_caliptra_runtime_graph') as graph:
        for index, (d3, wiring, case_source, case_pair) in enumerate(cases):
            try:
                prepare_compiled_f6_runtime_path(
                    d3, wiring, object(), source=case_source,
                    transfer_pair=case_pair, artifact_links={})
            except CompiledF6RuntimePathError:
                pass
            except Exception as error:
                pytest.fail(f'case {index} reached builder: {error}')
            else:
                pytest.fail(f'case {index} was accepted')
        graph.assert_not_called()


def test_public_compiler_refuses_valid_d3_route_count_and_operation_drift(tmp_path):
    from unittest.mock import patch
    from myfuzz.scenario.compiled_paths import (
        compile_paths, compiled_document_sha256, load_path_wiring,
    )
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    _, request, _ = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    for drift in ('missing', 'extra', 'operation'):
        document = deepcopy(request.wiring.document)
        routes = document['dma_master_routes']['routes']
        read = next(row for row in routes if row['route_id'] == pair.read_route_id)
        if drift == 'missing':
            routes.remove(read)
            document['dma_master_route_bindings'] = [row for row in
                document['dma_master_route_bindings']
                if row['route_id'] != pair.read_route_id]
        elif drift == 'extra':
            added = deepcopy(read)
            added['route_id'] = 'route.third'
            routes.append(added)
            binding = deepcopy(next(row for row in
                document['dma_master_route_bindings']
                if row['route_id'] == pair.read_route_id))
            binding['route_id'] = 'route.third'
            document['dma_master_route_bindings'].append(binding)
            routes.sort(key=lambda row: row['route_id'])
            document['dma_master_route_bindings'].sort(key=lambda row: row['route_id'])
        else:
            read['operation'] = 'write'
        document['dma_master_routes_sha256'] = compiled_document_sha256(
            document['dma_master_routes'])
        wiring = load_path_wiring(document)
        compiled = compile_paths(replace(request, wiring=wiring))
        assert next(row for row in compiled['paths']
                    if row['flow_id'] == 'F6')['reason']['code'] == \
            'dma-route-live-topology-binding-required'
        with patch('myfuzz.scenario.compiled_f6_runtime_path.build_caliptra_runtime_graph') as graph:
            with pytest.raises(CompiledF6RuntimePathError,
                               match='route-mismatch'):
                prepare_compiled_f6_runtime_path(
                    compiled, wiring, object(), source=source,
                    transfer_pair=pair, artifact_links={})
            graph.assert_not_called()


def test_public_compiler_refuses_write_operation_and_in_aperture_read_drift(tmp_path):
    from unittest.mock import patch
    from myfuzz.scenario.compiled_paths import (
        PathCompilationError, compile_paths, load_path_wiring,
    )
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    from tests.scenario.test_caliptra_sha256_dma_paths import _Runner
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory

    _, request, _ = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    memory = PersistentMemory(
        regions=(MemoryRegion('ram', 0x1000, 0x1000),),
        initialization_seed=23, max_initialized_bytes=0x1000)
    runner = _Runner(memory=memory)
    for drift, route_id, changes, selected_address in (
            ('write-operation', pair.write_route_id,
             {'operation': 'read', 'permissions': ['read'],
              'readable_offsets': [16], 'writable_offsets': [],
              'accepted_write_values': {'kind': 'values', 'values': []}},
             0x1000),
            ('in-aperture-read-address', pair.read_route_id,
             {'base': 0x1004, 'size': 0xffc}, 0x1000),
            ('in-aperture-selected-source', pair.read_route_id,
             {'size': 0xffc}, 0x1ffc)):
        document = deepcopy(request.wiring.document)
        next(row for row in document['dma_master_routes']['routes']
             if row['route_id'] == route_id).update(changes)
        document['dma_master_routes_sha256'] = compiled_document_sha256(
            document['dma_master_routes'])
        wiring = load_path_wiring(document)
        if drift == 'write-operation':
            with pytest.raises(PathCompilationError,
                               match='dma-route-target-register-permission-mismatch'):
                compile_paths(replace(request, wiring=wiring))
            continue
        compiled = compile_paths(replace(request, wiring=wiring))
        assert next(row for row in compiled['paths']
                    if row['flow_id'] == 'F6')['status'] == 'unsupported', drift
        with patch('myfuzz.scenario.compiled_f6_runtime_path.build_caliptra_runtime_graph') as graph:
            with pytest.raises(CompiledF6RuntimePathError,
                               match='route-mismatch'):
                prepare_compiled_f6_runtime_path(
                    compiled, wiring, runner,
                    source=replace(source, address=selected_address),
                    transfer_pair=pair, artifact_links={})
            graph.assert_not_called()


def test_public_compiler_refuses_real_d3_multiple_movers_and_targets(tmp_path):
    from unittest.mock import patch
    from myfuzz.scenario.compiled_paths import compile_paths, load_path_wiring
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    from tests.scenario.test_caliptra_sha256_dma_paths import _Runner

    _, request, _ = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    for drift in ('multiple-movers', 'multiple-targets'):
        document = deepcopy(request.wiring.document)
        devices = request.devices
        routes = document['dma_master_routes']['routes']
        bindings = document['dma_master_route_bindings']
        if drift == 'multiple-movers':
            dma = next(device for device in devices if device.instance_id == 'dma')
            profile = replace(dma.profile, endpoints=tuple(
                replace(endpoint, endpoint_id='dma2.' + endpoint.endpoint_id,
                        fields=tuple(
                    replace(field, aliases=tuple('dma2_' + alias
                                                 for alias in field.aliases))
                    for field in endpoint.fields))
                for endpoint in dma.profile.endpoints))
            capability = dma.capability
            feature = replace(capability.feature_contract, operations=tuple(
                replace(operation, endpoint_id='dma2.' + operation.endpoint_id)
                for operation in capability.feature_contract.operations))
            capability = replace(capability,
                profile_fingerprint=profile.profile_fingerprint,
                endpoint_capabilities=tuple(
                    replace(row, endpoint_id='dma2.' + row.endpoint_id)
                    for row in capability.endpoint_capabilities),
                observation_mappings=tuple(
                    replace(row, endpoint_id='dma2.' + row.endpoint_id)
                    for row in capability.observation_mappings),
                feature_contract=feature)
            dma2 = replace(dma, instance_id='dma2', profile=profile,
                           capability=capability)
            devices = (*devices, dma2)
            write = next(row for row in routes
                         if row['route_id'] == pair.write_route_id)
            write['initiator_instance'] = 'dma2'
            write['initiator_endpoint_id'] = 'dma2.dma.memory'
            next(row for row in bindings if row['route_id'] == pair.write_route_id)[
                'initiator']['profile_endpoint_sha256'] = digest({
                    'profile_fingerprint': profile.profile_fingerprint,
                    'endpoint_id': 'dma2.dma.memory',
                })
        else:
            rom = next(row for row in document['resources']
                       if row['resource_id'] == 'rom0')
            read = next(row for row in routes
                        if row['route_id'] == pair.read_route_id)
            extra = deepcopy(read)
            extra.update(route_id='route.rom-read',
                         target={'kind': 'persistent_memory',
                                 'component_instance': 'cpu',
                                 'resource_id': 'rom0'},
                         base=rom['base'], size=rom['size'],
                         permissions=['read'])
            routes.append(extra)
            binding = deepcopy(next(row for row in bindings
                                    if row['route_id'] == pair.read_route_id))
            binding['route_id'] = extra['route_id']
            binding['target']['resource_sha256'] = digest(rom)
            bindings.append(binding)
            routes.sort(key=lambda row: row['route_id'])
            bindings.sort(key=lambda row: row['route_id'])
        document['dma_master_routes_sha256'] = compiled_document_sha256(
            document['dma_master_routes'])
        wiring = load_path_wiring(document)
        compiled = compile_paths(replace(request, devices=devices, wiring=wiring))
        f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
        assert f6['reason']['code'] == (
            'dma-route-mover-ambiguous' if drift == 'multiple-movers'
            else 'dma-route-live-topology-binding-required')
        runner = _Runner()
        runner.sessions['dma2'] = runner.dma
        with patch('myfuzz.scenario.compiled_f6_runtime_path.build_caliptra_runtime_graph') as graph:
            with pytest.raises(CompiledF6RuntimePathError) as caught:
                prepare_compiled_f6_runtime_path(
                    compiled, wiring, runner, source=source,
                    transfer_pair=pair, artifact_links={})
            assert caught.value.code == (
                'compiled-f6-runtime-path-d3-invalid'
                if drift == 'multiple-movers'
                else 'compiled-f6-runtime-path-route-mismatch')
            graph.assert_not_called()


def _compiled_f5_probe_with_static_dma_routes(tmp_path):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.scenario.compiled_paths import compile_paths
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    from tests.scenario.test_compiled_paths import (
        ROOT, probe_device, probe_wiring,
    )
    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    profile_document = json.loads(
        (ROOT / 'configs/cpus/ibex/component_profile.json').read_text())
    interrupt = next(row for row in profile_document['endpoints']
                     if row['endpoint_id'] == 'processor.interrupts')
    interrupt['fields'][0]['width'] = 1
    cpu_profile = load_component_profile(profile_document)
    wiring_document = deepcopy(request.wiring.document)
    read_binding = next(row for row in wiring_document['dma_master_route_bindings']
                        if row['route_id'] == 'route.ram-read')
    read_binding['target']['owner_profile_fingerprint'] = \
        cpu_profile.profile_fingerprint
    base_wiring = load_path_wiring(wiring_document)
    probe = probe_device('probe_a', irq=True)
    probe_wiring_document = probe_wiring((probe,))
    delivery = replace(probe_wiring_document.deliveries[0],
                       consumer_instance='cpu')
    wiring = replace(base_wiring,
        windows=(*base_wiring.windows, *probe_wiring_document.windows),
        deliveries=(delivery,),
        environment_links=probe_wiring_document.environment_links)
    request = replace(request, cpu=replace(request.cpu, profile=cpu_profile),
                      devices=(*request.devices, probe), wiring=wiring)
    compiled = compile_paths(request)
    assert next(row for row in compiled['paths']
                if row['flow_id'] == 'F5')['status'] == 'executable'
    return request, compiled


def test_static_validator_allows_only_compiler_f5_uncontracted_event(tmp_path):
    from myfuzz.scenario.compiled_f6_dma_handoff import (
        CompiledF6DmaHandoffError, validate_compiled_f6_static,
    )
    request, compiled = _compiled_f5_probe_with_static_dma_routes(tmp_path)
    graph = compiled['runtime_dependency_graph']
    uncontracted = [edge for edge in graph['edges']
                    if (edge['rule_index'], edge['prerequisite_index']) not in {
                        (row['rule_index'], row['prerequisite_index'])
                        for row in compiled['runtime_path_contract']['edges']}]
    assert uncontracted == [{
        'rule_index': uncontracted[0]['rule_index'], 'prerequisite_index': 0,
        'prerequisite': 'F5.pin_event', 'target': 'F5.ip_irq',
        'kind': 'EVENT_ORDER'}]
    assert validate_compiled_f6_static(compiled, request.wiring.document)[
        'status'] == 'unsupported'
    missing_direct_binding = deepcopy(compiled)
    missing_direct_binding['runtime_path_contract']['edges'] = [
        row for row in missing_direct_binding['runtime_path_contract']['edges']
        if row['rule_index'] != uncontracted[0]['rule_index'] + 1]
    with pytest.raises(CompiledF6DmaHandoffError):
        validate_compiled_f6_static(missing_direct_binding,
                                    request.wiring.document)
    dual_source_drift = deepcopy(compiled)
    next(row for row in dual_source_drift['runtime_dependency_graph']['sources']
         if row['source_id'] == 'F5.pin_event')['component'] = 'sha'
    next(row for row in dual_source_drift['runtime_path_contract']['nodes']
         if row['node_id'] == 'F5.pin_event')['component'] = 'sha'
    dual_source_drift['runtime_path_contract']['graph_sha256'] = digest(
        dual_source_drift['runtime_dependency_graph'])
    with pytest.raises(CompiledF6DmaHandoffError):
        validate_compiled_f6_static(dual_source_drift, request.wiring.document)
    renamed_pin = deepcopy(compiled)
    graph = renamed_pin['runtime_dependency_graph']
    next(row for row in graph['sources'] if row['source_id'] == 'F5.pin_event')[
        'source_id'] = 'F5.ghost'
    for rule in graph['rules']:
        rule['prerequisites'] = [
            'F5.ghost' if value == 'F5.pin_event' else value
            for value in rule['prerequisites']]
    for edge in graph['edges']:
        if edge['prerequisite'] == 'F5.pin_event':
            edge['prerequisite'] = 'F5.ghost'
    next(row for row in renamed_pin['runtime_path_contract']['nodes']
         if row['node_id'] == 'F5.pin_event')['node_id'] = 'F5.ghost'
    renamed_pin['runtime_path_contract']['nodes'].sort(
        key=lambda row: row['node_id'])
    renamed_pin['runtime_path_contract']['edges'].append({
        'rule_index': uncontracted[0]['rule_index'],
        'prerequisite_index': 0, 'relation': 'causal_order',
        'initiator_component': None, 'device_id': None,
        'base': None, 'size': None, 'resource_component': None,
        'resource_id': None,
    })
    renamed_pin['runtime_path_contract']['edges'].sort(
        key=lambda row: (row['rule_index'], row['prerequisite_index']))
    renamed_pin['runtime_path_contract']['graph_sha256'] = digest(graph)
    with pytest.raises(CompiledF6DmaHandoffError):
        validate_compiled_f6_static(renamed_pin, request.wiring.document)
    duplicate_f5 = deepcopy(compiled)
    graph = duplicate_f5['runtime_dependency_graph']
    index = len(graph['rules'])
    graph['rules'].append({
        'rule_index': index, 'target': 'F5.ip_irq',
        'prerequisites': ['F5.pin_event'], 'kind': 'EVENT_ORDER',
    })
    graph['edges'].append({
        'rule_index': index, 'prerequisite_index': 0,
        'prerequisite': 'F5.pin_event', 'target': 'F5.ip_irq',
        'kind': 'EVENT_ORDER',
    })
    duplicate_f5['runtime_path_contract']['graph_sha256'] = digest(graph)
    with pytest.raises(CompiledF6DmaHandoffError):
        validate_compiled_f6_static(duplicate_f5, request.wiring.document)


def test_static_validator_refuses_unrelated_uncontracted_event(tmp_path):
    from unittest.mock import patch
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    graph = compiled['runtime_dependency_graph']
    index = len(graph['rules'])
    graph['rules'].append({
        'rule_index': index, 'target': 'F5.irq_event',
        'prerequisites': ['F1.program_image'], 'kind': 'EVENT_ORDER',
    })
    graph['edges'].append({
        'rule_index': index, 'prerequisite_index': 0,
        'prerequisite': 'F1.program_image', 'target': 'F5.irq_event',
        'kind': 'EVENT_ORDER',
    })
    compiled['runtime_path_contract']['graph_sha256'] = digest(graph)
    compiled['runtime_path_contract']['nodes'].append({
        'node_id': 'F5.irq_event', 'component': 'cpu', 'kind': 'logical',
        'port': None, 'bit_offset': 0, 'width': None,
    })
    compiled['runtime_path_contract']['nodes'].sort(key=lambda row: row['node_id'])
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   0x1000, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    with patch('myfuzz.scenario.compiled_f6_runtime_path.build_caliptra_runtime_graph') as builder:
        with pytest.raises(CompiledF6RuntimePathError):
            prepare_compiled_f6_runtime_path(
                compiled, request.wiring, object(), source=source,
                transfer_pair=pair, artifact_links={})
        builder.assert_not_called()


def test_static_validator_closes_register_claim_even_when_both_copies_drift(tmp_path):
    from myfuzz.scenario.compiled_f6_dma_handoff import (
        CompiledF6DmaHandoffError, validate_compiled_f6_static,
    )
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    from tests.scenario.test_compiled_paths import (
        SOC_RENDER_REQUEST, compile_document,
    )
    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    emitted = compile_document(SOC_RENDER_REQUEST, sources=[{
        'source_id': 'gpio.paddir', 'flow_id': 'F4', 'origin': 'fuzzable',
        'component': 'pulp_gpio', 'endpoint_id': 'gpio.bus',
        'register': 'PADDIR', 'field': 'value', 'mask': 0xffff,
    }])
    claim = deepcopy(emitted['declared_register_field_constraints'][0])
    compiled['declared_register_field_constraints'].append(claim)
    next(row for row in compiled['paths'] if row['flow_id'] == 'F4')[
        'constraints']['register_field_constraints'].append(deepcopy(claim))
    assert validate_compiled_f6_static(compiled, request.wiring.document)[
        'status'] == 'unsupported'
    compiled['declared_register_field_constraints'][0]['unexpected'] = True
    next(row for row in compiled['paths'] if row['flow_id'] == 'F4')[
        'constraints']['register_field_constraints'][0]['unexpected'] = True
    with pytest.raises(CompiledF6DmaHandoffError):
        validate_compiled_f6_static(compiled, request.wiring.document)


def test_public_compiler_refuses_owner_region_and_provider_drift(tmp_path):
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3,
    )
    from tests.scenario.test_dma_intent_topology_binding import generated_instance
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger
    from tests.scenario.test_caliptra_sha256_dma_paths import (
        _Runner, _ShaSession, SHA_BASE, SHA_SIZE,
    )
    RAM_BASE, RAM_SIZE = 0x1000, 0x1000
    _, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(tmp_path)
    links = {'dma': generated_instance('dma').endpoint_links_document()}
    source = DmaTransferSourceWord('cpu', 'ram', 'dma_payload',
                                   RAM_BASE, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    def check(mutator, match, case_source=source):
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
            initialization_seed=23, max_initialized_bytes=RAM_SIZE)
        runner = _Runner(memory=memory)
        mutator(runner)
        with pytest.raises(ValueError, match=match):
            prepare_compiled_f6_runtime_path(
                compiled, request.wiring, runner, source=case_source,
                transfer_pair=pair, artifact_links=links)
    check(lambda r: setattr(r.dma, 'memory_service', object()), 'shared memory service')
    check(lambda r: setattr(r.dma.memory_service, 'ledger', object()), 'shared memory service')
    check(lambda r: setattr(r.cpu, 'memory', PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=23, max_initialized_bytes=RAM_SIZE)),
        'shared memory service')
    check(lambda r: setattr(r.dma, 'memory_service', MemoryService(
        PersistentMemory(regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
            initialization_seed=23, max_initialized_bytes=RAM_SIZE),
        TransactionLedger())), 'shared memory service')
    check(lambda r: setattr(r.memory, '_regions', ()), 'missing or ambiguous')
    check(lambda r: setattr(r.memory, '_regions', r.memory._regions * 2),
          'missing or ambiguous')
    check(lambda r: setattr(r.memory, '_regions', (
        MemoryRegion('ram', RAM_BASE, RAM_SIZE, readable=False),)), 'not readable')
    check(lambda r: setattr(r.dma, 'master_targets', []), 'immutable typed tuple')
    check(lambda r: setattr(r.dma, 'master_targets', r.dma.master_targets * 2),
          'missing or ambiguous')
    check(lambda r: setattr(r.dma, 'master_targets', (
        MasterTargetWindow('sha', SHA_BASE, SHA_SIZE, _ShaSession(),
            (16,), (5,)),)), 'registered SHA session')
    check(lambda r: setattr(r.sha, 'dma_master_target_access', None), 'keyed DMA')
    check(lambda r: setattr(r.sha, 'dma_master_target_provider_identity_document',
                            None), 'provider identity')
    check(lambda r: setattr(r.sha, 'dma_master_target_provider_identity_document',
                            lambda: {'schema_version': 'wrong'}),
          'identity is unsupported')
    check(lambda r: setattr(r.sha.artifact, 'runtime_document', {}),
          'protocol trace')
    check(lambda r: r.sha.artifact.runtime_document['base_protocol_trace'].pop(
        'schema_version'), 'protocol trace')
    check(lambda r: r.sha.artifact.runtime_document['base_protocol_trace'].pop(
        'signals'), 'protocol trace')
    check(lambda r: r.sha.artifact.runtime_document['base_protocol_trace'].pop(
        'signal_widths'), 'protocol trace')
    check(lambda r: r.sha.artifact.runtime_document['base_protocol_trace'][
        'signal_widths'].__setitem__('hsel', True), 'protocol trace')
    def corrupt_trace_before_provider(runner):
        runner.sha.artifact.runtime_document['base_protocol_trace'][
            'signal_widths']['hsel'] = True
        runner.sha.dma_master_target_provider_identity_document = lambda: (
            (_ for _ in ()).throw(AssertionError('provider identity called')))
    check(corrupt_trace_before_provider, 'protocol trace')
    check(lambda r: setattr(r.dma, 'master_targets', (
        MasterTargetWindow('sha', SHA_BASE, SHA_SIZE, r.sha,
            (20,), (5,)),)), 'full-word CTRL')
    def mutate_window(runner, name, value):
        object.__setattr__(runner.dma.master_targets[0], name, value)
    check(lambda r: mutate_window(r, 'accepted_write_values', (4,)),
          'full-word CTRL')
    check(lambda r: mutate_window(r, 'writable_offsets', (20,)),
          'full-word CTRL')
    check(lambda r: mutate_window(r, 'readable_offsets', (0,)),
          'full-word CTRL')
    check(lambda r: mutate_window(r, 'byte_enable', 1),
          'full-word CTRL')
    check(lambda r: setattr(r.memory, '_regions', (
        MemoryRegion('ram', RAM_BASE, RAM_SIZE // 2),)),
        'source-outside-ram', replace(source, address=RAM_BASE + RAM_SIZE // 2))
    check(lambda r: None, 'route-mismatch',
          replace(source, address=RAM_BASE + RAM_SIZE))


def rehash_outer(document):
    document['identity_sha256'] = digest({key: value for key, value
                                           in document.items()
                                           if key != 'identity_sha256'})


def rehash_nested_handoff(document, *, rehash_d3=False):
    handoff = document['compiled_f6_handoff']
    if rehash_d3:
        handoff['compiled_paths_sha256'] = compiled_document_sha256(
            handoff['compiled_paths'])
    declaration = handoff['declaration']
    declaration['identity_sha256'] = digest({
        key: value for key, value in declaration.items()
        if key != 'identity_sha256'})
    handoff['declaration_sha256'] = declaration['identity_sha256']
    handoff['identity_sha256'] = digest({
        key: value for key, value in handoff.items()
        if key != 'identity_sha256'})
    rehash_outer(document)


def rehash_selection_path_id(prepared):
    selection = prepared['selections'][0]
    graph = DependencyGraph.from_edge_document(prepared['graph'])
    path = DependencyPath(
        selection['target'], tuple(selection['source_ids']),
        tuple(DependencyEdge(**row) for row in selection['edges']))
    selection['path_id'] = graph.path_identity(
        path, direction=selection['direction'])


def refuse(reader, document, code, pointer):
    with pytest.raises(CompiledF6RuntimePathError) as caught:
        reader.from_document(document)
    assert (caught.value.code, caught.value.pointer) == (code, pointer)


def test_descriptors_round_trip_to_detached_canonical_documents():
    source = DmaTransferSourceWord.from_document(source_document())
    pair = DmaTransferRoutePair.from_document(pair_document())
    assert source.document() == source_document()
    assert pair.document() == pair_document()
    source.document()['image_id'] = 'changed'
    pair.document()['read_route_id'] = 'changed'
    assert source.document() == source_document()
    assert pair.document() == pair_document()


def test_public_descriptor_constructors_enforce_reader_invariants():
    with pytest.raises(CompiledF6RuntimePathError) as bad_source:
        DmaTransferSourceWord('cpu', 'ram', 'image', 3, 4, 15, 'CPU_TO_IP')
    assert (bad_source.value.code, bad_source.value.pointer) == (
        'compiled-f6-runtime-path-source-invalid', '/address')

    with pytest.raises(CompiledF6RuntimePathError) as bad_pair:
        DmaTransferRoutePair('route.same', 'route.same', 'same_word_value')
    assert (bad_pair.value.code, bad_pair.value.pointer) == (
        'compiled-f6-runtime-path-pair-invalid', '/write_route_id')


@pytest.mark.parametrize(('field', 'value', 'pointer'), [
    ('memory_component', '', '/memory_component'),
    ('resource_id', ' ram', '/resource_id'),
    ('image_id', None, '/image_id'),
    ('address', True, '/address'),
    ('address', -4, '/address'),
    ('address', 3, '/address'),
    ('address', 1 << 64, '/address'),
    ('word_bytes', True, '/word_bytes'),
    ('word_bytes', 8, '/word_bytes'),
    ('byte_enable', False, '/byte_enable'),
    ('byte_enable', 7, '/byte_enable'),
    ('direction', 'IP_TO_CPU', '/direction'),
])
def test_source_rejects_invalid_fields(field, value, pointer):
    document = source_document()
    document[field] = value
    refuse(DmaTransferSourceWord, document,
           'compiled-f6-runtime-path-source-invalid', pointer)


@pytest.mark.parametrize('mutate', [
    lambda d: d.pop('image_id'),
    lambda d: d.update(unexpected=True),
])
def test_source_rejects_nonclosed_shape(mutate):
    document = source_document()
    mutate(document)
    refuse(DmaTransferSourceWord, document,
           'compiled-f6-runtime-path-source-schema-invalid', '/')


def test_source_allows_last_aligned_unsigned_64_bit_address():
    document = source_document()
    document['address'] = (1 << 64) - 4
    assert DmaTransferSourceWord.from_document(document).address == (1 << 64) - 4


@pytest.mark.parametrize(('field', 'value', 'pointer'), [
    ('read_route_id', '', '/read_route_id'),
    ('write_route_id', ' route.write', '/write_route_id'),
    ('write_route_id', 'route.ram-read', '/write_route_id'),
    ('relation', 'copy_word', '/relation'),
])
def test_pair_rejects_invalid_fields(field, value, pointer):
    document = pair_document()
    document[field] = value
    refuse(DmaTransferRoutePair, document,
           'compiled-f6-runtime-path-pair-invalid', pointer)


@pytest.mark.parametrize('mutate', [
    lambda d: d.pop('relation'),
    lambda d: d.update(unexpected=True),
])
def test_pair_rejects_nonclosed_shape(mutate):
    document = pair_document()
    mutate(document)
    refuse(DmaTransferRoutePair, document,
           'compiled-f6-runtime-path-pair-schema-invalid', '/')


def test_artifact_reader_round_trips_deterministic_caliptra_handoff():
    document = artifact_document()
    path = CompiledF6RuntimePath.from_document(document)
    assert path.document() == document
    assert path.identity_sha256 == document['identity_sha256']
    assert path.source.document() == source_document()
    assert path.transfer_pair.document() == pair_document()
    assert path.handoff.document() == document['compiled_f6_handoff']
    assert path.handoff._declaration._prepared_runtime_paths is not None
    document['source']['address'] = 0
    assert path.document()['source']['address'] == 65792


def test_runtime_path_artifact_cannot_be_constructed_without_validation():
    path = CompiledF6RuntimePath.from_document(artifact_document())
    with pytest.raises(TypeError):
        CompiledF6RuntimePath(b'{}', path.source, path.transfer_pair,
                              path.handoff)


def test_artifact_rejects_outer_digest_tampering():
    document = artifact_document()
    document['source']['image_id'] = 'different'
    refuse(CompiledF6RuntimePath, document,
           'compiled-f6-runtime-path-identity-mismatch', '/identity_sha256')


@pytest.mark.parametrize('mutate', [
    lambda d: d.pop('source'),
    lambda d: d.update(extra=True),
])
def test_artifact_rejects_nonclosed_outer_shape(mutate):
    document = artifact_document()
    mutate(document)
    refuse(CompiledF6RuntimePath, document,
           'compiled-f6-runtime-path-schema-invalid', '/')


@pytest.mark.parametrize(('path', 'value'), [
    (('compiled_paths_sha256',), '0' * 64),
    (('compiled_paths', 'paths', 'F6', 'status'), 'executable'),
    (('compiled_paths', 'paths', 'F6', 'reason', 'code'), 'different'),
])
def test_artifact_rejects_changed_nested_d3_refusal(path, value):
    document = artifact_document()
    nested = document['compiled_f6_handoff']
    if path[0] == 'compiled_paths_sha256':
        nested[path[0]] = value
    else:
        nested = nested['compiled_paths']
        for key in path[1:-1]:
            if key == 'F6':
                nested = next(row for row in nested
                              if row['flow_id'] == 'F6')
            else:
                nested = nested[key]
        nested[path[-1]] = value
    if path[0] == 'compiled_paths_sha256':
        rehash_nested_handoff(document)
    else:
        rehash_nested_handoff(document, rehash_d3=True)
    with pytest.raises(CompiledF6RuntimePathError) as caught:
        CompiledF6RuntimePath.from_document(document)
    assert caught.value.code == 'compiled-f6-runtime-path-handoff-invalid'
    assert caught.value.pointer.startswith('/compiled_f6_handoff/')


def test_artifact_rejects_static_dma_edge_even_with_outer_digest_rebuilt():
    document = artifact_document()
    graph = document['compiled_f6_handoff']['compiled_paths'][
        'runtime_dependency_graph']
    graph['edges'].append(dict(kind='DMA_MASTER_TRANSFER', rule_index=0,
                               prerequisite_index=0, prerequisite='a', target='b'))
    rehash_nested_handoff(document, rehash_d3=True)
    with pytest.raises(CompiledF6RuntimePathError) as caught:
        CompiledF6RuntimePath.from_document(document)
    assert caught.value.code == 'compiled-f6-runtime-path-handoff-invalid'


@pytest.mark.parametrize(('mutate', 'code', 'pointer'), [
    (lambda d: d['graph']['sources'][0].update(port='other-image'),
     'compiled-f6-runtime-path-graph-mismatch',
     '/compiled_f6_handoff/declaration/prepared_runtime_paths/graph'),
    (lambda d: d['contract']['nodes'][-1].update(kind='logical'),
     'compiled-f6-runtime-path-contract-mismatch',
     '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract/nodes'),
    (lambda d: d['contract']['edges'][1].update(relation='direct_binding'),
     'compiled-f6-runtime-path-contract-mismatch',
     '/compiled_f6_handoff/declaration/prepared_runtime_paths/contract/edges'),
])
def test_artifact_rejects_nonfixed_prepared_graph_or_contract(mutate, code, pointer):
    document = artifact_document()
    prepared = document['compiled_f6_handoff']['declaration'][
        'prepared_runtime_paths']
    mutate(prepared)
    prepared['contract']['graph_sha256'] = digest(prepared['graph'])
    if prepared['graph']['sources'][0]['port'] == 'other-image':
        rehash_selection_path_id(prepared)
    rehash_nested_handoff(document)
    with pytest.raises(CompiledF6RuntimePathError) as caught:
        CompiledF6RuntimePath.from_document(document)
    assert (caught.value.code, caught.value.pointer) == (code, pointer)


@pytest.mark.parametrize('mutate', [
    lambda rows: rows.pop(),
    lambda rows: rows.append(deepcopy(rows[0])),
    lambda rows: rows.reverse(),
])
def test_artifact_rejects_missing_duplicate_or_unsorted_route_links(mutate):
    document = artifact_document()
    mutate(document['compiled_f6_handoff']['declaration']['route_links'])
    rehash_nested_handoff(document)
    with pytest.raises(CompiledF6RuntimePathError) as caught:
        CompiledF6RuntimePath.from_document(document)
    assert caught.value.code == 'compiled-f6-runtime-path-handoff-invalid'


@pytest.mark.parametrize(('mutate', 'pointer'), [
    (lambda d: d['transfer_pair'].update(
        read_route_id='route.caliptra-ctrl',
        write_route_id='route.ram-read'), '/transfer_pair/read_route_id'),
    (lambda d: d['transfer_pair'].update(
        write_route_id='route.unknown'), '/transfer_pair/write_route_id'),
])
def test_artifact_requires_explicit_read_write_edge_mapping(mutate, pointer):
    document = artifact_document()
    mutate(document)
    rehash_outer(document)
    refuse(CompiledF6RuntimePath, document,
           'compiled-f6-runtime-path-route-mismatch', pointer)


def test_artifact_rejects_source_outside_static_read_route():
    document = artifact_document()
    document['source']['address'] = 0x40000
    rehash_outer(document)
    refuse(CompiledF6RuntimePath, document,
           'compiled-f6-runtime-path-route-mismatch', '/source/address')


def test_artifact_rejects_nonfinite_outer_json():
    document = artifact_document()
    document['source']['address'] = float('nan')
    refuse(CompiledF6RuntimePath, document,
           'compiled-f6-runtime-path-invalid-json', '/source/address')


def test_artifact_rejects_deep_json_with_stable_refusal():
    document = artifact_document()
    nested = []
    for _ in range(sys.getrecursionlimit() + 100):
        nested = [nested]
    document['compiled_f6_handoff']['compiled_paths']['gaps'] = nested
    refuse(CompiledF6RuntimePath, document,
           'compiled-f6-runtime-path-invalid-json', '/')


def test_static_validator_accepts_only_reconstructed_executable_f2_contract(tmp_path):
    from myfuzz.scenario.compiled_f6_dma_handoff import (
        CompiledF6DmaHandoffError, validate_compiled_f6_static)

    request, compiled = _compiled_f5_probe_with_static_dma_routes(tmp_path)
    f2 = next(row for row in compiled['paths'] if row['flow_id'] == 'F2')
    assert f2['status'] == 'executable'
    assert f2['execution_contract']['schema_version'] == 'compiled_F2_read_contract.v1'
    assert validate_compiled_f6_static(compiled, request.wiring.document)['status'] == 'unsupported'
    for mutation in ('changed', 'missing', 'extra'):
        changed = deepcopy(compiled)
        row = next(item for item in changed['paths'] if item['flow_id'] == 'F2')
        if mutation == 'changed':
            row['execution_contract']['address'] += 4
        elif mutation == 'missing':
            row.pop('execution_contract')
        else:
            row['unexpected'] = True
        with pytest.raises(CompiledF6DmaHandoffError):
            validate_compiled_f6_static(changed, request.wiring.document)
