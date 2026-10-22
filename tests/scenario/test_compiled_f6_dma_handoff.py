"""Static compiled F6 result must stay joined to its exact D4 declaration."""
from copy import deepcopy
import json

import pytest

from myfuzz.scenario.compiled_f6_dma_handoff import (
    CompiledF6DmaHandoffError,
    CompiledF6DmaHandoff,
    prepare_compiled_f6_dma_handoff,
)
from myfuzz.scenario.compiled_paths import (
    FLOW_DEFINITIONS, FLOW_IDS, compiled_document_sha256,
)
from tests.scenario.test_dma_intent_topology_binding import (
    digest, fixture, prepare_dma_intent_binding,
)


F6_REFUSAL = 'dma-route-live-topology-binding-required'


def _compiled_f6_for(wiring):
    declaration_wiring = wiring.document
    route_ids = [row['route_id'] for row in declaration_wiring['dma_master_routes']['routes']]
    binding_digest = digest(declaration_wiring['dma_master_route_bindings'])
    empty_graph = {
        'schema_version': 'dependency_edge_graph.v1',
        'sources': [], 'rules': [], 'edges': [],
    }
    paths = []
    for flow in FLOW_IDS:
        reason = ({
            'code': F6_REFUSAL, 'pointer': '/wiring/dma_master_routes',
            'detail': {
                'requires': 'bind every static intent before runtime DMA edges',
                'route_ids': route_ids,
                'intent_sha256': wiring.dma_master_routes_sha256,
            },
        } if flow == 'F6' else {
            'code': 'test-static-unsupported', 'pointer': '/paths',
            'detail': {'flow_id': flow},
        })
        paths.append({
            'path_id': f'{flow}:cpu.dma', 'flow_id': flow,
            'flow_name': FLOW_DEFINITIONS[flow]['name'],
            'definition': dict(FLOW_DEFINITIONS[flow]),
            'status': 'unsupported',
            'reason': {**reason, 'missing': [dict(reason)]},
            'target': {'component': 'cpu', 'node': f'{flow}.effect'},
            'direction': 'CPU_TO_IP', 'endpoints': [], 'sources': [],
            'bound_inputs': [], 'constraints': {
                'schema_version': 'soc_input_constraints.v1',
                'policy_hash': 'sha256:' + 'b' * 64, 'layout_hash': None,
                'rule_ids': [], 'rules': [],
                'register_field_constraints': [], 'source_constraints': [],
            }, 'prerequisites': [],
            'termination_observation': {}, 'seed': {},
            'assertions': [], 'runtime_path_identity': None,
            'not_claimed': [],
        })
    return {
        'schema_version': 'compiled_paths.v1',
        'identity': {
            'cpu': {
                'instance_id': 'cpu', 'component_id': 'test-cpu',
                'kind': 'processor', 'profile_fingerprint': 'sha256:' + 'a' * 64,
                'sidecar_fingerprint': None, 'sidecar_schema_version': None,
            },
            'devices': [],
            'wiring': {
                'schema_version': wiring.schema_version,
                'declared_sections': list(wiring.declared_sections),
                'absent_sections': list(wiring.absent_sections),
                'dma_master_routes_sha256': wiring.dma_master_routes_sha256,
                'dma_master_route_bindings_sha256': binding_digest,
            },
            'request_sha256': None,
        },
        'flow_definitions': {flow: dict(FLOW_DEFINITIONS[flow])
                             for flow in FLOW_IDS},
        'paths': paths,
        'counts': {'executable': 0, 'unsupported': len(paths),
                   'total': len(paths)},
        'declared_source_claims': [],
        'declared_register_field_constraints': [],
        'input_constraints': {
            'schema_version': 'soc_input_constraints.v1',
            'policy_hash': 'sha256:' + 'b' * 64,
            'drive_profile': 'cpu_execute', 'bus_owner': 'cpu',
            'layout_hash': None, 'layout': None, 'rules': [],
            'closure': [], 'cycles': [], 'dut_owned_inputs': [], 'gaps': [],
        },
        'runtime_dependency_graph': empty_graph,
        'runtime_path_contract': {
            'schema_version': 'runtime_path_contract.v1',
            'graph_sha256': digest(empty_graph),
            'nodes': [],
            'edges': [],
        },
        'runtime_path_contract_omissions': [],
        'gaps': [],
        'not_claimed': [],
    }


def _fixture():
    wiring, prepared, route_links = fixture()
    declaration = prepare_dma_intent_binding(wiring, prepared,
                                              route_links=route_links)
    return wiring, declaration, _compiled_f6_for(wiring)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def test_compiled_f6_handoff_accepts_exact_static_refusal():
    wiring, declaration, compiled = _fixture()

    handoff = prepare_compiled_f6_dma_handoff(compiled, declaration)
    document = handoff.document()

    assert document['schema_version'] == 'compiled_f6_dma_handoff.v1'
    assert document['compiled_paths'] == compiled
    assert document['compiled_paths_sha256'] == compiled_document_sha256(compiled)
    assert document['f6']['status'] == 'unsupported'
    assert document['f6']['reason_code'] == F6_REFUSAL
    assert document['f6']['route_ids'] == [row.route_id for row in wiring.dma_master_routes]
    assert document['wiring']['dma_master_routes_sha256'] == wiring.dma_master_routes_sha256
    assert handoff.identity_sha256 == document['identity_sha256']
    assert document['declaration'] == declaration.document()
    handoff.validate()
    restored = CompiledF6DmaHandoff.from_document(document)
    restored.validate()
    assert restored.document() == document
    document['compiled_paths']['paths'][-1]['reason']['detail']['route_ids'].clear()
    assert handoff.document()['f6']['route_ids'] == [
        row.route_id for row in wiring.dma_master_routes]


def test_compiled_f6_handoff_accepts_canonical_v2_dependency_graph():
    _wiring, declaration, compiled = _fixture()
    f1 = compiled['paths'][0]
    f1['path_id'] = 'F1:ram.image'
    f1['status'] = 'executable'
    f1['reason'] = {
        'code': None, 'pointer': None, 'detail': None, 'missing': [],
    }
    f1['sources'] = [{
        'source_id': 'ram.image', 'origin': 'fuzzable',
        'kind': 'instruction_image', 'component': 'cpu',
        'endpoint_id': 'processor.instruction', 'port': 'ram',
        'bit_offset': 0, 'width': 32, 'register': None, 'field': None,
        'mask': 0xffffffff, 'alignment': 4, 'range': [0x1000, 0x1fff],
        'origin_ref': 'wiring:test', 'constraint_basis': 'test instruction image',
    }]
    f1['constraints']['source_constraints'] = [{
        key: f1['sources'][0][key] for key in (
            'source_id', 'origin', 'kind', 'width', 'bit_offset', 'mask',
            'alignment', 'range', 'constraint_basis')
    }]
    compiled['counts'] = {'executable': 1, 'unsupported': 5, 'total': 6}
    compiled['runtime_dependency_graph'] = {
        'schema_version': 'dependency_edge_graph.v2',
        'sources': [{
            'source_id': 'F1.program_image', 'component': 'cpu', 'port': 'ram',
            'bit_offset': 0, 'width': 32,
            'directions': ['CPU_TO_IP'], 'kind': 'memory_image',
            'image_address': 0x1000,
        }],
        'rules': [{
            'rule_index': 0, 'target': 'cpu.retire',
            'prerequisites': ['F1.program_image'], 'kind': 'PERSISTENT_STATE_RULE',
        }],
        'edges': [{
            'rule_index': 0, 'prerequisite_index': 0,
            'prerequisite': 'F1.program_image', 'target': 'cpu.retire',
            'kind': 'PERSISTENT_STATE_RULE',
        }],
    }
    compiled['runtime_path_contract'] = {
        'schema_version': 'runtime_path_contract.v1',
        'graph_sha256': digest(compiled['runtime_dependency_graph']),
        'nodes': [
            {'node_id': 'F1.program_image', 'component': 'cpu', 'kind': 'state',
             'port': None, 'bit_offset': 0, 'width': None},
            {'node_id': 'cpu.retire', 'component': 'cpu', 'kind': 'logical',
             'port': None, 'bit_offset': 0, 'width': None},
        ],
        'edges': [{
            'rule_index': 0, 'prerequisite_index': 0,
            'relation': 'persistent_state', 'initiator_component': None,
            'device_id': None, 'base': None, 'size': None,
            'resource_component': 'cpu', 'resource_id': 'ram',
        }],
    }

    handoff = prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert handoff.document()['compiled_paths']['runtime_dependency_graph'] \
        == compiled['runtime_dependency_graph']


@pytest.mark.parametrize('field', [
    'dma_master_routes_sha256',
    'dma_master_route_bindings_sha256',
])
def test_compiled_f6_handoff_rejects_wiring_digest_mismatch(field):
    _wiring, declaration, compiled = _fixture()
    compiled['identity']['wiring'][field] = '0' * 64

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-wiring-mismatch'
    assert caught.value.pointer.startswith('/compiled_paths/identity/wiring')


@pytest.mark.parametrize(('field', 'value'), [
    ('status', 'executable'),
    ('runtime_path_identity', {'identity_sha256': 'a' * 64}),
])
def test_compiled_f6_handoff_rejects_executable_or_runtime_path(field, value):
    _wiring, declaration, compiled = _fixture()
    compiled['paths'][-1][field] = value

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-static-f6-required'


def test_compiled_f6_handoff_requires_explicit_null_runtime_identity():
    _wiring, declaration, compiled = _fixture()
    del compiled['paths'][-1]['runtime_path_identity']

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-static-f6-required'


def test_compiled_f6_handoff_rejects_wrong_reason_and_route_set():
    wiring, declaration, compiled = _fixture()
    compiled['paths'][-1]['reason']['code'] = 'dma-master-route-undeclared'

    with pytest.raises(CompiledF6DmaHandoffError) as wrong_reason:
        prepare_compiled_f6_dma_handoff(compiled, declaration)
    assert wrong_reason.value.code == 'compiled-f6-handoff-static-f6-required'

    compiled = _compiled_f6_for(wiring)
    compiled['paths'][-1]['reason']['detail']['route_ids'].pop()
    with pytest.raises(CompiledF6DmaHandoffError) as wrong_routes:
        prepare_compiled_f6_dma_handoff(compiled, declaration)
    assert wrong_routes.value.code == 'compiled-f6-handoff-route-set-mismatch'


@pytest.mark.parametrize('mutation', [
    lambda row: row['paths'][-1]['reason'].pop('missing'),
    lambda row: row['paths'][-1]['reason'].update(missing=[]),
    lambda row: row['paths'][-1]['reason']['missing'][0].update(
        code='dma-master-route-undeclared'),
])
def test_compiled_f6_handoff_rejects_mismatched_missing_reason(mutation):
    _wiring, declaration, compiled = _fixture()
    mutation(compiled)

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-static-f6-required'


def test_compiled_f6_handoff_reader_rejects_unknown_keys_and_bad_digests():
    _wiring, declaration, compiled = _fixture()
    document = prepare_compiled_f6_dma_handoff(compiled, declaration).document()

    for mutate in (
        lambda row: row.update(unknown=True),
        lambda row: row.update(identity_sha256='0' * 64),
        lambda row: row.update(compiled_paths_sha256='0' * 64),
        lambda row: row['declaration'].update(unknown=True),
    ):
        broken = deepcopy(document)
        mutate(broken)
        with pytest.raises(CompiledF6DmaHandoffError):
            CompiledF6DmaHandoff.from_document(broken)


@pytest.mark.parametrize('mutation', [
    lambda row: row.pop('runtime_dependency_graph'),
    lambda row: row.update(runtime_dependency_graph=None),
    lambda row: row.update(runtime_path_contract=None),
    lambda row: row['runtime_dependency_graph'].pop('edges'),
    lambda row: row['runtime_dependency_graph'].update(edges=[None]),
    lambda row: row['runtime_dependency_graph'].update(
        edges=[{'kind': 'OTHER', 'relation': 'DMA_MASTER_TRANSFER'}]),
    lambda row: row['runtime_dependency_graph'].update(
        edges=[{'kind': 'OTHER', 'relation': 'dma_master_route'}]),
    lambda row: row['runtime_path_contract'].update(edges=[{
        'rule_index': 0, 'prerequisite_index': 0,
        'relation': 'dma_master_route', 'initiator_component': None,
        'device_id': None, 'base': None, 'size': None,
        'resource_component': None, 'resource_id': None,
    }]),
    lambda row: row['runtime_path_contract'].update(edges=['not-an-edge']),
])
def test_compiled_f6_handoff_rejects_missing_or_malformed_static_graph(mutation):
    _wiring, declaration, compiled = _fixture()
    mutation(compiled)
    with pytest.raises(CompiledF6DmaHandoffError):
        prepare_compiled_f6_dma_handoff(compiled, declaration)


def test_compiled_f6_handoff_rejects_runtime_contract_dma_routes():
    _wiring, declaration, compiled = _fixture()
    _wiring, prepared, _route_links = fixture()
    compiled['runtime_path_contract'] = {
        'schema_version': 'runtime_path_contract.v2',
        'graph_sha256': '0' * 64,
        'nodes': [],
        'edges': [],
        'dma_master_routes': [route.document()
                              for route in prepared.contract.dma_master_routes],
    }

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-static-f6-required'


def test_compiled_f6_handoff_rejects_dma_dependency_rule_without_static_path():
    _wiring, declaration, compiled = _fixture()
    compiled['runtime_dependency_graph'] = {
        'schema_version': 'dependency_edge_graph.v1',
        'sources': [{
            'source_id': 'src', 'component': 'cpu', 'port': 'ram',
            'bit_offset': 0, 'width': 32,
            'directions': ['CPU_TO_IP'], 'kind': 'source',
        }],
        'rules': [{
            'rule_index': 0, 'target': 'dma.tx',
            'prerequisites': ['src'], 'kind': 'DMA_MASTER_TRANSFER',
        }],
        'edges': [{
            'rule_index': 0, 'prerequisite_index': 0,
            'prerequisite': 'src', 'target': 'dma.tx',
            'kind': 'DMA_MASTER_TRANSFER',
        }],
    }

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-static-f6-required'


@pytest.mark.parametrize('field', ['declared_sections', 'absent_sections'])
def test_compiled_f6_handoff_rejects_wiring_section_identity_mismatch(field):
    _wiring, declaration, compiled = _fixture()
    compiled['identity']['wiring'][field].append('invented-section')

    with pytest.raises(CompiledF6DmaHandoffError) as caught:
        prepare_compiled_f6_dma_handoff(compiled, declaration)

    assert caught.value.code == 'compiled-f6-handoff-wiring-mismatch'
