"""Actual compiled session wiring, stopped before any native build/start."""
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.integration.compiled_f4 import CompiledF4Runtime
from myfuzz.scenario.session_runtime import ScenarioSession
from tests.integration.test_compiled_f4_storage_producer import timer_loaded

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def inputs(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('bound-f4-wiring'))


@pytest.fixture(autouse=True)
def source_backed_prebuild_boundary():
    from tests.integration.test_compiled_f4_built_wiring import fake_preparation
    with fake_preparation():
        yield


class BeforeNative(Exception):
    pass


def test_compiler_f4_mmio_response_node_belongs_to_declared_target(inputs):
    _artifacts, values = inputs
    path = next(row for row in values['compiled']['paths'] if row['flow_id']=='F4')
    stream = next(row for row in path['sources'] if row['kind']=='cpu_mmio_stream')
    nodes = values['compiled']['runtime_path_contract']['nodes']
    target = next(row for row in nodes if row['node_id']==path['target']['node'])
    assert target['component'] == stream['register_access']['target_component']
    assert path['target']['component'] == target['component']


def test_actual_session_has_selected_contract_and_source_before_begin(inputs, tmp_path):
    artifacts, values = inputs
    captured = []

    def inspect_before_begin(session):
        assert session.runtime_contract is not None, 'F4 session contract missing'
        assert len(session.runtime_path_ids) == 1
        bindings = session.instruction_image_binding_documents
        assert len(bindings) == 1
        assert bindings[0]['path_id'] == session.runtime_path_ids[0]
        assert bindings[0]['memory_id'] == 'ram'
        assert bindings[0]['base'] == 0x10000
        assert bindings[0]['size'] == 0x30000
        from myfuzz.integration.compiled_rfuzz import build_compiled_rfuzz_executor
        runtime = session.checker.__self__
        executor = build_compiled_rfuzz_executor(runtime, run_id='prebegin')
        assert executor.runtime_path_status == 'contract_preflight'
        assert executor.runtime_contract == session.runtime_contract
        captured.append(session.runtime_path_document)
        raise BeforeNative

    with patch.object(ScenarioSession, 'begin', inspect_before_begin):
        with pytest.raises(BeforeNative):
            CompiledF4Runtime(artifacts=artifacts, compiled_inputs=values,
                base_dir=ROOT, cache_dir=tmp_path/'cache', max_cases=2)
    assert len(captured) == 1
    compiled = values['compiled']
    assert captured[0]['graph_sha256'] == compiled['runtime_path_contract']['graph_sha256']
    assert captured[0]['declaration']['graph'] == compiled['runtime_dependency_graph']


def _decoder(inputs):
    from myfuzz.integration.compiled_f4_runtime_path import admit_compiled_f4_runtime_path
    from myfuzz.scenario.compiled_online_decoder import CompiledOnlineDecoder
    _artifacts, values = inputs
    admission = admit_compiled_f4_runtime_path(request=values['request'], compiled=values['compiled'])
    path = next(row for row in values['compiled']['paths'] if row['flow_id']=='F4')
    decoder = CompiledOnlineDecoder.from_request(request=values['request'],
        compiled=values['compiled'], path=path, run_id='bound-f4',
        cpu_id='processor', schedule=('processor','peripheral'), rounds=32,
        instruction_start=0x10000, instruction_end=0x40000,
        result_address=0x3fffc, runtime_path_admission=admission)
    return admission, decoder


def test_decoder_keeps_logical_id_and_submits_explicit_runtime_source(inputs):
    from myfuzz.scenario.session_runtime import BoundOnlineInstruction
    admission, decoder = _decoder(inputs)
    candidate = decoder.decode_candidate(bytes(8), cursor=0x10000, case_index=0)
    assert candidate.path_id == admission.logical_path_id
    assert candidate.case.path_id == admission.runtime_path_id
    assert isinstance(candidate.case.source, BoundOnlineInstruction)
    assert candidate.case.source.source_id == admission.instruction_binding.source_id
    document = decoder.document()
    assert document['runtime_contract'] == admission.prepared.contract.document()
    assert document['graph'] == admission.prepared.graph.edge_document()
    assert document['path_mapping'] == admission.prepared.document()['selections']
    assert candidate.document()['runtime_path_id'] == admission.runtime_path_id
    assert candidate.document()['runtime_path_admission_sha256'] == admission.digest


def test_decoder_admission_cannot_be_replaced_by_a_mutated_cached_graph(inputs):
    admission, decoder = _decoder(inputs)
    admission.prepared.graph.sources.clear()
    with pytest.raises(ValueError):
        decoder.decode_candidate(bytes(8), cursor=0x10000, case_index=0)


def test_live_identity_refuses_changed_decoder_contract(inputs, tmp_path):
    from myfuzz.integration.scenario_rfuzz_live import _verify_runtime_path_material
    _artifacts, values = inputs
    _admission, decoder = _decoder(inputs)
    captured = []

    def inspect(session):
        captured.append(session.runtime_path_document)
        raise BeforeNative

    with patch.object(ScenarioSession, 'begin', inspect), pytest.raises(BeforeNative):
        CompiledF4Runtime(artifacts=_artifacts, compiled_inputs=values,
            base_dir=ROOT, cache_dir=tmp_path/'cache', max_cases=2)
    material = {'status':'contract_preflight',
        'declaration':captured[0]['declaration'], 'compiled':{'session':captured[0]}}
    _verify_runtime_path_material(material, decoder.document(), session=True)
    changed = deepcopy(decoder.document())
    changed['runtime_contract']['graph_sha256'] = '0'*64
    with pytest.raises(ValueError):
        _verify_runtime_path_material(material, changed, session=True)


@pytest.mark.parametrize('changed', ('none', 'manifest', 'plan', 'source', 'range',
    'logical_image', 'mmio_source', 'layout_slice', 'register',
    'selected_runtime', 'selected_target'))
def test_saved_source_identity_joins_decoder_manifest_and_plan(inputs, changed):
    from myfuzz.integration.scenario_rfuzz_live import _verify_instruction_image_material
    admission, decoder = _decoder(inputs)
    declaration = decoder.document()
    binding = admission.instruction_binding.document()
    prepared = admission.prepared.document()
    runtime = {'declaration':prepared}
    manifest = {'runtime_paths':runtime, 'instruction_image_bindings':[binding]}
    candidate = decoder.decode_candidate(bytes(8), cursor=0x10000, case_index=0)
    source = candidate.case.source
    plan = {'schema_version':24, 'runtime_paths':runtime,
        'instruction_image_bindings':[binding],
        'instruction_slots':[['processor',0x10000,0xbfff]],
        'cases':[{'path_id':candidate.case.path_id,'direction':candidate.direction,
            'source':{'kind':'bound_instruction','source_id':source.source_id,
                'action_id':source.action_id, 'component':source.component,
                'address':source.address, 'data_hex':source.data_hex}}]}
    manifest, plan = deepcopy(manifest), deepcopy(plan)
    if changed == 'manifest':
        manifest['instruction_image_bindings'][0]['base'] += 4
    elif changed == 'plan':
        plan['instruction_image_bindings'][0]['source_id'] = 'another-source'
    elif changed == 'source':
        plan['cases'][0]['source']['source_id'] = 'another-source'
    elif changed == 'range':
        plan['cases'][0]['source']['address'] = 0x3fffc
    elif changed == 'logical_image':
        declaration['instruction_source_id'] = 'wrong-logical-image'
    elif changed == 'mmio_source':
        declaration['source_id'] = 'wrong-mmio-source'
    elif changed == 'layout_slice':
        declaration['candidate_layout']['slices'][0]['mask'] ^= 1
    elif changed == 'register':
        declaration['register'] = 'wrong-register'
    elif changed in ('selected_runtime','selected_target'):
        import hashlib, json
        from dataclasses import asdict
        from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
        from myfuzz.scenario.compiled_online_decoder import _layout_document
        def digest(value):
            return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        saved = declaration['runtime_path_admission']
        path = saved['selected_path']
        if changed == 'selected_runtime':
            path['runtime_path_identity']['path_id'] = '0'*64
        else:
            path['target']['component'] = 'another-target'
        layout = compile_candidate_layout(path)
        saved['candidate_layout'] = asdict(layout)
        saved['selected_path_sha256'] = digest(path)
        declaration['candidate_layout'] = _layout_document(layout)
        saved['binding_sha256'] = digest({key:value for key,value in saved.items()
                                        if key != 'binding_sha256'})
    if changed == 'none':
        _verify_instruction_image_material(declaration, manifest, plan)
    else:
        with pytest.raises(ValueError):
            _verify_instruction_image_material(declaration, manifest, plan)
