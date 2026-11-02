"""Pure source-backed D3/plan validation; no native construction or authority."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
import pytest
from tests.integration.test_compiled_f2_decoder import inputs,decoder,wire


def materials(inputs):
    dec=decoder(inputs);admission=dec.runtime_path_admission
    runtime={'declaration':admission.prepared.document()}
    bindings=[admission.instruction_binding.document()]
    candidate=dec.decode_candidate(wire(inputs),cursor=0x10000,case_index=0)
    source=asdict(candidate.case.source);source['kind']='bound_instruction'
    plan=dict(schema_version=24,runtime_paths=runtime,instruction_image_bindings=bindings,
        instruction_slots=[['processor',0x10000,(0x3fffc-0x10000)//4]],
        cases=[dict(case_id=candidate.case.case_id,direction=candidate.case.direction,path_id=candidate.case.path_id,source=source)])
    return dec.document(),dict(runtime_paths=runtime,instruction_image_bindings=bindings),plan


def test_f2_decoder_documents_actual_prepared_runtime_fields(inputs):
    dec=decoder(inputs);document=dec.document();admission=dec.runtime_path_admission
    assert document.get('runtime_contract')==admission.prepared.contract.document()
    assert document.get('graph')==admission.prepared.graph.edge_document()
    assert document.get('path_mapping')==admission.prepared.document()['selections']
    assert document.get('instruction_image_bindings')==[admission.instruction_binding.document()]


def test_source_backed_f2_material_reaches_both_live_validators(inputs):
    from myfuzz.integration.scenario_rfuzz_live import _verify_runtime_path_material,_verify_instruction_image_material
    dec,manifest,plan=materials(inputs)
    _verify_runtime_path_material(dict(status='contract_preflight',declaration=manifest['runtime_paths']['declaration'],compiled={}),dec)
    _verify_instruction_image_material(dec,manifest,plan)


def helper():
    assert importlib.util.find_spec('myfuzz.integration.compiled_f2_online_material'), 'F2 online material helper missing'
    from myfuzz.integration.compiled_f2_online_material import verify_f2_instruction_image_material
    return verify_f2_instruction_image_material


def test_explicit_f2_helper_accepts_source_backed_material(inputs):
    helper()(*materials(inputs))


@pytest.mark.parametrize('change',['flow','schema','manifest','plan_binding','case_source','case_address','case_code','load_source','image','layout','selected_path','prepared','runtime_contract','graph','mapping','register'])
def test_f2_material_cross_substitutions_refuse(inputs,change):
    dec,manifest,plan=deepcopy(materials(inputs))
    if change=='flow':dec['flow_id']='F4'
    elif change=='schema':dec['runtime_path_admission']['schema_version']='compiled_F4_runtime_path_admission.v1'
    elif change=='manifest':manifest['instruction_image_bindings'][0]['base']+=4
    elif change=='plan_binding':plan['instruction_image_bindings'][0]['source_id']='borrowed'
    elif change=='case_source':plan['cases'][0]['source']['source_id']='borrowed'
    elif change=='case_address':plan['cases'][0]['source']['address']=0x3fffc
    elif change=='case_code':plan['cases'][0]['source']['data_hex']='00000000'
    elif change=='load_source':dec['source_id']='borrowed'
    elif change=='image':dec['instruction_source_id']='borrowed'
    elif change=='layout':dec['candidate_layout']['address_domain']=[0,0]
    elif change=='selected_path':dec['runtime_path_admission']['selected_path']['target']['component']='borrowed'
    elif change=='prepared':dec['runtime_path_admission']['prepared']['selections'][0]['path_id']='borrowed'
    elif change=='runtime_contract':dec['runtime_contract']['graph_sha256']='0'*64
    elif change=='graph':dec['graph']['sources']=[]
    elif change=='mapping':dec['path_mapping']=[]
    else:dec['register']='borrowed'
    with pytest.raises(ValueError):helper()(dec,manifest,plan)


def test_actual_identity_writer_accepts_f2_before_native_source_boundary(tmp_path):
    """Real source/runtime preparation and writer; synthetic empty execution only."""
    from pathlib import Path
    from unittest.mock import patch
    from myfuzz.integration.compiled_f2 import CompiledF2Runtime
    from myfuzz.integration.scenario_rfuzz_live import _write_online_run_identity,_canonical_json
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.replay import ScenarioTrace
    from tests.integration.test_compiled_f4_storage_producer import timer_loaded,ROOT
    from tests.integration.test_compiled_f4_built_wiring import fake_preparation
    (tmp_path/'source').mkdir()
    artifacts,values=timer_loaded(tmp_path/'source')
    captured=[]
    class BeforeNative(Exception):pass
    def stop(session):
        captured.append(deepcopy(session.runtime_path_document))
        raise BeforeNative('source-backed stop before native begin')
    with fake_preparation(),patch.object(ScenarioSession,'begin',stop),pytest.raises(BeforeNative):
        CompiledF2Runtime(artifacts=artifacts,compiled_inputs=values,base_dir=ROOT,
            cache_dir=tmp_path/'synthetic-cache',run_id='f2decoder',rounds_per_case=32,max_cases=2)
    dec,manifest,plan=materials(values)
    manifest['runtime_paths']=captured[0];plan['runtime_paths']=captured[0]
    manifest['runner']={'synthetic_pre_native_source_boundary':True}
    out=tmp_path/'identity';out.mkdir()
    canonical=lambda value:_canonical_json(value)+b'\n'
    plan_bytes=_canonical_json(plan)
    trace=ScenarioTrace(sha256(plan_bytes).hexdigest(),'synthetic_transport_only',(),{},'synthetic',sha256(_canonical_json(manifest)).hexdigest())
    for name,raw in {'decoder_manifest.json':canonical(dec),'targets.json':b'[]',
        'rfuzz.toml':b'# synthetic source boundary\n','seed.bin':wire(values),
        'online_plan.json':plan_bytes,'online_final_trace.json':canonical(asdict(trace))}.items():
        (out/name).write_bytes(raw)
    commitments=[]
    identity=_write_online_run_identity(out,session_manifest=manifest,plan_bytes=plan_bytes,
        trace=trace,client_binary=Path('/usr/bin/true'),run_config={'synthetic_transport_only':True},
        frozen_inputs={'collector':None,'source_files':[],'client':{'synthetic_transport_only':True}},
        commitment_sink=commitments.append)
    assert identity==commitments[0]['identity_sha256']
    assert commitments[0]['artifacts']['online_plan.json']==sha256(plan_bytes).hexdigest()
