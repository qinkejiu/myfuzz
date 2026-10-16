"""Generic D2/D3 F4 admission, forged declarations and real fresh prefixes."""
from copy import deepcopy
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from myfuzz.integration.compiled_f4 import CompiledF4Runtime, admit_f4
from myfuzz.local_harness.harness_set import load_compose, generate_harness_set
from myfuzz.local_harness.auto_harness_test import load_composition, build_path_compile_request
from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
from myfuzz.scenario.compiled_paths import load_path_compile_request,compile_paths
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership

ROOT=Path(__file__).resolve().parents[2]
# Current native-error admission targets Ibex; historical CV32 evidence is separate.
CONFIG=ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex'


def loaded(directory):
    generated=directory/'generated'
    compose=load_compose(CONFIG/'compose.json',base_dir=ROOT)
    generate_harness_set(compose,base_dir=ROOT,compose_base=CONFIG,output_root=generated)
    composition=load_composition(CONFIG/'compose.json',base_dir=ROOT)
    document,_=build_path_compile_request(composition,wiring_path=generated/'wiring_contract.json',
        ip_capabilities=[CONFIG/'test_capability.json'])
    document['environment_links']=[dict(link_id='pins',component_instance='peripheral',endpoint_id='gpio.pins',width=32,event_kind='pin_value')]
    request=load_path_compile_request(document,base_dir=ROOT);compiled=compile_paths(request)
    artifacts=load_generated_artifacts(generated_root=generated,base_dir=ROOT)
    # Physical source identity is the compiler's explicit endpoint/port mapping.
    source=next(s for p in compiled['paths'] if p['flow_id']=='F4'
                for s in p['sources'] if s['kind']=='external_pin')
    field=InputField(source['component'],source['port'],source['width'])
    owner=InputOwner(source['component'],source['port'],0,source['width'],'source',source['source_id'])
    ownership=compile_ownership((field,),(owner,))
    return artifacts,dict(request=request,compiled=compiled,ownership=ownership,
        physical_port_map={(field.component_id,field.port):field.port})


def test_exact_inputs_select_f4_by_protocol_and_isa(tmp_path):
    artifacts,inputs=loaded(tmp_path)
    with patch('subprocess.Popen',side_effect=AssertionError('pure admission')):
        path=admit_f4(artifacts=artifacts,compiled_inputs=inputs)
    assert path['flow_id']=='F4'
    assert set(artifacts)=={'processor','peripheral'}
    assert next(s for s in path['sources'] if s['kind']=='cpu_mmio_stream')['register']=='GPIOEN'


@pytest.mark.parametrize('field',['sources','assertions','seed','bound_inputs','prerequisites','constraints'])
def test_forged_compilation_never_admits(tmp_path,field):
    artifacts,inputs=loaded(tmp_path)
    altered=deepcopy(inputs['compiled']);path=next(p for p in altered['paths'] if p['flow_id']=='F4')
    path[field]={'forged': True}
    with pytest.raises(ValueError,match='compiled-runtime-input-refused'):
        admit_f4(artifacts=artifacts,compiled_inputs={**inputs,'compiled':altered})


@pytest.mark.skipif(os.environ.get('MYFUZZ_COMPILED_F4_REAL')!='1',reason='actual isolated RTL gate')
def test_real_continuous_compiled_f4_and_two_fresh_prefixes(tmp_path):
    artifacts,inputs=loaded(tmp_path)
    evidence=Path(os.environ.get('MYFUZZ_COMPILED_F4_EVIDENCE',str(tmp_path/'evidence')))
    evidence.mkdir(parents=True,exist_ok=True)
    cache=Path(os.environ.get('MYFUZZ_COMPILED_F4_CACHE',str(tmp_path/'cache')))
    runtime=CompiledF4Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,
        cache_dir=cache,run_id='compiled-f4-real',max_cases=4)
    pids={n:s.process.pid for n,s in runtime.runner.sessions.items()}
    try:
        for value in (0x55,0xaa,0x12345678):
            certificate=runtime.submit(value.to_bytes(4,'little')+bytes.fromhex('78563412'))
            assert certificate['runtime_admitted'] is True
            assert certificate['commit']['after']==value
            assert {n:s.process.pid for n,s in runtime.runner.sessions.items()}==pids
        plan=runtime.finish()
        altered=deepcopy(plan);altered['records'][0]['value']^=1
        with pytest.raises(ValueError,match='prefix-mismatch'):runtime.replay(altered)
        replays=[runtime.replay(plan) for _ in range(2)]
        assert all(row['matches'] for row in replays),replays
        (evidence/'prefix.json').write_text(json.dumps(plan,indent=2))
        (evidence/'replays.json').write_text(json.dumps(replays,indent=2))
        (evidence/'events.json').write_text(json.dumps(list(runtime.trace.events),indent=2))
    finally:
        if not runtime.finished:runtime.finish()


def test_actual_ibex_private_snapshot_reconstructs_immutable_profile_mappings(tmp_path):
    from myfuzz.integration.compiled_f4 import _private_admission_snapshot, _input_identity
    artifacts,inputs=loaded(tmp_path)
    with patch('subprocess.Popen',side_effect=AssertionError('pure private snapshot')):
        private_artifacts,private_inputs=_private_admission_snapshot(artifacts,inputs,ROOT)
        assert _input_identity(private_inputs,private_artifacts)==_input_identity(inputs,artifacts)
        assert admit_f4(artifacts=private_artifacts,compiled_inputs=private_inputs)['flow_id']=='F4'
    assert private_artifacts['processor'] is not artifacts['processor']
    assert private_inputs['request'] is not inputs['request']
    assert private_inputs['ownership'] is not inputs['ownership']
    inputs['ownership']._bits.clear()
    inputs['physical_port_map'].clear()
    artifacts['processor'].runtime_document['kind']='changed'
    assert private_inputs['ownership'].document()['owners']
    assert private_inputs['physical_port_map']
    assert private_artifacts['processor'].runtime_document['kind']=='obi_cpu'
