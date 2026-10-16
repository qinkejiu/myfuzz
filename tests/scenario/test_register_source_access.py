import copy
import pytest
from tests.scenario.test_compiled_paths import compile_document,SOC_RENDER_REQUEST,load_request,ROOT
from myfuzz.scenario.compiled_paths import load_path_compile_request
from myfuzz.scenario.register_source_access import validate_register_candidate


def inputs():
    request=load_path_compile_request(load_request(SOC_RENDER_REQUEST),base_dir=ROOT)
    compiled=compile_document(SOC_RENDER_REQUEST)
    path=next(p for p in compiled['paths'] if p['flow_id']=='F4')
    source=next(s for s in path['sources'] if s['kind']=='cpu_mmio_stream')
    return request,compiled,source


def test_window_alignment_and_exact_register_access_are_distinct():
    request,compiled,source=inputs()
    access=source['register_access']
    assert access['window_alignment']==4096
    assert access['address']==0x40000004
    assert access['register_offset']==4
    assert source['alignment']==access['access_alignment']==4
    assert source['range']==[access['address'],access['address']]
    candidate=validate_register_candidate(request,compiled,source_id=source['source_id'],
        source_component=source['component'],source_endpoint='processor.data',target_component=access['target_component'],
        address=access['address'],write=True,value=0x55,byte_enable=15)
    assert candidate['validated'] and candidate['runtime_admitted'] is False


@pytest.mark.parametrize('change,code',[
    ({'address':0x4000000c},'register-candidate-address-mismatch'),
    ({'byte_enable':1},'register-candidate-partial-access'),
    ({'source_component':'gpio'},'register-candidate-source-owner-mismatch'),
    ({'source_endpoint':'processor.instruction'},'register-candidate-source-owner-mismatch'),
    ({'target_component':'invented'},'register-candidate-target-mismatch'),
    ({'value':True},'register-candidate-value-invalid'),
])
def test_candidate_refuses_wrong_writer_or_access_shape(change,code):
    request,compiled,source=inputs()
    options=dict(source_id=source['source_id'],source_component=source['component'],
        source_endpoint='processor.data',target_component=source['register_access']['target_component'],
        address=0x40000004,write=True,value=0x55,byte_enable=15)
    options.update(change)
    with pytest.raises(ValueError,match=code):validate_register_candidate(request,compiled,**options)


def test_edited_access_or_mask_cannot_become_source_authority():
    request,compiled,source=inputs()
    options=dict(source_id=source['source_id'],source_component=source['component'],source_endpoint='processor.data',
        target_component=source.get('register_access',{}).get('target_component','gpio'),
        address=0x40000004,write=True,value=1,byte_enable=15)
    changed=copy.deepcopy(compiled)
    changed['paths'][3]['sources'][1]['mask']^=1
    with pytest.raises(ValueError,match='register-candidate-compiled-document-mismatch'):
        validate_register_candidate(request,changed,**options)


def test_read_response_remains_owned_by_target():
    request,compiled,_=inputs()
    path=next(p for p in compiled['paths'] if p['flow_id']=='F2')
    source=next(s for s in path['sources'] if s['kind']=='cpu_load_stream')
    access=source['register_access']
    assert access['value_origin']=='bound_target_rdata'
    assert access['address']==0x40000008
    with pytest.raises(ValueError,match='register-candidate-read-response-is-bound'):
        validate_register_candidate(request,compiled,source_id=source['source_id'],
            source_component=source['component'],source_endpoint=source['endpoint_id'],
            target_component=access['target_component'],address=access['address'],
            write=False,value=0xdeadbeef,byte_enable=15)


def test_edited_register_offset_is_refused_before_candidate_validation():
    request,compiled,source=inputs()
    changed=copy.deepcopy(compiled)
    changed['paths'][3]['sources'][1]['register_access']['register_offset']=12
    with pytest.raises(ValueError,match='register-candidate-compiled-document-mismatch'):
        validate_register_candidate(request,changed,source_id=source['source_id'],
            source_component=source['component'],source_endpoint=source['endpoint_id'],
            target_component=source['register_access']['target_component'],
            address=0x4000000c,write=True,value=1,byte_enable=15)


def test_reserved_bits_and_missing_merge_policy_are_not_randomized():
    from dataclasses import replace
    from myfuzz.scenario.compiled_paths import compile_paths
    request,_,_=inputs()
    device=request.devices[0]
    fields=tuple(replace(f,write_mask=7) if f.register=='GPIOEN' else f
                 for f in device.capability.register_semantics)
    device=replace(device,capability=replace(device.capability,register_semantics=fields))
    request=replace(request,devices=(device,*request.devices[1:]))
    compiled=compile_paths(request)
    source=next(s for p in compiled['paths'] if p['flow_id']=='F4'
                for s in p['sources'] if s['kind']=='cpu_mmio_stream')
    options=dict(source_id=source['source_id'],source_component=source['component'],
        source_endpoint=source['endpoint_id'],target_component=source['register_access']['target_component'],
        address=source['register_access']['address'],write=True,byte_enable=15)
    with pytest.raises(ValueError,match='register-candidate-reserved-value-bits'):
        validate_register_candidate(request,compiled,value=8,**options)
    with pytest.raises(ValueError,match='register-candidate-masked-merge-policy-undeclared'):
        validate_register_candidate(request,compiled,value=1,**options)
