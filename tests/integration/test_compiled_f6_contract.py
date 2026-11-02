"""Source-backed static F6 admission; these tests never construct sessions."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.scenario.f6_execution_contract import (
    F6ContractRefused, compile_f6_execution_contract, validate_f6_execution_contract)
from myfuzz.local_harness.generated_execution_admission import assess_compiled_f6_support
from myfuzz.scenario.compiled_paths import (
    PathCompilationError, PathCompileRequest, PathComponent, compile_paths, load_path_wiring,
    _wiring_resource_document)

ROOT = Path(__file__).resolve().parents[2]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _source_inputs(cpu_name='cpu', dma_name='dma', *, marked=True):
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, render_local_driver,
        verify_local_source_lock)
    from myfuzz.local_harness.dma_artifact_endpoint_links import render_dma_linked_runtime, PROVIDER_ID
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.dma_route_intent import DmaMasterRouteIntent, dma_master_route_intents_document
    artifacts = {}
    profiles = {}
    paths = {cpu_name: 'configs/cpus/ibex_rvfi_local/component_profile.json',
        dma_name: 'configs/peripherals/zipcpu_wbdmac/component_profile.json'}
    for instance, profile in paths.items():
        local = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path=profile, instance_id=instance, reset_assert_ticks=8,
            reset_release_ticks=8, max_wait_cycles=16))
        plan = plan_local_harness(local, base_dir=ROOT)
        structural = render_local_harness(plan)
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        if instance == dma_name:
            artifact = render_dma_linked_runtime(plan, structural, verified,
                base_dir=ROOT, provider_id=PROVIDER_ID).artifact
        else:
            artifact = render_local_driver(render_local_runtime(plan, structural,
                verified, base_dir=ROOT), base_dir=ROOT)
        artifacts[instance] = artifact
        profiles[instance] = plan.profile
    dma_profile = profiles[dma_name]
    sidecar = dict(schema_version='ip_test_capability.v2', component_id=dma_profile.component_id,
        profile_fingerprint=dma_profile.profile_fingerprint,
        endpoint_capabilities=[dict(endpoint_id='dma.control', operations=['request','accept','response','read','write','wait']),
            dict(endpoint_id='dma.memory', operations=['request','accept','response','read','write'])],
        register_semantics=[], observation_mappings=[dict(mapping_id='native-master',
            endpoint_id='dma.memory', role='adr', observation_kind='port_sample', evidence_ref='source:wbdmac')],
        feature_contract=dict(provider_id='wbdmac.transfer.v1', provider_version='1', operations=[dict(
            endpoint_id='dma.memory', operation='transfer', required_observation_mappings=['native-master'],
            evidence_ref='source:wbdmac')]))
    capability = load_ip_test_capability(sidecar, profile=dma_profile)
    resource = dict(resource_id='shared_ram', component_instance=cpu_name, base=0x10000,
        size=0x20000, read=True, write=True, execute=True, initialization_policy='preload')
    common = dict(initiator_instance=dma_name, initiator_endpoint_id='dma.memory',
        target=dict(kind='persistent_memory', component_instance=cpu_name, resource_id='shared_ram'),
        base=0x10000,size=0x20000, byte_enable=15, readable_offsets=(),writable_offsets=(),accepted_write_values=())
    routes = dma_master_route_intents_document(tuple(DmaMasterRouteIntent(route_id='copy.'+operation,
        operation=operation, permissions=(operation,), **common) for operation in ('read','write')))
    from myfuzz.local_harness.dma_artifact_endpoint_links import _artifact_link
    master = _artifact_link(artifacts[dma_name])
    bindings = [dict(route_id=r['route_id'], initiator=master['template_binding'],
        target=dict(kind='persistent_memory',owner_profile_fingerprint=profiles[cpu_name].profile_fingerprint,
        resource_sha256=digest(resource))) for r in routes['routes']]
    wiring_doc = dict(schema_version='path_wiring.v2',cpu=dict(instance_id=cpu_name,data_endpoint='processor.data'),
        windows=[dict(device_id=dma_name,target_instance=dma_name,endpoint_id='dma.control',base=0x40000000,size=16)],
        resources=[resource],deliveries=[dict(delivery_id='dma-completion',producer_instance=dma_name,
            producer_endpoint_id='dma.interrupt',producer_signal='o_interrupt',consumer_instance=cpu_name,
            consumer_endpoint_id='processor.interrupts',trigger='pulse')],
        dma_master_routes=routes,dma_master_routes_sha256=digest(routes),dma_master_route_bindings=bindings)
    wiring = load_path_wiring(wiring_doc)
    # resource canonicalization retains exactly the supplied explicitly declared facts.
    assert digest(_wiring_resource_document(wiring.resources[0])) == digest(resource)
    document = dict(schema_version='path_compile_request.v1',cpu=dict(instance_id=cpu_name,profile=paths[cpu_name],
        data_endpoint='processor.data',instruction_endpoint='processor.instruction'),
        devices=[dict(instance_id=dma_name,profile=paths[dma_name])],wiring=wiring_doc)
    if marked:
        document['f6_execution'] = dict(schema_version='compiled_F6_cpu_dma_contract.v1',seed=[1,2,3,4],
            program=dict(boot_address=0x10080,isr_address=0x1022c,park_address=0x10400,slot_base=0x11000,
                slot_count=2,source_address=0x22000,destination_address=0x23000,result_base=0x24000))
    request = PathCompileRequest(PathComponent(cpu_name,profiles[cpu_name],None,()),
        (PathComponent(dma_name,dma_profile,capability,()),),wiring,document,'processor.data','processor.instruction')
    return request, compile_paths(request), artifacts



def _saved_source_facts(profile, **kwargs):
    """Source-bound software generation fixture, with no HDL frontend run.

    Scalar widths come from the pinned wrapper. Its five opaque cap_t output
    widths use the earlier actual RVFI export manifest. Packed package widths
    are the pinned package's Ram1pReqWidth=12/RspWidth=1, IC_NUM_WAYS=2,
    five-word crash_dump_t and IbexMuBiWidth=4. No native claim is made.
    """
    import re
    from myfuzz.composition.component_profile import PhysicalFacts
    from myfuzz.composition.source_crawler import ElaboratedPortFact
    if profile.source.top_module=='wbdmac':
        saved=json.loads((ROOT/'configs/peripherals/zipcpu_wbdmac/evidence/elaborated_ports.json').read_text())
        ports=tuple(ElaboratedPortFact(name=r['name'],direction=r['direction'],width=r['width'],signed=r['signed'],
            source_file=r['source']['file'],line=r['source']['line'],column=r['source']['column']) for r in saved['ports'])
    else:
        source='src/myfuzz/composition/rtl/soc_ibex_rvfi_local.sv'
        header=(ROOT/source).read_text().split(');',1)[0]
        saved=json.loads((ROOT/'runs/task4-ibex-retire/rvfi-export-manifest.json').read_text())
        widths={r['physical_port']:r['width'] for r in saved['ports']}
        result=[]
        for line_index,line in enumerate(header.splitlines(),1):
            match=re.match(r'\s*(input|output)\s+(.+?)\s+(\w+),?$',line)
            if not match:continue
            direction,kind,name=match.groups()
            width=1
            if 'ram_1p_cfg_req_t' in kind:width=24
            elif 'ram_1p_cfg_rsp_t' in kind:width=2
            elif 'ibex_mubi_t' in kind:width=4
            elif 'crash_dump_t' in kind:width=160
            elif '$bits' in kind:width=widths[name]
            elif 'SCRAMBLE_KEY_W' in kind:width=128
            elif 'SCRAMBLE_NONCE_W' in kind:width=64
            else:
                span=re.search(r'\[\s*(\d+):0\]',kind)
                if span:width=int(span.group(1))+1
            result.append(ElaboratedPortFact(name,direction,width,False,source,line_index,1))
        ports=tuple(result)
    return PhysicalFacts(top_module=profile.source.top_module,ports=ports,
        content_hash=profile.source.revision,revision=profile.source.revision,
        files=profile.source.files,include_roots=profile.source.include_roots)


def source_inputs(cpu_name='cpu',dma_name='dma',*,marked=True):
    with patch('myfuzz.local_harness.plan.elaborate_profile',side_effect=_saved_source_facts), patch(
            'myfuzz.local_harness.runtime_renderer.elaborate_profile',side_effect=_saved_source_facts):
        return _source_inputs(cpu_name,dma_name,marked=marked)


@pytest.fixture(autouse=True)
def no_frontend_or_native(monkeypatch):
    import subprocess
    real=subprocess.Popen
    def guarded(argv,*a,**k):
        if Path(argv[0]).name!='git':raise AssertionError('no external frontend/native: '+str(argv))
        return real(argv,*a,**k)
    monkeypatch.setattr(subprocess,'Popen',guarded)

@pytest.fixture(scope='module')
def inputs():
    return source_inputs()


def f6(compiled):
    return next(p for p in compiled['paths'] if p['flow_id']=='F6')


def test_f6_wide_control_window_uses_declared_aperture(inputs):
    """Synthetic source bindings exercise compiler sizing, not native RTL."""
    from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider, f6_dma_static_bindings
    request, _, _ = inputs
    mover = request.devices[0]
    provider = select_f6_dma_source_provider(mover.profile, base_dir=ROOT)
    bindings = f6_dma_static_bindings(provider, mover.profile, base_dir=ROOT)
    csr = deepcopy(provider.csr)
    csr['offsets'] = dict(control=16, length=20, source=24, destination=28)
    provider = replace(provider, csr=csr, source={**provider.source, 'csr': csr})
    profile = replace(mover.profile, address=replace(mover.profile.address, window_size=32))
    doc = deepcopy(request.wiring.document)
    doc['windows'][0]['size'] = 32
    request = replace(request, devices=(replace(mover, profile=profile),), wiring=load_path_wiring(doc))
    with patch('myfuzz.scenario.f6_dma_source_provider.select_f6_dma_source_provider', return_value=provider), patch(
            'myfuzz.scenario.f6_dma_source_provider.f6_dma_static_bindings', return_value=bindings), patch(
            'myfuzz.scenario.compiled_paths._validate_static_dma_routes'):
        compiled = compile_f6_execution_contract(request, base_dir=ROOT)
        assert compiled['control']['size'] == 32
        assert compiled['dma']['csr']['offsets'] == csr['offsets']
        oversized = deepcopy(doc)
        oversized['windows'][0]['size'] = 64
        with pytest.raises(F6ContractRefused, match='f6-control-window-required'):
            compile_f6_execution_contract(replace(request, wiring=load_path_wiring(oversized)), base_dir=ROOT)


def test_no_marker_does_not_admit_f6():
    request, compiled, _ = source_inputs(marked=False)
    assert f6(compiled)['status']=='unsupported'
    bad=replace(request,document={**request.document,'f6_execution':{'schema_version':'wrong'}})
    with pytest.raises(F6ContractRefused) as caught:
        compile_f6_execution_contract(bad,base_dir=ROOT)
    assert caught.value.pointer=='/f6_execution/schema_version'


def test_compile_paths_reports_f6_unsupported_irq_as_path_compilation_refusal(inputs):
    request, _, _ = inputs
    delivery = replace(request.wiring.deliveries[0], trigger='level')
    wiring = replace(request.wiring, deliveries=(delivery,))
    request = replace(request, wiring=wiring)

    with pytest.raises(PathCompilationError) as caught:
        compile_paths(request)

    assert caught.value.code == 'f6-native-irq-binding-required'
    assert caught.value.pointer == '/wiring/deliveries'
    assert caught.value.detail is None


def test_compile_paths_preserves_f6_contract_refusal_detail(inputs, monkeypatch):
    request, _, _ = inputs
    detail = {'source': 'test-only F6 refusal detail'}

    def refuse(*args, **kwargs):
        raise F6ContractRefused('f6-contract-detail-probe', '/f6/detail', detail)

    monkeypatch.setattr(
        'myfuzz.scenario.f6_execution_contract.compile_f6_execution_contract',
        refuse)
    with pytest.raises(PathCompilationError) as caught:
        compile_paths(request)

    assert caught.value.code == 'f6-contract-detail-probe'
    assert caught.value.pointer == '/f6/detail'
    assert caught.value.detail == detail


def test_source_backed_closed_contract_and_four_sources(inputs):
    request, compiled, artifacts=inputs
    path=f6(compiled);contract=path['execution_contract']
    assert path['status']=='executable'
    assert set(contract)==set('schema_version flow_id path_id cpu dma instruction_source_id candidate_layout program_contract memory control master_routes irq termination expectation_ids'.split())
    assert len(path['sources'])==4 and all(s['kind']=='cpu_instruction_operand' for s in path['sources'])
    assert [s['bit_offset'] for s in path['sources']]==[0,11,22,33]
    assert [s['instruction_offset'] for s in path['sources']]==[40,48,56,64]
    assert contract['program_contract']['initial_image']
    assert contract['program_contract']['initial_image_sha256']==digest(contract['program_contract']['initial_image'])
    assert validate_f6_execution_contract(contract,request=request,base_dir=ROOT)==contract
    assert path['runtime_path_identity']['edges']
    assert {e['expectation_id'] for e in path['assertions']}==set(contract['expectation_ids'])
    from myfuzz.scenario.ownership import compile_ownership
    result=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=dict(request=request,compiled=compiled,
        ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
    assert result['status']=='supported' and result['runtime_started'] is False


@pytest.mark.parametrize('field,value,pointer',[
    ('seed',[0,0,0,0],'/f6_execution/seed'),('seed',[1,2,3,2048],'/f6_execution/seed'),
    ('seed',[True,2,3,4],'/f6_execution/seed'),('extra',True,'/f6_execution'),
    ('schema_version','other','/f6_execution/schema_version')])
def test_marker_refuses_invalid_fields(inputs,field,value,pointer):
    request,_,_=inputs;doc=deepcopy(request.document);doc['f6_execution'][field]=value
    with pytest.raises(F6ContractRefused) as caught:
        compile_f6_execution_contract(replace(request,document=doc),base_dir=ROOT)
    assert caught.value.pointer==pointer


@pytest.mark.parametrize('field,value', [('source_address',0x23000),('slot_count',17),
    ('isr_address',0x10200),('boot_address',0x10000),('result_base',0x11000)])
def test_program_ranges_and_native_reset_entry_refuse(inputs,field,value):
    request,_,_=inputs;doc=deepcopy(request.document);doc['f6_execution']['program'][field]=value
    with pytest.raises(F6ContractRefused) as caught:
        compile_f6_execution_contract(replace(request,document=doc),base_dir=ROOT)
    assert caught.value.pointer.startswith('/f6_execution/program')


@pytest.mark.parametrize('field', ['schema_version','candidate_layout','program_contract','irq','dma','cpu','master_routes'])
def test_contract_rebuild_rejects_every_static_section_drift(inputs,field):
    request,compiled,_=inputs;contract=deepcopy(f6(compiled)['execution_contract']);contract[field]=None
    with pytest.raises(F6ContractRefused) as caught:
        validate_f6_execution_contract(contract,request=request,base_dir=ROOT)
    assert caught.value.code=='contract-drift'


@pytest.mark.parametrize('mutation',['source','seed','expectation','graph','irq','template','route','permission'])
def test_support_recompiles_full_document_and_wiring(inputs,mutation):
    request,compiled,artifacts=inputs;compiled=deepcopy(compiled)
    if mutation=='source':f6(compiled)['sources'][0]['width']=12
    elif mutation=='seed':f6(compiled)['seed']['words'][0]=5
    elif mutation=='expectation':f6(compiled)['assertions'].clear()
    elif mutation=='graph':compiled['runtime_dependency_graph']['rules'].clear()
    else:
        doc=deepcopy(request.wiring.document)
        if mutation=='irq':doc['deliveries'][0]['producer_signal']='other'
        elif mutation=='template':doc['dma_master_route_bindings'][0]['initiator']['template_id']='other'
        elif mutation=='route':doc['dma_master_routes']['routes'][0]['base']+=4
        else:doc['resources'][0]['read']=False
        doc['dma_master_routes_sha256']=digest(doc['dma_master_routes'])
        request=replace(request,wiring=load_path_wiring(doc))
    from myfuzz.scenario.ownership import compile_ownership
    result=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=dict(request=request,compiled=compiled,
        ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
    assert result['status']=='unsupported' and result['refusals']
    assert result['refusals'][0]['code'] and result['refusals'][0]['pointer'].startswith('/')


def test_actual_artifact_irq_and_source_drift_refused(inputs):
    from myfuzz.scenario.ownership import compile_ownership
    request,compiled,artifacts=inputs
    for instance in ('cpu','dma'):
        supplied=deepcopy(artifacts)
        supplied[instance].runtime_document['source_verification']={}
        result=assess_compiled_f6_support(artifacts=supplied,compiled_inputs=dict(request=request,compiled=compiled,
            ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
        assert result['status']=='unsupported'


def test_source_backed_logical_instance_rename_preserves_semantics():
    request,compiled,artifacts=source_inputs('renamed_processor','renamed_mover')
    contract=f6(compiled)['execution_contract']
    assert contract['cpu']['instance_id']=='renamed_processor'
    assert contract['dma']['instance_id']=='renamed_mover'
    assert compile_f6_execution_contract(request,base_dir=ROOT)==contract


def test_same_protocol_cpu_without_registered_native_irq_provider_refused(inputs):
    from myfuzz.composition.component_profile import load_component_profile
    request,_,_=inputs
    profile=load_component_profile(ROOT/'configs/cpus/ibex_obi_local/component_profile.json')
    with pytest.raises(F6ContractRefused) as caught:
        compile_f6_execution_contract(replace(request,cpu=replace(request.cpu,profile=profile)),base_dir=ROOT)
    assert caught.value.code=='f6-cpu-provider-unsupported'


def test_firmware_and_candidate_interfaces_consume_actual_compiled_path(inputs):
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout, f6_seed_record
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    path=f6(inputs[1]);layout=compile_f6_candidate_layout(path)
    assert layout is not None
    assert f6_seed_record(path).hex()==path['seed']['raw8_hex']
    firmware=build_f6_firmware(path['execution_contract'])
    assert list(firmware.initial_segment_manifest)==path['execution_contract']['program_contract']['initial_image']


def test_source_contract_rejects_changed_rtl_before_source_lock(inputs,tmp_path):
    from myfuzz.local_harness.wbdmac_source_contract import verify_wbdmac_source_contract
    path=tmp_path/'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v'
    path.parent.mkdir(parents=True)
    path.write_bytes((ROOT/'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v').read_bytes()+b'\n// drift\n')
    with pytest.raises(ValueError,match='wbdmac-source-drift'):
        verify_wbdmac_source_contract(inputs[0].devices[0].profile,base_dir=tmp_path)


@pytest.mark.parametrize('mutation',['cpu_irq_probe','cpu_irq_export','cpu_mret_export','dma_master_assignment','dma_irq_export','dma_irq_width_bool','cpp_digest'])
def test_actual_d2_endpoint_and_observer_drift_refused(inputs,mutation):
    from myfuzz.scenario.ownership import compile_ownership
    request,compiled,original=inputs;artifacts=deepcopy(original)
    instance='cpu' if mutation.startswith('cpu') else 'dma'
    artifact=artifacts[instance]
    if mutation=='cpu_irq_probe':
        artifact=replace(artifact,runtime_sv=artifact.runtime_sv.replace('assign probe_irq_taken_pre =','assign other_probe ='))
    elif mutation=='cpu_irq_export':
        artifact.runtime_document['physical_exports']=[r for r in artifact.runtime_document['physical_exports'] if r['physical_port']!='irq_external_i']
    elif mutation=='cpu_mret_export':
        artifact.runtime_document['physical_exports']=[r for r in artifact.runtime_document['physical_exports'] if r['physical_port']!='rvfi_pc_wdata']
    elif mutation=='dma_master_assignment':
        artifact=replace(artifact,runtime_sv=artifact.runtime_sv.replace('assign mwb_adr =','assign another_adr ='))
    elif mutation=='dma_irq_export':
        artifact.runtime_document['physical_exports']=[r for r in artifact.runtime_document['physical_exports'] if r['physical_port']!='o_interrupt']
    elif mutation=='dma_irq_width_bool':
        next(r for r in artifact.runtime_document['physical_exports'] if r['physical_port']=='o_interrupt')['width']=True
    else:
        artifact=replace(artifact,cpp_text=artifact.cpp_text+'\n// altered\n')
    artifact.runtime_document['runtime_sv_sha256']=hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()
    if mutation!='cpp_digest':
        artifact.runtime_document['cpp_sha256']=hashlib.sha256(artifact.cpp_text.encode()).hexdigest()
    artifact.runtime_document['artifact_digest']=digest({k:v for k,v in artifact.runtime_document.items() if k!='artifact_digest'})
    artifacts[instance]=artifact
    result=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=dict(request=request,compiled=compiled,
        ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
    assert result['status']=='unsupported', mutation


def test_same_protocol_dma_with_other_actual_source_is_not_admitted(inputs):
    from myfuzz.composition.component_profile import load_component_profile
    request,_,_=inputs
    doc=json.loads((ROOT/'configs/peripherals/zipcpu_wbdmac/component_profile.json').read_text())
    doc['source']['top_module']='ziptimer'
    doc['source']['files']=['rtl/peripherals/ziptimer.v']
    assert (ROOT/'third_party/soc-zipcpu/rtl/peripherals/ziptimer.v').is_file()
    changed=load_component_profile(doc)
    assert [e.protocol for e in changed.endpoints]==[e.protocol for e in request.devices[0].profile.endpoints]
    with pytest.raises(F6ContractRefused) as caught:
        compile_f6_execution_contract(replace(request,devices=(replace(request.devices[0],profile=changed),)),base_dir=ROOT)
    assert caught.value.code=='dma-route-profile-endpoint-fingerprint-mismatch'
    assert caught.value.pointer=='/wiring/dma_master_route_bindings/0/initiator/profile_endpoint_sha256'


def test_marker_is_closed_optional_request_field(inputs):
    from myfuzz.scenario.compiled_paths import load_path_compile_request
    request,_,_=inputs
    # Loading accepts the explicit field without manufacturing transfer support
    # from the raw profile alone; the capability sidecar remains required.
    loaded=load_path_compile_request(request.document,base_dir=ROOT)
    assert loaded.document['f6_execution']==request.document['f6_execution']
    assert loaded.base_dir==str(ROOT)


def test_source_provider_requires_declared_fixed_zero_native_trigger(inputs):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.wbdmac_source_contract import verify_wbdmac_source_contract
    document=json.loads((ROOT/'configs/peripherals/zipcpu_wbdmac/component_profile.json').read_text())
    document['port_actions'][0]['value']=1
    with pytest.raises(ValueError,match='wbdmac-trigger-must-be-fixed-zero'):
        verify_wbdmac_source_contract(load_component_profile(document),base_dir=ROOT)


@pytest.mark.parametrize('mutation',[
    'tuple_sources','tuple_seed','tuple_initial_image','dict_subclass_root',
    'dict_subclass_layout','dict_subclass_source','list_subclass_sources','cyclic_layout'])
def test_validate_contract_rejects_nonexact_json_containers(inputs,mutation):
    class DictSubclass(dict):
        pass
    class ListSubclass(list):
        pass
    request,compiled,_=inputs
    contract=deepcopy(f6(compiled)['execution_contract'])
    layout=contract['candidate_layout']
    if mutation=='tuple_sources':layout['sources']=tuple(layout['sources'])
    elif mutation=='tuple_seed':layout['seed']=tuple(layout['seed'])
    elif mutation=='tuple_initial_image':
        contract['program_contract']['initial_image']=tuple(contract['program_contract']['initial_image'])
    elif mutation=='dict_subclass_root':contract=DictSubclass(contract)
    elif mutation=='dict_subclass_layout':contract['candidate_layout']=DictSubclass(layout)
    elif mutation=='dict_subclass_source':layout['sources'][0]=DictSubclass(layout['sources'][0])
    elif mutation=='list_subclass_sources':layout['sources']=ListSubclass(layout['sources'])
    else:layout['cycle']=layout
    with pytest.raises(F6ContractRefused) as caught:
        validate_f6_execution_contract(contract,request=request,base_dir=ROOT)
    assert caught.value.code=='contract-drift'
    assert caught.value.pointer=='/execution_contract'


def test_control_window_cannot_overlap_shared_memory_resource_between_used_regions(inputs):
    request,_,_=inputs
    wire=deepcopy(request.wiring.document)
    wire['windows'][0]['base']=0x20000
    altered=replace(request,wiring=load_path_wiring(wire))
    with pytest.raises(PathCompilationError) as caught:
        compile_paths(altered)
    assert caught.value.code=='f6-control-window-overlaps-memory-resource'
    assert caught.value.pointer=='/wiring/windows/0'
    assert caught.value.detail=={'resource_id':'shared_ram'}


@pytest.mark.parametrize('mutation',['raw8','words'])
def test_outer_seed_raw_is_derived_from_contract_words_and_full_d3_admission_rechecks_it(inputs,mutation):
    from myfuzz.scenario.ownership import compile_ownership
    request,compiled,artifacts=inputs
    path=f6(compiled)
    words=path['execution_contract']['candidate_layout']['seed']
    expected=sum(word << (11*index) for index,word in enumerate(words)).to_bytes(8,'little').hex()
    assert path['seed']['words']==words
    assert path['seed']['raw8_hex']==expected
    packed=int.from_bytes(bytes.fromhex(path['seed']['raw8_hex']),'little')
    assert [(packed >> (11*index)) & 2047 for index in range(4)]==words
    assert packed >> 44==0
    assert path['seed']['source_ids']==[s['source_id'] for s in path['execution_contract']['candidate_layout']['sources']]
    altered=deepcopy(compiled)
    if mutation=='raw8':f6(altered)['seed']['raw8_hex']='00'*8
    else:f6(altered)['seed']['words'][0]=5
    result=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=dict(request=request,compiled=altered,
        ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
    assert result['status']=='unsupported'
    assert result['refusals'][0]['code']=='compiled-document-mismatch'
    expected_pointer='/paths/5/seed/raw8_hex' if mutation=='raw8' else '/paths/5/seed/words/0'
    assert result['refusals'][0]['pointer']==expected_pointer


def test_control_window_cannot_overlap_an_additional_memory_resource(inputs):
    request,_,_=inputs
    wire=deepcopy(request.wiring.document)
    wire['resources'].append(dict(resource_id='additional_ram',component_instance='cpu',
        base=0x40000000,size=0x1000,read=True,write=True,execute=False))
    altered=replace(request,wiring=load_path_wiring(wire))
    with pytest.raises(PathCompilationError) as caught:
        compile_paths(altered)
    assert caught.value.code=='f6-control-window-overlaps-memory-resource'
    assert caught.value.pointer=='/wiring/windows/0'
    assert caught.value.detail['resource_id']=='additional_ram'


@pytest.mark.parametrize('port',['rvfi_trap','rvfi_mode','rvfi_halt'])
def test_required_native_isr_safety_exports_cannot_be_removed(inputs,port):
    from myfuzz.scenario.ownership import compile_ownership
    request,compiled,original=inputs
    artifacts=deepcopy(original)
    artifact=artifacts['cpu']
    artifact.runtime_document['physical_exports']=[r for r in artifact.runtime_document['physical_exports'] if r['physical_port']!=port]
    artifact.runtime_document['artifact_digest']=digest({k:v for k,v in artifact.runtime_document.items() if k!='artifact_digest'})
    result=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=dict(request=request,compiled=compiled,
        ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
    assert result['status']=='unsupported'
    assert result['refusals'][0]['code']=='f6-native-isr-observation-required'
    assert result['refusals'][0]['pointer']=='/artifacts/cpu/physical_exports/'+port


def test_coherently_rehashed_cpu_runtime_pc_connection_swap_is_refused(inputs):
    from myfuzz.scenario.ownership import compile_ownership
    request,compiled,original=inputs
    artifacts=deepcopy(original)
    artifact=artifacts['cpu']
    exports=artifact.runtime_document['physical_exports']
    read=next(r for r in exports if r['physical_port']=='rvfi_pc_rdata')
    write=next(r for r in exports if r['physical_port']=='rvfi_pc_wdata')
    read_connection=f'.{read["wrapper_name"]}({read["runtime_name"]})'
    write_connection=f'.{write["wrapper_name"]}({write["runtime_name"]})'
    assert artifact.runtime_sv.count(read_connection)==artifact.runtime_sv.count(write_connection)==1
    altered=artifact.runtime_sv.replace(read_connection,'__F6_TEST_PC_CONNECTION__')
    altered=altered.replace(write_connection,f'.{write["wrapper_name"]}({read["runtime_name"]})')
    altered=altered.replace('__F6_TEST_PC_CONNECTION__',f'.{read["wrapper_name"]}({write["runtime_name"]})')
    artifact=replace(artifact,runtime_sv=altered)
    artifact.runtime_document['runtime_sv_sha256']=hashlib.sha256(altered.encode()).hexdigest()
    artifact.runtime_document['artifact_digest']=digest({k:v for k,v in artifact.runtime_document.items() if k!='artifact_digest'})
    artifacts['cpu']=artifact
    result=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=dict(request=request,compiled=compiled,
        ownership=compile_ownership((),()),physical_port_map={}),base_dir=ROOT)
    assert result['status']=='unsupported'
    assert result['refusals'][0]['code']=='f6-runtime-physical-projection-mismatch'
    assert result['refusals'][0]['pointer']=='/artifacts/cpu/runtime_sv/u_component'
