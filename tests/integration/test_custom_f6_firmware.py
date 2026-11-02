"""Wishbone Pico F6 firmware selects custom0 ABI, without IRQ proofs."""
from copy import deepcopy
import pytest
from tests.integration.test_compiled_f6_firmware import contract, module, words, candidate


def test_custom_f6_boot_irq_vector_and_retirq_have_no_machine_csrs():
    c=contract(); p=c['program_contract']; p['boot_address']=0; p['isr_address']=0x400
    p['custom_irq']={'abi':'picorv32_custom0','irq_bit':3,'handler_address':16,'retirq_encoding':0x0400000b}
    fw=module().build_f6_firmware(c)
    images=fw.initial_images
    assert set((0,16,0x40,0x400)) <= set(images)
    observed=[word for address in (0,16,0x40,0x400) for word in words(images[address])]
    assert any(word & 0xfe00707f == 0x0600600b for word in observed)
    assert observed.count(0x0400000b)==2
    assert not any(word & 0x7f == 0x73 for word in observed)
    assert fw.document()['isr']['mret_addresses']==[]
    assert len(fw.document()['isr']['retirq_addresses'])==2
    assert len(fw.prefix(candidate(),case_index=0))==128


def test_custom_f6_rejects_internal_irq_and_unimplemented_group():
    c=contract();p=c['program_contract'];p['boot_address']=0;p['isr_address']=0x400
    p['custom_irq']={'abi':'picorv32_custom0','irq_bit':2,'handler_address':16,'retirq_encoding':0x0400000b}
    with pytest.raises(ValueError,match='custom-IRQ-contract'):module().build_f6_firmware(c)
    p['custom_irq']['irq_bit']=3;p['gpio_irq']={}
    with pytest.raises(ValueError,match='custom-IRQ-gpio-vector'):module().build_f6_firmware(c)


def test_custom_gpio_dispatch_uses_distinct_real_vector_bits_and_retirq():
    c=contract();p=c['program_contract'];p['boot_address']=0;p['isr_address']=0x1022c
    p['custom_irq']={'abi':'picorv32_custom0','irq_bit':3,'handler_address':16,'retirq_encoding':0x0400000b}
    p['gpio_irq']={'schema_version':'shared_gpio_IRQ_dispatch.v1','component':'peripheral',
        'pin':8,'irq_bit':4,'group_id':'shared-external','dma_handler_address':0x102a0,
        'gpio_handler_address':0x10320,'scratch_address':0x26000,'result_address':0x26040,
        'gpio_base':0x40001000,'status_offset':36,'status_ack':'read_clear_unless_new_trigger',
        'type_offset':28,'type_value':2<<16,'source_contract_digest':'0'*64}
    fw=module().build_f6_firmware(c);dispatch=fw.document()['irq_dispatch']
    assert [r['irq_bit'] for r in dispatch['routes']]==[3,4]
    assert len(dispatch['stages']['dma']['retirq_addresses'])==2
    assert len(dispatch['stages']['gpio']['retirq_addresses'])==1
    assert dispatch['source_attribution']=='unknown' and dispatch['retirement']=='unknown'
    p['gpio_irq']['irq_bit']=3
    with pytest.raises(ValueError,match='custom-IRQ-gpio-vector'):module().build_f6_firmware(c)


def custom_request():
    from dataclasses import replace
    from copy import deepcopy
    from pathlib import Path
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.scenario.compiled_paths import PathComponent, load_path_wiring
    from myfuzz.scenario.f6_execution_contract import compile_f6_execution_contract
    from tests.integration.test_compiled_f6_contract import source_inputs, digest
    root=Path(__file__).resolve().parents[2]
    request,_,artifacts=source_inputs()
    profile=load_component_profile(root/'configs/cpus/picorv32_wb_irq/component_profile.json')
    wiring=deepcopy(request.wiring.document)
    wiring['cpu']['data_endpoint']='processor.memory'
    resource=wiring['resources'][0];resource['base']=0;resource['size']=0x30000
    for route in wiring['dma_master_routes']['routes']:
        route['base']=0;route['size']=0x30000
    wiring['dma_master_routes_sha256']=digest(wiring['dma_master_routes'])
    for binding in wiring['dma_master_route_bindings']:
        binding['target']['owner_profile_fingerprint']=profile.profile_fingerprint
        binding['target']['resource_sha256']=digest(resource)
    doc=deepcopy(request.document);doc['f6_execution']['custom_irq_bit']=3
    doc['f6_execution']['program'].update(boot_address=0,isr_address=0x400)
    changed=replace(request,cpu=PathComponent('cpu',profile,None,()),
        wiring=load_path_wiring(wiring),document=doc,
        cpu_data_endpoint_id='processor.memory',cpu_instruction_endpoint_id='processor.memory')
    return changed, artifacts, root


def test_compile_f6_contract_accepts_unified_wishbone_custom_abi():
    from myfuzz.scenario.f6_execution_contract import compile_f6_execution_contract
    changed,_,root=custom_request()
    compiled=compile_f6_execution_contract(changed,base_dir=root)
    assert compiled['cpu']['artifact_kind']=='wishbone_cpu'
    assert compiled['program_contract']['custom_irq']['irq_bit']==3
    assert compiled['irq']['native_take_provider']['source_attribution']=='unknown'
    assert compiled['irq']['isr_return_schema']=='unobservable'


def test_custom_f6_observation_constructs_real_sessions_without_execution(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE
    from myfuzz.scenario import evidence
    request,artifacts,root=custom_request()
    artifacts['cpu']=artifact(PROFILE,'cpu')
    def capture(case,factory,output_dir,*,budget):
        runner=factory()
        assert set(runner.sessions)=={'cpu','dma'}
        assert runner.sessions['cpu']._custom_irq_contract is not None
        assert runner.ownership.binding_producer('cpu','irq',3,1)=='dma.irq'
        assert any(image.image_id=='candidate' for image in case.initial_images)
        return SimpleNamespace(status='not_executed')
    monkeypatch.setattr(evidence,'save_evidence_bundle',capture)
    monkeypatch.setattr(evidence,'replay_evidence_bundle',lambda *a,**k:SimpleNamespace(matches=False))
    result=CompiledF6Runtime.run_custom_irq_observation(artifacts=artifacts,
        compiled_inputs={'request':request},base_dir=root,cache_dir=tmp_path,
        raw=bytes.fromhex('0110c00008000000'),output_dir=tmp_path/'evidence')
    assert result['trace_status']=='not_executed'
    assert result['f6_certificate']=='not_granted' and result['retirement']=='unknown'


def test_custom_f6_contract_is_in_compiled_paths():
    from myfuzz.scenario.compiled_paths import compile_paths
    request,_,_=custom_request()
    compiled=compile_paths(request)
    row=next(row for row in compiled['paths'] if row['flow_id']=='F6')
    assert row['status']=='executable'
    assert row['execution_contract']['program_contract']['custom_irq']['irq_bit']==3


def test_shared_assembly_uses_custom_cpu_and_actual_irq_bit(tmp_path):
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly
    from myfuzz.scenario.f6_execution_contract import compile_f6_execution_contract
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE
    request,artifacts,root=custom_request()
    artifacts['cpu']=artifact(PROFILE,'cpu')
    contract=compile_f6_execution_contract(request,base_dir=root)
    owners=tuple(InputOwner('cpu','irq',bit,1,'bound' if bit==3 else 'fixed',
                            'dma.irq' if bit==3 else 'inactive') for bit in range(32))
    ownership=compile_ownership((InputField('cpu','irq',32),),owners)
    assembly=build_f6_assembly(contract=contract,artifacts=artifacts,ownership=ownership,
                               base_dir=root,cache_dir=tmp_path)
    assert assembly.cpu._custom_irq_contract is not None
    assert assembly.cpu.memory is assembly.dma.memory is assembly.memory
    assert assembly.runner.bindings[0].target_bit_offset==3
    assert assembly.runner.sessions['cpu'] is assembly.cpu
    again=assembly.validate(contract=contract,artifacts=artifacts,ownership=ownership,
                            base_dir=root,cache_dir=tmp_path)
    assert again.runner is assembly.runner and again.cpu is assembly.cpu
    owners=list(owners);owners[4]=InputOwner('cpu','irq',4,1,'source','external')
    invalid=compile_ownership((InputField('cpu','irq',32),),tuple(owners))
    with pytest.raises(ValueError,match='custom-IRQ-inactive-bits'):
        build_f6_assembly(contract=contract,artifacts=artifacts,ownership=invalid,
                          base_dir=root,cache_dir=tmp_path)


def test_custom_online_constructor_uses_same_runtime_and_shared_session(tmp_path,monkeypatch):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.scenario.compiled_paths import compile_paths
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.integration import compiled_build_join
    from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE
    request,artifacts,root=custom_request(); artifacts['cpu']=artifact(PROFILE,'cpu')
    compiled_inputs=dict(request=request,compiled=compile_paths(request),
        ownership=compile_ownership((),()),physical_port_map={})
    monkeypatch.setattr(GeneratedLocalSession,'configure_built_executable_receipt',lambda self:None)
    monkeypatch.setattr(GeneratedLocalSession,'prepare_local',lambda self:None)
    monkeypatch.setattr(GeneratedLocalSession,'validate_built_executable_receipt',lambda self:{})
    monkeypatch.setattr(compiled_build_join,'validate_built_receipts',lambda *args:None)
    runtime=CompiledF6Runtime(artifacts=artifacts,compiled_inputs=compiled_inputs,
        base_dir=root,cache_dir=tmp_path,max_cases=2,defer_begin=True)
    assert runtime._custom_online and runtime.session.runner is runtime.runner
    assert runtime.runner.sessions['cpu'] is runtime.cpu
    assert runtime.runner.sessions['dma'] is runtime.dma
    assert runtime.cpu.memory is runtime.dma.memory is runtime.memory
    assert runtime.runner.bindings[0].target_bit_offset==3


def test_custom_online_advances_only_after_observed_next_fetch():
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from myfuzz.scenario.compiled_paths import compile_paths
    request,_,_=custom_request()
    path=next(row for row in compile_paths(request)['paths'] if row['flow_id']=='F6')
    runtime=object.__new__(CompiledF6Runtime)
    runtime.path=path;runtime.contract=path['execution_contract'];runtime.layout=compile_f6_candidate_layout(path)
    runtime.runtime_path_admission={'runtime_path_ids':['dma-path','instruction-path']}
    runtime.program=module().build_f6_firmware(runtime.contract)
    runtime.max_cases=2;runtime.cursor=0;runtime.run_id='case';runtime.cpu_id='cpu';runtime.dma_id='dma'
    runtime.dma=SimpleNamespace(_irq_runtime_name='irq');runtime.artifacts={}
    runtime.rounds_per_case=4;runtime.records=[];runtime.attempts=[];runtime._terminal_error=None
    p=runtime.contract['program_contract'];runtime.cpu=SimpleNamespace(waiting_instruction_address=p['slot_base'])
    runtime.runner=SimpleNamespace(sessions={'cpu':object(),'dma':object()})
    calls=[]
    class Session:
        def submit_case(self,case,**kwargs):
            calls.append(case)
            runtime.cpu.waiting_instruction_address=(p['slot_base']+p['slot_bytes']*len(calls)
                if len(calls)<p['slot_count'] else p['park_address'])
            assert kwargs['stop_after_advance'](0)
            return SimpleNamespace(event_start=10,event_end=20,status='running',violations=(),events=())
    runtime.session=Session()
    raw=sum(value<<(11*i) for i,value in enumerate((51,52,53,54))).to_bytes(8,'little')
    first=runtime._submit_custom_online(raw,'F6')
    second=runtime._submit_custom_online(raw,'F6')
    assert len(calls)==2 and calls[1].source.address==calls[0].source.address+p['slot_bytes']
    assert first['status']==second['status']=='observed'
    assert first['retirement']=='unknown' and first['certificate']=='not_granted'
    assert first['feedback']=='unknown' and not first['reward_eligible']


def test_custom_f5_online_uses_real_pin_source_and_fixed_nop_support(monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration import shared_f5_slots
    from myfuzz.scenario.batch import BatchSourceEvent
    r=object.__new__(CompiledF6Runtime)
    p={'slot_count':2,'slot_base':0x1000,'slot_bytes':256,'park_address':0x3000,
       'shared_slots':{'enabled_flows':['F5']},'gpio_irq':{'component':'gpio','irq_bit':4},
       'custom_irq':{'irq_bit':3}}
    r.contract={'program_contract':p};r.runtime_path_admission={};r.compiled_inputs={}
    r.max_cases=2;r.cursor=0;r.rounds_per_case=4;r.run_id='f5';r.cpu_id='cpu';r.dma_id='dma'
    r.dma=SimpleNamespace(_irq_runtime_name='irq')
    r.artifacts={'gpio':SimpleNamespace(runtime_document={'physical_exports':[
        {'role':'irq','direction':'output','width':1,'runtime_name':'interrupt','physical_port':'interrupt'}]})}
    r.records=[];r.attempts=[];r.cpu=SimpleNamespace(waiting_instruction_address=0x1000)
    r.runner=SimpleNamespace(sessions={'cpu':object(),'gpio':object()})
    monkeypatch.setattr(shared_f5_slots,'declare_shared_pin',lambda *a,**k:dict(
        code_hex='13000000'*32,path_id='pin-path',direction='IP_TO_CPU',component='gpio',
        port='gpio_in',value=1,bit_offset=8,width=1))
    cases=[]
    class Session:
        def submit_case(self,case,**kwargs):
            cases.append(case);r.cpu.waiting_instruction_address=0x1100
            assert kwargs['stop_after_advance'](0)
            return SimpleNamespace(event_start=1,event_end=2,status='running',violations=(),events=())
    r.session=Session()
    result=r._submit_custom_online(bytes(8),'F5')
    assert isinstance(cases[0].source,BatchSourceEvent) and cases[0].source.value==1
    assert cases[0].source.bit_offset==8 and cases[0].support_instructions[0].data==bytes.fromhex('13000000')*32
    assert result['retirement']=='unknown' and result['irq_source_attribution']=='unknown'
    assert result['certificate']=='not_granted' and result['reward_eligible'] is False


def test_declared_irq_phase_is_written_before_dma_start():
    from tests.integration.test_compiled_f6_firmware import model
    c=contract();p=c['program_contract'];p['park_address']=0x10800
    p['declared_irq']={'schema_version':'shared_declared_irq_contract.v1',
        'phase_address':0x25000,'scratch_address':0x25100,'result_address':0x25200,
        'dma_handler_address':0x102a0,'target_handler_address':0x10380,
        'target_window':{'base':0x40003000,'size':4096},'status_offsets':[4],'clear_writes':[]}
    fw=module().build_f6_firmware(c)
    prefix=fw.prefix(candidate(),case_index=0)
    _,_,_,stores,_,_,_=model({p['slot_base']:prefix},p['slot_base'],stop=(p['slot_base']+128,))
    phase=next(i for i,(addr,value) in enumerate(stores) if (addr,value)==(0x25000,0))
    start=next(i for i,(addr,value) in enumerate(stores) if (addr,value)==(c['control']['base'],c['dma']['csr']['start_word']))
    assert phase < start
