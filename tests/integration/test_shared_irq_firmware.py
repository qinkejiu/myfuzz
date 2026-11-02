from copy import deepcopy
import pytest


def test_typed_single_gpio_firmware_reserves_disjoint_layout_and_read_clear_ack():
    from myfuzz.integration.shared_irq_firmware import build_irq_firmware
    fw=build_irq_firmware(image_start=0x10000,image_end=0x40000,first_fetch=0x10080,gpio_base=0x40001000,pin=8)
    assert fw['dynamic_start']==0x11000
    assert fw['gpio']['status_offset']==0x24 and fw['gpio']['ack']=='read_clear_unless_new_trigger'
    assert fw['gpio']['type_value']==2<<(2*8)
    for segment in fw['segments']:
        assert 0x10000<=segment['address']<segment['address']+len(bytes.fromhex(segment['data_hex']))<=0x11000
    handler=next(s for s in fw['segments'] if s['name']=='handler')
    words=[int.from_bytes(bytes.fromhex(handler['data_hex'])[i:i+4],'little') for i in range(0,len(bytes.fromhex(handler['data_hex'])),4)]
    assert 0x30200073==words[-1]
    assert any(w&0x7f==3 and w>>20==0x24 for w in words)


@pytest.mark.parametrize('changes',[{'pin':32},{'first_fetch':0x11000},{'image_end':0x11000},{'gpio_base':0x40001001}])
def test_firmware_rejects_unsupported_layout(changes):
    from myfuzz.integration.shared_irq_firmware import build_irq_firmware
    with pytest.raises(ValueError):
        build_irq_firmware(**(dict(image_start=0x10000,image_end=0x40000,first_fetch=0x10080,gpio_base=0x40001000,pin=8)|changes))


def test_irq_descriptor_is_explicit_and_defaults_unchanged():
    from pathlib import Path
    from myfuzz.runtime.generic_campaign import load_descriptor
    root=Path(__file__).resolve().parents[2];config=root/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'
    assert load_descriptor(config/'generic_scenario_irq.json',base_dir=root).irq_firmware is True
    assert load_descriptor(config/'generic_scenario_f2.json',base_dir=root).irq_firmware is False


@pytest.mark.parametrize('value',[0,0x7ff,0x800,0xfffff800,0xffffffff,0x40001000])
def test_fixed_load_sign_extends_low_twelve_bits(value):
    from myfuzz.integration.rv32_fixed_firmware import _lui_addi_load
    lui,addi=_lui_addi_load(3,value)
    low=addi>>20
    low=low-4096 if low&2048 else low
    assert ((lui&0xfffff000)+low)&0xffffffff==value


def observer_world(monkeypatch):
    from types import SimpleNamespace as NS
    from myfuzz.integration import shared_irq_firmware as module,compiled_f4,native_obi_hops,gpio_f2_consumer
    from myfuzz.integration import generated_storage_consumer
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    fw=module.build_irq_firmware(image_start=0x10000,image_end=0x40000,first_fetch=0x10080,gpio_base=0x40001000,pin=8)
    handler=next(s for s in fw['segments'] if s['name']=='handler');code=bytes.fromhex(handler['data_hex'])
    events=[dict(event_id=1,kind='cpu_external_irq_taken'),dict(event_id=2,kind='cpu_retire',pc_rdata=fw['vector']+44)]
    retires=[]
    for i in range(0,len(code),4):
        e=dict(event_id=100+(i//4)*10,kind='cpu_retire',component='cpu',pc_rdata=fw['handler']+i,
            insn=int.from_bytes(code[i:i+4],'little'),schema_version='cpu_retire.v2',observation_contract=ibex_irq_receipt_contract())
        retires.append(e);events.append(e)
    retires[-1]['pc_wdata']=fw['dynamic_start']
    beats={};accepted={};samples={}
    for seq,offset,value,accept,retire_index,write in [(1,8,256,150,7,False),(2,0,256,180,10,True),
            (3,36,256,200,11,False),(4,4,256,212,12,True)]:
        address=(fw['result'] if write else fw['gpio']['base'])+offset
        tx=dict(execution_id='run',testcase_id='one',source_component='cpu',source_epoch=0,channel_id='data',source_sequence=seq)
        beat=dict(acceptance_event=accept,address=address,write=int(write),value=value,rdata=value,byte_enable=15,response_event=accept+3)
        beats[('data',seq)]=beat
        retires[retire_index].update(mem_addr=address,**({'mem_wmask':15,'mem_wdata':value} if write else {'mem_rmask':15,'mem_rdata':value}))
        e=dict(event_id=accept+2,kind='memory_write' if write else 'mmio_delivery',component='cpu',address=address,
            value=value,byte_enable=15,producer_event_id=accept,transaction=tx,source_transaction=tx,device_id='gpio',offset=offset,write=write,read_value=value)
        events.append(e);accepted[e['event_id']]=dict(event_id=accept+1,producer_event_id=accept)
        samples[accept]=(dict(event_id=accept-2,outputs={}),dict(event_id=accept-1,outputs={}))
    target=NS(reset_epoch=0,artifact=NS(runtime_document={'base_protocol_trace':{'signals':{}}}),
        _normalized_physical=lambda outputs:dict(gpio_probe_status=0,gpio_probe_irq_trigger_mask=0,gpio_probe_native_irq=0))
    from myfuzz.scenario.source_provenance import SourceAdmission,AdmissionRegistry
    registry=AdmissionRegistry();admission=registry.register(SourceAdmission.create(case_id='one',case_index=0,source_id='pin8',path_id='pin-path',direction='IP_TO_CPU',component='gpio',action_id='one:pin',role='fuzz_source',input_kind='source_event',input_sha256='a'*64))
    events.append(dict(event_id=3,kind='gpio_irq_trigger',origin_status='known',causes=[dict(pin=8,current_sample=dict(origin_status='known',origin_refs=[admission.document()],value=1))]))
    serial=dict(proof_scope='cpu_retirement_serial',acceptance={'native_take_event_id':1,'source_trigger':{'trigger_event_id':3}},serial_certificate={'retirement_event_id':2})
    runner=NS(sessions={'gpio':target},_provenance=NS(registry=registry),gpio_irq_dependency_evidence_report=lambda:dict(certificates=[serial]))
    runtime=NS(artifacts={'cpu':NS(plan=NS(profile=NS(component_id='ibex_rvfi_local')))},session=NS(cases=[NS(case_id='one',source=NS(action_id='one:pin',value=1))]),f5_binding=NS(path={'runtime_path_identity':{'path_id':'pin-path'}}),_irq_firmware_enabled=True,runner=runner,irq_firmware=fw,cpu_id='cpu',target_id='gpio',access={'device_id':'gpio'},traces={},error_policy={},result=0x3fffc)
    monkeypatch.setattr(compiled_f4,'_borrow_exact_events',lambda runner:tuple(events))
    monkeypatch.setattr(native_obi_hops,'collect_native_obi_beats',lambda *a,**k:beats)
    monkeypatch.setattr(generated_storage_consumer,'_join_delivery',lambda events,**k:accepted[k['delivery']['event_id']])
    monkeypatch.setattr(gpio_f2_consumer,'gpio_read_samples',lambda events,**k:samples[k['producer_event_id']])
    receipt=NS(events=tuple(events),case_id='one')
    monkeypatch.setattr(module,'verify_irq_successor',lambda *a,**k:dict(return_target=fw['dynamic_start']))
    return runtime,receipt,retires,events,beats,accepted,samples


def test_isr_observer_links_actual_checker_boundaries_and_refuses_missing_data(monkeypatch):
    from myfuzz.integration import shared_irq_firmware as module
    runtime,receipt,retires,events,beats,accepted,samples=observer_world(monkeypatch)
    result=module.observe_irq_isr(runtime,receipt)
    assert result['status']=='verified' and result['certificates'][0]['mret_event']==retires[-1]['event_id']
    assert result['reward_eligible'] is False
    retires[11]['mem_rdata']=0
    assert module.observe_irq_isr(runtime,receipt)['status']=='unknown'


def successor_world():
    from dataclasses import asdict
    from types import SimpleNamespace as NS
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger,TransactionKey
    from myfuzz.scenario.session_runtime import OnlineCase,OnlineInstruction
    from myfuzz.scenario.batch import BatchSourceEvent,BatchAdvance
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x10000),),initialization_seed=0,max_initialized_bytes=0x10000)
    memory.declare_instruction_slots(0x11000,4)
    service=MemoryService(memory,TransactionLedger())
    support=OnlineInstruction('fixed-nops','cpu',0x11000,'13000000'*4)
    service.accept_instructions(support.address,support.data,source_event_id=support.action_id)
    tx=TransactionKey(execution_id='run',testcase_id='case',source_component='cpu',source_epoch=0,channel_id='instr',source_sequence=1)
    snapshot=service.read(tx,0x11000,width_bytes=4)
    source={**service.events[0],'component':'cpu','event_id':1}
    read={**next(e for e in service.events if e['kind']=='memory_read'),'component':'cpu','event_id':16,'producer_event_id':15}
    response=dict(kind='instr_response',component='cpu',event_id=24,producer_event_id=22,address=0x11000,rdata=0x13,error=0,
        response_tick=22,transaction=asdict(tx),snapshot={**asdict(snapshot),'value':snapshot.value,'data_hex':snapshot.data.hex()})
    mret=dict(kind='cpu_retire',component='cpu',event_id=20,order=10,local_tick=20,receipt_id={'execution':'run','sequence':20},pc_wdata=0)
    successor=dict(kind='cpu_retire',component='cpu',event_id=30,order=11,local_tick=24,receipt_id={'execution':'run','sequence':24},
        pc_rdata=0x11000,insn=0x13,intr=0,valid=1,schema_version='cpu_retire.v2',observation_contract=ibex_irq_receipt_contract(),
        irq_serial_observation={'retirement':{'status':'observed','value':0}})
    case=OnlineCase('case','IP_TO_CPU','path',BatchSourceEvent('pin','gpio','gpio_in',1,8,1),(BatchAdvance(('cpu',)),),(support,))
    runtime=NS(artifacts={'cpu':NS(plan=NS(profile=NS(component_id='ibex_rvfi_local')))},cpu_id='cpu',result=0x1fffc,image={'port':'ram'},irq_firmware={'dynamic_start':0x11000},
        session=NS(cases=[case]),runner=NS(sessions={'cpu':NS(memory=memory)}))
    backend_step=dict(event_id=22,component='cpu',local_tick=22,outputs=dict(driver_samples=[{'pre':{'backend':dict(i_rsp_valid=1,i_rsp_ready=1,i_rsp_error=0,i_rsp_rdata=0x13)}}],instr_rsp_consumed=1,instr_rsp_rdata=0x13,instr_rsp_source_sequence=1,instr_rsp_source_epoch=0))
    physical_step=dict(event_id=23,component='cpu',local_tick=23)
    events=[source,read,mret,backend_step,physical_step,response,successor]
    beats={('instr',1):dict(address=0x11000,rdata=0x13,acceptance_event=14,response_event=23)}
    return runtime,NS(case_id='case',events=events),mret,events,beats


def test_mret_actual_successor_uses_real_memory_service_bytes_versions():
    from myfuzz.integration.shared_irq_firmware import verify_irq_successor
    world=successor_world()
    proof=verify_irq_successor(*world)
    assert proof['return_target']==0x11000 and proof['raw_mret_pc_wdata']==0
    assert proof['source_action_id']=='fixed-nops'


def test_e20_successor_requires_the_selected_cpu_observation_contract():
    from types import SimpleNamespace as NS
    from myfuzz.integration.shared_irq_firmware import verify_irq_successor
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_receipt_contract
    runtime, receipt, mret, events, beats = successor_world()
    runtime.artifacts = {'cpu': NS(plan=NS(profile=NS(component_id='cv32e20')))}
    events[-1]['observation_contract'] = cv32e20_irq_receipt_contract()
    assert verify_irq_successor(runtime, receipt, mret, events, beats)['return_target'] == 0x11000
    events[-1]['observation_contract']['profile_id'] = 'unregistered'
    with pytest.raises(ValueError, match='scope-mismatch'):
        verify_irq_successor(runtime, receipt, mret, events, beats)


@pytest.mark.parametrize('mode',['pending','outside','response','version'])
def test_mret_no_future_slot_or_bad_actual_response_is_not_completion(mode):
    from myfuzz.integration.shared_irq_firmware import verify_irq_successor
    runtime,receipt,mret,events,beats=successor_world()
    if mode=='pending':receipt.events=events[:-1]
    if mode=='outside':events[-1]['pc_rdata']=0x10200
    if mode=='response':events[-2]['error']=1
    if mode=='version':events[-2]['snapshot']['versions']=((0,99),)*4
    with pytest.raises(ValueError):verify_irq_successor(runtime,receipt,mret,events,beats)


@pytest.mark.parametrize('index',[0,1])
def test_native_v2_backend_and_physical_response_boundaries_keep_real_byte_versions(index):
    import json
    from pathlib import Path
    from types import SimpleNamespace as NS
    from myfuzz.integration.shared_irq_firmware import verify_irq_successor
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.session_runtime import OnlineInstruction
    row=json.loads((Path(__file__).parent/'fixtures/gpio_irq_successor_native_v2.json').read_text())['cases'][index]
    memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x30000),),initialization_seed=0,max_initialized_bytes=0x30000)
    for i in range(row['read']['versions'][0][1]-1):
        memory.write(0x3e000+4*i,i,width_bytes=4,byte_enable=15,writer_event_id='prior-store')
    support=OnlineInstruction(**row['case']['support_instructions'][0]);memory.declare_instruction_slots(support.address,len(support.data)//4)
    MemoryService(memory,TransactionLedger()).accept_instructions(support.address,support.data,source_event_id=support.action_id)
    runtime=NS(artifacts={'processor':NS(plan=NS(profile=NS(component_id='ibex_rvfi_local')))},cpu_id='processor',result=0x3fffc,image={'port':'ram'},irq_firmware={'dynamic_start':0x11000},
        session=NS(cases=[NS(case_id=row['case']['case_id'],support_instructions=(support,))]),runner=NS(sessions={'processor':NS(memory=memory)}))
    events=[row[k] for k in ('source','read','mret','backend_step','physical_step','response','successor')]
    receipt=NS(case_id=row['case']['case_id'],events=events)
    beats={('instr',row['response']['transaction']['source_sequence']):row['native_OBI']}
    assert row['backend_step']['event_id']!=row['native_OBI']['response_event']
    # The live service retains tuples; JSON diagnostics retain lists. Equal
    # byte versions stay equal across that representation boundary.
    row['response']['snapshot']['versions']=tuple(tuple(v) for v in row['response']['snapshot']['versions'])
    row['response']['snapshot']['writer_event_ids']=tuple(row['response']['snapshot']['writer_event_ids'])
    proof=verify_irq_successor(runtime,receipt,row['mret'],events,beats)
    assert proof['backend_response_step']==row['backend_step']['event_id']
    assert proof['physical_response_step']==row['physical_step']['event_id']
    row['backend_step']['outputs']['instr_rsp_source_sequence']+=1
    with pytest.raises(ValueError,match='backend-to-OBI'):verify_irq_successor(runtime,receipt,row['mret'],events,beats)
    row['backend_step']['outputs']['instr_rsp_source_sequence']-=1
    memory.write(row['successor']['pc_rdata'],0x13,width_bytes=4,byte_enable=15,writer_event_id='same-value-new-writer')
    with pytest.raises(ValueError,match='byte-version'):verify_irq_successor(runtime,receipt,row['mret'],events,beats)


def common_observer_world(monkeypatch):
    """Noncontiguous dispatcher->GPIO path with a real intervening scratch op."""
    runtime,receipt,old,events,beats,accepted,samples=observer_world(monkeypatch)
    fw=runtime.irq_firmware
    selected=[e for e in events if e.get('kind') in ('memory_write','mmio_delivery')]
    events[:]=[e for e in events if e.get('kind')!='cpu_retire' and e not in selected]
    entry=dict(old[0],event_id=40,pc_rdata=fw['handler'],order=1,valid=1)
    scratch=dict(old[1],event_id=60,pc_rdata=fw['handler']+4,order=2,valid=1,
        mem_addr=fw['result']+64,mem_wmask=15,mem_rmask=0,mem_wdata=0xcafe)
    status_read=dict(old[11],event_id=80,pc_rdata=fw['handler']+8,order=3,valid=1)
    status_store=dict(old[12],event_id=100,pc_rdata=fw['handler']+12,order=4,valid=1)
    padin_read=dict(old[7],event_id=120,pc_rdata=fw['handler']+0x100,order=5,valid=1)
    padin_store=dict(old[10],event_id=140,pc_rdata=fw['handler']+0x104,order=6,valid=1)
    mret=dict(old[-1],event_id=150,pc_rdata=fw['handler']+0x108,order=7,valid=1)
    retired=[entry,scratch,status_read,status_store,padin_read,padin_store,mret]
    fw['retirement_path']=[(r['pc_rdata'],r['insn']) for r in retired]
    fw['read_retirement_pcs']={8:padin_read['pc_rdata'],36:status_read['pc_rdata']}
    fw['write_retirement_pcs']={0:padin_store['pc_rdata'],4:status_store['pc_rdata']}
    fw['transaction_sequence_offsets']=(3,4,1,2)
    runtime.runner.gpio_irq_dependency_evidence_report()['certificates'][0]['serial_certificate']['retirement_event_id']=40
    # The mock provider returns the same actual fixture object on every read.
    certificate=runtime.runner.gpio_irq_dependency_evidence_report()['certificates'][0]
    certificate['serial_certificate']['retirement_event_id']=40
    oldbeats=dict(beats);beats.clear();accepted.clear();samples.clear()
    for oldseq,newseq,accept in ((3,11,70),(4,12,90),(1,13,110),(2,14,130)):
        event=next(e for e in selected if e['transaction']['source_sequence']==oldseq)
        event['transaction']['source_sequence']=newseq
        event.update(event_id=accept+2,producer_event_id=accept)
        beat=dict(oldbeats[('data',oldseq)],acceptance_event=accept,response_event=accept+3)
        beats[('data',newseq)]=beat;events.append(event)
        accepted[event['event_id']]=dict(event_id=accept+1,producer_event_id=accept)
        samples[accept]=(dict(event_id=accept-2,outputs={}),dict(event_id=accept-1,outputs={}))
    tx=dict(selected[0]['transaction'],source_sequence=10)
    events.append(dict(event_id=52,kind='memory_write',component='cpu',address=fw['result']+64,
        value=0xcafe,byte_enable=15,transaction=tx,producer_event_id=50))
    beats[('data',10)]=dict(acceptance_event=50,response_event=53,address=fw['result']+64,
        write=1,value=0xcafe,byte_enable=15)
    events.extend(retired);events.sort(key=lambda e:e['event_id'])
    receipt.events=tuple(events)
    return runtime,receipt,retired,events,beats


def test_common_dispatcher_gpio_path_keeps_exact_memop_sequence_and_scratch_joins(monkeypatch):
    from myfuzz.integration.shared_irq_firmware import observe_irq_isr
    runtime,receipt,retired,events,beats=common_observer_world(monkeypatch)
    result=observe_irq_isr(runtime,receipt)
    assert result['status']=='verified',result.get('reason')
    assert result['certificates'][0]['handler_retire_events']==[r['event_id'] for r in retired]


@pytest.mark.parametrize('fault',['dma_insert','order','selected_offset','scratch_beat','scratch_retirement'])
def test_common_gpio_path_rejects_dma_diversion_or_unowned_intervening_memory(monkeypatch,fault):
    from myfuzz.integration.shared_irq_firmware import observe_irq_isr
    runtime,receipt,retired,events,beats=common_observer_world(monkeypatch)
    if fault=='dma_insert':
        events.insert(events.index(retired[4]),dict(retired[3],event_id=105,pc_rdata=0x10600))
        receipt.events=tuple(events)
    elif fault=='order':retired[3]['order']+=1
    elif fault=='selected_offset':runtime.irq_firmware['transaction_sequence_offsets']=(0,1,2,3)
    elif fault=='scratch_beat':beats[('data',10)]['value']^=1
    else:retired[1]['mem_addr']+=4
    result=observe_irq_isr(runtime,receipt)
    assert result['status']=='unknown' and not result['certificates'],result


@pytest.mark.parametrize('fault',[None,'missing','width','owner'])
def test_common_dispatcher_scratch_load_needs_its_own_RAM_OBI_retirement_join(monkeypatch,fault):
    from myfuzz.integration.shared_irq_firmware import observe_irq_isr
    from myfuzz.integration.rv32_fixed_firmware import _lw
    runtime,receipt,retired,events,beats=common_observer_world(monkeypatch)
    scratch=retired[1]
    scratch.update(insn=_lw(1,31,0),mem_wmask=0,mem_rmask=15,mem_rdata=0xcafe)
    runtime.irq_firmware['retirement_path'][1]=(scratch['pc_rdata'],scratch['insn'])
    memory=next(e for e in events if e['event_id']==52)
    memory.update(kind='memory_read',width_bytes=4,data_hex='feca0000')
    beats[('data',10)].update(write=0,rdata=0xcafe)
    if fault=='missing':events.remove(memory)
    elif fault=='width':memory['width_bytes']=2
    elif fault=='owner':memory['transaction']['source_component']='other-cpu'
    receipt.events=tuple(events)
    result=observe_irq_isr(runtime,receipt)
    assert result['status']==('verified' if fault is None else 'unknown'),result.get('reason')


def test_rv32e_handler_uses_only_available_registers_and_keeps_default_bytes():
    from myfuzz.integration.shared_irq_firmware import build_irq_firmware,firmware_digest
    params=dict(image_start=0x10000,image_end=0x40000,first_fetch=0x10080,gpio_base=0x40001000,pin=8)
    old=build_irq_firmware(**params)
    assert firmware_digest(old)=='370d158d888b845838942fa5bdebdad2607443a348be3655c4db8508352f8879'
    assert build_irq_firmware(**params,register_count=32)==old
    fw=build_irq_firmware(**params,register_count=16)
    handler=next(s for s in fw['segments'] if s['name']=='handler')
    words=[int.from_bytes(bytes.fromhex(handler['data_hex'])[i:i+4],'little')
        for i in range(0,len(bytes.fromhex(handler['data_hex'])),4)]
    assert words[0]==words[-2]==((0x340<<20)|(15<<15)|(1<<12)|(15<<7)|0x73)
    assert words[-1]==0x30200073
    for segment in fw['segments']:
        data=bytes.fromhex(segment['data_hex'])
        for offset in range(0,len(data),4):
            word=int.from_bytes(data[offset:offset+4],'little');opcode=word&127
            registers=[]
            if opcode in (0x37,0x13,0x03,0x6f):registers.append((word>>7)&31)
            if opcode in (0x13,0x03,0x23):registers.append((word>>15)&31)
            if opcode==0x23:registers.append((word>>20)&31)
            if opcode==0x73 and (word>>12)&7:registers.extend(((word>>7)&31,(word>>15)&31))
            assert all(reg<16 for reg in registers)


@pytest.mark.parametrize('count',[0,15,17,True])
def test_fixed_irq_firmware_rejects_unsupported_register_bank(count):
    from myfuzz.integration.shared_irq_firmware import build_irq_firmware
    with pytest.raises(ValueError):
        build_irq_firmware(image_start=0x10000,image_end=0x40000,first_fetch=0x10080,
            gpio_base=0x40001000,pin=8,register_count=count)


def test_one_borrowed_snapshot_and_one_event_index_per_case(monkeypatch):
    """A case pays one journal pass and one event index, shared by its helpers."""
    from myfuzz.integration import shared_irq_firmware as module, compiled_f4
    runtime, receipt, _retires, events, _beats, _accepted, _samples = observer_world(monkeypatch)
    borrows = []
    monkeypatch.setattr(compiled_f4, '_borrow_exact_events',
        lambda runner: (borrows.append(runner), tuple(events))[1])
    seen = {}
    monkeypatch.setattr(module, 'verify_irq_successor',
        lambda runtime, receipt, mret, events, beats, **keywords: (
            seen.update(keywords), dict(return_target=runtime.irq_firmware['dynamic_start']))[1])
    assert module.observe_irq_isr(runtime, receipt)['status'] == 'verified'
    assert borrows == [runtime.runner]
    index = seen['by_id']
    assert set(index) == {event['event_id'] for event in events}
    assert all(index[event['event_id']] is event for event in events)
