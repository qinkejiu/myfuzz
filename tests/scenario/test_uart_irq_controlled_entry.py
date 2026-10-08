from copy import deepcopy
from dataclasses import asdict
from functools import lru_cache
import json
import pytest

from myfuzz.scenario.ibex_uart_online import make_ibex_uart_online_bootstrap
from myfuzz.scenario.ibex_pulp_dual_source import _artifact, RVFI_CPU_PROFILE
from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract


@lru_cache(maxsize=1)
def artifact():
    return _artifact(RVFI_CPU_PROFILE, 'cpu').runtime_document


def feature():
    try:
        from myfuzz.scenario.uart_irq_entry import ControlledUartBootstrapRegistry, UartControlledIrqEntryJoin
    except ImportError:
        pytest.fail('controlled entry certificate and exact witness join are not implemented')
    return ControlledUartBootstrapRegistry, UartControlledIrqEntryJoin


def fixture():
    Registry, Join = feature()
    boot = make_ibex_uart_online_bootstrap()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x11000),),
        initialization_seed=1, max_initialized_bytes=0x11000)
    metadata = []
    for event_id, image in enumerate(boot.template.initial_images, 1):
        data = bytes.fromhex(image.data_hex); memory.preload(image.address, data)
        if image.image_id not in ('cpu.main', 'cpu.isr'): continue
        memory_id, generation, offset = memory.resolve_span(image.address, 1)
        metadata.append(dict(image_id=image.image_id,event_id=event_id,component='cpu',
            address=image.address,data_hex=image.data_hex,memory_id=memory_id,
            generation=generation,byte_offset=offset))
    registry = Registry.from_bootstrap(boot, component='cpu', memory_metadata={'images':metadata},
        runtime_artifact=artifact(), observation_contract=ibex_irq_receipt_contract())
    return Join(bootstrap_registry=registry), registry, memory, metadata


def common(tick, event_id):
    return dict(event_id=event_id,component='cpu',reset_epoch=0,source_component='cpu',
        source_epoch=0,execution_id='unit-execution',local_tick=tick,
        command_scope=dict(component='cpu',reset_epoch=0,command_sequence=tick),
        receipt_id=dict(execution='unit-process',sequence=tick),
        receipt_ticks=dict(tick_before=tick-1,tick_after=tick,new_ticks=1,local_tick_base=0),
        observation_contract=ibex_irq_receipt_contract())


def startup():
    event = common(0,10); event.pop('receipt_ticks')
    event.update(kind='cpu_native_startup',schema_version='cpu_native_startup.v1',
        phase='startup_ready',physical_reset=True,artifact_digest=artifact()['artifact_digest'],
        boot_base=0x10000,reset_outcome=dict(schema_version='native_cpu_reset_outcome.v1',
            assert_ticks=8,release_ticks=8,artifact_digest=artifact()['artifact_digest'],
            boot_base=0x10000,source='startup_ready'))
    return event


def sample(tick, event_id, taken=False):
    event = common(tick,event_id)
    zeros={k:0 for k in ibex_irq_receipt_contract()['notification_widths']}
    event.update(kind='cpu_external_irq_sample',schema_version='cpu_external_irq_sample.v1',
        phase='pre_post_rising',expected_input=int(taken),actual_pre_input=int(taken),
        actual_post_input=int(taken),irq_taken_pre=int(taken),irq_masked_pre=0,
        notification_pre=zeros,notification_post=deepcopy(zeros),input_context=None)
    return event


def response(memory,pc,sequence,event_id,case='case-A'):
    from myfuzz.scenario.ledger import TransactionKey
    key=dict(execution_id='unit-execution',testcase_id=case,source_component='cpu',
        source_epoch=0,channel_id='instr',source_sequence=sequence)
    measured=memory.read(pc,4,transaction_id=str(TransactionKey(**key)));snap=asdict(measured)
    snap['value']=measured.value
    snap['data_hex']=snap.pop('data').hex()
    snap=json.loads(json.dumps(snap))
    return dict(kind='instr_response',event_id=event_id,component='cpu',reset_epoch=0,
        source_component='cpu',source_epoch=0,execution_id='unit-execution',transaction=key,
        address=pc,raw_address=pc,aligned_address=pc,write=0,wdata=0,be=15,error=0,
        rdata=snap['value'],snapshot=snap,acceptance_tick=sequence-1,response_tick=sequence)


def retire(tick,event_id,pc,order,insn,rs1=0,intr=0):
    event=common(tick,event_id)
    fields={row['physical_port'].removeprefix('rvfi_'):0 for row in artifact()['physical_exports']
        if row['physical_port'].startswith('rvfi_')}
    fields.update(valid=1,order=order,pc_rdata=pc,pc_wdata=pc+4,insn=insn,
        trap=0,intr=intr,mode=3,halt=0,rs1_addr=(insn>>15)&31,rs1_rdata=rs1,
        rs2_addr=0,rs2_rdata=0,rd_addr=(insn>>7)&31,rd_wdata=0,mem_addr=0,
        mem_rmask=0,mem_wmask=0,mem_rdata=0,mem_wdata=0,ext_nmi=0,ext_nmi_int=0,
        ext_debug_req=0,ext_debug_mode=0)
    event.update(kind='cpu_retire',schema_version='cpu_retire.v2',phase='post',**fields,
        actual_post_ref=dict(command_scope=event['command_scope'],local_tick=tick,phase='post'),
        observation=dict(sampling_edge='post_rising',physical={'rvfi_'+k:v for k,v in fields.items()}))
    return event


def setup_events(memory):
    events=[startup()]
    image=make_ibex_uart_online_bootstrap().template.initial_images[0]
    for tick in range(1,len(bytes.fromhex(image.data_hex))//4+1):
        pc=image.address+(tick-1)*4
        operand={9:0x1012c,12:0x800,14:8}.get(tick,0)
        rsp=response(memory,pc,tick,100+tick)
        sampled=sample(tick,200+tick);sampled['notification_post']['rvfi_valid']=1
        events.extend((rsp,sampled,retire(tick,300+tick,pc,tick,rsp['rdata'],operand)))
    return events


def take_events(tick=16):
    sampled=sample(tick,400,True)
    sampled.update(binding_delivery_event_id=399,source_output_key=['uart',0,'rx_watermark',1],
        input_context=dict(schema_version='native_irq_input_context.v1',binding_delivery_event_id=399,
            expected_input=1,source_output_key=['uart',0,'rx_watermark',1],target_component='cpu',target_epoch=0))
    taken={**deepcopy(sampled), 'kind':'cpu_external_irq_taken','schema_version':'cpu_external_irq_taken.v1',
        'event_id':401,'sample_event_id':400,'sample_ref':dict(command_scope=sampled['command_scope'],local_tick=tick),
        'take_key':['cpu',0,1]}
    proof=dict(kind='uart_consumption_match',event_id=402,status='accepted',
        proof_scope='cpu_external_irq_taken',cpu_component='cpu',cpu_epoch=0,
        cpu_take_event_id=401,cpu_sample_event_id=400,binding_delivery_event_id=399,
        source_output_key=['uart',0,'rx_watermark',1],source_entry_ids=[['uart',0,0,1]],
        source_admissions=[],generic_isr_origin='unknown',operand_origin='unknown')
    return [sampled,taken,proof]


def accepted(records):
    return [r for r in records if r.get('status')=='accepted' and
        r.get('proof_scope')=='controlled_uart_external_irq_entry']


def feed(tracker,events):
    events=deepcopy(events)
    for index,event in enumerate(events):
        if event.get('kind')=='cpu_retire':
            for previous in reversed(events[:index]):
                if previous.get('kind')=='cpu_external_irq_sample' and previous['local_tick']==event['local_tick']:
                    previous['notification_post'].update(rvfi_valid=event['valid'],rvfi_intr=event['intr'])
                    break
    return [r for e in events for r in tracker.consume(e)]


def test_exact_setup_source_versions_taken_and_first_handler_accept():
    tracker,registry,memory,_=fixture()
    feed(tracker,setup_events(memory)+take_events())
    rsp=response(memory,0x1012c,16,501)
    events=[rsp,sample(17,502),retire(17,503,0x1012c,16,19,intr=1)]
    original=deepcopy(events)
    proofs=accepted(feed(tracker,events))
    assert len(proofs)==1 and events==original
    assert proofs[0]['cpu_take_event_id']==401 and proofs[0]['first_retirement_event_id']==503
    assert proofs[0]['entry_pc']==0x1012c and proofs[0]['derived_mtvec']==0x10101
    assert proofs[0]['generic_isr_origin']==proofs[0]['operand_origin']=='unknown'


@pytest.mark.parametrize('mutation',['startup','setup_rsp','setup_operand','setup_insn','override',
    'handler_rsp','version','writer','handler_pc','intr','order','trap','mode','receipt','nmi','second_take','native_proof'])
def test_missing_or_tampered_stage_never_accepts(mutation):
    tracker,_,memory,_=fixture(); events=setup_events(memory)+take_events()
    rsp=response(memory,0x1012c,16,501)
    handler=retire(17,503,0x1012c,16,19,intr=1)
    tail=[rsp,sample(17,502),handler]
    if mutation=='startup':events.pop(0)
    elif mutation=='setup_rsp':events=[e for e in events if e['event_id']!=109]
    elif mutation=='setup_operand':next(e for e in events if e['event_id']==309)['rs1_rdata']=0x2012c
    elif mutation=='setup_insn':next(e for e in events if e['event_id']==309)['insn']^=0x1000
    elif mutation=='override':handler['insn']=0x30539073;handler['rs1_rdata']=0x20000
    elif mutation=='handler_rsp':tail.pop(0)
    elif mutation=='version':rsp['snapshot']['versions'][0][1]=1
    elif mutation=='writer':rsp['snapshot']['writer_kinds'][0]='STORE'
    elif mutation=='handler_pc':handler['pc_rdata']+=4
    elif mutation=='intr':handler['intr']=0
    elif mutation=='order':handler['order']=True
    elif mutation=='trap':handler['trap']=1
    elif mutation=='mode':handler['mode']=0
    elif mutation=='receipt':handler.pop('receipt_id')
    elif mutation=='nmi':tail[1]['notification_post']['rvfi_ext_nmi']=1
    elif mutation=='second_take':events[-2]['take_key']=['cpu',0,2];events.insert(-1,{**deepcopy(events[-2]),'event_id':403})
    elif mutation=='native_proof':events.pop()
    assert not accepted(feed(tracker,events+tail))


def test_long_cross_case_wait_and_late_native_source_proof_do_not_guess_nearest():
    tracker,_,memory,_=fixture(); events=setup_events(memory)+take_events()
    late=events.pop();feed(tracker,events)
    late.update(component='uart',reset_epoch=0)
    feed(tracker,[sample(tick,1000+tick) for tick in range(17,520)])
    rsp=response(memory,0x1012c,16,6001,case='case-B')
    assert not accepted(feed(tracker,[rsp,sample(520,6002),retire(520,6003,0x1012c,16,19,intr=1)]))
    assert len(accepted(tracker.consume(late)))==1


def test_self_signed_registry_and_wrong_image_metadata_are_not_authority():
    Registry,_=feature();_,registry,_,metadata=fixture()
    boot=make_ibex_uart_online_bootstrap()
    for field,value in [('data_hex','00'),('generation',True),('address',0x2012c)]:
        changed=deepcopy(metadata);changed[1][field]=value
        with pytest.raises(ValueError):Registry.from_bootstrap(boot,component='cpu',
            memory_metadata={'images':changed},runtime_artifact=artifact(),observation_contract=ibex_irq_receipt_contract())
    assert registry.document()['schema_version']=='controlled_uart_bootstrap_registry.v1'


@pytest.mark.parametrize('mutation',['missing_field','bool_take','post_intr_mismatch','future_fetch','take_context','raw_taken_flag'])
def test_complete_snapshot_and_actual_receipt_fields_required(mutation):
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory))
    events=take_events()
    if mutation=='bool_take':events[0]['irq_taken_pre']=True
    if mutation=='take_context':events[0].pop('input_context')
    if mutation=='raw_taken_flag':events[1]['irq_taken_pre']=0
    feed(tracker,events)
    rsp=response(memory,0x1012c,16,501);handler=retire(17,503,0x1012c,16,19,intr=1)
    sampled=sample(17,502);sampled['notification_post'].update(rvfi_valid=1,rvfi_intr=1)
    if mutation=='missing_field':handler['observation']['physical'].pop('rvfi_mem_rdata')
    elif mutation=='post_intr_mismatch':sampled['notification_post']['rvfi_intr']=0
    elif mutation=='future_fetch':rsp['response_tick']=1000
    records=[]
    for e in (rsp,sampled,handler):records.extend(tracker.consume(e))
    assert not accepted(records)


@pytest.mark.parametrize('mutation',['execution','component','source_epoch','physical_shape','kind_shape'])
def test_malformed_exact_scope_is_total_and_cannot_accept(mutation):
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory)+take_events())
    rsp=response(memory,0x1012c,16,501);handler=retire(17,503,0x1012c,16,19,intr=1)
    if mutation=='execution':
        from myfuzz.scenario.ledger import TransactionKey
        rsp['transaction']['execution_id']='another-execution'
        rsp['snapshot']['transaction_id']=str(TransactionKey(**rsp['transaction']))
    elif mutation=='component':rsp['transaction']['source_component']='other-cpu'
    elif mutation=='source_epoch':handler['source_epoch']=True
    elif mutation=='physical_shape':handler['observation']=[]
    else:handler['kind']=[]
    assert not accepted(feed(tracker,[rsp,sample(17,502),handler]))


def test_certainty_loss_requires_advanced_measured_reset_and_cancels_pending():
    tracker,_,memory,_=fixture()
    bad=sample(1,20);tracker.consume(bad)
    tracker.consume(startup())
    assert not accepted(feed(tracker,setup_events(memory)[1:]+take_events()+[
        response(memory,0x1012c,16,501),sample(17,502),retire(17,503,0x1012c,16,19,intr=1)]))
    reset=startup();reset.update(kind='cpu_reset',event_id=700,reset_epoch=1,source_epoch=1)
    reset['command_scope']['reset_epoch']=1
    tracker.consume(reset)
    assert tracker._states['cpu']['epoch']==1 and not tracker._states['cpu']['bad']
    assert tracker._states['cpu']['active'] is None and not tracker._states['cpu']['candidates']


def test_repeated_entries_consume_frozen_fetches_without_history_exhaustion():
    tracker,_,memory,_=fixture();tracker.max_refs=16
    feed(tracker,setup_events(memory));tick=16;order=16;sequence=16
    image=make_ibex_uart_online_bootstrap().template.initial_images[1]
    data=bytes.fromhex(image.data_hex)
    for episode in range(20):
        take=take_events(tick)
        shift=10000*(episode+1)
        for event in take:event['event_id']+=shift
        take[1]['sample_event_id']=take[0]['event_id'];take[1]['take_key'][2]=episode+1
        take[2]['cpu_sample_event_id']=take[0]['event_id'];take[2]['cpu_take_event_id']=take[1]['event_id']
        feed(tracker,take);tick+=1
        accepted_count=0
        for index in range(len(data)//4):
            pc=image.address+index*4;insn=int.from_bytes(data[index*4:index*4+4],'little')
            rsp=response(memory,pc,sequence,shift+1000+index*10);sequence+=1
            rsp['acceptance_tick']=rsp['response_tick']=tick
            sampled=sample(tick,shift+1001+index*10)
            retired=retire(tick,shift+1002+index*10,pc,order,insn,intr=int(index==0))
            accepted_count+=len(accepted(feed(tracker,[rsp,sampled,retired])))
            tick+=1;order+=1
        assert accepted_count==1
        assert len(tracker._fetches)<=16 and not tracker._states['cpu']['proofs']


def test_instruction_full_key_cannot_be_reused_at_same_epoch():
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory)+take_events())
    rsp=response(memory,0x1012c,1,501)
    assert not accepted(feed(tracker,[rsp,sample(17,502),retire(17,503,0x1012c,16,19,intr=1)]))


def test_later_actual_csr_override_is_permanent_until_reset():
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory))
    override=retire(16,350,0x11000,16,0x30539073,rs1=0x20000)
    feed(tracker,[sample(16,349),override])
    feed(tracker,take_events(17))
    assert not accepted(feed(tracker,[response(memory,0x1012c,16,501),sample(18,502),
        retire(18,503,0x1012c,17,19,intr=1)]))


def test_missing_bootstrap_registry_remains_unknown_not_self_labeled_authority():
    _,Join=feature();_,_,memory,_=fixture();tracker=Join()
    events=setup_events(memory)+take_events()+[response(memory,0x1012c,16,501),
        sample(17,502),retire(17,503,0x1012c,16,19,intr=1)]
    assert not accepted(feed(tracker,events))


def test_configuration_has_reconstructable_bounds_and_rejects_tampered_builder():
    from dataclasses import replace
    from myfuzz.scenario.uart_irq_entry import controlled_uart_bootstrap_configuration
    boot=make_ibex_uart_online_bootstrap()
    configuration=controlled_uart_bootstrap_configuration(boot,component='cpu',
        runtime_artifact=artifact(),observation_contract=ibex_irq_receipt_contract())
    assert configuration.get('instruction_start')==boot.instruction_start
    assert configuration.get('instruction_end')==boot.instruction_end
    for key,value in (('instruction_start',0x12000),('instruction_end',True)):
        with pytest.raises(ValueError):controlled_uart_bootstrap_configuration(replace(boot,**{key:value}),
            component='cpu',runtime_artifact=artifact(),observation_contract=ibex_irq_receipt_contract())


def test_live_fetch_capacity_loss_cannot_replace_unknown_equal_byte_cohort():
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory)+take_events());tracker.max_refs=1
    old=response(memory,0x1012c,16,501)
    old['snapshot'].update(writer_kinds=['STORE']*4,writer_event_ids=['store:1']*4,versions=[[0,1]]*4)
    filler=response(memory,0x10080,17,502)
    new=response(memory,0x1012c,18,503)
    for event in (old,filler,new):event['acceptance_tick']=event['response_tick']=17
    records=feed(tracker,[old,sample(17,510),filler,sample(18,511),new,
        sample(19,512),retire(19,513,0x1012c,16,19,intr=1)])
    assert not accepted(records)
    assert tracker._states['cpu']['bad']
    reset=startup();reset.update(kind='cpu_reset',event_id=700,reset_epoch=1,source_epoch=1)
    reset['command_scope']['reset_epoch']=1
    tracker.consume(reset)
    assert not tracker._states['cpu']['bad']


def test_bad_state_stops_pending_candidate_allocation():
    tracker,_,memory,_=fixture();tracker.max_refs=1
    feed(tracker,setup_events(memory));tick=16;order=16;sequence=16
    image=make_ibex_uart_online_bootstrap().template.initial_images[1]
    data=bytes.fromhex(image.data_hex)
    for episode in range(5):
        take=take_events(tick)
        shift=10000*(episode+1)
        for event in take:event['event_id']+=shift
        take[1]['sample_event_id']=take[0]['event_id'];take[1]['take_key'][2]=episode+1
        take[2]['cpu_sample_event_id']=take[0]['event_id'];take[2]['cpu_take_event_id']=take[1]['event_id']
        feed(tracker,take[:2]);tick+=1
        accepted_count=0
        for index in range(len(data)//4):
            pc=image.address+index*4;insn=int.from_bytes(data[index*4:index*4+4],'little')
            rsp=response(memory,pc,sequence,shift+1000+index*10);sequence+=1
            rsp['acceptance_tick']=rsp['response_tick']=tick
            sampled=sample(tick,shift+1001+index*10)
            retired=retire(tick,shift+1002+index*10,pc,order,insn,intr=int(index==0))
            accepted_count+=len(accepted(feed(tracker,[rsp,sampled,retired])))
            tick+=1;order+=1
        assert accepted_count==0
        assert len(tracker._states['cpu']['candidates'])<=1
    assert tracker._states['cpu']['bad']



def test_certainty_barrier_stops_new_live_take_state():
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory))
    tracker._fail({'component':'cpu','event_id':999},'controlled_entry_pending_capacity')
    feed(tracker,take_events()[:2])
    assert tracker._states['cpu']['active'] is None


@pytest.mark.parametrize('edge',[None,'pre_rising'])
def test_retirement_requires_explicit_post_sampling_edge(edge):
    tracker,_,memory,_=fixture();feed(tracker,setup_events(memory)+take_events())
    event=retire(17,503,0x1012c,16,19,intr=1)
    if edge is None:del event['observation']['sampling_edge']
    else:event['observation']['sampling_edge']=edge
    assert not accepted(feed(tracker,[response(memory,0x1012c,16,501),sample(17,502),event]))
