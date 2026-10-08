"""Simulated full CPU/UART stream plus actual installed host-memory callbacks."""
from copy import deepcopy
from dataclasses import asdict
import pytest
from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
from tests.scenario.test_uart_operand_use import scenario
from myfuzz.scenario.uart_store_memory import UartStoreMemoryJoin


def setup(delayed=False,**limits):
    stream,store=scenario(delayed=delayed)
    k=next(e['transaction'] for e in stream.events if e.get('kind')=='data_accept' and e['write']==1)
    memory=PersistentMemory(regions=(MemoryRegion('host-ram',0x20000,4096),),
        initialization_seed=1,max_initialized_bytes=4096)
    ledger=TransactionLedger();service=MemoryService(memory,ledger,commit_stream_capacity=8)
    # Explicit simulated prior MMIO transaction advances shared channel order;
    # this is not a RAM write or a fake CPU receipt.
    ledger.execute_once(TransactionKey(**dict(k,source_sequence=1)),{'simulated_mmio_read':True},lambda:(0,0))
    receipt=service.write(TransactionKey(**k),0x20000,0,width_bytes=4,byte_enable=15)
    authority=MemoryCommitAuthority(services={'cpu':service})
    token=authority.stage('cpu',service,ledger,receipt.transaction_id,receipt)
    event=service.drain_commit_events()[0];event.update(event_id='actual-host-commit',component='cpu')
    service.ack_commit_events((event['commit_id'],))
    join=UartStoreMemoryJoin(memory_commit_authority=authority,admission_registry=stream.registry,
        ownership=stream.owner,edge_index=stream.index,**limits)
    return stream,store,service,authority,token,event,join


def play(model,events):return [r for e in events for r in model.consume(deepcopy(e))]
def accepted(out):return [r for r in out if r.get('status')=='accepted']


def test_commit_before_accept_joins_exact_raw_use_and_retired_fullkey():
    s,r,service,a,t,event,m=setup();out=list(m.consume(event,commit_token=t))+play(m,s.events)
    ps=accepted(out);assert len(ps)==1;p=ps[0]
    assert p['proof_scope']=='uart_operand_store_host_memory_byte'
    assert p['store_fullkey']==event['transaction'] and p['store_retirement_event_id']==r['event_id']
    assert p['source_register_version_key']==['cpu',0,0,3]
    assert p['memory_kind']=='modeled_host_persistent_memory' and p['memory_id']=='host-ram'
    assert p['byte_offset']==0 and p['byte_value']==0 and p['byte_version']==[0,1]
    assert p['unknown_written_lanes']==[1,2,3]
    assert p['rtl_ram_origin']==p['later_ram_read_origin']==p['whole_word_store_origin']==p['generic_isr_origin']=='unknown'
    assert m.pending_count==a.pending_count==0


def test_commit_after_retirement_still_joins_without_timing_guess():
    s,r,_,_,t,e,m=setup();out=play(m,s.events)+list(m.consume(e,commit_token=t))
    assert len(accepted(out))==1


def test_late_seed_pins_exact_historical_memory_version():
    s,r,service,a,t,e,m=setup(delayed=True)
    out=list(m.consume(e,commit_token=t));old=s.events.pop();out+=play(m,s.events)
    # Equal-value overwrite of backing cells cannot substitute the old commit.
    service.write(TransactionKey(**dict(e['transaction'],source_sequence=3)),0x20000,0,width_bytes=4,byte_enable=15)
    out+=play(m,[old]);p=accepted(out)[0]
    assert p['byte_version']==[0,1] and service.memory._commit_sequences['host-ram']==2


@pytest.mark.parametrize('kind',['uart_frame_validation','uart_rdata_access','uart_consumption_match',
    'cpu_retirement_match','instr_response','data_accept','data_response','cpu_retire'])
def test_missing_raw_stage_cannot_authorize_host_byte(kind):
    s,_,_,_,t,e,m=setup();out=list(m.consume(e,commit_token=t))+play(m,[x for x in s.events if x.get('kind')!=kind])
    assert not accepted(out)


def test_saved_selfsigned_commit_or_token_field_has_no_live_authority():
    s,_,_,_,t,e,m=setup();e['commit_token']=t
    assert not accepted(list(m.consume(e))+play(m,s.events))


@pytest.mark.parametrize('field,value',[('execution_id','other'),('testcase_id','other'),
    ('source_component','other'),('source_epoch',1),('channel_id','instr'),('source_sequence',3)])
def test_actual_token_cannot_authorize_replaced_fullkey(field,value):
    s,_,_,_,t,e,m=setup();e['transaction'][field]=value
    assert not accepted(list(m.consume(e,commit_token=t))+play(m,s.events))


@pytest.mark.parametrize('field,value',[('generation',True),('byte_offset',True),('memory_id','other'),
    ('version',[0,2]),('byte_enable',1),('performed_effect',False)])
def test_issued_document_cannot_be_replaced_by_matching_value_label(field,value):
    s,_,_,_,t,e,m=setup();e['commit_document'][field]=value
    assert not accepted(list(m.consume(e,commit_token=t))+play(m,s.events))


def test_duplicate_or_conflicting_commit_never_emits_second_effect_proof():
    s,_,_,_,t,e,m=setup();out=list(m.consume(e,commit_token=t))+play(m,s.events)
    assert len(accepted(out))==1
    assert not accepted(m.consume(e,commit_token=t))
    changed=deepcopy(e);changed['commit_document']['version']=[0,2]
    assert not accepted(m.consume(changed,commit_token=t))


def test_physical_cpu_reset_cancels_unfinished_old_source_join():
    s,_,_,_,t,e,m=setup(delayed=True);old=s.events.pop()
    play(m,s.events);m.consume(e,commit_token=t)
    reset=dict(kind='cpu_reset',event_id='measured-reset',component='cpu',source_component='cpu',
        source_epoch=1,reset_epoch=1,physical_reset=True,execution_id='cpu-execution')
    play(m,[reset]);assert m.pending_count==0 and not accepted(play(m,[old]))


def test_constructor_cannot_accept_selfsigned_authority_document():
    with pytest.raises(ValueError):UartStoreMemoryJoin(memory_commit_authority={'status':'accepted'})


def test_single_cpu_reset_cannot_repair_unknown_global_certainty_loss():
    _,_,_,_,_,_,m=setup();m.consume({'kind':[]});assert m.degraded
    reset=dict(kind='cpu_reset',event_id='actual-reset',component='cpu',source_component='cpu',
        source_epoch=1,reset_epoch=1,physical_reset=True,execution_id='cpu-execution')
    m.consume(reset);assert m.degraded


@pytest.mark.parametrize('field,value',[('error',False),('rdata',False),('write',True),('be',True)])
def test_response_numeric_type_substitution_cannot_promote(field,value):
    s,_,_,_,t,e,m=setup()
    for row in s.events:
        if row.get('kind')=='data_response' and row.get('write')==1:row[field]=value
    assert not accepted(list(m.consume(e,commit_token=t))+play(m,s.events))


def unrelated_store(store,events):
    store['insn']=0x0042a023;store['rs2_addr']=4
    store['observation']['physical']['rvfi_insn']=store['insn']
    store['observation']['physical']['rvfi_rs2_addr']=4
    for f in events:
        if f.get('kind')=='instr_response' and f.get('address')==store['pc_rdata']:
            f['rdata']=store['insn'];f['snapshot']['value']=store['insn']
            f['snapshot']['data_hex']=store['insn'].to_bytes(4,'little').hex()


def test_unrelated_equal_value_store_and_late_commit_release_without_uart_claim():
    s,r,_,a,t,e,m=setup();unrelated_store(r,s.events)
    assert not accepted(play(m,s.events)) and m.pending_count==0
    assert not accepted(m.consume(e,commit_token=t)) and m.pending_count==a.pending_count==0


def test_delayed_old_commit_survives_newer_unrelated_store_floor():
    from tests.scenario.test_uart_operand_use import append_store
    s,r,_,_,t,e,m=setup();later=append_store(s,r,2,3);unrelated_store(later,s.events)
    assert not accepted(play(m,s.events)) and m.pending_count==1
    p=accepted(m.consume(e,commit_token=t));assert len(p)==1 and p[0]['store_fullkey']['source_sequence']==2


def test_many_logical_cases_do_not_grow_closed_floor_maps_or_uart_pending():
    from tests.scenario.test_uart_operand_use import append_store
    s,r,_,_,_,_,m=setup(max_components=2);unrelated_store(r,s.events)
    play(m,s.events);last=r
    for i in range(2,35):
        start=len(s.events);last=append_store(s,last,i,i+1);unrelated_store(last,s.events[start:])
        for row in s.events[start:]:
            if row.get('kind') in ('data_accept','data_response'):row['transaction']['testcase_id']=f'case-{i}'
        assert not accepted(play(m,s.events[start:]))
    assert not m.degraded and m.pending_count==0 and len(m._closed_floors)<=2


def test_live_commit_slot_capacity_barrier_recovers_only_scoped_advanced_reset():
    s,r,service,a,t,e,m=setup(max_pending_commits=1);play(m,s.events)
    receipt=service.write(TransactionKey(**dict(e['transaction'],source_sequence=3)),0x20000,0,width_bytes=4,byte_enable=15)
    token=a.stage('cpu',service,service.ledger,receipt.transaction_id,receipt)
    event=service.drain_commit_events()[0];event.update(event_id='another-live-commit',component='cpu')
    assert not accepted(m.consume(event,commit_token=token)) and m.degraded and m.pending_count==1
    reset=dict(kind='cpu_reset',event_id='scoped-actual-reset',component='cpu',source_component='cpu',
        source_epoch=1,reset_epoch=1,physical_reset=True,execution_id='cpu-execution')
    m.consume(reset);assert not m.degraded and m.pending_count==0
