"""Software simulated full native receipts, not actual RTL evidence."""
from copy import deepcopy
import pytest
from tests.scenario.test_uart_operand_seed import overwrite
from tests.scenario.test_uart_retired_read import Stream
from tests.scenario.test_cpu_retirement import fetch
from myfuzz.scenario.uart_operand_use import UartOperandUseTracker

SW=0x0032a023


def scenario(delayed=False):
    s=Stream();s.lifecycle();load=next(e for e in s.events if e.get('kind')=='cpu_retire')
    key=next(e for e in s.events if e.get('kind')=='data_accept')['transaction']
    f=fetch(SW,seq=2,pc=0x104);f.update(event_id='store-fetch');f['transaction'].update(
        execution_id=key['execution_id'],source_component='cpu',source_epoch=0)
    f['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,writer_event_ids=['initial-image']*4)
    store=overwrite(load);store.update(event_id='store-retire',pc_rdata=0x104,pc_wdata=0x108,insn=SW,
        rs1_addr=5,rs1_rdata=0x20000,rs2_addr=3,rs2_rdata=0,rd_addr=0,rd_wdata=0,
        mem_addr=0x20000,mem_rmask=0,mem_wmask=15,mem_rdata=0,mem_wdata=0,mode=3)
    store['observation']['physical']={'rvfi_'+n:store[n] for n in load['observation']['physical'] for n in [n[5:]]}
    k=dict(key,source_sequence=2)
    a=dict(kind='data_accept',event_id='store-a',transaction=k,raw_address=0x20000,
        aligned_address=0x20000,address=0x20000,write=1,be=15,wdata=0)
    d=dict(a,kind='data_response',event_id='store-d',rdata=0,error=0)
    s.events.extend([f,a,d,store])
    if delayed:
        proof=next(e for e in s.events if e.get('kind')=='uart_consumption_match')
        s.events.remove(proof);s.events.append(proof)
    return s,store


def tracker(s,**kw):return UartOperandUseTracker(admission_registry=s.registry,
    ownership=s.owner,edge_index=s.index,**kw)


def play(m,events):return [r for e in events for r in m.consume(deepcopy(e))]


def accepted(out):return [r for r in out if r.get('status')=='accepted']


def test_exact_prior_seed_consumed_by_actual_shaped_sw_rs2():
    s,r=scenario();ps=accepted(play(tracker(s),s.events));assert len(ps)==1
    p=ps[0];assert p['source_register_version_key']==['cpu',0,0,3]
    assert p['operand_retirement_event_id']==r['event_id'] and p['operand_role']=='rs2_store_data'
    assert p['proof_scope']=='uart_seed_register_operand_read' and p['influenced_bits']==[0,8]
    assert p['ram_delivery_origin']==p['whole_word_store_origin']==p['generic_isr_origin']=='unknown'


def test_late_seed_proves_historical_use_after_current_register_overwrite():
    s,r=scenario(delayed=True);old=s.events.pop();new=overwrite(r)
    new.update(event_id='later-overwrite',rd_addr=3,rd_wdata=0,order=2,insn=0x000001b3)
    new['observation']['physical']={'rvfi_'+n:new[n] for n in r['observation']['physical'] for n in [n[5:]]}
    s.events.extend([new,old]);ps=accepted(play(tracker(s),s.events));assert len(ps)==1
    assert ps[0]['source_register_version_key']==['cpu',0,0,3]


@pytest.mark.parametrize('field,value',[('rs2_addr',4),('rs2_rdata',1),('mem_wdata',1),
    ('mem_wmask',1),('mem_rmask',1),('mem_addr',0x20004),('trap',1),('ext_rf_wr_suppress',1),
    ('mem_is_cap',1),('rs2_addr',True),('rs2_rdata',True),('order',3),('mode',0)])
def test_mutated_operand_or_native_effect_cannot_promote(field,value):
    s,r=scenario();r[field]=value;r['observation']['physical']['rvfi_'+field]=value
    assert not accepted(play(tracker(s),s.events))


@pytest.mark.parametrize('kind',['uart_frame_validation','uart_rdata_access','cpu_retirement_match',
    'instr_response','data_accept','data_response'])
def test_deleted_seed_authority_never_replaced_by_value(kind):
    s,_=scenario();assert not accepted(play(tracker(s),[e for e in s.events if e.get('kind')!=kind]))


def test_same_value_overwrite_before_use_blocks_old_seed():
    s,r=scenario();load=next(e for e in s.events if e.get('kind')=='cpu_retire')
    new=overwrite(load);new.update(event_id='overwrite-before-use')
    index=s.events.index(r);s.events.insert(index,new)
    r.update(order=2,local_tick=3);r['command_scope']['command_sequence']=3;r['receipt_id']['sequence']=3
    r['actual_post_ref'].update(command_scope=deepcopy(r['command_scope']),local_tick=3)
    r['receipt_ticks'].update(tick_before=2,tick_after=3)
    r['observation']['physical']['rvfi_order']=2
    assert not accepted(play(tracker(s),s.events))


def test_selfsigned_seed_label_does_not_authorize_use():
    s,r=scenario();es=[e for e in s.events if e.get('kind') not in ('uart_frame_validation','uart_consumption_match')]
    es.insert(-1,dict(kind='uart_operand_seed',event_id='forged',status='accepted',
        proof_scope='uart_retired_load_register_seed',register_version_key=['cpu',0,0,3]))
    assert not accepted(play(tracker(s),es))


def test_no_post_reference_no_use():
    s,r=scenario();r.pop('actual_post_ref');assert not accepted(play(tracker(s),s.events))


def test_unknown_scope_barriers_remain_bounded():
    s,_=scenario();m=tracker(s,max_components=1,max_pending_uses=1)
    for eid in range(1,51):m.consume(dict(kind='cpu_retire',event_id=eid,source_component=f'unknown{eid}',source_epoch=0))
    assert len(m._bad)<=1 and m._global_bad


def test_uart_reset_reclaims_unfinished_chain_but_not_certified_register():
    s,r=scenario(delayed=True);proof=s.events.pop();m=tracker(s)
    play(m,s.events);assert m.pending_count==1 and m._seed.pending_count==1
    reset=dict(kind='uart_reset',event_id='uart-reset',component='uart',source_component='uart',
        reset_epoch=1,source_epoch=1,physical_reset=True,local_tick=s.native.clock,
        command_scope=dict(component='uart',reset_epoch=1,command_sequence=0))
    play(m,[reset]);assert m.pending_count==m._seed.pending_count==0
    assert not accepted(play(m,[proof]))
    s,_=scenario();m=tracker(s);play(m,s.events);play(m,[reset])
    assert m._seed.register_at('cpu',0,3)['origin_status']=='known_uart_load'


@pytest.mark.parametrize('insn',[[],{},'sw',True,None])
def test_malformed_instruction_never_throws_or_promotes(insn):
    s,r=scenario();r['insn']=insn;r['observation']['physical']['rvfi_insn']=insn
    assert not accepted(play(tracker(s),s.events))


def test_duplicate_same_retirement_does_not_emit_twice_and_conflict_barriers():
    s,r=scenario();m=tracker(s);assert len(accepted(play(m,s.events)))==1
    assert not accepted(play(m,[r]))
    changed=deepcopy(r);changed['rs2_rdata']=1;changed['observation']['physical']['rvfi_rs2_rdata']=1
    assert not accepted(play(m,[changed])) and not m._healthy('cpu',0)


def test_cpu_reset_before_delayed_seed_cancels_old_use():
    s,r=scenario(delayed=True);old=s.events.pop();m=tracker(s);play(m,s.events)
    reset=dict(kind='cpu_reset',event_id='cpu-reset',component='cpu',source_component='cpu',
        reset_epoch=1,source_epoch=1,physical_reset=True,execution_id='cpu-execution')
    play(m,[reset]);assert m.pending_count==0
    assert not accepted(play(m,[old]))


def test_flush_before_delayed_seed_blocks_old_use():
    s,r=scenario(delayed=True);old=s.events.pop();m=tracker(s);play(m,s.events)
    play(m,[dict(kind='cpu_flush',event_id='flush',source_component='cpu',source_epoch=0,execution_id='cpu-execution')])
    assert not accepted(play(m,[old]))


def append_store(s,raw,order,sequence):
    r=overwrite(raw);r.update(event_id=f'store-r:{order}',insn=SW,order=order,
        rd_addr=0,rs1_addr=5,rs1_rdata=0x20000,rs2_addr=3,rs2_rdata=0,mem_addr=0x20000,
        mem_wmask=15,mem_rmask=0,mem_wdata=0,pc_rdata=0x104+4*(order-1),mode=3)
    r['observation']['physical']={'rvfi_'+n:r[n] for n in raw['observation']['physical'] for n in [n[5:]]}
    f=fetch(SW,seq=sequence,pc=r['pc_rdata']);f.update(event_id=f'use-fetch:{sequence}')
    key=next(e for e in s.events if e.get('kind')=='data_accept')['transaction']
    f['transaction'].update(execution_id=key['execution_id'],source_component='cpu',source_epoch=0)
    f['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,writer_event_ids=['initial-image']*4)
    a=dict(kind='data_accept',event_id=f'use-a:{sequence}',transaction=dict(key,source_sequence=sequence),
        raw_address=0x20000,aligned_address=0x20000,address=0x20000,write=1,be=15,wdata=0)
    d=dict(a,kind='data_response',event_id=f'use-d:{sequence}',rdata=0,error=0)
    s.events.extend([f,a,d,r]);return r


def test_use_pending_capacity_remains_bounded_until_advanced_reset():
    s,r=scenario(delayed=True);old=s.events.pop();append_store(s,r,2,3)
    m=tracker(s,max_pending_uses=1);out=play(m,s.events)
    assert any(p.get('reason')=='uart_operand_use_pending_capacity' for p in out)
    assert m.pending_count==1 and not accepted(play(m,[old]))
    reset=dict(kind='cpu_reset',event_id='advanced-reset',component='cpu',source_component='cpu',
        reset_epoch=1,source_epoch=1,physical_reset=True,execution_id='cpu-execution')
    play(m,[reset]);assert m.pending_count==0 and m._healthy('cpu',1)


def test_many_epoch_barriers_cannot_allocate_unbounded_tombstones():
    s,r=scenario();m=tracker(s,max_components=1);play(m,s.events)
    for epoch in range(1,301):
        e=deepcopy(r);e.update(event_id=f'bad-epoch:{epoch}',source_epoch=epoch)
        e['command_scope']['reset_epoch']=epoch;e['actual_post_ref']['command_scope']['reset_epoch']=epoch
        m.consume(e)
    assert len(m._bad)<=1 and m._global_bad


def test_other_phase_certificates_are_ignored_not_source_authority():
    s,r=scenario();m=tracker(s)
    extra=dict(kind='uart_consumption_match',event_id='native',proof_scope='cpu_external_irq_taken',status='accepted')
    assert not m.consume(extra)
    assert len(accepted(play(m,s.events)))==1


def test_repeated_same_scope_failure_does_not_prevent_measured_reset_recovery():
    s,r=scenario();m=tracker(s);play(m,s.events);m._seed.max_components=1
    for eid in ('bad-1','bad-2'):
        m.consume(dict(kind='cpu_flush',event_id=eid,source_component='cpu',source_epoch=0,execution_id='cpu-execution'))
    reset=dict(kind='cpu_reset',event_id='recovery-reset',component='cpu',source_component='cpu',
        reset_epoch=1,source_epoch=1,physical_reset=True,execution_id='cpu-execution')
    play(m,[reset]);assert m._healthy('cpu',1)
