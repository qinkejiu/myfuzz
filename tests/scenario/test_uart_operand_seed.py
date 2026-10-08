"""Simulated actual-shaped receipts; these are not real RTL evidence."""
from copy import deepcopy
import pytest
from tests.scenario.test_uart_retired_read import Stream
from myfuzz.scenario.uart_operand_seed import UartOperandSeedTracker


def model(s, **kwargs):
    return UartOperandSeedTracker(admission_registry=s.registry,ownership=s.owner,edge_index=s.index,**kwargs)


def play(m, events):
    return [r for e in events for r in m.consume(deepcopy(e))]


def seeds(out):
    return [r for r in out if r.get('status')=='accepted']


def test_exact_raw_load_seed_and_detached_current_version():
    s=Stream();es=s.lifecycle();m=model(s);ps=seeds(play(m,es));assert len(ps)==1
    p=ps[0];r=next(e for e in es if e.get('kind')=='cpu_retire')
    assert p['register_version_key']==['cpu',0,0,3]
    assert p['retirement_event_id']==r['event_id'] and p['fullkey']['source_sequence']==1
    assert p['proof_scope']=='uart_retired_load_register_seed'
    assert p['influenced_bits']==[0,8] and p['upper_bits_origin']=='unknown'
    current=m.register_at('cpu',0,3);assert current['origin_status']=='known_uart_load'
    current['origin_status']='forged';assert m.register_at('cpu',0,3)['origin_status']=='known_uart_load'
    assert not seeds(play(m,es))


@pytest.mark.parametrize('kind',['instr_response','data_accept','data_response','cpu_retire',
    'cpu_retirement_match','uart_frame_validation','uart_rdata_access','uart_consumption_match'])
def test_missing_raw_or_logged_witness_no_seed(kind):
    s=Stream();es=s.lifecycle();assert not seeds(play(model(s),[e for e in es if e.get('kind')!=kind]))


@pytest.mark.parametrize('field,value',[('rd_addr',0),('trap',1),('ext_rf_wr_suppress',1),
    ('rd_wcap',1),('mem_is_cap',1),('rd_addr',True),('order',True)])
def test_forbidden_destination_or_effect_no_seed(field,value):
    s=Stream();es=s.lifecycle()
    for e in es:
        if e.get('kind')=='cpu_retire':
            e[field]=value;e['observation']['physical']['rvfi_'+field]=value
    assert not seeds(play(model(s),es))


def overwrite(raw):
    e=deepcopy(raw);e.update(event_id='unknown-overwrite',order=raw['order']+1,insn=0x000001b3,
        local_tick=raw['local_tick']+1)
    e['command_scope']['command_sequence']+=1;e['receipt_id']['sequence']+=1
    e['actual_post_ref']=dict(command_scope=deepcopy(e['command_scope']),local_tick=e['local_tick'],phase='post')
    e['receipt_ticks']['tick_before']+=1;e['receipt_ticks']['tick_after']+=1
    e['observation']['physical']={'rvfi_'+k:e[k] for k in raw['observation']['physical'] for k in [k[5:]]}
    return e


def test_late_old_proof_cannot_relabel_equal_value_overwrite():
    s=Stream();es=s.lifecycle();r=next(e for e in es if e.get('kind')=='cpu_retire')
    proof=next(e for e in es if e.get('kind')=='uart_consumption_match')
    es=[e for e in es if e is not proof];pos=next(i for i,e in enumerate(es) if e.get('kind')=='cpu_retirement_match')
    es.insert(pos+1,overwrite(r));es.append(proof)
    m=model(s);ps=seeds(play(m,es));assert len(ps)==1
    assert ps[0]['register_version_key']==['cpu',0,0,3]
    cur=m.register_at('cpu',0,3);assert cur['register_version_key']==['cpu',0,1,3]
    assert cur['origin_status']=='unknown' and cur['measured_value']==0


def test_forged_accepted_label_without_raw_authority_no_seed():
    s=Stream();es=s.lifecycle();fake=dict(kind='uart_retired_read_match',event_id='forged',status='accepted',
        proof_scope='cpu_retired_uart_rdata_read',retirement_event_id='cpu-r:1',destination_register=3,read_value=0)
    assert not seeds(play(model(s),[fake]))


def test_live_pending_capacity_latches_barrier():
    s=Stream();es=s.lifecycle();r=next(e for e in es if e.get('kind')=='cpu_retire')
    m=model(s,max_pending=1);play(m,[e for e in es if e.get('kind')!='uart_consumption_match'])
    second=overwrite(r);second['insn']=r['insn'];second['observation']['physical']['rvfi_insn']=r['insn']
    out=play(m,[second]);assert any(x.get('reason')=='uart_operand_pending_capacity' for x in out)
    assert not seeds(play(m,[e for e in es if e.get('kind')=='uart_consumption_match']))


def test_measured_reset_invalidates_current_and_old_pending():
    s=Stream();es=s.lifecycle();m=model(s);play(m,es)
    reset=dict(kind='cpu_reset',event_id='actual-reset',component='cpu',source_component='cpu',reset_epoch=1,
        source_epoch=1,physical_reset=True,execution_id='run')
    play(m,[reset]);assert m.register_at('cpu',0,3) is None
    assert not seeds(play(m,es))


def test_current_query_closes_after_flush_barrier():
    s=Stream();m=model(s);play(m,s.lifecycle())
    play(m,[dict(kind='cpu_flush',event_id='flush',source_component='cpu',source_epoch=0,execution_id='cpu-execution')])
    assert m.register_at('cpu',0,3) is None


@pytest.mark.parametrize('bad',[{'kind':[]},{'kind':'cpu_retire','event_id':'bad','source_component':[]}])
def test_malformed_container_never_throws(bad):
    s=Stream();assert not seeds(model(s).consume(bad))


def test_evicted_numeric_event_identity_cannot_be_reused():
    s=Stream();m=model(s,max_pending=1,max_event_refs=2)
    for eid in (1,2,3):m.consume(dict(kind='cpu_retirement_match',event_id=eid))
    out=m.consume(dict(kind='cpu_retirement_match',event_id=1,status='accepted'))
    assert any(x.get('reason')=='stale_uart_operand_event_identity' for x in out)


@pytest.mark.parametrize('field,value',[('rd_addr',32),('rd_addr',-1),('rd_wdata',1<<32),
    ('rd_wdata',-1),('rd_wdata',True),('ext_rf_wr_suppress',True),('ext_rf_wr_suppress',2)])
def test_malformed_raw_write_width_cannot_mint_seed(field,value):
    s=Stream();es=s.lifecycle()
    for e in es:
        if e.get('kind')=='cpu_retire':e[field]=value;e['observation']['physical']['rvfi_'+field]=value
    assert not seeds(play(model(s),es))


def test_string_identity_capacity_fails_closed_without_eviction():
    s=Stream();m=model(s,max_event_refs=1)
    m.consume(dict(kind='cpu_retirement_match',event_id='old'))
    out=m.consume(dict(kind='cpu_retirement_match',event_id='new'))
    assert any(x.get('reason')=='uart_operand_event_identity_capacity' for x in out)
    assert 'old' in m._seen and 'new' not in m._seen


def test_source_contract_post_reference_required():
    s=Stream();es=s.lifecycle()
    for e in es:
        if e.get('kind')=='cpu_retire':e.pop('actual_post_ref')
    assert not seeds(play(model(s),es))


@pytest.mark.parametrize('field,value',[('execution_id','other'),('testcase_id','other'),
    ('source_component','other'),('source_epoch',1),('channel_id','instr'),('source_sequence',2)])
def test_all_transaction_key_fields_bind_seed_authority(field,value):
    s=Stream();es=s.lifecycle()
    for e in es:
        if e.get('kind')=='uart_consumption_match':e['source_transaction'][field]=value
    assert not seeds(play(model(s),es))


def test_many_consumed_numeric_event_identities_remain_bounded_and_replay_closed():
    s=Stream();m=model(s,max_event_refs=3)
    for eid in range(1,1101):
        out=m.consume(dict(kind='cpu_retirement_match',event_id=eid,source_component='cpu',
            source_epoch=0,execution_id='cpu-execution',status='rejected'))
        assert not out
    assert len(m._seen)==3 and not m._global_bad
    out=m.consume(dict(kind='cpu_retirement_match',event_id=1,source_component='cpu',
        source_epoch=0,execution_id='cpu-execution',status='accepted'))
    assert any(x.get('reason')=='stale_uart_operand_event_identity' for x in out)


def test_pending_capacity_cleared_only_by_measured_advanced_reset():
    s=Stream();es=s.lifecycle();r=next(e for e in es if e.get('kind')=='cpu_retire')
    m=model(s,max_pending=1);play(m,[e for e in es if e.get('kind')!='uart_consumption_match'])
    second=overwrite(r);second['insn']=r['insn'];second['observation']['physical']['rvfi_insn']=r['insn']
    play(m,[second]);assert m._states['cpu']['bad']
    reset=dict(kind='cpu_reset',event_id='measured-reset',component='cpu',source_component='cpu',
        reset_epoch=1,source_epoch=1,physical_reset=True,execution_id='cpu-execution')
    play(m,[dict(reset,event_id='unmeasured',physical_reset=False)])
    assert m._states['cpu']['bad']
    play(m,[reset]);assert not m._states['cpu']['bad'] and m.pending_count==0
