from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock
import pytest
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract, PULP_GPIO_PROBES
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger


def session(*replies):
    doc = {'schema_version':'local_runtime_artifact.v1','driver_schema_version':'local_driver_generation.v1','status':'driver_generated','driver_status':'generated','kind':'apb_gpio','artifact_digest':'a'*64,'driver_reset':{'schema_version':'generated_local_reset.v1','reset_assert_ticks':8,'reset_release_ticks':4},'effective_max_wait_cycles':8,'gpio_observation_contract':pulp_gpio_observation_contract()}
    doc['plan']={'instance_id':'gpio'}
    doc['physical_exports']=[{'physical_port':'gpio_probe_'+n,'runtime_name':'gpio_probe_'+n,'width':w,'direction':'output'} for n,(w,_) in PULP_GPIO_PROBES.items()] + [{'physical_port':'gpio_in','runtime_name':'gpio_in','width':32,'direction':'input'}]
    s = GeneratedPulpGpioSession(type('Artifact',(),{'runtime_document':doc})(),base_dir=Path('.'),cache_dir=Path('.'))
    s.command = Mock(side_effect=replies)
    return s


def receipt(offset=12, write=1, value=7, read=0, post_status=0):
    p = {f'gpio_probe_{name}':0 for name in PULP_GPIO_PROBES}
    p.update(dict(gpio_probe_apb_addr=offset,gpio_probe_psel=1,gpio_probe_penable=1,gpio_probe_pwrite=write,gpio_probe_pwdata=value,gpio_probe_prdata=read,gpio_probe_pready=1,gpio_probe_pslverr=0,gpio_probe_status=read,gpio_probe_irq_trigger_mask=0))
    snap = {'gpio_out':value,'gpio_dir':0,'gpio_in_sync':0,'interrupt':0,'gpio_padcfg':'0'*32,'physical':p,'backend':{'req_valid':1,'req_ready':1,'rsp_valid':1,'rsp_ready':1}}
    post = {**snap,'physical':{**p,'gpio_probe_status':post_status}}
    return DriverReceipt('result','a'*32,1,0,1,1,payload={'samples':[{'local_tick':1,'pre':snap,'post':post}],'observations':post,'rdata':read,'error':0})


def key(seq=1): return TransactionKey('exec','case','cpu',0,'data',seq)

def route(s): return DataflowRouter((DeviceWindow('gpio',0x40001000,4096,s),))
def send(r,l,k,**kw): return r.transact(l,k,address=0x4000100c,write=True,wdata=7,be=15,beat_bytes=4,**kw)

def test_full_keys_distinct_equal_values_retry_once():
    s=session(receipt(),receipt()); r=route(s); l=TransactionLedger()
    send(r,l,key()); send(r,l,key()); send(r,l,key(2))
    events=[e for e in s.gpio_events if e['kind']=='gpio_apb_access']
    assert [e['source_transaction'] for e in events]==[asdict(key()),asdict(key(2))]
    assert events[0]['access_id']!=events[1]['access_id']
    assert s.command.call_count==2
    assert r.deliveries[0]['target_access_id']==events[0]['access_id']

def test_partial_write_rejects_before_command():
    s=session(); r=route(s)
    with pytest.raises(ValueError,match='full-word'):
        r.transact(TransactionLedger(),key(),address=0x4000100c,write=True,wdata=7,be=1,beat_bytes=4)
    s.command.assert_not_called()

def test_read_uses_pre_status_value_and_detached_facts():
    s=session(receipt(36,0,0,read=9)); r=route(s)
    assert r.transact(TransactionLedger(),key(),address=0x40001024,write=False,wdata=0,be=15,beat_bytes=4)==(9,0)
    e=next(e for e in s.gpio_events if e['kind']=='gpio_apb_access')
    assert e['read_rdata']==9 and e['post']['gpio_probe_status']==0

def test_lost_receipt_uncertain_and_no_delivery():
    s=session(RuntimeError('lost_reply')); r=route(s); l=TransactionLedger()
    with pytest.raises(RuntimeError): send(r,l,key())
    assert not r.deliveries and key() in l.uncertain_keys
    assert s.gpio_events[-1]['status']=='uncertain'

def test_context_mismatch_before_command():
    s=session()
    with pytest.raises(ValueError,match='context'):
        s.routed_register_access(key(),address=0x4000100c,offset=12,write=True,value=7,be=15,delivery_context={'source_transaction':asdict(key(2))})
    s.command.assert_not_called()

def test_actual_request_and_response_handshakes_required_for_delivery_witness():
    reply=receipt()
    reply.payload['samples'][0]['pre']['backend']={'gpio_req_valid':1,'gpio_req_ready':1,'gpio_req_addr':12,'gpio_req_write':1,'gpio_req_wdata':7,'gpio_req_be':15,'gpio_rsp_valid':1,'gpio_rsp_ready':1,'gpio_rsp_rdata':0,'gpio_rsp_error':0}
    import copy
    access=copy.deepcopy(reply.payload['samples'][0])
    req=copy.deepcopy(access); req['local_tick']=1
    req['pre']['physical']['gpio_probe_psel']=0
    req['pre']['backend']['gpio_rsp_valid']=0
    access['local_tick']=2
    access['pre']['backend']['gpio_req_valid']=0
    access['pre']['backend']['gpio_rsp_valid']=0
    rsp=copy.deepcopy(access); rsp['local_tick']=3
    rsp['pre']['physical']['gpio_probe_psel']=0
    rsp['pre']['backend']['gpio_rsp_valid']=1
    reply.payload['samples']=[req,access,rsp]
    s=session(reply); r=route(s); send(r,TransactionLedger(),key())
    delivery=r.deliveries[0]
    assert delivery['target_request']['status']=='observed'
    assert delivery['target_response']['status']=='observed'
    assert delivery['target_request']['source_transaction']==asdict(key())


def test_cancelled_queue_never_accesses_target():
    s=session(); r=route(s); l=TransactionLedger()
    r.enqueue(l,key(),address=0x4000100c,write=True,wdata=7,be=15,beat_bytes=4,callback=lambda _:None)
    r.cancel_for_ledger(l)
    assert not r.drain_one('gpio')
    s.command.assert_not_called()

def test_setup_only_is_incomplete_without_access_witness():
    reply=receipt(); reply.payload['samples'][0]['pre']['physical']['gpio_probe_penable']=0
    s=session(reply); r=route(s); send(r,TransactionLedger(),key())
    assert not any(e['kind']=='gpio_apb_access' for e in s.gpio_events)
    assert r.deliveries[0]['target_request']['status']=='incomplete'

def test_callback_exception_preserves_actual_raw_facts_and_prevents_reexecute():
    s=session(receipt()); r=route(s); l=TransactionLedger()
    def fail(_): raise RuntimeError('callback')
    r.enqueue(l,key(),address=0x4000100c,write=True,wdata=7,be=15,beat_bytes=4,callback=fail)
    with pytest.raises(RuntimeError,match='callback'): r.drain_one('gpio')
    assert any(e['kind']=='gpio_apb_access' for e in s.gpio_events)
    assert not r.drain_one('gpio')
    assert not r.deliveries
    assert s.gpio_events[-1]['status']=='uncertain_source_response'
    assert s.command.call_count==1

def test_optin_identity_contains_context_schema_and_detached_contract():
    from unittest.mock import patch
    from myfuzz.local_harness.session import GeneratedLocalSession
    s=session()
    with patch.object(GeneratedLocalSession,'identity_document',return_value={'legacy':'unchanged'}):
        identity=s.identity_document()
    assert identity['gpio_target_context_schema_version']=='pulp_gpio_routed_access.v1'
    assert identity['gpio_observation_contract']==s.artifact.runtime_document['gpio_observation_contract']
    identity['gpio_observation_contract']['schema_version']='tampered'
    assert s.artifact.runtime_document['gpio_observation_contract']['schema_version']=='pulp_gpio_observation.v1'


def test_contract_mutation_rejected_before_access():
    s=session(); s.artifact.runtime_document['gpio_observation_contract']['variant_id']='tampered'
    with pytest.raises(ValueError,match='changed'):
        send(route(s),TransactionLedger(),key())
    s.command.assert_not_called()


def test_malformed_contract_rejected_on_construction():
    s=session(); s.artifact.runtime_document['gpio_observation_contract']={'schema_version':'fake'}
    with pytest.raises(ValueError,match='observation contract'):
        GeneratedPulpGpioSession(s.artifact,base_dir=Path('.'),cache_dir=Path('.'))


def test_reentrant_failed_callback_keeps_its_exact_access():
    s=session(receipt(),receipt()); r=route(s); l=TransactionLedger()
    def fail(_):
        send(r,l,key(2))
        raise RuntimeError('callback')
    r.enqueue(l,key(),address=0x4000100c,write=True,wdata=7,be=15,beat_bytes=4,callback=fail)
    with pytest.raises(RuntimeError):r.drain_one('gpio')
    assert [d['source_transaction'] for d in r.deliveries]==[key(2)]
    assert r.deliveries[0]['target_delivery_order']==2
    assert r.deliveries[0]['delivery_order']==2
    assert s.gpio_events[-1]['source_transaction']==asdict(key())
    assert s.gpio_events[-1]['access_id']!=r.deliveries[0]['target_access_id']


def test_router_carries_actual_apb_access():
    s=session(receipt()); r=route(s); send(r,TransactionLedger(),key())
    e=r.deliveries[0]['target_apb_access']
    assert e['source_transaction']==asdict(key())
    assert e['pre']['gpio_probe_penable']==1
    assert e['access_id']==r.deliveries[0]['target_access_id']

def test_missing_passive_probe_remains_incomplete():
    reply=receipt(); del reply.payload['samples'][0]['pre']['physical']['gpio_probe_sync0']
    s=session(reply); r=route(s); send(r,TransactionLedger(),key())
    assert r.deliveries[0]['target_apb_access']['status']!='observed'


def test_status_read_new_event_priority_and_lifetime_tick():
    reply=receipt(36,0,0,read=8,post_status=9)
    pre=reply.payload['samples'][0]['pre']['physical']
    pre.update(gpio_probe_irq_trigger_mask=1,gpio_probe_native_irq=1)
    s=session(reply); s._tick_base=100; s.reset_epoch=2; r=route(s)
    assert r.transact(TransactionLedger(),key(),address=0x40001024,write=False,wdata=0,be=15,beat_bytes=4)==(8,0)
    e=r.deliveries[0]['target_apb_access']
    assert e['local_tick']==101 and e['command_scope']['reset_epoch']==2
    assert e['read_rdata']==8 and e['post']['gpio_probe_status']==9
    assert e['status_read_outcome']=='new_event_priority'
    assert s.command.call_count==1

def source_context(value=1):
    return {'component':'gpio','segments':[{'bit_lo':0,'width':1,'value':value,'origin':{'action_id':'source-1'}}]}


def input_receipt(value=1):
    reply=receipt()
    for phase in ('pre','post'):reply.payload['samples'][0][phase]['physical']['gpio_in']=value
    return reply


def test_paired_tick_normalizes_authenticated_runtime_exports():
    # Exact artifact row mapping, rather than a guessed runtime name.
    reply=input_receipt();s=session(reply)
    rows=[{'physical_port':n,'runtime_name':'actual_'+n,'width':32} for n in reply.payload['samples'][0]['pre']['physical']]
    s.artifact.runtime_document['physical_exports']=rows;s._artifact_document['physical_exports']=rows
    for phase in ('pre','post'):
        snap=reply.payload['samples'][0][phase]
        snap['physical']={'actual_'+n:v for n,v in snap['physical'].items()}
    s.step_local({'gpio_in':1})
    e=next(e for e in s.gpio_events if e['kind']=='gpio_tick_observation')
    assert e['pre']['gpio_in']==1 and e['post']['gpio_probe_sync0']==0
    assert e['command_scope']['command_sequence']==1


def test_logical_context_not_applied_by_access():
    s=session(input_receipt());s.set_next_gpio_input_context(source_context())
    send(route(s),TransactionLedger(),key())
    assert not any(e['kind']=='gpio_input_applied' for e in s.gpio_events)
    e=next(e for e in s.gpio_events if e['kind']=='gpio_tick_observation')
    assert e['active_input_context'] is None


def test_input_context_only_applied_after_matching_actual_step():
    s=session(input_receipt(),input_receipt());ctx=source_context();s.set_next_gpio_input_context(ctx)
    ctx['segments'][0]['origin']['action_id']='changed'
    s.step_local({'gpio_in':1});send(route(s),TransactionLedger(),key())
    e=next(e for e in s.gpio_events if e['kind']=='gpio_input_applied')
    assert e['actual_input_value']==1
    assert e['segments'][0]['origin']['action_id']=='source-1'
    ticks=[e for e in s.gpio_events if e['kind']=='gpio_tick_observation']
    assert ticks[-1]['active_input_context']['segments'][0]['origin']['action_id']=='source-1'


def test_mismatched_actual_drive_and_reset_do_not_reuse_context():
    from unittest.mock import patch
    from myfuzz.local_harness.session import GeneratedLocalSession
    s=session(input_receipt(2),input_receipt())
    s.set_next_gpio_input_context(source_context());s.step_local({'gpio_in':1})
    assert not any(e['kind']=='gpio_input_applied' for e in s.gpio_events)
    s.set_next_gpio_input_context(source_context())
    def completed_reset(target):
        target.reset_epoch += 1
        return {}
    with patch.object(GeneratedLocalSession,'reset_local',completed_reset):s.reset_local()
    s.step_local({'gpio_in':1})
    assert not any(e['kind']=='gpio_input_applied' for e in s.gpio_events)

def test_routed_producer_access_precedes_its_exact_tick_and_tracker_versions():
    from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
    reply=input_receipt(0)
    reply.payload['samples'][0]['post']['physical']['gpio_probe_out']=7
    for phase in ('pre','post'):
        reply.payload['samples'][0][phase]['physical'].update(gpio_probe_decoded_word=3,gpio_probe_write=1,gpio_probe_write_out=0xffffffff)
    s=session(reply);send(route(s),TransactionLedger(),key())
    facts=[e for e in s.gpio_events if e['kind'] in ('gpio_apb_access','gpio_tick_observation')]
    assert [e['kind'] for e in facts]==['gpio_apb_access','gpio_tick_observation']
    assert facts[0]['command_scope']==facts[1]['command_scope']
    t=GpioConsumptionTracker();commit=None
    for n,e in enumerate(facts):
        e['event_id']=n+1
        records=t.consume(e)
        for record in records:
            if record['kind']=='gpio_register_commit':commit=record
    assert t.output_resources_at('gpio',0,1,'post')[0]['version']==commit['bit_resources'][0]['version']

def test_successful_reset_marker_advanced_epoch_and_next_tracker_sample():
    from unittest.mock import patch
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
    reply=input_receipt(0)
    for phase in ('pre','post'):
        reply.payload['samples'][0][phase]['physical'].update(gpio_probe_psel=0,gpio_probe_penable=0,gpio_probe_pwrite=0,gpio_probe_apb_addr=0)
    s=session(reply);t=GpioConsumptionTracker()
    def complete_reset(target):
        target.reset_epoch+=1;target._sequence=0
        return {'cancelled_responses':0}
    with patch.object(GeneratedLocalSession,'reset_local',complete_reset):s.reset_local()
    marker=s.gpio_events[-1]
    assert marker['kind']=='gpio_reset' and marker['reset_epoch']==marker['source_epoch']==1
    assert marker['command_scope']['command_sequence']==0
    marker['event_id']=1;assert t.consume(marker)[-1]['status']=='observed'
    s.step_local({'gpio_in':0})
    tick=next(e for e in s.gpio_events if e['kind']=='gpio_tick_observation')
    tick['event_id']=2
    assert any(e['kind']=='gpio_input_sample' and e['status']=='observed' for e in t.consume(tick))


def test_failed_reset_never_publishes_success_marker():
    from unittest.mock import patch
    from myfuzz.local_harness.session import GeneratedLocalSession
    s=session()
    with patch.object(GeneratedLocalSession,'reset_local',side_effect=RuntimeError('failed_reset')):
        with pytest.raises(RuntimeError):s.reset_local()
    assert not any(e['kind']=='gpio_reset' for e in s.gpio_events)
