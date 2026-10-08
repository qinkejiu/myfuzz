"""Software callback authority, never RTL RAM evidence."""
from dataclasses import asdict
import json
import pytest
from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
from myfuzz.scenario.memory_service import MemoryService,WriteReceipt
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority


def setup(**limits):
 m=PersistentMemory(regions=(MemoryRegion('ram',0x20000,4096),),initialization_seed=9,max_initialized_bytes=4096)
 l=TransactionLedger();s=MemoryService(m,l,commit_stream_capacity=4)
 return s,MemoryCommitAuthority(services={'cpu':s},**limits)


def key(seq=1):return TransactionKey('execution','case','cpu',0,'data',seq)
def write(s,seq=1,be=15):return s.write(key(seq),0x20000,90,width_bytes=4,byte_enable=be)
def stage(a,s,r,k=None):
 t=a.stage('cpu',s,s.ledger,k or (r.transaction_id if isinstance(r,WriteReceipt) else key()),r)
 if type(t) is int:s.ack_commit_events((r.commit_document()['commit_id'],))
 return t


def test_exact_actual_callback_once_and_detached():
 s,a=setup();r=write(s);t=stage(a,s,r);assert type(t) is int
 p=a.resolve(t);assert p['proof_scope']=='installed_host_memory_commit' and p['commit_document']==r.commit_document()
 assert p['memory_kind']=='modeled_host_persistent_memory' and p['source_origin']=='unknown'
 p['commit_document']['enabled_byte_cells'][0]['value']=255
 assert r.commit_document()['enabled_byte_cells'][0]['value']==90
 assert a.resolve(t) is None and stage(a,s,r) is None


def test_selfsigned_document_hash_or_manual_receipt_not_authority():
 s,a=setup();r=write(s)
 assert stage(a,s,r.commit_document(),key()) is None
 fake=WriteReceipt(key(),r.version,15);object.__setattr__(fake,'_commit_json',r._commit_json)
 assert stage(a,s,fake) is None


def test_forged_complete_same_installed_ledger_not_actual_callback():
 s,a=setup();k=key();payload=dict(op='write',address=0x20000,value=90,width_bytes=4,byte_enable=15)
 fake=WriteReceipt(k,(0,1),15)
 object.__setattr__(fake,'_commit_json',b'{}')
 s.ledger.execute_once(k,payload,lambda:fake)
 assert stage(a,s,fake) is None


def test_external_service_ledger_wrong_key_reject():
 s,a=setup();r=write(s);other,_=setup();rr=write(other)
 assert stage(a,other,rr) is None
 assert a.stage('cpu',s,other.ledger,key(),r) is None
 assert stage(a,s,r,key(2)) is None


def test_actual_receipt_original_bytes_cannot_be_modified():
 s,a=setup();r=write(s);doc=r.commit_document();doc['generation']=1
 object.__setattr__(r,'_commit_json',json.dumps(doc).encode())
 assert stage(a,s,r) is None


def test_be_zero_and_uncertain_never_authorize():
 s,a=setup();r=write(s,be=0);assert stage(a,s,r) is None
 k=key(2)
 def fail():raise RuntimeError('failed')
 with pytest.raises(RuntimeError):s.ledger.execute_once(k,{},fail)
 assert a.stage('cpu',s,s.ledger,k,WriteReceipt(k,(0,2),15)) is None


def test_delayed_resolve_survives_newer_exact_commits():
 s,a=setup(max_pending=2);old=stage(a,s,write(s))
 for seq in range(2,270):assert a.resolve(stage(a,s,write(s,seq))) is not None
 assert a.pending_count==1 and a.resolve(old)['commit_document']['version']==[0,1]
 assert stage(a,s,s.ledger._entries[key()].receipt) is None


def test_live_pending_capacity_global_barrier_never_eviction():
 s,a=setup(max_pending=1);old=stage(a,s,write(s));assert old is not None
 assert stage(a,s,write(s,2)) is None
 assert a.degraded and a.pending_count==1 and a.resolve(old) is None


def test_replacing_installed_memory_or_ledger_rejects():
 s,a=setup();r=write(s);s.ledger=TransactionLedger();assert stage(a,s,r) is None


@pytest.mark.parametrize('bad',[None,[],{},True,0,'not-token'])
def test_malformed_resolve_total(bad):
 s,a=setup();assert a.resolve(bad) is None


@pytest.mark.parametrize('field,value',[('execution_id','other'),('testcase_id','other'),
 ('source_component','other'),('source_epoch',1),('channel_id','instr'),('source_sequence',2)])
def test_each_fullkey_field_bound(field,value):
 s,a=setup();r=write(s);fields=asdict(key());fields[field]=value
 assert stage(a,s,r,TransactionKey(**fields)) is None


@pytest.mark.parametrize('limits',[{'max_pending':0},{'max_services':True},{'max_regions':0}])
def test_strict_capacity_constructor(limits):
 with pytest.raises(ValueError):setup(**limits)


def test_constructor_not_selfasserted_service_document():
 with pytest.raises(ValueError):MemoryCommitAuthority(services={'cpu':{'status':'accepted'}})


def test_producer_ack_before_stage_cannot_mint_old_receipt():
 s,a=setup();r=write(s);s.ack_commit_events((r.commit_document()['commit_id'],))
 assert stage(a,s,r) is None


def test_stage_historical_certificate_is_not_current_memory_retention():
 s,a=setup();r=write(s);t=stage(a,s,r)
 s.memory.cold_reset();new=stage(a,s,write(s,2))
 assert a.resolve(t)['commit_document']['generation']==0
 assert a.resolve(new)['commit_document']['generation']==1


def test_unstaged_out_of_order_older_issuance_stays_unknown():
 s,a=setup();old=write(s);new=write(s,2)
 t=a.stage('cpu',s,s.ledger,key(2),new);assert type(t) is int
 assert a.stage('cpu',s,s.ledger,key(),old) is None
 assert a.resolve(t)['commit_document']['version']==[0,2]
 s.ack_commit_events((old.commit_document()['commit_id'],new.commit_document()['commit_id']))


def test_be_zero_drain_unknown_and_ack_does_not_leak_capacity():
 s,a=setup()
 for sequence in range(1,270):
  r=write(s,sequence,be=0);assert stage(a,s,r) is None
  s.ack_commit_events((r.commit_document()['commit_id'],))
 assert a.pending_count==0 and not a.degraded and s.memory.initialized_bytes==0


def test_corrupted_actual_issuance_latches_barrier():
 s,a=setup();r=write(s);object.__setattr__(r,'_commit_json',b'{}')
 assert stage(a,s,r) is None and a.degraded
 assert a.stage('cpu',s,s.ledger,key(2),write(s,2)) is None


@pytest.mark.parametrize('component',['other',None,[],True])
def test_uninstalled_component_total_unknown(component):
 s,a=setup();r=write(s);assert a.stage(component,s,s.ledger,key(),r) is None
