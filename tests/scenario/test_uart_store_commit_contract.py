"""RED producer contract for modeled host PersistentMemory, never RTL RAM.

Real MemoryService/TransactionLedger callbacks are exercised. No later RAM read
or UART-to-Store origin is claimed here: this contract supplies a future join's
missing immutable commit receipt, not source authority by an accepted label.
"""
from dataclasses import asdict
import hashlib
import json
from unittest.mock import patch
import pytest
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService


def fixture():
    memory=PersistentMemory(regions=(MemoryRegion('host-ram',0x20000,0x1000),),
        initialization_seed=9,max_initialized_bytes=4096)
    ledger=TransactionLedger();return memory,ledger,MemoryService(memory,ledger)


def key(sequence=1,**fields):
    return TransactionKey(**dict(dict(execution_id='simulated-execution',testcase_id='case-A',
        source_component='cpu',source_epoch=0,channel_id='data',source_sequence=sequence),**fields))


def write(service,k=None,value=0x5a,be=15):
    return service.write(k or key(),0x20000,value,width_bytes=4,byte_enable=be)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def test_actual_callback_commit_document_binds_fullkey_and_enabled_byte_versions():
    memory,ledger,service=fixture();k=key();receipt=write(service,k)
    # Proposed narrow API. Missing on current producer: intentional RED.
    doc=receipt.commit_document()
    assert doc['schema_version']=='memory_write_commit_receipt.v1'
    assert doc['fullkey']==asdict(k) and doc['memory_kind']=='modeled_host_persistent_memory'
    assert doc['memory_id']=='host-ram' and doc['generation']==0 and doc['byte_offset']==0
    assert doc['width_bytes']==4 and doc['byte_enable']==15 and doc['version']==[0,1]
    payload=dict(op='write',address=0x20000,value=0x5a,width_bytes=4,byte_enable=15)
    assert doc['payload_sha256']==TransactionLedger._digest(payload)
    assert doc['commit_status']=='complete' and doc['performed_effect'] is True
    assert doc['enabled_byte_cells']==[
        dict(byte_offset=i,value=(0x5a if i==0 else 0),version=[0,1],writer_kind='STORE',writer_event_id=str(k))
        for i in range(4)]
    core={name:value for name,value in doc.items() if name!='commit_id'}
    assert doc['commit_id']==hashlib.sha256(canonical(core)).hexdigest()
    assert not ledger.uncertain_keys and len(service.events)==1
    doc['enabled_byte_cells'][0]['value']=0xff
    assert receipt.commit_document()['enabled_byte_cells'][0]['value']==0x5a


def test_duplicate_returns_same_frozen_commit_after_later_equal_value_store():
    memory,_,service=fixture();k=key();old=write(service,k);before=old.commit_document()
    newer=write(service,key(2));assert newer.version!=old.version
    repeated=write(service,k)
    assert repeated is old and repeated.commit_document()==before
    assert len(service.events)==2 and memory._commit_sequences['host-ram']==2


def test_partial_enable_certifies_only_actual_enabled_cells():
    _,_,service=fixture();receipt=write(service,be=1);doc=receipt.commit_document()
    assert doc['enabled_byte_cells']==[dict(byte_offset=0,value=0x5a,version=[0,1],
        writer_kind='STORE',writer_event_id=str(key()))]
    assert doc['byte_enable']==1 and doc['performed_effect'] is True


def test_zero_enable_is_not_a_byte_effect_certificate():
    memory,_,service=fixture();receipt=write(service,be=0);doc=receipt.commit_document()
    assert doc['version'] is None and doc['enabled_byte_cells']==[]
    assert doc['performed_effect'] is False and memory._commit_sequences['host-ram']==0


def test_warm_reset_preserves_old_receipt_cold_reset_separates_generation():
    memory,_,service=fixture();old=write(service);original=old.commit_document()
    memory.warm_reset();assert old.commit_document()==original
    memory.cold_reset();new=write(service,key(2))
    assert old.commit_document()==original and new.commit_document()['version']==[1,1]
    assert new.commit_document()['commit_id']!=original['commit_id']


@pytest.mark.parametrize('field,value',[('execution_id',True),('testcase_id',True),
    ('source_component',True),('channel_id',True),('execution_id',1),('source_component',1)])
def test_malformed_fullkey_rejected_before_any_host_memory_commit(field,value):
    memory,_,service=fixture()
    with pytest.raises((ValueError,TypeError)):write(service,key(**{field:value}))
    assert not service.events and memory._commit_sequences['host-ram']==0


def test_samekey_conflicting_payload_does_not_execute_another_commit():
    memory,_,service=fixture();write(service)
    with pytest.raises(ValueError,match='identity_conflict'):write(service,value=0x7e)
    assert len(service.events)==1 and memory._commit_sequences['host-ram']==1


def test_failed_callback_has_no_receipt_or_success_event_and_cannot_retry():
    memory,ledger,service=fixture();k=key()
    with patch.object(memory,'write',side_effect=RuntimeError('simulated callback failure')):
        with pytest.raises(RuntimeError,match='callback failure'):write(service,k)
    assert ledger.uncertain_keys==(k,) and not service.events
    assert memory._commit_sequences['host-ram']==0
    with pytest.raises(RuntimeError,match='uncertain_effect'):write(service,k)
    assert not service.events and memory._commit_sequences['host-ram']==0


def test_effect_then_callback_failure_stays_uncertain_even_if_bytes_changed():
    memory,ledger,service=fixture();original=memory.write;k=key()
    def fail_after_effect(*args,**kwargs):
        original(*args,**kwargs);raise RuntimeError('simulated post-effect failure')
    with patch.object(memory,'write',side_effect=fail_after_effect):
        with pytest.raises(RuntimeError,match='post-effect failure'):write(service,k)
    assert memory._commit_sequences['host-ram']==1 and not service.events
    assert ledger.uncertain_keys==(k,)
    with pytest.raises(RuntimeError,match='uncertain_effect'):write(service,k)
    assert memory._commit_sequences['host-ram']==1 and not service.events


def test_legacy_receipt_dataclass_shape_and_constructor_remain_three_fields():
    from dataclasses import fields
    from myfuzz.scenario.memory_service import WriteReceipt
    _,_,service=fixture();receipt=write(service)
    assert [f.name for f in fields(WriteReceipt)]==['transaction_id','version','byte_enable']
    assert asdict(receipt)==dict(transaction_id=asdict(key()),version=(0,1),byte_enable=15)
    legacy=WriteReceipt(key(),(0,1),15)
    with pytest.raises(ValueError,match='no measured'):legacy.commit_document()


def test_commit_document_never_materializes_disabled_or_missing_bytes():
    memory,_,service=fixture();receipt=write(service,be=1)
    assert memory.initialized_bytes==1
    receipt.commit_document();assert memory.initialized_bytes==1
    memory,_,service=fixture();receipt=write(service,be=0)
    receipt.commit_document();assert memory.initialized_bytes==0


def test_receipt_internal_snapshot_is_immutable():
    from dataclasses import FrozenInstanceError
    _,_,service=fixture();receipt=write(service)
    with pytest.raises(FrozenInstanceError):receipt._commit_json=b'{}'


def test_callback_returned_version_conflicting_with_actual_cells_is_uncertain():
    memory,ledger,service=fixture();original=memory.write;k=key()
    def wrong_version(*args,**kwargs):
        original(*args,**kwargs);return (0,99)
    with patch.object(memory,'write',side_effect=wrong_version):
        with pytest.raises(RuntimeError,match='conflicts'):write(service,k)
    assert ledger.uncertain_keys==(k,) and not service.events
    assert memory._commit_sequences['host-ram']==1


def test_out_of_range_epoch_rejected_before_effect():
    memory,_,service=fixture()
    with pytest.raises(ValueError):write(service,key(source_epoch=1<<64))
    assert not service.events and memory._commit_sequences['host-ram']==0


@pytest.mark.parametrize('version',[(False,1.0),(0.0,True),[0,1],(0,0),(1,1),(-1,1),(0,1<<64),None])
def test_post_effect_malformed_or_mismatched_version_cannot_certify(version):
    memory,ledger,service=fixture();original=memory.write;k=key()
    def wrong_version(*args,**kwargs):
        original(*args,**kwargs);return version
    with patch.object(memory,'write',side_effect=wrong_version):
        with pytest.raises(RuntimeError,match='conflicts'):write(service,k)
    assert ledger.uncertain_keys==(k,) and not service.events
    assert memory._commit_sequences['host-ram']==1


def test_zero_enable_with_fabricated_version_does_not_certify_effect():
    memory,ledger,service=fixture();k=key()
    with patch.object(memory,'write',return_value=(0,1)):
        with pytest.raises(RuntimeError,match='conflicts'):write(service,k,be=0)
    assert ledger.uncertain_keys==(k,) and not service.events
    assert memory._commit_sequences['host-ram']==0


@pytest.mark.parametrize('span',[('other-memory',0,0),('host-ram',0,1),('host-ram',1,0),
    ('',0,0),(True,0,0),('host-ram',0,-1)])
@pytest.mark.parametrize('be',[0,15])
def test_commit_span_must_match_actual_installed_host_region(span,be):
    memory,ledger,service=fixture();k=key()
    with patch.object(memory,'resolve_span',return_value=span):
        with pytest.raises(RuntimeError,match='span identity'):write(service,k,be=be)
    assert ledger.uncertain_keys==(k,) and not service.events
    assert memory._commit_sequences['host-ram']==(1 if be else 0)
