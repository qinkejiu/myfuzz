"""Opt-in bounded actual host-memory callback stream, not signed JSON authority."""
from dataclasses import asdict
from copy import deepcopy
from unittest.mock import patch
import pytest
from myfuzz.scenario.memory_service import MemoryService, WriteReceipt
from tests.scenario.test_uart_store_commit_contract import fixture,key,write


def enabled(capacity=2):
    memory,ledger,_=fixture()
    return memory,ledger,MemoryService(memory,ledger,commit_stream_capacity=capacity)


def test_default_disabled_legacy_event_shape_is_unchanged():
    _,_,service=fixture();receipt=write(service)
    assert service.drain_commit_events()==() and service.pending_commit_count==0
    assert set(service.events[0])=={'kind','transaction','address','width_bytes','memory_id','generation',
        'byte_offset','value','byte_enable','version'}
    assert asdict(receipt)==dict(transaction_id=asdict(key()),version=(0,1),byte_enable=15)


def test_only_fresh_completed_callback_enrolled_with_exact_object():
    _,ledger,service=enabled();receipt=write(service)
    events=service.drain_commit_events();assert len(events)==1
    e=events[0];assert e['kind']=='memory_write_commit' and e['schema_version']=='memory_write_commit.v1'
    assert e['service_commit_sequence']==1 and e['transaction']==asdict(key())
    assert e['commit_document']==receipt.commit_document() and e['commit_id']==e['commit_document']['commit_id']
    actual,detached=service.lookup_pending_commit(e['commit_id'])
    assert actual is receipt and detached==e
    assert service.lookup_issued_write_commit(receipt)==e
    assert ledger._entries[key()].status=='complete'
    detached['commit_document']['enabled_byte_cells'][0]['value']=255
    assert service.drain_commit_events()[0]['commit_document']['enabled_byte_cells'][0]['value']==0x5a


def test_cached_duplicate_never_publishes_a_second_effect():
    memory,_,service=enabled();receipt=write(service);assert write(service) is receipt
    assert service.pending_commit_count==1 and len(service.events)==1
    assert memory._commit_sequences['host-ram']==1


def test_manual_receipt_in_complete_ledger_is_not_callback_issuance():
    _,ledger,service=enabled();manual=WriteReceipt(key(),(0,1),15)
    payload=dict(op='write',address=0x20000,value=0x5a,width_bytes=4,byte_enable=15)
    ledger.execute_once(key(),payload,lambda:manual)
    assert write(service) is manual and service.drain_commit_events()==()
    with pytest.raises(ValueError):service.lookup_issued_write_commit(manual)


def test_equal_receipt_from_other_service_is_not_this_actual_object():
    _,_,one=enabled();_,_,two=enabled();receipt=write(one);other=write(two)
    assert receipt==other and receipt is not other
    with pytest.raises(ValueError):one.lookup_issued_write_commit(other)


def test_ack_releases_only_exact_fifo_prefix_and_cannot_resurrect():
    _,_,service=enabled();one=write(service);two=write(service,key(2));events=service.drain_commit_events()
    ids=tuple(e['commit_id'] for e in events)
    with pytest.raises(ValueError):service.ack_commit_events(tuple(reversed(ids)))
    assert service.pending_commit_count==2
    service.ack_commit_events(ids[:1]);assert service.pending_commit_count==1
    with pytest.raises(ValueError):service.lookup_pending_commit(ids[0])
    with pytest.raises(ValueError):service.lookup_issued_write_commit(one)
    assert write(service) is one and service.pending_commit_count==1
    service.ack_commit_events(ids[1:]);assert service.pending_commit_count==0
    with pytest.raises(ValueError):service.lookup_issued_write_commit(two)


def test_full_queue_rejects_fresh_effect_before_commit_but_allows_duplicate():
    memory,ledger,service=enabled(1);one=write(service)
    with pytest.raises(RuntimeError,match='capacity'):write(service,key(2))
    assert memory._commit_sequences['host-ram']==1 and len(service.events)==1
    assert key(2) not in ledger._entries and write(service) is one
    first=service.drain_commit_events()[0];service.ack_commit_events((first['commit_id'],))
    write(service,key(2));assert memory._commit_sequences['host-ram']==2
    assert service.drain_commit_events()[0]['service_commit_sequence']==2


def test_failed_callback_never_publishes_or_enrolls():
    memory,ledger,service=enabled();original=memory.write
    def failed(*a,**kw):original(*a,**kw);raise RuntimeError('actual post-effect failure')
    with patch.object(memory,'write',side_effect=failed):
        with pytest.raises(RuntimeError):write(service)
    assert ledger.uncertain_keys==(key(),) and service.drain_commit_events()==()
    with pytest.raises(RuntimeError):write(service)
    assert memory._commit_sequences['host-ram']==1 and service.pending_commit_count==0


def test_zero_enable_publishes_no_effect_fact_only():
    memory,_,service=enabled();receipt=write(service,be=0);event=service.drain_commit_events()[0]
    assert event['commit_document']['performed_effect'] is False
    assert event['commit_document']['enabled_byte_cells']==[] and receipt.version is None
    assert memory.initialized_bytes==memory._commit_sequences['host-ram']==0


@pytest.mark.parametrize('capacity',[True,False,0,-1,1.0,'2'])
def test_stream_capacity_requires_positive_exact_integer(capacity):
    with pytest.raises(ValueError):enabled(capacity)


def test_many_acknowledged_effects_use_bounded_membership():
    memory,_,service=enabled(1)
    for seq in range(1,1101):
        receipt=write(service,key(seq));event=service.drain_commit_events()[0]
        assert service.pending_commit_count==1 and service.lookup_pending_commit(event['commit_id'])[0] is receipt
        service.ack_commit_events((event['commit_id'],));assert service.pending_commit_count==0
    assert memory._commit_sequences['host-ram']==1100
    with pytest.raises(ValueError):service.lookup_issued_write_commit(receipt)


def test_reentrant_fresh_callback_cannot_exceed_reserved_capacity():
    memory,_,service=enabled(1);original=memory.write;attempted=False
    def nested(*args,**kwargs):
        nonlocal attempted
        if not attempted:
            attempted=True
            with pytest.raises(RuntimeError,match='capacity'):
                write(service,key(source_component='other-cpu'))
        return original(*args,**kwargs)
    with patch.object(memory,'write',side_effect=nested):write(service)
    assert service.pending_commit_count==1 and memory._commit_sequences['host-ram']==1


@pytest.mark.parametrize('ids',[[],('unknown',),('unknown','other'),(True,)])
def test_ack_wrong_shape_or_unissued_ids_rejected_without_release(ids):
    _,_,service=enabled();write(service)
    with pytest.raises(ValueError):service.ack_commit_events(ids)
    assert service.pending_commit_count==1


def test_mutated_receipt_or_uncertain_ledger_cannot_confirm_issuance():
    _,ledger,service=enabled();receipt=write(service);eid=service.drain_commit_events()[0]['commit_id']
    original=receipt._commit_json;object.__setattr__(receipt,'_commit_json',b'{}')
    with pytest.raises(RuntimeError):service.lookup_pending_commit(eid)
    object.__setattr__(receipt,'_commit_json',original);ledger._entries[key()].status='uncertain_effect'
    with pytest.raises(RuntimeError):service.lookup_issued_write_commit(receipt)


def test_limited_drain_is_detached_and_does_not_ack():
    _,_,service=enabled();write(service);write(service,key(2))
    first=service.drain_commit_events(max_events=1);assert len(first)==1 and service.pending_commit_count==2
    first[0]['commit_document']['performed_effect']=False
    assert service.drain_commit_events()[0]['commit_document']['performed_effect'] is True
    for limit in (True,0,-1,1.0):
        with pytest.raises(ValueError):service.drain_commit_events(limit)


def test_no_effect_or_unknown_authority_fact_can_be_acknowledged_without_token():
    _,_,service=enabled(1);receipt=write(service,be=0)
    event=service.drain_commit_events()[0]
    assert event['commit_document']['performed_effect'] is False
    service.ack_commit_events((event['commit_id'],));assert service.pending_commit_count==0
    with pytest.raises(ValueError):service.lookup_issued_write_commit(receipt)
    write(service,key(2));assert service.pending_commit_count==1
