"""Reset and namespace controls for coherent Runner observation streams."""
import pytest

from myfuzz.scenario.coherent_event_stream import CoherentAcceptedEventStream


def stream(**kwargs):
    return CoherentAcceptedEventStream(component_id='cpu',instance_id='cpu',
        endpoint_id='coherent',clock_domain='clock',**kwargs)


GET=dict(channel='A',opcode=4,param=0,size=3,source=0,address=0x80000000,mask=255,data=0)


def test_explicit_reset_cancels_without_a_later_cpu_edge():
    consumer=stream()
    borrowed=consumer.runtime_events
    consumer.consume_step([GET],execution_id='first',reset_epoch=0,local_tick=1)
    rows=consumer.acknowledge_reset({'cancelled_responses':1},
        execution_id='fresh',reset_epoch=1,local_tick=1)
    assert [r['kind'] for r in rows]==['coherent_native_reset_acknowledgement','transaction_cancel']
    assert consumer.report()['pending_sources']==0
    assert consumer.report()['stream_closed']
    assert consumer.runtime_events is borrowed
    assert rows[1]['raw_event_refs']==[rows[0]['raw_event_id']]
    assert rows[1]['raw_event_scope']==consumer.stream_id
    consumer.consume_step([],execution_id='fresh',reset_epoch=1,local_tick=2)


@pytest.mark.parametrize('changed', [dict(execution_id='other',reset_epoch=0,local_tick=2),
    dict(execution_id='first',reset_epoch=1,local_tick=2),
    dict(execution_id='first',reset_epoch=0,local_tick=3)])
def test_receipt_cannot_change_identity_epoch_or_skip_a_tick(changed):
    consumer=stream()
    consumer.consume_step([],execution_id='first',reset_epoch=0,local_tick=1)
    with pytest.raises(ValueError):
        consumer.consume_step([],**changed)
    assert consumer.report()['stream_poisoned']


def test_protocol_poison_retains_raw_but_never_recovers_on_reset():
    consumer=stream()
    consumer.consume_step([dict(channel='B')],execution_id='first',reset_epoch=0,local_tick=1)
    assert consumer.report()['structural_error']
    consumer.acknowledge_reset({},execution_id='fresh',reset_epoch=1,local_tick=1)
    consumer.consume_step([GET],execution_id='fresh',reset_epoch=1,local_tick=2)
    assert consumer.report()['normalization_poisoned']
    assert not consumer.report()['stream_closed']
    raw=[r for r in consumer.runtime_events if r['kind']=='coherent_accepted_raw']
    assert len(raw)==2


def test_bounded_raw_journal_poison_does_not_grant_runtime_success():
    consumer=stream(max_records=2)
    consumer.consume_step([GET],execution_id='first',reset_epoch=0,local_tick=1)
    with pytest.raises(ValueError,match='record-bound'):
        consumer.consume_step([GET],execution_id='first',reset_epoch=0,local_tick=2)
    report=consumer.report()
    assert report['stream_poisoned'] and not report['runtime_accepted']
