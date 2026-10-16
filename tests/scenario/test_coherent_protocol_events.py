"""Structural controls for the admitted single-client coherent journal subset."""
import json
from pathlib import Path

import pytest

from myfuzz.scenario.coherent_protocol_events import CoherentProtocolEventNormalizer


def normalizer(**kwargs):
    return CoherentProtocolEventNormalizer(component_id='cpu', instance_id='cpu',
        endpoint_id='coherent', clock_domain='clock', address_bits=32,
        source_bits=3, sink_bits=3, **kwargs)


def request(channel='A', opcode=6, source=0, **changes):
    return dict(channel=channel, opcode=opcode, param=0, size=4,
        source=source, address=0x80000000, mask=255, data=0, **changes)


def response(opcode=5, source=0, beat=0, **changes):
    row=dict(channel='D', opcode=opcode, param=1 if opcode == 5 else 0,
        size=4, source=source, sink=1, beat=beat, data=0)
    return {**row, **changes}


@pytest.mark.parametrize('name', ['fresh1', 'fresh2', 'fault_read'])
def test_saved_real_cpu_traces_remain_protocol_observations(name):
    path=Path(__file__).resolve().parents[2] / 'configs/cpus/boom/evidence/generated-runtime-20261017'
    consumer=normalizer(manager_order='per_source')
    rows=[json.loads(line) for line in (path / (name+'.jsonl')).read_text().splitlines()]
    count=0
    for ref,row in enumerate(rows,1):
        if 'channel' not in row:
            continue
        events=consumer.consume_accepted(row,raw_event_ref=ref)
        assert all(e['authority']=='observation_only' for e in events)
        count+=1
    report=consumer.report()
    assert count==279 and report['stream_closed']
    assert not any(report[k] for k in ('structural_error', 'runtime_accepted',
        'semantic_accepted', 'source_authority'))


def test_per_source_response_order_and_independent_channel_namespaces():
    consumer=normalizer(manager_order='per_source')
    rows=[request(), request(channel='C',opcode=6), response(opcode=6),
        response(), response(beat=1), dict(channel='E',sink=1)]
    events=[consumer.consume_accepted(row,raw_event_ref=i) for i,row in enumerate(rows,1)]
    assert events[2][0]['related_request_event_refs']==[2]
    assert events[3][0]['related_request_event_refs']==[1]
    assert consumer.report()['stream_closed']


def test_fifo_scope_rejects_the_same_valid_per_source_reordering():
    consumer=normalizer()
    consumer.consume_accepted(request(),raw_event_ref=1)
    consumer.consume_accepted(request(channel='C',opcode=6),raw_event_ref=2)
    with pytest.raises(ValueError,match='response-order-identity-or-beat-mismatch'):
        consumer.consume_accepted(response(opcode=6),raw_event_ref=3)
    assert consumer.report()['structural_error']


def test_multibeat_d_cannot_interleave_even_with_per_source_order():
    consumer=normalizer(manager_order='per_source')
    for ref,row in enumerate([request(),request(channel='C',opcode=6),response()],1):
        consumer.consume_accepted(row,raw_event_ref=ref)
    with pytest.raises(ValueError,match='response-order-identity-or-beat-mismatch'):
        consumer.consume_accepted(response(opcode=6),raw_event_ref=4)


def test_grant_sink_is_live_until_e_and_source_can_be_reused_after_d():
    consumer=normalizer(manager_order='per_source')
    for ref,row in enumerate([request(),response(),response(beat=1)],1):
        consumer.consume_accepted(row,raw_event_ref=ref)
    assert consumer.report()['pending_sources']==0
    assert consumer.report()['pending_sinks']==1
    consumer.consume_accepted(request(),raw_event_ref=4)
    with pytest.raises(ValueError,match='sink-reuse'):
        consumer.consume_accepted(response(),raw_event_ref=5)


@pytest.mark.parametrize('change', [dict(source=8),dict(size=21),dict(address=0x80000001),
    dict(mask=256),dict(data=1<<64),dict(source=True)])
def test_malformed_request_poison_is_permanent(change):
    consumer=normalizer()
    row={**request(),**change}
    with pytest.raises(ValueError):
        consumer.consume_accepted(row,raw_event_ref=1)
    with pytest.raises(ValueError,match='already-invalid'):
        consumer.consume_accepted(request(),raw_event_ref=2)


@pytest.mark.parametrize('field',['mask','data','address','param'])
def test_missing_data_bearing_request_field_is_not_invented(field):
    consumer=normalizer()
    row=request(opcode=0);row['size']=3;row.pop(field)
    with pytest.raises(ValueError):
        consumer.consume_accepted(row,raw_event_ref=1)


@pytest.mark.parametrize('field',['sink','param','beat','data'])
def test_missing_native_grant_field_is_not_invented(field):
    consumer=normalizer()
    consumer.consume_accepted(request(),raw_event_ref=1)
    row=response();row.pop(field)
    with pytest.raises(ValueError):
        consumer.consume_accepted(row,raw_event_ref=2)


def test_duplicate_raw_identity_and_reset_cancellation_unique_requests():
    consumer=normalizer()
    consumer.consume_accepted(request(),raw_event_ref=1)
    consumer.consume_accepted(response(),raw_event_ref=2)
    cancelled=consumer.acknowledge_reset(raw_event_ref=3,reset_epoch=1)
    assert len(cancelled)==1
    assert cancelled[0]['related_request_event_refs']==[1]
    assert consumer.coverage()['counts']['reset_cancellations']==1
    assert consumer.report()['pending_sources']==consumer.report()['pending_sinks']==0
    with pytest.raises(ValueError,match='raw-identity'):
        consumer.consume_accepted(request(),raw_event_ref=3,reset_epoch=1)
