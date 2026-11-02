"""F1/F3 joins consume actual protocol-adapter beats and host RAM receipts."""
from types import SimpleNamespace

from myfuzz.runtime.flows.memory import _observe_f3_write, observe_ram_read_documentary


class Adapter:
    protocol='wishbone'
    def __init__(self, beats): self.beats=beats
    def completed_beats(self, events, cpu): return self.beats


def test_wishbone_f3_requires_same_case_measured_write_and_response():
    tx=dict(execution_id='run',testcase_id='test',source_component='cpu',source_epoch=0,
            channel_id='data',source_sequence=1)
    events=[{'event_id':1},dict(event_id=2,kind='memory_write',component='cpu',address=0x100,
        value=85,width_bytes=4,byte_enable=15,memory_id='ram',byte_offset=0x100,generation=0,
        version=[0,2],transaction=tx,producer_event_id=1,
        provenance={'observed_case':{'case_id':'case'}}),{'event_id':3}]
    beat=dict(acceptance_event=1,response_event=3,address=0x100,write=1,value=85,byte_enable=15)
    receipt=SimpleNamespace(event_start=0,event_end=3,case_id='case')
    kwargs=dict(events=events,receipt=receipt,cpu='cpu',address=0x100,value=85,memory_id='ram',
        memory_base=0,memory_generation=0,traces={},error_policy={},transaction_scope=tx,
        cpu_adapter=Adapter({('data',1):beat}))
    assert _observe_f3_write(**kwargs)['memory_write_event']==2
    assert _observe_f3_write(**{**kwargs,'receipt':SimpleNamespace(event_start=0,event_end=2,case_id='case')}) is None
    assert _observe_f3_write(**{**kwargs,'cpu_adapter':Adapter({('data',1):{**beat,'byte_enable':3}})}) is None


def test_unified_cpu_f3_uses_memory_channel_and_measured_data_beat():
    tx=dict(execution_id='run',testcase_id='test',source_component='cpu',source_epoch=0,
            channel_id='memory',source_sequence=7)
    events=[{'event_id':1},dict(event_id=2,kind='memory_write',component='cpu',address=0x100,
        value=85,width_bytes=4,byte_enable=15,memory_id='ram',byte_offset=0x100,generation=0,
        version=[0,2],transaction=tx,producer_event_id=1,
        provenance={'observed_case':{'case_id':'case'}}),{'event_id':3}]
    beat=dict(acceptance_event=1,response_event=3,address=0x100,write=1,value=85,byte_enable=15)
    for protocol in ('ahb-lite','axi4-lite'):
        adapter=Adapter({('data',7):beat});adapter.protocol=protocol;adapter.channel_model='unified'
        kwargs=dict(events=events,receipt=SimpleNamespace(event_start=0,event_end=3,case_id='case'),
            cpu='cpu',address=0x100,value=85,memory_id='ram',memory_base=0,memory_generation=0,
            traces={},error_policy={},transaction_scope=tx,cpu_adapter=adapter)
        assert _observe_f3_write(**kwargs)['memory_write_event']==2
        bad=dict(tx,channel_id='data')
        changed=[events[0],dict(events[1],transaction=bad),events[2]]
        assert _observe_f3_write(**{**kwargs,'events':changed}) is None


def test_wishbone_f1_historical_byte_observation_does_not_grant_reward():
    tx=dict(execution_id='run',testcase_id='test',source_component='cpu',source_epoch=0,
            channel_id='data',source_sequence=2)
    read=dict(event_id=2,kind='memory_read_issuance',component='cpu',address=0x100,
        memory_id='ram',generation=0,byte_offset=0x100,width_bytes=4,fullkey=tx,
        value=85,versions=[[0,2]]*4,writer_event_ids=['writer']*4,producer_event_id=1)
    events=[{'event_id':1},read,{'event_id':3}]
    certs=[dict(proof_scope='memory_byte_version',validity='historical',component='cpu',memory_id='ram',
        generation=0,byte_offset=0x100+i,read_event_id=2,read_transaction=tx,byte_version=[0,2],
        writer_event_id='writer',value=(85>>(8*i))&255) for i in range(4)]
    beat=dict(acceptance_event=1,response_event=3,address=0x100,write=0,rdata=85)
    kwargs=dict(events=events,receipt=SimpleNamespace(event_start=0,event_end=3),cpu='cpu',
        address=0x100,memory_id='ram',memory_base=0,memory_generation=0,traces={},error_policy={},
        report={'journal_integrity':True,'certificates':certs},cpu_adapter=Adapter({('data',2):beat}))
    result=observe_ram_read_documentary(**kwargs)
    assert result['status']=='observed' and result['retirement']=='unknown'
    assert result['reward_eligible'] is False and result['native_authority'] is False
    assert result['proof_scope']=='historical_dut_wishbone_read_host_ram_versions'
    assert observe_ram_read_documentary(**{**kwargs,'cpu_adapter':Adapter({('data',2):{**beat,'rdata':0}})}) is None
