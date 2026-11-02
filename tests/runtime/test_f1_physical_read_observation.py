"""An actual case-local RAM read is observation, not version/reward proof."""
from types import SimpleNamespace
import pytest
from myfuzz.runtime.flows.memory import observe_ram_read_physical


class CpuAdapter:
    def __init__(self, protocol, beats):
        self.protocol, self.channel_model, self.beats = protocol, 'unified', beats
    def completed_beats(self, events, cpu):
        return self.beats


def fixture(protocol='axi4-lite'):
    tx=dict(execution_id='local-execution',testcase_id='campaign',source_component='cpu',
            source_epoch=0,channel_id='memory',source_sequence=13)
    beat=dict(acceptance_event=101,response_event=104,address=0xfff8,write=0,rdata=85)
    read=dict(event_id=102,kind='memory_read',component='cpu',address=0xfff8,
        memory_id='ram',generation=0,byte_offset=0xfff8,width_bytes=4,value=85,
        producer_event_id=101,transaction=tx,
        provenance={'observed_case':{'case_id':'F1-case'}})
    events=[{'event_id':101},read,{'event_id':103},{'event_id':104}]
    return dict(events=events,receipt=SimpleNamespace(event_start=0,event_end=4,case_id='F1-case'),
        cpu='cpu',address=0xfff8,memory_id='ram',memory_base=0,memory_generation=0,
        traces={},error_policy={},transaction_scope=tx,cpu_adapter=CpuAdapter(protocol,{('data',13):beat}))


@pytest.mark.parametrize('protocol',['axi4-lite','ahb-lite'])
def test_actual_read_is_observed_without_claiming_writer_or_retirement(protocol):
    result=observe_ram_read_physical(**fixture(protocol))
    assert result['status']=='observed' and result['memory_read_event']==102
    assert result['acceptance_event']==101 and result['response_event']==104
    assert result['retirement']=='unknown' and result['source_origin']=='unknown'
    assert result['reward_eligible'] is False and result['grants_prerequisites'] is False
    assert 'byte_relations' not in result


@pytest.mark.parametrize('change',['response','address','scope','wrong_case','unresolved','outside','ambiguous'])
def test_incomplete_or_wrong_read_stays_unknown(change):
    args=fixture();read=args['events'][1];beat=args['cpu_adapter'].beats[('data',13)]
    if change=='response':beat['rdata']=86
    elif change=='address':read['address']+=4
    elif change=='scope':read['transaction']={**read['transaction'],'source_epoch':1}
    elif change=='wrong_case':read['provenance']['observed_case']['case_id']='other'
    elif change=='unresolved':args['cpu_adapter'].beats={}
    elif change=='outside':args['receipt'].event_end=3
    else:
        duplicate={**read,'event_id':103};args['events'][2]=duplicate
    assert observe_ram_read_physical(**args) is None
