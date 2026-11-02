from copy import deepcopy
from unittest.mock import patch
import pytest
from myfuzz.integration.compiled_f6_saved_semantics import _saved_level_irq_evidence, _EvidenceIssue


def evidence():
    key={'source_component':'cpu','source_epoch':1,'testcase_id':'case','execution_id':'local-execution'}
    case={'case_id':'case','case_index':0}
    def row(event_id,kind,component,**fields):
        return dict(event_id=event_id,kind=kind,component=component,provenance={'observed_case':case},**fields)
    take=row(10,'cpu_external_irq_taken','cpu',local_tick=5,reset_epoch=1,take_key=['cpu',1,1],binding_delivery_event_id=2,source_output_key=['dma',1,'irq',1])
    accept=row(11,'data_accept','cpu',address=256,write=1,wdata=4,transaction=key)
    receipt=dict(source_transaction=key,address=256,offset=0,write=True,value=4,byte_enable=15,edge_ticks=[8])
    delivery=row(12,'mmio_delivery','cpu',source_transaction=key,device_id='d',address=256,write=True,dma_control_receipt=receipt)
    response=row(13,'data_response','cpu',transaction=key,address=256,write=1)
    raw=row(14,'local_tick_sample','dma',reset_epoch=1,local_tick=8,phase='post',outputs={'irq':0,'physical':{'irq':0}})
    sample=row(15,'cpu_external_irq_sample','cpu',reset_epoch=1,local_tick=9,expected_input=0,actual_pre_input=0,actual_post_input=0)
    high=row(9,'cpu_external_irq_sample','cpu',reset_epoch=1,local_tick=5,expected_input=1,actual_pre_input=1,actual_post_input=1)
    events=[high,take,accept,delivery,response,raw,sample]
    return events,take,case


def run(events,take,case):
    from types import SimpleNamespace
    group=SimpleNamespace(members=[SimpleNamespace(source_id='dma.irq')])
    def frame(group,sample,events,runner,**kwargs):
        if sample['local_tick']==5:return {'unique_source':'dma.irq','native_take_event_id':10,'take_key':['cpu',1,1]}
        return {'value':0,'members':[{'source_id':'dma.irq','mode':'level','value':0,'latest_native_source':{'event_id':14}}]}
    contract={'control':{'base':256,'device_id':'d'},'dma':{'behavior':{'irq_clear':{'method':'write','offset':0,'value':4,'byte_enable':15}}}}
    with patch('myfuzz.integration.saved_irq_group.frame_for_sample',side_effect=frame):
        return _saved_level_irq_evidence(contract,group,events,{r['event_id']:r for r in events},'cpu','dma',1,case,take,{'event_id':2,'source_output_key':['dma',1,'irq',1]},None)


def test_level_requires_real_clear_and_sampled_low():
    events,take,case=evidence()
    assert run(events,take,case)['low_sample_event_id']==15
    for kind in ('data_accept','mmio_delivery','data_response','local_tick_sample','cpu_external_irq_sample'):
        damaged=[r for r in events if not (r['kind']==kind and (kind!='cpu_external_irq_sample' or r['local_tick']==9))]
        with pytest.raises(_EvidenceIssue):run(damaged,take,case)


def test_level_rejects_bad_clear_and_old_low():
    events,take,case=evidence()
    for mutate in (lambda rows:rows[3]['dma_control_receipt'].__setitem__('byte_enable',0),
                   lambda rows:rows[5].__setitem__('reset_epoch',0)):
        changed=deepcopy(events);mutate(changed)
        with pytest.raises(_EvidenceIssue):run(changed,take,case)
