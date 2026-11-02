"""The extracted GPIO consumer retains the native commit joins, no DUT needed."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import pytest


def fixture(monkeypatch):
    from myfuzz.integration import gpio_write_consumer as consumer
    raw=json.loads((Path(__file__).resolve().parents[1]/'runtime/fixtures/gpio_f4_legacy_commit_join.json').read_text())
    commit=deepcopy(raw['commit']);artifact=object()
    observed={'joins':raw['joins'],'RAM_event':900}
    receipt=SimpleNamespace(events=(dict(event_id=raw['joins'][0]['delivery_event'],
        source_transaction=deepcopy(commit['context']['source_transaction'])),
        dict(event_id=raw['joins'][0]['native_APB_event'],local_tick=commit['tick'])))
    calls=[]
    class Authority:
        target=SimpleNamespace(artifact=artifact)
        def writes(self):return [commit]
        def issue(self,**kwargs):calls.append(kwargs);return object()
        def consume(self,token):return {'value':256}
    authority=Authority()
    monkeypatch.setattr(consumer,'validate_gpio_authority',lambda authority:None)
    monkeypatch.setattr(consumer,'check_writer_observation',lambda declaration,actual,*,target_artifact: observed)
    kwargs=dict(target_artifact=artifact,authority=authority,access={'address':1073745924,'register_offset':4},
        target_component='peripheral',register='GPIOEN',reset_epoch=0,
        before={'value':0,'reset_epoch':0},prior_writes=0)
    return consumer,commit,receipt,kwargs,calls


def test_real_saved_commit_join_is_preserved_by_the_public_consumer(monkeypatch):
    module,commit,receipt,kwargs,calls=fixture(monkeypatch)
    observed,actual,after=module.check_gpio_write_observation({'candidate':{'value':256}},receipt,**kwargs)
    assert actual==commit and observed['RAM_event']==900 and after['value']==256
    assert calls==[{'register':'GPIOEN','reset_epoch':0}]


@pytest.mark.parametrize('fault',['count','transaction','address','offset','write','value','be','before','after',
    'epoch','tick','command_sequence','component','current'])
def test_commit_context_native_identity_and_current_value_all_remain_required(monkeypatch,fault):
    module,commit,receipt,kwargs,calls=fixture(monkeypatch)
    if fault=='count':kwargs['prior_writes']=1
    elif fault=='transaction':commit['context']['source_transaction']={}
    elif fault in ('address','offset','value','be'):commit['context'][fault]+=1
    elif fault=='write':commit['context']['write']=False
    elif fault in ('before','after','epoch','tick','command_sequence'):commit[fault]+=1
    elif fault=='component':commit['context']['command_scope']['component']='wrong-instance'
    else:kwargs['authority'].consume=lambda token:{'value':0}
    with pytest.raises(ValueError,match='compiled-F4-'):
        module.check_gpio_write_observation({'candidate':{'value':256}},receipt,**kwargs)
    if fault!='current':assert calls==[]


def test_saved_document_is_not_a_gpio_authority():
    from myfuzz.integration.gpio_write_consumer import check_gpio_write_observation
    with pytest.raises(ValueError):
        check_gpio_write_observation({'candidate':{'value':256}},SimpleNamespace(events=()),
            target_artifact=object(),authority={},access={},target_component='gpio',
            register='GPIOEN',reset_epoch=0,before={'reset_epoch':0,'value':0},prior_writes=0)


def test_existing_gpio_f4_runtime_delegates_the_same_actual_arguments(monkeypatch):
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    import myfuzz.integration.compiled_f4 as f4
    from myfuzz.integration import gpio_write_consumer
    from myfuzz.scenario.runner import ScenarioRunner
    runner=object.__new__(ScenarioRunner);runner._events=[]
    runner.sessions={'cpu':SimpleNamespace(memory=SimpleNamespace(read=lambda *a,**kw:object()))}
    artifact=object();authority=object();access={'address':4,'register_offset':4}
    runtime=SimpleNamespace(row='gpio_causal',artifacts={'gpio':artifact},authority=authority,
        access=access,target_id='gpio',register_name='GPIOEN',runner=runner,cpu_id='cpu',cursor=0,records=[],
        image={'source_id':'source'},stream={},traces={},declared_edges=[],error_policy={})
    receipt=SimpleNamespace(violations=());declaration={};before={'reset_epoch':0}
    expected=({'joins':[],'RAM_event':1},{'tick':2},{'value':256})
    calls=[]
    def consume(actual,actual_receipt,**kwargs):
        calls.append(kwargs)
        assert actual is declaration and actual_receipt is receipt
        assert kwargs==dict(target_artifact=artifact,authority=authority,access=access,
            target_component='gpio',register='GPIOEN',reset_epoch=0,before=before,prior_writes=3)
        return expected
    monkeypatch.setattr(gpio_write_consumer,'check_gpio_write_observation',consume)
    monkeypatch.setattr(f4,'check_f4_exact_hops',lambda **kwargs:dict(edges=[],data_hops=[],
        ram_write_hop=dict(memory_write_event=1,transaction={},address=32,value=256)))
    observed,commit,after=CompiledF4Runtime._check_chain(runtime,receipt,declaration,before,3)
    assert len(calls)==1 and commit is expected[1] and after is expected[2]
