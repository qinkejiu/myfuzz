"""GPIO's native commit identifies its effecting join without a write flag."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.flows.storage import StorageFlowKernel, _effect_status


def transaction(sequence):
    return dict(execution_id='execution',testcase_id='test',source_component='cpu',
        source_epoch=0,channel_id='data',source_sequence=sequence)


def world():
    joins=[dict(source_transaction=transaction(1),native_APB_event=373,delivery_event=343),
           dict(source_transaction=transaction(2),native_APB_event=528,delivery_event=498)]
    commit=dict(tick=16,before=0,after=256,context=dict(write=True,source_transaction=transaction(1)))
    events={373:dict(event_id=373,kind='local_tick_sample',component='target',phase='pre',
        local_tick=16,producer_event_id=300),343:dict(event_id=343,kind='mmio_delivery',
        component='cpu',write=True,write_value=256,source_transaction=transaction(1),producer_event_id=300)}
    context=SimpleNamespace(flow_id='F4',cpu_component='cpu',target_component='target',lookup_event=events.get)
    return context,joins,commit,events


def test_commit_selects_actual_write_transaction_in_either_join_order():
    context,joins,commit,_=world()
    for order in (joins,list(reversed(joins))):
        assert StorageFlowKernel._primary_join(context,order,commit=commit)['source_transaction']==transaction(1)
    assert all('write' not in join and 'tick' not in join for join in joins)


@pytest.mark.parametrize('damage',['missing','duplicate','malformed','read','flag-conflict'])
def test_bad_commit_link_is_refused_without_order_fallback(damage):
    context,joins,commit,_=world()
    if damage=='missing':commit['context']['source_transaction']=transaction(3)
    if damage=='duplicate':joins.append(deepcopy(joins[0]))
    if damage=='malformed':commit['context']['source_transaction']={'source_sequence':1}
    if damage=='read':commit['context']['write']=False
    if damage=='flag-conflict':joins[1]['write']=True
    with pytest.raises(GenericRuntimeRefused):
        StorageFlowKernel._primary_join(context,joins,commit=commit)


def test_legacy_apb_wishbone_and_read_join_selection_is_preserved():
    context,joins,_,_=world()
    joins[0]['write']=True;joins[1]['write']=False
    assert StorageFlowKernel._primary_join(context,list(reversed(joins))) is joins[0]
    assert StorageFlowKernel._primary_join(SimpleNamespace(flow_id='F2'),joins) is joins[1]
    assert StorageFlowKernel._primary_join(context,[{'native_wishbone_event':1}])=={'native_wishbone_event':1}


def test_effect_projects_actual_native_tick_without_editing_certificate():
    context,joins,commit,_=world()
    receipt={'commit':commit,'postcondition':{'value':256}}
    assert _effect_status(context,receipt,joins,'certified',True)=='certified'
    assert all('tick' not in join for join in joins)


@pytest.mark.parametrize('damage',['tick','component','producer','transaction'])
def test_effect_cannot_infer_native_commit_match(damage):
    context,joins,commit,events=world()
    if damage=='tick':events[373]['local_tick']=15
    if damage=='component':events[373]['component']='other'
    if damage=='producer':events[373]['producer_event_id']=301
    if damage=='transaction':events[343]['source_transaction']=transaction(2)
    assert _effect_status(context,{'commit':commit,'postcondition':{'value':256}},joins,'certified',True)!='certified'


def test_saved_native_gpio_certificate_identifies_commit_join_without_flags():
    import json
    from pathlib import Path
    receipt=json.loads((Path(__file__).parent/'fixtures/gpio_f4_legacy_commit_join.json').read_text())
    for joins in (receipt['joins'],list(reversed(receipt['joins']))):
        selected=StorageFlowKernel._primary_join(SimpleNamespace(flow_id='F4'),joins,commit=receipt['commit'])
        assert selected['source_transaction']==receipt['commit']['context']['source_transaction']
    assert all('write' not in row and 'tick' not in row for row in receipt['joins'])
