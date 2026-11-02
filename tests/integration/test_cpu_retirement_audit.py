"""Pure partial retirement checks; never create native source authority."""
from copy import deepcopy
import pytest
from scripts.verify_cpu_retirement import retirement_fields,check_retirements


def fixture():
    fields={name:dict(width=width) for name,width in
        {'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32}.items()}
    samples=[];events=[];fetches=[]
    for index,insn in enumerate((0x13,0x100093)):
        pc=0x10000+4*index;tick=10+index
        physical=dict(rvfi_valid=1,rvfi_order=index,rvfi_insn=insn,rvfi_pc_rdata=pc)
        samples.append(dict(tick=tick,fields=physical))
        events.append(dict(kind='cpu_retire',component='cpu',tick=tick,
            **{k.removeprefix('rvfi_'):v for k,v in physical.items()},
            observation=dict(sampling_edge='post_rising',physical=deepcopy(physical))))
        fetches.append(dict(address=pc,data=insn.to_bytes(4,'little'),tick=tick-1,event_id=index+1))
    return fields,samples,events,fetches


def check(data):
    fields,samples,events,fetches=data
    return check_retirements(events,samples,fields,fetches,component='cpu')


def test_partial_retirement_uses_actual_POST_and_source_fetched_bytes_only():
    data=fixture();result=check(data)
    assert [r['order'] for r in result]==[0,1]
    assert all('intr' not in row and 'pc_wdata' not in row for row in data[2])


@pytest.mark.parametrize('change',['order','bytes','POST','intr','pc_wdata','IRQ','missing_fetch','future_fetch'])
def test_inconsistent_native_retirement_evidence_refuses(change):
    data=fixture();fields,samples,events,fetches=data
    if change=='order':samples[1]['fields']['rvfi_order']=0
    elif change=='bytes':fetches[1]['data']=bytes(4)
    elif change=='POST':events[0]['observation']['physical']['rvfi_insn']=0
    elif change in ('intr','pc_wdata'):events[0][change]=0
    elif change=='IRQ':events[0]['irq_serial_observation']={}
    elif change=='missing_fetch':fetches.pop()
    elif change=='future_fetch':fetches[1]['tick']=100
    with pytest.raises(ValueError):check(data)


def test_held_valid_same_order_does_not_invent_second_retirement():
    data=fixture();data[1].insert(1,deepcopy(data[1][0]));assert len(check(data))==2


def test_export_contract_requires_all_four_real_essential_outputs():
    artifact={'physical_exports':[dict(physical_port=name,runtime_name='sample_'+name,
        direction='output',disposition='observe',width=width,bit_lo=0,bit_hi=width-1)
        for name,width in {'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32}.items()]}
    assert len(retirement_fields(artifact))==4
    artifact['physical_exports'].pop()
    with pytest.raises(ValueError):retirement_fields(artifact)
