from copy import deepcopy
import pytest


def pair():
    role={'status':'observed','value':0}
    mret=dict(insn=0x30200073,order=10,local_tick=20,receipt_id={'execution':'run','sequence':20})
    successor=dict(order=11,local_tick=23,receipt_id={'execution':'run','sequence':23},pc_rdata=0x11000,
        intr=0,irq_serial_observation={'retirement':role})
    return mret,successor


def test_actual_successor_does_not_use_mret_pc_wdata():
    from myfuzz.scenario.irq_return_successor import validate_return_successor
    mret,next=pair();mret['pc_wdata']=0
    assert validate_return_successor(mret,next,start=0x11000,end=0x11010)==0x11000


@pytest.mark.parametrize('change',[{'order':12},{'pc_rdata':0x10200},{'intr':1},{'local_tick':20},
    {'receipt_id':{'execution':'other','sequence':23}}, {'irq_serial_observation':{'retirement':{'status':'observed','value':1}}}])
def test_first_invalid_successor_is_not_skipped(change):
    from myfuzz.scenario.irq_return_successor import validate_return_successor
    mret,next=pair();next.update(change)
    with pytest.raises(ValueError):validate_return_successor(mret,next,start=0x11000,end=0x11010)
