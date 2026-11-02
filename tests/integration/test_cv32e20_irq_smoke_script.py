"""Pure fixed-ROM and documentary checker tests; not native acceptance."""
from copy import deepcopy
import pytest
from scripts.run_cv32e20_irq_smoke import fixed_program,inspect_evidence


def fixture():
    p=fixed_program(0x10000);pc=p['park'];events=[
        dict(kind='instr_response',address=p['boot'],rdata=0,local_tick=1),
        dict(kind='cpu_external_irq_sample',actual_pre_input=1,irq_masked_pre=1,local_tick=2),
        dict(kind='cpu_external_irq_taken',local_tick=4,irq_serial_observation={'decision':dict(status='observed',value=1)}),
        dict(kind='cpu_retire',order=1,pc_rdata=p['handler'],insn=0,intr=1,irq_serial_observation={'retirement':dict(status='observed',value=1)}),
        dict(kind='memory_write',address=p['marker'],value=42),
        dict(kind='cpu_retire',order=2,pc_rdata=p['handler']+20,insn=0x00522023,intr=0,mem_addr=p['marker'],mem_wmask=15,mem_wdata=42),
        dict(kind='cpu_retire',order=3,pc_rdata=p['mret'],insn=0x30200073,local_tick=6,receipt_id=dict(execution='native',sequence=4)),
        dict(kind='instr_response',address=pc,rdata=0x6f,local_tick=7),
        dict(kind='cpu_retire',order=4,pc_rdata=pc,insn=0x6f,intr=0,local_tick=8,receipt_id=dict(execution='native',sequence=6),irq_serial_observation={'retirement':dict(status='observed',value=0)}),
        dict(kind='cpu_external_irq_sample',actual_pre_input=0,irq_masked_pre=0,local_tick=8)]
    return p,events


def test_fixed_rom_and_documentary_checks():
    p,e=fixture();result=inspect_evidence(e,p,42,p['park'])
    assert result['return_pc']==p['park'] and result['grants_F5'] is result['grants_F6'] is False
    assert p['boot']==0x10000 and p['mret']<0x11000
    from myfuzz.integration.rv32_fixed_firmware import _jal
    external=p['vector']+11*4
    assert int.from_bytes(bytes.fromhex(p['images'][str(external)]),'little')==_jal(external,p['handler'])


@pytest.mark.parametrize('change',['serial','successor','store'])
def test_bad_documentary_join_is_rejected(change):
    p,e=fixture()
    if change=='serial':e[3]['irq_serial_observation']['retirement']['value']=2
    if change=='successor':e[8]['pc_rdata']+=4
    if change=='store':e[5]['mem_wdata']=41
    with pytest.raises(ValueError):inspect_evidence(e,p,42,p['park'])
