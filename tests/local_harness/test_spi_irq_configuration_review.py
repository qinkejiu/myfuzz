"""Independent configuration/encoding review; no native IRQ authority."""
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]


def test_checked_in_SPI_trigger_is_one_actual_full_word_INTCFG_store():
    from scripts.run_timer_irq_smoke import source_options,timer_program
    from scripts.run_cv32e20_irq_smoke import fixed_program
    config=json.loads((ROOT/'configs/peripherals/pulp_spi_irq/smoke.json').read_text())
    options=source_options(config)
    assert options['source_adapter']=='declared-output.v1'
    assert (options['source_port'],options['source_bit_offset'])==('events_o',0)
    request=json.loads((ROOT/options['source_request']).read_text())
    assert request['profile_path']=='configs/peripherals/pulp_spi/component_profile.json'
    assert {(r['endpoint_id'],r['role'],r['value']) for r in request['tuning']['fixed_inputs']}=={
        ('spi.pins','sdi'+str(i),0) for i in range(4)}
    old=fixed_program(0x10080)
    program=timer_program(0x10080,options['active_base'],trigger_writes=options['trigger_writes'])
    prefix=bytes.fromhex(old['images'][str(old['boot'])])[:-4]
    code=bytes.fromhex(program['images'][str(program['boot'])]);assert code.startswith(prefix)
    registers=[0]*32;stores=[]
    for offset in range(len(prefix),len(code)-4,4):
        word=int.from_bytes(code[offset:offset+4],'little');op=word&127;rd=word>>7&31;rs=word>>15&31
        if op==0x37:registers[rd]=word&0xfffff000
        elif op==0x13:
            imm=word>>20;imm=imm-4096 if imm&0x800 else imm
            registers[rd]=(registers[rs]+imm)&0xffffffff
        elif op==0x23:
            assert word>>12&7==2  # actual SW, not a byte/halfword store
            imm=(word>>25<<5)|(word>>7&31);imm=imm-4096 if imm&0x800 else imm
            stores.append(((registers[rs]+imm)&0xffffffff,registers[word>>20&31]))
        else:raise AssertionError('unexpected trigger instruction')
    assert stores==[(options['active_base']+0x24,0x80000000)]
    assert timer_program(0x10080,0x40001000)==timer_program(0x10080,0x40001000,
        trigger_writes=((4,0),(8,0),(0,0xffffffff)))


@pytest.mark.parametrize('writes',[((0x24,1<<32),),((0x25,0x80000000),)])
def test_trigger_encoding_rejects_out_of_range_value_or_unaligned_store(writes):
    from scripts.run_timer_irq_smoke import timer_program
    with pytest.raises(ValueError):timer_program(0x10080,0x40001000,trigger_writes=writes)
