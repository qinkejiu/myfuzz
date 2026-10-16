"""Narrow field reads execute mask extraction on CPU words, never host oracles."""
import json
import pytest
from myfuzz.scenario.memory import MemoryRegion
from myfuzz.scenario.register_program import compile_register_program, verify_register_program_document
from myfuzz.composition.test_capability import load_ip_test_capability
from tests.scenario.test_register_program_verification import arguments
from tests.composition.test_pulp_gpio_test_capability import SIDECAR


def inputs(**changes):
    return arguments(register='PADCFG_0',field='pin7',operation='register_read',value=None,
        result_address=0x21000,result_regions=(MemoryRegion('result',0x21000,64),),**changes)


def execute(raw,bus):
    """Independent machine-word interpreter for generated read fragments."""
    regs=[0]*32;reads=[];writes=[]
    for start in range(0,len(raw),4):
        word=int.from_bytes(raw[start:start+4],'little')
        opcode=word&127;rd=word>>7&31;rs1=word>>15&31;rs2=word>>20&31;funct=word>>12&7
        imm=word>>20;imm=imm-4096 if imm&2048 else imm
        if opcode==0x37:regs[rd]=word&0xfffff000
        elif opcode==0x13:
            if funct==0:regs[rd]=(regs[rs1]+imm)&0xffffffff
            elif funct==5:
                assert word>>25==0
                regs[rd]=regs[rs1]>>(word>>20&31)
            elif funct==7:regs[rd]=regs[rs1]&(imm&0xffffffff)
            else:raise AssertionError('unsupported immediate operation')
        elif opcode==0x33:
            assert funct==7 and word>>25==0
            regs[rd]=regs[rs1]&regs[rs2]
        elif opcode==0x03:
            assert funct==2
            reads.append((regs[rs1]+imm)&0xffffffff);regs[rd]=bus
        elif opcode==0x23:
            assert funct==2
            immediate=(word>>25<<5)|(word>>7&31)
            immediate=immediate-4096 if immediate&2048 else immediate
            writes.append(((regs[rs1]+immediate)&0xffffffff,regs[rs2]))
        else:raise AssertionError('unsupported instruction')
        regs[0]=0
    return reads,writes


@pytest.mark.parametrize('register,field,lsb,width,offset',[
    ('PADCFG_0','pin0',0,4,40),('PADCFG_0','pin7',28,4,40),
    ('PADCFG_3','pin31',28,4,52),('INTTYPE_LOW','pin0',0,2,28),
    ('INTTYPE_HIGH','pin16',0,2,32),('INTTYPE_HIGH','pin31',30,2,32)])
def test_actual_encoded_read_extracts_unsigned_field(register,field,lsb,width,offset):
    profile,cap,args=arguments(register=register,field=field,operation='register_read',value=None,
        result_address=0x21000,result_regions=(MemoryRegion('result',0x21000,64),))
    program=compile_register_program(profile,cap,**args)
    for bus in (0,0xffffffff,0x81234567):
        reads,writes=execute(program.fragment,bus)
        assert reads==[0x40000000+offset]
        assert writes==[(0x21000,(bus>>lsb)&((1<<width)-1))]
    assert len(program.fragment)==(20 if lsb==0 else 24)
    assert program.document()['result_storage']['field_extraction']==dict(
        lsb=lsb,width=width,read_mask=(1<<width)-1,bus_width=32,representation='field_relative_zero_extended')
    assert verify_register_program_document(profile,cap,program.document(),**args).fragment==program.fragment


def test_large_mask_uses_independent_register_without_sign_extension():
    profile,_,args=inputs()
    doc=json.loads(SIDECAR.read_text())
    doc['register_semantics']=[row for row in doc['register_semantics'] if row['register']!='PADCFG_0']
    template=json.loads(SIDECAR.read_text())['register_semantics'][-1]
    for field,lsb,width in (('lower',0,12),('upper',12,20)):
        doc['register_semantics'].append({**template,'register':'PADCFG_0','field':field,
            'lsb':lsb,'width':width,'read_mask':(1<<width)-1,'write_mask':(1<<width)-1,'reset_value':0})
    cap=load_ip_test_capability(doc,profile=profile)
    for field,lsb,width,size in (('lower',0,12,28),('upper',12,20,32)):
        program=compile_register_program(profile,cap,**{**args,'field':field})
        assert len(program.fragment)==size
        assert execute(program.fragment,0xffffffff)[1]==[(0x21000,(1<<width)-1)]


@pytest.mark.parametrize('change',[{'mask_register':1},{'mask_register':2},{'mask_register':True},
    {'program_size':20},{'result_address':0x20000},{'read_modify_write':True}])
def test_narrow_read_rejects_conflicts_and_short_slot_before_emission(change):
    profile,cap,args=inputs()
    with pytest.raises(ValueError):compile_register_program(profile,cap,**{**args,**change})


@pytest.mark.parametrize('mutation',['missing','read_clear','writeonly','partial_read_mask'])
def test_other_fields_must_not_hide_word_read_effects_or_unknown_bits(mutation):
    from dataclasses import replace
    profile,_,args=inputs()
    doc=json.loads(SIDECAR.read_text())
    other=next(row for row in doc['register_semantics'] if row['register']=='PADCFG_0' and row['field']=='pin0')
    if mutation=='missing':doc['register_semantics'].remove(other)
    elif mutation=='read_clear':pass
    elif mutation=='writeonly':other.update(access='wo',read_mask=0)
    else:other['read_mask']=7
    cap=load_ip_test_capability(doc,profile=profile)
    if mutation=='read_clear':
        cap=replace(cap,register_semantics=tuple(replace(row,side_effect='read_clears')
            if row.register=='PADCFG_0' and row.field=='pin0' else row for row in cap.register_semantics))
    # The loader's typed contract also rejects an impossible mixed-effect row
    # before compilation; neither boundary may let allow_side_effect bypass it.
    reason='typed-contract-mismatch|complete-plain-readable' if mutation=='read_clear' else 'complete-plain-readable'
    with pytest.raises(ValueError,match=reason):
        compile_register_program(profile,cap,**args)


def test_fullword_read_layout_and_document_are_unchanged():
    profile,cap,args=arguments(register='PADOUT',field='value',operation='register_read',value=None,
        result_address=0x21000,result_regions=(MemoryRegion('result',0x21000,64),))
    program=compile_register_program(profile,cap,**args)
    assert len(program.fragment)==16
    assert [instruction.operation for instruction in program.instructions]==['LUI','LW','LUI','SW']
    assert set(program.document()['result_storage'])=={'address','width_bytes','purpose','evidence_scope'}
