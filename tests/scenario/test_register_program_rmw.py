"""Explicit CPU read/modify/write preserves bits loaded from the device."""
import pytest

from myfuzz.scenario.rv32i_sources import (Rv32iInstruction, validate_instruction_bytes,
                                         instruction_operator_id)
from tests.scenario.test_register_program import compile


@pytest.mark.parametrize('operation,word', [('AND', 0x00317133), ('OR', 0x00316133)])
def test_register_logic_encoding_and_closed_validation(operation, word):
    instruction = Rv32iInstruction(operation, rd=2, rs1=2, rs2=3)
    assert instruction.word() == word
    validate_instruction_bytes(word.to_bytes(4, 'little'))
    for reserved in (1, 0x20, 0x7f):
        with pytest.raises(ValueError):
            validate_instruction_bytes((word | (reserved << 25)).to_bytes(4, 'little'))
    for immediate in (1, -1, True, False):
        with pytest.raises(ValueError):
            Rv32iInstruction(operation, rd=2, rs1=2, rs2=3, immediate=immediate)


def execute(program, old_value):
    """Decode machine words independently; no compiler instruction metadata."""
    registers = [0] * 32
    reads, writes = [], []
    for offset in range(0, len(program.fragment), 4):
        word = int.from_bytes(program.fragment[offset:offset+4], 'little')
        opcode, rd, rs1, rs2 = word & 127, word >> 7 & 31, word >> 15 & 31, word >> 20 & 31
        if opcode == 0x37:
            registers[rd] = word & 0xfffff000
        elif opcode == 0x13:
            assert word >> 12 & 7 == 0
            immediate = word >> 20
            if immediate & 0x800: immediate -= 4096
            registers[rd] = (registers[rs1] + immediate) & 0xffffffff
        elif opcode == 0x03:
            assert word >> 12 & 7 == 2
            immediate = word >> 20
            if immediate & 0x800: immediate -= 4096
            reads.append((registers[rs1] + immediate) & 0xffffffff)
            registers[rd] = old_value
        elif opcode == 0x33:
            assert word >> 25 == 0
            function = word >> 12 & 7
            assert function in (6, 7)
            registers[rd] = (registers[rs1] & registers[rs2] if function == 7
                             else registers[rs1] | registers[rs2])
        elif opcode == 0x23:
            assert word >> 12 & 7 == 2
            immediate = (word >> 25 << 5) | (word >> 7 & 31)
            if immediate & 0x800: immediate -= 4096
            writes.append(((registers[rs1] + immediate) & 0xffffffff, registers[rs2]))
        else:
            raise AssertionError('unsupported machine instruction')
        registers[0] = 0
    return reads, writes


@pytest.mark.parametrize('register,field,lsb,width,address', [
    ('INTTYPE_LOW', 'pin0', 0, 2, 0x4000001c),
    ('INTTYPE_LOW', 'pin7', 14, 2, 0x4000001c),
    ('INTTYPE_HIGH', 'pin31', 30, 2, 0x40000020),
    ('PADCFG_0', 'pin0', 0, 4, 0x40000028),
    ('PADCFG_1', 'pin11', 12, 4, 0x4000002c),
    ('PADCFG_3', 'pin31', 28, 4, 0x40000034),
])
@pytest.mark.parametrize('old', [0, 0xffffffff, 0x12345678, 0x80000000, 0xaaaaaaaa])
def test_encoded_rmw_preserves_actual_read_bits(register, field, lsb, width, address, old):
    value = ((1 << width) - 1) // 2
    program = compile(register=register, field=field, value=value, read_modify_write=True)
    reads, writes = execute(program, old)
    mask = ((1 << width) - 1) << lsb
    assert reads == [address]
    assert writes == [(address, (old & ~mask) | (value << lsb))]
    assert len(program.fragment) == 36
    document = program.document()
    assert document['access_context']['read_modify_write'] is True
    assert document['grants_prerequisites'] is False
    assert 'expected' not in repr(document)


@pytest.mark.parametrize('changes', [
    dict(read_modify_write=1), dict(mask_register=True), dict(mask_register=0),
    dict(mask_register=1), dict(mask_register=2), dict(mask_register=32),
    dict(program_size=16),
])
def test_rmw_requires_explicit_flag_scratch_and_sufficient_slot(changes):
    args = dict(register='PADCFG_0', field='pin0', value=1, read_modify_write=True)
    args.update(changes)
    with pytest.raises(ValueError): compile(**args)


@pytest.mark.parametrize('changes', [
    dict(register='PADOUTSET', field='bits', allow_side_effect=True),
    dict(register='PADOUTCLR', field='bits', allow_side_effect=True),
    dict(operation='register_read', value=None),
])
def test_rmw_refuses_side_effects_and_read_operation(changes):
    args = dict(register='PADCFG_0', field='pin0', value=1, read_modify_write=True)
    args.update(changes)
    with pytest.raises(ValueError, match='rmw'): compile(**args)


@pytest.mark.parametrize('operation', ['AND', 'OR'])
def test_register_logic_has_exact_operator_identity(operation):
    instruction = Rv32iInstruction(operation, rd=2, rs1=2, rs2=3)
    assert instruction_operator_id(instruction.word().to_bytes(4, 'little')) == 'rv32i:' + operation


def test_complete_rmw_operator_identity_does_not_claim_byte_stores():
    program = compile(register='PADCFG_0', field='pin0', value=1, read_modify_write=True)
    assert instruction_operator_id(program.fragment) == 'rv32i:LUI+LW+LUI+ADDI+AND+LUI+ADDI+OR+SW'


@pytest.mark.parametrize('mutation', ['missing', 'readonly', 'read_mask', 'write_mask'])
def test_rmw_requires_all_unselected_fields_to_be_plain_complete_rw(mutation):
    import json
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.register_program import compile_register_program
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    from tests.scenario.test_register_program_verification import arguments
    profile, _, args = arguments(register='INTTYPE_LOW', field='pin0', value=1,
                                 read_modify_write=True)
    document = json.loads(SIDECAR.read_text())
    other = next(row for row in document['register_semantics']
                 if row['register'] == 'INTTYPE_LOW' and row['field'] == 'pin15')
    if mutation == 'missing': document['register_semantics'].remove(other)
    elif mutation == 'readonly': other.update(access='ro', write_mask=0)
    else: other[mutation] = 1
    capability = load_ip_test_capability(document, profile=profile)
    with pytest.raises(ValueError, match='rmw-requires-complete-plain-rw-register'):
        compile_register_program(profile, capability, **args)


@pytest.mark.parametrize('permission', ['read', 'write', 'width'])
def test_rmw_requires_both_actual_declared_bus_permissions(permission):
    from myfuzz.scenario.rv32i_sources import MmioWindow
    args = dict(readable=permission != 'read', writable=permission != 'write',
                write_widths=(1,) if permission == 'width' else (4,))
    with pytest.raises(ValueError):
        compile(register='PADCFG_0', field='pin0', value=1, read_modify_write=True,
                windows=(MmioWindow(0x40000000, 4096, **args),))
