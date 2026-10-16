"""Source-backed GPIO declarations do not imply executable field semantics."""
import pytest

from myfuzz.composition.test_capability import plan_register_operation
from myfuzz.scenario.memory import MemoryRegion
from tests.composition.test_pulp_gpio_test_capability import loaded
from tests.scenario.test_register_program import compile


def test_all_profile_registers_have_exact_nonoverlapping_field_coverage():
    profile, capability = loaded()
    fields = capability.register_semantics
    assert len(fields) == 72
    assert {field.register for field in fields} == {reg.name for reg in profile.address.registers}
    for register in profile.address.registers:
        rows = [field for field in fields if field.register == register.name]
        mask = 0
        for field in rows:
            bits = ((1 << field.width) - 1) << field.lsb
            assert not mask & bits
            mask |= bits
        assert mask == 0xffffffff


@pytest.mark.parametrize('register,access,read_mask,write_mask,effect', [
    ('GPIOEN', 'rw', 0xffffffff, 0xffffffff, 'none'),
    ('PADIN', 'ro', 0xffffffff, 0, 'none'),
    ('INTEN', 'rw', 0xffffffff, 0xffffffff, 'none'),
    ('INTSTATUS', 'ro', 0xffffffff, 0, 'read_clears'),
])
def test_additional_word_declarations_are_exact(register, access, read_mask, write_mask, effect):
    _, capability = loaded()
    field = next(field for field in capability.register_semantics if field.register == register)
    assert (field.field, field.lsb, field.width, field.access, field.read_mask,
        field.write_mask, field.reset_value, field.side_effect) == (
        'value', 0, 32, access, read_mask, write_mask, 0, effect)


@pytest.mark.parametrize('register,start,offset', [
    ('INTTYPE_LOW', 0, 0x1c), ('INTTYPE_HIGH', 16, 0x20),
    ('PADCFG_0', 0, 0x28), ('PADCFG_1', 8, 0x2c),
    ('PADCFG_2', 16, 0x30), ('PADCFG_3', 24, 0x34),
])
def test_packed_pin_fields_keep_word_relative_offsets(register, start, offset):
    profile, capability = loaded()
    width = 2 if register.startswith('INTTYPE') else 4
    count = 32 // width
    rows = [field for field in capability.register_semantics if field.register == register]
    assert [(field.field, field.lsb, field.width) for field in rows] == [
        ('pin' + str(start + index), index * width, width) for index in range(count)]
    for index, field in enumerate(rows):
        assert (field.access, field.read_mask, field.write_mask, field.reset_value,
                field.side_effect) == ('rw', (1 << width) - 1, (1 << width) - 1, 0, 'none')
        plan = plan_register_operation(profile, capability, register=register,
            field=field.field, operation='register_write', value=(1 << width) - 1)
        assert (plan.offset, plan.bus_mask, plan.bus_value) == (
            offset, ((1 << width) - 1) << (index * width),
            ((1 << width) - 1) << (index * width))


@pytest.mark.parametrize('register,field', [
    ('INTTYPE_LOW', 'pin0'), ('INTTYPE_HIGH', 'pin31'),
    ('PADCFG_0', 'pin7'), ('PADCFG_3', 'pin31'),
])
def test_declared_narrow_fields_remain_unexecutable_without_rmw(register, field):
    with pytest.raises(ValueError, match='full-word-field-required'):
        compile(register=register, field=field, value=1)


def test_conditional_status_read_is_declared_but_not_given_clear_oracle():
    profile, capability = loaded()
    plan = plan_register_operation(profile, capability, register='INTSTATUS', field='value',
        operation='register_read', allow_side_effect=True)
    assert plan.side_effect == 'read_clears'
    with pytest.raises(ValueError, match='unsupported-side-effect'):
        compile(register='INTSTATUS', operation='register_read', value=None,
            allow_side_effect=True, result_address=0x21000,
            result_regions=(MemoryRegion(
                'result', 0x21000, 64),))


@pytest.mark.parametrize('register', ['PADIN', 'INTSTATUS'])
def test_readonly_declarations_reject_write_plans(register):
    profile, capability = loaded()
    with pytest.raises(ValueError, match='field-not-writable'):
        plan_register_operation(profile, capability, register=register, field='value',
            operation='register_write', value=1, allow_side_effect=True)
