"""Declarative register compilation; no RTL execution or inferred oracle."""
from dataclasses import replace
import pytest
from myfuzz.scenario.register_program import compile_register_program
from myfuzz.scenario.rv32i_sources import MmioWindow, fragment_bytes, validate_instruction_bytes
from myfuzz.scenario.memory import MemoryRegion
from tests.composition.test_pulp_gpio_test_capability import loaded

BASE = 0x40000000


def compile(**changes):
    profile, capability = loaded()
    args = dict(register='PADOUT', field='value', operation='register_write', value=0x80000801,
        address_base=BASE, windows=(MmioWindow(BASE, profile.address.window_size),),
        cpu_component='cpu', action_id='register-write', program_address=0x20000, program_size=64, program_regions=(MemoryRegion('program', 0x20000, 64),))
    args.update(changes)
    return compile_register_program(profile, capability, **args)


def test_full_word_real_store_fragment_and_data_only_identity():
    program = compile()
    assert [i.operation for i in program.instructions] == ['LUI', 'ADDI', 'LUI', 'SW']
    assert program.fragment == fragment_bytes(program.instructions) == program.source.data
    assert program.source.address == 0x20000
    validate_instruction_bytes(program.fragment)
    doc = program.document()
    assert doc['operation_plan']['bus_value'] == 0x80000801
    assert doc['scope'] == 'declarative_cpu_register_program_only'
    assert doc['grants_prerequisites'] is False
    assert doc['result_storage'] is None
    doc['operation_plan'].clear()
    assert program.document()['operation_plan']
    assert program.document() == compile().document()


@pytest.mark.parametrize('register', ['PADOUTSET', 'PADOUTCLR'])
def test_explicit_set_clear_aliases_issue_actual_store_only(register):
    program = compile(register=register, field='bits', allow_side_effect=True)
    assert [i.operation for i in program.instructions][-1] == 'SW'
    assert 'LW' not in [i.operation for i in program.instructions]
    with pytest.raises(ValueError): compile(register=register, field='bits')


def test_read_stores_actual_loaded_word_in_explicit_ram_location():
    program = compile(operation='register_read', value=None, result_address=0x21000,
        result_regions=(MemoryRegion('caller-ram', 0x21000, 64),))
    assert [i.operation for i in program.instructions] == ['LUI', 'LW', 'LUI', 'SW']
    assert program.instructions[1].rd == program.instructions[3].rs2
    assert program.document()['result_storage'] == dict(address=0x21000, width_bytes=4,
        purpose='caller_declared_result_storage', evidence_scope='requires_actual_cpu_store_and_read_snapshot')
    assert 'expected' not in repr(program.document())


@pytest.mark.parametrize('changes', [dict(address_base=True), dict(program_address=True),
    dict(program_size=True), dict(program_size=12), dict(program_address=0xfffffffc),
    dict(address_base=0xfffff800), dict(base_register=True), dict(data_register=0),
    dict(base_register=2), dict(windows=(MmioWindow(BASE, 0x2000),)),
    dict(windows=(MmioWindow(BASE-4, 4100),)), dict(result_address=0x21000)])
def test_access_context_rejects_unsafe_or_noncanonical(changes):
    with pytest.raises(ValueError): compile(**changes)


@pytest.mark.parametrize('result_address,result_regions', [
    (None, ()), (True, (MemoryRegion('ram', 0x21000, 64),)),
    (0x21001, (MemoryRegion('ram', 0x21000, 64),)),
    (BASE, (MemoryRegion('not-ram', BASE, 4096),)),
    (0x20000, (MemoryRegion('program', 0x20000, 64),)),
    (0x21000, (MmioWindow(0x21000, 64),)),
    (0x21000, (MemoryRegion('readonly', 0x21000, 64, writable=False),)),
])
def test_read_result_requires_separate_explicit_storage(result_address, result_regions):
    with pytest.raises(ValueError):
        compile(operation='register_read', value=None, result_address=result_address, result_regions=result_regions)


def test_narrow_ordinary_field_cannot_zero_unrelated_bits():
    from tests.composition.test_test_capability import VersionedCapabilitySidecarTests, PROFILE
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.composition.test_capability import load_ip_test_capability
    profile = load_component_profile(PROFILE)
    helper = VersionedCapabilitySidecarTests(); helper.profile = profile
    cap = load_ip_test_capability(helper.document(), profile=profile)
    for operation, value in [('register_write', 1), ('register_read', None)]:
        with pytest.raises(ValueError, match='full-word'):
            compile_register_program(profile, cap, register='CTRL', field='enable', operation=operation,
                value=value, address_base=BASE, windows=(MmioWindow(BASE, profile.address.window_size),),
                cpu_component='cpu', action_id='narrow', program_address=0x20000, program_size=64, program_regions=(MemoryRegion('program', 0x20000, 64),))


def test_mutated_typed_capability_is_revalidated():
    profile, cap = loaded()
    cap = replace(cap, sidecar_fingerprint='0'*64)
    with pytest.raises(ValueError):
        compile_register_program(profile, cap, register='PADOUT', field='value', operation='register_write', value=1,
            address_base=BASE, windows=(MmioWindow(BASE, 4096),), cpu_component='cpu', action_id='bad',
            program_address=0x20000, program_size=64, program_regions=(MemoryRegion('program', 0x20000, 64),))


def execute_words(program, read_value=0):
    """Tiny independent architectural check of the emitted LW/SW result path."""
    regs = [0] * 32; stores = []
    for offset in range(0, len(program.fragment), 4):
        word = int.from_bytes(program.fragment[offset:offset+4], 'little')
        opcode = word & 127; rd = word >> 7 & 31; rs1 = word >> 15 & 31; rs2 = word >> 20 & 31
        if opcode == 0x37: regs[rd] = word & 0xfffff000
        elif opcode == 0x13:
            immediate = word >> 20
            if immediate & 0x800: immediate -= 4096
            regs[rd] = (regs[rs1] + immediate) & 0xffffffff
        elif opcode == 3: regs[rd] = read_value
        elif opcode == 0x23:
            immediate = ((word >> 25) << 5) | (word >> 7 & 31)
            if immediate & 0x800: immediate -= 4096
            stores.append(((regs[rs1] + immediate) & 0xffffffff, regs[rs2]))
        else: raise AssertionError('unexpected instruction')
    return stores


def test_encoded_store_value_and_target_with_signed_low_immediate():
    assert execute_words(compile()) == [(BASE+12, 0x80000801)]


def test_compiled_read_has_no_host_result_value_and_preserves_loaded_data():
    program = compile(operation='register_read', value=None, result_address=0x21000,
        result_regions=(MemoryRegion('ram', 0x21000, 64),))
    assert execute_words(program, read_value=0xdeadbeef) == [(0x21000, 0xdeadbeef)]
    assert execute_words(program, read_value=0x12345678) == [(0x21000, 0x12345678)]


@pytest.mark.parametrize('regions', [(), (MemoryRegion('alias', 0x20000, 64, aliases=(0x30000,)),),
    (MemoryRegion('r', 0x20000, 64, writable=False),),
    (MemoryRegion('a', 0x20000, 64), MemoryRegion('b', 0x20000, 64)),
    (MemoryRegion('mmio', BASE, 4096),)])
def test_program_region_authorization_is_complete_and_unambiguous(regions):
    with pytest.raises(ValueError): compile(program_regions=regions)


def altered_contract(effect='none', readable=True, writable=True):
    import json
    from tests.composition.test_pulp_gpio_test_capability import PROFILE, SIDECAR
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.composition.test_capability import load_ip_test_capability
    document = json.loads(PROFILE.read_text())
    document['capabilities']['read'] = readable
    document['capabilities']['write'] = writable
    next(r for r in document['address']['registers'] if r['name'] == 'PADOUT')['side_effect'] = effect
    profile = load_component_profile(document)
    sidecar = json.loads(SIDECAR.read_text())
    sidecar['profile_fingerprint'] = profile.profile_fingerprint
    next(r for r in sidecar['register_semantics'] if r['register'] == 'PADOUT')['side_effect'] = effect
    # PADOUT is also the destination of the declared PADOUTSET/PADOUTCLR
    # aliases, and an alias destination must declare no side effect. These tests
    # are about which side effects a register program may be authorized for, not
    # about aliases, so the alias declarations that would conflict with the
    # altered semantics are dropped rather than the contract being relaxed.
    sidecar['register_aliases'] = [
        row for row in sidecar.get('register_aliases', ())
        if row.get('destination_register') != 'PADOUT']
    return profile, load_ip_test_capability(sidecar, profile=profile)


def custom_compile(profile, cap, **changes):
    args = dict(register='PADOUT', field='value', operation='register_write', value=1,
        address_base=BASE, windows=(MmioWindow(BASE, 4096),), cpu_component='cpu', action_id='custom',
        program_address=0x20000, program_size=64, program_regions=(MemoryRegion('program', 0x20000, 64),))
    args.update(changes)
    return compile_register_program(profile, cap, **args)


@pytest.mark.parametrize('effect', ['write_drives_output_enable', 'write_drives_pads'])
def test_declared_output_side_effects_require_explicit_authorization(effect):
    profile, cap = altered_contract(effect)
    with pytest.raises(ValueError): custom_compile(profile, cap)
    assert custom_compile(profile, cap, allow_side_effect=True).document()['operation_plan']['side_effect'] == effect


def test_unsupported_functional_side_effect_is_not_enabled_by_authorization():
    profile, cap = altered_contract('write_starts_transfer')
    with pytest.raises(ValueError, match='unsupported-side-effect'):
        custom_compile(profile, cap, allow_side_effect=True)


def test_profile_bus_permission_cannot_be_granted_by_caller_window():
    profile, cap = altered_contract(writable=False)
    with pytest.raises(ValueError, match='bus-permission'):
        custom_compile(profile, cap)


@pytest.mark.parametrize('register', ['PADDIR', 'PADOUT'])
def test_actual_output_register_read_with_declared_write_only_effect(register):
    profile, cap = loaded()
    program = custom_compile(profile, cap, register=register, operation='register_read', value=None,
        allow_side_effect=True, result_address=0x21000,
        result_regions=(MemoryRegion('ram', 0x21000, 64),))
    assert [i.operation for i in program.instructions] == ['LUI', 'LW', 'LUI', 'SW']
    assert execute_words(program, read_value=0x81234567) == [(0x21000, 0x81234567)]


@pytest.mark.parametrize('effect', ['read_clears', 'read_pops_fifo'])
def test_read_effects_remain_refused_despite_authorization(effect):
    profile, cap = altered_contract(effect)
    with pytest.raises(ValueError, match='unsupported-side-effect'):
        custom_compile(profile, cap, operation='register_read', value=None, allow_side_effect=True,
            result_address=0x21000, result_regions=(MemoryRegion('ram', 0x21000, 64),))


@pytest.mark.parametrize('effect', ['write_drives_output_enable', 'write_drives_pads'])
def test_read_write_only_output_effect_preserves_planner_authorization(effect):
    profile, cap = altered_contract(effect)
    args = dict(operation='register_read', value=None, result_address=0x21000,
        result_regions=(MemoryRegion('ram', 0x21000, 64),))
    with pytest.raises(ValueError, match='side-effect-requires-explicit'):
        custom_compile(profile, cap, **args)
    program = custom_compile(profile, cap, allow_side_effect=True, **args)
    assert program.document()['operation_plan']['side_effect'] == effect
    assert [i.operation for i in program.instructions] == ['LUI', 'LW', 'LUI', 'SW']
