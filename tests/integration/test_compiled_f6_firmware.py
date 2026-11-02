"""Canonical F6 bytecode and a software-only RV32I control-flow model."""
from copy import deepcopy
from hashlib import sha256
import importlib
import importlib.util
import json

import pytest

from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.rv32i_sources import validate_instruction_bytes
from tests.integration.test_compiled_f6_layout import declared_path, module as layout_module, raw


def module():
    name = 'myfuzz.integration.compiled_f6_firmware'
    assert importlib.util.find_spec(name) is not None, 'F6 firmware is not installed'
    return importlib.import_module(name)


def contract():
    return dict(program_contract=dict(schema_version='compiled_F6_program.v1',
        boot_address=0x10080, isr_address=0x1022c, park_address=0x10400,
        slot_base=0x11000, slot_count=2, source_address=0x22804,
        destination_address=0x23808, result_base=0x2480c,
        slot_bytes=256, online_prefix_bytes=128, result_stride=24,
        operand_instruction_offsets=[40, 48, 56, 64],
        initial_image=[], initial_image_sha256=None, instruction_source_id='cpu.image'),
        control=dict(base=0x40000800), dma=dict(csr=dict(
            offsets=dict(control=0, length=4, source=8, destination=12),
            configuration_order=['source', 'destination', 'length', 'control'],
            start_key=0xfed, start_word=0x0fed0004, length_words=4, block_words=4,
            increment_source=True, increment_destination=True,
            source_destination_units='byte_address_shift_right_2',
            master_address_units='word', master_byte_enable=15, status_error_mask=0x40000000)))


def candidate(words=(1, 2, 3, 4)):
    return layout_module().compile_f6_candidate_layout(declared_path()).decode(raw(words))


def words(data):
    return [int.from_bytes(data[i:i+4], 'little') for i in range(0, len(data), 4)]


def signed(value, width):
    return value - (1 << width) if value & (1 << (width-1)) else value


def model(images, start, *, registers=None, ram=None, stop=(), limit=200,
          mip_values=(), mip_reads=None, timeline=None, csr_values=None):
    """Test interpreter only. It does not issue RTL or native receipts."""
    code = {a+4*i: w for a, data in images.items() for i, w in enumerate(words(data))}
    regs = [0]*32 if registers is None else registers.copy()
    ram = {} if ram is None else ram.copy()
    mip_values = iter(mip_values)
    if mip_reads is None:
        mip_reads = []
    pc, stores, loads, returns, csrs = start, [], [], [], dict(csr_values or {})
    for _ in range(limit):
        if pc in stop:
            return pc, regs, ram, stores, loads, returns, csrs
        w = code[pc]
        op, rd, a, b = w & 127, (w >> 7) & 31, (w >> 15) & 31, (w >> 20) & 31
        following = pc+4
        if op == 0x37:
            regs[rd] = w & 0xfffff000
        elif op == 0x13:
            imm = signed(w >> 20, 12)
            funct3 = (w >> 12) & 7
            if funct3 == 0:
                regs[rd] = (regs[a]+imm) & 0xffffffff
            elif funct3 == 5:
                regs[rd] = regs[a] >> ((w >> 20) & 31)
            elif funct3 == 7:
                regs[rd] = regs[a] & imm
            else:
                raise AssertionError(f'unsupported test OP-IMM funct3 {funct3}')
        elif op == 0x23:
            offset = signed(((w >> 25) << 5) | ((w >> 7) & 31), 12)
            address = (regs[a]+offset) & 0xffffffff
            ram[address] = regs[b]
            stores.append((address, regs[b]))
            if timeline is not None:
                timeline.append(('store', address, regs[b]))
        elif op == 0x33 and (w >> 12) & 7 == 7:
            regs[rd] = regs[a] & regs[b]
        elif op == 0x03:
            address = (regs[a]+signed(w >> 20, 12)) & 0xffffffff
            loads.append(address)
            regs[rd] = ram[address]
        elif op == 0x63:
            offset = signed(((w >> 31) << 12) | (((w >> 7) & 1) << 11)
                | (((w >> 25) & 63) << 5) | (((w >> 8) & 15) << 1), 13)
            funct3=(w>>12)&7
            if (regs[a]==regs[b]) if funct3==0 else (regs[a]!=regs[b]):
                following = pc+offset
        elif op == 0x6f:
            offset = signed(((w >> 31) << 20) | (((w >> 12) & 255) << 12)
                | (((w >> 20) & 1) << 11) | (((w >> 21) & 1023) << 1), 21)
            regs[rd] = following
            following = pc+offset
        elif w == 0x30200073:
            returns.append(pc)
            if timeline is not None:
                timeline.append(('mret', pc))
            following = ram['mepc']
        elif op == 0x73:
            csr, funct3 = w >> 20, (w >> 12) & 7
            if csr == 0x344 and funct3 == 2 and a == 0:
                value = next(mip_values, 0)
                mip_reads.append(value)
                regs[rd] = value
                if timeline is not None:
                    timeline.append(('mip', value))
            else:
                prior=csrs.get(csr,0);operand=regs[a]
                csrs[csr] = operand if funct3==1 else prior|operand
                regs[rd]=prior
        else:
            raise AssertionError(f'unsupported test instruction {w:x}')
        regs[0] = 0
        pc = following
    return pc, regs, ram, stores, loads, returns, csrs


def test_only_four_declared_immediates_change():
    fw = module().build_f6_firmware(contract())
    x = fw.prefix(candidate(), case_index=0)
    y = fw.prefix(candidate((2047, 0, 1024, 1023)), case_index=0)
    assert len(x) == len(y) == 128
    assert [i for i, (a, b) in enumerate(zip(words(x), words(y))) if a != b] == [10, 12, 14, 16]
    for i in (10, 12, 14, 16):
        assert (words(x)[i] ^ words(y)[i]) & ~0x7ff00000 == 0
        assert words(x)[i] & 0x800fffff == 0x193
    validate_instruction_bytes(x)
    validate_instruction_bytes(y)


def test_prefix_programs_exact_bound_pointers_values_and_csr_order():
    c = contract(); p = c['program_contract']
    fw = module().build_f6_firmware(c)
    for index in range(2):
        data = fw.prefix(candidate(), case_index=index)
        validate_instruction_bytes(data)
        _, regs, _, stores, _, _, _ = model({0: data}, 0, stop=(128,))
        assert [regs[r] for r in (1, 2, 4, 5, 10, 11)] == [c['control']['base'],
            p['source_address'], p['destination_address'], p['result_base']+24*index, 0, 1]
        assert stores == [(p['source_address']+4*i, i+1) for i in range(4)] + [
            (c['control']['base']+8, p['source_address']),
            (c['control']['base']+12, p['destination_address']),
            (c['control']['base']+4, 4), (c['control']['base'], 0x0fed0004)]
        assert words(data)[25:] == [0x13]*7


def test_firmware_uses_dma_csr_description_for_control_sequence_and_irq_status():
    """A DMA with the same transfer behavior can use a different CSR layout."""
    c = contract()
    csr = c['dma']['csr']
    csr['offsets'] = dict(control=12, length=8, source=0, destination=4)
    csr['start_key'] = 0x123
    csr['start_word'] = 0x12340004
    csr['status_error_mask'] = 0x20000000
    p = c['program_contract']
    fw = module().build_f6_firmware(c)
    code = fw.prefix(candidate(), case_index=0)
    _, _, ram, stores, _, _, _ = model({p['slot_base']:code}, p['slot_base'],
                                       stop=(p['slot_base'] + 128,))
    assert stores[-4:] == [(c['control']['base'], p['source_address']),
        (c['control']['base']+4, p['destination_address']),
        (c['control']['base']+8, 4), (c['control']['base']+12, 0x12340004)]
    ram.update({p['destination_address']+4*i: i+1 for i in range(4)})
    ram[c['control']['base']+12] = 0x20000000
    ram['mepc'] = p['park_address']
    _, regs, _, stores, loads, returns, _ = model(
        fw.initial_images, p['isr_address'],
        registers=[0,c['control']['base'],p['source_address'],0,
                   p['destination_address'],p['result_base']]+[0]*26,
        ram=ram, stop=(p['park_address'],))
    assert loads[0] == c['control']['base']+12
    assert stores[-1] == (p['result_base']+20, 2)
    assert len(returns) == 1


def test_firmware_rejects_csr_description_that_differs_from_source_contract():
    c = contract()
    c['dma']['source_contract'] = {'csr': deepcopy(c['dma']['csr'])}
    c['dma']['csr']['start_word'] ^= 1
    with pytest.raises(ValueError, match='csr-source-drift'):
        module().build_f6_firmware(c)


@pytest.mark.parametrize('offsets', [
    dict(control=0, length=0, source=8, destination=12),
    dict(control=0, length=4, source=8, destination=16),
    dict(control=0, length=4, source=8, destination=3),
])
def test_firmware_rejects_invalid_or_out_of_window_csr_offsets(offsets):
    c = contract()
    c['dma']['csr']['offsets'] = offsets
    with pytest.raises(ValueError, match='csr-offsets'):
        module().build_f6_firmware(c)


def test_prefix_has_exact_rv32i_opcodes_and_register_fields():
    fw = module().build_f6_firmware(contract())
    expected = [0x400010b7, 0x80008093, 0x00023137, 0x80410113,
        0x00024237, 0x80820213, 0x000252b7, 0x80c28293,
        0x00000513, 0x00100593, 0x00100193, 0x00312023,
        0x00200193, 0x00312223, 0x00300193, 0x00312423,
        0x00400193, 0x00312623, 0x0020a423, 0x0040a623,
        0x00400193, 0x0030a223, 0x0fed01b7, 0x00418193, 0x0030a023] + [0x13]*7
    assert words(fw.prefix(candidate(), case_index=0)) == expected
    for address, image in fw.initial_images.items():
        with pytest.raises(ValueError):
            validate_instruction_bytes(image)


def test_final_park_fetch_remains_an_unmaterialized_instruction_boundary():
    c = contract(); p = c['program_contract']; fw = module().build_f6_firmware(c)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in fw.initial_images.items():
        memory.preload(address, image)
    for address, count in fw.instruction_slots:
        memory.declare_instruction_slots(address, count)

    assert memory.instruction_slot_unmaterialized(p['park_address'])
    assert all(memory.inspect_byte('ram', p['park_address']-0x10000+i) is None
               for i in range(4))
    for address in (p['boot_address'], p['isr_address'], 0x11080, 0x11180):
        assert memory.inspect_byte('ram', address-0x10000) is not None


def test_sparse_manifest_leaves_every_reserved_prefix_byte_unmaterialized():
    c = contract(); p = c['program_contract']; fw = module().build_f6_firmware(c)
    assert fw.instruction_slots == ((0x11000, 32), (0x11100, 32), (p['park_address'], 1))
    expected = [dict(address=a, length=len(data), sha256=sha256(data).hexdigest())
                for a, data in sorted(fw.initial_images.items())]
    assert list(fw.initial_segment_manifest) == expected
    assert fw.manifest_sha256 == sha256(json.dumps(expected, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    assert set(fw.initial_images) == {p['boot_address'], p['isr_address'], 0x11080, 0x11180}
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in fw.initial_images.items():
        memory.preload(address, image)
    for address, count in fw.instruction_slots:
        memory.declare_instruction_slots(address, count)
        assert all(memory.instruction_slot_unmaterialized(address+4*i) for i in range(count))
        assert all(memory.inspect_byte('ram', address-0x10000+i) is None for i in range(count*4))
    assert memory.initialized_bytes == sum(map(len, fw.initial_images.values()))
    data = fw.prefix(candidate(), case_index=0)
    memory.accept_instructions(0x11000, data, source_event_id='case0')
    with pytest.raises(ValueError, match='overwrite'):
        memory.accept_instructions(0x11000, data, source_event_id='again')
    with pytest.raises(ValueError, match='overwrite'):
        memory.preload(0x11100, data)


@pytest.mark.parametrize('error', [False, True])
def test_software_isr_mret_preserves_registers_and_distinct_control_behavior(error):
    c = contract(); p = c['program_contract']; fw = module().build_f6_firmware(c)
    data = fw.prefix(candidate(), case_index=0)
    island = p['slot_base']+128
    _, regs, ram, _, _, _, _ = model({p['slot_base']: data}, p['slot_base'], stop=(island,))
    kept = {i: regs[i] for i in (1, 2, 4, 5, 11)}
    ram.update({p['destination_address']+4*i: i+1 for i in range(4)})
    ram[c['control']['base']] = 0x40000000 if error else 0
    ram['mepc'] = island
    pc, regs, ram, stores, loads, returns, _ = model(fw.initial_images, p['isr_address'],
        registers=regs, ram=ram, stop=(island,))
    assert {i: regs[i] for i in kept} == kept
    assert len(returns) == 1 and regs[10] == (2 if error else 1)
    assert ram[p['result_base']+20] == (2 if error else 1)
    assert loads[0] == c['control']['base']
    assert [a for a in loads if p['destination_address'] <= a < p['destination_address']+16] == ([] if error else [p['destination_address']+4*i for i in range(4)])
    pc, *_ = model(fw.initial_images, island, registers=regs, ram=ram,
        stop=(p['slot_base']+256,), limit=5)
    assert pc == (island if error else p['slot_base']+256)


def test_boot_and_final_control_island_land_at_declared_boundaries():
    c = contract(); p = c['program_contract']; fw = module().build_f6_firmware(c)
    _, _, _, _, _, _, csrs = model(fw.initial_images, p['boot_address'], stop=(p['slot_base'],))
    # Vectored mode names the same fixed IRQ entry on every adapter; CV32E40P
    # would otherwise enter a direct-mode trap at the base instead of base+44.
    assert csrs == {0x305: (p['isr_address']-44)|1, 0x304: 2048, 0x300: 8}
    regs = [0]*32; regs[10] = regs[11] = 1
    pc, *_ = model(fw.initial_images, p['slot_base']+256+128, registers=regs,
        stop=(p['park_address'],))
    assert pc == p['park_address']


@pytest.mark.parametrize('error,status', [(False, 0), (True, 0x40000000)])
def test_isr_waits_for_real_external_pending_to_clear_before_terminal_store_and_mret(
        error, status):
    c = contract(); p = c['program_contract']; fw = module().build_f6_firmware(c)
    island = p['slot_base']+128
    registers = [0]*32
    registers[1] = c['control']['base']
    registers[2] = p['source_address']
    registers[4] = p['destination_address']
    registers[5] = p['result_base']
    ram = {c['control']['base']: status, 'mepc': island}
    ram.update({p['destination_address']+4*i: i+11 for i in range(4)})
    mip_reads = []
    timeline = []

    pc, registers, ram, stores, loads, returns, _ = model(
        fw.initial_images, p['isr_address'], registers=registers, ram=ram,
        stop=(island,), mip_values=(1 << 11, 1 << 11, 0), mip_reads=mip_reads,
        timeline=timeline)

    assert pc == island
    assert mip_reads == [1 << 11, 1 << 11, 0]
    assert registers[10] == (2 if error else 1)
    assert ram[p['result_base']+20] == (2 if error else 1)
    assert [address for address, _value in stores][-1] == p['result_base']+20
    terminal_store = next(i for i, event in enumerate(timeline)
        if event[:2] == ('store', p['result_base']+20))
    assert [event[1] for event in timeline if event[0] == 'mip'] == [
        1 << 11, 1 << 11, 0]
    assert max(i for i, event in enumerate(timeline)
        if event[0] == 'mip') < terminal_store
    assert len(returns) == 1
    assert loads == [c['control']['base']] + ([] if error else [
        p['destination_address']+4*i for i in range(4)])


def test_isr_masks_mip_to_meip_bit_before_leaving_the_terminal_island():
    c = contract(); p = c['program_contract']; fw = module().build_f6_firmware(c)
    island = p['slot_base']+128
    registers = [0]*32
    registers[1] = c['control']['base']
    registers[2] = p['source_address']
    registers[4] = p['destination_address']
    registers[5] = p['result_base']
    ram = {c['control']['base']: 0, 'mepc': island}
    ram.update({p['destination_address']+4*i: i+11 for i in range(4)})
    mip_reads = []

    pc, registers, ram, _stores, _loads, returns, _ = model(
        fw.initial_images, p['isr_address'], registers=registers, ram=ram,
        stop=(island,), mip_values=(1 << 7, 0), mip_reads=mip_reads)

    assert pc == island
    assert mip_reads == [1 << 7]
    assert registers[10] == 1
    assert ram[p['result_base']+20] == 1
    assert len(returns) == 1


@pytest.mark.parametrize('field,value', [('slot_count', 0), ('slot_count', 17),
    ('slot_count', True), ('online_prefix_bytes', 124), ('slot_bytes', 128),
    ('isr_address', 0x10200), ('slot_base', 0x10200), ('source_address', 0x11000),
    ('result_base', 0x22804), ('boot_address', 0x11000), ('park_address', 0x11080)])
def test_refuses_overlap_and_invalid_slots(field, value):
    c = contract(); c['program_contract'][field] = value
    with pytest.raises(ValueError):
        module().build_f6_firmware(c)


@pytest.mark.parametrize('index', [-1, 2, True, 1.0])
def test_prefix_slot_exhaustion(index):
    fw = module().build_f6_firmware(contract())
    with pytest.raises(ValueError):
        fw.prefix(candidate(), case_index=index)


def test_manifest_pin_refuses_mutated_branch_mret_and_preload_hash():
    c = contract(); fw = module().build_f6_firmware(c)
    c['program_contract']['initial_image'] = list(fw.initial_segment_manifest)
    c['program_contract']['initial_image_sha256'] = fw.manifest_sha256
    assert module().build_f6_firmware(c).manifest_sha256 == fw.manifest_sha256
    for address, offset in [(0x11080, 0), (0x1022c, len(fw.initial_images[0x1022c])-4)]:
        bad = deepcopy(c)
        altered = bytearray(fw.initial_images[address]); altered[offset] ^= 1
        row = next(r for r in bad['program_contract']['initial_image'] if r['address'] == address)
        row['sha256'] = sha256(altered).hexdigest()
        with pytest.raises(ValueError):
            module().build_f6_firmware(bad)
    bad = deepcopy(c); bad['program_contract']['initial_image_sha256'] = '0'*64
    with pytest.raises(ValueError):
        module().build_f6_firmware(bad)


def test_mutated_nonoperand_byte_is_refused_against_canonical_prefix():
    fw = module().build_f6_firmware(contract())
    data = bytearray(fw.prefix(candidate(), case_index=0))
    # This remains a legal LUI under the generic validator, but changes DMA pointer.
    data[3] ^= 1
    validate_instruction_bytes(bytes(data))
    with pytest.raises(ValueError):
        fw.validate_prefix(bytes(data), candidate(), case_index=0)
    fw.validate_prefix(fw.prefix(candidate(), case_index=0), candidate(), case_index=0)


@pytest.mark.parametrize('addresses', [(0, 2048, 4092), (0xfffff000, 0xfffff800, 0xffffffc0)])
def test_pointer_loads_cover_low_half_sign_and_rv32_wrap(addresses):
    c = contract(); p = c['program_contract']
    p['source_address'], p['destination_address'], p['result_base'] = addresses
    fw = module().build_f6_firmware(c)
    data = fw.prefix(candidate(), case_index=1)
    validate_instruction_bytes(data)
    _, regs, *_ = model({0: data}, 0, stop=(128,))
    assert (regs[2], regs[4], regs[5]) == (*addresses[:2], addresses[2]+24)


def test_document_pins_exact_fixed_isr_return_sites_and_is_detached():
    fw = module().build_f6_firmware(contract())
    doc = fw.document()
    image = fw.initial_images[0x1022c]
    assert doc['isr'] == dict(address=0x1022c, length=len(image),
        sha256=sha256(image).hexdigest(), mret_addresses=[0x1027c, 0x10298])
    for address in doc['isr']['mret_addresses']:
        assert image[address-0x1022c:address-0x1022c+4] == bytes.fromhex('73002030')
    doc['isr']['mret_addresses'].clear()
    doc['program_contract']['slot_count'] = 100
    images = fw.initial_images; images.clear()
    assert len(fw.document()['isr']['mret_addresses']) == 2
    assert len(fw.instruction_slots) == 3 and len(fw.initial_images) == 4


@pytest.mark.parametrize('container', ['operand_instruction_offsets', 'configuration_order', 'initial_image'])
def test_protocol_arrays_refuse_tuple_containers(container):
    c = contract()
    if container == 'initial_image':
        fw = module().build_f6_firmware(c)
        c['program_contract']['initial_image'] = list(fw.initial_segment_manifest)
        c['program_contract']['initial_image_sha256'] = fw.manifest_sha256
    owner = c['dma']['csr'] if container == 'configuration_order' else c['program_contract']
    owner[container] = tuple(owner[container])
    with pytest.raises(ValueError):
        module().build_f6_firmware(c)


@pytest.mark.parametrize('container', ['csr.offsets', 'manifest.entry'])
def test_protocol_objects_refuse_dict_subclasses(container):
    class DerivedDict(dict):
        pass
    c = contract()
    if container == 'csr.offsets':
        c['dma']['csr']['offsets'] = DerivedDict(c['dma']['csr']['offsets'])
    else:
        fw = module().build_f6_firmware(c)
        c['program_contract']['initial_image'] = list(fw.initial_segment_manifest)
        c['program_contract']['initial_image_sha256'] = fw.manifest_sha256
        c['program_contract']['initial_image'][0] = DerivedDict(c['program_contract']['initial_image'][0])
    with pytest.raises(ValueError):
        module().build_f6_firmware(c)


def test_dma_behavior_byte_length_and_control_irq_clear():
    c=contract();p=c['program_contract'];csr=c['dma']['csr']
    csr.update(offsets=dict(control=0,source=4,destination=8,length=12),
        start_key=0,start_word=0,source_destination_units='byte_address')
    c['dma']['behavior']=dict(length_unit='bytes',
        irq_clear=dict(method='write',offset=0,value=0x80000000,byte_enable=15))
    fw=module().build_f6_firmware(c)
    code=fw.prefix(candidate(),case_index=0)
    _,_,ram,stores,_,_,_=model({p['slot_base']:code},p['slot_base'],stop=(p['slot_base']+128,))
    assert stores[-4:]==[(c['control']['base']+4,p['source_address']),
        (c['control']['base']+8,p['destination_address']),
        (c['control']['base']+12,16),(c['control']['base'],0)]
    ram.update({p['destination_address']+4*i:i+1 for i in range(4)})
    ram[c['control']['base']]=0;ram['mepc']=p['park_address']
    _,_,_,stores,_,returns,_=model(fw.initial_images,p['isr_address'],
        registers=[0,c['control']['base'],p['source_address'],0,
                   p['destination_address'],p['result_base']]+[0]*26,
        ram=ram,stop=(p['park_address'],))
    assert (c['control']['base'],0x80000000) in stores
    assert stores[-1]==(p['result_base']+20,1)
    assert len(returns)==1


def test_explicit_legacy_behavior_keeps_wbdmac_bytes_identical():
    from hashlib import sha256
    c=contract();original=module().build_f6_firmware(c)
    c['dma']['behavior']=dict(length_unit='words',irq_clear=dict(method='none'))
    explicit=module().build_f6_firmware(c)
    assert explicit.initial_images==original.initial_images
    assert explicit.prefix(candidate(),case_index=0)==original.prefix(candidate(),case_index=0)
    assert original.manifest_sha256=='9ee143fb7d55738a878a03fc37ef88692bdfbac75b1e53e8a23345e5f2beab88'
    assert sha256(original.prefix(candidate(),case_index=0)).hexdigest()=='0187cdd2fdfad0d630c7aecf955c0126d79f286a8d20a26b6937d65d57092e72'


def test_zipdma_semantics_derive_from_verified_source_contract():
    from pathlib import Path
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.zipdma_profile_session import verify_zipdma_profile
    from myfuzz.integration.f6_dma_behavior import f6_dma_semantics_from_source
    root=Path(__file__).resolve().parents[2]
    profile=load_component_profile(root/'configs/peripherals/zipdma_smoke/component_profile.json')
    source=verify_zipdma_profile(profile,base_dir=root)
    csr,behavior=f6_dma_semantics_from_source(source)
    c=contract();c['dma']={'csr':csr,'behavior':behavior,'source_contract':source}
    fw=module().build_f6_firmware(c)
    p=c['program_contract'];code=fw.prefix(candidate(),case_index=0)
    _,_,ram,stores,_,_,_=model({p['slot_base']:code},p['slot_base'],stop=(p['slot_base']+128,))
    assert stores[-4:]==[(c['control']['base']+4,p['source_address']),
        (c['control']['base']+8,p['destination_address']),
        (c['control']['base']+12,16),(c['control']['base'],0)]
    ram[c['control']['base']]=0x40000000;ram['mepc']=p['park_address']
    _,_,_,stores,_,returns,_=model(fw.initial_images,p['isr_address'],
        registers=[0,c['control']['base'],p['source_address'],0,
                   p['destination_address'],p['result_base']]+[0]*26,
        ram=ram,stop=(p['park_address'],))
    assert (c['control']['base'],0x80000000) in stores
    assert stores[-1]==(p['result_base']+20,2)
    assert len(returns)==1
    c['dma']['behavior']['irq_clear']['byte_enable']=7
    with pytest.raises(ValueError,match='irq-clear'):module().build_f6_firmware(c)
