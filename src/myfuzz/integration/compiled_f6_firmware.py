"""Canonical whitelist prefixes and sparse immutable F6 firmware.

These bytes are pure compilation output, never native execution evidence.

Reset epochs
------------
The sparse image is laid out once: boot, ISR, one 256-byte arena with a
128-byte online prefix window plus an 8-byte control island per slot, and the
terminal park fetch.  A measured reset relaunches the CPU process, which re-runs
the same boot code; a later epoch therefore needs its own *entry* into the same
arena, or it would replay the epoch it just left.

``build_f6_firmware(contract, entry=...)`` renders exactly that: the same slot
payloads (prefix ABI, islands, islands' walk, ISR, park) with the boot's single
final jump retargeted to the declared slot.  The rule is declared once
(:data:`ENTRY_POLICY`, :func:`declare_program_entry`) and is not a special case:
epoch 0 enters the first slot, every later epoch enters the slot it declares,
and the declared slot of a later epoch can never be the first slot because that
window's instruction bytes are already materialized with a pre-reset payload.
"""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json

from myfuzz.scenario.rv32i_sources import validate_instruction_bytes
from .compiled_f6_layout import F6Candidate, _validate_document_containers
from . import rv32_fixed_firmware as _rv32

_addi = _rv32._addi
_sw = _rv32._sw


def _require(condition, code):
    if not condition:
        raise ValueError('compiled-F6-firmware-' + code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _csrrs(rd, csr, rs1=0):
    return csr << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x73


def _srli(rd, rs, shift):
    return shift << 20 | rs << 15 | 5 << 12 | rd << 7 | 0x13


def _andi(rd, rs, immediate):
    return (immediate & 0xfff) << 20 | rs << 15 | 7 << 12 | rd << 7 | 0x13


def _load(rd, value):
    """LUI plus sign-extended ADDI, including low halves with bit11 set."""
    return [_rv32._lui(rd, (value+0x800) >> 12), _addi(rd, rd, value & 0xfff)]


def _lw(rd, base, offset):
    return _rv32._lw(rd, base, offset & 0xfff)


def _bne(a, b, offset):
    value = offset & 0x1fff
    return ((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25 | b << 20 | a << 15 | 1 << 12 | ((value >> 1) & 15) << 8 | ((value >> 11) & 1) << 7 | 0x63


def _jal(offset):
    _require(type(offset) is int and offset % 2 == 0 and -(1 << 20) <= offset < (1 << 20), 'jump-range')
    return _rv32._jal(0, offset)


def _wait_for_external_irq_low():
    """Poll real mip.MEIP so the return boundary follows the fixed IRQ window."""
    return [_csrrs(6, 0x344), _srli(6, 6, 11), _andi(6, 6, 1), _bne(6, 0, -12)]


def _encode(words):
    return b''.join(w.to_bytes(4, 'little') for w in words)


#: The one declared program-entry rule.  ``boot`` ends with one ``jal`` whose
#: target is ``slot_base + slot_bytes*slot``; the epoch-0 rendering targets the
#: first slot, which is the original (pre-reset) image byte for byte.
ENTRY_SCHEMA_VERSION = 'compiled_F6_entry.v1'
ENTRY_POLICY = 'declared_resume_slot'
_ENTRY_KEYS = frozenset({'schema_version', 'policy', 'reset_epoch', 'slot',
                         'slot_count'})


def declare_program_entry(*, reset_epoch, slot, slot_count):
    """Declare one epoch's arena entry under the single declared rule.

    ``reset_epoch`` 0 is the first rendering: it must enter the first slot,
    because the whole pre-reset evidence chain (first fetch, launch identity,
    slot ledger) is pinned to that address.  Every later epoch declares the slot
    it resumes at, and that slot is never the first one: the first window's
    instruction bytes are already materialized with a pre-reset case payload, so
    entering it again would be a replay of an old case, not continuation.
    """
    _require(type(reset_epoch) is int and reset_epoch >= 0, 'entry-epoch')
    _require(type(slot_count) is int and 1 <= slot_count <= 16, 'entry-slot-count')
    _require(type(slot) is int and 0 <= slot < slot_count, 'entry-slot')
    _require(slot == 0 if reset_epoch == 0 else slot >= 1, 'entry-epoch-slot')
    return {'schema_version': ENTRY_SCHEMA_VERSION, 'policy': ENTRY_POLICY,
            'reset_epoch': reset_epoch, 'slot': slot, 'slot_count': slot_count}


def _validated_entry(entry, program):
    """Re-declare (never trust) a caller's entry document."""
    if entry is None:
        return None
    _require(type(entry) is dict and set(entry) == _ENTRY_KEYS, 'entry-fields')
    _require(entry['schema_version'] == ENTRY_SCHEMA_VERSION
             and entry['policy'] == ENTRY_POLICY, 'entry-policy')
    declared = declare_program_entry(reset_epoch=entry['reset_epoch'],
                                     slot=entry['slot'],
                                     slot_count=entry['slot_count'])
    _require(_canonical(declared) == _canonical(entry), 'entry-drift')
    _require(declared['slot_count'] == program['slot_count'],
             'entry-slot-count-drift')
    return declared


def _entry_address(program, slot):
    _require(type(slot) is int and 0 <= slot < program['slot_count'], 'entry-slot')
    return program['slot_base'] + program['slot_bytes']*slot


@dataclass(frozen=True)
class F6Firmware:
    _program: str
    _csr: str
    _control_base: int
    _segments: tuple[tuple[int, bytes], ...]
    _irq_dispatch: str = 'null'
    _entry: str = 'null'
    _behavior: str = '{"irq_clear":{"method":"none"},"length_unit":"words"}'

    @property
    def entry(self):
        """The declared entry document, or None for the implicit first entry."""
        return json.loads(self._entry)

    def entry_document(self):
        """This rendering's entry, with the rule it satisfies stated explicitly."""
        p, entry = json.loads(self._program), self.entry
        slot = 0 if entry is None else entry['slot']
        return {'schema_version': ENTRY_SCHEMA_VERSION, 'policy': ENTRY_POLICY,
                'declared': entry is not None,
                'reset_epoch': 0 if entry is None else entry['reset_epoch'],
                'slot': slot, 'slot_count': p['slot_count'],
                'slot_base': p['slot_base'], 'slot_bytes': p['slot_bytes'],
                'boot_address': p['boot_address'],
                'entry_address': _entry_address(p, slot),
                'rule': 'boot_jal_target = slot_base + slot_bytes*slot'}

    @property
    def initial_images(self):
        return dict(self._segments)

    @property
    def initial_segment_manifest(self):
        return tuple(dict(address=a, length=len(data), sha256=sha256(data).hexdigest())
                     for a, data in self._segments)

    @property
    def manifest_sha256(self):
        return sha256(_canonical(self.initial_segment_manifest).encode()).hexdigest()

    @property
    def instruction_slots(self):
        p = json.loads(self._program)
        return tuple((p['slot_base']+i*p['slot_bytes'], p['online_prefix_bytes']//4)
                     for i in range(p['slot_count'])) + ((p['park_address'], 1),)

    def prefix(self, candidate, *, case_index):
        _require(type(candidate) is F6Candidate, 'candidate')
        # Recheck even frozen dataclass instances before encoding trusted bytes.
        F6Candidate(candidate.raw, candidate.words)
        p, csr = json.loads(self._program), json.loads(self._csr)
        behavior = json.loads(self._behavior)
        _require(type(case_index) is int and 0 <= case_index < p['slot_count'], 'slot-exhausted')
        code = (_load(1, self._control_base) + _load(2, p['source_address'])
                + _load(4, p['destination_address'])
                + _load(5, p['result_base']+case_index*p['result_stride'])
                + [_addi(10, 0, 0), _addi(11, 0, 1)])
        for i, value in enumerate(candidate.words):
            code += [_addi(3, 0, value), _sw(3, 2, i*4)]
        offsets = csr['offsets']
        code += [_sw(2, 1, offsets['source']), _sw(4, 1, offsets['destination']),
                 _addi(3, 0, csr['length_words'] * (4 if behavior['length_unit'] == 'bytes' else 1)),
                 _sw(3, 1, offsets['length'])]
        code += _load(3, csr['start_word'])
        declared_irq = p.get('declared_irq')
        if declared_irq is not None:
            phase = declared_irq.get('phase_address')
            _require(type(phase) is int and 0 <= phase <= 0xfffffffc and phase % 4 == 0,
                     'declared-IRQ-phase-address')
            code += _load(6, phase) + [_sw(0, 6, 0)]
        code += [_sw(3, 1, offsets['control'])]
        code += [0x13]*(32-len(code))
        data = _encode(code)
        _require(len(data) == p['online_prefix_bytes'], 'prefix-size')
        validate_instruction_bytes(data)
        return data

    def document(self):
        p = json.loads(self._program)
        isr = self.initial_images[p['isr_address']]
        sites = [p['isr_address']+offset for offset in range(0, len(isr), 4)
                 if isr[offset:offset+4] == bytes.fromhex('73002030')]
        document = dict(schema_version='compiled_F6_firmware.v1',
                    program_contract=p,
                    initial_segment_manifest=list(self.initial_segment_manifest),
                    manifest_sha256=self.manifest_sha256,
                    instruction_slots=[list(slot) for slot in self.instruction_slots],
                    isr=dict(address=p['isr_address'], length=len(isr),
                             sha256=sha256(isr).hexdigest(), mret_addresses=sites))
        if json.loads(self._program).get('custom_irq') is not None:
            document['isr']['return_abi']='picorv32_custom0'
            document['isr']['retirq_addresses']=[p['isr_address']+offset
                for offset in range(0,len(isr),4) if isr[offset:offset+4]==bytes.fromhex('0b000004')]
        dispatch=json.loads(self._irq_dispatch)
        if dispatch is not None:
            document['irq_dispatch']=dispatch
            document['isr']['mret_addresses']=dispatch['stages']['dma']['mret_addresses']
        if self.entry is not None:
            # Only a declared entry adds a key, so every pinned digest of the
            # implicit first rendering (``initial_image_sha256``, the sparse
            # program manifest, an existing build join) stays exactly valid.
            document['entry'] = self.entry_document()
        if 'storage_support' in p:
            from .f6_storage_support import storage_fragment
            island = p['slot_base']+(p['slot_count']-1)*256+128
            document['storage_support_sites'] = {
                'before': dict(address=p['boot_address']+32, segment_address=p['boot_address'],
                    size=len(storage_fragment(p['storage_support'], 'before'))),
                'after': dict(address=island+4, segment_address=island,
                    size=len(storage_fragment(p['storage_support'], 'after')))}
        return document

    def validate_prefix(self, data, candidate, *, case_index):
        """Require exact canonical bytes, including every fixed nonoperand bit."""
        _require(type(data) is bytes and data == self.prefix(candidate, case_index=case_index),
                 'prefix-drift')
        validate_instruction_bytes(data)


def build_f6_firmware(contract, *, entry=None) -> F6Firmware:
    _require(type(contract) is dict and type(contract.get('program_contract')) is dict,
             'contract')
    p = contract['program_contract']
    _validate_document_containers(p)
    keys = {'schema_version', 'boot_address', 'isr_address', 'park_address', 'slot_base',
            'slot_count', 'source_address', 'destination_address', 'result_base',
            'slot_bytes', 'online_prefix_bytes', 'result_stride', 'operand_instruction_offsets',
            'initial_image', 'initial_image_sha256', 'instruction_source_id'}
    _require(set(p) == keys | (set(p) & {'storage_support', 'shared_slots','gpio_irq','declared_irq','custom_irq'})
        and p['schema_version'] == 'compiled_F6_program.v1', 'program-fields')
    for key in ('boot_address', 'isr_address', 'park_address', 'slot_base',
                'source_address', 'destination_address', 'result_base'):
        _require(type(p[key]) is int and 0 <= p[key] <= 0xfffffffc and p[key] % 4 == 0, key)
    for key, expected in [('slot_bytes', 256), ('online_prefix_bytes', 128), ('result_stride', 24)]:
        _require(type(p[key]) is int and p[key] == expected, key)
    _require(type(p['slot_count']) is int and 1 <= p['slot_count'] <= 16, 'slot-count')
    custom_irq = p.get('custom_irq')
    if custom_irq is None:
        _require(p['isr_address'] % 256 == 44, 'isr-vector')
    else:
        _require(type(custom_irq) is dict and set(custom_irq) == {'abi','irq_bit','handler_address','retirq_encoding'}
            and custom_irq['abi']=='picorv32_custom0' and type(custom_irq['irq_bit']) is int
            and 3 <= custom_irq['irq_bit'] < 32 and custom_irq['handler_address']==16
            and custom_irq['retirq_encoding']==0x0400000b and p['boot_address']==0,
            'custom-IRQ-contract')
        _require('declared_irq' not in p, 'custom-IRQ-dispatch-not-integrated')
        if 'gpio_irq' in p:
            _require(type(p['gpio_irq']) is dict and type(p['gpio_irq'].get('irq_bit')) is int
                and 3<=p['gpio_irq']['irq_bit']<32 and p['gpio_irq']['irq_bit']!=custom_irq['irq_bit'],
                'custom-IRQ-gpio-vector')
    _require(_canonical(p['operand_instruction_offsets']) == '[40,48,56,64]', 'operand-offsets')
    _require(type(p['instruction_source_id']) is str and p['instruction_source_id'], 'instruction-source')
    control = contract.get('control'); dma = contract.get('dma')
    _require(type(control) is dict and type(control.get('base')) is int
             and 0 <= control['base'] <= 0xfffffff0 and control['base'] % 4 == 0, 'control-base')
    _require(type(dma) is dict and type(dma.get('csr')) is dict, 'dma-csr')
    csr = dma['csr']
    from .f6_dma_behavior import validate_f6_dma_behavior
    behavior = validate_f6_dma_behavior(dma.get('behavior'), control_size=control.get('size',16))
    _validate_document_containers(csr)
    expected = dict(configuration_order=['source', 'destination', 'length', 'control'],
        length_words=4, block_words=4,
        increment_source=True, increment_destination=True,
        master_address_units='word',
        master_byte_enable=15)
    variable = {'offsets', 'start_key', 'start_word', 'status_error_mask', 'source_destination_units'}
    _require(set(csr) == set(expected) | variable
        and all(type(csr[k]) is type(v) and csr[k] == v for k,v in expected.items()),
        'csr-semantics')
    _require(csr['source_destination_units'] in ('byte_address','byte_address_shift_right_2'),
             'csr-address-units')
    offsets = csr['offsets']
    window_size = control.get('size', 16)
    _require(type(window_size) is int and window_size >= 4
        and type(offsets) is dict and set(offsets) == {'control', 'length', 'source', 'destination'}
        and all(type(value) is int and value % 4 == 0 and 0 <= value <= 2044
                and value + 4 <= window_size for value in offsets.values())
        and len(set(offsets.values())) == 4, 'csr-offsets')
    _require(all(type(csr[name]) is int and 0 <= csr[name] <= 0xffffffff
        for name in ('start_key', 'start_word', 'status_error_mask'))
        and csr['status_error_mask'] != 0, 'csr-values')
    if 'source_contract' in dma:
        source = dma['source_contract']
        _require(type(source) is dict, 'csr-source-drift')
        if source.get('schema_version') is not None:
            from .f6_dma_behavior import f6_dma_semantics_from_source
            source_csr, source_behavior = f6_dma_semantics_from_source(source)
            _require(_canonical(source_csr) == _canonical(csr)
                and _canonical(source_behavior) == _canonical(behavior), 'csr-source-drift')
        else:
            _require(_canonical(source.get('csr')) == _canonical(csr), 'csr-source-drift')
    # mtvec = base | MODE.  CV32E40P honours MTVEC[1:0] and enters a direct-mode
    # trap at the base (m_exc_vec_pc_mux_id = 0); CVE2 and Ibex always vector for
    # IRQ.  Vectored mode therefore names the same fixed entry (base + 4*cause)
    # on all three adapters without changing the CVE2/Ibex base.
    declared_entry = _validated_entry(entry, p)
    entry_slot = 0 if declared_entry is None else declared_entry['slot']
    if custom_irq is None:
        boot = _load(7, (p['isr_address']-44) | 1) + [0x30539073]
        if 'declared_irq' in p:
            boot += _load(7,p['declared_irq']['scratch_address']) + [0x34039073, _addi(10,0,1), _addi(11,0,1)]
        elif 'gpio_irq' in p:
            from .shared_irq_dispatcher import gpio_boot_words
            boot += gpio_boot_words(p['gpio_irq'])
        boot += _load(7, 2048) + [0x3043a073, _addi(7, 0, 8), 0x3003a073]
        boot_address = p['boot_address']
    else:
        # Pico reset starts masked. Branch around the fixed IRQ vector at 0x10.
        boot_address = 0x40
        mask = (~((1 << custom_irq['irq_bit']) | (1 << p['gpio_irq']['irq_bit'] if 'gpio_irq' in p else 0))) & 0xffffffff
        if 'gpio_irq' in p:
            from .shared_irq_dispatcher import custom_gpio_boot_words
            boot = custom_gpio_boot_words(p['gpio_irq'])
        else:
            boot = []
        boot += _load(7, mask) + [3 << 25 | 7 << 15 | 6 << 12 | 0x0b]
    if 'storage_support' in p:
        from .f6_storage_support import storage_fragment
        support_code = storage_fragment(p['storage_support'], 'before')
        boot += [int.from_bytes(support_code[i:i+4], 'little') for i in range(0, len(support_code), 4)]
    # The whole entry rule is this one jump target; nothing else in the image moves.
    boot += [_jal(_entry_address(p, entry_slot)-(boot_address+4*len(boot)))]
    # Only scratch registers x6..x8 and completion register x10 are modified.
    isr = [_lw(7, 1, csr['offsets']['control']), _sw(7, 5, 0)]
    clear = behavior['irq_clear']
    if clear['method'] == 'write':
        isr += _load(6, clear['value']) + [_sw(6, 1, clear['offset'])]
    isr += _load(6, csr['status_error_mask'])
    isr += [7 << 20 | 6 << 15 | 7 << 12 | 6 << 7 | 0x33, 0]
    branch = len(isr)-1
    for i in range(4):
        isr += [_lw(8, 4, 4*i), _sw(8, 5, 4+4*i)]
    if custom_irq is None:
        isr += _wait_for_external_irq_low()
    return_word = 0x30200073 if custom_irq is None else custom_irq['retirq_encoding']
    isr += [_addi(10, 0, 1), _sw(10, 5, 20), return_word]
    error = len(isr)
    isr += [_addi(10, 0, 2)]
    if custom_irq is None:
        isr += _wait_for_external_irq_low()
    isr += [_sw(10, 5, 20), return_word]
    isr[branch] = _bne(6, 0, (error-branch)*4)
    # The final park fetch must remain pending, just like a next-case prefix.
    # Reserving its word without supplying bytes gives the runtime a terminal
    # boundary instead of automatically servicing an endless park self-loop.
    dispatch=None;isr_bytes=_encode(isr)
    if 'declared_irq' in p:
        from .shared_irq_dispatcher import build_declared_phase_irq_firmware
        shared=build_declared_phase_irq_firmware(entry_address=p['isr_address'],dma_isr_bytes=isr_bytes,declaration=p['declared_irq'])
        isr_bytes=shared['data'];dispatch=shared['document']
    elif 'gpio_irq' in p:
        if custom_irq is None:
            from .shared_irq_dispatcher import build_common_irq_firmware
            shared=build_common_irq_firmware(entry_address=p['isr_address'],dma_isr_bytes=isr_bytes,declaration=p['gpio_irq'])
        else:
            from .shared_irq_dispatcher import build_custom_gpio_irq_firmware
            shared=build_custom_gpio_irq_firmware(entry_address=p['isr_address'],dma_isr_bytes=isr_bytes,
                declaration=p['gpio_irq'],dma_irq_bit=custom_irq['irq_bit'])
        isr_bytes=shared['data'];dispatch=shared['document']
    if custom_irq is None:
        segments = [(p['boot_address'], _encode(boot)), (p['isr_address'], isr_bytes)]
    else:
        segments = [(0, _encode([_jal(boot_address)])),
                    (custom_irq['handler_address'], _encode([_jal(p['isr_address']-custom_irq['handler_address'])])),
                    (boot_address, _encode(boot)), (p['isr_address'], isr_bytes)]
    fixed_segments = tuple(segments)
    for i in range(p['slot_count']):
        island = p['slot_base']+i*256+128
        target = p['slot_base']+(i+1)*256 if i+1 < p['slot_count'] else p['park_address']
        island_words = [_bne(10, 11, 0)]
        if i == p['slot_count']-1 and 'storage_support' in p:
            support_code = storage_fragment(p['storage_support'], 'after')
            island_words += [int.from_bytes(support_code[j:j+4], 'little') for j in range(0, len(support_code), 4)]
        island_words += [_jal(target-island-4*len(island_words))]
        segments.append((island, _encode(island_words)))
    # Reserve the entire slot arena, not only the materialized 8-byte islands.
    spans = [(p['slot_base'], 256*p['slot_count']),
             (p['source_address'], 16), (p['destination_address'], 16),
             (p['result_base'], 24*p['slot_count']), (control['base'], window_size)]
    spans += [(address, len(data)) for address, data in fixed_segments]
    spans.append((p['park_address'], 4))
    for i, (address, length) in enumerate(spans):
        _require(address+length <= 1 << 32, 'address-span')
        _require(not any(address < other+size and other < address+length
                         for other, size in spans[:i]), 'overlap')
    if 'gpio_irq' in p:
        extra=[(p['gpio_irq']['scratch_address'],16),(p['gpio_irq']['result_address'],12)]
        for a,n in extra:
            _require(not any(a<b+size and b<a+n for b,size in spans),'gpio-data-overlap')
            spans.append((a,n))
    fw = F6Firmware(_canonical(p), _canonical(csr), control['base'], tuple(sorted(segments)),_canonical(dispatch),_canonical(declared_entry),_canonical(behavior))
    if p['initial_image'] != [] or p['initial_image_sha256'] is not None:
        _require(_canonical(p['initial_image']) == _canonical(fw.initial_segment_manifest)
                 and p['initial_image_sha256'] == fw.manifest_sha256, 'initial-image-drift')
    return fw


def render_epoch_program(contract, *, reset_epoch, slot):
    """Render one reset epoch's program together with its own declared image pin.

    The returned contract is the same contract with ``initial_image`` /
    ``initial_image_sha256`` re-derived from *this* rendering, so the pin keeps
    refusing drift instead of refusing the epoch: a caller may not hand-write a
    post-reset image, and a per-epoch image may not be silently substituted for
    the pinned one.
    """
    _require(type(contract) is dict and type(contract.get('program_contract')) is dict,
             'contract')
    program_contract = contract['program_contract']
    _require(type(program_contract.get('slot_count')) is int, 'slot-count')
    entry = declare_program_entry(reset_epoch=reset_epoch, slot=slot,
                                  slot_count=program_contract['slot_count'])
    unpinned = deepcopy(contract)
    unpinned['program_contract']['initial_image'] = []
    unpinned['program_contract']['initial_image_sha256'] = None
    program = build_f6_firmware(unpinned, entry=entry)
    pinned = deepcopy(contract)
    pinned['program_contract']['initial_image'] = list(program.initial_segment_manifest)
    pinned['program_contract']['initial_image_sha256'] = program.manifest_sha256
    verified = build_f6_firmware(pinned, entry=entry)
    _require(verified.manifest_sha256 == program.manifest_sha256, 'epoch-pin')
    return {'schema_version': 'compiled_F6_epoch_program.v1',
            'entry': program.entry_document(), 'program': program,
            'contract': pinned}
