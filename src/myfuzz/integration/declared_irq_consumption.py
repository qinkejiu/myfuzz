"""Declared-IRQ F5 consumption: fixed RV32 firmware, admission, layered observation.

The three evidence layers stay separate and explicit:

``transport``
    One actual target native output sample (real signal *and* bit), the host OR
    group frame that names it, the unique-vs-ambiguous attribution, the parsed
    CPU input pre/post and the native take with its real decision probe (plus a
    non-zero decision token only when the CPU contract provides one).

``consumption``
    The actual ISR read of every declared status register joined to the target's
    own native pre/post sample and to the CPU's native OBI beat, the dependent
    RAM writes carrying the real values, the real retirement of the load/store
    instructions that performed them, MRET and its real successor.

``unknown``
    Internal IP cause/version, case origin and cross-case writer attribution stay
    unknown.  ``reward_eligible``/``grants_F5``/``grants_F6`` are always false.

A successful IRQ delivery or a CPU take is **not** consumption.  Only the joined
ISR read of the declared target register with its real value plus a real
dependent RAM write raises ``irq_consumption`` to ``verified``, and even then the
document claims nothing about an IP-internal cause unless the actual status read
proves a declared pending bit (``cause_source='read_status_bit'``).

Every joined value here comes from actual events/beats/receipts.  Nothing is
taken from the scenario configuration.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from .rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _lw, _sw

MRET_WORD = 0x30200073
CSR_MTVEC = 0x305
CSR_MSCRATCH = 0x340
CSR_MIE = 0x304
CSR_MSTATUS = 0x300
MACHINE_EXTERNAL_BIT = 1 << 11
MSTATUS_MIE = 8
MAX_STATUS_OFFSETS = 16
DECLARED_WINDOW = 0x1000

#: Roles a declared register window may present in its native protocol trace.
_ADDRESS_ROLES = ('paddr', 'haddr', 'adr', 'addr')
_DATA_OUT_ROLES = ('prdata', 'hrdata', 'dat_r')
_DATA_IN_ROLES = ('pwdata', 'hwdata', 'dat_w')
_PROTOCOLS = {'apb3': 'apb3', 'apb': 'apb3', 'apb-3': 'apb3',
              'wishbone': 'wishbone', 'ahb-lite': 'ahb-lite', 'ahb': 'ahb-lite'}

#: Import-time probe for the real pc/insn/order-only retirement path.  A
#: field-light CPU (pc/insn/order only) is admitted only when the limited branch
#: that already natively verified CV32E40P F5/F6 is importable in full: the
#: public dispatcher, the limited observation, the helpers it uses, and the
#: shared successor validator it delegates to.  Nothing is re-implemented here
#: and no entry point is invented; a missing helper yields the precise
#: ``unsupported`` admission instead of a faked value-level retirement join.
_RETIREMENT_ONLY_MODULE = 'myfuzz.integration.shared_irq_firmware'
_RETIREMENT_ONLY_ENTRY_POINTS = (
    ('dispatcher', 'observe_irq_isr'),
    ('entry_point', '_observe_limited_irq_isr'),
    ('take_scope', '_limited_take_scope'),
    ('retirement_window', '_limited_retirement_window'),
    ('data_join', '_join_limited_memory_operations'),
    ('fixed_isr_path', 'fixed_isr_path'),
    ('redirect_rows', '_redirect_rows'),
    ('unobserved_fields', '_unobserved_fields'),
    ('reject_unobserved_fields', '_reject_unobserved_fields'),
)
_RETIREMENT_ONLY_SUCCESSOR_MODULE = 'myfuzz.scenario.irq_return_successor'
_RETIREMENT_ONLY_SUCCESSOR_ENTRY_POINT = 'validate_return_successor'
#: The limited branch's own join label; reused, not reworded, so the declared-F5
#: document and the natively verified shared certificate describe one mechanism.
_RETIREMENT_ONLY_JOIN_SCOPE = 'ordered_retirement_to_actual_data_transaction'
_RETIREMENT_ONLY_SCOPE = 'first_retirement_after_native_take'
_RETIREMENT_ONLY_JOINS = 'by_documented_order'
_RETIREMENT_FIELD_NAMES = ('mem_addr', 'mem_rmask', 'mem_rdata', 'mem_wmask', 'mem_wdata')


def _require(condition, reason):
    if not condition:
        raise ValueError('declared-F5-' + reason)


def _uint(value, bits=32):
    return type(value) is int and 0 <= value < 1 << bits


def _encode(words):
    return b''.join(word.to_bytes(4, 'little') for word in words)


def _decode(code):
    return {offset: int.from_bytes(code[offset:offset + 4], 'little')
            for offset in range(0, len(code) - 3, 4)}


def _csr(address, source, operation=1, destination=0):
    """Encode one Zicsr instruction; identical to the fixed smoke convention."""
    _require(_uint(address, 12) and address < DECLARED_WINDOW and _uint(source, 5)
             and operation in (1, 2, 3, 5, 6, 7) and _uint(destination, 5)
             and destination < 32, 'CSR-encoding-operands')
    return address << 20 | source << 15 | operation << 12 | destination << 7 | 0x73


def _digest(document):
    return sha256(json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Fixed firmware
# ---------------------------------------------------------------------------
def build_declared_irq_firmware(*, image_start, image_end, first_fetch, target_base,
                                status_offsets, result_address, register_count=32,
                                clear_writes=(), irq_abi=None, irq_bit=None, extra_irq_bits=()):
    """Build the fixed bootstrap/vector/ISR images for one declared target.

    The bootstrap enables the declared machine-external line (``mie`` bit 11),
    installs ``mtvec``/``mscratch`` and finally ``mstatus.MIE`` before entering
    the case image at ``dynamic_start``.  The handler reads every declared
    status register, writes each read value to its RAM result word, performs the
    declared clear/ack writes with the value just read (only for offsets the
    caller already admitted against the target's declared register map) and
    returns with MRET.

    ``memory_operations`` documents the declared load/store order and
    ``retirement_path`` the exact ``(pc, word)`` handler sequence so a
    field-light CPU can be joined by documented order.
    """
    numbers = (image_start, image_end, first_fetch, target_base, result_address)
    _require(all(type(value) is int for value in numbers), 'firmware-layout-types')
    _require(type(register_count) is int and register_count in (16, 32), 'register-bank-unsupported')
    _require(image_start % 4096 == 0 and image_end % 4 == 0 and image_end > image_start + 0x1100,
             'firmware-image-window')
    _require(image_start <= first_fetch < image_start + 0x180 and first_fetch % 4 == 0,
             'firmware-first-fetch')
    _require(target_base % 4096 == 0 and 0 <= target_base <= 0xffffffff - DECLARED_WINDOW,
             'firmware-target-base')
    _require(isinstance(status_offsets, (tuple, list)) and 1 <= len(status_offsets) <= MAX_STATUS_OFFSETS,
             'firmware-status-count')
    status_offsets = tuple(status_offsets)
    _require(len(set(status_offsets)) == len(status_offsets), 'firmware-status-duplicate')
    _require(all(type(offset) is int and offset % 4 == 0 and 0 <= offset <= DECLARED_WINDOW - 4
                 for offset in status_offsets), 'firmware-status-offset')
    scratch_register = register_count - 1
    _require(scratch_register >= 5, 'firmware-scratch-register')
    _require(isinstance(clear_writes, (tuple, list)), 'firmware-clear-writes-shape')
    clear_writes = tuple((row[0], row[1]) if isinstance(row, (tuple, list)) and len(row) == 2 else (None, None)
                         for row in clear_writes)
    _require(all(type(offset) is int and offset % 4 == 0 and 0 <= offset <= DECLARED_WINDOW - 4
                 and type(index) is int and 0 <= index < len(status_offsets)
                 for offset, index in clear_writes), 'firmware-clear-write-declaration')
    _require(len({offset for offset, _ in clear_writes}) == len(clear_writes), 'firmware-clear-write-duplicate')
    custom = irq_abi is not None
    if custom:
        _require(type(irq_abi) is dict and irq_abi.get('abi') == 'picorv32_custom0'
                 and irq_abi.get('schema_version') == 'custom_irq_abi.v1'
                 and irq_abi.get('retirement') == 'unknown'
                 and irq_abi.get('machine_external_take') == 'unsupported', 'custom-IRQ-ABI')
        _require(register_count == 32, 'custom-IRQ-register-bank')
        _require(type(irq_bit) is int and 3 <= irq_bit < 32, 'custom-IRQ-line')
        _require(type(extra_irq_bits) is tuple and all(type(bit) is int and 3 <= bit < 32
                 for bit in extra_irq_bits) and len(set((irq_bit,*extra_irq_bits))) == 1 + len(extra_irq_bits),
                 'custom-IRQ-lines')
        _require(first_fetch == image_start and image_start == 0
                 and irq_abi.get('handler_address') == 16
                 and irq_abi.get('retirq_encoding') == 0x0400000b, 'custom-IRQ-layout')
    else:
        _require(irq_bit is None and extra_irq_bits == (), 'IRQ-line-without-custom-ABI')
    vector = irq_abi['handler_address'] if custom else image_start + 0x200
    handler = image_start + 0x400
    scratch = image_start + 0xc00
    dynamic_start = image_start + 0x1000
    _require(result_address >= image_start and result_address % 4 == 0
             and result_address + 4 * len(status_offsets) <= dynamic_start,
             'firmware-result-window')
    _require(not (result_address < scratch + 16 and scratch < result_address + 4 * len(status_offsets)),
             'firmware-result-overlaps-scratch')

    # Preserve the four working registers and the scratch pointer.  The
    # interrupted fixed stream is a self-loop, but the save keeps this handler
    # safe for any fixed caller.
    swap = _csr(CSR_MSCRATCH, scratch_register, 1, scratch_register)
    if custom:
        # q2 is ABI scratch: save the interrupted scratch register there before
        # loading its RAM save area. q0/q1 remain owned by the CPU IRQ entry.
        setq = 1 << 25 | scratch_register << 15 | 2 << 12 | 2 << 7 | 0x0b
        words = [setq, *_lui_addi_load(scratch_register, scratch)]
    else:
        words = [swap]
    words += [_sw(1, scratch_register, 0), _sw(2, scratch_register, 4),
              _sw(3, scratch_register, 8), _sw(4, scratch_register, 12)]
    words.extend(_lui_addi_load(1, target_base))
    words.extend(_lui_addi_load(3, result_address))
    # Declared load/store order: per status register one read then its dependent
    # RAM result write, followed by that register's declared clear/ack writes.
    operations = []

    def record(**row):
        row['index'] = len(operations)
        operations.append(row)

    for index, offset in enumerate(status_offsets):
        # The recorded PC is always the retiring load/store itself; a large
        # offset only adds the two address-materialization words before it.
        if offset < 2048:
            access_pc = handler + 4 * len(words)
            words.append(_lw(2, 1, offset))
        else:
            words.extend(_lui_addi_load(4, target_base + offset))
            access_pc = handler + 4 * len(words)
            words.append(_lw(2, 4, 0))
        record(kind='read', pc=access_pc, offset=offset, address=target_base + offset, width=4,
               target_register_index=index)
        store_pc = handler + 4 * len(words)
        words.append(_sw(2, 3, 4 * index))
        record(kind='write', pc=store_pc, address=result_address + 4 * index, width=4,
               result_index=index, value_source='read_value[%d]' % index)
        for ack_offset, source_index in clear_writes:
            if source_index != index:
                continue
            if ack_offset < 2048:
                ack_pc = handler + 4 * len(words)
                words.append(_sw(2, 1, ack_offset))
            else:
                words.extend(_lui_addi_load(4, target_base + ack_offset))
                ack_pc = handler + 4 * len(words)
                words.append(_sw(2, 4, 0))
            record(kind='write', pc=ack_pc, offset=ack_offset, address=target_base + ack_offset,
                   width=4, value_source='read_value[%d]' % source_index,
                   role='declared_clear_or_ack')
    words.extend([_lw(1, scratch_register, 0), _lw(2, scratch_register, 4),
                  _lw(3, scratch_register, 8), _lw(4, scratch_register, 12)])
    if custom:
        getq = 2 << 15 | 4 << 12 | scratch_register << 7 | 0x0b
        words.extend([getq, irq_abi['retirq_encoding']])
    else:
        words.extend([swap, MRET_WORD])
    retirement_path = [[handler + 4 * position, word] for position, word in enumerate(words)]
    code = _encode(words)
    _require(len(code) % 4 == 0 and len(code) < 0x400, 'firmware-handler-size')

    vector_word = _jal(vector, handler)
    bootstrap = [*_lui_addi_load(3, vector | 1), _csr(CSR_MTVEC, 3, 1),
                 *_lui_addi_load(3, scratch), _csr(CSR_MSCRATCH, 3, 1),
                 *_lui_addi_load(3, MACHINE_EXTERNAL_BIT), _csr(CSR_MIE, 3, 2),
                 _addi(3, 0, MSTATUS_MIE), _csr(CSR_MSTATUS, 3, 2)]
    bootstrap.append(_jal(first_fetch + 4 * len(bootstrap), dynamic_start))
    segments = [
        dict(name='vector_direct', address=vector, data_hex=_encode([vector_word]).hex()),
        dict(name='vector_external', address=vector + 11 * 4, data_hex=_encode([_jal(vector + 11 * 4, handler)]).hex()),
        dict(name='handler', address=handler, data_hex=code.hex()),
        dict(name='bootstrap', address=first_fetch, data_hex=_encode(bootstrap).hex()),
    ]
    if custom:
        # Reset vector and IRQ vector overlap a linear bootstrap; branch around
        # the fixed 0x10 IRQ vector and initialize only Pico's maskirq register.
        boot_address = image_start + 0x40
        enabled_mask = sum(1 << bit for bit in (irq_bit,*extra_irq_bits))
        bootstrap = [*_lui_addi_load(3, (~enabled_mask) & 0xffffffff),
                     3 << 25 | 3 << 15 | 6 << 12 | 0x0b]
        bootstrap.append(_jal(boot_address + 4 * len(bootstrap), dynamic_start))
        segments = [dict(name='reset_trampoline', address=first_fetch,
                         data_hex=_encode([_jal(first_fetch, boot_address)]).hex()),
                    dict(name='vector_custom', address=vector, data_hex=_encode([vector_word]).hex()),
                    dict(name='handler', address=handler, data_hex=code.hex()),
                    dict(name='bootstrap', address=boot_address, data_hex=_encode(bootstrap).hex())]
    intervals = [(row['address'], row['address'] + len(bytes.fromhex(row['data_hex']))) for row in segments]
    intervals.extend([(scratch, scratch + 16),
                      (result_address, result_address + 4 * len(status_offsets))])
    _require(all(image_start <= start < stop <= image_start + 0x1100 for start, stop in intervals),
             'firmware-images-outside-window')
    _require(all(not (left_start < right_stop and right_start < left_stop)
                 for position, (left_start, left_stop) in enumerate(intervals)
                 for right_start, right_stop in intervals[position + 1:]),
             'firmware-images-overlap')
    document = dict(
        schema_version='declared_irq_f5_firmware.v1',
        image_start=image_start, image_end=image_end, first_fetch=first_fetch,
        vector=vector, vector_external=vector + 11 * 4, handler=handler, scratch=scratch,
        dynamic_start=dynamic_start, target_base=target_base,
        status_offsets=list(status_offsets), clear_writes=[list(row) for row in clear_writes],
        result_address=result_address, result_words=len(status_offsets),
        register_count=register_count, scratch_register=scratch_register,
        mret_pc=handler + 4 * (len(words) - 1), mret_word=MRET_WORD,
        entry_pcs=[vector, vector + 11 * 4, handler],
        image_words=dict(vector=vector_word, vector_external=retirement_path[0][1]),
        segments=segments, memory_operations=operations, retirement_path=retirement_path,
        handler_words=len(words), cause_bits={},
        clear_write_role='write_value_read_from_declared_status_register',
        scope='fixed_RV32I_declared_target_ISR_images')
    if custom:
        document.pop('mret_pc')
        document.pop('mret_word')
        document.update(irq_abi='picorv32_custom0', irq_bit=irq_bit,
            return_pc=handler + 4 * (len(words) - 1), return_word=irq_abi['retirq_encoding'],
            entry_pcs=[vector, handler], retirement_authority='unknown',
            source_attribution='unknown', q_register_clobbers=['q2'],
            scope='fixed_RV32I_custom_IRQ_declared_target_ISR_images')
        if extra_irq_bits:
            document['irq_bits'] = [irq_bit,*extra_irq_bits]
        document.pop('vector_external')
        document['image_words'] = dict(vector=vector_word)
    document['digest'] = _digest(document)
    return document


def build_profile_custom_irq_firmware(artifact, *, base_dir, irq_bit,
                                      dispatcher_address=None, extra_irq_routes=(), **arguments):
    """Bind shared target operations to a verified CPU profile ABI.

    An optional q1 dispatcher is shared with multi-source firmware. Generated
    bytes and a source-backed description are not execution evidence.
    """
    from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
    abi = verify_custom_irq_artifact(artifact, base_dir=base_dir)
    _require(type(extra_irq_routes) is tuple and all(type(row) is tuple and len(row)==2
             for row in extra_irq_routes), 'custom-IRQ-extra-routes')
    _require(not extra_irq_routes or dispatcher_address is not None, 'custom-IRQ-dispatcher-required')
    firmware = build_declared_irq_firmware(**arguments, irq_abi=abi, irq_bit=irq_bit,
                                           extra_irq_bits=tuple(row[0] for row in extra_irq_routes))
    if dispatcher_address is not None:
        from .shared_irq_dispatcher import build_custom_irq_dispatcher
        dispatcher = build_custom_irq_dispatcher(address=dispatcher_address,
            routes=((irq_bit, firmware['handler']),*extra_irq_routes), return_word=abi['retirq_encoding'])
        end = dispatcher_address + len(bytes.fromhex(dispatcher['data_hex']))
        occupied = [(s['address'], s['address'] + len(bytes.fromhex(s['data_hex'])))
                    for s in firmware['segments']]
        occupied += [(firmware['scratch'],firmware['scratch']+16),
                     (firmware['result_address'],firmware['result_address']+4*firmware['result_words'])]
        _require(firmware['image_start'] <= dispatcher_address < end <= firmware['dynamic_start']
                 and not any(dispatcher_address < b and a < end for a,b in occupied),
                 'custom-IRQ-dispatcher-overlap')
        vector = next(s for s in firmware['segments'] if s['name']=='vector_custom')
        vector_word = _jal(vector['address'],dispatcher_address)
        vector['data_hex'] = _encode([vector_word]).hex()
        firmware['image_words']['vector'] = vector_word
        firmware['segments'].append(dict(name='custom_dispatcher',address=dispatcher_address,
                                         data_hex=dispatcher['data_hex']))
        firmware['custom_dispatcher'] = dispatcher
        firmware['entry_pcs'] = [firmware['vector'], dispatcher_address, firmware['handler']]
        firmware.pop('digest')
        firmware['digest'] = _digest(firmware)
    return firmware


def firmware_code(document):
    """Decode every fixed image to its absolute ``pc -> word`` map."""
    code = {}
    for segment in document['segments']:
        for offset, word in _decode(bytes.fromhex(segment['data_hex'])).items():
            address = segment['address'] + offset
            _require(address not in code or code[address] == word, 'firmware-image-conflict')
            code[address] = word
    return code


# ---------------------------------------------------------------------------
# Admission against the declared register map and the CPU IRQ contract
# ---------------------------------------------------------------------------
def _repo_root():
    return Path(__file__).resolve().parents[3]


def _profile(value, root):
    from myfuzz.composition.component_profile import load_component_profile
    if type(value) in (str, Path):
        path = Path(value)
        return load_component_profile(path if path.is_absolute() else root / path)
    if value is None:
        raise ValueError('declared-F5-admission-profile-required')
    return value


def _request_profile_path(config, root):
    request = config.get('source_request') or config.get('timer_request')
    _require(type(request) in (str, Path), 'admission-source-request-required')
    path = Path(request)
    document = json.loads((path if path.is_absolute() else root / path).read_text())
    _require(type(document.get('profile_path')) is str, 'admission-request-profile')
    return document['profile_path']


def _retirement_authority(profile, root):
    """Read the CPU contract's own declared retirement authority.

    The registered native IRQ receipt contracts of full-RVFI CPUs carry no
    ``retirement_authority`` key (their complete parsed retirement receipt is
    implied); the pc/insn/order-only monitor declares
    ``retirement_authority='pc_insn_order_only'`` explicitly.  Unregistered CPUs
    have no admission at all.
    """
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract_for_profile
    try:
        contract = native_irq_receipt_contract_for_profile(profile)
    except ValueError:
        return None, None
    _require(isinstance(contract, dict), 'admission-CPU-contract-shape')
    authority = contract.get('retirement_authority', 'full_rvfi_retirement_receipt')
    if authority not in ('full_rvfi_retirement_receipt', 'pc_insn_order_only'):
        return None, contract
    return authority, contract


def retirement_only_provider():
    """Resolve the real pc/insn/order-only retirement path by import.

    Every name below is a function ``shared_irq_firmware`` actually defines and
    that its own hard-failing CV32E40P F5/F6 chain exercises.  The probe never
    guesses: if any of them (or the shared successor validator) is missing the
    caller gets ``None``, which admission reports as ``unsupported``.
    """
    import importlib
    try:
        module = importlib.import_module(_RETIREMENT_ONLY_MODULE)
        successor = importlib.import_module(_RETIREMENT_ONLY_SUCCESSOR_MODULE)
    except ImportError:  # pragma: no cover - both modules ship in this tree
        return None
    if not all(callable(getattr(module, name, None))
               for _, name in _RETIREMENT_ONLY_ENTRY_POINTS):
        return None
    if not callable(getattr(successor, _RETIREMENT_ONLY_SUCCESSOR_ENTRY_POINT, None)):
        return None
    document = dict(provider='shared_irq_firmware_limited_retirement_path',
                    module=_RETIREMENT_ONLY_MODULE,
                    successor_module=_RETIREMENT_ONLY_SUCCESSOR_MODULE,
                    successor_entry_point=_RETIREMENT_ONLY_SUCCESSOR_ENTRY_POINT,
                    retirement_authority='pc_insn_order_only',
                    join_scope=_RETIREMENT_ONLY_JOIN_SCOPE)
    document.update({role: name for role, name in _RETIREMENT_ONLY_ENTRY_POINTS})
    return document


def _limited_helpers():
    """Import the real limited-retirement helpers, or refuse precisely."""
    provider = retirement_only_provider()
    if provider is None:
        raise ValueError('declared-F5-pc-insn-order-only-retirement-work-unavailable')
    import importlib
    module = importlib.import_module(provider['module'])
    return dict(
        provider=provider,
        retirement_window=getattr(module, provider['retirement_window']),
        fixed_isr_path=getattr(module, provider['fixed_isr_path']),
        redirect_rows=getattr(module, provider['redirect_rows']),
        unobserved_fields=getattr(module, provider['unobserved_fields']),
        reject_unobserved_fields=getattr(module, provider['reject_unobserved_fields']))


def _admit_limited_cpu(contract):
    """Validate the registered contract of a pc/insn/order-only CPU.

    The declared fields must be the four the limited monitor really drives, the
    contract must declare what stays unobserved, none of those unobserved names
    may also be declared observed, and the real pre-edge entry-PC acceptance
    probe must exist (the documented entry is pinned by it, never guessed).
    """
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_acceptance
    from myfuzz.scenario.irq_return_successor import (
        PC_INSN_ORDER_ONLY_AUTHORITY, retirement_authority)
    _require(retirement_authority(contract) == PC_INSN_ORDER_ONLY_AUTHORITY,
             'admission-limited-CPU-authority')
    helpers = _limited_helpers()
    unobserved = helpers['unobserved_fields'](contract)
    fields = list(contract.get('retirement_fields') or ())
    _require(set(('valid', 'order', 'insn', 'pc_rdata')) <= set(fields),
             'admission-limited-CPU-retirement-fields')
    _require(not set(unobserved) & set(fields), 'admission-limited-CPU-fabricated-field')
    _require(native_irq_acceptance(contract) is not None,
             'admission-limited-CPU-entry-PC-probe')
    return unobserved


def declared_register_map(profile):
    """The target's own declared register map, never an invented offset list."""
    address = getattr(profile, 'address', None)
    _require(address is not None and address.registers, 'admission-register-map-required')
    rows = {}
    for register in address.registers:
        _require(register.offset not in rows, 'admission-duplicate-declared-offset')
        rows[register.offset] = dict(offset=register.offset, name=register.name,
                                     width=register.width, access=register.access,
                                     side_effect=getattr(register, 'side_effect', None))
    return rows, address.window_size


def _resolve_admission_input(value, root):
    if isinstance(value, dict):
        cpu = _profile(value.get('cpu_profile'), root)
        target = _profile(value.get('target_profile') or _request_profile_path(value, root), root)
        offsets = value.get('status_offsets')
        clear = value.get('clear_writes', ())
        result = value.get('result_address')
        digest = value.get('target_profile') or _request_profile_path(value, root)
        return dict(cpu=cpu, target=target, status_offsets=offsets, clear_writes=clear,
                    result_address=result, source=dict(kind='configuration', target_profile=str(digest)))
    artifacts = getattr(value, 'artifacts', None)
    if isinstance(artifacts, dict):
        cpu_id, target_id = getattr(value, 'cpu_id', None), getattr(value, 'target_id', None)
        _require(cpu_id in artifacts and target_id in artifacts, 'admission-runtime-artifacts')
        firmware = getattr(value, 'irq_firmware', None)
        _require(isinstance(firmware, dict), 'admission-runtime-firmware')
        return dict(cpu=artifacts[cpu_id].plan.profile, target=artifacts[target_id].plan.profile,
                    status_offsets=firmware.get('status_offsets'),
                    clear_writes=firmware.get('clear_writes', ()),
                    result_address=firmware.get('result_address'),
                    source=dict(kind='runtime', cpu_id=cpu_id, target_id=target_id))
    raise ValueError('declared-F5-admission-input-unsupported')


def admit_declared_irq_consumption(runtime_or_config, *, base_dir=None, cpu_contract=None):
    """Resolve the declared register map and the CPU IRQ contract for F5.

    Returns ``status='admitted'`` with the exact resolved join rules, or a
    precise ``status='unsupported'`` for a pc/insn/order-only CPU whose real
    limited retirement path is not importable.  A caller holding the realized
    artifact may pass its own ``cpu_contract``: it must be the registered
    contract of this profile and the ones the observation will use.  Malformed
    or invented declarations (undeclared offsets, unreadable status registers,
    a limited contract that also claims an unobserved field) raise
    ``ValueError``.
    """
    root = Path(base_dir or _repo_root()).resolve()
    resolved = _resolve_admission_input(runtime_or_config, root)
    target_profile, cpu_profile = resolved['target'], resolved['cpu']
    registers, window = declared_register_map(target_profile)
    offsets = resolved['status_offsets']
    _require(isinstance(offsets, (tuple, list)) and 1 <= len(offsets) <= MAX_STATUS_OFFSETS
             and all(type(offset) is int for offset in offsets)
             and len(set(offsets)) == len(offsets), 'admission-status-offsets')
    status_rows = []
    for offset in offsets:
        register = registers.get(offset)
        _require(register is not None, 'admission-status-offset-undeclared')
        _require(register['width'] == 32 and register['access'] in ('ro', 'rw'),
                 'admission-status-register-unreadable')
        _require(offset + 4 <= window, 'admission-status-outside-window')
        status_rows.append(dict(register, role='status',
                                read_side_effect=register['side_effect']))
    clear_rows = []
    for row in resolved['clear_writes'] or ():
        _require(isinstance(row, (tuple, list)) and len(row) == 2, 'admission-clear-write-shape')
        offset, index = row
        register = registers.get(offset)
        _require(register is not None, 'admission-clear-offset-undeclared')
        _require(register['access'] in ('wo', 'rw'), 'admission-clear-register-unwritable')
        _require(type(index) is int and 0 <= index < len(offsets), 'admission-clear-value-source')
        clear_rows.append(dict(register, role='clear_or_ack', value_source='read_value[%d]' % index,
                               declared_clear=bool(register['side_effect']) and
                               any(token in str(register['side_effect']) for token in ('clear', 'rearm', 'ack'))))
    if resolved['result_address'] is not None:
        _require(_uint(resolved['result_address']) and resolved['result_address'] % 4 == 0,
                 'admission-result-address')
    endpoints = [endpoint for endpoint in target_profile.endpoints
                 if getattr(endpoint, 'function', None) == 'mmio_slave']
    _require(len(endpoints) == 1, 'admission-single-declared-slave')
    protocol = _PROTOCOLS.get(str(endpoints[0].protocol[0]).lower())
    _require(protocol is not None, 'admission-target-protocol-unsupported')
    authority, contract = _retirement_authority(cpu_profile, root)
    if cpu_contract is not None:
        # The realized artifact must carry exactly the contract admitted here.
        from myfuzz.local_harness.native_irq_receipt_contract import (
            validate_native_irq_receipt_contract)
        validate_native_irq_receipt_contract(cpu_contract)
        _require(contract is not None and _digest(cpu_contract) == _digest(contract),
                 'admission-CPU-contract-mismatch')
    provider = retirement_only_provider() if authority == 'pc_insn_order_only' else None
    unobserved = (list(contract.get('unobserved_retirement_fields') or ())
                  if contract is not None else [])
    if authority == 'pc_insn_order_only' and provider is not None:
        unobserved = _admit_limited_cpu(contract)
    document = dict(
        schema_version='declared_irq_f5_admission.v1',
        status='admitted', reason=None,
        source=resolved['source'],
        target=dict(component_id=target_profile.component_id, window_size=window,
                    protocol=protocol, endpoint_id=endpoints[0].endpoint_id,
                    profile_fingerprint=target_profile.profile_fingerprint,
                    status_registers=status_rows, clear_registers=clear_rows,
                    register_map_sha256=_digest(sorted(registers.values(), key=lambda row: row['offset']))),
        cpu=dict(component_id=cpu_profile.component_id, retirement_authority=authority,
                 observation_contract=deepcopy(contract) if contract is not None else None,
                 retirement_fields=(list(contract.get('retirement_fields') or ())
                                    if contract is not None else []),
                 unobserved_retirement_fields=(unobserved if contract is not None else []),
                 retirement_only_provider=provider,
                 retirement_joins=('exact_fields' if authority == 'full_rvfi_retirement_receipt'
                                   else _RETIREMENT_ONLY_JOINS),
                 obi_and_delivery_joins='available',
                 contract_serial_observation=bool(contract and 'serial_observation' in contract)),
        consumption=dict(requires=['target_native_pre_post_sample', 'cpu_native_obi_beat',
                                   'declared_status_read_value', 'dependent_RAM_write_value',
                                   'load_store_retirements', 'MRET_retirement', 'MRET_successor'],
                         value_joins=('delivery_read_value==OBI_rdata==retirement_mem_value==RAM_write_value'
                                      if authority == 'full_rvfi_retirement_receipt' else
                                      'delivery_read_value==OBI_rdata==RAM_write_value'),
                         retirement_joins=('exact_fields' if authority == 'full_rvfi_retirement_receipt'
                                           else _RETIREMENT_ONLY_JOINS)),
        layers=dict(transport='available',
                    consumption=('full' if authority == 'full_rvfi_retirement_receipt'
                                 else 'order_only' if provider is not None else 'unsupported'),
                    internal_cause='unknown', internal_version='unknown', case_origin='unknown'),
        irq_consumption='unknown', isr_mmio='unknown', reward_eligible=False,
        grants_F5=False, grants_F6=False, grants_prerequisites=False)
    if authority is None:
        document.update(status='unsupported',
                        reason='declared-F5-CPU-observation-contract-unregistered',
                        layers=dict(document['layers'], consumption='unsupported'))
    elif authority == 'pc_insn_order_only' and provider is None:
        document.update(status='unsupported',
                        reason='declared-F5-pc-insn-order-only-retirement-work-unavailable',
                        layers=dict(document['layers'], consumption='unsupported'))
    return document


# ---------------------------------------------------------------------------
# Layered observation
# ---------------------------------------------------------------------------
def _receipt_view(receipt, events):
    case_events = events
    case_id = None
    if isinstance(receipt, dict):
        case_id = receipt.get('case_id')
        case_events = receipt.get('events', events)
    elif receipt is not None:
        case_id = getattr(receipt, 'case_id', None)
        case_events = getattr(receipt, 'events', events)
    _require(isinstance(case_events, (list, tuple)) and case_events, 'observation-events-required')
    return tuple(case_events), case_id


def _group_view(group):
    if isinstance(group, dict):
        document = dict(group)
        identity = document.get('group_sha256') or _digest(document)
    else:
        document = group.document()
        identity = getattr(group, 'identity_sha256', None) or _digest(document)
    members = document.get('members') or ()
    _require(isinstance(members, (list, tuple)) and members, 'observation-group-members')
    return document, identity, tuple(dict(member) for member in members)


def _contract_document(cpu_contract):
    if cpu_contract is None:
        return None
    from myfuzz.local_harness.native_irq_receipt_contract import validate_native_irq_receipt_contract
    validate_native_irq_receipt_contract(cpu_contract)
    return cpu_contract


def _sample(rows, *, phase, tick):
    matches = [row for row in rows if row.get('phase') == phase and row.get('local_tick') == tick]
    _require(len(matches) == 1, 'native-sample-pair-missing')
    return matches[0]


def _trace_value(backend, signals, role):
    signal = signals.get(role)
    _require(signal is not None, 'native-trace-role-missing: ' + role)
    value = backend.get(signal)
    _require(type(value) is int, 'native-trace-value-missing: ' + role)
    return value


def _target_read_samples(rows, *, protocol, signals, offset, value, write, reset_epoch):
    """Join the target's own native pre/post (and data-phase) samples.

    Rules are taken from the existing per-protocol consumers
    (``gpio_read_samples`` for APB3, ``_transfer_samples`` in the Wishbone
    storage consumer, ``dma_master_target_access`` for AHB-Lite).
    """
    _require(rows, 'target-native-sample-missing')
    for row in rows:
        _require(row.get('observation_schema_version') == 'ip_raw_observation.v1'
                 and type(row.get('local_tick')) is int and row['local_tick'] > 0
                 and row.get('reset_epoch') == reset_epoch
                 and isinstance(row.get('outputs'), dict)
                 and isinstance(row['outputs'].get('backend'), dict), 'target-native-sample-scope')
    pre_rows = [row for row in rows if row.get('phase') == 'pre']
    if protocol == 'apb3':
        accepted = [row for row in pre_rows
                    if _trace_value(row['outputs']['backend'], signals, 'psel') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'penable') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'pready') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'pwrite') == int(write)
                    and _trace_value(row['outputs']['backend'], signals, 'paddr') == offset]
        _require(len(accepted) == 1, 'target-native-read-count')
        pre = accepted[0]
        post = _sample(rows, phase='post', tick=pre['local_tick'])
        if 'pslverr' in signals:
            _require(_trace_value(pre['outputs']['backend'], signals, 'pslverr') == 0,
                     'target-native-protocol-error')
        if write:
            if 'pwdata' in signals:
                _require(_trace_value(pre['outputs']['backend'], signals, 'pwdata') == value,
                         'target-native-write-value-mismatch')
            data = dict(status='observed', event_id=pre['event_id'], phase='pre',
                        role='pwdata', value=value)
        else:
            data_value = _trace_value(pre['outputs']['backend'], signals, 'prdata')
            _require(data_value == value, 'target-native-read-value-mismatch')
            data = dict(status='observed', event_id=pre['event_id'], phase='pre',
                        role='prdata', value=data_value)
        return dict(pre=pre, post=post, data=data, address_presentation='paddr')
    if protocol == 'wishbone':
        accepted = [row for row in pre_rows
                    if _trace_value(row['outputs']['backend'], signals, 'cyc') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'stb') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'we') == int(write)]
        _require(len(accepted) == 1, 'target-native-read-count')
        pre = accepted[0]
        post = _sample(rows, phase='post', tick=pre['local_tick'])
        backend = post['outputs']['backend']
        # The registered ACK may already be visible in the request tick's post
        # sample; only CYC and the deasserted STB are fixed there.
        _require(_trace_value(backend, signals, 'cyc') == 1
                 and _trace_value(backend, signals, 'stb') == 0
                 and _trace_value(backend, signals, 'stall') == 0, 'target-native-request-phase')
        address_presentation = 'absent'
        for role in _ADDRESS_ROLES:
            if role in signals:
                _require(_trace_value(pre['outputs']['backend'], signals, role) == offset,
                         'target-native-request-offset')
                address_presentation = role
                break
        if write and 'sel' in signals:
            _require(_trace_value(pre['outputs']['backend'], signals, 'sel') == 15,
                     'target-native-write-select')
        if write:
            _require(_trace_value(pre['outputs']['backend'], signals, 'dat_w') == value,
                     'target-native-write-value-mismatch')
        terminal = None
        later = sorted((row for row in rows
                        if (row['local_tick'], 0 if row.get('phase') == 'pre' else 1)
                        > (pre['local_tick'], 0)),
                       key=lambda row: (row['local_tick'], row.get('phase') != 'pre'))
        for row in later:
            terminal_backend = row['outputs']['backend']
            _require(_trace_value(terminal_backend, signals, 'stall') == 0,
                     'target-native-protocol-stall')
            if _trace_value(terminal_backend, signals, 'ack') == 1:
                _require(_trace_value(terminal_backend, signals, 'cyc') == 1
                         and _trace_value(terminal_backend, signals, 'stb') == 0,
                         'target-native-ack-phase')
                terminal = row
                break
            _require(_trace_value(terminal_backend, signals, 'cyc') == 1,
                     'target-native-request-held')
        _require(terminal is not None, 'target-native-ack-missing')
        if write:
            data = dict(status='observed', event_id=terminal['event_id'], phase=terminal['phase'],
                        role='dat_w', value=value, terminal='ack',
                        request_event_id=pre['event_id'])
        else:
            data_value = _trace_value(terminal['outputs']['backend'], signals, 'dat_r')
            _require(data_value == value, 'target-native-read-value-mismatch')
            data = dict(status='observed', event_id=terminal['event_id'], phase=terminal['phase'],
                        role='dat_r', value=data_value, terminal='ack',
                        request_event_id=pre['event_id'])
        return dict(pre=pre, post=post, data=data, address_presentation=address_presentation)
    if protocol == 'ahb-lite':
        accepted = [row for row in pre_rows
                    if _trace_value(row['outputs']['backend'], signals, 'hsel') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'hreadyin') == 1
                    and _trace_value(row['outputs']['backend'], signals, 'htrans') in (2, 3)]
        _require(len(accepted) == 1, 'target-native-read-count')
        pre = accepted[0]
        post = _sample(rows, phase='post', tick=pre['local_tick'])
        backend = pre['outputs']['backend']
        _require(_trace_value(backend, signals, 'haddr') == offset
                 and _trace_value(backend, signals, 'hwrite') == int(write)
                 and _trace_value(backend, signals, 'hsize') == 2, 'target-native-request-geometry')
        terminal = None
        for row in sorted((row for row in rows if row.get('local_tick') > pre['local_tick']),
                          key=lambda row: (row['local_tick'], row.get('phase') != 'pre')):
            if row.get('phase') != 'pre':
                continue
            terminal_backend = row['outputs']['backend']
            _require(_trace_value(terminal_backend, signals, 'htrans') == 0
                     and _trace_value(terminal_backend, signals, 'hresp') == 0,
                     'target-native-data-phase-mismatch')
            if write:
                _require(_trace_value(terminal_backend, signals, 'hwdata') == value,
                         'target-native-write-value-mismatch')
            if _trace_value(terminal_backend, signals, 'hreadyout') == 1:
                terminal = row
                break
        _require(terminal is not None, 'target-native-data-phase-missing')
        if write:
            data = dict(status='observed', event_id=terminal['event_id'], phase='pre',
                        role='hwdata', value=value, terminal='data_phase')
        else:
            data_value = _trace_value(terminal['outputs']['backend'], signals, 'hrdata')
            _require(data_value == value, 'target-native-read-value-mismatch')
            data = dict(status='observed', event_id=terminal['event_id'], phase='pre',
                        role='hrdata', value=data_value, terminal='data_phase')
        return dict(pre=pre, post=post, data=data, address_presentation='haddr')
    raise ValueError('declared-F5-target-protocol-unsupported: ' + repr(protocol))


def _word_map(firmware):
    return firmware_code(firmware)


def _path_pairs(firmware):
    path = firmware.get('retirement_path')
    _require(isinstance(path, (list, tuple)) and path, 'firmware-retirement-path-missing')
    rows = []
    for row in path:
        _require(isinstance(row, (list, tuple)) and len(row) == 2
                 and type(row[0]) is int and type(row[1]) is int, 'firmware-retirement-path-shape')
        rows.append((row[0], row[1]))
    _require(rows[-1][1] == MRET_WORD, 'firmware-retirement-path-mret')
    return rows


def _operations(firmware):
    rows = firmware.get('memory_operations')
    _require(isinstance(rows, (list, tuple)) and rows, 'firmware-memory-operations-missing')
    operations = []
    for position, row in enumerate(rows):
        _require(isinstance(row, dict) and row.get('kind') in ('read', 'write')
                 and type(row.get('pc')) is int and type(row.get('address')) is int,
                 'firmware-memory-operation-shape')
        _require(row.get('index') == position, 'firmware-memory-operation-order')
        if row['kind'] == 'write':
            _require(type(row.get('value_source')) is str, 'firmware-memory-operation-value-source')
        operations.append(dict(row))
    return operations


def _retirement_rows(case_events, *, cpu_id, firmware):
    """The exact handler retirement window, never a guessed adjacency."""
    path = _path_pairs(firmware)
    code = _word_map(firmware)
    entry_pcs = set(firmware.get('entry_pcs') or ())
    retirements = [event for event in case_events
                   if event.get('kind') == 'cpu_retire' and event.get('component') == cpu_id]
    return retirements, path, code, entry_pcs


def _verify_retirement_path(retirements, linked, path, code, entry_pcs, handler, mret_pc):
    _require(linked.get('valid') == 1, 'entry-retirement-invalid')
    for field in ('trap', 'halt'):
        _require(not linked.get(field), 'entry-retirement-diverted')
    prefix = []
    if linked.get('pc_rdata') == handler:
        position = retirements.index(linked)
    elif linked.get('pc_rdata') in entry_pcs:
        _require(code.get(linked.get('pc_rdata')) == linked.get('insn'), 'entry-retirement-word')
        _require(linked.get('pc_rdata') < handler, 'entry-retirement-position')
        prefix = [(linked['pc_rdata'], linked['insn'])]
        position = retirements.index(linked) + 1
    else:
        raise ValueError('declared-F5-entry-retirement-outside-fixed-vector')
    _require(position + len(path) <= len(retirements), 'retirement-path-truncated')
    window = retirements[position:position + len(path)]
    _require([(row.get('pc_rdata'), row.get('insn')) for row in window] == path,
             'retirement-path-mismatch')
    _require([row.get('order') for row in window] == list(range(window[0].get('order'),
                                                               window[0].get('order') + len(window))),
             'retirement-path-order')
    for row in window:
        _require(row.get('valid') == 1 and not row.get('trap') and not row.get('halt'),
                 'retirement-path-diverted')
    mret = window[-1]
    _require(mret.get('pc_rdata') == mret_pc and mret.get('insn') == MRET_WORD, 'retirement-path-mret')
    return prefix + path, window, mret


def _successor(retirements, mret):
    following = [row for row in retirements if row.get('event_id', 0) > mret.get('event_id', 0)]
    _require(following, 'native-ISR-return-successor-pending')
    return following[0]


def _beat(beats, channel, sequence, reason):
    _require(type(sequence) is int and sequence >= 1, reason + '-sequence')
    beat = beats.get((channel, sequence))
    _require(beat is not None, reason)
    return beat


def observe_declared_irq_consumption(*, events, receipt, traces, error_policy, cpu_id, target_id,
                                     access, firmware, group, target_trace=None, successor_range=None,
                                     reset_epoch=0, cpu_contract=None):
    """Return the layered transport/consumption/unknown document.

    ``access`` carries the CPU-visible route geometry of the declared register
    window (``device_id``, ``target_component``, ``window_base``, ``offset``).
    ``target_trace`` is the target's declared ``base_protocol_trace`` document
    (``protocol`` plus ``signals``); without it no register-read join is claimed.

    The retirement authority comes from the registered CPU contract itself.  A
    pc/insn/order-only CPU takes the real limited branch of
    ``shared_irq_firmware``: the documented handler path is joined by order, the
    successor goes through the shared limited authority, and every field this
    CPU never drives (``intr``/``pc_wdata``/``mem_*``/serial) stays absent
    rather than being read as a value.
    """
    from types import SimpleNamespace
    from .native_obi_hops import collect_native_obi_beats
    from .generated_storage_consumer import _join_delivery
    from myfuzz.scenario.irq_return_successor import (
        PC_INSN_ORDER_ONLY_AUTHORITY, retirement_authority, retirement_serial_unobservable,
        validate_return_successor)

    case_events, case_id = _receipt_view(receipt, events)
    group_document, group_identity, members = _group_view(group)
    matching = [member for member in members if member.get('source_component') == target_id]
    _require(len(matching) == 1, 'observation-single-group-member')
    member = matching[0]
    source_port = member['source_port']
    source_bit_offset = member.get('source_bit_offset', 0)
    _require(type(access) is dict and access.get('device_id')
             and type(access.get('window_base')) is int
             and type(access.get('offset')) is int and firmware.get('target_base') == access.get('window_base'),
             'observation-register-window-access')
    document = dict(
        schema_version='declared_irq_f5_consumption.v1', status='refused',
        case_id=case_id, cpu_id=cpu_id, target_id=target_id,
        group=dict(group_id=group_document.get('group_id'), group_sha256=group_identity,
                   target_component=group_document.get('target_component'),
                   target_port=group_document.get('target_port'),
                   member_source_ids=[row.get('source_component') + '.' + row.get('source_port')
                                      for row in members]),
        firmware_digest=firmware.get('digest'),
        transport=None, consumption=None,
        unknown=dict(internal_ip_cause='unknown', internal_version='unknown',
                     case_origin='unknown', cross_case_writer_attribution='unknown',
                     irq_generic_entry_origin='unknown', target_register_data_phase='unavailable',
                     cpu_observation_contract=('declared' if cpu_contract is not None else 'unavailable')),
        reward_eligible=False, grants_F5=False, grants_F6=False, grants_prerequisites=False,
        irq_consumption='unknown', cause_source='unknown', refusals=[],
        receipt_scope=('whole-case-journal' if receipt is not None else 'caller-events'))
    contract = _contract_document(cpu_contract)
    authority = retirement_authority(contract)
    limited = authority == PC_INSN_ORDER_ONLY_AUTHORITY
    try:
        transport, by_id, frame = _verify_transport(
            case_events, group_document=group_document, group_identity=group_identity,
            members=members, member=member, target_id=target_id, cpu_id=cpu_id,
            source_port=source_port, source_bit_offset=source_bit_offset, contract=contract,
            limited=limited)
        document['transport'] = transport
        if transport['attribution'] != 'unique':
            document.update(status='ambiguous', irq_consumption='unknown',
                            consumption=dict(status='ambiguous', irq_consumption='unknown',
                                             reason='declared-F5-OR-attribution-not-unique',
                                             active_sources=transport['or_frame']['active_sources']))
            document['refusals'] = ['declared-F5-OR-attribution-not-unique']
            return document
        token = transport['decision_serial']
        retirements, path, code, entry_pcs = _retirement_rows(case_events, cpu_id=cpu_id, firmware=firmware)
        unobserved, pre_entry = [], []
        if limited:
            # The natively verified limited path: the real pre-edge entry PC pins
            # the documented entry, the window runs to exactly one MRET, and the
            # shared helper rejects every field this CPU cannot drive.
            helpers = _limited_helpers()
            unobserved = helpers['unobserved_fields'](contract)
            take = by_id[transport['native_take']['event_id']]
            sample = by_id[transport['cpu_input']['sample_event_id']]
            for event, what in ((sample, 'native-take-input-sample'), (take, 'native-take')):
                helpers['reject_unobserved_fields'](contract, event, what=what)
            window_path = _limited_entry_path(helpers, firmware,
                                              transport['native_take']['irq_entry_pc'])
            window, pre_entry = helpers['retirement_window'](
                SimpleNamespace(cpu_id=cpu_id), SimpleNamespace(events=list(case_events)),
                take, window_path, contract)
            linked, mret = [window[0]], window[-1]
            # trap/halt are unobservable on this CPU, so a real non-IRQ exception
            # redirect is the only diverted-entry evidence there is.
            _require(not helpers['redirect_rows'](case_events, low=take['event_id'],
                                                  high=mret['event_id']),
                     'limited-CPU-exception-redirect-before-MRET')
            join_scope = _RETIREMENT_ONLY_SCOPE
        else:
            if token is None:
                # The CPU contract declares no serial observation: the first real
                # retirement after the native take is the documented entry, which is
                # exactly why this stays labelled weaker than a serial join.
                following = [row for row in retirements
                             if row.get('event_id', 0) > transport['native_take']['event_id']]
                _require(following, 'first-retirement-after-take-missing')
                linked = [following[0]]
                join_scope = _RETIREMENT_ONLY_SCOPE
            else:
                linked = [row for row in retirements
                          if (row.get('irq_serial_observation') or {}).get('retirement', {}).get('status') == 'observed'
                          and row['irq_serial_observation']['retirement']['value'] == token]
                join_scope = 'exact_decision_serial_join'
            _require(len(linked) == 1, 'first-handler-retirement-serial')
            window_path, window, mret = _verify_retirement_path(
                retirements, linked[0], path, code, entry_pcs, firmware['handler'], firmware['mret_pc'])
        transport['first_handler_retirement'] = dict(
            event_id=linked[0]['event_id'], pc=linked[0].get('pc_rdata'), insn=linked[0].get('insn'),
            order=linked[0].get('order'), scope=join_scope)
        if limited:
            transport['first_handler_retirement']['retirement_joins'] = _RETIREMENT_ONLY_JOINS
        try:
            # A shared case can start with a fetch already accepted by the CPU.
            # Reconstruct bus state and sequence numbers from the real journal;
            # IRQ, ISR, delivery and value joins below remain case-scoped.
            beats = collect_native_obi_beats(events, cpu=cpu_id, traces=traces,
                                             error_policy=error_policy)
        except ValueError as error:
            raise ValueError('declared-F5-native-OBI-collection:' + str(error)) from None
        operations = _operations(firmware)
        lower = linked[0]['event_id']
        upper = mret['event_id']
        relevant = [event for event in case_events if lower < event.get('event_id', 0) < upper]
        full_fields = (not limited) and all(all(name in row for name in _RETIREMENT_FIELD_NAMES)
                                           for row in window)
        consumption = _verify_consumption(
            relevant=relevant, window=window, operations=operations, firmware=firmware,
            access=access, target_id=target_id, target_trace=target_trace, beats=beats,
            join_delivery=_join_delivery, full_fields=full_fields, reset_epoch=reset_epoch)
        successor = _successor(retirements, mret)
        if limited:
            # A serial token is not driven by this CPU anywhere in the chain, and
            # a real exception redirect would destroy the documented return path.
            for event in (*window, successor):
                _require(retirement_serial_unobservable(event),
                         'limited-CPU-fabricated-retirement-serial')
            _require(not helpers['redirect_rows'](case_events, low=take['event_id'],
                                                  high=successor['event_id']),
                     'limited-CPU-exception-redirect-before-successor')
        start, end = (successor_range or (firmware['image_start'], firmware['image_end']))
        return_pc = validate_return_successor(mret, successor, start=start, end=end,
                                              authority=authority)
        if limited:
            helpers['reject_unobserved_fields'](contract, successor, what='successor-retirement')
            _require(successor.get('valid') == 1
                     and successor.get('schema_version') == 'cpu_retire.v2'
                     and successor.get('observation_contract') == contract,
                     'limited-CPU-successor-retire-scope')
        responses = [event for event in case_events if event.get('kind') == 'instr_response'
                     and event.get('component') == cpu_id and event.get('address') == return_pc
                     and event.get('rdata') == successor.get('insn') and event.get('error') == 0
                     and type(event.get('response_tick')) is int
                     and event['response_tick'] <= successor.get('local_tick', -1)]
        _require(responses, 'successor-instruction-response-missing')
        response = responses[-1]
        reads = [event for event in case_events if event.get('kind') == 'memory_read'
                 and event.get('component') == cpu_id and event.get('address') == return_pc
                 and event.get('transaction') == response.get('transaction')]
        sources = [event for event in reads
                   if event.get('data_hex') == successor['insn'].to_bytes(4, 'little').hex()]
        successor_evidence = dict(
            event_id=successor['event_id'], pc=return_pc, insn=successor.get('insn'),
            order=successor.get('order'))
        if not limited:
            successor_evidence['raw_mret_pc_wdata'] = mret.get('pc_wdata')
        successor_evidence.update(
            instruction_response_event=response['event_id'],
            instruction_response_tick=response.get('response_tick'),
            source_byte_version=(dict(status='observed', memory_read_event=sources[0]['event_id'],
                                      data_hex=sources[0]['data_hex'],
                                      generation=sources[0].get('generation'),
                                      versions=deepcopy(sources[0].get('versions')),
                                      writer_event_ids=deepcopy(sources[0].get('writer_event_ids')))
                                 if sources else dict(status='unavailable',
                                                      reason='successor-source-byte-version-not-observed')))
        if limited:
            successor_evidence.update(
                return_target_source='first_subsequent_valid_retirement_pc',
                retirement_authority=authority,
                unobserved_retirement_fields=list(unobserved))
        document['cause_source'] = consumption.get('cause_source', 'unknown')
        if document['cause_source'] == 'read_status_bit':
            document['unknown']['internal_ip_cause'] = 'read_status_bit'
            document['unknown']['internal_ip_cause_proof'] = consumption.get('cause_proof')
        mret_evidence = dict(event_id=mret['event_id'], pc=mret.get('pc_rdata'),
                             insn=mret.get('insn'), order=mret.get('order'))
        if not limited:
            mret_evidence['raw_pc_wdata'] = mret.get('pc_wdata')
        consumption.update(status='verified', irq_consumption='verified', mret=mret_evidence,
                           handler_retirements=[dict(event_id=row['event_id'], order=row.get('order'),
                                                     pc=row.get('pc_rdata'), insn=row.get('insn')) for row in window],
                           retirement_path=[list(row) for row in window_path],
                           successor=successor_evidence, return_target=return_pc)
        if limited:
            consumption.update(retirement_authority=authority,
                               unobserved_retirement_fields=list(unobserved),
                               per_retirement_join='unobservable',
                               join_scope=_RETIREMENT_ONLY_JOIN_SCOPE,
                               pre_entry_retirements=deepcopy(pre_entry))
        document.update(status='verified', consumption=consumption, irq_consumption='verified',
                        refusals=[])
        return document
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, StopIteration) as error:
        reason = type(error).__name__ + ': ' + str(error)
        document['refusals'] = [reason]
        if document['transport'] is None:
            document['transport'] = dict(status='refused', reason=reason)
        document['consumption'] = dict(status='refused', reason=reason, irq_consumption='unknown')
        document['irq_consumption'] = 'unknown'
        return document


def _limited_entry_path(helpers, firmware, entry_pc):
    """Documented ``(pc, word)`` path from the real pre-edge entry PC to the MRET.

    The entry PC is the take's own pre-edge exception-entry observation, never a
    scenario constant.  A direct vector entry (or the handler itself) uses the
    fixed images as declared; a vectored external entry prefixes the real
    trampoline word taken from the same fixed image.
    """
    _require(type(entry_pc) is int and 0 <= entry_pc < 1 << 32 and entry_pc % 4 == 0,
             'limited-CPU-entry-PC')
    code = _word_map(firmware)
    handler = firmware.get('handler')
    path = [[row[0], row[1]] for row in _path_pairs(firmware)]
    if entry_pc == handler:
        view = firmware
    else:
        _require(entry_pc in set(firmware.get('entry_pcs') or ())
                 and type(handler) is int and entry_pc < handler,
                 'limited-CPU-entry-retirement-outside-fixed-vector')
        _require(type(code.get(entry_pc)) is int, 'limited-CPU-entry-instruction-missing')
        view = dict(firmware, retirement_path=[[entry_pc, code[entry_pc]], *path])
    return helpers['fixed_isr_path'](view, entry_pc)


def _verify_transport(case_events, *, group_document, group_identity, members, member, target_id,
                      cpu_id, source_port, source_bit_offset, contract, limited=False):
    by_id = {event['event_id']: event for event in case_events
             if type(event.get('event_id')) is int}
    takes = [event for event in case_events
             if event.get('kind') == 'cpu_external_irq_taken' and event.get('component') == cpu_id]
    _require(len(takes) == 1, 'one-actual-native-CPU-take-required')
    take = takes[0]
    frames = [event for event in case_events if event.get('kind') == 'irq_group_delivery'
              and event.get('native_take_event_id') == take['event_id']]
    _require(len(frames) == 1, 'actual-OR-delivery-take-join-required')
    frame = frames[0]
    _require(frame.get('group_id') == group_document.get('group_id')
             and frame.get('group_sha256') == group_identity
             and frame.get('target_component') == group_document.get('target_component')
             and frame.get('target_port') == group_document.get('target_port'),
             'OR-frame-group-identity')
    _require(frame.get('value') == 1, 'OR-frame-value')
    source_id = target_id + '.' + source_port
    frame_members = frame.get('members') or ()
    _require(isinstance(frame_members, (list, tuple))
             and [row.get('source_id') for row in frame_members]
             == [row.get('source_component') + '.' + row.get('source_port') for row in members],
             'OR-frame-members')
    _require(frame.get('attribution_status') in ('unique', 'joint', 'unknown'), 'OR-frame-attribution')
    active = list(frame.get('active_sources') or ())
    _require(isinstance(active, list), 'OR-frame-active-sources')
    attribution = ('unique' if frame.get('attribution_status') == 'unique' and active == [source_id]
                   else 'ambiguous')
    transport = dict(
        status='observed', target_component=target_id, target_port=source_port,
        source_bit_offset=source_bit_offset,
        or_frame=dict(event_id=frame['event_id'], group_id=frame.get('group_id'),
                      group_sha256=frame.get('group_sha256'), cpu_tick=frame.get('cpu_tick'),
                      value=frame.get('value'), attribution_status=frame.get('attribution_status'),
                      unique_source=frame.get('unique_source'), active_sources=active,
                      member_source_ids=[row.get('source_id') for row in frame_members],
                      native_sample_event_id=frame.get('native_sample_event_id'),
                      native_take_event_id=frame.get('native_take_event_id')),
        attribution=attribution, cpu_input=None, native_take=None,
        native_output=None, decision_serial=None, decision_serial_status='unavailable')
    if attribution != 'unique':
        return transport, by_id, frame
    truth = [row for row in frame_members if row.get('source_id') == source_id]
    _require(len(truth) == 1, 'OR-frame-target-member')
    reference = truth[0].get('native_source') or {}
    pulse = by_id.get(reference.get('event_id'))
    _require(isinstance(pulse, dict) and pulse.get('kind') == 'local_tick_sample'
             and pulse.get('component') == target_id
             and pulse.get('phase') == reference.get('phase')
             and pulse.get('local_tick') == reference.get('local_tick')
             and pulse.get('reset_epoch') == reference.get('reset_epoch')
             and truth[0].get('value') == 1, 'actual-target-native-output-sample')
    runtime_name = reference.get('runtime_name')
    _require(type(runtime_name) is str and runtime_name, 'target-native-output-wire')
    physical = (pulse.get('outputs') or {}).get('physical') or {}
    raw = physical.get(runtime_name)
    _require(type(raw) is int and raw >= 0, 'target-native-output-raw-value')
    _require(type(source_bit_offset) is int and 0 <= source_bit_offset < 64
             and raw >> source_bit_offset & 1 == 1, 'target-native-output-bit')
    _require((pulse.get('outputs') or {}).get(source_port) == raw,
             'target-native-output-projection')
    transport['native_output'] = dict(
        event_id=pulse['event_id'], component=target_id, local_tick=pulse.get('local_tick'),
        phase=pulse.get('phase'), reset_epoch=pulse.get('reset_epoch'), producer_event_id=pulse.get('producer_event_id'),
        runtime_name=runtime_name, physical_port=source_port, raw_value=raw,
        bit=source_bit_offset, bit_value=raw >> source_bit_offset & 1,
        adapter_id=reference.get('adapter_id'))
    sample = by_id.get(frame.get('native_sample_event_id'))
    _require(isinstance(sample, dict) and sample.get('kind') == 'cpu_external_irq_sample'
             and sample.get('component') == cpu_id and sample.get('event_id') == take.get('sample_event_id')
             and sample.get('producer_event_id') == take.get('producer_event_id')
             and sample.get('local_tick') == frame.get('cpu_tick')
             and take.get('local_tick') == frame.get('cpu_tick'), 'actual-parsed-CPU-input-required')
    for event in (sample, take):
        _require(all(type(event.get(key)) is int and event[key] == frame.get('value')
                     for key in ('expected_input', 'actual_pre_input', 'actual_post_input')),
                 'CPU-input-pre-post-mismatch')
        if contract is not None:
            _require(event.get('observation_contract') == contract, 'CPU-observation-contract-mismatch')
    transport['cpu_input'] = dict(
        sample_event_id=sample['event_id'], producer_event_id=sample.get('producer_event_id'),
        local_tick=sample.get('local_tick'), expected_input=sample.get('expected_input'),
        actual_pre_input=sample.get('actual_pre_input'), actual_post_input=sample.get('actual_post_input'),
        observation_contract=('declared' if contract is not None else 'unavailable'),
        irq_masked_pre=take.get('irq_masked_pre'))
    _require(type(take.get('irq_taken_pre')) is int and take['irq_taken_pre'] == 1,
             'native-take-decision-probe')
    for field in ('trap', 'halt'):
        _require(not sample.get(field), 'native-take-diverted')
    serial = deepcopy(take.get('irq_serial_observation'))
    decision = (serial or {}).get('decision') or {}
    token = decision.get('value')
    if limited:
        # This CPU drives no serial token anywhere: a claimed decision or
        # retirement token is a fabricated observation, and the transport never
        # emits a serial document at all.
        from myfuzz.scenario.irq_return_successor import retirement_serial_unobservable
        _require(decision.get('status') != 'observed',
                 'limited-CPU-fabricated-decision-serial')
        _require(retirement_serial_unobservable(take),
                 'limited-CPU-fabricated-retirement-serial')
        transport['decision_serial'] = None
        transport['decision_serial_status'] = 'unavailable'
    elif decision.get('status') == 'observed':
        # A zero token proves no source lineage, so it can never anchor the
        # first-handler retirement join.
        _require(type(token) is int and token > 0, 'non-zero-native-decision-serial-required')
        transport['decision_serial'] = token
        transport['decision_serial_status'] = 'observed'
    else:
        _require(contract is None or 'serial_observation' not in contract,
                 'native-decision-serial-unobservable')
        transport['decision_serial'] = None
        transport['decision_serial_status'] = 'unavailable'
    native_take = dict(
        event_id=take['event_id'], local_tick=take.get('local_tick'),
        irq_taken_pre=take.get('irq_taken_pre'), irq_masked_pre=take.get('irq_masked_pre'),
        take_key=deepcopy(take.get('take_key')))
    if limited:
        # The real pre-edge ack/id/entry-PC acceptance of this take; the entry PC
        # is the only accepted anchor of the documented handler path.
        from myfuzz.local_harness.native_irq_receipt_contract import native_irq_acceptance
        acceptance = native_irq_acceptance(contract)
        _require(acceptance is not None, 'limited-CPU-acceptance-probes-unavailable')
        entry_pc = take.get(acceptance['entry_pc_probe'])
        _require(take.get(acceptance['ack_probe']) == 1
                 and take.get(acceptance['id_probe']) == acceptance['source_id']
                 and type(entry_pc) is int and 0 <= entry_pc < 1 << 32 and entry_pc % 4 == 0,
                 'limited-CPU-native-acceptance')
        native_take.update(irq_ack_pre=take[acceptance['ack_probe']],
                           irq_id_pre=take[acceptance['id_probe']],
                           accepted_source_id=acceptance['source_id'],
                           irq_entry_pc=entry_pc)
    else:
        native_take['irq_serial_observation'] = (serial if serial is not None
                                                 else dict(status='unavailable'))
    transport['native_take'] = native_take
    return transport, by_id, frame


def _verify_consumption(*, relevant, window, operations, firmware, access, target_id, target_trace,
                        beats, join_delivery, full_fields, reset_epoch):
    _require(isinstance(target_trace, dict) and isinstance(target_trace.get('signals'), dict),
             'target-declared-trace-required')
    protocol = _PROTOCOLS.get(str(target_trace.get('protocol')).lower())
    _require(protocol is not None, 'target-declared-protocol-unsupported')
    signals = target_trace['signals']
    retirements = {row.get('pc_rdata'): row for row in window}
    read_values = {}
    reads, writes, acks = [], [], []
    cause_bits = {int(key): int(value) for key, value in (firmware.get('cause_bits') or {}).items()}
    cause_source = 'unknown'
    cause_proof = None
    for operation in operations:
        retirement = retirements.get(operation['pc'])
        _require(retirement is not None, 'declared-memory-operation-retirement')
        opcode = retirement.get('insn', 0) & 0x7f
        if operation['kind'] == 'read':
            _require(opcode == 0x03, 'declared-read-retirement-opcode')
            if full_fields:
                _require(retirement.get('mem_addr') == operation['address']
                         and retirement.get('mem_rmask') == 15, 'declared-read-retirement-geometry')
            candidates = [event for event in relevant if event.get('kind') == 'mmio_delivery'
                          and event.get('device_id') == access['device_id']
                          and event.get('offset') == operation.get('offset')
                          and event.get('write') is False]
            _require(len(candidates) == 1, 'declared-status-read-missing')
            delivery = candidates[0]
            value = delivery.get('read_value')
            _require(type(value) is int and 0 <= value <= 0xffffffff, 'declared-status-read-value')
            accepted = join_delivery(relevant, delivery=delivery, component=delivery.get('component'),
                                     device=access['device_id'], address=delivery.get('address'),
                                     offset=operation.get('offset'), write=False)
            rows = [event for event in relevant if event.get('kind') == 'local_tick_sample'
                    and event.get('component') == target_id
                    and event.get('producer_event_id') == delivery.get('producer_event_id')]
            samples = _target_read_samples(rows, protocol=protocol, signals=signals,
                                           offset=operation.get('offset'), value=value,
                                           write=False, reset_epoch=reset_epoch)
            beat = _beat(beats, 'data', (delivery.get('source_transaction') or {}).get('source_sequence'),
                         'declared-status-read-native-OBI-beat')
            _require(beat['acceptance_event'] == accepted.get('producer_event_id')
                     and beat['write'] == 0 and beat['address'] == access['window_base'] + operation['offset']
                     and beat['rdata'] == value and beat['byte_enable'] == 15
                     and accepted['event_id'] < delivery['event_id'] < beat['response_event'],
                     'declared-status-read-native-OBI-mismatch')
            _require(beat['acceptance_event'] < beat['response_event'] < retirement['event_id'],
                     'declared-status-read-retirement-order')
            if full_fields:
                _require(retirement.get('mem_rdata') == value, 'declared-status-read-retirement-value')
            read_values[operation['target_register_index']] = value
            mask = None
            for offset, declared_mask in cause_bits.items():
                if offset == operation.get('offset'):
                    mask = declared_mask
            if mask is not None and value & mask:
                cause_source = 'read_status_bit'
                cause_proof = dict(offset=operation.get('offset'), mask=mask, value=value,
                                   source='actual_ISR_status_read')
            reads.append(dict(
                offset=operation.get('offset'), value=value, delivery_event=delivery['event_id'],
                acceptance_event=accepted['event_id'],
                native_pre_event=samples['pre']['event_id'], native_post_event=samples['post']['event_id'],
                native_data=samples['data'], address_presentation=samples['address_presentation'],
                native_OBI=dict(beat), transaction=deepcopy(delivery.get('source_transaction')),
                retirement_event=retirement['event_id'], retirement_pc=operation['pc'],
                retirement_join=('exact_fields' if full_fields else 'by_documented_order'),
                target_register_index=operation.get('target_register_index')))
            continue
        value = read_values.get(_source_index(operation))
        _require(type(value) is int, 'declared-write-value-source-missing')
        if 'result_index' in operation:
            _require(opcode == 0x23, 'declared-result-retirement-opcode')
            candidates = [event for event in relevant if event.get('kind') == 'memory_write'
                          and event.get('address') == operation['address']
                          and event.get('value') == value and event.get('byte_enable') == 15]
            _require(len(candidates) == 1, 'dependent-RAM-write-missing')
            event = candidates[0]
            beat = _beat(beats, 'data', (event.get('transaction') or {}).get('source_sequence'),
                         'dependent-RAM-native-OBI-beat')
            _require(beat['write'] == 1 and beat['address'] == event['address']
                     and beat['value'] == value and beat['byte_enable'] == 15
                     and beat['acceptance_event'] == event.get('producer_event_id')
                     and beat['acceptance_event'] < event['event_id'] < beat['response_event']
                     and beat['response_event'] < retirement['event_id'],
                     'dependent-RAM-native-OBI-mismatch')
            if full_fields:
                _require(retirement.get('mem_addr') == event['address']
                         and retirement.get('mem_wmask') == 15
                         and retirement.get('mem_wdata') == value,
                         'dependent-RAM-retirement-mismatch')
            writes.append(dict(index=operation['result_index'], address=event['address'], value=value,
                               event_id=event['event_id'], native_OBI=dict(beat),
                               retirement_event=retirement['event_id'], retirement_pc=operation['pc'],
                               retirement_join=('exact_fields' if full_fields else 'by_documented_order')))
            continue
        _require(opcode == 0x23, 'declared-ack-retirement-opcode')
        candidates = [event for event in relevant if event.get('kind') == 'mmio_delivery'
                      and event.get('device_id') == access['device_id']
                      and event.get('offset') == operation.get('offset')
                      and event.get('write') is True and event.get('write_value') == value]
        _require(len(candidates) == 1, 'declared-clear-ack-write-missing')
        delivery = candidates[0]
        accepted = join_delivery(relevant, delivery=delivery, component=delivery.get('component'),
                                 device=access['device_id'], address=delivery.get('address'),
                                 offset=operation.get('offset'), write=True)
        rows = [event for event in relevant if event.get('kind') == 'local_tick_sample'
                and event.get('component') == target_id
                and event.get('producer_event_id') == delivery.get('producer_event_id')]
        samples = _target_read_samples(rows, protocol=protocol, signals=signals,
                                      offset=operation.get('offset'), value=value,
                                      write=True, reset_epoch=reset_epoch)
        beat = _beat(beats, 'data', (delivery.get('source_transaction') or {}).get('source_sequence'),
                     'declared-clear-ack-native-OBI-beat')
        _require(beat['acceptance_event'] == accepted.get('producer_event_id')
                 and beat['write'] == 1 and beat['value'] == value
                 and beat['address'] == access['window_base'] + operation['offset']
                 and accepted['event_id'] < delivery['event_id'] < beat['response_event']
                 and beat['response_event'] < retirement['event_id'],
                 'declared-clear-ack-native-OBI-mismatch')
        if full_fields:
            _require(retirement.get('mem_addr') == beat['address']
                     and retirement.get('mem_wmask') == 15
                     and retirement.get('mem_wdata') == value, 'declared-clear-ack-retirement-mismatch')
        acks.append(dict(offset=operation.get('offset'), value=value,
                         value_source=operation.get('value_source'),
                         role=operation.get('role'), delivery_event=delivery['event_id'],
                         acceptance_event=accepted['event_id'],
                         native_pre_event=samples['pre']['event_id'],
                         native_post_event=samples['post']['event_id'],
                         native_data=samples['data'], native_OBI=dict(beat),
                         retirement_event=retirement['event_id'], retirement_pc=operation['pc']))
    _require(reads and writes, 'declared-consumption-empty')
    return dict(status='observed', irq_consumption='unknown',
                register_reads=reads, result_ram_writes=writes, ack_writes=acks,
                retirement_joins=('exact_fields' if full_fields else 'by_documented_order'),
                value_join='delivery_read_value==OBI_rdata==retirement_mem_value==RAM_write_value'
                           if full_fields else
                           'delivery_read_value==OBI_rdata==RAM_write_value',
                cause_source=cause_source, cause_proof=cause_proof,
                target_protocol=protocol, reset_epoch=reset_epoch)


def _source_index(operation):
    source = operation.get('value_source')
    _require(type(source) is str and source.startswith('read_value[') and source.endswith(']'),
             'declared-write-value-source')
    body = source[len('read_value['):-1]
    _require(body.isdigit(), 'declared-write-value-source')
    return int(body)
