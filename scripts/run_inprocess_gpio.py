#!/usr/bin/env python3
"""Build and run one process that drives the PULP APB3 GPIO through its pins.

One OBI CPU model, one generated ``apb_gpio`` model and the host RAM are
initialized once.  The CPU executes a fixed polling program from that RAM, so a
case is handed over by writing one mailbox word; no case recompiles,
re-initializes or resets any model.  What makes this host different from the
F1-F4 one is the *pin side*, which no other in-process host had:

* every tick the host samples the device's own ``gpio_out``/``gpio_dir`` ports,
  resolves the pad wire from them plus one declared external driver value, drives
  that resolution back into ``gpio_in`` and samples the device's synchronizer,
  its transition probes and its interrupt output;
* a pad value is therefore never a constant copied from a config: it is the
  device's registered output for a pin whose direction bit is high, and the host
  driver value otherwise; the host prints every resolution it applied.

The flows:

* F1 the CPU fetches and retires one word from the trampoline slot
* F2 the CPU reads one RAM word or one APB register
* F3 the CPU stores one word to RAM
* F4 the CPU stores one word through the APB window; for the PADOUT family the
  sampled ``gpio_out`` and the pad the host resolved are both checked
* P  the host drives the declared external pin value and the CPU then reads the
  device's PADIN register: the word the CPU commits is compared with the pad the
  host itself resolved for those pins
* F5 the CPU performs the declared trigger writes, a real pin transition inside
  the device produces the device's own interrupt, the host samples it and
  delivers it to the CPU input its profile declares, and the ISR reads the
  declared status register (reading INTSTATUS is the device's own clear), stores
  the value it read and sets the flag

Unsupported components, windows, registers or device behavior are refused by
name.  The result is a compact observation, not a certificate and not a replay.
"""
import argparse
from pathlib import Path
import json
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from scripts.inprocess_build import build_link_run
from scripts.run_inprocess_f1f4 import (Program, _check_spans, _jalr, explicit_timing,
                                        incremental_runner, run_arguments)

# Fixed offsets of the one RAM image.  Nothing moves between cases: only the
# trampoline slot word, the mailbox, the handler block the ISR reads and the
# host's own external pin driver change.
VECTOR_OFFSET = 0x200
HANDLER_OFFSET = 0x400
MAIN_OFFSET = 0x1000
SLOT_OFFSET = 0x2000
MAILBOX_OFFSET = 0x3000
HANDLER_BLOCK_OFFSET = MAILBOX_OFFSET + 0x40
DATA_OFFSET = 0x4000
RESULT_OFFSET = 0x5000
INPUT_BLOCK = 16                      # first input word inside the mailbox
MAILBOX_BYTES = 32
HB = 0x40                             # handler block, stated from the mailbox pointer
HB_STATUS, HB_RESULT, HB_CLEAR, HB_CLEAR_VALUE, HB_FLAG = HB, HB + 4, HB + 8, HB + 12, HB + 16
HANDLER_BLOCK_BYTES = 20
DATA_WORDS = (0xDEADBEEF, 0x11111111, 0x00000000)
MRET_WORD = 0x30200073
COMMANDS = {'F1': 1, 'F2': 2, 'F3': 3, 'F4': 4, 'F5': 5, 'P': 6}
CASE_OBSERVATION_KEYS = {
    'F1': ('fetch', 'retire_pc', 'retire_insn', 'successor_pc'),
    'F2': ('read_addr', 'read_value', 'echo_value', 'read_from', 'apb_rdata',
           'pad_at_read', 'padin_latch'),
    'P': ('read_addr', 'read_value', 'echo_value', 'read_from', 'apb_rdata',
          'pad_at_read', 'padin_latch'),
    'F3': ('write_addr', 'write_value', 'write_be', 'ram_before', 'ram_after'),
    'F4': ('mmio_addr', 'mmio_value', 'apb_offset', 'apb_pwdata', 'apb_pready',
           'out_before', 'dir_before'),
    'F5': ('trigger_writes', 'apb_read_offset', 'apb_read_data', 'apb_last_write_offset',
           'apb_last_write_data', 'irq_edges', 'irq_high_ticks', 'irq_takes',
           'irq_cause_pins', 'inten_at_irq', 'rise_mask', 'first_rise_tick',
           'first_irq_tick', 'status_after_read', 'isr_result', 'isr_flag'),
}
CASE_PIN_KEYS = ('pad_before', 'pad_after', 'out_after', 'dir_after', 'ext_value',
                 'pad_changes', 'pad_rise_events', 'rise_mask', 'fall_mask')
CASE_COUNTER_KEYS = ('i_fetches', 'd_reads', 'd_writes', 'apb_reads', 'apb_writes')


# ---------------------------------------------------------------------------
# Declaration checks: the selected components decide what is offered
# ---------------------------------------------------------------------------
def declared_windows(config):
    """The two address windows this host routes between, from the declaration."""
    window, ram_base, ram_end = (config.get('target_window'), config.get('image_start'),
                                 config.get('image_end'))
    if any(type(value) is not int for value in (ram_base, ram_end)):
        raise ValueError('config requires integer image_start and image_end')
    if (not isinstance(window, dict)
            or any(type(window.get(key)) is not int for key in ('base', 'size'))):
        raise ValueError('config requires a declared APB target_window')
    ram_size = ram_end - ram_base
    if ram_base % 4 or ram_size < DATA_OFFSET + 4 * len(DATA_WORDS):
        raise ValueError('declared RAM is too small for the fixed image')
    if (window['base'] % 4 or window['size'] < 4
            or window['base'] + window['size'] > 1 << 32):
        raise ValueError('declared APB window is unusable for this host')
    if max(window['base'], ram_base) < min(window['base'] + window['size'], ram_end):
        raise ValueError('declared APB window overlaps the RAM image')
    return dict(ram_base=ram_base, ram_size=ram_size,
                ip_base=window['base'], ip_size=window['size'],
                data_base=ram_base + DATA_OFFSET)


def build_layout(windows, boot):
    """Every fixed address of the one RAM image, checked for overlap."""
    ram = windows['ram_base']
    layout = dict(boot=boot, vector=ram + VECTOR_OFFSET, handler=ram + HANDLER_OFFSET,
                  main=ram + MAIN_OFFSET, slot=ram + SLOT_OFFSET,
                  mailbox=ram + MAILBOX_OFFSET, mailbox_bytes=MAILBOX_BYTES,
                  handler_block=ram + HANDLER_BLOCK_OFFSET,
                  handler_block_bytes=HANDLER_BLOCK_BYTES,
                  data_base=windows['data_base'],
                  result_f5=ram + RESULT_OFFSET, flag=ram + RESULT_OFFSET + 8,
                  data_end=ram + windows['ram_size'], ram_base=ram,
                  ram_size=windows['ram_size'], ip_base=windows['ip_base'],
                  ip_size=windows['ip_size'])
    if boot % 4 or not ram <= boot <= ram + windows['ram_size'] - 4:
        raise ValueError('the declared CPU boot address is not an aligned RAM word')
    if boot + 4 * 12 > layout['vector']:
        raise ValueError('the declared CPU boot address leaves no room for the bootstrap')
    return layout


def _registers(ip_profile, window):
    address = ip_profile.address
    if address is None or window['size'] != address.window_size:
        raise ValueError('unsupported: the APB window does not match the target profile')
    if window['base'] % address.alignment:
        raise ValueError('unsupported: the APB window is not aligned to the target')
    return {row.offset: row for row in address.registers}


def irq_declaration(config, ip_profile):
    """Check the declared IRQ behavior against the target's own register map."""
    declaration = config.get('irq')
    if declaration is None:
        return None
    if not isinstance(declaration, dict):
        raise ValueError('config irq declaration must be an object')
    registers = _registers(ip_profile, config['target_window'])
    status = registers.get(declaration.get('status_offset'))
    if (status is None or status.width != 32 or status.access not in ('ro', 'rw')):
        raise ValueError('unsupported: the declared status register is not a readable word')
    triggers = declaration.get('trigger_offsets')
    if not isinstance(triggers, list) or not triggers or len(triggers) > 4:
        raise ValueError('unsupported: F5 needs one to four declared trigger offsets')
    for offset in triggers:
        row = registers.get(offset) if type(offset) is int else None
        if (row is None or row.width != 32 or row.access not in ('wo', 'rw')):
            raise ValueError('unsupported: a declared trigger register is not a writable word')
    clear = declaration.get('clear')
    if clear is not None:
        row = registers.get(clear.get('offset')) if isinstance(clear, dict) else None
        if row is None or row.width != 32 or row.access not in ('wo', 'rw'):
            raise ValueError('unsupported: the declared clear register is not a writable word')
    bit, port = declaration.get('source_bit_offset'), declaration.get('source_port')
    if type(bit) is not int or not isinstance(port, str):
        raise ValueError('config requires source_port and source_bit_offset')
    endpoints = {endpoint.endpoint_id: endpoint for endpoint in ip_profile.endpoints}
    sources = [source for source in ip_profile.interrupts
               if (source.bit if source.bit is not None else 0) == bit
               and source.endpoint_id in endpoints
               and any(field.role == source.role and port in field.aliases
                       for field in endpoints[source.endpoint_id].fields)]
    if len(sources) != 1:
        raise ValueError('unsupported: the target declares no single IRQ output on ' + port)
    source = sources[0]
    if source.polarity not in ('active_high', 'active_low'):
        raise ValueError('unsupported: declared IRQ polarity')
    if source.trigger != 'pulse':
        raise ValueError('unsupported: this host samples a transition pulse only')
    width = declaration.get('pulse_width_ticks')
    if type(width) is not int or not 1 <= width <= 4096:
        raise ValueError('a pulse IRQ source needs a declared delivery width')
    return dict(port=port, bit=bit, trigger=source.trigger, polarity=source.polarity,
                pulse_ticks=width, status_offset=declaration['status_offset'],
                trigger_offsets=list(triggers), clear=clear)


def pin_declaration(config, ip_profile):
    """Check the declared pad model against the target's own pin endpoint."""
    declaration = config.get('pins')
    if not isinstance(declaration, dict):
        raise ValueError('config requires a pins declaration')
    if declaration.get('pad_resolution') != 'device_drives_when_dir_bit_high_else_host':
        raise ValueError('unsupported: only the dir-resolved pad model is implemented')
    pads = [endpoint for endpoint in ip_profile.endpoints
            if endpoint.function == 'external_pins']
    if len(pads) != 1:
        raise ValueError('unsupported: the target declares no single external pin endpoint')
    shape = {field.role: field.direction for field in pads[0].fields}
    if (shape.get('in') != 'input' or shape.get('out') != 'output'
            or shape.get('dir') != 'output'):
        raise ValueError('unsupported: the target declares no dir-resolved pad endpoint')
    declared = {field.role: field.width for field in pads[0].fields}
    if declared.get('in') != 32:
        raise ValueError('unsupported: the declared pad input is not 32 bits wide')
    value = declaration.get('external_value')
    if type(value) is not int or not 0 <= value < 1 << 32:
        raise ValueError('pins.external_value must be one 32-bit word')
    registers = _registers(ip_profile, config['target_window'])
    padin = registers.get(declaration.get('padin_offset'))
    if padin is None or padin.width != 32 or padin.access not in ('ro', 'rw'):
        raise ValueError('unsupported: pins.padin_offset is not a readable word')
    return dict(endpoint_id=pads[0].endpoint_id, width=32, external_value=value,
                padin_offset=declaration['padin_offset'])


def flow_arity(irq):
    arity = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'P': 2}
    if irq is not None:
        arity['F5'] = len(irq['trigger_offsets'])
    return arity


# ---------------------------------------------------------------------------
# Input records
# ---------------------------------------------------------------------------
def parse_record(text, *, windows, arity, pins):
    """Turn one operator record into the exact input this host will hand over."""
    if type(text) is not str or not text:
        raise ValueError('one record text is required')
    fields = text.split(':')
    flow = fields[0]
    if flow not in arity:
        raise ValueError('unsupported flow tag: ' + flow)
    if len(fields) - 1 != arity[flow]:
        raise ValueError(flow + ' needs ' + str(arity[flow]) + ' word(s)')
    values = []
    for field in fields[1:]:
        if not 0 < len(field) <= 8 or any(character not in '0123456789abcdefABCDEF'
                                          for character in field):
            raise ValueError('record words must be 1-8 hexadecimal digits')
        values.append(int(field, 16))
    first = values[0]
    data_base, ip_base, ip_size = windows['data_base'], windows['ip_base'], windows['ip_size']
    if flow == 'F1':
        if first & 3 != 3:
            raise ValueError('F1 input must be one 32-bit instruction word')
    elif flow == 'F2':
        ram = data_base <= first <= windows['ram_base'] + windows['ram_size'] - 4
        target = ip_base <= first <= ip_base + ip_size - 4
        if first & 3 or not (ram or target):
            raise ValueError('F2 address must be an aligned APB or data-window RAM word')
    elif flow == 'F3':
        if first & 3 or not data_base <= first <= windows['ram_base'] + windows['ram_size'] - 4:
            raise ValueError('F3 address must be an aligned data-window RAM word')
    elif flow == 'F4':
        if first & 3 or not ip_base <= first <= ip_base + ip_size - 4:
            raise ValueError('F4 address must be an aligned word in the APB window')
    elif flow == 'P':
        if first != ip_base + pins['padin_offset']:
            raise ValueError('P needs the declared PADIN address as its first word')
    text = flow + ':' + ':'.join(format(value, '08x') for value in values)
    message = 'CASE ' + flow + ' ' + ' '.join(format(value, '08x') for value in values)
    return dict(flow=flow, fields=tuple(values), text=text, message=message)


def validate_record(record, *, isa, windows):
    """Reject an F1 word the fixed trampoline or the declared ISA cannot execute."""
    from scripts.run_inprocess_f1f4 import validate_record as validate_f1
    return validate_f1(record, isa=isa, windows=windows)


# ---------------------------------------------------------------------------
# The one RAM image
# ---------------------------------------------------------------------------
def _csr(address, source, operation=1, destination=0):
    if not 0 <= address < 1 << 12 or not 0 <= source < 32 or not 0 <= destination < 32:
        raise ValueError('fixed CSR operands are out of range')
    if operation not in (1, 2, 3, 5, 6, 7):
        raise ValueError('unsupported CSR operation')
    return (address << 20) | (source << 15) | (operation << 12) | (destination << 7) | 0x73


def build_firmware(layout, *, irq):
    """Assemble the one-time RAM image; nothing here changes per case."""
    from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _lw, _sw
    program = Program(layout['main'])
    program.emit(*_lui_addi_load(8, layout['mailbox']))
    program.mark('poll')
    program.emit(_lw(5, 8, 0))
    program.branch(5, 0, 'poll')
    for flow, target in (('F1', 'f1'), ('F2', 'f2'), ('F3', 'store'), ('F4', 'store'),
                         ('P', 'f2'), ('F5', 'f5')):
        if flow not in COMMANDS or (flow == 'F5' and irq is None):
            continue
        program.emit(_addi(6, 0, COMMANDS[flow]))
        program.branch(5, 6, target)
    program.jump('poll')
    program.mark('f1')
    program.emit(*_lui_addi_load(9, layout['slot']))
    program.emit(_jalr(0, 9))
    program.mark('f1_back')
    program.emit(_sw(0, 8, 0))
    program.jump('poll')
    program.mark('f2')
    program.emit(_lw(9, 8, 4), _lw(7, 9, 0), _sw(7, 8, 8), _sw(0, 8, 0))
    program.jump('poll')
    program.mark('store')
    program.emit(_lw(9, 8, 4), _lw(7, 8, 12), _sw(7, 9, 0), _sw(0, 8, 0))
    program.jump('poll')

    if irq is not None:
        # F5: publish the declared handler parameters, then perform the declared
        # trigger writes with the values this case put in the input block.
        program.mark('f5')
        program.emit(*_lui_addi_load(10, layout['flag']))
        program.emit(_sw(0, 10, 0))
        program.emit(*_lui_addi_load(9, layout['ip_base'] + irq['status_offset']))
        program.emit(_sw(9, 8, HB_STATUS))
        program.emit(*_lui_addi_load(9, layout['result_f5']))
        program.emit(_sw(9, 8, HB_RESULT))
        if irq['clear'] is not None:
            program.emit(*_lui_addi_load(9, layout['ip_base'] + irq['clear']['offset']))
            program.emit(_sw(9, 8, HB_CLEAR))
            program.emit(*_lui_addi_load(9, irq['clear']['value']))
            program.emit(_sw(9, 8, HB_CLEAR_VALUE))
        else:
            program.emit(_sw(0, 8, HB_CLEAR), _sw(0, 8, HB_CLEAR_VALUE))
        program.emit(*_lui_addi_load(11, layout['ip_base']))
        for index, offset in enumerate(irq['trigger_offsets']):
            program.emit(_lw(9, 8, INPUT_BLOCK + 4 * index))
            program.emit(_sw(9, 11, offset))
        program.mark('f5_wait')
        program.emit(_lw(9, 10, 0))
        program.branch(9, 0, 'f5_wait')
        program.emit(_sw(0, 8, 0))
        program.jump('poll')
    code = program.link()

    handler_code = b''
    if irq is not None:
        handler = Program(layout['handler'])
        handler.emit(_lw(12, 8, HB_STATUS))          # address of the declared status word
        handler.emit(_lw(13, 12, 0))                 # the real MMIO read that also clears
        handler.emit(_lw(14, 8, HB_RESULT))          # RAM cell that keeps the read value
        handler.emit(_sw(13, 14, 0))
        handler.emit(_lw(12, 8, HB_CLEAR))           # zero means "no extra clear declared"
        handler.branch(12, 0, 'ack')
        handler.emit(_lw(15, 8, HB_CLEAR_VALUE))
        handler.emit(_sw(15, 12, 0))
        handler.mark('ack')
        handler.emit(_lw(14, 8, HB_FLAG))
        handler.emit(_addi(15, 0, 1))
        handler.emit(_sw(15, 14, 0))
        handler.emit(MRET_WORD)
        handler_code = handler.link()

    slot = (b'\x13\x00\x00\x00'                   # host overwrites this word
            + _jal(layout['slot'] + 4, program.labels['f1_back']).to_bytes(4, 'little'))
    vector_words = ([_jal(layout['vector'], layout['handler'])]
                    + [0x00000013] * 10           # machine-external slot is vector + 11*4
                    + [_jal(layout['vector'] + 44, layout['handler'])])
    boot = Program(layout['boot'])
    boot.emit(*_lui_addi_load(8, layout['mailbox']))       # mailbox pointer before any IRQ
    boot.emit(*_lui_addi_load(3, layout['vector'] | 1))    # declared vector, vectored mode
    boot.emit(_csr(0x305, 3))
    boot.emit(*_lui_addi_load(3, 0x800))                   # mie.MEIE
    boot.emit(_csr(0x304, 3, 2))
    boot.emit(_addi(3, 0, 8))                              # mstatus.MIE
    boot.emit(_csr(0x300, 3, 2))
    boot.emit(_jal(boot.address, layout['main']))
    boot_code = boot.link()

    handler_block = bytearray(HANDLER_BLOCK_BYTES)
    flag_cell = HB_FLAG - HB
    handler_block[flag_cell:flag_cell + 4] = layout['flag'].to_bytes(4, 'little')
    data = b''.join(word.to_bytes(4, 'little') for word in DATA_WORDS)
    images = {layout['boot']: boot_code,
              layout['vector']: b''.join(word.to_bytes(4, 'little') for word in vector_words),
              layout['handler']: handler_code,
              layout['main']: code, layout['slot']: slot, layout['data_base']: data,
              layout['handler_block']: bytes(handler_block)}
    _check_spans(layout, {'boot': (layout['boot'], len(boot_code)),
                          'vector': (layout['vector'], len(vector_words) * 4),
                          'handler': (layout['handler'], len(handler_code)),
                          'main': (layout['main'], len(code)),
                          'slot': (layout['slot'], len(slot)),
                          'mailbox': (layout['mailbox'], MAILBOX_BYTES),
                          'handler_block': (layout['handler_block'], HANDLER_BLOCK_BYTES),
                          'data': (layout['data_base'], len(data)),
                          'result': (layout['result_f5'], 16)})
    if layout['handler_block'] != layout['mailbox'] + HB_STATUS:
        raise ValueError('the handler block must sit HB_STATUS into the mailbox')
    return dict(images=images, layout=layout, slot_return=program.labels['f1_back'],
                main_words=len(program.words), handler_words=len(vector_words))


def firmware_text(firmware):
    return ''.join(f'{address:x} {data.hex()}\n'
                   for address, data in sorted(firmware['images'].items()))


# ---------------------------------------------------------------------------
# Generated binding header
# ---------------------------------------------------------------------------
def render_bindings(config, cpu, ip, layout, profile, *, irq, pins, registers):
    """Bind generated model ports from the artifacts; nothing is inferred."""
    from scripts.prepare_inprocess_irq_bindings import identifier, one
    if cpu.get('kind') != 'obi_cpu':
        raise ValueError('unsupported: requires an OBI CPU model')
    if ip.get('kind') != 'apb_gpio':
        raise ValueError('unsupported: requires the PULP apb_gpio model')
    if ip.get('base_protocol_trace', {}).get('protocol') != 'apb3':
        raise ValueError('unsupported: the target declares no APB3 protocol trace')
    if any('driver_timing' in artifact for artifact in (cpu, ip)):
        raise ValueError('unsupported: timed models require a timing scheduler')

    def declared_clock(artifact):
        schedule = artifact.get('clock_schedule', {})
        clocks = schedule.get('clocks', [])
        if (len(clocks) != 1 or schedule.get('phase_policy') != 'all_low_then_half_period_toggle'
                or clocks[0].get('signal') != 'clk' or clocks[0].get('ratio') != 1
                or clocks[0].get('first_rising_fast_tick') != 1
                or clocks[0].get('half_period_fast_ticks') != 1
                or type(clocks[0].get('frequency_hz')) is not int
                or clocks[0]['frequency_hz'] <= 0):
            raise ValueError('unsupported: requires one simple clock per model')
        return clocks[0]['frequency_hz']

    if declared_clock(cpu) != declared_clock(ip):
        raise ValueError('unsupported: CPU and target clock frequencies differ')
    fields = {}
    try:
        for role in ('valid', 'trap', 'insn', 'pc_rdata'):
            fields['CPU_RVFI_' + role.upper()] = one(
                cpu['physical_exports'], physical_port='rvfi_' + role,
                direction='output')['runtime_name']
    except ValueError as error:
        raise ValueError('unsupported: F1 needs the CPU rvfi_* retirement probe (' + str(error) + ')')
    cpu_irq = one(cpu['physical_exports'], endpoint_id=profile.cpu.irq_entry_endpoint,
                  role=profile.cpu.irq_entry_role, direction='input')
    if cpu_irq['width'] != 1:
        raise ValueError('unsupported: requires a one-bit CPU IRQ input')
    if (profile.cpu.irq_entry_polarity != 'active_high'
            or profile.cpu.irq_semantics != 'machine_external'):
        raise ValueError('unsupported: requires an active-high machine-external CPU IRQ input')
    fields['CPU_IRQ'] = cpu_irq['runtime_name']
    take = [row for row in cpu.get('runtime_ports', [])
            if row.get('name') == 'probe_irq_taken_pre' and row.get('direction') == 'output']
    have_take = len(take) == 1
    if have_take:
        fields['CPU_IRQ_TAKE'] = 'probe_irq_taken_pre'
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    for channel in ('i', 'd'):
        for role in roles:
            fields['CPU_' + channel.upper() + '_' + role.upper()] = one(
                cpu['backend_ports'], channel=channel, role=role)['name']
    for role in roles:
        rows = [row for row in ip['backend_ports'] if row.get('role') == role
                and row.get('channel') != 'ip_protocol_trace']
        if len(rows) != 1:
            raise ValueError('unsupported: the target does not expose one ' + role + ' beat role')
        fields['IP_' + role.upper()] = rows[0]['name']
    signals = ip['base_protocol_trace'].get('signals', {})
    apb = ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata')
    missing = [role for role in apb if role not in signals]
    if missing:
        raise ValueError('unsupported: the APB3 trace lacks ' + ','.join(missing))
    for role in apb:
        fields['IP_TRACE_' + role.upper()] = signals[role]
    # The pin side: the two device-driven pin ports plus the synchronizer.
    for role, key in (('in', 'IP_PIN_IN'), ('out', 'IP_PIN_OUT'), ('dir', 'IP_PIN_DIR'),
                      ('in_sync', 'IP_PIN_IN_SYNC')):
        row = one(ip['physical_exports'], endpoint_id=pins['endpoint_id'], role=role)
        if row['direction'] not in ('input', 'output'):
            raise ValueError('unsupported: pin port direction for ' + role)
        if row['width'] != pins['width']:
            raise ValueError('unsupported: the generated pin port ' + role +
                             ' is not ' + str(pins['width']) + ' bits wide')
        fields[key] = row['runtime_name']
    probes = {'status': 'IP_PROBE_STATUS', 'padin_latch': 'IP_PROBE_PADIN_LATCH',
              'rise': 'IP_PROBE_RISE', 'fall': 'IP_PROBE_FALL', 'inten': 'IP_PROBE_INTEN'}
    for name, key in probes.items():
        row = one(ip['physical_exports'], physical_port='gpio_probe_' + name,
                  direction='output')
        fields[key] = row['runtime_name']
    have_irq = 0
    if irq is not None:
        source = one(ip['physical_exports'], physical_port=irq['port'], direction='output')
        if source['width'] <= 64 and source['bit_lo'] <= irq['bit'] <= source['bit_hi']:
            fields['IP_IRQ'] = source['runtime_name']
            have_irq = 1
        else:
            raise ValueError('unsupported: the declared IRQ bit is outside the sampled port')
    cpu_model = 'V' + identifier(cpu['module_name'])
    ip_model = 'V' + identifier(ip['module_name'])
    lines = ['#pragma once', f'#include "{cpu_model}.h"', f'#include "{ip_model}.h"',
             f'#define CPU_MODEL {cpu_model}', f'#define IP_MODEL {ip_model}',
             f'#define HAVE_IRQ_LINK {have_irq}', f'#define HAVE_CPU_TAKE {int(have_take)}',
             f'#define PAD_WIDTH {pins["width"]}',
             f'#define IP_PAD_EXT_DEFAULT 0x{pins["external_value"]:x}u',
             f'#define IP_PADIN_OFFSET {pins["padin_offset"]}u',
             f'#define IP_PADOUT_OFFSET {registers["PADOUT"]}u',
             f'#define IP_PADOUTSET_OFFSET {registers["PADOUTSET"]}u',
             f'#define IP_PADOUTCLR_OFFSET {registers["PADOUTCLR"]}u']
    lines += [f'#define {key} {identifier(value)}' for key, value in fields.items()]
    lines += [f'#define RAM_BASE {layout["ram_base"]}u', f'#define RAM_SIZE {layout["ram_size"]}u',
              f'#define IP_BASE 0x{layout["ip_base"]:x}u', f'#define IP_SIZE {layout["ip_size"]}u',
              f'#define SLOT_ADDRESS {layout["slot"]}u',
              f'#define MAILBOX_ADDRESS {layout["mailbox"]}u',
              f'#define DATA_BASE {layout["data_base"]}u']
    if irq is not None:
        lines += [f'#define IP_STATUS_OFFSET {irq["status_offset"]}u',
                  f'#define IP_TRIGGER_LAST_OFFSET {irq["trigger_offsets"][-1]}u',
                  f'#define IP_RESULT_ADDRESS {layout["result_f5"]}u',
                  f'#define FLAG_ADDRESS {layout["flag"]}u',
                  f'#define TRIGGER_COUNT {len(irq["trigger_offsets"])}u',
                  f'#define IP_IRQ_PULSE_TICKS {irq["pulse_ticks"]}u']
    for tag, artifact in (('CPU', cpu), ('IP', ip)):
        timing = artifact['plan']['timing']
        lines += [f'#define {tag}_RESET_ASSERT {timing["reset_assert_ticks"]}u',
                  f'#define {tag}_RESET_RELEASE {timing["reset_release_ticks"]}u']
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------
def _value(key, text):
    if text.startswith('0x'):
        return int(text, 16)
    if key.endswith('seconds'):
        try:
            return float(text)
        except ValueError:
            raise ValueError('invalid seconds value: ' + text)
    if text.isdigit():
        return int(text)
    return text


def _pairs(tokens):
    if len(tokens) % 2:
        raise ValueError('observation fields must be key/value pairs')
    fields = {}
    for position in range(0, len(tokens), 2):
        key = tokens[position]
        if key in fields:
            raise ValueError('duplicate observation field: ' + key)
        fields[key] = _value(key, tokens[position + 1])
    return fields


def parse_case_line(line, *, flows):
    tokens = line.split()
    if len(tokens) < 5 or tokens[0] != 'case':
        raise ValueError('not a case line')
    try:
        index = int(tokens[1])
    except ValueError:
        raise ValueError('case index is not an integer: ' + tokens[1])
    if tokens[2] not in ('observations_passed', 'failed'):
        raise ValueError('unsupported case status: ' + tokens[2])
    fields = _pairs(tokens[3:])
    if 'flow' not in fields or fields['flow'] not in flows:
        raise ValueError('case line lacks a supported flow tag')
    fields['index'] = index
    fields['status'] = tokens[2]
    return fields


def parse_summary_line(line):
    tokens = line.split()
    if len(tokens) < 3 or tokens[0] != 'summary':
        raise ValueError('not a summary line')
    fields = _pairs(tokens[2:])
    fields['status'] = tokens[1]
    return fields


def parse_run_log(text, *, flows):
    """Read the compact case/summary lines; anything else is not interpreted."""
    if type(text) is not str:
        raise ValueError('run log text required')
    cases, summary, installed, pin_events, irq_edges = [], None, [], 0, 0
    for line in text.splitlines():
        if line.startswith('case '):
            cases.append(parse_case_line(line, flows=flows))
        elif line.startswith('summary '):
            if summary is not None:
                raise ValueError('duplicate summary line')
            summary = parse_summary_line(line)
        elif line.startswith('pin '):
            pin_events += 1
        elif line.startswith('irq_edge '):
            irq_edges += 1
        elif line.startswith('CASE_INSTALLED '):
            installed.append(int(line.split()[1]))
    if summary is None:
        raise ValueError('run log has no summary line')
    return dict(cases=cases, summary=summary, installed=installed,
                pin_events=pin_events, irq_edges=irq_edges)


def case_document(record, case):
    """One case: the input, the real observations and the time it took."""
    observation = {key: case.get(key, 'unknown')
                   for key in CASE_OBSERVATION_KEYS[record['flow']]}
    observation.update({key: case.get(key, 'unknown') for key in CASE_PIN_KEYS})
    observation.update({key: case.get(key, 'unknown') for key in CASE_COUNTER_KEYS})
    return dict(index=case['index'], flow=case['flow'], record=record['text'],
                input=case.get('record', 'unknown'),
                status=case['status'], ticks=case.get('ticks', 'unknown'),
                seconds=case.get('seconds', 'unknown'), observation=observation)


def _expected_out(offset, before, value, registers):
    """The PADOUT-family semantics applied to the output value seen before."""
    if offset == registers['PADOUT']:
        return value
    if offset == registers['PADOUTSET']:
        return before | value
    if offset == registers['PADOUTCLR']:
        return before & ~value
    return before


def correspondence(record, case, *, layout, windows, irq, pins):
    """Check that the observed facts belong to the input that was handed over.

    This re-reads the native report; it never derives a fact from the profile.
    Returns None when every checked fact matches, or the first mismatch.
    """
    if case['flow'] != record['flow']:
        return 'flow differs from the input'
    if case.get('record') != record['text']:
        return 'echoed record differs from the input'
    first = record['fields'][0]
    if record['flow'] == 'F1':
        if case.get('fetch') != layout['slot']:
            return 'F1 fetch address is not the trampoline slot'
        if case.get('retire_pc') != layout['slot'] or case.get('retire_insn') != first:
            return 'F1 retired word differs from the input'
        if case.get('successor_pc') != layout['slot'] + 4:
            return 'F1 has no observed successor'
        return None
    if record['flow'] == 'F2':
        if case.get('read_addr') != first:
            return 'F2 read address differs from the input'
        if case.get('echo_value') != case.get('read_value'):
            return 'F2 CPU did not commit the returned word'
        if case.get('read_from') == 'apb':
            if case.get('apb_rdata') != case.get('read_value'):
                return 'F2 APB read data differs from the CPU response'
            if case.get('apb_reads') != 1:
                return 'F2 expected exactly one APB transfer'
            if (first - windows['ip_base'] == pins['padin_offset']
                    and case.get('read_value') != case.get('padin_latch')):
                return 'F2 PADIN read differs from the device synchronizer latch'
        elif case.get('read_from') != 'ram' or case.get('apb_reads') != 0:
            return 'F2 read was not a plain RAM read'
        return None
    if record['flow'] == 'P':
        if case.get('read_addr') != first:
            return 'P read address differs from the input'
        if case.get('read_from') != 'apb' or case.get('apb_reads') != 1:
            return 'P did not complete exactly one APB read'
        if case.get('ext_value') != record['fields'][1]:
            return 'P external pin value differs from the input'
        if case.get('echo_value') != case.get('read_value'):
            return 'P CPU did not commit the value it read'
        if case.get('read_value') != case.get('padin_latch'):
            return 'P PADIN read differs from the device synchronizer latch'
        if case.get('read_value') != case.get('pad_at_read'):
            return 'P PADIN read differs from the pad the host resolved'
        if ((case.get('pad_at_read') & ~case.get('dir_after') & 0xFFFFFFFF)
                != (record['fields'][1] & ~case.get('dir_after') & 0xFFFFFFFF)):
            return 'P the host driver value did not reach the input pins'
        return None
    if record['flow'] == 'F3':
        if case.get('write_addr') != first or case.get('write_value') != record['fields'][1]:
            return 'F3 write differs from the input'
        if case.get('write_be') != 15 or case.get('ram_after') != record['fields'][1]:
            return 'F3 RAM did not commit the input word'
        return None
    if record['flow'] == 'F4':
        offset, value = first - windows['ip_base'], record['fields'][1]
        if case.get('mmio_addr') != first or case.get('mmio_value') != value:
            return 'F4 MMIO write differs from the input'
        if (case.get('apb_offset') != offset or case.get('apb_pready') != 1
                or case.get('apb_pwdata') != value or case.get('apb_writes') != 1):
            return 'F4 APB transfer differs from the input'
        expected = (_expected_out(offset, case.get('out_before'), value, registers_of(windows))
                    & 0xFFFFFFFF)
        if case.get('out_after') != expected:
            return 'F4 sampled gpio_out does not follow the written register'
        if ((case.get('pad_after') & case.get('dir_after'))
                != (expected & case.get('dir_after'))):
            return 'F4 device-driven pads do not show the written output'
        if ((case.get('pad_after') & ~case.get('dir_after') & 0xFFFFFFFF)
                != (case.get('ext_value') & ~case.get('dir_after') & 0xFFFFFFFF)):
            return 'F4 host-driven pads changed without a host stimulus'
        return None
    if case.get('apb_writes') != len(irq['trigger_offsets']):
        return 'F5 did not complete every declared trigger write'
    if case.get('apb_last_write_offset') != irq['trigger_offsets'][-1]:
        return 'F5 last trigger write address differs from the declaration'
    if case.get('apb_last_write_data') != record['fields'][-1]:
        return 'F5 last trigger value differs from the input'
    if case.get('apb_reads') != 1 or case.get('apb_read_offset') != irq['status_offset']:
        return 'F5 handler did not read the declared status register'
    if case.get('isr_result') != case.get('apb_read_data'):
        return 'F5 handler store differs from the status value it read'
    if case.get('isr_flag') != 1:
        return 'F5 handler did not complete'
    if not (case.get('irq_edges') >= 1 and case.get('irq_takes') >= 1):
        return 'F5 has no sampled device IRQ edge and CPU take'
    if not case.get('pad_rise_events'):
        return 'F5 no pin transition was observed on the sampled pads'
    if case.get('first_irq_tick') < case.get('first_rise_tick'):
        return 'F5 the interrupt preceded the pin transition it is attributed to'
    if not (case.get('irq_cause_pins') & case.get('inten_at_irq')):
        return 'F5 the asserted interrupt has no enabled pin in its cause mask'
    return None


_REGISTER_NAMES = ('PADDIR', 'GPIOEN', 'PADIN', 'PADOUT', 'PADOUTSET', 'PADOUTCLR', 'INTEN',
                   'INTTYPE_LOW', 'INTTYPE_HIGH', 'INTSTATUS', 'PADCFG_0')


def registers_of(windows):
    """The reviewed PULP apb_gpio offsets this host reasons about."""
    return {name: windows['registers'][name] for name in
            ('PADOUT', 'PADOUTSET', 'PADOUTCLR')}


def final_status(result, parsed, records):
    if result['returncode'] != 0:
        return 'failed'
    if parsed is None or parsed['summary'].get('status') != 'observations_passed':
        return 'failed'
    if len(parsed['cases']) != len(records):
        return 'failed'
    if any(case['status'] != 'observations_passed' for case in parsed['cases']):
        return 'failed'
    return 'observations_passed'


def self_rate(artifact):
    clocks = artifact.runtime_document['clock_schedule']['clocks']
    return clocks[0]['frequency_hz'] if len(clocks) == 1 else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True,
                        help='CPU + APB3 GPIO + pad declaration with explicit timing')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory inside the workspace')
    parser.add_argument('--records', required=True,
                        help='comma-separated records, e.g. '
                             'F4:4000000c:0000002a,P:40000008:000000aa')
    parser.add_argument('--online', action='store_true',
                        help='hand over one record per NEED_RECORD instead of preloading all')
    parser.add_argument('--max-ticks', type=int, default=20000)
    args = parser.parse_args(argv)
    if args.max_ticks < 1:
        parser.error('--max-ticks must be positive')
    try:
        config = json.loads(args.config.read_text())
    except (OSError, ValueError) as error:
        parser.error('cannot read the declaration: ' + str(error))
    if args.output.exists():
        parser.error('output directory already exists')

    from myfuzz.composition.component_profile import (elaboration_mode_scope,
                                                      load_component_profile)
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.isa.constraints import f1_isa_from_profile
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.run_inprocess_f1f4 import cpu_request_from_config
    from scripts.run_timer_irq_smoke import timer_artifact

    started = time.monotonic()
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            harness_validation_scope(), execution_validation_scope():
        cpu_request_path = (args.output / 'cpu_request.json').resolve()
        cpu_request_path.write_text(json.dumps(cpu_request_from_config(config), indent=2) + '\n')
        timing = explicit_timing(config, 'source_timing')
        tuning = dict(config.get('source_tuning') or {})
        tuning.setdefault('raw_tick_stream', [dict(sampling='pre_post')])
        source_request_path = (args.output / 'source_request.json').resolve()
        source_request_path.write_text(json.dumps(
            dict(schema_version='local_harness.v2', profile_path=config['source_profile'],
                 instance_id=config['active_id'], **timing, tuning=tuning),
            indent=2) + '\n')
        cpu = timer_artifact(ROOT, str(cpu_request_path), 'cpu')
        ip = timer_artifact(ROOT, str(source_request_path), config['active_id'])

        ip_profile = ip.plan.profile
        irq = irq_declaration(config, ip_profile)
        pins = pin_declaration(config, ip_profile)
        windows = declared_windows(config)
        windows['registers'] = {name: _reviewed_offset(ip_profile, name, config)
                                for name in _REGISTER_NAMES}
        arity = flow_arity(irq)
        records = [parse_record(text, windows=windows, arity=arity, pins=pins)
                   for text in args.records.split(',')]
        boot = source_backed_boot_fetch(
            cpu.plan.profile, base_dir=ROOT,
            configured_boot_base=cpu.runtime_document['boot_contract']['configured_boot_base'])
        isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
        for record in records:
            validate_record(record, isa=isa, windows=windows)
        layout = build_layout(windows, boot)
        firmware = build_firmware(layout, irq=irq)
        header = render_bindings(config, cpu.runtime_document, ip.runtime_document,
                                 layout, cpu.plan.profile, irq=irq, pins=pins,
                                 registers=windows['registers'])
        (args.output / 'spike_config.h').write_text(header)
        (args.output / 'firmware.txt').write_text(firmware_text(firmware))
        submitted = []
        runner = incremental_runner([record['message'] for record in records], submitted) \
            if args.online else None
        result = build_link_run((cpu, ip),
                                ROOT / 'scripts/inprocess_obi_apb_gpio_spike.cpp',
                                args.output, args.cache,
                                run_arguments(args.output, records, args.online, args.max_ticks),
                                root=ROOT, runner=runner)
        log = (args.output / 'run.log').read_text()
        try:
            parsed, failure = parse_run_log(log, flows=arity), None
        except ValueError as error:
            parsed, failure = None, 'run log unreadable: ' + str(error)
        cases = [] if parsed is None else parsed['cases']
        verified, checks = [], []
        for record, case in zip(records, cases):
            document = case_document(record, case)
            mismatch = correspondence(record, case, layout=layout, windows=windows,
                                      irq=irq, pins=pins)
            document['correspondence'] = 'matched' if mismatch is None else 'mismatched'
            if mismatch is not None:
                document['correspondence_reason'] = mismatch
            verified.append(document)
            checks.append(mismatch)
        result.update(
            scope='one OBI CPU + the pinned PULP APB3 GPIO + a host pad model receiving '
                  'F1-F5 and the P pin flow in one process; compact observations only',
            preparation_scope='two component profiles only; no TL-UL GPIO, no full D3, no '
                              'scenario search and no replay',
            input_mode='incremental' if args.online else 'preloaded',
            input_channel='held-RAM-mailbox + instruction trampoline slot + host external pin driver',
            records=[record['text'] for record in records],
            submitted=submitted if args.online else [record['text'] for record in records],
            cases=verified,
            run_summary=None if parsed is None else parsed['summary'],
            installed=None if parsed is None else parsed['installed'],
            pin_events=None if parsed is None else parsed['pin_events'],
            cpu_instance='cpu', ip_instance=config['active_id'],
            components=dict(
                cpu=dict(profile=config['cpu_profile'], model=cpu.runtime_document['module_name'],
                         declared_hz=self_rate(cpu)),
                target=dict(profile=config['source_profile'],
                            model=ip.runtime_document['module_name'],
                            declared_hz=self_rate(ip))),
            clock_assumption=('one host tick for both models; declared rates ' +
                              '/'.join(str(self_rate(row)) for row in (cpu, ip)) + ' Hz'),
            pin_model=dict(endpoint=pins['endpoint_id'], width=pins['width'],
                           padin_offset=pins['padin_offset'],
                           external_value=pins['external_value'],
                           resolution='device drives a pad while its dir bit is high; the host '
                                      'drives the remaining pins with the declared value',
                           sampling='gpio_out/gpio_dir/gpio_in_sync sampled every tick from the '
                                    'device ports; synchronizer, transition and interrupt '
                                    'probes sampled from the authenticated probe contract',
                           stimulus='flow P rewrites the host driver value before the CPU reads '
                                    'PADIN; no other case moves it',
                           status='observed'),
            irq_sources=[] if irq is None else [
                dict(index=0, device='target', port=irq['port'], bit=irq['bit'],
                     trigger=irq['trigger'], polarity=irq['polarity'],
                     delivery_ticks=irq['pulse_ticks'], status_offset=irq['status_offset'],
                     trigger_offsets=irq['trigger_offsets'], clear=irq['clear'])],
            ram=dict(base=windows['ram_base'], size=windows['ram_size']),
            ip_window=dict(base=windows['ip_base'], size=windows['ip_size']),
            registers=dict(windows['registers']),
            layout=firmware['layout'], slot_return=firmware['slot_return'],
            irq_delivery='observed' if parsed is not None else 'unknown',
            combination_specific_branches='none: wiring comes from the generated binding '
                                          'header and the declared device behavior',
            limitations=[
                'one host tick drives both models; declared clock rates are not modelled',
                'the pad has exactly two drivers: the device while its dir bit is high, the '
                'host driver value otherwise; no contention, no pull-up and no pad delay '
                'beyond the device\'s own two-stage synchronizer',
                'only the 32 low pads are resolved (PAD_NUM = 32)',
                'full-word transfers only: partial byte enables are refused, not emulated',
                'a pulse source is stretched to its declared delivery width by the host',
                'no feedback-driven input, certificate or replay in this entry'],
            certificate='none', replay='not_performed',
            total_seconds=time.monotonic() - started)
        if failure is not None:
            result['failure'] = failure
        mismatched = [mismatch for mismatch in checks if mismatch is not None]
        result['status'] = final_status(result, parsed, records)
        if result['status'] == 'observations_passed' and (mismatched or len(cases) != len(records)):
            result['status'] = 'failed'
            result['failure'] = 'correspondence: ' + mismatched[0] if mismatched else 'case count'
        (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'output': str(args.output),
                          'cases': len(verified), 'run_seconds': result['run_seconds'],
                          'total_seconds': result['total_seconds']}))
        return 0 if result['status'] == 'observations_passed' else 1


def _reviewed_offset(ip_profile, name, config):
    """One register offset, from the profile's own map, checked against config."""
    registers = {row.name: row.offset for row in ip_profile.address.registers}
    offset = registers.get(name)
    declared = (config.get('registers') or {}).get(name)
    if offset is None:
        raise ValueError('unsupported: the target declares no ' + name + ' register')
    if declared is not None and declared != offset:
        raise ValueError('config registers.' + name + ' disagrees with the target profile')
    return offset


if __name__ == '__main__':
    raise SystemExit(main())
