#!/usr/bin/env python3
"""Build and run one process that receives F1-F4 inputs on OBI CPU + APB IP.

One OBI CPU model and one APB3 target model are initialized once next to the
host RAM.  The CPU executes a fixed polling program from that RAM, so a case is
handed over by writing one mailbox word (or the instruction trampoline slot for
F1); no case recompiles, re-initializes or resets either model.  The host
reports only what the two models actually did: the fetched/retired addresses,
the data-bus handshakes, the RAM read/write and the completed APB transfers.

F5 (IRQ delivery) and F6 (DMA) are not wired here and stay unknown.  The result
is a compact observation, not a certificate and not a replay.
"""
import argparse
from pathlib import Path
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

# Fixed offsets of the one RAM image.  The program, the trampoline slot, the
# park loop and the mailbox never move; only the slot word and the three
# mailbox cells change per case.
MAIN_OFFSET = 0x1000
SLOT_OFFSET = 0x2000
PARK_OFFSET = 0x2100
MAILBOX_OFFSET = 0x3000
DATA_OFFSET = 0x4000
DATA_WORDS = (0xDEADBEEF, 0x11111111, 0x00000000)
FLOW_ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}
CASE_OBSERVATION_KEYS = {
    'F1': ('fetch', 'retire_pc', 'retire_insn', 'successor_pc'),
    'F2': ('read_addr', 'read_value', 'echo_value', 'read_from', 'apb_rdata'),
    'F3': ('write_addr', 'write_value', 'write_be', 'ram_before', 'ram_after'),
    'F4': ('mmio_addr', 'mmio_value', 'apb_offset', 'apb_pwdata', 'apb_pready'),
}
CASE_COUNTER_KEYS = ('i_fetches', 'd_reads', 'd_writes', 'apb_reads', 'apb_writes')


def declared_windows(config):
    """The RAM and APB windows this host routes between, from the declaration."""
    window = config.get('target_window')
    ram_base, ram_end = config.get('image_start'), config.get('image_end')
    if any(type(value) is not int for value in (ram_base, ram_end)):
        raise ValueError('config requires integer image_start and image_end')
    if not isinstance(window, dict) or any(type(window.get(key)) is not int
                                          for key in ('base', 'size')):
        raise ValueError('config requires a declared APB target_window')
    if (ram_base % 4 or ram_end - ram_base < DATA_OFFSET + 4 * len(DATA_WORDS)
            or window['base'] % 4 or window['size'] < 4 or window['base'] + window['size'] > 1 << 32):
        raise ValueError('declared RAM or APB window is unusable for this host')
    return dict(ram_base=ram_base, ram_size=ram_end - ram_base,
                ip_base=window['base'], ip_size=window['size'],
                data_base=ram_base + DATA_OFFSET)


def build_layout(windows, boot):
    """Every fixed address of the one RAM image, checked for overlap."""
    layout = dict(boot=boot, main=windows['ram_base'] + MAIN_OFFSET,
                  slot=windows['ram_base'] + SLOT_OFFSET,
                  park=windows['ram_base'] + PARK_OFFSET,
                  mailbox=windows['ram_base'] + MAILBOX_OFFSET,
                  data_base=windows['data_base'],
                  data_end=windows['ram_base'] + windows['ram_size'],
                  ram_base=windows['ram_base'], ram_size=windows['ram_size'],
                  ip_base=windows['ip_base'], ip_size=windows['ip_size'])
    if boot % 4 or not windows['ram_base'] <= boot <= windows['ram_base'] + windows['ram_size'] - 4:
        raise ValueError('the declared CPU boot address is not an aligned RAM word')
    return layout


def _check_spans(layout, spans):
    """Refuse a RAM image whose fixed regions overlap or leave the window."""
    low, high = layout['ram_base'], layout['data_end']
    ordered = sorted((start, start + size, name) for name, (start, size) in spans.items())
    for start, end, name in ordered:
        if start < low or end > high:
            raise ValueError(name + ' leaves the declared RAM')
    for (_, end, name), (next_start, _, next_name) in zip(ordered, ordered[1:]):
        if next_start < end:
            raise ValueError(name + ' overlaps ' + next_name)


def parse_record(text, *, windows):
    """Turn one operator record into the exact input this host will hand over."""
    if type(text) is not str or not text:
        raise ValueError('one F1-F4 record text is required')
    fields = text.split(':')
    flow = fields[0]
    if flow not in FLOW_ARITY:
        raise ValueError('unsupported flow tag: ' + flow)
    if len(fields) - 1 != FLOW_ARITY[flow]:
        raise ValueError(flow + ' needs ' + str(FLOW_ARITY[flow]) + ' word(s)')
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
    else:
        if first & 3 or not ip_base <= first <= ip_base + ip_size - 4:
            raise ValueError('F4 address must be an aligned word in the APB window')
    text = flow + ':' + ':'.join(format(value, '08x') for value in values)
    message = 'CASE ' + flow + ' ' + ' '.join(format(value, '08x') for value in values)
    return dict(flow=flow, fields=tuple(values), text=text, message=message)


def validate_record(record, *, isa, windows):
    """Reject an F1 word the fixed trampoline or the declared ISA cannot execute.

    The instruction subset is the existing F1 legality gate, narrowed to what one
    straight-line word in a trampoline slot can do without escaping it.
    """
    from myfuzz.scenario.rv32i_sources import validate_instruction_bytes
    if record['flow'] != 'F1':
        return record
    word = record['fields'][0]
    if word & 3 != 3:
        raise ValueError('F1 requires one 32-bit instruction; compressed input is unsupported')
    validate_instruction_bytes(word.to_bytes(4, 'little'), isa=isa)
    opcode, rd = word & 0x7F, (word >> 7) & 31
    if opcode not in (0x37, 0x17, 0x13, 0x33):
        raise ValueError('F1 opcode 0x%02x is outside the executed ALU subset '
                         '(no memory, control-flow or CSR word in the trampoline)' % opcode)
    if rd == 8:
        raise ValueError('F1 instruction may not overwrite the fixed mailbox register x8')
    return record


def _jalr(rd, rs1, immediate=0):
    if any(type(value) is not int for value in (rd, rs1, immediate)):
        raise ValueError('fixed JALR operands must be integers')
    if not 0 <= rd < 32 or not 0 <= rs1 < 32 or not -2048 <= immediate < 2048:
        raise ValueError('fixed JALR operands are out of range')
    word = ((immediate & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x67
    decoded = (word >> 20) & 0xfff
    decoded = decoded - 4096 if decoded & 2048 else decoded
    if decoded != immediate or word & 0x7f != 0x67:
        raise ValueError('fixed JALR encoding does not round-trip')
    return word


def _csrrw(destination, address, source):
    if not 0 <= address < 1 << 12 or not 0 <= source < 32 or not 0 <= destination < 32:
        raise ValueError('fixed CSRRW operands are out of range')
    return (address << 20) | (source << 15) | (1 << 12) | (destination << 7) | 0x73


class Program:
    """Tiny label assembler for the two fixed RAM programs."""

    def __init__(self, base):
        self.base = base
        self.words = []
        self.labels = {}
        self.pending = []

    @property
    def address(self):
        return self.base + 4 * len(self.words)

    def mark(self, name):
        if name in self.labels:
            raise ValueError('duplicate program label: ' + name)
        self.labels[name] = self.address

    def emit(self, *words):
        for word in words:
            if type(word) is not int or not 0 <= word < 1 << 32:
                raise ValueError('program word is not a 32-bit integer')
            self.words.append(word)

    def jump(self, name):
        self.pending.append(('jal', len(self.words), self.address, name))
        self.words.append(0)

    def branch(self, rs1, rs2, name, *, funct3=0):
        # funct3 0 is BEQ, 1 is BNE: the only two conditional forms the fixed
        # firmware uses.  A bounded wait loop needs the BNE form.
        self.pending.append((('branch', rs1, rs2, funct3), len(self.words),
                             self.address, name))
        self.words.append(0)

    def link(self):
        from myfuzz.integration.rv32_fixed_firmware import _branch, _jal
        for kind, index, pc, name in self.pending:
            if name not in self.labels:
                raise ValueError('unresolved program label: ' + name)
            target = self.labels[name]
            self.words[index] = (_jal(pc, target) if kind == 'jal'
                                 else _branch(kind[1], kind[2], target - pc,
                                              funct3=kind[3]))
        return b''.join(word.to_bytes(4, 'little') for word in self.words)


def build_firmware(layout):
    """Assemble the one-time RAM image; nothing here changes per case."""
    from myfuzz.integration.rv32_fixed_firmware import (_addi, _jal, _lui_addi_load,
                                                        _lw, _sw)
    program = Program(layout['main'])
    program.emit(*_lui_addi_load(8, layout['mailbox']))   # x8 = mailbox, never clobbered
    program.mark('poll')
    program.emit(_lw(5, 8, 0))                            # x5 = command word
    program.branch(5, 0, 'poll')
    program.emit(_addi(6, 0, 1))
    program.branch(5, 6, 'f1')
    program.emit(_addi(6, 0, 2))
    program.branch(5, 6, 'f2')
    program.emit(_addi(6, 0, 3))
    program.branch(5, 6, 'store')
    program.emit(_addi(6, 0, 4))
    program.branch(5, 6, 'store')
    program.jump('poll')                                  # unknown command: keep polling
    program.mark('f1')
    program.emit(*_lui_addi_load(9, layout['slot']))
    program.emit(_jalr(0, 9))                             # a real indirect fetch of the slot
    program.mark('f1_back')
    program.emit(_sw(0, 8, 0))                            # the CPU's own completion store
    program.jump('poll')
    program.mark('f2')
    program.emit(_lw(9, 8, 4), _lw(7, 9, 0), _sw(7, 8, 8), _sw(0, 8, 0))
    program.jump('poll')
    program.mark('store')                                 # F3 and F4 share one store body;
    program.emit(_lw(9, 8, 4), _lw(7, 8, 12), _sw(7, 9, 0), _sw(0, 8, 0))  # the routed
    program.jump('poll')                                  # address selects RAM or APB
    code = program.link()
    slot = (b'\x13\x00\x00\x00'                           # host overwrites this word
            + _jal(layout['slot'] + 4, program.labels['f1_back']).to_bytes(4, 'little'))
    boot = b''.join(word.to_bytes(4, 'little') for word in (*_lui_addi_load(3, layout['park']),
                                                            _csrrw(0, 0x305, 3)))
    boot += _jal(layout['boot'] + len(boot), layout['main']).to_bytes(4, 'little')
    data = b''.join(word.to_bytes(4, 'little') for word in DATA_WORDS)
    images = {layout['boot']: boot, layout['main']: code, layout['slot']: slot,
              layout['park']: _jal(layout['park'], layout['park']).to_bytes(4, 'little'),
              layout['data_base']: data}
    _check_spans(layout, {'boot': (layout['boot'], len(boot)),
                          'main': (layout['main'], len(code)),
                          'slot': (layout['slot'], len(slot)),
                          'park': (layout['park'], 4),
                          'mailbox': (layout['mailbox'], 16),
                          'data': (layout['data_base'], len(data))})
    if layout['mailbox'] + 16 > layout['data_base']:
        raise ValueError('the mailbox overlaps the data window')
    return dict(images=images, layout=layout, slot_return=program.labels['f1_back'],
                main_words=len(program.words))


def firmware_text(firmware):
    return ''.join(f'{address:x} {data.hex()}\n' for address, data in sorted(firmware['images'].items()))


def render_bindings(config, cpu, ip, layout, profile):
    """Bind generated model ports from the two artifacts; nothing is inferred."""
    from scripts.prepare_inprocess_irq_bindings import identifier, one
    if cpu.get('kind') != 'obi_cpu' or ip.get('kind') != 'apb3_register_observe':
        raise ValueError('unsupported: requires an OBI CPU and an APB3 register target')
    if ip.get('base_protocol_trace', {}).get('protocol') != 'apb3':
        raise ValueError('unsupported: the target declares no APB3 protocol trace')
    if 'driver_timing' in cpu or 'driver_timing' in ip:
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
                cpu['physical_exports'], physical_port='rvfi_' + role, direction='output')['runtime_name']
    except ValueError as error:
        raise ValueError('unsupported: F1 needs the CPU rvfi_* retirement probe (' + str(error) + ')')
    irq_input = one(cpu['physical_exports'], endpoint_id=profile.cpu.irq_entry_endpoint,
                    role=profile.cpu.irq_entry_role, direction='input')
    if irq_input['width'] != 1:
        raise ValueError('unsupported: requires a one-bit CPU IRQ input')
    fields['CPU_IRQ'] = irq_input['runtime_name']
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    for channel in ('i', 'd'):
        for role in roles:
            fields['CPU_' + channel.upper() + '_' + role.upper()] = one(
                cpu['backend_ports'], channel=channel, role=role)['name']
    for role in roles:
        fields['IP_' + role.upper()] = one(ip['backend_ports'], channel='reg', role=role)['name']
    signals = ip['base_protocol_trace'].get('signals', {})
    apb = ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata')
    missing = [role for role in apb if role not in signals]
    if missing:
        raise ValueError('unsupported: the APB3 trace lacks ' + ','.join(missing))
    for role in apb:
        fields['IP_TRACE_' + role.upper()] = signals[role]
    ip_irq_bit = None
    if config.get('source_port'):
        try:
            source = one(ip['physical_exports'], physical_port=config['source_port'],
                         direction='output')
        except ValueError:
            source = None
        bit = config.get('source_bit_offset', 0)
        if (source is not None and type(bit) is int and source['width'] <= 64
                and source['bit_lo'] <= bit <= source['bit_hi']):
            fields['IP_IRQ'] = source['runtime_name']
            ip_irq_bit = bit - source['bit_lo']
    cpu_model, ip_model = 'V' + identifier(cpu['module_name']), 'V' + identifier(ip['module_name'])
    lines = ['#pragma once', f'#include "{cpu_model}.h"', f'#include "{ip_model}.h"',
             f'#define CPU_MODEL {cpu_model}', f'#define IP_MODEL {ip_model}']
    lines += [f'#define {key} {identifier(value)}' for key, value in fields.items()]
    lines += [f'#define HAVE_IP_IRQ {int(ip_irq_bit is not None)}',
              f'#define IP_IRQ_BIT {ip_irq_bit if ip_irq_bit is not None else 0}',
              f'#define RAM_BASE {layout["ram_base"]}u', f'#define RAM_SIZE {layout["ram_size"]}u',
              f'#define IP_BASE 0x{layout["ip_base"]:x}u', f'#define IP_SIZE {layout["ip_size"]}u',
              f'#define BOOT_ADDRESS {layout["boot"]}u', f'#define MAIN_ADDRESS {layout["main"]}u',
              f'#define SLOT_ADDRESS {layout["slot"]}u', f'#define PARK_ADDRESS {layout["park"]}u',
              f'#define MAILBOX_ADDRESS {layout["mailbox"]}u',
              f'#define DATA_BASE {layout["data_base"]}u']
    for tag, artifact in (('CPU', cpu), ('IP', ip)):
        timing = artifact['plan']['timing']
        lines += [f'#define {tag}_RESET_ASSERT {timing["reset_assert_ticks"]}u',
                  f'#define {tag}_RESET_RELEASE {timing["reset_release_ticks"]}u']
    return '\n'.join(lines) + '\n'


def explicit_timing(config, key):
    timing = config.get(key)
    names = ('reset_assert_ticks', 'reset_release_ticks', 'max_wait_cycles')
    if not isinstance(timing, dict) or any(type(timing.get(name)) is not int for name in names):
        raise ValueError(key + ' requires explicit reset_assert_ticks, reset_release_ticks '
                              'and max_wait_cycles')
    return {name: timing[name] for name in names}


def cpu_request_from_config(config):
    # The instance id is the generated module name.  It defaults to 'cpu' so
    # every existing scenario keeps its cache key; a pinned archive whose model
    # was generated under another id (CVA6's 'processor') names it explicitly.
    return dict(schema_version='local_harness.v1', profile_path=config['cpu_profile'],
                instance_id=config.get('cpu_instance_id', 'cpu'),
                **explicit_timing(config, 'cpu_timing'))


def source_request_from_profile(config):
    """Make the existing APB request from a profile and explicit timing."""
    timing = explicit_timing(config, 'source_timing')
    profile = json.loads((ROOT / config['source_profile']).read_text())
    endpoints = [row for row in profile['endpoints'] if row.get('function') == 'mmio_slave'
                 and row.get('protocol') == ['apb', '3']]
    if len(endpoints) != 1:
        raise ValueError('source_profile requires exactly one APB3 MMIO endpoint')
    tuning = dict(config.get('source_tuning', {}))
    tuning.setdefault('endpoint_policies', [dict(endpoint_id=endpoints[0]['endpoint_id'],
                                                 template_id='target.apb3', template_version='1',
                                                 variant_id='full-word', max_outstanding=1)])
    return dict(schema_version='local_harness.v2', profile_path=config['source_profile'],
                instance_id=config['active_id'], **timing, tuning=tuning)


def run_arguments(output, records, online, max_ticks):
    encoded = '--online' if online else ','.join(record['text'] for record in records)
    return [(output / 'firmware.txt').resolve(), encoded, max_ticks]


def incremental_runner(messages, submitted):
    """Forward one record per request without restarting or resetting a model."""
    def run(command, log_path):
        with log_path.open('w') as log:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, bufsize=1)
            try:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    print(line, end='', flush=True)
                    if not line.startswith('NEED_RECORD '):
                        continue
                    index = int(line.split()[1])
                    if index != len(submitted):
                        raise RuntimeError('host requested an out-of-order F1-F4 record')
                    if index >= len(messages):
                        process.stdin.write('END\n')
                        process.stdin.flush()
                        continue
                    process.stdin.write(messages[index] + '\n')
                    process.stdin.flush()
                    submitted.append(messages[index].split()[1])
                return process.wait()
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait()
    return run


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


def parse_case_line(line):
    """Parse one `case <index> <status> <key> <value> ...` line."""
    tokens = line.split()
    if len(tokens) < 5 or tokens[0] != 'case':
        raise ValueError('not a F1-F4 case line')
    try:
        index = int(tokens[1])
    except ValueError:
        raise ValueError('case index is not an integer: ' + tokens[1])
    if tokens[2] not in ('observations_passed', 'failed'):
        raise ValueError('unsupported case status: ' + tokens[2])
    fields = _pairs(tokens[3:])
    if 'flow' not in fields or fields['flow'] not in FLOW_ARITY:
        raise ValueError('case line lacks a supported flow tag')
    fields['index'] = index
    fields['status'] = tokens[2]
    return fields


def parse_summary_line(line):
    tokens = line.split()
    if len(tokens) < 3 or tokens[0] != 'summary':
        raise ValueError('not a F1-F4 summary line')
    fields = _pairs(tokens[2:])
    fields['status'] = tokens[1]
    return fields


def parse_run_log(text):
    """Read the compact case/summary lines; anything else is not interpreted."""
    if type(text) is not str:
        raise ValueError('run log text required')
    cases, summary, installed = [], None, []
    for line in text.splitlines():
        if line.startswith('case '):
            cases.append(parse_case_line(line))
        elif line.startswith('summary '):
            if summary is not None:
                raise ValueError('duplicate summary line')
            summary = parse_summary_line(line)
        elif line.startswith('CASE_INSTALLED '):
            installed.append(int(line.split()[1]))
        elif line.startswith('NEED_RECORD '):
            continue
    if summary is None:
        raise ValueError('run log has no summary line')
    return dict(cases=cases, summary=summary, installed=installed)


def case_document(record, case):
    """One case: the input, the real observations and the time it took."""
    observation = {key: case.get(key, 'unknown') for key in CASE_OBSERVATION_KEYS[record['flow']]}
    observation.update({key: case.get(key, 'unknown') for key in CASE_COUNTER_KEYS})
    return dict(index=case['index'], flow=case['flow'], record=record['text'],
                input=case.get('record', 'unknown'),
                status=case['status'], ticks=case.get('ticks', 'unknown'),
                seconds=case.get('seconds', 'unknown'), observation=observation)


def correspondence(record, case, *, layout, windows):
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
        executed = case.get('retire_insn')
        if case.get('fetch') != layout['slot']:
            return 'F1 fetch address is not the trampoline slot'
        if case.get('retire_pc') != layout['slot'] or executed != first:
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
        elif case.get('read_from') != 'ram' or case.get('apb_reads') != 0:
            return 'F2 read was not a plain RAM read'
        return None
    if record['flow'] == 'F3':
        if case.get('write_addr') != first or case.get('write_value') != record['fields'][1]:
            return 'F3 write differs from the input'
        if case.get('write_be') != 15 or case.get('ram_after') != record['fields'][1]:
            return 'F3 RAM did not commit the input word'
        return None
    if case.get('mmio_addr') != first or case.get('mmio_value') != record['fields'][1]:
        return 'F4 MMIO write differs from the input'
    if (case.get('apb_offset') != first - windows['ip_base'] or case.get('apb_pready') != 1
            or case.get('apb_pwdata') != record['fields'][1] or case.get('apb_writes') != 1):
        return 'F4 APB transfer differs from the input'
    return None


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path,
                        default=ROOT / 'configs/scenarios/inprocess-irq-pulp-timer-profile.json',
                        help='existing CPU/IP declaration with explicit timing')
    parser.add_argument('--cpu-profile', type=Path, help='override the declared CPU profile')
    parser.add_argument('--ip-profile', type=Path, help='override the declared IP profile')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory inside the workspace')
    parser.add_argument('--records', required=True,
                        help='comma-separated records, e.g. F1:2ab00693,F4:40001008:0fffffff')
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
    if args.cpu_profile:
        config['cpu_profile'] = str(args.cpu_profile)
    if args.ip_profile:
        config['source_profile'] = str(args.ip_profile)
    try:
        windows = declared_windows(config)
        records = [parse_record(text, windows=windows) for text in args.records.split(',')]
        if not isinstance(config.get('active_id'), str) or not config['active_id']:
            raise ValueError('config requires an active_id for the APB target')
        for key in ('cpu_profile', 'source_profile'):
            if not isinstance(config.get(key), str) or not (ROOT / config[key]).is_file():
                raise ValueError('declared ' + key + ' is not a readable component profile')
    except (KeyError, ValueError) as error:
        parser.error(str(error))
    if args.output.exists():
        parser.error('output directory already exists')
    args.output.mkdir(parents=True)

    from myfuzz.composition.component_profile import elaboration_mode_scope, load_component_profile
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.isa.constraints import f1_isa_from_profile
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.inprocess_build import build_link_run
    from scripts.run_timer_irq_smoke import timer_artifact

    started = time.monotonic()
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            harness_validation_scope(), execution_validation_scope():
        cpu_request_path = (args.output / 'cpu_request.json').resolve()
        cpu_request_path.write_text(json.dumps(cpu_request_from_config(config), indent=2) + '\n')
        source_request_path = (args.output / 'source_request.json').resolve()
        source_request_path.write_text(json.dumps(source_request_from_profile(config), indent=2) + '\n')
        cpu = timer_artifact(ROOT, str(cpu_request_path), 'cpu')
        ip = timer_artifact(ROOT, str(source_request_path), config['active_id'])
        boot = source_backed_boot_fetch(cpu.plan.profile, base_dir=ROOT,
                                        configured_boot_base=cpu.runtime_document['boot_contract']['configured_boot_base'])
        isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
        for record in records:
            validate_record(record, isa=isa, windows=windows)
        layout = build_layout(windows, boot)
        firmware = build_firmware(layout)
        header = render_bindings(config, cpu.runtime_document, ip.runtime_document, layout,
                                 cpu.plan.profile)
        (args.output / 'spike_config.h').write_text(header)
        (args.output / 'firmware.txt').write_text(firmware_text(firmware))
        submitted = []
        runner = incremental_runner([record['message'] for record in records], submitted) \
            if args.online else None
        result = build_link_run((cpu, ip), ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp',
                                args.output, args.cache,
                                run_arguments(args.output, records, args.online, args.max_ticks),
                                root=ROOT, runner=runner)
        log = (args.output / 'run.log').read_text()
        try:
            parsed = parse_run_log(log)
            failure = None
        except ValueError as error:
            parsed, failure = None, 'run log unreadable: ' + str(error)
        cases = [] if parsed is None else parsed['cases']
        verified, checks = [], []
        for record, case in zip(records, cases):
            document = case_document(record, case)
            mismatch = correspondence(record, case, layout=layout, windows=windows)
            document['correspondence'] = 'matched' if mismatch is None else 'mismatched'
            if mismatch is not None:
                document['correspondence_reason'] = mismatch
            verified.append(document)
            checks.append(mismatch)
        result.update(
            scope='one OBI CPU + one APB3 target + host RAM receiving F1-F4 in one process; '
                  'compact observations only',
            preparation_scope='two component profiles only; no GPIO, no full D3, no F5 IRQ '
                              'delivery and no F6 DMA model',
            input_mode='incremental' if args.online else 'preloaded',
            input_channel='held-RAM-mailbox + instruction trampoline slot',
            records=[record['text'] for record in records],
            submitted=submitted if args.online else [record['text'] for record in records],
            cases=verified,
            run_summary=None if parsed is None else parsed['summary'],
            installed=None if parsed is None else parsed['installed'],
            cpu_instance='cpu', ip_instance=config['active_id'],
            ram=dict(base=windows['ram_base'], size=windows['ram_size']),
            ip_window=dict(base=windows['ip_base'], size=windows['ip_size']),
            layout=firmware['layout'], slot_return=firmware['slot_return'],
            irq_delivery='unknown', dma='not_present',
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


if __name__ == '__main__':
    raise SystemExit(main())
