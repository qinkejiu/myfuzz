#!/usr/bin/env python3
"""Build and run one process that drives an APB3 target from a Wishbone CPU.

This is the second CPU bus in the in-process loop.  One generated PicoRV32
(``picorv32_wb``) model, one APB3 target model and the host RAM are initialized
once.  The CPU's *single* Wishbone master port carries both instruction fetches
and data accesses, so the host decodes one shared request stream and reads the
CPU's own ``mem_instr`` output to tell a fetch from a load; nothing about the
bus is inferred from the flow tag.

A case is still handed over by writing one mailbox word in RAM: no case
recompiles, re-initializes or resets any model.  The flows keep the semantics of
the other in-process hosts:

* F1 the CPU fetches and retires one word from the trampoline slot
* F2 the CPU reads one RAM word or one APB register
* F3 the CPU stores one word to RAM
* F4 the CPU stores one word through the APB window

Every retirement is reported with the CPU's own RVFI order, rd_addr and
rd_wdata, so the retirement evidence is stronger than the OBI host's.  There is
no interrupt and no DMA in this build: the CPU's 32-bit irq input is driven to
zero and no F5/F6 flow is offered.  Unsupported components, windows or records
are refused by name.  The result is a compact observation, not a certificate and
not a replay.
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
from scripts.run_inprocess_f1f4 import (Program, _check_spans, _jalr,
                                        incremental_runner, run_arguments)

# Fixed offsets inside the one RAM image.  The boot address is the CPU's own
# declared reset vector, which the entry takes from its boot contract.
MAIN_OFFSET = 0x1000
SLOT_OFFSET = 0x2000
MAILBOX_OFFSET = 0x3000
DATA_OFFSET = 0x4000
MAILBOX_BYTES = 16
DATA_WORDS = (0xDEADBEEF, 0x11111111, 0x00000000)
FLOW_ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}
CASE_OBSERVATION_KEYS = {
    'F1': ('fetch', 'retire_pc', 'retire_insn', 'successor_pc', 'slot_rd_wdata', 'slot_order'),
    'F2': ('read_addr', 'read_value', 'echo_value', 'read_from', 'apb_rdata'),
    'F3': ('write_addr', 'write_value', 'write_be', 'ram_before', 'ram_after'),
    'F4': ('mmio_addr', 'mmio_value', 'apb_offset', 'apb_pwdata', 'apb_pready'),
}
CASE_COUNTER_KEYS = ('i_fetches', 'd_reads', 'd_writes', 'wb_retires',
                     'wb_rvfi_order_rising', 'apb_reads', 'apb_writes')


# ---------------------------------------------------------------------------
# Declaration checks
# ---------------------------------------------------------------------------
def declared_windows(config):
    """The RAM and APB windows this host routes one Wishbone port between."""
    window, ram_base, ram_end = (config.get('target_window'), config.get('image_start'),
                                 config.get('image_end'))
    if any(type(value) is not int for value in (ram_base, ram_end)):
        raise ValueError('config requires integer image_start and image_end')
    if (not isinstance(window, dict)
            or any(type(window.get(key)) is not int for key in ('base', 'size'))):
        raise ValueError('config requires a declared APB target_window')
    if ram_base % 4 or ram_end - ram_base < DATA_OFFSET + 4 * len(DATA_WORDS):
        raise ValueError('declared RAM is too small for the fixed image')
    if (window['base'] % 4 or window['size'] < 4
            or window['base'] + window['size'] > 1 << 32):
        raise ValueError('declared APB window is unusable for this host')
    if max(window['base'], ram_base) < min(window['base'] + window['size'], ram_end):
        raise ValueError('declared APB window overlaps the RAM image')
    return dict(ram_base=ram_base, ram_size=ram_end - ram_base,
                ip_base=window['base'], ip_size=window['size'],
                data_base=ram_base + DATA_OFFSET)


def build_layout(windows, boot):
    """Every fixed address of the one RAM image, checked for overlap."""
    ram = windows['ram_base']
    layout = dict(boot=boot, main=ram + MAIN_OFFSET, slot=ram + SLOT_OFFSET,
                  mailbox=ram + MAILBOX_OFFSET, mailbox_bytes=MAILBOX_BYTES,
                  data_base=windows['data_base'],
                  data_end=ram + windows['ram_size'], ram_base=ram,
                  ram_size=windows['ram_size'], ip_base=windows['ip_base'],
                  ip_size=windows['ip_size'])
    if boot % 4 or not ram <= boot <= ram + windows['ram_size'] - 4:
        raise ValueError('the declared CPU boot address is not an aligned RAM word')
    if boot + 4 > layout['main']:
        raise ValueError('the declared CPU boot address leaves no room for the bootstrap')
    return layout


def cpu_bus_declaration(cpu_document):
    """The one Wishbone master this host serves, straight from the artifact."""
    if cpu_document.get('kind') != 'wishbone_cpu':
        raise ValueError('unsupported: requires a Wishbone CPU model')
    marker = cpu_document.get('instruction_identity_observation')
    if not isinstance(marker, str) or not marker:
        raise ValueError('unsupported: the generated CPU declares no mem_instr observation')
    return dict(instruction_identity=marker)


# ---------------------------------------------------------------------------
# Input records
# ---------------------------------------------------------------------------
def parse_record(text, *, windows):
    if type(text) is not str or not text:
        raise ValueError('one record text is required')
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
    from scripts.run_inprocess_f1f4 import validate_record as validate_f1
    return validate_f1(record, isa=isa, windows=windows)


# ---------------------------------------------------------------------------
# The one RAM image
# ---------------------------------------------------------------------------
def build_firmware(layout):
    """Assemble the one-time RAM image; nothing here changes per case."""
    from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _lw, _sw
    program = Program(layout['main'])
    program.emit(*_lui_addi_load(8, layout['mailbox']))
    program.mark('poll')
    program.emit(_lw(5, 8, 0))
    program.branch(5, 0, 'poll')
    for command, target in ((1, 'f1'), (2, 'f2'), (3, 'store'), (4, 'store')):
        program.emit(_addi(6, 0, command))
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
    code = program.link()

    # The bootstrap is one real jump from the CPU's own reset vector into main:
    # nothing else is installed at address 0.
    boot = _jal(layout['boot'], layout['main']).to_bytes(4, 'little')
    slot = (b'\x13\x00\x00\x00'                   # host overwrites this word
            + _jal(layout['slot'] + 4, program.labels['f1_back']).to_bytes(4, 'little'))
    data = b''.join(word.to_bytes(4, 'little') for word in DATA_WORDS)
    images = {layout['boot']: boot, layout['main']: code, layout['slot']: slot,
              layout['data_base']: data}
    _check_spans(layout, {'boot': (layout['boot'], len(boot)),
                          'main': (layout['main'], len(code)),
                          'slot': (layout['slot'], len(slot)),
                          'mailbox': (layout['mailbox'], MAILBOX_BYTES),
                          'data': (layout['data_base'], len(data))})
    if layout['mailbox'] + MAILBOX_BYTES > layout['data_base']:
        raise ValueError('the mailbox overlaps the data window')
    return dict(images=images, layout=layout, slot_return=program.labels['f1_back'],
                main_words=len(program.words))


def firmware_text(firmware):
    return ''.join(f'{address:x} {data.hex()}\n'
                   for address, data in sorted(firmware['images'].items()))


# ---------------------------------------------------------------------------
# Generated binding header
# ---------------------------------------------------------------------------
def render_bindings(config, cpu, ip, layout, bus):
    """Bind generated model ports from the artifacts; nothing is inferred."""
    from scripts.prepare_inprocess_irq_bindings import identifier, one
    if cpu.get('kind') != 'wishbone_cpu':
        raise ValueError('unsupported: requires a Wishbone CPU model')
    if ip.get('kind') != 'apb3_register_observe':
        raise ValueError('unsupported: requires an APB3 register target')
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
    for role in ('valid', 'trap', 'insn', 'pc_rdata', 'order', 'rd_addr', 'rd_wdata'):
        rows = [row for row in cpu['physical_exports'] if row.get('physical_port') == 'rvfi_' + role
                and row.get('direction') == 'output']
        if len(rows) != 1:
            raise ValueError('unsupported: the CPU does not expose one rvfi_' + role)
        fields['CPU_RVFI_' + role.upper()] = rows[0]['runtime_name']
    fields['CPU_WB_INSTR'] = identifier(bus['instruction_identity'])
    wb_roles = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel')
    for role in wb_roles:
        fields['CPU_WB_' + role.upper()] = one(cpu['backend_ports'], channel='wb',
                                             role=role, direction='output')['name']
    for role in ('ack', 'dat_r'):
        fields['CPU_WB_' + role.upper()] = one(cpu['backend_ports'], channel='wb',
                                              role=role, direction='input')['name']
    # The CPU declares a 32-bit external interrupt input; this build delivers
    # nothing on it, which the summary states instead of hiding.
    irq_input = one(cpu['physical_exports'], endpoint_id=cpu_irq_endpoint(bus),
                    role=cpu_irq_role(bus), direction='input')
    if irq_input['width'] < 1:
        raise ValueError('unsupported: the declared CPU IRQ input has no width')
    fields['CPU_IRQ'] = irq_input['runtime_name']
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    for role in roles:
        fields['IP_' + role.upper()] = one(ip['backend_ports'], channel='reg', role=role)['name']
    signals = ip['base_protocol_trace'].get('signals', {})
    apb = ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata')
    missing = [role for role in apb if role not in signals]
    if missing:
        raise ValueError('unsupported: the APB3 trace lacks ' + ','.join(missing))
    for role in apb:
        fields['IP_TRACE_' + role.upper()] = signals[role]
    cpu_model = 'V' + identifier(cpu['module_name'])
    ip_model = 'V' + identifier(ip['module_name'])
    lines = ['#pragma once', f'#include "{cpu_model}.h"', f'#include "{ip_model}.h"',
             f'#define CPU_MODEL {cpu_model}', f'#define IP_MODEL {ip_model}']
    lines += [f'#define {key} {identifier(value)}' for key, value in fields.items()]
    lines += [f'#define RAM_BASE {layout["ram_base"]}u', f'#define RAM_SIZE {layout["ram_size"]}u',
              f'#define IP_BASE 0x{layout["ip_base"]:x}u', f'#define IP_SIZE {layout["ip_size"]}u',
              f'#define SLOT_ADDRESS {layout["slot"]}u',
              f'#define MAILBOX_ADDRESS {layout["mailbox"]}u',
              f'#define DATA_BASE {layout["data_base"]}u']
    for tag, artifact in (('CPU', cpu), ('IP', ip)):
        timing = artifact['plan']['timing']
        lines += [f'#define {tag}_RESET_ASSERT {timing["reset_assert_ticks"]}u',
                  f'#define {tag}_RESET_RELEASE {timing["reset_release_ticks"]}u']
    return '\n'.join(lines) + '\n'


def cpu_irq_endpoint(bus):
    return bus['irq_entry_endpoint']


def cpu_irq_role(bus):
    return bus['irq_entry_role']


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
    if type(text) is not str:
        raise ValueError('run log text required')
    cases, summary, installed, retires, bus_lines = [], None, [], 0, 0
    for line in text.splitlines():
        if line.startswith('case '):
            cases.append(parse_case_line(line, flows=flows))
        elif line.startswith('summary '):
            if summary is not None:
                raise ValueError('duplicate summary line')
            summary = parse_summary_line(line)
        elif line.startswith('retire '):
            retires += 1
        elif line.startswith('wb '):
            bus_lines += 1
        elif line.startswith('CASE_INSTALLED '):
            installed.append(int(line.split()[1]))
    if summary is None:
        raise ValueError('run log has no summary line')
    return dict(cases=cases, summary=summary, installed=installed,
                bus_events=bus_lines, retire_events=retires)


def case_document(record, case):
    observation = {key: case.get(key, 'unknown')
                   for key in CASE_OBSERVATION_KEYS[record['flow']]}
    observation.update({key: case.get(key, 'unknown') for key in CASE_COUNTER_KEYS})
    return dict(index=case['index'], flow=case['flow'], record=record['text'],
                input=case.get('record', 'unknown'),
                status=case['status'], ticks=case.get('ticks', 'unknown'),
                seconds=case.get('seconds', 'unknown'), observation=observation)


def correspondence(record, case, *, layout, windows):
    """Check that the observed facts belong to the input that was handed over."""
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
        if case.get('wb_rvfi_order_rising') != case.get('wb_retires'):
            return 'F1 RVFI order did not rise at every retirement'
        if not case.get('slot_order'):
            return 'F1 the retired slot word carries no RVFI order'
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
    offset, value = first - windows['ip_base'], record['fields'][1]
    if case.get('mmio_addr') != first or case.get('mmio_value') != value:
        return 'F4 MMIO write differs from the input'
    if (case.get('apb_offset') != offset or case.get('apb_pready') != 1
            or case.get('apb_pwdata') != value or case.get('apb_writes') != 1):
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


def self_rate(artifact):
    clocks = artifact.runtime_document['clock_schedule']['clocks']
    return clocks[0]['frequency_hz'] if len(clocks) == 1 else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True,
                        help='Wishbone CPU + APB3 target declaration with explicit timing')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory inside the workspace')
    parser.add_argument('--records', required=True,
                        help='comma-separated records, e.g. F1:2ab00693,F2:40000000')
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
    from scripts.run_inprocess_f1f4 import (cpu_request_from_config,
                                            source_request_from_profile)
    from scripts.run_timer_irq_smoke import timer_artifact

    started = time.monotonic()
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            harness_validation_scope(), execution_validation_scope():
        cpu_request_path = (args.output / 'cpu_request.json').resolve()
        cpu_request_path.write_text(json.dumps(cpu_request_from_config(config), indent=2) + '\n')
        source_request_path = (args.output / 'source_request.json').resolve()
        source_request_path.write_text(json.dumps(
            source_request_from_profile(config), indent=2) + '\n')
        cpu = timer_artifact(ROOT, str(cpu_request_path), 'cpu')
        ip = timer_artifact(ROOT, str(source_request_path), config['active_id'])

        bus = cpu_bus_declaration(cpu.runtime_document)
        bus['irq_entry_endpoint'] = cpu.plan.profile.cpu.irq_entry_endpoint
        bus['irq_entry_role'] = cpu.plan.profile.cpu.irq_entry_role
        windows = declared_windows(config)
        records = [parse_record(text, windows=windows) for text in args.records.split(',')]
        boot = source_backed_boot_fetch(
            cpu.plan.profile, base_dir=ROOT,
            configured_boot_base=cpu.runtime_document['boot_contract']['configured_boot_base'])
        isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
        for record in records:
            validate_record(record, isa=isa, windows=windows)
        layout = build_layout(windows, boot)
        firmware = build_firmware(layout)
        header = render_bindings(config, cpu.runtime_document, ip.runtime_document,
                                 layout, bus)
        (args.output / 'spike_config.h').write_text(header)
        (args.output / 'firmware.txt').write_text(firmware_text(firmware))
        submitted = []
        runner = incremental_runner([record['message'] for record in records], submitted) \
            if args.online else None
        result = build_link_run((cpu, ip),
                                ROOT / 'scripts/inprocess_wb_cpu_spike.cpp',
                                args.output, args.cache,
                                run_arguments(args.output, records, args.online, args.max_ticks),
                                root=ROOT, runner=runner)
        log = (args.output / 'run.log').read_text()
        try:
            parsed, failure = parse_run_log(log, flows=FLOW_ARITY), None
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
            scope='one PicoRV32 Wishbone CPU + one APB3 target + host RAM receiving F1-F4 '
                  'in one process; compact observations only',
            preparation_scope='two component profiles only; no DMA, no interrupt delivery, '
                              'no scenario search and no replay',
            input_mode='incremental' if args.online else 'preloaded',
            input_channel='held-RAM-mailbox + instruction trampoline slot over one shared '
                          'Wishbone master port',
            records=[record['text'] for record in records],
            submitted=submitted if args.online else [record['text'] for record in records],
            cases=verified,
            run_summary=None if parsed is None else parsed['summary'],
            installed=None if parsed is None else parsed['installed'],
            bus_events=None if parsed is None else parsed['bus_events'],
            retire_events=None if parsed is None else parsed['retire_events'],
            cpu_instance='cpu', ip_instance=config['active_id'],
            components=dict(
                cpu=dict(profile=config['cpu_profile'], model=cpu.runtime_document['module_name'],
                         declared_hz=self_rate(cpu)),
                target=dict(profile=config['source_profile'],
                            model=ip.runtime_document['module_name'],
                            declared_hz=self_rate(ip))),
            clock_assumption=('one host tick for both models; declared rates ' +
                              '/'.join(str(self_rate(row)) for row in (cpu, ip)) + ' Hz'),
            cpu_bus=dict(protocol='wishbone-classic', port='one shared master',
                         fetch_marker=bus['instruction_identity'],
                         window=dict(ram=[windows['ram_base'],
                                          windows['ram_base'] + windows['ram_size']],
                                     ip=[windows['ip_base'],
                                         windows['ip_base'] + windows['ip_size']]),
                         outstanding=1,
                         acknowledgement='RAM accesses are acknowledged in the cycle they are '
                                         'decoded; an APB-window access is acknowledged only '
                                         'after the target answered',
                         rvfi_observation='valid/trap/insn/pc_rdata plus order, rd_addr and '
                                          'rd_wdata printed per retirement',
                         status='observed'),
            irq_delivery='none: the CPU irq input is driven to zero in this build',
            ram=dict(base=windows['ram_base'], size=windows['ram_size']),
            ip_window=dict(base=windows['ip_base'], size=windows['ip_size']),
            layout=firmware['layout'], slot_return=firmware['slot_return'],
            combination_specific_branches='none: wiring comes from the generated binding '
                                          'header and the CPU\'s own fetch marker',
            limitations=[
                'one host tick drives both models; declared clock rates are not modelled',
                'no interrupt and no DMA in this build; F5/F6 are refused, not guessed',
                'full-word beats only: a partial Wishbone store is refused, not emulated',
                'the host acknowledges at once, so no Wishbone wait state is exercised',
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


if __name__ == '__main__':
    raise SystemExit(main())
