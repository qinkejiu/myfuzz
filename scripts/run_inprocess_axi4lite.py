#!/usr/bin/env python3
"""Build and run one process that receives F1-F4 inputs on OBI CPU + AXI4-Lite IP.

One OBI CPU model, one AXI4-Lite target model and the host RAM are initialized
once.  The CPU executes a fixed polling program from that RAM, so a case is
handed over by writing one mailbox word (or the instruction trampoline slot for
F1); no case recompiles, re-initializes or resets either model.  The four flows
share that one RAM, one address route and one model lifetime:

* F1 the CPU fetches and retires one word from the trampoline slot
* F2 the CPU reads a RAM word or the target's declared AXI4-Lite register
* F3 the CPU stores to RAM
* F4 the CPU stores through the AXI4-Lite window

The target's own AXI4-Lite slave port is driven by the generated bridge, whose
beat side this host serves; AW/W/B and AR/R are joined only when both halves of
each channel handshake in the same pre-edge sample.  Everything reported is a
fact the two models produced: the fetched/retired word, the RAM read/write, the
channel handshakes, the declared register's data/strobes and the response codes.
``BRESP``/``RRESP`` are physical pins, but this slave only drives OKAY, so the
error path is reported as ``unknown`` rather than claimed as covered.  F5 (IRQ)
and F6 (DMA) are not wired here and are refused by name.  The result is a
compact observation, not a certificate and not a replay.
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
# The F1-F4 trampoline, mailbox and RAM image are protocol independent, so this
# entry reuses them instead of keeping a second copy that could drift.
from scripts.run_inprocess_f1f4 import (build_firmware, build_layout, explicit_timing,
                                        firmware_text, incremental_runner, run_arguments,
                                        validate_record)
from scripts.run_timer_irq_smoke import timer_artifact

DEFAULT_CONFIG = ROOT / 'configs/scenarios/inprocess-obi-axi4lite-ibex-zipcpu-uart-f1f4.json'
FLOW_ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}
DATA_OFFSET = 0x4000
#: The exact AXI4-Lite roles the target must expose as passive taps.  They are
#: checked against the generated trace instead of being assumed present.
TRACE_ROLES = ('awaddr', 'awprot', 'awvalid', 'awready',
               'wdata', 'wstrb', 'wvalid', 'wready',
               'bresp', 'bvalid', 'bready',
               'araddr', 'arprot', 'arvalid', 'arready',
               'rdata', 'rresp', 'rvalid', 'rready')
CASE_OBSERVATION_KEYS = {
    'F1': ('fetch', 'retire_pc', 'retire_insn', 'successor_pc'),
    'F2': ('read_addr', 'read_value', 'echo_value', 'read_from', 'axil_araddr',
           'axil_arprot', 'axil_rdata', 'axil_rresp'),
    'F3': ('write_addr', 'write_value', 'write_be', 'ram_before', 'ram_after'),
    'F4': ('mmio_addr', 'mmio_value', 'axil_awaddr', 'axil_awprot', 'axil_wdata',
           'axil_wstrb', 'axil_bresp', 'ram_store'),
}
CASE_COUNTER_KEYS = ('i_fetches', 'd_reads', 'd_writes', 'axi_reads', 'axi_writes',
                     'axi_aw', 'axi_w', 'axi_b', 'axi_ar', 'axi_r')
SUMMARY_COUNTER_KEYS = ('instruction_fetches', 'instruction_fetch_evidence',
                        'rvfi_retire_events', 'retirement_evidence', 'ram_reads',
                        'ram_writes', 'axi_transfers', 'axi_reads', 'axi_writes',
                        'axi_aw', 'axi_w', 'axi_b', 'axi_ar', 'axi_r',
                        'bresp_okay', 'bresp_non_okay', 'rresp_okay', 'rresp_non_okay',
                        'error_response', 'irq_delivery', 'dma', 'fixed_target_inputs')


# ---------------------------------------------------------------------------
# Declaration checks: the selected components decide what is offered
# ---------------------------------------------------------------------------
def declared_windows(config):
    """The RAM and AXI4-Lite windows this host routes between, from the declaration."""
    window = config.get('target_window')
    ram_base, ram_end = config.get('image_start'), config.get('image_end')
    if any(type(value) is not int for value in (ram_base, ram_end)):
        raise ValueError('config requires integer image_start and image_end')
    if not isinstance(window, dict) or any(type(window.get(key)) is not int
                                          for key in ('base', 'size')):
        raise ValueError('config requires a declared AXI4-Lite target_window')
    if not 0 < window['size'] <= 4096 or window['size'] % 4:
        raise ValueError('the declared AXI4-Lite window must be a positive word count')
    if (ram_base % 4 or ram_end - ram_base < DATA_OFFSET + 16
            or window['base'] % 4 or window['base'] + window['size'] > 1 << 32):
        raise ValueError('declared RAM or AXI4-Lite window is unusable for this host')
    return dict(ram_base=ram_base, ram_size=ram_end - ram_base,
                ip_base=window['base'], ip_size=window['size'],
                data_base=ram_base + DATA_OFFSET)


def parse_record(text, *, windows, write_mask):
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
            raise ValueError('F2 address must be an aligned AXI4-Lite or data-window RAM word')
    elif flow == 'F3':
        if first & 3 or not data_base <= first <= windows['ram_base'] + windows['ram_size'] - 4:
            raise ValueError('F3 address must be an aligned data-window RAM word')
    else:
        if first & 3 or not ip_base <= first <= ip_base + ip_size - 4:
            raise ValueError('F4 address must be an aligned word in the AXI4-Lite window')
        if values[1] & ~write_mask:
            raise ValueError('F4 value has bits the declared AXI4-Lite write mask drops')
    text = flow + ':' + ':'.join(format(value, '08x') for value in values)
    message = 'CASE ' + flow + ' ' + ' '.join(format(value, '08x') for value in values)
    return dict(flow=flow, fields=tuple(values), text=text, message=message)


class _Profile:
    """Minimal read-only profile view for the pin declaration check."""

    def __init__(self, document):
        self.endpoints = [_Endpoint(row) for row in document.get('endpoints', [])]


class _Endpoint:
    def __init__(self, document):
        self.endpoint_id = document.get('endpoint_id')
        self.function = document.get('function')
        self.fields = [_Field(row) for row in document.get('fields', [])]


class _Field:
    def __init__(self, document):
        self.role = document.get('role')
        self.direction = document.get('direction')


def fixed_inputs(config, profile):
    """Every declared target input pin needs one fixed value in the declaration."""
    declared = {}
    for endpoint in profile.endpoints:
        if endpoint.function != 'external_pins':
            continue
        for field in endpoint.fields:
            if field.direction == 'input':
                declared[(endpoint.endpoint_id, field.role)] = None
    rows = config.get('source_fixed_inputs')
    if not isinstance(rows, list) or not rows:
        raise ValueError('config requires source_fixed_inputs for the declared target pins')
    values = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('each source_fixed_inputs row must be an object')
        key = (row.get('endpoint_id'), row.get('role'))
        if key not in declared:
            raise ValueError('unsupported: declared fixed input is not a declared target pin')
        value = row.get('value')
        if type(value) is not int or not 0 <= value < 1 << 32:
            raise ValueError('unsupported: a declared target pin value must be a 32-bit integer')
        values[key] = value
    if set(values) != set(declared):
        raise ValueError('unsupported: every declared target input pin needs one fixed value')
    return values


def source_request_from_profile(config, profile):
    """Make the existing v2 AXI4-Lite request from a profile and explicit timing."""
    from myfuzz.local_harness.axi4lite_register_template import bus_shape
    endpoints = [row for row in profile.get('endpoints', [])
                 if row.get('function') == 'mmio_slave'
                 and row.get('protocol') == ['axi4-lite', '1']]
    if len(endpoints) != 1:
        raise ValueError('unsupported: source_profile requires exactly one AXI4-Lite '
                         'MMIO slave endpoint')
    address_width = profile.get('capabilities', {}).get('address_width')
    if type(address_width) is not int or not 1 <= address_width <= 12:
        raise ValueError('unsupported: the target declares no usable AXI4-Lite address width')
    declared = {field.get('role') for field in endpoints[0].get('fields', [])}
    missing = sorted(set(bus_shape(address_width)) - declared)
    if missing:
        raise ValueError('unsupported: the AXI4-Lite endpoint lacks ' + ','.join(missing))
    pins = fixed_inputs(config, _Profile(profile))
    tuning = dict(config.get('source_tuning', {}))
    tuning.setdefault('endpoint_policies', [dict(
        endpoint_id=endpoints[0]['endpoint_id'], template_id='target.axi4-lite',
        template_version='1', variant_id='single-outstanding-error-codes', max_outstanding=1)])
    tuning.setdefault('fixed_inputs', [dict(endpoint_id=endpoint_id, role=role, value=value)
                                       for (endpoint_id, role), value in sorted(pins.items())])
    return dict(schema_version='local_harness.v2', profile_path=config['source_profile'],
                instance_id=config['active_id'], **explicit_timing(config, 'source_timing'),
                tuning=tuning)


def axi_declaration(config, ip_profile):
    """Check the declared AXI4-Lite behavior against the target's own register map."""
    address = ip_profile.address
    window = config['target_window']
    if address is None or not address.registers:
        raise ValueError('unsupported: the target declares no AXI4-Lite register map')
    if window['size'] != address.window_size or window['base'] % address.alignment:
        raise ValueError('unsupported: the declared AXI4-Lite window does not match the '
                         'target profile')
    capabilities = ip_profile.capabilities
    if (capabilities.get('data_width') != 32 or capabilities.get('byte_enable') is not True
            or capabilities.get('max_outstanding') != 1
            or capabilities.get('bursts') is not False or capabilities.get('ids') is not False):
        raise ValueError('unsupported: the target declares more than one outstanding '
                         'single-beat AXI4-Lite port')
    if type(capabilities.get('address_width')) is not int:
        raise ValueError('unsupported: the target declares no AXI4-Lite address width')
    if type(capabilities.get('max_wait_cycles')) is not int:
        raise ValueError('unsupported: the target declares no AXI4-Lite wait bound')
    registers = {row.offset: row for row in address.registers}
    offset = config.get('register_offset')
    if type(offset) is not int or offset not in registers:
        raise ValueError('config requires a declared register_offset of the target')
    register = registers[offset]
    if register.width != 32 or register.access not in ('ro', 'rw', 'wo'):
        raise ValueError('unsupported: the declared register is not a 32-bit AXI4-Lite word')
    if config.get('register') is not None and config.get('register') != register.name:
        raise ValueError('the declared register name and offset disagree')
    masks = {}
    for key in ('write_mask', 'read_mask'):
        mask = config.get(key)
        if type(mask) is not int or not 0 <= mask < 1 << 32:
            raise ValueError('config requires a 32-bit integer ' + key)
        masks[key] = mask
    if register.access == 'ro' and masks['write_mask']:
        raise ValueError('unsupported: a write mask on a read-only AXI4-Lite register')
    return dict(register=dict(name=register.name, offset=register.offset,
                              width=register.width, access=register.access,
                              side_effect=register.side_effect),
                write_mask=masks['write_mask'], read_mask=masks['read_mask'],
                address_width=capabilities['address_width'],
                max_wait_cycles=capabilities['max_wait_cycles'])


# ---------------------------------------------------------------------------
# Generated binding header
# ---------------------------------------------------------------------------
def render_bindings(config, cpu, ip, layout, profile, declaration):
    """Bind generated model ports from the two artifacts; nothing is inferred."""
    from scripts.prepare_inprocess_irq_bindings import identifier, one
    if cpu.get('kind') != 'obi_cpu' or ip.get('kind') != 'axi4lite_register_observe':
        raise ValueError('unsupported: requires an OBI CPU and an AXI4-Lite register target')
    trace = ip.get('base_protocol_trace', {})
    if trace.get('protocol') != 'axi4-lite':
        raise ValueError('unsupported: the target declares no AXI4-Lite protocol trace')
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

    rates = (declared_clock(cpu), declared_clock(ip))
    if rates[0] != rates[1] and config.get('assume_single_clock') is not True:
        raise ValueError('unsupported: declared clock rates differ (' +
                         ','.join(str(rate) for rate in rates) +
                         '); state assume_single_clock to drive them from one host tick')
    fields = {}
    try:
        for role in ('valid', 'trap', 'insn', 'pc_rdata'):
            fields['CPU_RVFI_' + role.upper()] = one(
                cpu['physical_exports'], physical_port='rvfi_' + role,
                direction='output')['runtime_name']
    except ValueError as error:
        raise ValueError('unsupported: F1 needs the CPU rvfi_* retirement probe (' +
                         str(error) + ')')
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
    signals = trace.get('signals', {})
    missing = [role for role in TRACE_ROLES if role not in signals]
    if missing:
        raise ValueError('unsupported: the AXI4-Lite trace lacks ' + ','.join(missing))
    for role in TRACE_ROLES:
        fields['IP_TRACE_' + role.upper()] = signals[role]
    # The profile pins some target inputs at a constant; they are driven from
    # here so the host loop needs no per-device edit.
    fixed = ip.get('fixed_physical_inputs')
    if not isinstance(fixed, list):
        raise ValueError('unsupported: the target model declares no fixed input list')
    declared_pins = {(row.get('endpoint_id'), row.get('role')): row.get('value')
                     for row in config.get('source_fixed_inputs', [])}
    rows = {(row.get('endpoint_id'), row.get('role')): row for row in fixed}
    if set(rows) != set(declared_pins):
        raise ValueError('unsupported: the generated target does not expose every declared pin')
    for key, value in declared_pins.items():
        width = rows[key].get('width')
        if (not isinstance(rows[key].get('runtime_name'), str)
                or rows[key].get('value') != value
                or type(width) is not int or not 1 <= width <= 64
                or value >= 1 << width):
            raise ValueError('unsupported: the generated target pin constant or name differs')
    cpu_model = 'V' + identifier(cpu['module_name'])
    ip_model = 'V' + identifier(ip['module_name'])
    lines = ['#pragma once', f'#include "{cpu_model}.h"', f'#include "{ip_model}.h"',
             f'#define CPU_MODEL {cpu_model}', f'#define IP_MODEL {ip_model}']
    lines += [f'#define {key} {identifier(value)}' for key, value in fields.items()]
    pin_rows = ['  X({name}, {value}u)'.format(name=identifier(rows[key]['runtime_name']),
                                              value=value)
                for key, value in sorted(declared_pins.items())]
    lines.append(f'#define IP_FIXED_INPUT_COUNT {len(pin_rows)}')
    lines.append('#define IP_FIXED_INPUTS(X)' + ''.join(' \\\n' + row for row in pin_rows))
    lines += [f'#define RAM_BASE {layout["ram_base"]}u', f'#define RAM_SIZE {layout["ram_size"]}u',
              f'#define IP_BASE 0x{layout["ip_base"]:x}u', f'#define IP_SIZE {layout["ip_size"]}u',
              f'#define BOOT_ADDRESS {layout["boot"]}u', f'#define MAIN_ADDRESS {layout["main"]}u',
              f'#define SLOT_ADDRESS {layout["slot"]}u', f'#define PARK_ADDRESS {layout["park"]}u',
              f'#define MAILBOX_ADDRESS {layout["mailbox"]}u',
              f'#define DATA_BASE {layout["data_base"]}u',
              f'#define REGISTER_OFFSET {declaration["register"]["offset"]}u',
              f'#define REGISTER_WIDTH {declaration["register"]["width"]}u',
              f'#define WRITE_MASK 0x{declaration["write_mask"]:08x}u',
              f'#define READ_MASK 0x{declaration["read_mask"]:08x}u',
              f'#define AXI_ADDRESS_WIDTH {declaration["address_width"]}u']
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


def parse_case_line(line):
    """Parse one `case <index> <status> <key> <value> ...` line."""
    tokens = line.split()
    if len(tokens) < 5 or tokens[0] != 'case':
        raise ValueError('not an F1-F4 case line')
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
        raise ValueError('not an F1-F4 summary line')
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


def correspondence(record, case, *, layout, windows, declaration):
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
        if case.get('read_from') == 'axi4lite':
            if case.get('axi_reads') != 1 or case.get('axi_ar') != 1 or case.get('axi_r') != 1:
                return 'F2 expected exactly one AR and R handshake'
            if case.get('axil_araddr') != first - windows['ip_base']:
                return 'F2 AXI4-Lite read address differs from the input'
            if case.get('axil_rdata') != case.get('read_value'):
                return 'F2 AXI4-Lite read data differs from the CPU response'
            if case.get('axil_rresp') != 0:
                return 'F2 AXI4-Lite read response is not OKAY'
            if case.get('read_value', 0) & ~declaration['read_mask']:
                return 'F2 read value has bits outside the declared read mask'
        elif case.get('read_from') != 'ram' or case.get('axi_reads') != 0:
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
    if (case.get('axil_awaddr') != first - windows['ip_base']
            or case.get('axil_wdata') != record['fields'][1]
            or case.get('axil_wstrb') != 15 or case.get('axil_bresp') != 0):
        return 'F4 AXI4-Lite write differs from the input'
    if (case.get('axi_writes') != 1 or case.get('axi_aw') != 1 or case.get('axi_w') != 1
            or case.get('axi_b') != 1):
        return 'F4 expected exactly one AW, W and B handshake'
    if case.get('ram_store') != 0:
        return 'F4 store landed in RAM instead of the AXI4-Lite window'
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
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG,
                        help='CPU + AXI4-Lite target declaration with explicit timing')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory inside the workspace')
    parser.add_argument('--records', required=True,
                        help='comma-separated records, e.g. '
                             'F1:2ab00693,F2:40001000,F4:40001000:00005a5a')
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
    try:
        if not isinstance(config.get('active_id'), str) or not config['active_id']:
            raise ValueError('config requires an active_id for the AXI4-Lite target')
        for key in ('cpu_profile', 'source_profile'):
            if not isinstance(config.get(key), str) or not (ROOT / config[key]).is_file():
                raise ValueError('declared ' + key + ' is not a readable component profile')
        windows = declared_windows(config)
        profile_document = json.loads((ROOT / config['source_profile']).read_text())
        request_document = source_request_from_profile(config, profile_document)
        records = [parse_record(text, windows=windows,
                                write_mask=config.get('write_mask', 0xffffffff))
                   for text in args.records.split(',')]
    except (KeyError, ValueError) as error:
        parser.error(str(error))
    args.output.mkdir(parents=True)

    from myfuzz.composition.component_profile import (elaboration_mode_scope,
                                                      load_component_profile)
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.isa.constraints import f1_isa_from_profile
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.run_inprocess_f1f4 import cpu_request_from_config

    started = time.monotonic()
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            harness_validation_scope(), execution_validation_scope():
        cpu_request_path = (args.output / 'cpu_request.json').resolve()
        cpu_request_path.write_text(json.dumps(cpu_request_from_config(config), indent=2) + '\n')
        source_request_path = (args.output / 'source_request.json').resolve()
        source_request_path.write_text(json.dumps(request_document, indent=2) + '\n')
        cpu = timer_artifact(ROOT, str(cpu_request_path), 'cpu')
        ip = timer_artifact(ROOT, str(source_request_path), config['active_id'])
        declaration = axi_declaration(config, ip.plan.profile)
        boot = source_backed_boot_fetch(
            cpu.plan.profile, base_dir=ROOT,
            configured_boot_base=cpu.runtime_document['boot_contract']['configured_boot_base'])
        isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
        for record in records:
            validate_record(record, isa=isa, windows=windows)
        layout = build_layout(windows, boot)
        firmware = build_firmware(layout)
        header = render_bindings(config, cpu.runtime_document, ip.runtime_document,
                                 layout, cpu.plan.profile, declaration)
        (args.output / 'spike_config.h').write_text(header)
        (args.output / 'firmware.txt').write_text(firmware_text(firmware))
        submitted = []
        runner = incremental_runner([record['message'] for record in records], submitted) \
            if args.online else None
        result = build_link_run((cpu, ip), ROOT / 'scripts/inprocess_obi_axi4lite_spike.cpp',
                                args.output, args.cache,
                                run_arguments(args.output, records, args.online,
                                              args.max_ticks),
                                root=ROOT, runner=runner)
        log = (args.output / 'run.log').read_text()
        try:
            parsed, failure = parse_run_log(log), None
        except ValueError as error:
            parsed, failure = None, 'run log unreadable: ' + str(error)
        cases = [] if parsed is None else parsed['cases']
        verified, checks = [], []
        for record, case in zip(records, cases):
            document = case_document(record, case)
            mismatch = correspondence(record, case, layout=layout, windows=windows,
                                      declaration=declaration)
            document['correspondence'] = 'matched' if mismatch is None else 'mismatched'
            if mismatch is not None:
                document['correspondence_reason'] = mismatch
            verified.append(document)
            checks.append(mismatch)
        summary = None if parsed is None else parsed['summary']
        result.update(
            scope='one OBI CPU + one AXI4-Lite IP target + host RAM receiving F1-F4 in one '
                  'process; compact observations only',
            preparation_scope='two component profiles only; no GPIO, no full D3, no F5 IRQ '
                              'delivery and no F6 DMA model',
            input_mode='incremental' if args.online else 'preloaded',
            input_channel='held-RAM-mailbox + instruction trampoline slot',
            records=[record['text'] for record in records],
            submitted=submitted if args.online else [record['text'] for record in records],
            cases=verified,
            run_summary=summary,
            installed=None if parsed is None else parsed['installed'],
            cpu_instance='cpu', ip_instance=config['active_id'],
            components=dict(
                cpu=dict(profile=config['cpu_profile'],
                         model=cpu.runtime_document['module_name'],
                         declared_hz=self_rate(cpu)),
                target=dict(profile=config['source_profile'],
                            model=ip.runtime_document['module_name'],
                            declared_hz=self_rate(ip),
                            bus='axi4-lite', kind=ip.runtime_document['kind'])),
            target=dict(window=dict(base=windows['ip_base'], size=windows['ip_size']),
                        register=declaration['register'],
                        write_mask=hex(declaration['write_mask']),
                        read_mask=hex(declaration['read_mask']),
                        address_width=declaration['address_width'],
                        channel_join='a write is one AW, one W and one B handshake; a read is '
                                     'one AR and one R handshake; OKAY only'),
            ram=dict(base=windows['ram_base'], size=windows['ram_size']),
            ip_window=dict(base=windows['ip_base'], size=windows['ip_size']),
            layout=firmware['layout'], slot_return=firmware['slot_return'],
            irq_delivery='unknown', dma='not_present',
            # A response code the slave never drives is not claimed as covered.
            error_response=('unknown' if summary is None
                            else str(summary.get('error_response', 'unknown'))),
            channel_handshakes={key: (None if summary is None else summary.get(key, 'unknown'))
                                for key in ('axi_aw', 'axi_w', 'axi_b', 'axi_ar', 'axi_r')},
            fixed_target_inputs={row['endpoint_id'] + '.' + row['role']: row['value']
                                 for row in request_document['tuning']['fixed_inputs']},
            certificate='none', replay='not_performed',
            total_seconds=time.monotonic() - started)
        if failure is not None:
            result['failure'] = failure
        mismatched = [mismatch for mismatch in checks if mismatch is not None]
        result['status'] = final_status(result, parsed, records)
        if result['status'] == 'observations_passed' and (mismatched or len(cases) != len(records)):
            result['status'] = 'failed'
            result['failure'] = 'correspondence: ' + mismatched[0] if mismatched else 'case count'
        if summary is not None:
            missing_keys = [key for key in SUMMARY_COUNTER_KEYS if key not in summary]
            if missing_keys:
                result['status'] = 'failed'
                result['failure'] = 'run summary lacks ' + ','.join(missing_keys)
        (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'output': str(args.output),
                          'cases': len(verified), 'run_seconds': result['run_seconds'],
                          'total_seconds': result['total_seconds']}))
        return 0 if result['status'] == 'observations_passed' else 1


def self_rate(artifact):
    """The one declared clock rate of a generated model, or None."""
    clocks = artifact.runtime_document['clock_schedule']['clocks']
    return clocks[0]['frequency_hz'] if len(clocks) == 1 else None


if __name__ == '__main__':
    raise SystemExit(main())
