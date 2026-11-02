#!/usr/bin/env python3
"""Render the existing F6 firmware without the GPIO companion for a spike."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
from myfuzz.composition.component_profile import load_component_profile


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value):
        raise ValueError('generated C++ identifier invalid')
    return value


def _physical(artifact, *, endpoint=None, physical, direction):
    matches = [row for row in artifact['physical_exports'] if row['physical_port'] == physical
               and row['direction'] == direction and (endpoint is None or row['endpoint_id'] == endpoint)]
    if len(matches) != 1 or matches[0]['width'] != 1:
        raise ValueError('IRQ physical export unsupported')
    return _identifier(matches[0]['runtime_name'])


def _backend(artifact, required):
    rows = {(r['channel'], r['role']): r for r in artifact['backend_ports']}
    if len(rows) != len(artifact['backend_ports']):
        raise ValueError('duplicate backend role')
    for (channel, role), (direction, width) in required.items():
        row = rows.get((channel, role))
        if (row is None or row['name'] != channel + '_' + role or row['direction'] != direction
                or (width is not None and row['width'] != width)):
            raise ValueError('backend role shape unsupported: ' + channel + '.' + role)
    return rows


def write_binding(path, contract, cpu, dma, *, assume_lockstep=False, profile_base=ROOT):
    """Generate only shape-compatible model bindings; never infer IRQ behavior."""
    if cpu['kind'] != 'obi_cpu' or dma['kind'] != 'wishbone_dma':
        raise ValueError('spike requires OBI CPU and Wishbone DMA')
    clocks = []
    for artifact in (cpu, dma):
        clocks = artifact['clock_schedule']['clocks']
        if (len(clocks) != 1 or clocks[0]['signal'] != 'clk'
                or clocks[0]['half_period_fast_ticks'] != 1 or clocks[0]['ratio'] != 1
                or clocks[0]['first_rising_fast_tick'] != 1):
            raise ValueError('spike requires one matching clock')
        profile = load_component_profile(Path(profile_base) / artifact['plan']['profile_path'])
        if profile.capabilities.get('verilator_timing_mode') not in (None, 'no_timing'):
            raise ValueError('timing-model delays unsupported')
    cpu_hz = cpu['clock_schedule']['clocks'][0]['frequency_hz']
    dma_hz = dma['clock_schedule']['clocks'][0]['frequency_hz']
    if cpu_hz != dma_hz and not assume_lockstep:
        raise ValueError('different declared clock rates require explicit --assume-lockstep')
    cpu_shape = {}
    for channel in ('i', 'd'):
        for role, direction, width in (
            ('req_valid','output',1), ('req_ready','input',1), ('req_write','output',1),
            ('req_addr','output',32), ('req_wdata','output',32), ('req_be','output',4),
            ('rsp_valid','input',1), ('rsp_ready','output',1), ('rsp_rdata','input',32), ('rsp_error','input',1)):
            cpu_shape[channel,role] = (direction,width)
    _backend(cpu, cpu_shape)
    dma_shape = {('swb',role):(direction,width) for role,direction,width in (
        ('cyc','input',1),('stb','input',1),('we','input',1),('adr','input',None),
        ('dat_w','input',32),('stall','output',1),('ack','output',1),('dat_r','output',32))}
    dma_shape.update({('mwb',role):(direction,width) for role,direction,width in (
        ('cyc','output',1),('stb','output',1),('we','output',1),('adr','output',30),
        ('dat_w','output',32),('stall','input',1),('ack','input',1),('dat_r','input',32),('err','input',1))})
    dma_ports = _backend(dma, dma_shape)
    if not 1 <= dma_ports['swb','adr']['width'] <= 32:
        raise ValueError('DMA control address width unsupported')
    edge = dma['dma_edge_contract']
    if (edge['master_address_units'] != 'word' or edge['master_address_shift'] != 2
            or edge['environment_max_outstanding'] != 1 or edge['same_edge_accept_and_complete']):
        raise ValueError('DMA edge shape unsupported')
    control_signal, master_signal = edge.get('control_byte_enable_signal'), edge.get('master_byte_enable_signal')
    if control_signal not in (None, 'swb_sel') or master_signal not in (None, 'mwb_sel'):
        raise ValueError('DMA SEL signal name unsupported')
    for channel, signal, direction in (('swb',control_signal,'input'), ('mwb',master_signal,'output')):
        sel = dma_ports.get((channel,'sel'))
        if ((signal is None) != (sel is None) or
                sel is not None and (sel['name'] != signal or sel['direction'] != direction or sel['width'] != 4)):
            raise ValueError('DMA SEL role mismatch')
    if (master_signal is None and edge.get('master_fixed_byte_enable') != 15):
        raise ValueError('DMA fixed master byte-enable unsupported')
    irq = contract['irq']
    policy = irq['delivery_policy']
    if policy not in ('level', 'IrqPulseDelivery'):
        raise ValueError('IRQ delivery policy unsupported')
    irq_cpu = _physical(cpu, endpoint=irq['consumer_endpoint_id'], physical=irq['consumer_port'], direction='input')
    irq_dma = _physical(dma, endpoint=irq['producer_endpoint_id'], physical=irq['producer_port'], direction='output')
    ports = {row['name'] for row in cpu['runtime_ports']}
    rvfi = {}
    for name in ('valid', 'trap', 'insn'):
        matches = [row['runtime_name'] for row in cpu['physical_exports']
                   if row['physical_port'] == 'rvfi_' + name and row['direction'] == 'output']
        if len(matches) == 1:
            rvfi[name] = _identifier(matches[0])
    have_rvfi = len(rvfi) == 3
    have_take = 'probe_irq_taken_pre' in ports and bool(irq.get('native_take_provider'))
    clear = contract['dma']['behavior']['irq_clear']
    if clear['method'] not in ('none', 'write'):
        raise ValueError('IRQ clear behavior unsupported')
    p, ram = contract['program_contract'], contract['memory']['resource']
    definitions = {
        'F6_CPU_HEADER': '"V' + _identifier(cpu['module_name']) + '.h"',
        'F6_DMA_HEADER': '"V' + _identifier(dma['module_name']) + '.h"',
        'F6_CPU_MODEL': 'V' + _identifier(cpu['module_name']),
        'F6_DMA_MODEL': 'V' + _identifier(dma['module_name']),
        'F6_CPU_IRQ': irq_cpu, 'F6_DMA_IRQ': irq_dma,
        'F6_HAVE_RVFI': int(have_rvfi), 'F6_HAVE_TAKE': int(have_take),
        'F6_CONTROL_SEL': int(edge.get('control_byte_enable_signal') == 'swb_sel'),
        'F6_MASTER_SEL': int(edge.get('master_byte_enable_signal') == 'mwb_sel'),
        'F6_PULSE_TICKS': irq['target_local_ticks'] if policy == 'IrqPulseDelivery' else 0,
        'F6_RAM_BASE': ram['base'], 'F6_RAM_SIZE': ram['size'],
        'F6_DMA_BASE': contract['control']['base'], 'F6_DMA_SIZE': contract['control']['size'],
        'F6_SRC': p['source_address'], 'F6_DST': p['destination_address'], 'F6_RESULT': p['result_base'],
        'F6_SLOT_BASE': p['slot_base'], 'F6_SLOT_BYTES': p['slot_bytes'],
        'F6_PREFIX_BYTES': p['online_prefix_bytes'], 'F6_SLOT_COUNT': p['slot_count'],
        'F6_CLEAR_REQUIRED': int(clear['method'] == 'write'),
        'F6_CLEAR_OFFSET': clear.get('offset', 0), 'F6_CLEAR_VALUE': clear.get('value', 0),
        'F6_CPU_RESET_ASSERT': cpu['driver_reset']['reset_assert_ticks'],
        'F6_CPU_RESET_RELEASE': cpu['driver_reset']['reset_release_ticks'],
        'F6_DMA_RESET_ASSERT': dma['driver_reset']['reset_assert_ticks'],
        'F6_DMA_RESET_RELEASE': dma['driver_reset']['reset_release_ticks'],
        'F6_CPU_DECLARED_HZ': cpu_hz, 'F6_DMA_DECLARED_HZ': dma_hz,
        'F6_ASSUMED_LOCKSTEP': int(cpu_hz != dma_hz),
    }
    if have_rvfi:
        definitions.update({'F6_RVFI_' + k.upper(): v for k, v in rvfi.items()})
    if have_take:
        definitions['F6_CPU_TAKE'] = 'probe_irq_taken_pre'
    path.write_text('#pragma once\n' + ''.join(f'#define {k} {v}\n' for k, v in definitions.items()))


def render_firmware(path, raw):
    """Render the selected F6 contract without its optional companions."""
    candidate = compile_f6_candidate_layout(path).decode(raw)
    contract = deepcopy(path['execution_contract'])
    p = contract['program_contract']
    if any(key in p for key in ('declared_irq', 'storage_support', 'custom_irq')):
        raise ValueError('spike requires OBI CPU and no extra firmware companion')
    p.pop('gpio_irq', None)
    p['initial_image'], p['initial_image_sha256'] = [], None
    firmware = build_f6_firmware(contract)
    images = dict(firmware.initial_images)
    images[p['slot_base']] = firmware.prefix(candidate, case_index=0)
    return contract, candidate, ''.join(f'{address:x} {data.hex()}\n'
                                       for address, data in sorted(images.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiled-paths', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpu-artifact', type=Path)
    parser.add_argument('--dma-artifact', type=Path)
    parser.add_argument('--binding-header', type=Path)
    parser.add_argument('--profile-base', type=Path, default=ROOT)
    parser.add_argument('--assume-lockstep', action='store_true',
                        help='explicitly simulate equal clock periods when profile frequencies differ')
    args = parser.parse_args()
    paths = json.loads(args.compiled_paths.read_text())['paths']
    path = next(row for row in paths if row['flow_id'] == 'F6')
    contract, candidate, firmware = render_firmware(path, bytes.fromhex('0110c00008000000'))
    p = contract['program_contract']
    args.output.write_text(firmware)
    if any((args.cpu_artifact, args.dma_artifact, args.binding_header)):
        if not all((args.cpu_artifact, args.dma_artifact, args.binding_header)):
            parser.error('CPU artifact, DMA artifact and binding header must be supplied together')
        write_binding(args.binding_header, contract, json.loads(args.cpu_artifact.read_text()),
                      json.loads(args.dma_artifact.read_text()),
                      assume_lockstep=args.assume_lockstep, profile_base=args.profile_base)
    print(json.dumps({'scope': 'profile-bound F6 spike; no GPIO or certificate',
        'slot': p['slot_base'], 'result_base': p['result_base'],
        'source_address': p['source_address'], 'destination_address': p['destination_address'],
        'words': list(candidate.words), 'segments': len(firmware.splitlines())}))


if __name__ == '__main__':
    main()
