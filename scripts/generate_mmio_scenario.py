#!/usr/bin/env python3
"""Generate an F1–F4 MMIO scenario from adapted component profiles.

The generator uses declared CPU/IP interfaces and an existing IP capability
sidecar. It does not infer missing electrical inputs, register side effects or
runtime support. The resulting scenario still needs preparation and execution.
"""
import argparse
import json
import os
from pathlib import Path
import sys
from copy import deepcopy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.local_harness.request import load_local_harness_request
from scripts.profile_scenario_inputs import _member, _request, _component_request, _capability


def _select_name(declaration, key, candidates, description):
    """Use the profile default only when it names one compatible choice."""
    names = tuple(dict.fromkeys(candidates))
    selected = declaration.get(key)
    if selected is not None:
        if selected not in names:
            raise ValueError(description + ' missing or incompatible')
        return selected
    if len(names) != 1:
        raise ValueError(description + ' must be specified when absent or ambiguous')
    return names[0]


def generate_scenario(declaration, *, base_dir, output):
    base = Path(base_dir).resolve()
    out = Path(output).resolve()
    if not out.is_relative_to(base) or out == base or out.exists():
        raise ValueError('output must be a new directory under base_dir')
    cpu_path, cpu_request, cpu, cpu_generated = _component_request(declaration, 'cpu', base, out)
    ip_path, ip_request, ip, ip_generated = _component_request(declaration, 'ip', base, out)
    capability_path, capability, capability_generated = _capability(
        ip, declaration.get('ip_capability'), 'ip', base, out)
    if cpu.kind != 'cpu' or ip.kind != 'peripheral' or cpu_request.instance_id == ip_request.instance_id:
        raise ValueError('one CPU and one distinct peripheral are required')
    cpu_endpoint = _select_name(declaration, 'cpu_endpoint',
        (e.endpoint_id for e in cpu.endpoints if e.function in ('data_memory_master', 'memory_master')),
        'CPU data endpoint')
    ip_endpoint = _select_name(declaration, 'ip_endpoint',
        (e.endpoint_id for e in ip.endpoints if e.function == 'mmio_slave' and e.protocol in (('apb', '3'),('wishbone','classic'))
         and any(c.endpoint_id == e.endpoint_id and {'read', 'write'} <= set(c.operations)
                 for c in capability.endpoint_capabilities)), 'supported MMIO target endpoint')
    endpoint=next(e for e in ip.endpoints if e.endpoint_id==ip_endpoint)
    if ip_generated is not None:
        tuning = deepcopy(declaration.get('ip_tuning', {}))
        if not isinstance(tuning, dict):
            raise ValueError('IP tuning must be an object')
        template,variant=(('target.apb3','full-word') if endpoint.protocol==('apb','3') else
                          ('target.wishbone','word-addressed-registered-ack'))
        tuning.setdefault('endpoint_policies', [dict(endpoint_id=ip_endpoint,
            template_id=template, template_version='1', variant_id=variant, max_outstanding=1)])
        ip_generated.update(schema_version='local_harness.v2', tuning=tuning)
        ip_request = load_local_harness_request(ip_generated)
    endpoints = [e for e in capability.endpoint_capabilities if e.endpoint_id == ip_endpoint]
    if len(endpoints) != 1 or not {'read', 'write'} <= set(endpoints[0].operations):
        raise ValueError('declared read/write capability required')
    side_effectful=declaration.get('allow_side_effectful_register',False)
    if type(side_effectful) is not bool or (side_effectful and 'register' not in declaration):
        raise ValueError('side-effectful register requires explicit register selection')
    register_name = _select_name(declaration, 'register',
        (r.register for r in capability.register_semantics
         if any(p.name == r.register and p.width == 32 and p.access == 'rw' and (side_effectful or p.side_effect == 'none')
                for p in ip.address.registers)
         and r.lsb == 0 and r.width == 32 and r.access == 'rw' and (side_effectful or r.side_effect == 'none')
         and r.read_mask and r.write_mask), 'register')
    registers = [r for r in ip.address.registers if r.name == register_name]
    semantics = [r for r in capability.register_semantics if r.register == register_name]
    if (len(registers) != 1 or len(semantics) != 1
            or ('register_offset' in declaration and registers[0].offset != declaration['register_offset'])
            or registers[0].width != 32 or registers[0].access != 'rw' or (not side_effectful and registers[0].side_effect != 'none')
            or semantics[0].lsb != 0 or semantics[0].width != 32 or semantics[0].access != 'rw'
            or (side_effectful and semantics[0].side_effect != registers[0].side_effect)
            or (not side_effectful and semantics[0].side_effect != 'none') or not semantics[0].read_mask or not semantics[0].write_mask):
        raise ValueError('declared 32-bit read/write register required')
    mask = semantics[0].write_mask
    # A masked full-word write always declares its policy: which bits are really
    # stored and that the value's reserved bits are zero.  A real write side
    # effect is a separate declaration and never substitutes for the policy;
    # allow_side_effectful_register only permits selecting a side-effectful
    # register at all.
    if mask != 0xffffffff and semantics[0].write_policy != 'full_word_reserved_zero':
        raise ValueError('partial register mask needs full_word_reserved_zero policy')
    values = declaration['write_values']
    if not isinstance(values, list) or not values or any(type(v) is not int or not 0 <= v <= 0xffffffff or v & ~mask for v in values):
        raise ValueError('write_values must fit declared register mask')
    address = declaration['mmio_base']
    ram = declaration['ram']
    if (type(address) is not int or address < 0 or address % ip.address.alignment
            or address + ip.address.window_size > 1 << 32
            or not isinstance(ram, dict) or type(ram.get('base')) is not int or type(ram.get('size')) is not int
            or ram['base'] < 0 or ram['size'] < 4 or ram['base'] + ram['size'] > 1 << 32
            or max(address, ram['base']) < min(address + ip.address.window_size, ram['base'] + ram['size'])):
        raise ValueError('valid disjoint RV32 MMIO and RAM windows required')
    absolute = address + registers[0].offset
    if absolute % 4 or registers[0].offset + 4 > ip.address.window_size:
        raise ValueError('aligned register must fit MMIO window')
    rounds = declaration.get('rounds', 128)
    if type(rounds) is not int or not 1 <= rounds <= 65536:
        raise ValueError('rounds must be in 1..65536')
    read_record = absolute.to_bytes(4, 'little').hex()
    write_records = [v.to_bytes(4, 'little').hex() for v in values]
    records = [item for write in write_records for item in ('F4:' + write, 'F2:' + read_record)]
    memory_flows = declaration.get('memory_flows', False)
    if type(memory_flows) is not bool:
        raise ValueError('memory_flows must be boolean')
    if memory_flows:
        records = ['F3:' + write_records[0], 'F1:03200000'] + records
    relative = lambda p: str(p.relative_to(base))
    compose = {'schema_version': 'harness_compose.v1',
        'cpu': {'instance_id': cpu_request.instance_id, 'request': os.path.relpath(cpu_path, out), 'data_endpoint': cpu_endpoint},
        'devices': [{'device_id': ip_request.instance_id, 'instance_id': ip_request.instance_id,
                     'request': os.path.relpath(ip_path, out), 'bus_endpoint': ip_endpoint,
                     'base': address, 'size': ip.address.window_size}],
        'memory': [{'resource_id': 'ram', 'component_instance': cpu_request.instance_id,
                    'base': ram['base'], 'size': ram['size'], 'read': True, 'write': True,
                    'execute': True, 'initialization_policy': 'preload'}]}
    supplement = {'schema_version': 'compiled_execution_file_supplement.v1',
                  'request_supplements': {}, 'ownership': {'fields': [], 'owners': []}, 'physical_port_map': []}
    descriptor = {'schema_version': 'generic_scenario_descriptor.v1', 'scenario_id': declaration['name'], 'root': '.',
                  'compose': relative(out / 'compose.json'), 'supplement': relative(out / 'execution_supplement.json'),
                  'capability': relative(capability_path), 'flow_ids': ['F2', 'F4'],
                  'executors': {'F2': 'compiled_mmio', 'F4': 'compiled_mmio'},
                  'f2_records': [read_record], 'f4_records': write_records, 'rounds': rounds}
    if memory_flows:
        descriptor.update(flow_ids=['F1','F2','F3','F4'],
            executors={flow:'compiled_mmio' for flow in ('F1','F2','F3','F4')},
            f1_records=['03200000'], f3_records=[write_records[0]])
    out.mkdir(parents=True)
    for name, value in (('compose.json', compose), ('execution_supplement.json', supplement),
                        ('generic_scenario.json', descriptor), ('acceptance_sequence.json', records)):
        (out / name).write_text(json.dumps(value, indent=2) + '\n')
    for path, document in ((cpu_path, cpu_generated), (ip_path, ip_generated),
                           (capability_path, capability_generated)):
        if document is not None:
            path.write_text(json.dumps(document, indent=2) + '\n')
    result = out / 'generic_scenario.json'
    load_descriptor(result, base_dir=base)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-dir', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        descriptor = generate_scenario(json.loads(args.config.read_text()), base_dir=args.base_dir, output=args.output)
    except (KeyError, TypeError, ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')
    print(descriptor)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
