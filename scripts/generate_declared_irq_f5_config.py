#!/usr/bin/env python3
"""Combine an adapted CPU profile and an IP's IRQ behavior for the F5 runner.

The IP behavior gives the real trigger, output and ISR register accesses; it
does not establish that an arbitrary IP has those semantics. The existing
source/profile admission and native observation remain the authority.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]


def generate(cpu_profile, behavior, *, base=ROOT, active_base=0x40001000,
             idle_base=0x40002000, image_start=0x10000, image_end=0x30000,
             result_address=0x10c40):
    from myfuzz.integration.declared_irq_consumption import admit_declared_irq_consumption
    from scripts.run_declared_irq_f5 import f5_fields, trigger_words

    required = ('source_request', 'instance_name', 'source_port', 'source_bit_offset',
                'pulse_width_ticks', 'window_size', 'trigger_writes', 'status_offsets',
                'status_registers', 'clear_writes', 'status_cause_bits')
    if (not isinstance(behavior, dict) or behavior.get('schema_version') != 'declared_irq_behavior.v1'
            or any(key not in behavior for key in required)):
        raise ValueError('declared IRQ behavior requires source and trigger description')
    name = behavior['instance_name']
    if not isinstance(name, str) or not name:
        raise ValueError('declared IRQ behavior instance name required')
    config = dict(schema_version='declared_irq_f5_config.v1', cpu_profile=str(cpu_profile),
        source_request=behavior['source_request'], source_adapter='declared-output.v1',
        source_port=behavior['source_port'], source_bit_offset=behavior['source_bit_offset'],
        pulse_width_ticks=behavior['pulse_width_ticks'], active_id=name+'_active',
        idle_id=name+'_idle', active_base=active_base, idle_base=idle_base,
        trigger_writes=behavior['trigger_writes'], target_window=dict(base=active_base, size=behavior['window_size']),
        status_offsets=behavior['status_offsets'], status_registers=behavior['status_registers'],
        clear_writes=behavior['clear_writes'], status_cause_bits=behavior['status_cause_bits'],
        image_start=image_start, image_end=image_end, result_address=result_address)
    admission = admit_declared_irq_consumption(config, base_dir=Path(base))
    if admission['status'] != 'admitted':
        raise ValueError('declared IRQ admission: ' + str(admission.get('reason')))
    fields = f5_fields(config, admission)
    trigger_words(active_base, behavior['trigger_writes'], fields['window_size'])
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu-profile', required=True)
    parser.add_argument('--irq-behavior', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--active-base', type=lambda text: int(text, 0), default=0x40001000)
    parser.add_argument('--idle-base', type=lambda text: int(text, 0), default=0x40002000)
    parser.add_argument('--image-start', type=lambda text: int(text, 0), default=0x10000)
    parser.add_argument('--image-end', type=lambda text: int(text, 0), default=0x30000)
    parser.add_argument('--result-address', type=lambda text: int(text, 0), default=0x10c40)
    args = parser.parse_args()
    behavior = json.loads(args.irq_behavior.read_text())
    config = generate(args.cpu_profile, behavior, active_base=args.active_base,
        idle_base=args.idle_base, image_start=args.image_start, image_end=args.image_end,
        result_address=args.result_address)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        json.dump(config, output, indent=2)
        output.write('\n')
    print(json.dumps({'config': str(args.output), 'admission': 'static', 'native': 'not-run'}))


if __name__ == '__main__':
    main()
