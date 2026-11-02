#!/usr/bin/env python3
"""Prepare and run one profile-selected OBI CPU + Wishbone DMA exploration.

Models remain separate: the C++ host simulates RAM, control routing and IRQ.
The compact observations do not grant the full F6 certificate or replay.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.inprocess_f6_firmware import write_binding
from scripts.inprocess_feedback import F6_RULE, F6DmaFeedback, feedback_line, hex_bytes
from scripts.profile_scenario_inputs import _component_request, _capability
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
from myfuzz.integration.compiled_f6_layout import F6Candidate
from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider


def direct_candidate(raw):
    if type(raw) is not bytes or len(raw) != 8:
        raise ValueError('F6 input must contain eight bytes')
    value = int.from_bytes(raw, 'little')
    return F6Candidate(raw, tuple((value >> (11*i)) & 2047 for i in range(4)))


def render_images(contract, records, *, online=False):
    """Preload each declared slot with the existing F6 firmware encoding."""
    if (not records and not online) or len(records) > contract['program_contract']['slot_count']:
        raise ValueError('F6 batch must contain 1..slot_count records')
    candidates = [direct_candidate(raw) for raw in records]
    firmware = build_f6_firmware(contract)
    images = dict(firmware.initial_images)
    for index, candidate in enumerate(candidates):
        address = contract['program_contract']['slot_base'] + index * 256
        images[address] = firmware.prefix(candidate, case_index=index)
    return candidates, images


def online_case_message(firmware, line, index):
    """Use the existing firmware compiler for one on-demand raw8 record."""
    candidate = direct_candidate(bytes.fromhex(line))
    return 'CASE ' + candidate.raw.hex() + ' ' + firmware.prefix(candidate, case_index=index).hex() + '\n'


def online_runner(firmware, submitted, feedback=None):
    """Relay native boundary events and feed one compiled case at a time.

    With a feedback loop every record after the first is derived from the data
    the DMA actually moved in the previous case; the pipe is then unused and the
    loop stops after the requested number of cases.
    """
    def run(command, log_path):
        with log_path.open('w') as log:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
            ending=False
            try:
                for line in process.stdout:
                    log.write(line); log.flush()
                    print(line, end='', flush=True)
                    if feedback is not None:
                        feedback.note(line)
                    if not line.startswith('NEED_RECORD '):
                        continue
                    index = int(line.split()[1])
                    if index != len(submitted):
                        raise RuntimeError('native requested an out-of-order F6 slot')
                    if feedback is not None:
                        if index >= feedback.cases:
                            if not ending:
                                process.stdin.write('END\n'); process.stdin.flush()
                                ending = True
                            continue
                        raw = feedback.raw(index)
                        message = online_case_message(firmware, raw.hex(), index)
                        if feedback.records:
                            note = feedback_line(feedback.records[-1])
                            log.write(note); log.flush()
                            print(note, end='', flush=True)
                        process.stdin.write(message); process.stdin.flush()
                        submitted.append(raw.hex())
                        continue
                    while True:
                        user_line = sys.stdin.readline()
                        if not user_line or user_line.strip().upper() == 'END':
                            process.stdin.write('END\n'); process.stdin.flush()
                            break
                        try:
                            message = online_case_message(firmware, user_line.strip(), index)
                        except ValueError as error:
                            print('invalid F6 record: ' + str(error), file=sys.stderr, flush=True)
                            continue
                        process.stdin.write(message); process.stdin.flush()
                        submitted.append(message.split()[1])
                        break
                return process.wait()
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait()
    return run


def direct_program(boot, layout, control_size):
    """Build the small firmware layout used by this observation-only run."""
    values = dict(ram_base=0x10000, ram_size=0x20000, control_base=0x40000000,
        isr_address=0x1022c, park_address=0x10400, slot_base=0x11000, slot_count=8,
        source_address=0x22000, destination_address=0x23000, result_base=0x24000)
    if not isinstance(layout, dict) or set(layout) - set(values):
        raise ValueError('unsupported F6 layout field')
    values.update(layout)
    if any(type(v) is not int or v < 0 for v in values.values()):
        raise ValueError('F6 layout requires nonnegative integer addresses')
    rb, rs, cb = values['ram_base'], values['ram_size'], values['control_base']
    if rs < 4 or rb + rs > 1 << 32 or cb + control_size > 1 << 32:
        raise ValueError('F6 RAM or control range invalid')
    if max(rb, cb) < min(rb + rs, cb + control_size):
        raise ValueError('F6 RAM and MMIO overlap')
    spans = [(boot, 4), (values['isr_address'], 4), (values['park_address'], 4),
             (values['slot_base'], values['slot_count'] * 256),
             (values['source_address'], 16), (values['destination_address'], 16),
             (values['result_base'], values['slot_count'] * 24)]
    if any(start < rb or start + size > rb + rs for start, size in spans):
        raise ValueError('F6 program and data must fit the declared RAM')
    p = {key: values[key] for key in ('isr_address','park_address','slot_base','slot_count',
        'source_address','destination_address','result_base')}
    p.update(schema_version='compiled_F6_program.v1', boot_address=boot,
        slot_bytes=256, online_prefix_bytes=128, result_stride=24,
        operand_instruction_offsets=[40,48,56,64], initial_image=[],
        initial_image_sha256=None, instruction_source_id='cpu.image')
    return p, dict(base=rb, size=rs), dict(base=cb, size=control_size)


def _artifact(request):
    from myfuzz.local_harness import (plan_local_harness, render_local_harness,
        verify_local_source_lock, render_local_runtime, render_local_driver)
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def prepare_inputs(declaration, *, output, raw, assume_lockstep=False, online=False):
    """Prepare only the actual CPU/DMA artifacts; no full scenario or D3."""
    if any(key in declaration for key in ('target','declared_irq_behavior','custom_irq_bit','custom_gpio_irq_bit')):
        raise ValueError('in-process F6 does not support extra targets or custom IRQ')
    _, cpu_request, cpu_profile, _ = _component_request(declaration, 'cpu', ROOT, output)
    _, dma_request, dma_profile, _ = _component_request(declaration, 'dma', ROOT, output)
    if (cpu_request.instance_id == dma_request.instance_id or cpu_profile.kind != 'cpu'
            or cpu_profile.cpu is None or cpu_profile.cpu.family.lower() != 'riscv'
            or cpu_profile.cpu.xlen != 32 or 'i' not in cpu_profile.cpu.extensions
            or cpu_profile.cpu.irq_entry_polarity != 'active_high'
            or cpu_profile.cpu.irq_semantics != 'machine_external'):
        raise ValueError('in-process F6 requires distinct RV32 CPU and DMA with active-high IRQ')
    if 'dma_capability' in declaration:
        _capability(dma_profile, declaration['dma_capability'], 'dma', ROOT, output)
    provider = select_f6_dma_source_provider(dma_profile, base_dir=ROOT)
    irq_endpoint = next((e for e in cpu_profile.endpoints
                         if e.endpoint_id == cpu_profile.cpu.irq_entry_endpoint), None)
    fields = ([] if irq_endpoint is None or irq_endpoint.function != 'interrupt_entry' else [f for f in irq_endpoint.fields
        if f.role == cpu_profile.cpu.irq_entry_role and f.direction == 'input' and f.width == 1])
    if len(fields) != 1 or len(fields[0].aliases) != 1:
        raise ValueError('CPU requires one declared IRQ input')
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract_for_profile, verify_native_irq_cpu_source)
    try:
        native_irq = native_irq_receipt_contract_for_profile(cpu_profile)
    except ValueError:
        native_irq = None
    if native_irq is not None:
        verify_native_irq_cpu_source(cpu_profile, base_dir=ROOT)
    boot = source_backed_boot_fetch(cpu_profile, base_dir=ROOT,
                                    configured_boot_base=cpu_profile.cpu.reset_vector)
    program, ram, control = direct_program(boot, declaration.get('layout', {}), dma_profile.address.window_size)
    if control['base'] % dma_profile.address.alignment:
        raise ValueError('DMA control base alignment invalid')
    irq = dict(consumer_endpoint_id=irq_endpoint.endpoint_id, consumer_port=fields[0].aliases[0],
        producer_endpoint_id=provider.irq_endpoint_id, producer_port=provider.irq_port,
        delivery_policy='level' if provider.irq_trigger == 'level' else 'IrqPulseDelivery',
        target_local_ticks=0 if provider.irq_trigger == 'level' else declaration.get('irq_pulse_ticks', 16),
        native_take_provider=native_irq)
    if irq['delivery_policy'] == 'IrqPulseDelivery' and (type(irq['target_local_ticks']) is not int
            or not 1 <= irq['target_local_ticks'] <= 4096):
        raise ValueError('pulse IRQ requires a positive delivery width')
    contract = dict(schema_version='inprocess_f6_observation.v1',
        cpu={'instance_id': cpu_request.instance_id},
        dma=dict(instance_id=dma_request.instance_id, csr=provider.csr, behavior=provider.behavior,
                 source_contract=provider.source),
        irq=irq, program_contract=program, memory={'resource':ram}, control=control)
    records = (raw,) if isinstance(raw, bytes) else tuple(raw)
    _, images = render_images(contract, records, online=online)
    if any(address < ram['base'] or address + len(data) > ram['base'] + ram['size']
           for address, data in images.items()):
        raise ValueError('F6 firmware segments must fit the declared RAM')
    cpu, dma = _artifact(cpu_request), _artifact(dma_request)
    write_binding(output / 'f6_binding.h', contract, cpu.runtime_document, dma.runtime_document,
                  assume_lockstep=assume_lockstep, profile_base=ROOT)
    (output / 'firmware.txt').write_text(''.join(f'{address:x} {data.hex()}\n'
                                               for address, data in sorted(images.items())))
    return (cpu, dma), contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True, help='CPU/DMA profile declaration')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory inside the workspace')
    records_group = parser.add_mutually_exclusive_group()
    records_group.add_argument('--record', help='one F6 raw8 record in hexadecimal')
    records_group.add_argument('--records', help='comma-separated F6 raw8 records, at most slot_count')
    records_group.add_argument('--online', action='store_true', help='read one raw8 record per line on demand')
    parser.add_argument('--feedback', action='store_true',
                        help='derive every case after the first from the previous real DMA data')
    parser.add_argument('--seed', help='first feedback record as eight hexadecimal bytes')
    parser.add_argument('--cases', type=int, help='number of feedback cases to run')
    parser.add_argument('--assume-lockstep', action='store_true',
                        help='explicitly simulate equal periods if declared clock frequencies differ')
    args = parser.parse_args()
    if args.feedback:
        args.online = True
        if args.record is not None or args.records is not None:
            parser.error('--feedback cannot be combined with --record or --records')
    elif args.seed is not None or args.cases is not None:
        parser.error('--seed and --cases require --feedback')
    declaration = json.loads(args.config.read_text())
    values = [] if args.online else args.records.split(',') if args.records is not None else [args.record or '0110c00008000000']
    try:
        raws = [bytes.fromhex(value) for value in values]
        for raw in raws:
            direct_candidate(raw)
    except ValueError as error:
        parser.error(str(error))
    feedback = None
    if args.feedback:
        seed_hex = args.seed or declaration.get('feedback_seed') or '0110c00008000000'
        try:
            seed_raw = hex_bytes(seed_hex)
            direct_candidate(seed_raw)
        except ValueError as error:
            parser.error(str(error))
        cases = args.cases if args.cases is not None else declaration.get('feedback_cases', 2)
        feedback = F6DmaFeedback(seed_raw, cases=cases)
    if args.output.exists():
        raise ValueError('output directory already exists')
    args.output.mkdir(parents=True)
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.inprocess_build import build_link_run
    started = time.monotonic()
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), harness_validation_scope(), execution_validation_scope():
        artifacts, contract = prepare_inputs(declaration, output=args.output,
            raw=raws, assume_lockstep=args.assume_lockstep, online=args.online)
        encoded_records = '--online' if args.online else ','.join(raw.hex() for raw in raws)
        submitted = []
        runner = online_runner(build_f6_firmware(contract), submitted, feedback) if args.online else None
        result = build_link_run(artifacts, ROOT / 'scripts/inprocess_obi_wb_dma_spike.cpp',
            args.output, args.cache, [str((args.output / 'firmware.txt').resolve()), encoded_records],
            root=ROOT, runner=runner)
        actual_records = submitted if args.online else [raw.hex() for raw in raws]
        result.update(scope='one profile-selected OBI CPU + Wishbone DMA; no full F6 certificate or replay',
            preparation_scope='two component profiles only; no GPIO or full D3',
            record=actual_records[0] if len(actual_records) == 1 else None,
            records=actual_records,
            input_mode='feedback' if feedback is not None else 'online' if args.online else 'preloaded',
            cpu_instance=contract['cpu']['instance_id'],
            dma_instance=contract['dma']['instance_id'],
            assume_lockstep=args.assume_lockstep, total_seconds=time.monotonic()-started,
            slot_count=contract['program_contract']['slot_count'],
            input_channel='held-instruction-fetch')
        if feedback is not None:
            result.update(feedback_rule=F6_RULE, cases_requested=feedback.cases,
                          feedback=feedback.records, feedback_observations=feedback.observations)
        (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'output': str(args.output),
                          'run_seconds': result['run_seconds'], 'total_seconds': result['total_seconds']}))
        return result['returncode']


if __name__ == '__main__':
    raise SystemExit(main())
