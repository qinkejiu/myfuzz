#!/usr/bin/env python3
"""Real CV32E20 + ZipDMA sessions sharing RAM; no ISR or F6 claim.

Build ZipDMA separately with run_zipdma_smoke.build(), then provide its binary.
The host pauses the CPU after its start write while the DMA finishes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _lw, _sw
from myfuzz.local_harness.zipdma_smoke import zipdma_behavior
from myfuzz.local_harness.zipdma_profile_session import create_zipdma_session
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner

SRC, DST, RESULT, MMIO = 0x11000, 0x12000, 0x13000, 0x40001000
WORDS = (0x12345678, 0x89abcdef, 0x31415926, 0xfeedbeef)
DMA_PROFILE = ROOT / 'configs/peripherals/zipdma_smoke/profile.json'
DMA_DRIVER = ROOT / 'src/myfuzz/local_harness/rtl/zipdma_smoke_driver.cpp'


def firmware(base):
    # x1 = control base, x2 = source, x3 = destination, x4 = result.
    w = []
    for rd, value in ((1, MMIO), (2, SRC), (3, DST), (4, RESULT)):
        w.extend(_lui_addi_load(rd, value))
    w.extend((_sw(2, 1, 4), _sw(3, 1, 8), _addi(5, 0, 16),
              _sw(5, 1, 12), _sw(0, 1, 0)))
    for i in range(4):
        w.extend((_lw(6, 3, i * 4), _sw(6, 4, i * 4)))
    w.extend(_lui_addi_load(5, 0x80000000))
    w.extend((_sw(5, 1, 0), _addi(5, 0, 1), _sw(5, 4, 16)))
    w.append(_jal(base + len(w) * 4, base + len(w) * 4))
    return b''.join(word.to_bytes(4, 'little') for word in w)


def check_master_events(events):
    reads = [e['address'] for e in events if not e['write']]
    writes = [e['address'] for e in events if e['write']]
    return (reads == [SRC + 4*i for i in range(4)]
            and writes == [DST + 4*i for i in range(4)]
            and all(e['sel'] == 15 for e in events))


def expected_retirements(base):
    code = firmware(base)
    rows = []
    for offset in range(0, len(code), 4):
        insn = int.from_bytes(code[offset:offset + 4], 'little')
        opcode, rs1 = insn & 0x7f, (insn >> 15) & 31
        if (opcode, rs1) in ((0x23, 1), (0x03, 3)):
            rows.append({'pc': base + offset, 'insn': insn,
                         'operation': 'control_write' if opcode == 0x23 else 'destination_read'})
    return rows


def retirement_evidence(events, expected):
    retired = [e for e in events if e.get('kind') == 'cpu_retire'
               and e.get('component') == 'cpu']
    rows = []
    for item in expected:
        matches = [e for e in retired if e.get('pc_rdata') == item['pc']]
        if not matches:
            rows.append({**item, 'status': 'unknown'})
            continue
        event = matches[0]
        if any(key not in event for key in ('insn', 'trap', 'event_id')):
            status = 'unknown'
        else:
            status = 'observed' if event['insn'] == item['insn'] and event['trap'] == 0 else 'mismatch'
        rows.append({**item, 'status': status, 'retirement': event})
    statuses = {row['status'] for row in rows}
    status = 'mismatch' if 'mismatch' in statuses else 'unknown' if 'unknown' in statuses else 'observed'
    return {'status': status, 'instructions': rows,
            'scope': 'matching PC and opcode in actual RVFI retirement; not ISR acceptance'}


def irq_evidence(events):
    deliveries = [e for e in events if e.get('kind') == 'dataflow_delivery'
                  and tuple(e.get('source', ())) == ('dma', 'irq')
                  and tuple(e.get('target', ())) == ('cpu', 'irq')]
    inputs = [{'event_id': e['event_id'], 'local_tick': e['local_tick'],
               'irq': e['inputs']['irq']} for e in events
              if e.get('component') == 'cpu' and isinstance(e.get('inputs'), dict)
              and 'irq' in e['inputs'] and 'local_tick' in e and 'event_id' in e]
    return {'delivery_status': 'observed_high' if any(e.get('value') == 1 for e in deliveries) else 'unknown',
            'cpu_input_status': 'observed_high' if any(e['irq'] == 1 for e in inputs) else 'unknown',
            'deliveries': deliveries, 'cpu_step_inputs': inputs,
            'cpu_interrupt_acceptance': 'unknown',
            'scope': 'runner delivery and inputs passed to CPU step; not physical interrupt acceptance'}


def dma_build_evidence(binary, profile, driver_sha256, build_record):
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    expected = {'binary_sha256': binary_sha256, 'source_revision': profile['source_revision'],
                'source_sha256': profile['sources'], 'driver_sha256': driver_sha256}
    comparison = ('unknown' if build_record is None else
                  'matching' if build_record.get('status') == 'verified' and
                  all(build_record.get(k) == v for k, v in expected.items()) else 'mismatch')
    return {**expected, 'comparison': comparison, 'build_record': build_record,
            'scope': 'current files compared with self-reported standalone build result; not a build attestation'}


def process_evidence(cpu, dma, dma_process, observed_executable_sha256=None):
    return {'cpu': {'build_receipt': cpu.built_executable_receipt_document(),
                    'launches': cpu.built_executable_launch_observations()},
            'zipdma': {'identity': dma.execution_identity(),
                       'observed_executable_sha256': observed_executable_sha256,
                       'returncode': dma_process.poll(),
                       'reaped': dma_process.poll() is not None}}


def execute(artifact, binary, cache, max_steps, build_record=None):
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    boot = source_backed_boot_fetch(artifact.plan.profile, base_dir=ROOT,
        configured_boot_base=artifact.runtime_document['boot_contract']['configured_boot_base'])
    profile = json.loads(DMA_PROFILE.read_text())
    behavior = zipdma_behavior(profile, ROOT / 'third_party/soc-zipcpu')
    dma_build = dma_build_evidence(binary, profile, hashlib.sha256(DMA_DRIVER.read_bytes()).hexdigest(), build_record)
    dma_build['behavior'] = behavior
    if dma_build['comparison'] == 'mismatch':
        raise ValueError('ZipDMA standalone build result differs from current inputs or binary')
    if boot != 0x10000:
        raise ValueError('smoke layout requires CV32E20 first fetch at 0x10000')
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x4000),),
                              initialization_seed=0, max_initialized_bytes=0x4000)
    memory.preload(boot, firmware(boot))
    memory.preload(SRC, b''.join(w.to_bytes(4, 'little') for w in WORDS))
    dma = create_zipdma_session(load_component_profile(
        ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json'), binary=binary,
        memory_service=MemoryService(memory, TransactionLedger()), base_dir=ROOT)
    router = DataflowRouter((DeviceWindow('dma', MMIO, 16, dma),))
    cpu = GeneratedCve2Session(artifact, base_dir=ROOT, cache_dir=cache, memory=memory,
                               router=router, physical_tick_samples=True)
    cpu.configure_built_executable_receipt()
    ownership = compile_ownership((InputField('cpu', 'irq', 1),),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),))
    runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma}, ownership=ownership,
                            bindings=(Binding('dma', 'irq', 'cpu', 'irq', 1),))
    result = None
    dma_process = None
    dma_executable_sha256 = None
    try:
        runner.begin_test('cpu-zipdma-copy')
        dma_process = dma.driver.process
        try:
            dma_executable_sha256 = hashlib.sha256(Path(f'/proc/{dma_process.pid}/exe').read_bytes()).hexdigest()
        except OSError:
            pass  # The host may not expose /proc; no identity is inferred.
        if dma_executable_sha256 is not None and dma_executable_sha256 != dma_build['binary_sha256']:
            raise RuntimeError('running ZipDMA executable differs from requested binary')
        # Supply a measured baseline before advancing the CPU.
        runner.step('dma')
        for _ in range(max_steps):
            runner.step('cpu')
            if 'dma' in router.pending_targets:
                runner.step('dma')
            if len(dma.control_events) >= 4:
                break
        else:
            raise RuntimeError('CPU did not start DMA within the step limit')
        for _ in range(max_steps):
            runner.step('dma')
            if dma.irq:
                break
        else:
            raise RuntimeError('DMA completion IRQ not observed')
        for _ in range(max_steps):
            runner.step('cpu')
            if 'dma' in router.pending_targets:
                runner.step('dma')
            if any(e.get('kind') == 'memory_write' and e.get('address') == RESULT + 16
                   for e in cpu.service.events):
                break
        else:
            raise RuntimeError('CPU did not write completion marker within the step limit')
        # The memory service sees a store request before the CPU retires it.
        # Allow its preceding clear write to retire, without extending execution
        # indefinitely when this CPU has no RVFI observations.
        if cpu._rvfi_enabled:
            expected_retired = expected_retirements(boot)
            for _ in range(min(max_steps, 32)):
                status = retirement_evidence(runner.events_since(0), expected_retired)['status']
                if status != 'unknown':
                    break
                runner.step('cpu')
                if 'dma' in router.pending_targets:
                    runner.step('dma')
        values = [memory.read(RESULT + 4*i, 4, transaction_id='verify').value for i in range(4)]
        master = dma._bridge.events
        control = dma.control_events
        writes = [(e['offset'], e['value'], e['be']) for e in control if e['write']]
        expected = [(4, SRC, 15), (8, DST, 15), (12, 16, 15),
                    (0, 0, 15), (0, 0x80000000, 15)]
        cpu_reads = [e for e in cpu.service.events if e.get('kind') == 'memory_read'
                     and DST <= e.get('address', 0) < DST + 16]
        events = list(runner.events_since(0))
        retirement = retirement_evidence(events, expected_retirements(boot))
        irq_delivery = irq_evidence(events)
        irq = [e for e in events if e.get('kind') == 'local_tick_sample'
               and e.get('component') == 'dma' and e.get('outputs', {}).get('irq') == 1]
        if (values != list(WORDS) or writes != expected or not check_master_events(master)
                or [e['address'] for e in cpu_reads] != [DST + 4*i for i in range(4)]
                or not irq or dma.irq or retirement['status'] == 'mismatch'):
            raise RuntimeError('observed CPU/DMA copy evidence did not match expectations')
        result = {'status': 'verified', 'scope': 'CPU MMIO and RAM consumption; sampled IRQ; host-controlled scheduling; no ISR or F6 claim',
                'values': values, 'control_events': control, 'master_events': master,
                'cpu_reads': cpu_reads, 'irq_high_samples': len(irq),
                'irq_final': dma.irq, 'cpu_ticks': runner.local_ticks['cpu'],
                'dma_ticks': runner.local_ticks['dma'],
                'retirement_evidence': retirement, 'irq_evidence': irq_delivery,
                'cpu_retirements': [e for e in events if e.get('kind') == 'cpu_retire'],
                'router_deliveries': router.deliveries, 'zipdma_build': dma_build,
                'zipdma_session': dma.identity_document(),
                'zipdma_runtime_events': dma.runtime_events}
    finally:
        runner.finalize()
    result['processes'] = process_evidence(cpu, dma, dma_process, dma_executable_sha256)
    result['zipdma_lifecycle'] = dma.lifecycle_receipt()
    return result


def main():
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True, help='fresh ZipDMA driver binary')
    p.add_argument('--cache', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-steps', type=int, default=2000)
    p.add_argument('--dma-build-result', type=Path, help='optional standalone ZipDMA result.json for SHA comparison')
    a = p.parse_args()
    if a.max_steps < 1 or a.output.exists():
        p.error('positive step limit and new output file required')
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
        artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
        if a.dma_build_result is None:
            result = execute(artifact, a.binary, a.cache, a.max_steps)
        else:
            result = execute(artifact, a.binary, a.cache, a.max_steps,
                             json.loads(a.dma_build_result.read_text()))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps({'status': result['status'], 'output': str(a.output)}))


if __name__ == '__main__':
    main()
