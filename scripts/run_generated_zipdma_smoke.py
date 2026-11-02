#!/usr/bin/env python3
"""Exercise a source-admitted generated Wishbone SEL ZipDMA session.

Single-device RAM-to-RAM smoke; no CPU, F6, ISR or native partial-master claim.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

WORDS = (1, 2, 3, 4)
PROFILE = 'configs/peripherals/zipdma_smoke/component_profile.json'


def control_select_observed(events, *, offset, value, select):
    for event in events:
        pre = event.get('payload', {}).get('pre_backend', {})
        if (pre.get('swb_cyc') == 1 and pre.get('swb_stb') == 1 and pre.get('swb_we') == 1
                and pre.get('swb_adr') == offset // 4 and pre.get('swb_sel') == select
                and pre.get('swb_dat_w') == value):
            return True
    return False


def verify_result(values, beats, partial_readback, irq_high, irq_after_clear):
    if partial_readback != 0x180:
        raise RuntimeError('partial control write did not update only the selected byte')
    reads = [beat['address'] for beat in beats if not beat['write']]
    writes = [beat['address'] for beat in beats if beat['write']]
    if (reads != [0x100 + 4*i for i in range(4)] or writes != [0x200 + 4*i for i in range(4)]
            or any(beat['byte_enable'] != 15 for beat in beats)):
        raise RuntimeError('observed DMA master beats or select do not match aligned transfer')
    if values != list(WORDS) or irq_high != 1 or irq_after_clear != 0:
        raise RuntimeError('copy result or observed IRQ did not match')
    return True


def run(artifact, *, cache, max_steps):
    from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    memory.preload(0x100, b''.join(n.to_bytes(4, 'little') for n in WORDS))
    dma = GeneratedWishboneDmaScenarioSession(artifact, base_dir=ROOT, cache_dir=cache,
                                              memory=memory, command_timeout_seconds=30)
    dma.configure_built_executable_receipt()
    process = None
    result = None
    try:
        dma.begin_case('generated-zipdma')
        process = dma.process
        # Confirm selected control byte on real RTL before configuring transfer.
        dma.write_register(4, 0x100)
        dma.write_register(4, 0x80, byte_enable=1)
        partial_readback = dma.read_register(4)
        if not control_select_observed(dma.events, offset=4, value=0x80, select=1):
            raise RuntimeError('partial control select was not observed on the real backend')
        for offset, value in ((4, 0x100), (8, 0x200), (12, 16), (0, 0)):
            dma.write_register(offset, value)
        irq_high = 0
        for _ in range(max_steps):
            irq_high = dma.step_local({})['irq']
            if irq_high:
                break
        else:
            raise RuntimeError('DMA completion IRQ not observed within tick limit')
        dma.write_register(0, 0x80000000)
        irq_after_clear = dma.step_local({})['irq']
        values = [memory.read(0x200 + 4*i, 4, transaction_id='verify').value for i in range(4)]
        beats = [event['accepted'] for event in dma.events if 'accepted' in event]
        verify_result(values, beats, partial_readback, irq_high, irq_after_clear)
        result = {'status': 'verified',
            'scope': 'one generated ZipDMA process; 4 aligned words; no CPU, F6, ISR or partial master transfer claim',
            'partial_control_readback': partial_readback, 'partial_control_select': 1,
            'partial_control_observed': True, 'values': values, 'master_beats': beats,
            'irq_high': irq_high, 'irq_after_clear': irq_after_clear, 'local_ticks': dma.local_ticks,
            'source_verification': artifact.source_verification,
            'profile_fingerprint': artifact.plan.profile.profile_fingerprint,
            'runtime_artifact_digest': artifact.runtime_document['artifact_digest'],
            'dma_edge_contract': artifact.runtime_document['dma_edge_contract'],
            'build_receipt': dma.built_executable_receipt_document(),
            'events': dma.events, 'memory_events': dma.memory_service.events}
    finally:
        dma.end_case()
    result['launches'] = dma.built_executable_launch_observations()
    result['process'] = {'pid': process.pid, 'returncode': process.poll(),
                         'reaped': process.poll() is not None}
    if result['process']['returncode'] != 0:
        raise RuntimeError('DMA process did not exit cleanly')
    return result


def main():
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-steps', type=int, default=2000)
    args = parser.parse_args()
    if args.output.exists() or args.max_steps < 1:
        parser.error('output must be new and max-steps positive')
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
        artifact = _artifact(PROFILE, 'dma')
        result = run(artifact, cache=args.cache, max_steps=args.max_steps)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps({'status': result['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
