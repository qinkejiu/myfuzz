#!/usr/bin/env python3
"""Directed native exception gate: a synchronous trap must not mint IRQ lineage.

Builds one real CPU session (no external IRQ source, no target), boots a fixed
program that enables the machine-external interrupt, and then executes one
illegal instruction.  It observes the real redirect decision and the real
retirement of the exception handler, and requires that the run contains no
external-IRQ acceptance and no serial lineage.  Two independent native sessions
(original/fresh) must produce the same semantic document.

This is a directed evidence case.  It grants no F5/F6 authority, no storage
version and no reward.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

RESULT_OFFSET = 0x400
TRAP_WORD = 0x00000073  # ECALL from M-mode; cause 11, never a fetch/illegal print
TRAP_CAUSE = 11


def build_program(boot, *, image_base, handler_base):
    from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _sw

    def csr(address, source, operation=1, destination=0):
        return address << 20 | source << 15 | operation << 12 | destination << 7 | 0x73

    result = image_base + RESULT_OFFSET
    main = [*_lui_addi_load(2, handler_base), csr(0x305, 2),
            *_lui_addi_load(2, 1 << 11), csr(0x304, 2, 2),
            _addi(2, 0, 8), csr(0x300, 2, 2),
            _addi(3, 0, 0)]
    trap_pc = boot + 4 * len(main)
    main.append(TRAP_WORD)
    handler = [*_lui_addi_load(2, result), _addi(3, 0, 1), _sw(3, 2, 0)]
    park = handler_base + 4 * len(handler)
    handler.append(_jal(park, park))

    def encode(words):
        return b''.join(word.to_bytes(4, 'little') for word in words).hex()

    return dict(boot=boot, image_base=image_base, handler_base=handler_base,
        result=result, trap_pc=trap_pc, trap_cause=TRAP_CAUSE, park=park,
        images={str(boot): encode(main), str(handler_base): encode(handler)},
        handler_words=len(handler))


def target_artifact(profile_path, *, base):
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    return _artifact(profile_path, 'cpu')


def execute_once(artifact, program, *, base, cache, output, max_steps):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.runner import ScenarioRunner
    output.mkdir()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=0, max_initialized_bytes=0x20000)
    for address, data in program['images'].items():
        memory.preload(int(address), bytes.fromhex(data))
    cpu = GeneratedCve2Session(artifact, base_dir=base, cache_dir=cache,
        memory=memory, router=DataflowRouter(()), native_irq_receipts=True,
        physical_tick_samples=True)
    runner = ScenarioRunner(sessions={'cpu': cpu},
        ownership=compile_ownership((), ()), bindings=())
    cpu.configure_built_executable_receipt()
    with record_local_commands() as recording:
        try:
            runner.begin_test('native-exception-irq-lineage')
            retired_after = None
            for _ in range(max_steps):
                runner.step('cpu')
                for event in runner._event_refs_since(0):
                    if (event.get('kind') == 'cpu_retire'
                            and event.get('pc_rdata') == program['park']
                            and retired_after is None):
                        retired_after = event
                if retired_after is not None:
                    break
            else:
                raise ValueError('exception programme step budget exhausted')
            result = inspect_events(runner._event_refs_since(0), program)
        except BaseException as error:
            (output / 'failure.json').write_text(json.dumps(
                dict(error_type=type(error).__name__, error=str(error)), indent=2) + '\n')
            raise
        finally:
            try:
                runner.finalize()
            finally:
                (output / 'events.json').write_text(json.dumps(runner.events, sort_keys=True) + '\n')
                (output / 'local_commands.json').write_text(json.dumps(
                    recording.export_sessions(), sort_keys=True) + '\n')
                (output / 'executions.json').write_text(json.dumps(
                    recording.export_executions(), sort_keys=True) + '\n')
    identities = recording.export_executions()
    if (len(identities) != 1 or identities[0].get('exit_code') != 0
            or not identities[0].get('reaped')):
        raise ValueError('one clean native CPU process exit required')
    return result, identities


def inspect_events(events, program):
    """Recompute the gate from actual events; no configured expectation is reused."""
    redirects = [event for event in events
                 if event.get('kind') == 'cpu_native_exception_redirect']
    takes = [event for event in events if event.get('kind') == 'cpu_external_irq_taken']
    if takes:
        raise ValueError('a synchronous exception must not mint an IRQ acceptance')
    if redirects:
        # A CPU whose adapter declares a real redirect probe names the redirect
        # edge.  CV32E40P asserts the exception vector selector one cycle after
        # csr_save_cause_o, so the same-edge exc_cause_o sample is not the
        # architectural cause; that stays explicitly unknown rather than being
        # copied from the configured trap word.
        if len(redirects) != 1:
            raise ValueError('exactly one actual exception redirect required')
        redirect = redirects[0]
        if redirect.get('irq_entry_pc') != program['handler_base']:
            raise ValueError('redirect entry PC differs from the aligned exception base')
        cause_known = redirect.get('redirect_cause') == program['trap_cause']
        redirect_evidence = ('native_redirect_probe' if cause_known else
                             'native_redirect_probe_cause_unknown')
    else:
        # Full-RVFI CPUs without a redirect probe must show the real trapping
        # retirement (trap=1, no interrupt retirement).
        trapped = [event for event in events if event.get('kind') == 'cpu_retire'
                   and event.get('pc_rdata') == program['trap_pc']
                   and event.get('trap') == 1 and event.get('intr') == 0]
        if len(trapped) != 1:
            raise ValueError('actual trapping retirement required')
        redirect = trapped[0]
        redirect_evidence = 'rvfi_trap_retirement'
    if any(event.get('irq_serial_observation', {}).get('decision', {}).get('status') == 'observed'
           and event['irq_serial_observation']['decision']['value'] for event in events):
        raise ValueError('no IRQ decision serial may appear without an acceptance')
    retirements = [event for event in events if event.get('kind') == 'cpu_retire']
    trapped_retirements = [event for event in retirements
                           if event.get('pc_rdata') == program['trap_pc']]
    if not trapped_retirements:
        raise ValueError('the trapping instruction must be observed at its real PC')
    if any(event.get('intr') for event in trapped_retirements):
        raise ValueError('the trapping retirement must not be an interrupt return')
    after = [event for event in retirements
             if event.get('event_id', 0) > redirect.get('event_id', 0)
             and event.get('pc_rdata') == program['handler_base']]
    if len(after) != 1:
        raise ValueError('one real handler-entry retirement required')
    entry = after[0]
    first_word = int.from_bytes(bytes.fromhex(program['images'][str(program['handler_base'])])[:4],
                               'little')
    if entry.get('insn') != first_word or entry.get('valid') != 1:
        raise ValueError('handler entry retirement differs from the source image')
    if entry.get('trap') or entry.get('intr'):
        raise ValueError('handler entry must be an ordinary retirement')
    writes = [event for event in events if event.get('kind') == 'memory_write'
              and event.get('component') == 'cpu'
              and event.get('address') == program['result'] and event.get('value') == 1]
    if len(writes) != 1:
        raise ValueError('one real handler RAM marker write required')
    # handler words: lui, addi, addi x3=1, sw x3,0(x2), park jump -> store at +12
    store = [event for event in retirements
             if event.get('pc_rdata') == program['handler_base'] + 12]
    if len(store) != 1 or store[0].get('insn', 0) & 0x7F != 0x23:
        raise ValueError('handler store retirement required')
    samples = [event for event in events if event.get('kind') == 'cpu_external_irq_sample']
    if not samples or any(event.get('actual_pre_input') != 0 for event in samples):
        raise ValueError('the CPU external IRQ input must stay inactive')
    park = [event for event in retirements if event.get('pc_rdata') == program['park']]
    if not park:
        raise ValueError('actual handler park retirement required')
    return dict(status='verified', scope='directed_native_exception_no_irq_lineage',
        trap_pc=program['trap_pc'], trap_cause=program['trap_cause'],
        redirect_evidence=redirect_evidence, redirect_event=redirect['event_id'],
        redirect_tick=redirect.get('local_tick'),
        redirect_cause=(redirect.get('redirect_cause') if redirect_evidence !=
                        'native_redirect_probe_cause_unknown' else None),
        redirect_cause_scope=('native_same_edge_probe' if redirect_evidence ==
                              'native_redirect_probe' else 'unknown_pc_set_edge_not_atomic'),
        configured_trap_cause=program['trap_cause'],
        handler_entry=entry.get('pc_rdata'), handler_entry_order=entry.get('order'),
        handler_store_event=store[0].get('event_id'),
        marker_write_event=writes[0].get('event_id'),
        irq_take_count=0, irq_input_samples=len(samples),
        irq_consumption='not_attempted', reward_eligible=False,
        grants_F5=False, grants_F6=False, native_authority=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--max-steps', type=int, default=4000)
    parser.add_argument('--native', action='store_true', required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    profile_path = config['cpu_profile']
    if not 1 <= args.max_steps <= 10000:
        raise ValueError('bounded positive max-steps required')
    if args.output.exists():
        raise ValueError('native output must not exist')
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            execution_validation_scope():
        artifact = target_artifact(profile_path, base=ROOT)
        boot = source_backed_boot_fetch(artifact.plan.profile, base_dir=ROOT,
            configured_boot_base=artifact.runtime_document['boot_contract']['configured_boot_base'])
        # The exception vector is the 256-byte aligned mtvec base on every
        # adapter (Ibex/CVE2/E40 all derive the entry from mtvec[31:8]).
        handler_base = (boot + 0x1000) & ~0xFF
        program = build_program(boot, image_base=boot, handler_base=handler_base)
        (args.output / 'program.json').write_text(json.dumps(program, sort_keys=True) + '\n')
        (args.output / 'config.json').write_text(json.dumps(config, sort_keys=True) + '\n')
        (args.output / 'cpu-artifact.json').write_text(
            json.dumps(artifact.runtime_document, sort_keys=True) + '\n')
        original, old = execute_once(artifact, program, base=ROOT, cache=args.cache,
            output=args.output / 'original', max_steps=args.max_steps)
        fresh, new = execute_once(artifact, program, base=ROOT, cache=args.cache,
            output=args.output / 'fresh', max_steps=args.max_steps)
        if (old[0]['pid'] == new[0]['pid']
                or old[0]['execution_nonce'] == new[0]['execution_nonce']):
            raise ValueError('independent fresh native process required')
        if original != fresh:
            raise ValueError('fresh exception semantics mismatch')
        (args.output / 'summary.json').write_text(json.dumps(dict(status='verified',
            fresh_matches=True, fresh_scope='same-invocation-independent-native-sessions',
            semantic_sha256=sha256(json.dumps(original, sort_keys=True).encode()).hexdigest(),
            processes={'original': old, 'fresh': new}, result=original),
            sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': 'verified', 'output': str(args.output)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
