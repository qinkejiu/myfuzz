#!/usr/bin/env python3
"""Native configured MMIO -> declared output -> OR -> CPU IRQ/retirement smoke.

The default is the original Timer configuration. Explicit source configurations
reuse the same public component sessions, router and ScenarioRunner.
It supplies no F5 pin case and grants no storage version, ISR-MMIO or reward.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


def source_options(config):
    """Explicit source wiring; legacy Timer configurations retain their defaults."""
    options = dict(source_request=config.get('source_request', config.get('timer_request')),
        active_base=config.get('active_base', config.get('timer_active_base')),
        idle_base=config.get('idle_base', config.get('timer_idle_base')),
        active_id=config.get('active_id', 'timer_active'), idle_id=config.get('idle_id', 'timer_idle'),
        source_port=config.get('source_port', 'irq_o'), source_bit_offset=config.get('source_bit_offset', 0),
        source_adapter=config.get('source_adapter'), pulse_width_ticks=config['pulse_width_ticks'],
        trigger_writes=tuple(tuple(row) for row in config.get('trigger_writes', ((4, 0), (8, 0), (0, 0xFFFFFFFF)))))
    if (options['source_adapter'] not in (None, 'declared-output.v1')
            or not all(type(options[k]) is str and options[k] for k in ('source_request', 'active_id', 'idle_id', 'source_port'))
            or len({'cpu', options['active_id'], options['idle_id']}) != 3
            or type(options['source_bit_offset']) is not int or not 0 <= options['source_bit_offset'] < 64
            or any(type(options[k]) is not int or options[k] < 0 or options[k] % 4096 for k in ('active_base', 'idle_base'))):
        raise ValueError('invalid explicit IRQ source configuration')
    return options


def timer_program(boot, timer_base, *, trigger_writes=None, window_size=4096):
    from scripts.run_cv32e20_irq_smoke import fixed_program
    from myfuzz.integration.rv32_fixed_firmware import _lui_addi_load, _addi, _sw, _jal
    trigger_writes = tuple(trigger_writes) if trigger_writes is not None else ((4, 0), (8, 0), (0, 0xFFFFFFFF))
    if (type(window_size) is not int or window_size < 4 or window_size % 4
            or type(timer_base) is not int or timer_base < 0 or timer_base % 4
            or timer_base + window_size > 1 << 32
            or not 1 <= len(trigger_writes) <= 16 or any(len(row) != 2
                or type(row[0]) is not int or row[0] % 4 or not 0 <= row[0] <= window_size - 4
                or type(row[1]) is not int or not 0 <= row[1] < 1 << 32 for row in trigger_writes)):
        raise ValueError('bounded aligned MMIO trigger writes required')
    program = fixed_program(boot)
    main = bytes.fromhex(program['images'][str(boot)])[:-4]
    # The original CSR enable precedes these real CPU stores. No host register
    # write or guessed IRQ input substitutes for the MMIO/RTL path.
    if trigger_writes == ((4, 0), (8, 0), (0, 0xFFFFFFFF)):
        words = [*_lui_addi_load(8, timer_base), _addi(9, 0, 0),
                 _sw(9, 8, 4), _sw(9, 8, 8), _addi(9, 0, -1), _sw(9, 8, 0)]
    else:
        words = list(_lui_addi_load(8, timer_base))
        for offset, value in trigger_writes:
            if offset < 2048:
                words.extend((*_lui_addi_load(9, value), _sw(9, 8, offset)))
            else:
                # RV32 SW sign-extends its 12-bit displacement. Materialize the
                # complete address instead of truncating a legal large offset.
                words.extend((*_lui_addi_load(10, timer_base + offset),
                              *_lui_addi_load(9, value), _sw(9, 10, 0)))
    park = boot + len(main) + len(words) * 4
    if park + 4 > program['vector']:
        raise ValueError('Timer smoke main overlaps fixed vector')
    program['images'][str(boot)] = (main + b''.join(w.to_bytes(4, 'little')
        for w in [*words, _jal(park, park)])).hex()
    program['park'] = park
    return program


def inspect_evidence(events, program, *, contract, active, idle, timer_wire, timer_base, group,
        source_port='irq_o', source_bit_offset=0, source_width=4,
        trigger_writes=((4, 0), (8, 0), (0, 0xFFFFFFFF)), transport_only=False):
    """Recompute the narrow diagnostic chain from exported actual events."""
    by_id = {e['event_id']: e for e in events}
    deliveries = [e for e in events if e.get('kind') == 'mmio_delivery'
        and e.get('device_id') == active and e.get('component') == 'cpu' and e.get('write') is True]
    writes = [(e.get('offset'), e.get('write_value')) for e in deliveries]
    if writes != list(trigger_writes):
        raise ValueError('actual Timer MMIO trigger sequence required')
    idle_samples = [e for e in events if e.get('kind') == 'local_tick_sample' and e.get('component') == idle]
    if not idle_samples or any(type(e.get('outputs', {}).get(source_port)) is not int
            or e['outputs'][source_port] >> source_bit_offset & 1 for e in idle_samples):
        raise ValueError('idle Timer native zero required')
    takes = [e for e in events if e.get('kind') == 'cpu_external_irq_taken' and e.get('component') == 'cpu']
    if len(takes) != 1: raise ValueError('one actual native CPU take required')
    take = takes[0]
    frames = [e for e in events if e.get('kind') == 'irq_group_delivery'
        and e.get('native_take_event_id') == take['event_id']]
    if len(frames) != 1: raise ValueError('actual OR delivery/take join required')
    frame = frames[0]
    if (frame.get('group_id') != group.group_id or frame.get('group_sha256') != group.identity_sha256
            or frame.get('target_component') != group.target_component or frame.get('target_port') != group.target_port
            or frame.get('attribution_status') != 'unique' or frame.get('unique_source') != active + '.' + source_port
            or frame.get('active_sources') != [active + '.' + source_port] or frame.get('value') != 1):
        raise ValueError('unique active Timer source required')
    member, = [m for m in frame['members'] if m['source_id'] == active + '.' + source_port]
    ref = member.get('native_source', {})
    pulse = by_id.get(ref.get('event_id'), {})
    raw = pulse.get('outputs', {}).get('physical', {}).get(timer_wire)
    if (pulse.get('kind') != 'local_tick_sample' or pulse.get('component') != active
            or pulse.get('phase') != ref.get('phase') or pulse.get('local_tick') != ref.get('local_tick')
            or pulse.get('reset_epoch') != ref.get('reset_epoch')
            or pulse.get('event_id', 0) <= deliveries[-1]['event_id']
            or deliveries[-1].get('address') != timer_base + trigger_writes[-1][0]
            or type(raw) is not int or not 0 <= raw < 1 << source_width or raw >> source_bit_offset & 1 != 1
            or pulse.get('outputs', {}).get(source_port) != raw):
        raise ValueError('actual raw Timer overflow pulse required')
    sample = by_id.get(frame.get('native_sample_event_id'), {})
    if (sample.get('event_id') != take.get('sample_event_id')
            or sample.get('producer_event_id') != take.get('producer_event_id')
            or sample.get('local_tick') != frame.get('cpu_tick')
            or take.get('local_tick') != frame.get('cpu_tick')
            or sample.get('observation_contract') != contract or take.get('observation_contract') != contract
            or any(type(row.get('irq_taken_pre')) is not int or row['irq_taken_pre'] != 1 for row in (sample, take))
            or any(type(sample.get(k)) is not int or sample[k] != 1
                for k in ('expected_input', 'actual_pre_input', 'actual_post_input'))):
        raise ValueError('actual parsed CPU input/take required')
    decision = take.get('irq_serial_observation', {}).get('decision', {})
    token = decision.get('value')
    if decision.get('status') != 'observed' or type(token) is not int or token <= 0:
        raise ValueError('nonzero actual decision serial required')
    linked = [e for e in events if e.get('kind') == 'cpu_retire' and e.get('component') == 'cpu'
        and e.get('irq_serial_observation', {}).get('retirement', {}).get('status') == 'observed'
        and e['irq_serial_observation']['retirement']['value'] == token]
    if len(linked) != 1: raise ValueError('unique first-handler retirement serial required')
    first = linked[0]
    code = {int(base) + offset: int.from_bytes(bytes.fromhex(data)[offset:offset+4], 'little')
        for base, data in program['images'].items() for offset in range(0, len(bytes.fromhex(data)), 4)}
    if (first.get('schema_version') != 'cpu_retire.v2'
            or first.get('observation_contract') != contract or first.get('valid') != 1
            or first.get('intr') != 1 or first.get('trap') or first.get('halt')
            or first.get('pc_rdata') not in (program['vector'], program['vector'] + 44, program['handler'])
            or first.get('insn') != code.get(first.get('pc_rdata'))):
        raise ValueError('actual fixed first-handler retirement required')
    fetch = next((e for e in events if e.get('kind') == 'instr_response' and e.get('component') == 'cpu'), None)
    if fetch is None or fetch.get('address') != program['boot']:
        raise ValueError('actual source-backed boot fetch required')
    return dict(status='verified', scope=('declared-IP-output-to-CPU-first-handler' if transport_only else 'Timer-native-pulse-to-CPU-first-handler'),
        trigger_writes=writes, first_fetch=program['boot'], source_pulse_tick=pulse['local_tick'],
        native_take_tick=take['local_tick'], first_retirement_pc=first['pc_rdata'], decision_serial=token,
        idle_observed_samples=len(idle_samples), source_version='unknown', isr_mmio='unknown',
        grants_F5=False, grants_F6=False, reward_eligible=False,
        **({'transport_only': True} if transport_only else {}))


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def timer_artifact(base, request_path, instance):
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    document = json.loads((base / request_path).read_text()); document['instance_id'] = instance
    plan = plan_local_harness(load_local_harness_request(document), base_dir=base)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=base), base_dir=base), base_dir=base)


def target_session(artifact, *, base, cache):
    from myfuzz.local_harness.declared_irq_output import declared_irq_target_session_type
    return declared_irq_target_session_type(artifact)(artifact, base_dir=base, cache_dir=cache)


def execute_once(artifacts, program, config, *, base, cache, output, max_steps):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.pulp_timer_irq_contract import timer_irq_runtime_mapping
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    from myfuzz.scenario.runner import ScenarioRunner
    output.mkdir()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),), initialization_seed=0, max_initialized_bytes=0x20000)
    memory.preload(program['marker'], bytes(8))
    for address, data in program['images'].items(): memory.preload(int(address), bytes.fromhex(data))
    options = source_options(config)
    active, idle = options['active_id'], options['idle_id']
    sources = {name: target_session(artifacts[name], base=base, cache=cache)
        for name in (active, idle)}
    router = DataflowRouter(tuple(DeviceWindow(name, options['active_base'] if name == active else options['idle_base'],
            session.artifact.plan.profile.address.window_size, session)
        for name, session in sources.items()))
    cpu = GeneratedCve2Session(artifacts['cpu'], base_dir=base, cache_dir=cache, memory=memory,
        router=router, native_irq_receipts=True, physical_tick_samples=True)
    group = IrqDeliveryGroup('timer-external-irq', 'cpu', cpu.irq_input_port,
        tuple(IrqDeliveryMember(name, options['source_port'], pulse_width_ticks=options['pulse_width_ticks'],
            source_bit_offset=options['source_bit_offset'], **({'source_adapter': options['source_adapter']}
                if options['source_adapter'] is not None else {})) for name in sources))
    fields = [InputField('cpu', cpu.irq_input_port, 1)]
    owners = [InputOwner('cpu', cpu.irq_input_port, 0, 1, 'bound', group.owner_ref)]
    for name, source in sources.items():
        for row in source.artifact.runtime_document['fixed_physical_inputs']:
            port = row['endpoint_id'] + '.' + row['role']
            fields.append(InputField(name, port, row['width']))
            owners.append(InputOwner(name, port, 0, row['width'], 'fixed', 'profile_constant'))
    owner = compile_ownership(tuple(fields), tuple(owners))
    runner = ScenarioRunner(sessions={'cpu': cpu, **sources}, ownership=owner,
        bindings=group.member_bindings(), irq_delivery_groups=(group,))
    for session in runner.sessions.values(): session.configure_built_executable_receipt()
    for name in sources:
        # The existing observer validates its actual APB/WB/AHB raw fields.
        # Transport remains protocol-specific, not relabelled as APB.
        if runner.install_protocol_checker(name) is None:
            raise ValueError('actual target protocol checker required')
    result = None
    with record_local_commands() as recording:
        try:
            runner.begin_test('timer-native-irq-smoke')
            # Capture actual reset-idle samples before requesting any CPU clock.
            for name in sources: runner.step(name)
            cursor = 0; mret_order = None
            for _ in range(max_steps):
                runner.step('cpu')
                for name in router.ready_targets: runner.step(name)
                # Keep both real source clocks moving; idle is measured, not a constant.
                for name in sources: runner.step(name)
                completed = False
                for event in runner._event_refs_since(cursor):
                    if event.get('kind') != 'cpu_retire': continue
                    if event.get('pc_rdata') == program['mret']: mret_order = event['order']
                    elif mret_order is not None and event.get('order', 0) > mret_order: completed = True
                cursor = runner.event_count
                if completed: break
            else: raise ValueError('Timer IRQ smoke step budget exhausted')
            if options['source_adapter'] is None:
                mapping = timer_irq_runtime_mapping(sources[active])
            else:
                from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
                mapping = declared_irq_runtime_mapping(sources[active], physical_port=options['source_port'],
                    source_bit_offset=options['source_bit_offset'])
            result = inspect_evidence(runner._event_refs_since(0), program,
                contract=native_irq_receipt_contract(artifacts['cpu']), active=active, idle=idle,
                timer_wire=mapping['runtime_name'], timer_base=options['active_base'], group=group,
                source_port=options['source_port'], source_bit_offset=options['source_bit_offset'],
                source_width=mapping['source_width'], trigger_writes=options['trigger_writes'],
                transport_only=bool(mapping.get('transport_only', False)))
            protocol = artifacts[active].runtime_document['base_protocol_trace']['protocol']
            if protocol != 'apb3':
                result['native_target_protocol'] = protocol
        except BaseException as error:
            save(output / 'failure.json', dict(error_type=type(error).__name__, error=str(error)))
            raise
        finally:
            try: runner.finalize()
            finally:
                save(output / 'events.json', runner.events)
                save(output / 'local_commands.json', recording.export_sessions())
                save(output / 'executions.json', recording.export_executions())
    identities = recording.export_executions()
    if (len(identities) != 3 or any(e.get('exit_code') != 0 or not e.get('reaped') for e in identities)):
        raise ValueError('three clean actual native process exits required')
    save(output / 'result.json', result)
    return result, identities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--config', type=Path, default=Path('configs/peripherals/pulp_timer_irq/smoke.json'))
    parser.add_argument('--output', type=Path, required=True); parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--max-steps', type=int, default=1500)
    args = parser.parse_args(); base = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(base), str(base / 'src')]
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    config = json.loads((base / args.config).read_text())
    if not 1 <= args.max_steps <= 10000: raise ValueError('bounded positive max-steps required')
    if args.output.exists(): raise ValueError('smoke output must not exist')
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
        options = source_options(config)
        artifacts = {'cpu': _artifact(config['cpu_profile'], 'cpu')}
        artifacts.update({name: timer_artifact(base, options['source_request'], name) for name in (options['active_id'], options['idle_id'])})
        boot = source_backed_boot_fetch(artifacts['cpu'].plan.profile, base_dir=base,
            configured_boot_base=artifacts['cpu'].runtime_document['boot_contract']['configured_boot_base'])
        program = timer_program(boot, options['active_base'], trigger_writes=options['trigger_writes'],
            window_size=artifacts[options['active_id']].plan.profile.address.window_size)
        save(args.output / 'program.json', program); save(args.output / 'config.json', config)
        for name, artifact in artifacts.items(): save(args.output / (name + '-artifact.json'), artifact.runtime_document)
        original, old = execute_once(artifacts, program, config, base=base, cache=args.cache, output=args.output / 'original', max_steps=args.max_steps)
        fresh, new = execute_once(artifacts, program, config, base=base, cache=args.cache, output=args.output / 'fresh', max_steps=args.max_steps)
        for component in artifacts:
            first, = [row for row in old if row['component'] == component]
            second, = [row for row in new if row['component'] == component]
            if (type(first.get('pid')) is not int or type(second.get('pid')) is not int
                    or first['pid'] == second['pid'] or not first.get('execution_nonce')
                    or not second.get('execution_nonce') or first['execution_nonce'] == second['execution_nonce']):
                raise ValueError('independent fresh native processes required')
        if original != fresh: raise ValueError('fresh Timer IRQ semantic mismatch')
    save(args.output / 'summary.json', dict(status='verified', fresh_matches=True,
        fresh_scope='same-invocation-independent-native-sessions',
        semantic_sha256=sha256(json.dumps(original, sort_keys=True).encode()).hexdigest(),
        processes={'original': old, 'fresh': new}, result=original))
    print(json.dumps(dict(status='verified', output=str(args.output))))


if __name__ == '__main__': main()
