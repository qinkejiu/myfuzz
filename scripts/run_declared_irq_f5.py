#!/usr/bin/env python3
"""One declared-IRQ F5 consumption case in a real native CPU/target session.

The case delivers the target's organic declared IRQ output through the existing
host OR group: the fixed CPU image performs the declared MMIO trigger writes and
no host-invented pulse is injected.  The layered observation document separates
transport (actual output sample, OR frame, CPU input, native take) from
consumption (actual ISR register read joined to the target's native samples and
the CPU OBI beat, dependent RAM writes, load/store/MRET retirements and the real
successor) and keeps internal IP cause/version unknown.

``--mode original`` and ``--mode fresh`` are separate invocations of the same
configuration.  Fresh recomputes everything from the configuration and never
reads the original's summary or events; the two semantic digests are compared by
the operator (or by the fresh invocation's optional ``--original`` identity
check, which runs only after its own evidence is written).
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def read(path):
    return json.loads(Path(path).read_text())


def f5_source_options(config):
    """Reuse the existing source parser, optionally realizing one target only."""
    from scripts.run_timer_irq_smoke import source_options
    single = config.get('single_source', False)
    if type(single) is not bool:
        raise ValueError('single-source mode must be boolean')
    if not single:
        return source_options(config)
    # The shared parser validates both names. These parser-only placeholders
    # never become a component, device window, group member or evidence.
    adapted = dict(config)
    active_id = adapted.get('active_id', 'timer_active')
    adapted['idle_id'] = str(active_id) + '__unused'
    adapted['idle_base'] = adapted.get('active_base', adapted.get('timer_active_base'))
    options = source_options(adapted)
    options['idle_id'] = options['idle_base'] = None
    return options


def f5_source_ids(options):
    return ((options['active_id'],) if options['idle_id'] is None
            else (options['active_id'], options['idle_id']))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def semantic_digest(document):
    return sha256(canonical(document).encode()).hexdigest()


#: The admission label of each registered CPU retirement authority.
ADMITTED_AUTHORITY = {'full_rvfi': 'full_rvfi_retirement_receipt',
                      'pc_insn_order_only': 'pc_insn_order_only'}
LIMITED_AUTHORITY = 'pc_insn_order_only'


def cpu_authority(contract):
    """The retirement authority the realized CPU contract itself declares."""
    from myfuzz.scenario.irq_return_successor import retirement_authority
    return retirement_authority(contract)


def check_cpu_authority(admission, contract):
    """Bind the realized CPU observation contract to the admitted authority.

    A pc/insn/order-only CPU is admitted only through its real limited path, so
    the join stays by documented order; a full-RVFI CPU keeps the exact-field
    join.  No branch here reads or requires ``raw_pc_wdata``.
    """
    from myfuzz.integration.declared_irq_consumption import _require
    authority = cpu_authority(contract)
    expected = ADMITTED_AUTHORITY.get(authority)
    _require(expected is not None, 'admission-CPU-retirement-authority-unknown')
    _require(admission['cpu']['retirement_authority'] == expected,
             'admission-CPU-retirement-authority-mismatch')
    if authority == LIMITED_AUTHORITY:
        _require(admission['status'] == 'admitted'
                 and admission['cpu']['retirement_only_provider'] is not None,
                 'admission-limited-CPU-provider-required')
        _require(admission['cpu']['retirement_joins'] == 'by_documented_order',
                 'admission-limited-CPU-retirement-joins')
    else:
        _require(admission['cpu']['retirement_joins'] == 'exact_fields',
                 'admission-full-CPU-retirement-joins')
    return authority


def f5_fields(config, admission):
    """Validate the new F5 fields against the admitted declared register map."""
    from myfuzz.integration.declared_irq_consumption import _require
    required = ('image_start', 'image_end', 'result_address', 'status_offsets', 'target_window')
    _require(all(name in config for name in required), 'configuration-f5-fields-missing')
    window = config['target_window']
    _require(type(window) is dict and set(window) == {'base', 'size'}, 'configuration-target-window')
    _require(window['base'] == config['active_base'], 'configuration-window-base')
    _require(window['size'] == admission['target']['window_size'], 'configuration-window-size')
    _require(type(config['image_start']) is int and config['image_start'] % 4096 == 0
             and type(config['image_end']) is int
             and config['image_end'] > config['image_start'] + 0x1100, 'configuration-image-layout')
    offsets = config['status_offsets']
    _require(isinstance(offsets, (list, tuple)) and offsets
             and all(type(offset) is int for offset in offsets), 'configuration-status-offsets')
    declared = {row['offset'] for row in admission['target']['status_registers']}
    _require(set(offsets) <= declared, 'configuration-status-offset-undeclared')
    clear = config.get('clear_writes', [])
    _require(isinstance(clear, (list, tuple))
             and all(isinstance(row, (list, tuple)) and len(row) == 2 for row in clear),
             'configuration-clear-writes')
    _require({row[0] for row in clear} <= {row['offset'] for row in admission['target']['clear_registers']},
             'configuration-clear-offset-undeclared')
    cause = config.get('status_cause_bits') or {}
    _require(isinstance(cause, dict) and all(str(key).isdigit() for key in cause),
             'configuration-cause-bits')
    _require({int(key) for key in cause} <= set(offsets), 'configuration-cause-bit-offset')
    return dict(status_offsets=[int(offset) for offset in offsets],
                clear_writes=tuple((int(row[0]), int(row[1])) for row in clear),
                image_start=config['image_start'], image_end=config['image_end'],
                result_address=config['result_address'], target_base=window['base'],
                window_size=window['size'],
                cause_bits={int(key): int(mask) for key, mask in cause.items()})


def trigger_words(target_base, trigger_writes, window_size):
    """Encode the declared MMIO trigger writes; no host pulse substitutes them."""
    from myfuzz.integration.declared_irq_consumption import _require
    from myfuzz.integration.rv32_fixed_firmware import _lui_addi_load, _sw
    _require(isinstance(trigger_writes, (list, tuple)) and 1 <= len(trigger_writes) <= 16,
             'configuration-trigger-writes')
    words = list(_lui_addi_load(8, target_base))
    for row in trigger_writes:
        _require(isinstance(row, (list, tuple)) and len(row) == 2
                 and type(row[0]) is int and row[0] % 4 == 0 and 0 <= row[0] <= window_size - 4
                 and type(row[1]) is int and 0 <= row[1] < 1 << 32, 'configuration-trigger-write')
        offset, value = row
        if offset < 2048:
            words.extend((*_lui_addi_load(9, value), _sw(9, 8, offset)))
        else:
            # RV32 SW sign-extends its 12-bit displacement: materialize the whole
            # address instead of truncating a legal large offset.
            words.extend((*_lui_addi_load(10, target_base + offset),
                          *_lui_addi_load(9, value), _sw(9, 10, 0)))
    return words


def case_program(firmware, options, fields):
    """Fixed case image: declared trigger writes then a real self-loop park."""
    from myfuzz.integration.declared_irq_consumption import _require
    from myfuzz.integration.rv32_fixed_firmware import _jal
    words = trigger_words(fields['target_base'], options['trigger_writes'], fields['window_size'])
    entry = firmware['dynamic_start']
    park = entry + 4 * len(words)
    words.append(_jal(park, park))
    _require(park + 4 <= firmware['image_end'], 'configuration-case-image-overflow')
    images = {segment['address']: segment['data_hex'] for segment in firmware['segments']}
    _require(entry not in images, 'configuration-case-entry-overlaps-firmware')
    images[entry] = b''.join(word.to_bytes(4, 'little') for word in words).hex()
    return dict(images={str(address): data for address, data in sorted(images.items())},
                case_entry=entry, park=park,
                trigger_writes=[list(row) for row in options['trigger_writes']],
                trigger_words=len(words), dynamic_sha256=sha256(bytes.fromhex(images[entry])).hexdigest())


def cpu_obi_traces(artifact):
    """Declared OBI channels of the actual CPU artifact, never an invented map."""
    from myfuzz.integration.declared_irq_consumption import _require
    profile = artifact.plan.profile
    endpoints = tuple(getattr(profile.cpu, 'master_endpoints', ()) or ())
    _require(len(endpoints) == 2, 'CPU-master-endpoint-pair-required')
    rows = artifact.runtime_document.get('base_protocol_traces', {}).get('traces', ())
    traces, error_roles = {}, []
    for channel, endpoint in zip(('instr', 'data'), endpoints):
        matches = [row for row in rows
                   if row.get('endpoint_id') == endpoint and row.get('protocol') == 'obi'
                   and row.get('boundary') == 'cpu_physical_abi' and row.get('max_outstanding') == 1]
        _require(len(matches) == 1, 'CPU-OBI-' + channel + '-trace-required')
        signals = matches[0]['signals']
        required = {'req', 'gnt', 'addr', 'rvalid', 'rdata'}
        if channel == 'data':
            required |= {'we', 'wdata', 'be'}
        _require(required <= set(signals), 'CPU-OBI-' + channel + '-trace-incomplete')
        traces[channel] = dict(signals)
        error_roles.append('error' in signals)
    # The policy follows the actual declared pins: no error role means the CPU
    # ABI carries no error response to observe.
    native = all(error_roles)
    return traces, dict(mode=('native_error_role' if native else 'fail_stop_no_error_pin'),
                        native_error_observation=native)


def execute_once(*, artifacts, active, idle, program, firmware, options, base, cache, output,
                 max_steps, case_id, cpu_contract=None, evidence='full'):
    """Run one real native case and export its actual journal."""
    from myfuzz.integration.declared_irq_consumption import (
        _require, observe_declared_irq_consumption)
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner
    from scripts.run_timer_irq_smoke import target_session
    contract = (native_irq_receipt_contract(artifacts['cpu'])
                if cpu_contract is None else cpu_contract)
    output.mkdir(parents=True)
    size = firmware['image_end'] - firmware['image_start']
    memory = PersistentMemory(regions=(MemoryRegion('ram', firmware['image_start'], size),),
                              initialization_seed=0, max_initialized_bytes=size)
    for address, data in program['images'].items():
        memory.preload(int(address), bytes.fromhex(data))
    memory.preload(firmware['scratch'], bytes(16))
    memory.preload(firmware['result_address'], bytes(4 * firmware['result_words']))
    sources = {name: target_session(artifacts[name], base=base, cache=cache)
               for name in f5_source_ids(options)}
    router = DataflowRouter(tuple(
        DeviceWindow(name, options['active_base'] if name == active else options['idle_base'],
                     session.artifact.plan.profile.address.window_size, session)
        for name, session in sources.items()))
    cpu = GeneratedCve2Session(artifacts['cpu'], base_dir=base, cache_dir=cache, memory=memory,
                               router=router, native_irq_receipts=True, physical_tick_samples=True)
    group = IrqDeliveryGroup('declared-f5-or-' + active, 'cpu', cpu.irq_input_port,
        tuple(IrqDeliveryMember(name, options['source_port'],
                                pulse_width_ticks=options['pulse_width_ticks'],
                                source_bit_offset=options['source_bit_offset'],
                                source_adapter=options['source_adapter'])
              for name in sources))
    fields = [InputField('cpu', cpu.irq_input_port, 1)]
    owners = [InputOwner('cpu', cpu.irq_input_port, 0, 1, 'bound', group.owner_ref)]
    for name, source in sources.items():
        for row in source.artifact.runtime_document['fixed_physical_inputs']:
            port = row['endpoint_id'] + '.' + row['role']
            fields.append(InputField(name, port, row['width']))
            owners.append(InputOwner(name, port, 0, row['width'], 'fixed', 'profile_constant'))
    runner = ScenarioRunner(sessions={'cpu': cpu, **sources},
                            ownership=compile_ownership(tuple(fields), tuple(owners)),
                            bindings=group.member_bindings(), irq_delivery_groups=(group,))
    for session in runner.sessions.values():
        session.configure_built_executable_receipt()
    for name in sources:
        # The existing observer validates its actual APB/WB/AHB raw fields.
        if runner.install_protocol_checker(name) is None:
            raise ValueError('actual target protocol checker required')
    completed = 0
    with record_local_commands(capture_records=evidence == 'full') as recording:
        try:
            runner.begin_test(case_id)
            # Actual reset-idle samples before any case request.
            for name in sources:
                runner.step(name)
            cursor = 0
            mret_order = None
            for _ in range(max_steps):
                runner.step('cpu')
                for name in router.ready_targets:
                    runner.step(name)
                for name in sources:
                    runner.step(name)
                for event in runner._event_refs_since(cursor):
                    if event.get('kind') != 'cpu_retire':
                        continue
                    if event.get('pc_rdata') == firmware['mret_pc'] and mret_order is None:
                        mret_order = event.get('order')
                    elif mret_order is not None and event.get('order', 0) > mret_order:
                        completed += 1
                cursor = runner.event_count
                if completed >= 2:
                    break
            else:
                raise ValueError('declared-IRQ-F5-step-budget-exhausted')
        except BaseException as error:
            save(output / 'failure.json', dict(error_type=type(error).__name__, error=str(error)))
            raise
        finally:
            try:
                runner.finalize()
            finally:
                if evidence == 'full':
                    save(output / 'events.json', runner.events)
                    save(output / 'local_commands.json', recording.export_sessions())
                save(output / 'executions.json', recording.export_executions())
    identities = recording.export_executions()
    _require(len(identities) == len(sources) + 1
             and all(row.get('exit_code') == 0 and row.get('reaped') for row in identities),
             'clean-native-process-exits')
    traces, policy = cpu_obi_traces(artifacts['cpu'])
    receipt = SimpleNamespace(case_id=case_id, events=tuple(runner._event_refs_since(0)))
    observation = observe_declared_irq_consumption(
        events=tuple(runner.events), receipt=receipt, traces=traces, error_policy=policy,
        cpu_id='cpu', target_id=active,
        access=dict(device_id=active, target_component=active,
                    window_base=firmware['target_base'], window_size=options['window_size'],
                    offset=int(firmware['status_offsets'][0])),
        firmware=firmware, group=group,
        target_trace=artifacts[active].runtime_document['base_protocol_trace'],
        successor_range=(firmware['image_start'], firmware['image_end']),
        cpu_contract=contract)
    save(output / 'observation.json', observation)
    return observation, identities, group


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('original', 'fresh'), required=True)
    parser.add_argument('--original', type=Path, default=None,
                        help='fresh only: compare the original summary digest after writing own evidence')
    parser.add_argument('--cache', type=Path, default=None)
    parser.add_argument('--max-steps', type=int, default=2000)
    parser.add_argument('--evidence', choices=('full', 'summary'), default='full',
                        help='summary skips raw journal and command export; verification remains enabled')
    args = parser.parse_args()
    base = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(base), str(base / 'src')]
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.integration.declared_irq_consumption import (
        _require, admit_declared_irq_consumption, build_declared_irq_firmware, firmware_code)
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from scripts.run_timer_irq_smoke import timer_artifact
    _require(1 <= args.max_steps <= 10000, 'bounded-positive-max-steps')
    _require(not args.output.exists(), 'output-must-not-exist')
    _require(args.mode == 'fresh' or args.original is None, 'original-mode-cannot-compare')
    cache = (args.cache or Path(os.environ.get('MYFUZZ_F5_CACHE')
                                or Path(tempfile.gettempdir()) / 'myfuzz-declared-irq-f5-cache')).resolve()
    config = read(args.config)
    admission = admit_declared_irq_consumption(config, base_dir=base)
    _require(admission['status'] == 'admitted', 'admission-' + str(admission.get('reason')))
    fields = f5_fields(config, admission)
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / 'config.json', config)
    save(args.output / 'admission.json', admission)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            execution_validation_scope():
        options = dict(f5_source_options(config), window_size=fields['window_size'])
        artifacts = {'cpu': _artifact(config['cpu_profile'], 'cpu')}
        artifacts.update({name: timer_artifact(base, options['source_request'], name)
                          for name in f5_source_ids(options)})
        # Bind the realized CPU's own observation contract/authority to the
        # admitted join rules before any native step is taken.
        cpu_contract = native_irq_receipt_contract(artifacts['cpu'])
        authority = check_cpu_authority(admission, cpu_contract)
        bound = admit_declared_irq_consumption(config, base_dir=base,
                                               cpu_contract=cpu_contract)
        _require(semantic_digest(bound) == semantic_digest(admission),
                 'admission-bound-CPU-contract-mismatch')
        boot = source_backed_boot_fetch(artifacts['cpu'].plan.profile, base_dir=base,
            configured_boot_base=artifacts['cpu'].runtime_document['boot_contract']['configured_boot_base'])
        firmware = build_declared_irq_firmware(
            image_start=fields['image_start'], image_end=fields['image_end'], first_fetch=boot,
            target_base=fields['target_base'], status_offsets=fields['status_offsets'],
            result_address=fields['result_address'], clear_writes=fields['clear_writes'])
        _require(firmware['first_fetch'] == boot, 'configured-boot-fetch-mismatch')
        firmware['cause_bits'] = dict(fields['cause_bits'])
        firmware['digest'] = semantic_digest({key: value for key, value in firmware.items()
                                              if key != 'digest'})
        program = case_program(firmware, options, fields)
        case_id = 'declared-irq-f5-' + options['active_id']
        case = dict(schema_version='declared_irq_f5_case.v1', case_id=case_id,
                    cpu='cpu', target=options['active_id'], idle_source=options['idle_id'],
                    source_request=options['source_request'], source_port=options['source_port'],
                    source_bit_offset=options['source_bit_offset'],
                    trigger_writes=program['trigger_writes'], case_entry=program['case_entry'],
                    park=program['park'], host_invented_pulse=False, organic_target_irq=True,
                    status_offsets=list(firmware['status_offsets']),
                    clear_writes=[list(row) for row in firmware['clear_writes']],
                    result_address=firmware['result_address'])
        observation, identities, group = execute_once(
            artifacts=artifacts, active=options['active_id'], idle=options['idle_id'],
            program=program, firmware=firmware, options=options, base=base, cache=cache,
            output=args.output / args.mode, max_steps=args.max_steps, case_id=case_id,
            cpu_contract=cpu_contract, evidence=args.evidence)
        prefix = dict(
            schema_version='declared_irq_f5_prefix.v1', mode=args.mode,
            config_sha256=semantic_digest(config), admission_sha256=semantic_digest(admission),
            retirement_authority=authority,
            case=case, group=group.document(), first_fetch=boot, firmware=firmware,
            fixed_words=len(firmware_code(firmware)),
            program=dict(case_entry=program['case_entry'], park=program['park'],
                         images={address: data for address, data in program['images'].items()},
                         trigger_words=program['trigger_words'],
                         dynamic_sha256=program['dynamic_sha256']),
            artifacts={name: artifact.runtime_document['artifact_digest']
                       for name, artifact in artifacts.items()},
            target_protocol=artifacts[options['active_id']].runtime_document['base_protocol_trace']['protocol'],
            session_script=Path(__file__).name)
        save(args.output / 'prefix.json', prefix)
        digest = semantic_digest({key: value for key, value in observation.items()
                                  if key != 'case_id'})
        summary = dict(schema_version='declared_irq_f5_summary.v1', mode=args.mode,
                       evidence_mode=args.evidence,
                       status=observation['status'], irq_consumption=observation['irq_consumption'],
                       retirement_authority=authority,
                       cause_source=observation.get('cause_source'),
                       internal_version='unknown', case_origin='unknown',
                       reward_eligible=False, grants_F5=False, grants_F6=False,
                       semantic_sha256=digest, processes=identities,
                       refusals=observation.get('refusals'), unknown=observation.get('unknown'),
                       fresh_scope='separate-invocation-same-config-recomputed',
                       case_id=case_id, target=options['active_id'])
        if args.mode == 'fresh' and args.original is not None:
            original = read(args.original / 'summary.json')
            summary['fresh_matches'] = original.get('semantic_sha256') == digest
            _require(summary['fresh_matches'], 'fresh-semantic-mismatch')
        save(args.output / 'summary.json', summary)
        print(json.dumps(dict(status=summary['status'], mode=args.mode,
                              irq_consumption=summary['irq_consumption'],
                              semantic_sha256=digest, output=str(args.output))))
        if summary['status'] != 'verified' or summary['irq_consumption'] != 'verified':
            raise ValueError('declared-IRQ-F5-consumption-not-verified: '
                             + json.dumps(observation.get('refusals')))


if __name__ == '__main__':
    main()
