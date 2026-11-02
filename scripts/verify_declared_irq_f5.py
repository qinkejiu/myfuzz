#!/usr/bin/env python3
"""Independent offline re-derivation of a saved declared-IRQ F5 run.

Reads only saved artifacts (never runs RTL) and re-derives each claim from the
raw events: the two-phase semantic digest, the real target output sample, the
OR frame/take join, the ISR register read value against the CPU OBI beat and the
dependent RAM write, the MRET/successor join and the independent process
identities.  Anything it cannot recompute is reported as unavailable.

Scope: archived-artifact consistency.  It grants no live authority, no storage
version, no cross-case attribution and no reward.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

SCHEMA = 'declared_irq_f5_audit.v1'
MRET_WORD = 0x30200073


def load(path):
    return json.loads(Path(path).read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


def events_of(phase):
    rows = load(phase / 'events.json')
    if not isinstance(rows, list):
        raise ValueError('saved events must be a list')
    return rows


def by_id(rows):
    return {row['event_id']: row for row in rows if type(row.get('event_id')) is int}


def require(ok, reason, problems):
    if not ok:
        problems.append(reason)
    return ok


def check_phase(phase_dir):
    problems = []
    summary = load(phase_dir / 'summary.json')
    evidence = phase_dir / phase_dir.name
    observation = load(evidence / 'observation.json')
    executions = load(evidence / 'executions.json')
    rows = events_of(evidence)
    index = by_id(rows)
    stored_digest = summary.get('semantic_sha256')
    recomputed = digest({key: value for key, value in observation.items()
                         if key != 'case_id'})
    require(summary.get('status') == 'verified', 'summary-status', problems)
    require(summary.get('irq_consumption') == 'verified', 'summary-irq-consumption', problems)
    require(stored_digest == recomputed, 'semantic-digest-mismatch', problems)
    require(summary.get('grants_F5') is False and summary.get('grants_F6') is False
            and summary.get('reward_eligible') is False, 'false-grant-violated', problems)
    transport = observation.get('transport') or {}
    consumption = observation.get('consumption') or {}
    group = observation.get('group') or {}
    target_port = group.get('target_port')
    member_ids = list(group.get('member_source_ids') or ())
    require(len(member_ids) == 2, 'group-members', problems)

    # 1. The target's own native output sample carries the declared bit.
    output = transport.get('native_output') or {}
    pulse = index.get(output.get('event_id'))
    if require(isinstance(pulse, dict) and pulse.get('kind') == 'local_tick_sample'
               and pulse.get('component') == observation.get('target_id')
               and pulse.get('phase') == output.get('phase')
               and pulse.get('local_tick') == output.get('local_tick')
               and pulse.get('reset_epoch') == output.get('reset_epoch'),
               'target-native-sample', problems):
        physical = (pulse.get('outputs') or {}).get('physical') or {}
        raw = physical.get(output.get('runtime_name'))
        require(type(raw) is int and (raw >> int(output.get('bit', 0))) & 1 == 1,
                'target-native-output-bit', problems)
        require((pulse.get('outputs') or {}).get(output.get('physical_port')) == raw,
                'target-native-output-projection', problems)

    # 2. The OR frame is the unique active source and is joined to the take.
    frame_row = transport.get('or_frame') or {}
    frame = index.get(frame_row.get('event_id'))
    take = index.get((transport.get('native_take') or {}).get('event_id'))
    if require(isinstance(frame, dict) and frame.get('kind') == 'irq_group_delivery',
               'or-frame-event', problems):
        unique = frame.get('unique_source')
        require(frame.get('attribution_status') == 'unique'
                and type(unique) is str and unique in member_ids
                and unique.split('.', 1)[0] == observation.get('target_id')
                and frame.get('active_sources') == [unique],
                'or-frame-unique-attribution', problems)
        require(frame.get('value') == 1, 'or-frame-value', problems)
        require(isinstance(take, dict) and frame.get('native_take_event_id') == take.get('event_id'),
                'or-frame-take-join', problems)
    if require(isinstance(take, dict) and take.get('kind') == 'cpu_external_irq_taken',
               'native-take-event', problems):
        require(take.get('irq_taken_pre') == 1, 'native-take-decision', problems)
        for name in ('irq_ack_pre', 'irq_id_pre', 'irq_entry_pc'):
            if name in take:
                require(take.get(name) not in (None, 0), 'native-take-' + name, problems)
        sample = index.get(take.get('sample_event_id'))
        require(isinstance(sample, dict) and sample.get('kind') == 'cpu_external_irq_sample'
                and sample.get('local_tick') == take.get('local_tick')
                and all(sample.get(key) == 1 for key in
                        ('expected_input', 'actual_pre_input', 'actual_post_input')),
                'cpu-input-sample', problems)
        serial = (take.get('irq_serial_observation') or {}).get('decision') or {}
        token = serial.get('value')
        if serial.get('status') == 'observed':
            require(type(token) is int and token > 0, 'decision-serial-nonzero', problems)
            joined = [row for row in rows if row.get('kind') == 'cpu_retire'
                      and ((row.get('irq_serial_observation') or {}).get('retirement') or {}).get('value') == token
                      and ((row.get('irq_serial_observation') or {}).get('retirement') or {}).get('status') == 'observed']
            require(len(joined) == 1, 'decision-serial-retirement-join', problems)
            require((transport.get('first_handler_retirement') or {}).get('event_id')
                    == (joined[0].get('event_id') if joined else None),
                    'first-handler-retirement', problems)

    # 3. The declared status read value is identical on every layer.
    reads = list(consumption.get('register_reads') or ())
    require(bool(reads), 'declared-status-read', problems)
    for read in reads:
        delivery = index.get(read.get('delivery_event'))
        require(isinstance(delivery, dict) and delivery.get('kind') == 'mmio_delivery'
                and delivery.get('write') is False
                and delivery.get('offset') == read.get('offset')
                and delivery.get('read_value') == read.get('value'),
                'status-read-delivery-value', problems)
        beat = read.get('native_OBI') or {}
        require(beat.get('write') == 0 and beat.get('rdata') == read.get('value'),
                'status-read-obi-value', problems)
        require(read.get('retirement_join') in ('exact_fields', 'by_documented_order'),
                'status-read-retirement-join', problems)
    for write in list(consumption.get('result_ram_writes') or ()):
        beat = write.get('native_OBI') or {}
        require(beat.get('write') == 1 and beat.get('value') == write.get('value'),
                'ram-write-obi-value', problems)
        require(write.get('value') == (reads[write.get('index', 0)].get('value')
                                       if reads else None), 'ram-write-read-value', problems)

    # 4. MRET and the first successor.
    mret = consumption.get('mret') or {}
    successor = consumption.get('successor') or {}
    require(mret.get('insn') == MRET_WORD, 'mret-word', problems)
    require(successor.get('order') == (mret.get('order') + 1
                                       if type(mret.get('order')) is int else None),
            'successor-order', problems)
    require(successor.get('event_id') in index, 'successor-event', problems)

    # 5. Process identities are real, reaped and clean.
    require(isinstance(executions, list) and len(executions) == 3,
            'three-component-executions', problems)
    identities = []
    for row in executions if isinstance(executions, list) else ():
        require(row.get('exit_code') == 0 and row.get('reaped') is True,
                'component-exit', problems)
        require(type(row.get('pid')) is int and row.get('pid') > 0
                and type(row.get('execution_nonce')) is str and row.get('execution_nonce'),
                'component-identity', problems)
        identities.append(dict(component=row.get('component'), pid=row.get('pid'),
                               execution_nonce=row.get('execution_nonce'),
                               binary_sha256=row.get('binary_sha256'),
                               build_digest=row.get('build_digest')))
    return dict(mode=phase_dir.name, status=summary.get('status'),
                irq_consumption=summary.get('irq_consumption'),
                semantic_sha256=recomputed, stored_digest=stored_digest,
                event_count=len(rows), target=observation.get('target_id'),
                group=group, transport=dict(attribution=transport.get('attribution'),
                                            decision_serial=transport.get('decision_serial')),
                read_values=[read.get('value') for read in reads],
                result_values=[write.get('value') for write in
                               (consumption.get('result_ram_writes') or ())],
                mret_pc=mret.get('pc'), return_target=consumption.get('return_target'),
                successor_pc=successor.get('pc'), identities=identities,
                observation=observation, problems=problems)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True,
                        help='case directory holding original/ and fresh/')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('audit output must not exist')
    phases = {}
    for mode in ('original', 'fresh'):
        phases[mode] = check_phase(args.run / mode)
    first, second = phases['original'], phases['fresh']
    problems = list(first['problems']) + list(second['problems'])
    if first['semantic_sha256'] != second['semantic_sha256']:
        problems.append('cross-phase-semantic-mismatch')
    if canonical({k: v for k, v in first['observation'].items() if k != 'case_id'}) != \
            canonical({k: v for k, v in second['observation'].items() if k != 'case_id'}):
        problems.append('cross-phase-observation-mismatch')
    independent = {}
    for name in {row['component'] for row in first['identities']} & \
            {row['component'] for row in second['identities']}:
        one, = [row for row in first['identities'] if row['component'] == name]
        two, = [row for row in second['identities'] if row['component'] == name]
        same = (one['pid'] == two['pid'] or one['execution_nonce'] == two['execution_nonce'])
        independent[name] = dict(original=one, fresh=two, independent=not same)
        if same:
            problems.append('process-not-independent:' + name)
        for key in ('binary_sha256', 'build_digest'):
            if one.get(key) != two.get(key):
                problems.append('build-identity-drift:' + name + ':' + key)
    checks = dict(
        both_phases_verified=(first['status'] == 'verified' and second['status'] == 'verified'),
        irq_consumption_verified=(first['irq_consumption'] == 'verified'
                                  and second['irq_consumption'] == 'verified'),
        semantic_digests_recomputed=(first['semantic_sha256'] == first['stored_digest']
                                     and second['semantic_sha256'] == second['stored_digest']),
        cross_phase_equal=(first['semantic_sha256'] == second['semantic_sha256']),
        processes_independent=all(row['independent'] for row in independent.values())
        and len(independent) == 3,
        joins_rederived=not problems,
    )
    audit = dict(schema_version=SCHEMA, run=str(args.run),
                 status='verified' if all(checks.values()) else 'incomplete',
                 checks=checks, problems=sorted(set(problems)),
                 phases={mode: {key: value for key, value in phase.items()
                                if key not in ('observation', 'problems')}
                         for mode, phase in phases.items()},
                 process_identity=independent,
                 scope='saved_artifact_independent_consistency_verification_not_live_authority',
                 grants_F5=False, grants_F6=False, native_authority=False,
                 reward_eligible=False,
                 not_claimed=['live authority', 'internal register version',
                              'cross-case writer attribution', 'online RTL coverage AUC',
                              'strategy superiority'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(audit, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(status=audit['status'], checks=checks, problems=audit['problems'])))
    raise SystemExit(0 if audit['status'] == 'verified' else 1)


if __name__ == '__main__':
    main()
