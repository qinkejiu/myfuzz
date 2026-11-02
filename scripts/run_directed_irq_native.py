#!/usr/bin/env python3
"""Native directed IRQ cases for the lead's frozen window; never a fake pass.

Usage::

    python3 scripts/run_directed_irq_native.py \\
        --config configs/scenarios/directed-irq-matrix.json \\
        --case cross-protocol.apb-spi-cv32e20 \\
        --output runs/directed-irq-native/<case> --native --cache <dir>

Every case is declared in the matrix JSON with its expected evidence layers.
An *executable* case delegates the real RTL session to an existing public
runner (``scripts/run_timer_irq_smoke.py``) and then re-derives each declared
layer from the produced journal.  A case that no public runner can build is
refused with its declared code; it is never reported as a pass.

The script adds no RTL, no firmware and no probe.  It never reports
``verified`` unless every declared evidence layer was derived from a real
saved journal with a clean native process exit.  Missing tooling, a missing
config or a missing cache yields ``unavailable`` with the exact reason.

Scope fields are explicit: ``native_authority=False``, ``grants_F5=False``,
``grants_F6=False``, ``reward_eligible=False``, ``isr_mmio='unknown'`` and
``irq_consumption='unknown'``.  ``--preflight`` performs the same config and
admission checks without starting anything.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

MATRIX_SCHEMA = 'directed_irq_matrix.v1'
SUMMARY_SCHEMA = 'directed_irq_native_summary.v1'
LAYERS = frozenset((
    'source_verification', 'declared_output_mapping', 'irq_group_unique_attribution',
    'irq_group_joint_attribution', 'cpu_native_sample', 'cpu_native_take',
    'cpu_retirement_serial', 'irq_serial_certificate', 'reset_barrier',
    'post_reset_fresh_epoch', 'no_lineage_after_reset', 'no_lineage_from_sync_exception',
    'debug_nmi_diversion_refused', 'unknown_origin_no_credit', 'no_delivery_frame_no_join',
    'overrun_or_cancelled_no_credit'))
NO_AUTHORITY = dict(native_authority=False, grants_F5=False, grants_F6=False,
                    reward_eligible=False, isr_mmio='unknown', irq_consumption='unknown')


def load_matrix(path):
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if document.get('schema_version') != MATRIX_SCHEMA:
        raise ValueError('unsupported directed IRQ matrix schema')
    if type(document.get('cases')) is not list or not document['cases']:
        raise ValueError('directed IRQ matrix requires cases')
    ids = [case.get('id') for case in document['cases']]
    if any(type(name) is not str or not name for name in ids) or len(set(ids)) != len(ids):
        raise ValueError('directed IRQ matrix case ids must be unique strings')
    return document


def case_by_id(document, name):
    selected = [case for case in document['cases'] if case.get('id') == name]
    if len(selected) != 1:
        raise ValueError('unknown directed IRQ case:' + str(name))
    return selected[0]


def _resolve(relative):
    path = Path(relative)
    return (path if path.is_absolute() else ROOT / path)


def case_configs(case):
    """Every repository config path one case references, in declared order."""
    names = ('real_config', 'declared_scenario', 'secondary_scenario', 'saved_evidence')
    return {name: case[name] for name in names
            if type(case.get(name)) is str and case[name]}


def preflight(document, *, base_dir=None):
    """Validate declarations without building, running or claiming anything."""
    base = Path(base_dir or ROOT)
    rows = []
    for case in document['cases']:
        row = {'case': case['id'], 'kind': case.get('kind'),
               'native_ready': bool(case.get('native_ready')),
               'problems': [], 'status': None, 'refusal': case.get('native_refusal')}
        for name, relative in case_configs(case).items():
            if not _resolve(relative).exists():
                row['problems'].append('missing-' + name + ':' + relative)
        runner = case.get('runner')
        if case.get('native_ready'):
            if type(runner) is not str or not _resolve(runner).is_file():
                row['problems'].append('missing-native-runner:' + str(runner))
            if type(case.get('real_config')) is not str:
                row['problems'].append('native-case-requires-real-config')
            if type(case.get('required_evidence_layers')) is not list \
                    or not case['required_evidence_layers']:
                row['problems'].append('native-case-requires-evidence-layers')
            unsupported = sorted(set(case.get('required_evidence_layers') or ()) - LAYERS)
            if unsupported:
                row['problems'].append('unsupported-evidence-layers:' + ','.join(unsupported))
            row['status'] = 'ready' if not row['problems'] else 'error'
        else:
            refusal = case.get('native_refusal')
            if (type(refusal) is not dict or type(refusal.get('code')) is not str
                    or not refusal['code'] or type(refusal.get('detail')) is not str
                    or not refusal['detail']):
                row['problems'].append('missing-exact-native-refusal')
            row['status'] = 'refused' if not row['problems'] else 'error'
        claimed = set(case.get('claimed_layers') or ())
        measurable = set(case.get('measurable_layers') or ())
        if not claimed or not claimed <= measurable:
            row['problems'].append('claimed-layers-exceed-measurable-layers')
        if claimed - LAYERS or measurable - LAYERS:
            row['problems'].append('unknown-evidence-layer')
        if row['problems']:
            row['status'] = 'error'
        rows.append(row)
    return {
        'schema_version': 'directed_irq_native_preflight.v1',
        'status': 'ready' if all(row['status'] != 'error' for row in rows) else 'error',
        'scope': 'declaration-validation-only; nothing was built or run',
        'native_run': False,
        **NO_AUTHORITY,
        'cases': rows,
        'counts': {'ready': sum(row['status'] == 'ready' for row in rows),
                   'refused': sum(row['status'] == 'refused' for row in rows),
                   'error': sum(row['status'] == 'error' for row in rows)},
        'limitations': ['Preflight reads declarations and paths only.',
                        'A ready case still needs the frozen native window to produce evidence.'],
    }


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def _summary(case, status, *, evidence=None, missing=None, refusal=None, native=True,
             **extra):
    document = {
        'schema_version': SUMMARY_SCHEMA,
        'status': status,
        'native': native,
        'case': {'id': case['id'], 'kind': case.get('kind'),
                 'native_ready': bool(case.get('native_ready'))},
        'config': case.get('real_config'),
        'runner': case.get('runner'),
        'scope': extra.pop('scope', 'directed-IRQ-native-case'),
        **NO_AUTHORITY,
        'declared_layers': list(case.get('required_evidence_layers') or ()),
        'derived_layers': sorted(evidence or {}),
        'missing_layers': sorted(missing or ()),
        'evidence': evidence or {},
        'refusal': refusal,
        **extra,
        'limitations': [
            'A pass here covers only the declared layers of this one case.',
            'It grants no ISR/MMIO, F5/F6, storage-version or reward authority.',
            'Native authority remains with the frozen-window acceptance process.',
        ],
    }
    return document


def _refused(case):
    refusal = case.get('native_refusal')
    if type(refusal) is not dict:
        raise ValueError('non-native case requires a declared refusal')
    return _summary(case, 'refused', native=False,
                    refusal={'code': refusal['code'], 'reason': refusal['detail'],
                             'stage': 'case-declaration'},
                    scope='directed-IRQ-native-refusal')


def _run_delegate(case, *, cache, output, max_steps):
    runner = _resolve(case['runner'])
    config = _resolve(case['real_config'])
    target = output / 'runner'
    if target.exists():
        raise ValueError('native case output must not exist:' + str(target))
    # The delegate builds into this content-addressed cache root; create the
    # root so a first frozen-window run does not fail on a missing parent.
    Path(cache).mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(runner), '--native', '--config', str(config),
               '--output', str(target), '--cache', str(cache), '--max-steps', str(max_steps)]
    completed = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True)
    (output / 'runner-command.json').write_text(
        json.dumps({'command': command, 'returncode': completed.returncode},
                   indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (output / 'runner-stdout.txt').write_text(completed.stdout, encoding='utf-8')
    (output / 'runner-stderr.txt').write_text(completed.stderr, encoding='utf-8')
    return completed, target


def _source_verification(artifact_document):
    document = artifact_document.get('source_verification')
    if type(document) is not dict or document.get('source_status') != 'source_verified':
        raise ValueError('native case lacks a source-verified CPU artifact')
    return {'source_status': document['source_status'],
            'elaboration_status': document.get('elaboration_status'),
            'schema_version': document.get('schema_version'),
            'profile_id': document.get('profile_id') or document.get('component_id'),
            'sha256': sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()}


def _declared_output(artifact_document, component, port, offset):
    rows = [row for row in artifact_document['physical_exports']
            if row.get('physical_port') == port and row.get('direction') == 'output'
            and row.get('disposition') in ('observe', 'functional')
            and type(row.get('bit_lo')) is int and type(row.get('bit_hi')) is int
            and row['bit_lo'] <= offset <= row['bit_hi']]
    if len(rows) != 1:
        raise ValueError('native case lacks one declared IRQ output:' + str(port))
    row = rows[0]
    return {'component': component, 'adapter_id': 'declared-output.v1',
            'physical_port': row['physical_port'], 'runtime_name': row['runtime_name'],
            'width': row['width'], 'bit_lo': row['bit_lo'], 'bit_hi': row['bit_hi'],
            'source_bit_offset': offset, 'transport_only': True,
            'cause': 'unknown', 'internal_version': 'unknown'}


def _group_from_config(config, frame, ports):
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    order = [(config['active_id'], ports['active']),
             (config['idle_id'], ports['idle'])]
    group = IrqDeliveryGroup(
        frame['group_id'], frame['target_component'], frame['target_port'],
        tuple(IrqDeliveryMember(component, port, mode='pulse',
                                pulse_width_ticks=config['pulse_width_ticks'],
                                source_bit_offset=config.get('source_bit_offset', 0),
                                source_adapter=config.get('source_adapter'))
              for component, port in order))
    if group.identity_sha256 != frame['group_sha256']:
        raise ValueError('native case group identity does not match its declaration')
    return group


def derive_evidence(case, *, runner_output, matrix_config):
    """Re-derive every layer from saved journals; refuse when any is missing."""
    from myfuzz.integration.saved_irq_group import frame_for_sample
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    summary_path = runner_output / 'summary.json'
    config = json.loads((runner_output / 'config.json').read_text(encoding='utf-8'))
    artifacts = {}
    for name in ('cpu', config['active_id'], config['idle_id']):
        artifacts[name] = json.loads((runner_output / (name + '-artifact.json')).read_text(
            encoding='utf-8'))
    runner_summary = json.loads(summary_path.read_text(encoding='utf-8'))
    evidence = {}
    missing = []
    source_port = config['source_port'] if type(config.get('source_port')) is str else 'irq'
    ports = {'active': source_port, 'idle': source_port}
    evidence['source_verification'] = _source_verification(artifacts['cpu'])
    evidence['declared_output_mapping'] = {
        role: _declared_output(artifacts[config[role + '_id']], config[role + '_id'],
                               ports[role], config.get('source_bit_offset', 0))
        for role in ('active', 'idle')}
    events = json.loads((runner_output / 'original' / 'events.json').read_text(encoding='utf-8'))
    fresh = json.loads((runner_output / 'fresh' / 'events.json').read_text(encoding='utf-8'))
    by_id = {event['event_id']: event for event in events}
    takes = [event for event in events if event.get('kind') == 'cpu_external_irq_taken']
    if len(takes) != 1:
        raise ValueError('native case requires exactly one actual IRQ take')
    take = takes[0]
    frames = [event for event in events if event.get('kind') == 'irq_group_delivery'
              and event.get('native_take_event_id') == take['event_id']]
    if len(frames) != 1:
        raise ValueError('native case requires exactly one delivery frame for the take')
    frame = frames[0]
    group = _group_from_config(config, frame, ports)
    sample = by_id.get(frame.get('native_sample_event_id'))
    if type(sample) is not dict or sample.get('kind') != 'cpu_external_irq_sample':
        raise ValueError('native case delivery frame lacks its parsed CPU sample')
    joined = frame_for_sample(group, sample, events, by_id)
    unique = config['active_id'] + '.' + ports['active']
    if joined.get('attribution_status') != 'unique' or joined.get('unique_source') != unique:
        raise ValueError('native case take is not uniquely attributed to the active source')
    evidence['irq_group_unique_attribution'] = {
        'group_id': group.group_id, 'group_sha256': group.identity_sha256,
        'group_document': group.document(), 'attribution_status': 'unique',
        'unique_source': unique, 'active_sources': joined['active_sources'],
        'cpu_tick': joined['cpu_tick'], 'delivery_event_id': frame['event_id'],
        'native_sample_event_id': frame['native_sample_event_id'],
        'native_take_event_id': take['event_id']}
    if (any(type(sample.get(name)) is not int or sample[name] != 1 for name in
            ('expected_input', 'actual_pre_input', 'actual_post_input'))
            or sample.get('irq_taken_pre') != 1
            or sample.get('local_tick') != joined['cpu_tick']):
        raise ValueError('native case sample is not a real high external IRQ input')
    evidence['cpu_native_sample'] = {
        'event_id': sample['event_id'], 'producer_event_id': sample.get('producer_event_id'),
        'local_tick': sample['local_tick'], 'receipt_id': sample.get('receipt_id'),
        'reset_epoch': sample.get('reset_epoch'), 'irq_taken_pre': sample.get('irq_taken_pre'),
        'expected_input': sample['expected_input'], 'actual_pre_input': sample['actual_pre_input'],
        'actual_post_input': sample['actual_post_input']}
    key = take.get('take_key')
    if (type(key) is not list or len(key) != 3 or key[0] != group.target_component
            or type(key[1]) is not int or key[1] != sample.get('reset_epoch')
            or type(key[2]) is not int or key[2] < 1):
        raise ValueError('native case take identity is not the exact CPU take')
    evidence['cpu_native_take'] = {
        'event_id': take['event_id'], 'sample_event_id': take.get('sample_event_id'),
        'producer_event_id': take.get('producer_event_id'), 'take_key': key,
        'irq_taken_pre': take.get('irq_taken_pre'),
        'irq_serial_observation': take.get('irq_serial_observation')}
    certificates = IrqSerialCertificates().ingest(events)
    if len(certificates) != 1:
        raise ValueError('native case requires exactly one exact serial certificate')
    certificate = certificates[0]
    if (certificate['decision_serial'] != certificate['retirement_serial']
            or certificate['decision_serial'] <= 0):
        raise ValueError('native case certificate is not a nonzero serial equality')
    fresh_certificates = IrqSerialCertificates().ingest(fresh)
    if len(fresh_certificates) != 1:
        raise ValueError('fresh native session requires exactly one serial certificate')
    evidence['irq_serial_certificate'] = {
        'decision_serial': certificate['decision_serial'],
        'retirement_serial': certificate['retirement_serial'],
        'decision_event_id': certificate['decision_event_id'],
        'retirement_event_id': certificate['retirement_event_id'],
        'take_identity': certificate['take_identity'],
        'execution_id': certificate['execution_id'],
        'reset_epoch': certificate['reset_epoch'],
        'schema_version': certificate['schema_version'],
        'fresh_session_event_ids': [fresh_certificates[0]['decision_event_id'],
                                    fresh_certificates[0]['retirement_event_id']]}
    evidence['cpu_retirement_serial'] = {
        'retirement_event_id': certificate['retirement_event_id'],
        'retirement_serial': certificate['retirement_serial'],
        'scope': 'post_rising_rvfi_retirement_serial_observation'}
    if runner_summary.get('status') != 'verified' or runner_summary.get('fresh_matches') is not True:
        raise ValueError('native delegate did not verify a fresh independent session')
    if type(runner_summary.get('processes')) is not dict:
        raise ValueError('native delegate recorded no process identities')
    processes = []
    for role, rows in runner_summary['processes'].items():
        for row in rows:
            processes.append(dict(role=role, component=row.get('component'),
                                  pid=row.get('pid'), execution_nonce=row.get('execution_nonce'),
                                  exit_code=row.get('exit_code'), reaped=row.get('reaped')))
    missing = sorted(set(case.get('required_evidence_layers') or ()) - set(evidence))
    return evidence, missing, dict(
        runner_summary=str(summary_path), runner_scope=runner_summary.get('fresh_scope'),
        runner_result={key: runner_summary.get('result', {}).get(key) for key in
                       ('status', 'scope', 'decision_serial', 'native_take_tick',
                        'first_retirement_pc')},
        processes=processes, matrix_config=str(matrix_config))


def execute_case(case, *, config_path, cache, output, max_steps):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    if not case.get('native_ready'):
        summary = _refused(case)
        _write(output / 'summary.json', summary)
        return summary, 2
    for relative in case_configs(case).values():
        if not _resolve(relative).exists():
            summary = _summary(case, 'unavailable', refusal={
                'code': 'declared-config-missing', 'reason': relative,
                'stage': 'config-resolution'}, scope='directed-IRQ-native-unavailable')
            _write(output / 'summary.json', summary)
            return summary, 3
    if cache is None:
        summary = _summary(case, 'unavailable', refusal={
            'code': 'native-cache-path-required',
            'reason': 'a cache directory is required for the real harness build',
            'stage': 'argument-validation'}, scope='directed-IRQ-native-unavailable')
        _write(output / 'summary.json', summary)
        return summary, 3
    completed, runner_output = _run_delegate(case, cache=Path(cache), output=output,
                                             max_steps=max_steps)
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or '').strip().splitlines()[-8:]
        summary = _summary(case, 'unavailable', refusal={
            'code': 'native-delegate-failed',
            'reason': '; '.join(tail) or 'no native output',
            'stage': 'native-delegate',
            'delegate_returncode': completed.returncode},
            scope='directed-IRQ-native-unavailable',
            delegate_output=str(runner_output))
        _write(output / 'summary.json', summary)
        return summary, 3
    try:
        evidence, missing, extra = derive_evidence(case, runner_output=runner_output,
                                                   matrix_config=config_path)
    except (OSError, ValueError, KeyError, TypeError) as error:
        summary = _summary(case, 'failed', refusal={
            'code': 'evidence-derivation-failed', 'reason': str(error),
            'stage': 'evidence-derivation'}, scope='directed-IRQ-native-failed',
            delegate_output=str(runner_output))
        _write(output / 'summary.json', summary)
        return summary, 1
    status = 'verified' if not missing else 'failed'
    summary = _summary(case, status, evidence=evidence, missing=missing,
                       scope='declared-output-transport-to-CPU-first-handler',
                       delegate_output=str(runner_output), **extra)
    _write(output / 'summary.json', summary)
    return summary, 0 if status == 'verified' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path,
                        default=ROOT / 'configs/scenarios/directed-irq-matrix.json')
    parser.add_argument('--case', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--cache', type=Path, default=None)
    parser.add_argument('--max-steps', type=int, default=1500)
    parser.add_argument('--preflight', action='store_true',
                        help='validate declarations only; starts nothing')
    args = parser.parse_args(argv)
    if not 1 <= args.max_steps <= 10000:
        print(json.dumps({'status': 'refused', 'reason': 'bounded-positive-max-steps-required'}))
        return 2
    try:
        document = load_matrix(args.config)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}, sort_keys=True))
        return 2
    if args.preflight:
        report = preflight(document)
        report['selected_case'] = args.case
        try:
            case_by_id(document, args.case)
        except ValueError as error:
            report['problems'] = [str(error)]
        text = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if args.output is not None:
            _write(args.output / 'preflight.json', report)
        print(text, end='')
        return 0 if report['status'] == 'ready' and not report.get('problems') else 2
    try:
        case = case_by_id(document, args.case)
        summary, code = execute_case(case, config_path=args.config, cache=args.cache,
                                     output=args.output, max_steps=args.max_steps)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}, sort_keys=True))
        return 2
    print(json.dumps({'status': summary['status'], 'case': case['id'],
                      'output': str(args.output),
                      'derived_layers': summary['derived_layers'],
                      'refusal': summary['refusal']}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
