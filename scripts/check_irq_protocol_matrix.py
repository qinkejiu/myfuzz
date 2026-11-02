#!/usr/bin/env python3
"""Cross-protocol admission gate for declared IRQ delivery; never runs a DUT.

For every combination of CPU protocol adapter (OBI, Wishbone, AHB-Lite) and
declared target protocol (APB SPI, Wishbone ZipTimer, AHB SHA) this gate:

* builds the CPU and target artifacts through the public local-harness
  factories (``_artifact`` / ``timer_artifact``),
* constructs the real component sessions *without preparation* (constructing a
  session never compiles or launches anything; ``prepare_local`` does),
* installs the explicit :class:`IrqDeliveryGroup` and asks the production
  verifier :func:`verify_group_sessions` to admit or refuse it, and
* records the exact evidence objects on admission and the exact refusal code
  and reason otherwise.

No native process, no Verilator build and no DUT simulation is started. A row
of this matrix is a *software preparation* fact: it states whether the
combination can produce the declared-output and native-CPU evidence at all. It
is not an IRQ take, not a serial certificate and not a native result.

A combination whose CPU has no registered native IRQ source contract is
refused by name (``unregistered-native-IRQ-CPU-adapter`` plus the profile id)
instead of being silently skipped.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

MATRIX_SCHEMA = 'irq_protocol_matrix.v1'
SCOPE = 'software-preparation-admission-only'
NO_NATIVE = dict(native_run=False, native_authority=False, grants_F5=False,
                 grants_F6=False, reward_eligible=False)
SOURCE_CONTRACT_REFUSAL = 'unregistered-native-IRQ-CPU-adapter'


def _cpu_session(artifact, *, base_dir, cache_dir):
    """Construct the public CPU session for one real artifact kind."""
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.router import DataflowRouter
    kind = artifact.runtime_document.get('kind')
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    router = DataflowRouter(())
    if kind == 'obi_cpu':
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        return GeneratedCve2Session(artifact, base_dir=base_dir, cache_dir=cache_dir,
                                    memory=memory, router=router, native_irq_receipts=True,
                                    physical_tick_samples=True)
    if kind == 'wishbone_cpu':
        from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
        return GeneratedWishboneCpuSession(artifact, base_dir=base_dir, cache_dir=cache_dir,
                                           memory=memory, router=router)
    if kind == 'ahb_lite_cpu':
        from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
        return GeneratedAhbMemorySession(artifact, base_dir=base_dir, cache_dir=cache_dir,
                                         memory=memory, router=router)
    raise ValueError('no-public-cpu-session:' + str(kind))


def _target_session(artifact, *, base_dir, cache_dir):
    from myfuzz.local_harness.declared_irq_output import declared_irq_target_session_type
    return declared_irq_target_session_type(artifact)(artifact, base_dir=base_dir,
                                                      cache_dir=cache_dir)


def _cpu_irq_port(session):
    port = getattr(session, 'irq_input_port', None)
    return port if type(port) is str and port else 'irq'


def _module_present(name):
    return type(name) is str and importlib.util.find_spec(name) is not None


def _contract_status(profile):
    """Whether a registered native IRQ source contract exists for this profile."""
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract_for_profile)
    try:
        contract = native_irq_receipt_contract_for_profile(profile)
    except ValueError as error:
        return False, {'code': str(error), 'reason': str(error),
                       'profile_id': profile.component_id}
    return True, {'schema_version': contract.get('schema_version'),
                  'profile_id': contract.get('profile_id'),
                  'input_port': contract.get('input_port'),
                  'decision_probes': sorted(contract.get('decision_probes', {}))}


def _source_verification(profile, *, base_dir):
    from myfuzz.local_harness.native_irq_receipt_contract import verify_native_irq_cpu_source
    return verify_native_irq_cpu_source(profile, base_dir=base_dir)


def _artifact(profile_path, instance):
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact as build_artifact
    return build_artifact(profile_path, instance)


def _target_artifact(base_dir, relative, instance):
    from scripts.run_timer_irq_smoke import timer_artifact
    return timer_artifact(base_dir, relative, instance)


def _evidence(row, group, mapping, target_artifact):
    """Detach the exact preparation evidence objects produced for one admission."""
    exports = [r for r in target_artifact.runtime_document['physical_exports']
               if r.get('physical_port') == mapping['physical_port']
               and r.get('runtime_name') == mapping['runtime_name']]
    return {
        'cpu_source_verification': row['cpu']['source_verification'],
        'cpu_native_irq_contract': row['cpu']['contract'],
        'declared_output_mapping': dict(mapping),
        'target_irq_export': exports[0] if len(exports) == 1 else exports,
        'group_document': group.document(),
        'group_sha256': group.identity_sha256,
        'group_owner_ref': group.owner_ref,
        'member_bindings': [asdict(b) for b in group.member_bindings()],
    }


def _evaluate_one(adapter, target, *, base_dir, cache_dir):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.scenario.irq_delivery_group import (IrqDeliveryGroup, IrqDeliveryMember,
                                                    verify_group_sessions)
    profile = load_component_profile(ROOT / adapter['profile'])
    row = {'cpu_adapter': adapter['id'], 'target_protocol': target['id'],
           'protocol_pair': adapter['protocol'] + '->' + target['protocol'],
           'cpu': {'id': adapter['id'], 'protocol': adapter['protocol'],
                   'profile': adapter['profile'], 'profile_id': profile.component_id},
           'target': {'id': target['id'], 'protocol': target['protocol'],
                      'request': target['request'], 'source_port': target['source_port']}}

    def refused(code, reason, *, stage, extra=None):
        row.update(status='refused', admission=None,
                   refusal={'code': code, 'reason': reason, 'stage': stage,
                            **(extra or {})})
        return row

    contract_ok, contract = _contract_status(profile)
    row['cpu']['contract'] = contract
    row['cpu']['contract_registered'] = contract_ok
    row['cpu']['contract_module'] = adapter.get('native_irq_receipt_contract')
    row['cpu']['contract_module_present'] = _module_present(adapter.get('native_irq_receipt_contract'))
    if not contract_ok:
        # No registered native IRQ source contract: refuse by name, before any
        # session exists.  This is the honest gate order, not a skipped row.
        return refused(contract['code'], contract['reason'], stage='cpu-source-contract',
                       extra={'cpu_profile_id': profile.component_id,
                              'cpu_contract_module': adapter.get('native_irq_receipt_contract'),
                              'cpu_contract_module_present': row['cpu']['contract_module_present']})
    try:
        cpu_artifact = _artifact(adapter['profile'], 'cpu')
    except (OSError, ValueError, KeyError, TypeError) as error:
        return refused('cpu-artifact-unavailable', str(error), stage='cpu-artifact')
    row['cpu']['runtime_kind'] = cpu_artifact.runtime_document.get('kind')
    try:
        row['cpu']['source_verification'] = _source_verification(profile, base_dir=ROOT)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return refused('cpu-source-verification-failed', str(error),
                       stage='cpu-source-verification')
    try:
        target_artifact = _target_artifact(ROOT, target['request'],
                                          target['id'].replace('-', '_') + '_sample')
    except (OSError, ValueError, KeyError, TypeError) as error:
        return refused('target-artifact-unavailable', str(error), stage='target-artifact')
    row['target']['runtime_kind'] = target_artifact.runtime_document.get('kind')
    if row['target']['runtime_kind'] != target['expected_kind']:
        return refused('target-protocol-kind-mismatch', target['expected_kind'],
                       stage='target-artifact')
    try:
        cpu = _cpu_session(cpu_artifact, base_dir=ROOT, cache_dir=cache_dir)
        target_session = _target_session(target_artifact, base_dir=ROOT, cache_dir=cache_dir)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return refused('session-construction-failed', str(error), stage='session')
    row['cpu']['session'] = type(cpu).__name__
    row['cpu']['native_irq_receipts_enabled'] = bool(
        getattr(cpu, 'native_irq_receipts_enabled', False))
    row['target']['session'] = type(target_session).__name__
    cpu_id = cpu_artifact.plan.request.instance_id
    target_id = target_artifact.plan.request.instance_id
    group = IrqDeliveryGroup('directed-irq-matrix:' + adapter['id'] + ':' + target['id'],
                             cpu_id, _cpu_irq_port(cpu),
                             (IrqDeliveryMember(target_id, target['source_port'], mode='pulse',
                                                pulse_width_ticks=16,
                                                source_adapter='declared-output.v1'),))
    row['group_id'] = group.group_id
    try:
        mappings = verify_group_sessions(group, {cpu_id: cpu, target_id: target_session})
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        message = str(error)
        code = contract['code'] if not contract_ok and message == contract['code'] else message
        return refused(code, message, stage='group-admission',
                       extra={'cpu_profile_id': profile.component_id})
    mapping, = mappings.values()
    row.update(status='admitted', refusal=None,
               admission=_evidence(row, group, mapping, target_artifact))
    return row


def _expectation(adapter, target, row):
    """Compare the observed row with the declaration; never relax the rule."""
    expected = adapter['expectation']
    mode = expected['status']
    actual = row['status']
    if mode == 'admitted':
        honest = actual == 'admitted' and row.get('admission', {}).get(
            'declared_output_mapping', {}).get('adapter_id') == expected.get('adapter_id')
        return {'status': 'admitted', 'adapter_id': expected.get('adapter_id'),
                'honest': honest}
    if mode == 'refused':
        code = (row.get('refusal') or {}).get('code')
        return {'status': 'refused', 'refusal_code': expected.get('refusal_code'),
                'observed_refusal_code': code,
                'honest': actual == 'refused' and code == expected.get('refusal_code')}
    if mode == 'admitted_when_contract_module_present':
        module = adapter.get('native_irq_receipt_contract')
        present = _module_present(module)
        if not present:
            code = (row.get('refusal') or {}).get('code')
            return {'status': 'refused_without_contract_module',
                    'refusal_code': expected.get('refusal_code'),
                    'observed_refusal_code': code,
                    'required_module': module,
                    'honest': actual == 'refused' and code == expected.get('refusal_code')}
        if actual == 'admitted':
            return {'status': 'admitted', 'required_module': module, 'honest': True}
        return {'status': 'refused_with_contract_module_present',
                'required_module': module,
                'observed_refusal_code': (row.get('refusal') or {}).get('code'),
                'pending_source_support': 'dispatch registration in '
                                          'myfuzz/local_harness/native_irq_receipt_contract.py',
                'honest': False}
    raise ValueError('unsupported matrix expectation:' + str(mode))


def evaluate_matrix(config, *, base_dir=None, cache_dir=None):
    """Build every declared combination; return the admission document."""
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    base = Path(base_dir or ROOT).resolve()
    cache = Path(cache_dir or (base / '.directed-irq-matrix-cache'))
    rows = []
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            execution_validation_scope():
        for adapter in config['cpu_adapters']:
            for target in config['target_protocols']:
                row = _evaluate_one(adapter, target, base_dir=base, cache_dir=cache)
                row['expectation'] = _expectation(adapter, target, row)
                row['combination'] = 'cross-protocol:' + adapter['id'] + ':' + target['id']
                rows.append(row)
    config_path = Path(config.get('_path', '')) if type(config.get('_path')) is str else None
    counts = {name: sum(1 for row in rows if row['status'] == name)
              for name in ('admitted', 'refused', 'error')}
    return {
        'schema_version': MATRIX_SCHEMA,
        'status': 'complete' if counts['error'] == 0 else 'error',
        'scope': SCOPE,
        **NO_NATIVE,
        'matrix_config': str(config_path) if config_path is not None else None,
        'matrix_config_sha256': (sha256(config_path.read_bytes()).hexdigest()
                                 if config_path is not None and config_path.is_file() else None),
        'cpu_adapters': [dict(id=a['id'], protocol=a['protocol'], profile=a['profile'],
                              expectation=a['expectation'])
                         for a in config['cpu_adapters']],
        'target_protocols': [dict(id=t['id'], protocol=t['protocol'], request=t['request'],
                                  source_port=t['source_port'],
                                  expected_kind=t['expected_kind'])
                             for t in config['target_protocols']],
        'rows': rows,
        'counts': counts,
        'dishonest': [row['combination'] for row in rows if not row['expectation']['honest']],
        'limitations': [
            'Admission is a preparation fact: it builds artifacts and sessions only.',
            'No session was prepared or launched; no DUT was simulated and no IRQ was taken.',
            'A refused combination names its missing contract; it is never silently skipped.',
            'The declared-output adapter carries transport only; cause and internal version stay unknown.',
        ],
    }


def load_matrix(path):
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if document.get('schema_version') != 'directed_irq_matrix.v1':
        raise ValueError('unsupported directed IRQ matrix schema')
    document['_path'] = str(Path(path).resolve())
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path,
                        default=ROOT / 'configs/scenarios/directed-irq-matrix.json')
    parser.add_argument('--output', type=Path, default=None,
                        help='write the admission document here instead of stdout')
    parser.add_argument('--cache', type=Path, default=None,
                        help='cache directory path for the sessions; nothing is built')
    args = parser.parse_args(argv)
    try:
        document = evaluate_matrix(load_matrix(args.config), cache_dir=args.cache)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'error', 'reason': str(error)}, sort_keys=True))
        return 2
    text = json.dumps(document, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.write_text(text, encoding='utf-8')
        print(json.dumps({'status': document['status'], 'output': str(args.output),
                          'counts': document['counts'],
                          'dishonest': document['dishonest']}, sort_keys=True))
    else:
        print(text, end='')
    return 0 if document['status'] == 'complete' and not document['dishonest'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
