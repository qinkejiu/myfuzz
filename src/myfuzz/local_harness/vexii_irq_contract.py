"""Opt-in derived VexiiRiscv profile that exposes the real machine-external IRQ.

The pinned generated RTL has one physical external-interrupt input,
``PrivilegedPlugin_logic_harts_0_int_m_external``. The baseline profile holds
that input at constant zero, so the baseline runtime cannot take an external
interrupt at all. This module derives a second profile from the authenticated
baseline instead of editing it: the derived document is validated as an *exact
declared delta* every time it is loaded, and the source closure is the same
generated RTL bytes.

Only the declaration changes:

* the baseline ``constant 0`` action for the external input is removed, so the
  physical pin becomes an ``interrupt_entry`` field owned by the harness;
* ``cpu.irq_entry_*`` names that entry as ``machine_external``/``active_high``;
* the remaining timer/software interrupt inputs and ``rdtime`` stay constant 0
  exactly as the baseline declares them.

Nothing here claims interrupt semantics for the RTL; the derived profile's
runtime artifact is only a source-admitted top. Whether the real core takes a
trap, runs an ISR and returns is measured by the fixed-instance scenario, not
by this contract.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from .vexii_source_contract import verify_vexii_source_contract

BASE_DIRECTORY = 'configs/cpus/vexiiriscv/'
DIRECTORY = 'configs/cpus/vexiiriscv_irq/'
BASELINE_COMPONENT = 'vexiiriscv'
COMPONENT = 'vexiiriscv_irq'
EXTERNAL = 'PrivilegedPlugin_logic_harts_0_int_m_external'
ENDPOINT = 'processor.interrupts'
ROLE = 'external'
CONSTANT_IRQ_PORTS = ('PrivilegedPlugin_logic_harts_0_int_m_timer',
                      'PrivilegedPlugin_logic_harts_0_int_m_software')
BASELINE_DESCRIPTION = (
    'Pinned generated cacheless RV32 VexiiRiscv, reduced single-beat AXI fetch '
    'AR/R and LSU AW/W/B/AR/R. Runtime acceptance tracked independently. No '
    'LEN/BURST/LOCK/QOS pins.')
DERIVED_DESCRIPTION = (
    'Opt-in derived profile of the pinned generated VexiiRiscv: the real '
    'machine-external interrupt input is an environment-owned interrupt entry '
    'instead of constant zero. Same generated RTL and reduced single-beat AXI4 '
    'contract; timer/software interrupt inputs and rdtime remain constant zero. '
    'Interrupt behaviour requires measured runtime acceptance.')


def irq_profile(baseline: Mapping) -> dict:
    """Return the one declared derived profile of an authenticated baseline."""
    if not isinstance(baseline, Mapping):
        raise ValueError('vexii-irq-baseline-document')
    result = deepcopy(dict(baseline))
    if (result.get('component_id') != BASELINE_COMPONENT
            or result.get('top_module', result.get('source', {}).get('top_module'))
            != 'VexiiRiscv'):
        raise ValueError('vexii-irq-baseline-identity')
    result['component_id'] = COMPONENT
    result['description'] = DERIVED_DESCRIPTION
    actions = [row for row in result.get('port_actions', ())
               if row.get('port') != EXTERNAL]
    if len(actions) != len(result.get('port_actions', ())) - 1:
        raise ValueError('vexii-irq-baseline-external-action')
    result['port_actions'] = actions
    result['endpoints'] = [*result.get('endpoints', ()),
        {'endpoint_id': ENDPOINT, 'function': 'interrupt_entry',
         'fields': [{'role': ROLE, 'aliases': [EXTERNAL],
                     'direction': 'input', 'width': 1}]}]
    result['cpu'] = {**result['cpu'],
        'irq_entry_endpoint': ENDPOINT, 'irq_entry_role': ROLE,
        'irq_entry_polarity': 'active_high',
        'irq_semantics': 'machine_external'}
    result['evidence'] = {**result.get('evidence', {}),
        'derived_profile': {
            'baseline_component_id': BASELINE_COMPONENT,
            'delta': ['remove-constant-external-interrupt-input',
                      'add-interrupt-entry-endpoint',
                      'declare-machine-external-irq-entry'],
            'unmeasured': [
                'The derived profile is a declaration only. Trap entry, ISR '
                'execution, mret return and IRQ deassertion remain runtime '
                'acceptance items of the fixed-instance scenario.']}}
    return result


def validate_irq_profile(document, baseline) -> dict:
    """Refuse anything except the exact declared baseline delta."""
    if not isinstance(document, Mapping) or not isinstance(baseline, Mapping):
        raise ValueError('vexii-irq-profile-document')
    expected = irq_profile(baseline)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'),
                                         ensure_ascii=False)
    if canonical(document) != canonical(expected):
        raise ValueError('vexii-irq-profile-must-be-exact-declared-baseline-delta')
    actions = {row.get('port'): row for row in baseline.get('port_actions', ())}
    for name in (*CONSTANT_IRQ_PORTS, 'PrivilegedPlugin_logic_rdtime'):
        if (actions.get(name, {}).get('action') != 'constant'
                or actions[name].get('value') != 0):
            raise ValueError('vexii-irq-baseline-constant-contract-changed:' + name)
    if actions.get(EXTERNAL, {}).get('action') != 'constant' or actions[EXTERNAL].get('value') != 0:
        raise ValueError('vexii-irq-baseline-external-constant-contract-changed')
    baseline_endpoints = [row.get('endpoint_id') for row in baseline.get('endpoints', ())]
    if baseline_endpoints != ['processor.memory.i', 'processor.memory.d']:
        raise ValueError('vexii-irq-baseline-endpoint-contract-changed')
    if baseline.get('cpu', {}).get('irq_entry_endpoint') is not None:
        raise ValueError('vexii-irq-baseline-already-declares-an-entry')
    return {'schema_version': 'vexii_irq_profile_delta.v1',
            'component_id': COMPONENT, 'baseline_component_id': BASELINE_COMPONENT,
            'physical_port': EXTERNAL, 'endpoint_id': ENDPOINT, 'role': ROLE,
            'polarity': 'active_high', 'semantics': 'machine_external',
            'constant_ports': list(CONSTANT_IRQ_PORTS)}


def _read(root: Path, name: str) -> bytes:
    path = root / name
    if path.is_symlink() or path.resolve() != path or not path.is_file():
        raise ValueError('vexii-irq-source-path:' + name)
    return path.read_bytes()


def verify_vexii_irq_source_contract(profile, *, base_dir: Path) -> dict:
    """Authenticate the baseline closure and this exact derived declaration."""
    root = Path(base_dir).resolve()
    baseline_raw = _read(root, BASE_DIRECTORY + 'component_profile.json')
    baseline_document = json.loads(baseline_raw)
    baseline_profile = load_component_profile(baseline_document)
    baseline_facts = verify_vexii_source_contract(baseline_profile, base_dir=base_dir)
    derived_raw = _read(root, DIRECTORY + 'component_profile.json')
    document = json.loads(derived_raw)
    delta = validate_irq_profile(document, baseline_document)
    if load_component_profile(document) != profile:
        raise ValueError('vexii-irq-profile-object-mismatch')
    if (profile.source.revision != baseline_profile.source.revision
            or profile.source.files != baseline_profile.source.files
            or profile.source.source_root != baseline_profile.source.source_root):
        raise ValueError('vexii-irq-source-selection-must-equal-baseline')
    return {
        'schema_version': 'local_source_lock_verification.v1',
        'source_status': 'source_verified',
        'elaboration_status': 'elaboration_verified',
        'profile_union_revision': profile.source.revision,
        'closure_sha256': baseline_facts['closure_sha256'],
        'lock_sha256': baseline_facts['lock_sha256'],
        'derived_profile': delta,
        'baseline_profile_sha256': hashlib.sha256(baseline_raw).hexdigest(),
        'derived_profile_sha256': hashlib.sha256(derived_raw).hexdigest(),
        'closure_record': {'id': profile.component_id, 'elaboration': {
            'evidence': BASE_DIRECTORY + 'closure.json',
            'evidence_sha256': baseline_facts['closure_sha256']}},
    }
