"""Pure contract tests for the derived VexiiRiscv external-interrupt profile.

No RTL is built or simulated here. The tests pin the exact declared delta, the
authenticated baseline closure, the generated runtime/driver shape and the
session's IRQ step contract. Whether the core actually traps remains a real-RTL
acceptance item of the fixed-instance scenario.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_driver, render_local_harness, render_local_runtime,
    verify_local_source_lock)
from myfuzz.local_harness.vexii_axi_fields import (SHAPES, STEP_MAXIMA, STEP_PORTS,
                                                   IRQ_STEP_MAXIMA)
from myfuzz.local_harness.vexii_axi_session import (GeneratedReducedAxiCpuSession,
    GeneratedReducedAxiIrqCpuSession)
from myfuzz.local_harness.vexii_irq_contract import (ENDPOINT, EXTERNAL, ROLE,
    irq_profile, validate_irq_profile)
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService

ROOT = Path(__file__).resolve().parents[2]
BASELINE = 'configs/cpus/vexiiriscv/component_profile.json'
DERIVED = 'configs/cpus/vexiiriscv_irq/component_profile.json'
BOOT = 0x80000000


def baseline_document():
    return json.loads((ROOT / BASELINE).read_text())


def derived_document():
    return json.loads((ROOT / DERIVED).read_text())


def artifact(profile_path=DERIVED):
    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile_path,
        instance_id='cpu', reset_assert_ticks=12, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)


def test_derived_profile_is_the_exact_declared_baseline_delta():
    baseline = baseline_document()
    derived = derived_document()
    assert derived == irq_profile(baseline)
    assert derived['component_id'] == 'vexiiriscv_irq'
    assert derived['source'] == baseline['source']
    assert derived['capabilities'] == baseline['capabilities']
    assert [row['port'] for row in derived['port_actions']] == [
        'PrivilegedPlugin_logic_rdtime',
        'PrivilegedPlugin_logic_harts_0_int_m_timer',
        'PrivilegedPlugin_logic_harts_0_int_m_software']
    entry = [row for row in derived['endpoints'] if row['endpoint_id'] == ENDPOINT]
    assert len(entry) == 1 and entry[0]['function'] == 'interrupt_entry'
    assert entry[0]['fields'] == [{'role': ROLE, 'aliases': [EXTERNAL],
                                   'direction': 'input', 'width': 1}]
    assert derived['cpu']['irq_entry_endpoint'] == ENDPOINT
    assert derived['cpu']['irq_entry_role'] == ROLE
    assert derived['cpu']['irq_entry_polarity'] == 'active_high'
    assert derived['cpu']['irq_semantics'] == 'machine_external'
    # The baseline itself still pins the same physical pin to zero.
    actions = {row['port']: row for row in baseline['port_actions']}
    assert actions[EXTERNAL]['action'] == 'constant'
    assert actions[EXTERNAL]['value'] == 0
    assert baseline['cpu'].get('irq_entry_endpoint') is None
    assert validate_irq_profile(derived, baseline)['physical_port'] == EXTERNAL


@pytest.mark.parametrize('mutation', [
    're-add-constant-action',
    'drop-endpoint',
    'change-role',
    'add-field-width',
    'change-polarity',
    'change-semantics',
    'change-component-id',
])
def test_any_other_derived_document_is_refused(mutation):
    baseline = baseline_document()
    derived = derived_document()
    if mutation == 're-add-constant-action':
        derived['port_actions'].append({'port': EXTERNAL, 'action': 'constant',
                                        'value': 0, 'reason': 're-pinned'})
    elif mutation == 'drop-endpoint':
        derived['endpoints'] = derived['endpoints'][:-1]
    elif mutation == 'change-role':
        derived['endpoints'][-1]['fields'][0]['role'] = 'machine_timer'
    elif mutation == 'add-field-width':
        derived['endpoints'][-1]['fields'][0]['width'] = 2
    elif mutation == 'change-polarity':
        derived['cpu']['irq_entry_polarity'] = 'active_low'
    elif mutation == 'change-semantics':
        derived['cpu']['irq_semantics'] = 'machine_timer'
    else:
        derived['component_id'] = 'vexiiriscv'
    with pytest.raises(ValueError, match='exact-declared-baseline-delta'):
        validate_irq_profile(derived, baseline)


def test_derived_profile_cannot_come_from_the_derived_baseline():
    derived = derived_document()
    with pytest.raises(ValueError):
        irq_profile(derived)


def test_derived_source_contract_reauthenticates_the_baseline_closure():
    expected = json.loads((ROOT / 'configs/cpus/vexiiriscv/closure.json').read_text())['profile_sha256']
    baseline_profile = load_component_profile(baseline_document())
    baseline_facts = verify_local_source_lock(baseline_profile, base_dir=ROOT)
    derived_profile = load_component_profile(derived_document())
    facts = verify_local_source_lock(derived_profile, base_dir=ROOT)
    assert facts['source_status'] == 'source_verified'
    assert facts['elaboration_status'] == 'elaboration_verified'
    assert facts['closure_sha256'] == baseline_facts['closure_sha256']
    assert facts['derived_profile']['physical_port'] == EXTERNAL
    assert facts['baseline_profile_sha256'] == expected
    assert derived_profile.source.revision == baseline_profile.source.revision
    assert derived_profile.source.files == baseline_profile.source.files


def test_derived_runtime_and_driver_expose_exactly_one_irq_input():
    a = artifact()
    document = a.runtime_document
    assert document['kind'] == 'reduced_dual_axi_irq_cpu'
    assert len(a.plan.facts.ports) == 48
    assert len(document['backend_ports']) == 42
    exports = document['physical_exports']
    assert len(exports) == 1
    row = exports[0]
    assert (row['physical_port'], row['direction'], row['width']) == (EXTERNAL, 'input', 1)
    assert (row['endpoint_id'], row['role']) == (ENDPOINT, ROLE)
    # The real driver assigns the IRQ pin before evaluating the edge.
    assert document['driver_field_map'] == {'irq_external': row['runtime_name']}
    assert f'dut.{row["runtime_name"]} = command.fields[0];' in a.cpp_text
    assert 'STEP_REDUCED_AXI_IRQ' in a.cpp_text
    assert '"STEP_REDUCED_AXI"' not in a.cpp_text
    assert document['boot_contract']['configured_boot_base'] == BOOT
    assert IRQ_STEP_MAXIMA == (1,) + STEP_MAXIMA
    assert len(IRQ_STEP_MAXIMA) == len(STEP_PORTS) + 1


def test_baseline_artifact_stays_irq_free():
    a = artifact(BASELINE)
    document = a.runtime_document
    assert document['kind'] == 'reduced_dual_axi_cpu'
    assert document['physical_exports'] == []
    assert document['driver_field_map'] == {}
    assert 'STEP_REDUCED_AXI_IRQ' not in a.cpp_text


def fake_irq_cpu():
    cpu = object.__new__(GeneratedReducedAxiIrqCpuSession)
    cpu.memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 4096),),
                                  initialization_seed=0, max_initialized_bytes=4096)
    cpu.service = MemoryService(cpu.memory, TransactionLedger())
    cpu._execution = 'unit-test-vexii-irq'
    cpu._case_id, cpu.source_component, cpu.reset_epoch = 'case', 'cpu', 0
    cpu.read_beats = cpu.write_beats = cpu.write_responses = 0
    cpu.local_ticks = 0
    cpu.irq_edges = []
    cpu.irq_level = 0
    cpu._clear()
    cpu.irq_edges = []
    calls = []
    tick = [0]

    def command(operation, fields):
        calls.append((operation, fields))
        tick[0] += 1
        row = {p + '_' + role: 0 for p, shape in SHAPES.items() for role in shape}
        row.update(zip(STEP_PORTS, fields[1:]))
        return SimpleNamespace(status='ok', new_ticks=1, payload={
            'kind': cpu.artifact_kind, 'pre_backend': row,
            'samples': [{'local_tick': tick[0], 'pre': {'backend': row},
                         'post': {'backend': copy.deepcopy(row)}}],
            'observations': {'physical': {}}})

    cpu.command = command
    return cpu, calls


def test_irq_session_drives_the_pin_first_and_rejects_other_inputs():
    cpu, calls = fake_irq_cpu()
    cpu.step_local({'irq': 1})
    assert len(calls) == 1
    operation, fields = calls[0]
    assert operation == 'STEP_REDUCED_AXI_IRQ'
    assert len(fields) == len(IRQ_STEP_MAXIMA) == 18
    assert fields[0] == 1
    assert cpu.irq_level == 1 and cpu.irq_edges == [{'local_tick': 0, 'level': 1}]
    cpu.step_local({'irq': 0})
    assert calls[0] == ('STEP_REDUCED_AXI_IRQ', fields)
    assert calls[1][1][0] == 0
    assert [row['level'] for row in cpu.irq_edges] == [1, 0]
    for bad in ({}, {'irq': 2}, {'irq': True}, {'irq': '1'}, {'other': 0}):
        with pytest.raises(ValueError):
            cpu.step_local(bad)
    assert len(calls) == 2


def test_irq_session_clear_keeps_edges_initialised():
    cpu, _calls = fake_irq_cpu()
    cpu.step_local({'irq': 1})
    cpu._clear()
    assert cpu.irq_level == 0 and cpu.irq_edges == []
    # The base constructor calls _clear before this subclass allocates
    # irq_edges; that first call must not depend on creation order.
    fresh = object.__new__(GeneratedReducedAxiIrqCpuSession)
    fresh.source_component = 'cpu'
    GeneratedReducedAxiIrqCpuSession._clear(fresh)
    assert fresh.irq_level == 0 and not hasattr(fresh, 'irq_edges')
