"""Real CV32E40P native IRQ receipts: real ack/id/entry-PC, never RVFI intr.

The local top assigns only rvfi valid/order/insn/pc_rdata, so acceptance must
come from the controller's real pre-edge decision and its real ack/id outputs.
"""
import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from tests.local_harness.test_cpu_session import NAMES, Target

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/cpus/cv32e40p_rvfi_local/component_profile.json'
BASE_PROFILE = 'configs/cpus/cv32e40p/component_profile.json'
ENVELOPE = {'kind', 'schema_version', 'component', 'source_component', 'execution_id',
            'reset_epoch', 'source_epoch', 'tick'}
LEGACY_SAMPLE_FIELDS = {'local_tick', 'phase', 'command_scope', 'receipt_id',
    'receipt_ticks', 'expected_input', 'actual_pre_input', 'actual_post_input',
    'input_context', 'observation_contract', 'notification_pre', 'notification_post',
    'irq_serial_observation', 'actual_post_ref', 'irq_masked_pre', 'irq_taken_pre'}


def _profile(path=PROFILE):
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / path)


@lru_cache(maxsize=1)
def _e40_artifact():
    from myfuzz.local_harness import (render_local_harness, render_local_runtime,
        verify_local_source_lock)
    from tests.local_harness.test_renderer import real_plan
    plan = real_plan(PROFILE, 'processor')
    return render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)


def _contract():
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import cv32e40p_irq_receipt_contract
    return cv32e40p_irq_receipt_contract()


def _cpu(artifact=None, **kwargs):
    artifact = artifact if artifact is not None else _e40_artifact()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
        initialization_seed=3, max_initialized_bytes=0x30000)
    cpu = GeneratedCve2Session(artifact, base_dir=ROOT, cache_dir=Path('/tmp/e40-irq-unused'),
        memory=memory, router=DataflowRouter((DeviceWindow('target', 0x40000000, 0x1000, Target()),)),
        native_irq_receipts=True, **kwargs)
    cpu._case_id = 'stream'
    cpu._execution = 'a' * 32
    return cpu


def _physical(cpu, probes, retire=False):
    physical = {row['runtime_name']: ('0' * row['hex_digits'] if row['width'] > 64 else 0)
                for row in cpu._artifact_document['physical_exports']}
    physical.update({'probe_' + name: value for name, value in probes.items()})
    if retire:
        names = {row['physical_port']: row['runtime_name']
                 for row in cpu._artifact_document['physical_exports']}
        physical.update({names['rvfi_valid']: 1, names['rvfi_order']: 1,
                         names['rvfi_insn']: 0x00000013, names['rvfi_pc_rdata']: 0x10000})
    return physical


def _receipt(cpu, values, *, probes=None, retire=False, post_extra=None):
    physical = _physical(cpu, probes or {}, retire=retire)
    physical[cpu._irq_runtime_name] = values[0]
    post = deepcopy(physical)
    post.update(post_extra or {})
    pre = dict.fromkeys(NAMES, 0)
    pre.update(zip(('i_req_ready', 'i_rsp_valid', 'i_rsp_rdata', 'i_rsp_error',
                    'd_req_ready', 'd_rsp_valid', 'd_rsp_rdata', 'd_rsp_error'), values[1:]))
    tick = cpu.local_ticks - cpu._tick_base + 1
    sequence = cpu._sequence + 1
    payload = dict(kind='obi_cpu',
        samples=[dict(local_tick=tick, pre={'backend': pre, 'physical': physical},
                      post={'backend': pre, 'physical': post})],
        pre_backend=pre, observations={'backend': pre, 'physical': post}, rdata=0, error=0)
    receipt = DriverReceipt('result', cpu._execution, sequence, tick - 1, tick, 1, payload)
    cpu._sequence = sequence
    cpu.local_ticks = cpu._tick_base + tick
    return receipt


def _step(cpu, **probes):
    retire = probes.pop('retire', False)
    with patch.object(cpu, 'command',
            side_effect=lambda op, values: _receipt(cpu, values, probes=probes, retire=retire)):
        return cpu.step_local({'irq': 1})


def _event(cpu, kind):
    return next(event for event in cpu.cpu_events if event['kind'] == kind)


def test_real_source_contract_returns_the_identity_hashed_RVFI_closure():
    """The IRQ verifier must return the artifact's own source_verification.

    ``cpu.source_verification_sha256`` is the canonical hash of this document,
    so it may only ever be the pinned RVFI closure; the IRQ scope facts live in
    the contract, never in the hashed document.
    """
    import hashlib
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
        verify_cv32e40p_irq_source_contract)
    from myfuzz.local_harness.cv32e40p_rvfi_contract import (
        verify_cv32e40p_rvfi_source_contract)
    profile = _profile()
    verified = verify_cv32e40p_irq_source_contract(profile, base_dir=ROOT)
    closure = verify_cv32e40p_rvfi_source_contract(profile, base_dir=ROOT)
    assert verified == closure
    assert (verified['source_status'], verified['elaboration_status']) == (
        'source_verified', 'elaboration_verified')
    assert verified['observation_fields'] == {'rvfi_valid': 1, 'rvfi_order': 64,
                                              'rvfi_insn': 32, 'rvfi_pc_rdata': 32}
    assert verified['irq_source_authority'] is False and verified['F6_authority'] is False
    artifact = _e40_artifact()
    def digest(document):
        return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':'),
                                         allow_nan=False).encode()).hexdigest()
    assert digest(verified) == digest(artifact.runtime_document['source_verification'])
    contract = _contract()
    assert contract['irq_ports'] == {
        'irq_i': dict(direction='input', width=32, line_offset=11),
        'irq_ack_o': dict(direction='output', width=1),
        'irq_id_o': dict(direction='output', width=5)}
    assert contract['irq_authority_scope'].startswith('native_pre_edge_external_cause_decision')
    assert contract['decision_probe_widths'] == {
        'irq_masked_pre': 1, 'irq_taken_pre': 1, 'irq_ack_pre': 1, 'irq_id_pre': 5,
        'irq_entry_pc': 32, 'irq_redirect_pre': 1, 'irq_redirect_cause': 5}


def test_closed_contract_declares_only_real_probes_and_no_serial_token():
    contract = _contract()
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
        validate_cv32e40p_irq_receipt_contract)
    validate_cv32e40p_irq_receipt_contract(contract)
    assert contract['schema_version'] == 'cv32e40p_native_irq_receipts.v1'
    assert contract['profile_id'] == 'cv32e40p_rvfi_local'
    assert (contract['input_port'], contract['input_width'], contract['input_bit_offset']) == (
        'irq_i', 1, 11)
    assert (contract['sampling'], contract['wire_schema_version']) == (
        'pre_post_rising', 'local_driver.v1')
    assert set(contract['decision_probes']) == {'irq_masked_pre', 'irq_taken_pre'}
    taken = contract['decision_probes']['irq_taken_pre']
    for token in ('id_stage_i.controller_i.pc_set_o', 'csr_save_cause_o',
                  'cv32e40p_pkg::EXC_PC_IRQ', "exc_cause_o == 5'd11"):
        assert token in taken
    masked = contract['decision_probes']['irq_masked_pre']
    assert 'cs_registers_i.mie_q[11]' in masked and 'mstatus_q.mie' in masked
    probes = {**contract['decision_probes'], **contract['decision_probes_all']}
    assert set(probes) == set(contract['decision_probe_widths'])
    assert probes['irq_ack_pre'].endswith('controller_i.irq_ack_o')
    assert probes['irq_id_pre'].endswith('controller_i.irq_id_o')
    assert probes['irq_entry_pc'].endswith('if_stage_i.exc_pc')
    assert 'pc_set_o' in probes['irq_redirect_pre'] and 'EXC_PC_DBE' in probes['irq_redirect_pre']
    assert probes['irq_redirect_cause'].endswith('controller_i.exc_cause_o')
    assert contract['decision_acceptance'] == {'ack_probe': 'irq_ack_pre',
        'id_probe': 'irq_id_pre', 'source_id': 11, 'id_width': 5,
        'entry_pc_probe': 'irq_entry_pc'}
    assert contract['redirect_probes'] == {'taken': 'irq_redirect_pre',
                                           'cause': 'irq_redirect_cause'}
    assert contract['notification_widths'] == {'rvfi_valid': 1, 'irq_ack_o': 1,
                                               'irq_id_o': 5}
    assert 'pre_edge' in contract['notification_semantics']
    assert 'rvfi_intr' in contract['notification_semantics']
    assert contract['retirement_authority'] == 'pc_insn_order_only'
    assert contract['retirement_fields'] == ['valid', 'order', 'insn', 'pc_rdata']
    assert set(contract['unobserved_retirement_fields']) == {'intr', 'pc_wdata', 'trap',
        'halt', 'mode', 'mem_addr', 'mem_rdata', 'mem_wdata', 'mem_rmask', 'mem_wmask'}
    assert contract['retirement_diversion_fields'] == []
    assert contract['retirement_diversion_scope'] == 'unobservable'
    assert 'serial_observation' not in contract
    assert contract['retirement_receipt']['schema_version'] == 'cpu_retire.v2'
    assert contract['retirement_receipt']['rvfi_fields'] == 4
    assert contract['startup_reset_receipt']['source'] == 'authenticated_startup_ready'


def test_declared_source_pins_match_the_real_base_profile_revision():
    contract = _contract()
    base = json.loads((ROOT / BASE_PROFILE).read_text())
    assert contract['source']['root'] == 'external_designs/cv32e40p'
    assert contract['source']['revision'] == base['source']['revision']
    assert contract['source']['revision'].startswith('git:')
    findings = contract['source']['sha256']
    assert 'rtl/cv32e40p_controller.sv' in findings and 'rtl/include/cv32e40p_pkg.sv' in findings
    for name, digest in findings.items():
        path = ROOT / contract['source']['root'] / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


def test_other_profiles_and_contracts_cannot_claim_the_E40_adapter():
    from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_receipt_contract
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
        validate_cv32e40p_irq_receipt_contract, verify_cv32e40p_irq_source_contract)
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract_for_profile, validate_native_irq_receipt_contract)
    assert native_irq_receipt_contract_for_profile(_profile()) == _contract()
    assert native_irq_receipt_contract_for_profile(
        _profile('configs/cpus/cv32e20/component_profile.json')) == cv32e20_irq_receipt_contract()
    for path in ('configs/cpus/cv32e20/component_profile.json', BASE_PROFILE,
                 'configs/cpus/ibex_rvfi_local/component_profile.json'):
        with pytest.raises(ValueError):
            verify_cv32e40p_irq_source_contract(_profile(path), base_dir=ROOT)
    for path in (BASE_PROFILE, 'configs/cpus/ibex/component_profile.json'):
        with pytest.raises(ValueError):
            native_irq_receipt_contract_for_profile(_profile(path))
    for value in (cv32e20_irq_receipt_contract(), ibex_irq_receipt_contract(),
                  {'schema_version': 'cv32e40p_native_irq_receipts.v1'}):
        with pytest.raises(ValueError):
            validate_cv32e40p_irq_receipt_contract(value)
    validate_native_irq_receipt_contract(_contract())
    for value in ({'schema_version': 'cv32e40p_native_irq_receipts.v1'},
                  {'schema_version': 'cv32e40p_native_irq_receipts.v1', 'rvfi_intr': 1}):
        with pytest.raises(ValueError):
            validate_native_irq_receipt_contract(value)


def test_E40_contract_cannot_be_edited_into_an_RVFI_intr_claim():
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_notification_observed, native_irq_retirement_diverted,
        native_irq_retirement_diversion_fields, native_irq_serial_observation)
    contract = _contract()
    fabricated = deepcopy(contract)
    fabricated['notification_widths']['rvfi_intr'] = 1
    with pytest.raises(ValueError):
        from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
            validate_cv32e40p_irq_receipt_contract)
        validate_cv32e40p_irq_receipt_contract(fabricated)
    with pytest.raises(ValueError):
        native_irq_serial_observation(contract, sampling='pre_post_rising',
            decision_value=1, retirement_value=1, decision_phase='pre', retirement_phase='post')
    # Post-edge notification is physically impossible here; a fabricated True is
    # never returned even when an artifact lies about rvfi_intr.
    assert native_irq_notification_observed(contract,
        {'rvfi_valid': 1, 'rvfi_intr': 1, 'irq_ack_o': 1, 'irq_id_o': 11}) is False
    assert native_irq_retirement_diversion_fields(contract) == ()
    assert native_irq_retirement_diverted(contract, {}) is False
    assert native_irq_retirement_diverted(contract, {'rvfi_halt': 1}) is False


def test_actual_E40_render_exports_the_real_probes_verbatim():
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
        verify_cv32e40p_irq_receipt_artifact)
    artifact = _e40_artifact()
    assert artifact.runtime_document['kind'] == 'obi_cpu'
    runtime_name = verify_cv32e40p_irq_receipt_artifact(artifact, base_dir=ROOT)
    contract = _contract()
    exports = {row['physical_port']: row for row in artifact.runtime_document['physical_exports']}
    assert exports['irq_i']['runtime_name'] == runtime_name
    assert (exports['irq_i']['direction'], exports['irq_i']['width'],
            exports['irq_i']['bit_lo'], exports['irq_i']['bit_hi']) == ('input', 1, 11, 11)
    assert (exports['irq_ack_o']['direction'], exports['irq_ack_o']['width']) == ('output', 1)
    assert (exports['irq_id_o']['direction'], exports['irq_id_o']['width']) == ('output', 5)
    for name, expression in {**contract['decision_probes'],
                             **contract['decision_probes_all']}.items():
        assert f'assign probe_{name} = {expression};' in artifact.runtime_sv
        row = exports[name]
        assert (row['direction'], row['width'], row['bit_lo']) == (
            'output', contract['decision_probe_widths'][name], 0)
    for name in ('rvfi_intr', 'rvfi_pc_wdata', 'rvfi_trap', 'rvfi_mode', 'rvfi_halt'):
        assert name not in exports
        assert f'assign {name}' not in artifact.runtime_sv
    assert 'assign rvfi_pc_wdata' not in artifact.runtime_sv


def test_artifact_claiming_fabricated_RVFI_fields_or_probes_is_refused():
    from myfuzz.local_harness.cv32e40p_irq_receipt_contract import (
        verify_cv32e40p_irq_receipt_artifact)
    artifact = _e40_artifact()
    fake = deepcopy(artifact)
    fake.runtime_document['physical_exports'].append(
        dict(fake.runtime_document['physical_exports'][0], physical_port='rvfi_intr',
             runtime_name='rvfi_intr', width=1, bit_lo=0, bit_hi=0))
    with pytest.raises(ValueError, match='fabricated'):
        verify_cv32e40p_irq_receipt_artifact(fake, base_dir=ROOT)
    tampered = deepcopy(artifact)
    expected = ('assign probe_irq_taken_pre = '
                + _contract()['decision_probes']['irq_taken_pre'] + ';')
    assert expected in tampered.runtime_sv
    broken = tampered.runtime_sv.replace(expected, "assign probe_irq_taken_pre = 1'b1;")
    assert broken != tampered.runtime_sv
    tampered = replace(tampered, runtime_sv=broken,
        runtime_document={**tampered.runtime_document,
                          'runtime_sv_sha256': hashlib.sha256(broken.encode()).hexdigest()})
    with pytest.raises(ValueError, match='probe'):
        verify_cv32e40p_irq_receipt_artifact(tampered, base_dir=ROOT)
    with pytest.raises(ValueError):
        verify_cv32e40p_irq_receipt_artifact(
            replace(artifact, runtime_document={**artifact.runtime_document,
                                                'runtime_sv_sha256': '0' * 64}), base_dir=ROOT)


def test_generated_probes_elaborate_without_running_the_DUT(tmp_path):
    import shutil
    import subprocess
    if shutil.which('verilator') is None:
        pytest.skip('Verilator unavailable')
    artifact = _e40_artifact()
    wrapper = tmp_path / 'structural.sv'
    runtime = tmp_path / 'runtime.sv'
    wrapper.write_text(artifact.structural.wrapper_sv)
    runtime.write_text(artifact.runtime_sv)
    source = artifact.plan.profile.source_document
    source_root = ROOT / source['root']
    argv = ['verilator', '--lint-only', '-Wno-fatal', '--top-module',
            artifact.runtime_document['module_name']]
    argv += ['-I' + str(source_root / path) for path in source['include_roots']]
    argv += ['-D' + row['name'] + '=' + row['value']
             for row in source['elaboration'].get('defines', [])]
    argv += [str(source_root / path) for path in source['files']] + [
        str(ROOT / 'src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv'),
        str(wrapper), str(runtime)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr


def test_take_requires_and_records_the_real_pre_edge_acceptance():
    cpu = _cpu()
    _step(cpu, irq_masked_pre=0, irq_taken_pre=1, irq_ack_pre=1, irq_id_pre=11,
          irq_entry_pc=0x2c, irq_redirect_pre=0, irq_redirect_cause=0)
    assert [event['kind'] for event in cpu.cpu_events] == [
        'cpu_external_irq_sample', 'cpu_external_irq_taken']
    sample, taken = cpu.cpu_events
    assert sample['irq_taken_pre'] == 1 and sample['irq_ack_pre'] == 1
    assert sample['irq_id_pre'] == 11 and sample['irq_entry_pc'] == 0x2c
    assert taken['sample_ref'] == {'command_scope': sample['command_scope'],
                                   'local_tick': sample['local_tick']}
    assert taken['take_key'] == [cpu.source_component, 0, 1]
    assert (taken['irq_ack_pre'], taken['irq_id_pre'], taken['irq_entry_pc'],
            taken['accepted_source_id']) == (1, 11, 0x2c, 11)
    assert taken['observation_contract'] == _contract()
    json.dumps(cpu.cpu_events)


@pytest.mark.parametrize('probes', [
    {'irq_taken_pre': 1, 'irq_ack_pre': 0, 'irq_id_pre': 11, 'irq_entry_pc': 0x2c},
    {'irq_taken_pre': 1, 'irq_ack_pre': 1, 'irq_id_pre': 12, 'irq_entry_pc': 0x2c},
    {'irq_taken_pre': 1, 'irq_ack_pre': 1, 'irq_id_pre': 11, 'irq_entry_pc': 0x2a},
    {'irq_taken_pre': 1, 'irq_ack_pre': 1, 'irq_id_pre': 11, 'irq_entry_pc': 1 << 32},
])
def test_take_without_real_ack_id_or_aligned_entry_pc_fails_closed(probes):
    cpu = _cpu()
    with pytest.raises(ProtocolEnvironmentError):
        _step(cpu, irq_masked_pre=0, irq_redirect_pre=0, irq_redirect_cause=0, **probes)
    assert not cpu.cpu_events


def test_real_non_irq_redirect_emits_the_native_redirect_event():
    cpu = _cpu()
    _step(cpu, irq_masked_pre=1, irq_taken_pre=0, irq_ack_pre=0, irq_id_pre=0,
          irq_entry_pc=0, irq_redirect_pre=1, irq_redirect_cause=2)
    assert [event['kind'] for event in cpu.cpu_events] == [
        'cpu_external_irq_sample', 'cpu_native_exception_redirect']
    sample, redirect = cpu.cpu_events
    assert redirect['redirect_cause'] == 2
    assert redirect['local_tick'] == sample['local_tick']
    assert redirect['sample_ref'] == {'command_scope': sample['command_scope'],
                                      'local_tick': sample['local_tick']}
    assert redirect['irq_redirect_pre'] == 1 and redirect['irq_redirect_cause'] == 2
    taken_cpu = _cpu()
    _step(taken_cpu, irq_masked_pre=0, irq_taken_pre=1, irq_ack_pre=1, irq_id_pre=11,
          irq_entry_pc=0x2c, irq_redirect_pre=1, irq_redirect_cause=7)
    assert 'cpu_native_exception_redirect' not in [e['kind'] for e in taken_cpu.cpu_events]


def test_masked_or_unredirected_sample_emits_only_the_sample_event():
    cpu = _cpu()
    _step(cpu, irq_masked_pre=1, irq_taken_pre=0, irq_ack_pre=0, irq_id_pre=0,
          irq_entry_pc=0, irq_redirect_pre=0, irq_redirect_cause=0)
    assert [event['kind'] for event in cpu.cpu_events] == ['cpu_external_irq_sample']
    assert cpu.cpu_events[0]['notification_post'] == {'rvfi_valid': 0, 'irq_ack_o': 0,
                                                      'irq_id_o': 0}


def test_no_irq_serial_observation_or_post_notification_for_E40():
    cpu = _cpu()
    _step(cpu, irq_masked_pre=0, irq_taken_pre=1, irq_ack_pre=1, irq_id_pre=11,
          irq_entry_pc=0x2c, irq_redirect_pre=0, irq_redirect_cause=0, retire=True)
    kinds = [event['kind'] for event in cpu.cpu_events]
    assert 'cpu_irq_notification' not in kinds
    assert any(kind == 'cpu_retire' for kind in kinds)
    for event in cpu.cpu_events:
        assert 'irq_serial_observation' not in event
    retire = _event(cpu, 'cpu_retire')
    assert set(retire['observation']['physical']) == {'rvfi_valid', 'rvfi_order',
                                                      'rvfi_insn', 'rvfi_pc_rdata'}
    assert (retire['valid'], retire['order'], retire['insn']) == (1, 1, 0x13)


def test_ibex_event_shape_is_unchanged_by_the_third_contract():
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    artifact = _artifact('configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu')
    cpu = _cpu(artifact)
    names = {row['physical_port']: row['runtime_name']
             for row in cpu._artifact_document['physical_exports']}
    with patch.object(cpu, 'command', side_effect=lambda op, values: _receipt(cpu, values,
            probes={'irq_masked_pre': 0, 'irq_taken_pre': 1},
            post_extra={names['rvfi_ext_irq_valid']: 1})):
        cpu.step_local({'irq': 1})
    assert [event['kind'] for event in cpu.cpu_events] == [
        'cpu_external_irq_sample', 'cpu_external_irq_taken', 'cpu_irq_notification']
    sample, taken, notice = cpu.cpu_events
    assert set(sample) == ENVELOPE | LEGACY_SAMPLE_FIELDS
    assert set(taken) == ENVELOPE | LEGACY_SAMPLE_FIELDS | {'sample_ref', 'take_key'}
    assert sample['irq_serial_observation']['schema_version'] == 'ibex_irq_serial_observation.v1'
    assert sample['irq_serial_observation'] == taken['irq_serial_observation']
    assert notice['rvfi_ext_irq_valid'] == 1 and notice['phase'] == 'post'
    assert not any(event['kind'] == 'cpu_native_exception_redirect' for event in cpu.cpu_events)


def test_host_irq_value_is_the_declared_one_bit_port_local_slice():
    """The host drives the profile's one-bit slice, not the wide vector.

    ``input_bit_offset=11`` is the documentary DUT line; delivery stays the
    port-local 0/1 value of the one-bit host-facing port.
    """
    cpu = _cpu(irq_input_port='irq_i')
    assert _contract()['input_bit_offset'] == 11
    probes = dict(irq_masked_pre=0, irq_taken_pre=0, irq_ack_pre=0, irq_id_pre=0,
                  irq_entry_pc=0, irq_redirect_pre=0, irq_redirect_cause=0)
    for value in (0, 1):
        seen = {}
        def command(operation, values):
            seen['values'] = values
            return _receipt(cpu, values, probes=probes)
        with patch.object(cpu, 'command', side_effect=command):
            cpu.step_local({'irq_i': value})
        assert seen['values'][0] == value
        assert cpu.cpu_events[-1]['actual_pre_input'] == value
    with pytest.raises(ValueError, match='zero or one'):
        cpu.step_local({'irq_i': 2})


def test_raw_tick_stream_request_accepts_the_declared_cpu_bit_slice():
    """The wide-request raw mapping must accept a real one-bit DUT slice."""
    from myfuzz.local_harness import (plan_local_harness, render_local_harness,
        render_local_runtime, verify_local_source_lock)
    from myfuzz.local_harness.native_physical_observation import (
        native_physical_observation_mapping, verify_native_physical_observation)
    from myfuzz.local_harness.request import load_local_harness_request
    request = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path=PROFILE, instance_id='processor', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16,
        tuning={'raw_tick_stream': [{'sampling': 'pre_post'}]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    artifact = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    assert verify_native_physical_observation(artifact) is True
    mapping = native_physical_observation_mapping(plan, 'obi_cpu',
        artifact.runtime_document['physical_exports'], 'core')
    alias, = mapping['aliases']
    assert alias['port'] == 'irq' and alias['physical_port'] == 'irq_i'
    row, = [export for export in artifact.runtime_document['physical_exports']
            if export['physical_port'] == alias['physical_port']]
    assert (row['width'], row['bit_lo'], row['bit_hi']) == (1, 11, 11)
