"""Software-only D2/D3 onboarding checks for the registered PULP SPI row.

The native first/fresh gate is intentionally exercised elsewhere, after the
SPI hierarchy proof has received its independent review.  These tests only
generate declarations, compile D3 paths, and check an executor preflight
refusal; they do not build or start a native process.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p'
CLI = ROOT / 'scripts/auto_harness_test.py'
EXPECTED_SPI_SDI_FIXED_INPUTS = {
    ('spi.pins', f'sdi{lane}', 0) for lane in range(4)}


def _json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def _assert_spi_sdi_fixed_inputs(rows):
    assert len(rows) == 4
    assert {(row['endpoint_id'], row['role'], row['value'])
            for row in rows} == EXPECTED_SPI_SDI_FIXED_INPUTS


def _generate_spi_d2_d3(output: Path):
    """Use the real source generator and D3 compiler without runtime startup."""
    from myfuzz.local_harness.auto_harness_test import build_path_compile_request, load_composition
    from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
    from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
    from myfuzz.scenario.compiled_paths import compile_paths, load_path_compile_request
    from myfuzz.scenario.ownership import compile_ownership

    generated = output / 'generated'
    compose = load_compose(CONFIG / 'compose.json', base_dir=ROOT)
    generate_harness_set(compose, base_dir=ROOT, compose_base=CONFIG,
                         output_root=generated)
    composition = load_composition(CONFIG / 'compose.json', base_dir=ROOT)
    document, sidecars = build_path_compile_request(
        composition, wiring_path=generated / 'wiring_contract.json',
        ip_capabilities=[CONFIG / 'test_capability.json'])
    request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(request)
    artifacts = load_generated_artifacts(generated_root=generated, base_dir=ROOT)
    compiled_inputs = dict(request=request, compiled=compiled,
                           ownership=compile_ownership((), ()),
                           physical_port_map={})
    return generated, sidecars, artifacts, compiled_inputs


@pytest.fixture(scope='module')
def spi_d2_d3(tmp_path_factory):
    return _generate_spi_d2_d3(tmp_path_factory.mktemp('compiled-f4-spi'))


def test_spi_composition_compiles_one_spicmd_f4_storage_candidate(spi_d2_d3):
    from myfuzz.integration.compiled_storage_producer import select_storage_producer
    from myfuzz.local_harness.compiled_execution_projection import assess_compiled_f4_support

    generated, sidecars, artifacts, inputs = spi_d2_d3
    assert sidecars == [{'instance_id': 'peripheral',
        'profile': 'configs/peripherals/pulp_spi/local_component_profile.json',
        'test_capability': 'configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/test_capability.json',
        'source': 'declared-option'}]
    assert _json(CONFIG / 'compose.json')['devices'][0] == {
        'device_id': 'peripheral', 'instance_id': 'peripheral',
        'request': 'requests/peripheral.json', 'bus_endpoint': 'spi.bus',
        'base': 0x40001000, 'size': 4096}
    peripheral_request = _json(CONFIG / 'requests/peripheral.json')
    fixed_inputs = peripheral_request['tuning']['fixed_inputs']
    assert {(row['endpoint_id'], row['role'], row['value'])
            for row in fixed_inputs} == {
                ('spi.pins', f'sdi{lane}', 0) for lane in range(4)}
    assert peripheral_request['tuning']['endpoint_policies'] == [{
        'endpoint_id': 'spi.bus', 'template_id': 'target.apb3',
        'template_version': '1', 'variant_id': 'full-word',
        'max_outstanding': 1}]
    assert peripheral_request['tuning']['apb_storage_observations'] == [{
        'endpoint_id': 'spi.bus',
        'contract_id': 'pulp-apb-spi.spicmd.source.v1',
        'register': 'SPICMD'}]

    assert inputs['request'].cpu.instance_id == 'processor'
    assert inputs['request'].cpu.profile.component_id == 'cv32e40p'
    assert _json(CONFIG / 'requests/processor.json')['profile_path'] == \
        'configs/cpus/cv32e40p/component_profile.json'
    assert artifacts['peripheral'].runtime_document['kind'] == 'apb3_register_observe'
    observation = artifacts['peripheral'].runtime_document['storage_observation']
    assert observation['selection'] == {
        'endpoint_id': 'spi.bus',
        'contract_id': 'pulp-apb-spi.spicmd.source.v1',
        'register': 'SPICMD'}
    assert observation['source_contract']['register'] == {
        'name': 'SPICMD', 'canonical_offset': 8, 'width': 32,
        'reset_value': 0, 'read_mask': 0xffffffff,
        'write_mask': 0xffffffff}
    _assert_spi_sdi_fixed_inputs(
        artifacts['peripheral'].runtime_document['fixed_physical_inputs'])

    executable_f4 = [row for row in inputs['compiled']['paths']
                      if row['flow_id'] == 'F4'
                      and row['status'] == 'executable']
    assert len(executable_f4) == 1
    path = executable_f4[0]
    assert [(row['kind'], row['source_id']) for row in path['sources']] == [
        ('instruction_image', 'ram.image'),
        ('cpu_mmio_stream', 'peripheral.SPICMD.value.mmio')]
    register_access = path['sources'][1]['register_access']
    assert {key: register_access[key] for key in (
        'register', 'address', 'register_offset', 'width_bytes', 'operation',
        'allowed_byte_enables')} == {
            'register': 'SPICMD', 'address': 0x40001008,
            'register_offset': 8, 'width_bytes': 4, 'operation': 'write',
            'allowed_byte_enables': [15]}
    assert register_access['value_mask'] == 0xffffffff
    assert path['bound_inputs'] == [{
        'input_id': 'peripheral.spi.bus.register.SPICMD.value',
        'origin': 'bound', 'kind': 'ip_register_commit',
        'component': 'peripheral', 'endpoint_id': 'spi.bus',
        'basis': path['bound_inputs'][0]['basis']}]
    assert path['prerequisites'] == [{
        'kind': 'ip_register_version',
        'basis': path['prerequisites'][0]['basis'],
        'subject': {'component': 'peripheral', 'register': 'SPICMD',
                    'reset_epoch': 0}}]
    assert {row['expectation_id'] for row in path['assertions']} == {
        'protocol_checker.receipt_violations',
        'cross_component.declared_edge_hops',
        'cross_component.chain_certificate_hops'}

    binding = select_storage_producer(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    document = binding.document()
    assert binding.row == 'generic_apb_storage_abi'
    assert document['register']['name'] == 'SPICMD'
    assert document['register']['offset'] == 8
    assert document['register']['address'] == 0x40001008
    assert document['source']['contract_id'] == 'pulp-apb-spi.spicmd.source.v1'
    assert document['prerequisite']['expected']['subject'] == {
        'component': 'peripheral', 'register': 'SPICMD', 'reset_epoch': 0}
    assert document['candidate']['byte_length'] == 4
    assert document['candidate']['bit_length'] == 32
    assert document['candidate']['packed_bits'] == 32
    assert document['candidate']['external_pin_sources'] == []
    assert document['bound_input']['kind'] == 'ip_register_commit'
    assert document['producer']['session_construction'] == {
        'setup_writes': [], 'probe_offsets': [], 'dynamic_inputs': [],
        'bound_inputs': []}
    support = assess_compiled_f4_support(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    assert support['status'] == 'supported_requires_actual_startup'
    assert support['execution_supported'] == 1
    assert support['runtime_admitted'] is False
    assert support['producer_binding']['row'] == 'generic_apb_storage_abi'
    assert support['producer_binding']['register'] == document['register']
    assert support['producer_binding']['candidate']['external_pin_sources'] == []
    assert support['receipt_elements']['complete'] is True
    assert support['receipt_elements']['elements']['version_token']['present'] is True
    assert (generated / 'harness_set.json').is_file()


def test_spi_executor_cli_generates_d1_to_d3_without_starting_session(tmp_path):
    """The configured compiled executor can complete software-only stages."""
    output = tmp_path / 'software-only'
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    command = [sys.executable, str(CLI),
        '--cpu', 'configs/cpus/cv32e40p/component_profile.json',
        '--ip', 'configs/peripherals/pulp_spi/local_component_profile.json',
        '--ip-capability', str(CONFIG / 'test_capability.json'),
        '--compose', str(CONFIG / 'compose.json'), '--output', str(output),
        '--executor', 'compiled-f4-rfuzz', '--skip-session']
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            env=environment, timeout=120)
    assert result.returncode == 0, result.stderr[-4000:]
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1])
    assert payload['status'] == 'complete'
    assert payload['executor']['requested'] == 'compiled-f4-rfuzz'
    assert payload['stages']['declaration_review']['status'] == 'ok'
    assert payload['stages']['harness_set']['status'] == 'ok'
    assert payload['stages']['path_compilation']['status'] == 'ok'
    assert payload['stages']['session']['status'] == 'not_requested'
    assert _json(output / 'compiled_paths.v1.json')['counts']['executable'] >= 1
    compiled = _json(output / 'compiled_paths.v1.json')
    f4 = [row for row in compiled['paths']
          if row['flow_id'] == 'F4' and row['status'] == 'executable']
    assert len(f4) == 1
    assert f4[0]['sources'][1]['register_access']['address'] == 0x40001008
    assert _json(output / 'path_compile_request.json')['devices'][0][
        'test_capability'] == \
        'configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/test_capability.json'
    assert (output / 'generated' / 'harness_set.json').is_file()
    assert not (output / 'session').exists()
    assert not (output / 'fresh-verification.json').exists()


def test_spi_executor_cli_refuses_similar_cpu_override_before_d2(tmp_path):
    """Request identity remains CV32E40P while the CLI reviews CV32E20."""
    output = tmp_path / 'wrong-cpu'
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    command = [sys.executable, str(CLI),
        '--cpu', 'configs/cpus/cv32e20/component_profile.json',
        '--ip', 'configs/peripherals/pulp_spi/local_component_profile.json',
        '--ip-capability', str(CONFIG / 'test_capability.json'),
        '--compose', str(CONFIG / 'compose.json'), '--output', str(output),
        '--executor', 'compiled-f4-rfuzz']
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            env=environment, timeout=120)
    assert result.returncode != 0, result.stdout
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1])
    assert payload['status'] == 'refused'
    assert payload['executor']['requested'] == 'compiled-f4-rfuzz'
    assert payload['executor']['family_fallback'] is False
    refusal = next(row for row in payload['refusals']
                   if row['code'] == 'composition-profile-not-reviewed')
    assert refusal['pointer'] == '/cpu/request'
    assert refusal['detail']['profile'] == 'configs/cpus/cv32e40p/component_profile.json'
    assert not (output / 'generated' / 'harness_set.json').exists()
    assert not (output / 'compiled_paths.v1.json').exists()
    assert not (output / 'session').exists()
    assert not (output / 'fresh-verification.json').exists()


@pytest.mark.parametrize(('mutation', 'expected'), [
    ('source', 'apb-storage-source-identity-unsupported'),
    ('template', 'apb3-register-template-policy-required'),
])
def test_spi_d2_refuses_wrong_registered_source_or_apb_template(mutation,
                                                                 expected):
    from copy import deepcopy

    from myfuzz.local_harness import (load_local_harness_request,
        plan_local_harness, render_local_harness, render_local_runtime,
        verify_local_source_lock)

    document = _json(CONFIG / 'requests/peripheral.json')
    changed = deepcopy(document)
    if mutation == 'source':
        changed['tuning']['apb_storage_observations'][0].update(
            contract_id='pulp-apb-timer.ctrl0.source.v1',
            register='TIMER0_CTRL')
    else:
        changed['tuning']['endpoint_policies'][0]['variant_id'] = 'byte-enable'
    request = load_local_harness_request(changed)
    with pytest.raises(ValueError, match=expected):
        plan = plan_local_harness(request, base_dir=ROOT)
        harness = render_local_harness(plan)
        source_lock = verify_local_source_lock(plan.profile, base_dir=ROOT)
        render_local_runtime(plan, harness, source_lock, base_dir=ROOT)


def test_spi_sdi_generated_input_set_guard_detects_a_missing_lane(spi_d2_d3):
    _generated, _sidecars, artifacts, _inputs = spi_d2_d3
    rows = artifacts['peripheral'].runtime_document['fixed_physical_inputs']
    with pytest.raises(AssertionError):
        _assert_spi_sdi_fixed_inputs(rows[:-1])


def test_compiled_session_inputs_own_only_d2_fixed_inputs_and_d3_external_pins(
        spi_d2_d3, tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.local_harness.auto_harness_test import load_compiled_session_inputs
    from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership

    generated, _sidecars, artifacts, source_inputs = spi_d2_d3
    _loaded, inputs = load_compiled_session_inputs(
        generated_root=generated, base_dir=ROOT,
        request=source_inputs['request'], compiled=source_inputs['compiled'])
    ownership = inputs['ownership']
    document = ownership.document()
    fixed = [row for row in document['owners']
             if row['component_id'] == 'peripheral' and row['kind'] == 'fixed']
    assert {(row['port'], row['bit_offset'], row['width'], row['producer_ref'])
            for row in fixed} == {
                (f'spi.pins.sdi{lane}', 0, 1, 'profile_constant')
                for lane in range(4)}
    assert {inputs['physical_port_map'][('peripheral', f'spi.pins.sdi{lane}')]
            for lane in range(4)} == {f'spi_sdi{lane}' for lane in range(4)}

    path = next(row for row in source_inputs['compiled']['paths']
                if row['flow_id'] == 'F4' and row['status'] == 'executable')
    expected_external = {
        (row['component'], row['port'], row['bit_offset'], row['width'],
         'source', row['source_id'])
        for row in path['sources'] if row['kind'] == 'external_pin'}
    observed_external = {
        (row['component_id'], row['port'], row['bit_offset'], row['width'],
         row['kind'], row['producer_ref'])
        for row in document['owners'] if row['kind'] == 'source'}
    assert observed_external == expected_external

    target = GeneratedApb3RegisterSession(
        artifacts['peripheral'], base_dir=ROOT, cache_dir=tmp_path / 'cache')
    target.validate_scenario_ownership('peripheral', ownership)
    admission = admit_compiled_artifacts(artifacts=_loaded,
        request=source_inputs['request'], compiled=source_inputs['compiled'],
        ownership=ownership, physical_port_map=inputs['physical_port_map'])
    assert admission['status'] == 'compatible', admission['refusals']

    omitted_fields = tuple(
        InputField(row['component_id'], row['port'], row['width'])
        for row in document['fields']
        if not (row['component_id'] == 'peripheral'
                and row['port'] == 'spi.pins.sdi3'))
    omitted_owners = tuple(
        InputOwner(**row) for row in document['owners']
        if not (row['component_id'] == 'peripheral'
                and row['port'] == 'spi.pins.sdi3'))
    omitted = compile_ownership(omitted_fields, omitted_owners)
    with pytest.raises(ValueError, match='scenario ownership fields mismatch'):
        target.validate_scenario_ownership('peripheral', omitted)

    audit = _json(generated.parent / 'compiled_ownership.v1.json')
    assert audit['fixed_input_identity'] == [{
        'component_id': 'peripheral', 'input_name': f'spi.pins.sdi{lane}',
        'endpoint_id': 'spi.pins', 'role': f'sdi{lane}',
        'runtime_name': artifacts['peripheral'].runtime_document[
            'fixed_physical_inputs'][lane]['runtime_name'],
        'physical_port': f'spi_sdi{lane}',
        'width': 1, 'value': 0,
        'artifact_digest': artifacts['peripheral'].runtime_document[
            'artifact_digest'],
    } for lane in range(4)]


def test_compiled_session_inputs_keep_refusing_wiring_fixed_inputs(spi_d2_d3,
                                                                   tmp_path):
    from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
        load_compiled_session_inputs)

    generated, _sidecars, _artifacts, source_inputs = spi_d2_d3
    copied = tmp_path / 'generated'
    shutil.copytree(generated, copied)
    contract_path = copied / 'wiring_contract.json'
    contract = _json(contract_path)
    contract['fixed_inputs'] = [{'component_id': 'peripheral',
                                 'port': 'synthetic.constant', 'value': 0}]
    contract_path.write_text(json.dumps(contract), encoding='utf-8')
    with pytest.raises(AutoHarnessRefused) as refused:
        load_compiled_session_inputs(generated_root=copied, base_dir=ROOT,
            request=source_inputs['request'], compiled=source_inputs['compiled'])
    assert refused.value.code == 'compiled-rfuzz-fixed-input-unsupported'
    assert refused.value.pointer == '/wiring/fixed_inputs'


def test_compiled_session_inputs_refuse_typed_request_fixed_inputs_when_disk_is_empty(
        spi_d2_d3):
    from dataclasses import replace

    from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
        load_compiled_session_inputs)
    from myfuzz.scenario.compiled_paths import WiringFixedInput

    generated, _sidecars, _artifacts, source_inputs = spi_d2_d3
    request = source_inputs['request']
    fixed = WiringFixedInput('peripheral', 'synthetic.constant', 0, 1, 0,
                             'test-request')
    mutated_request = replace(request, wiring=replace(
        request.wiring, fixed_inputs=(fixed,)))
    assert not _json(generated / 'wiring_contract.json').get('fixed_inputs')
    with pytest.raises(AutoHarnessRefused) as refused:
        load_compiled_session_inputs(generated_root=generated, base_dir=ROOT,
            request=mutated_request, compiled=source_inputs['compiled'])
    assert refused.value.code == 'compiled-rfuzz-fixed-input-unsupported'
    assert refused.value.pointer == '/request/wiring/fixed_inputs'


def test_compiled_session_inputs_refuse_harness_set_inline_fixed_inputs_when_disk_is_empty(
        spi_d2_d3, tmp_path):
    from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
        load_compiled_session_inputs)

    generated, _sidecars, _artifacts, source_inputs = spi_d2_d3
    copied = tmp_path / 'generated'
    shutil.copytree(generated, copied)
    harness_path = copied / 'harness_set.json'
    harness = _json(harness_path)
    harness['wiring']['fixed_inputs'] = [{
        'component_instance': 'peripheral', 'port': 'synthetic.constant',
        'bit_offset': 0, 'width': 1, 'constant': 0, 'source': 'test-inline'}]
    harness_path.write_text(json.dumps(harness), encoding='utf-8')
    assert not _json(copied / 'wiring_contract.json').get('fixed_inputs')
    with pytest.raises(AutoHarnessRefused) as refused:
        load_compiled_session_inputs(generated_root=copied, base_dir=ROOT,
            request=source_inputs['request'], compiled=source_inputs['compiled'])
    assert refused.value.code == 'compiled-rfuzz-fixed-input-unsupported'
    assert refused.value.pointer == '/harness_set/wiring/fixed_inputs'


@pytest.mark.parametrize('surface', ['typed', 'typed-document', 'harness-inline'])
def test_compiled_session_inputs_refuse_malformed_fixed_input_declarations(
        spi_d2_d3, tmp_path, surface):
    from dataclasses import replace

    from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
        load_compiled_session_inputs)

    generated, _sidecars, _artifacts, source_inputs = spi_d2_d3
    request = source_inputs['request']
    expected_pointer = '/request/wiring/fixed_inputs'
    expected_code = 'compiled-rfuzz-wiring-fixed-inputs-invalid'
    if surface == 'typed':
        request = replace(request, wiring=replace(request.wiring,
                                                   fixed_inputs=None))
    elif surface == 'typed-document':
        request = replace(request, wiring=replace(request.wiring,
            document={'fixed_inputs': None}))
        expected_pointer = '/request/wiring/document/fixed_inputs'
    else:
        source_generated = generated
        generated = tmp_path / 'generated'
        shutil.copytree(source_generated, generated)
        harness_path = generated / 'harness_set.json'
        harness = _json(harness_path)
        harness['wiring']['fixed_inputs'] = {}
        harness_path.write_text(json.dumps(harness), encoding='utf-8')
        expected_pointer = '/harness_set/wiring/fixed_inputs'
        expected_code = 'compiled-rfuzz-harness-wiring-invalid'

    with pytest.raises(AutoHarnessRefused) as refused:
        load_compiled_session_inputs(generated_root=generated, base_dir=ROOT,
            request=request, compiled=source_inputs['compiled'])
    assert refused.value.code == expected_code
    assert refused.value.pointer == expected_pointer


def test_compiled_f4_admission_rejects_conflicting_composition_fixed_input(
        spi_d2_d3):
    from dataclasses import replace

    from myfuzz.integration.compiled_f4 import admit_f4
    from myfuzz.scenario.compiled_paths import WiringFixedInput, compile_paths

    _generated, _sidecars, artifacts, inputs = spi_d2_d3
    fixed = WiringFixedInput('peripheral', 'spi_sdi0', 0, 1, 1,
                             'test-conflict-with-profile-constant')
    request = replace(inputs['request'], wiring=replace(
        inputs['request'].wiring, fixed_inputs=(fixed,)))
    compiled = compile_paths(request)
    with pytest.raises(ValueError) as refused:
        admit_f4(artifacts=artifacts, compiled_inputs={**inputs,
            'request': request, 'compiled': compiled})
    assert refused.value.code == 'compiled-rfuzz-fixed-input-unsupported'
    assert refused.value.pointer == '/request/wiring/fixed_inputs'


@pytest.mark.parametrize(('shape', 'expected_code', 'expected_pointer'), [
    ('typed-nonempty', 'compiled-rfuzz-fixed-input-unsupported',
     '/request/wiring/fixed_inputs'),
    ('raw-nonempty', 'compiled-rfuzz-fixed-input-unsupported',
     '/request/wiring/document/fixed_inputs'),
    ('typed-malformed', 'compiled-rfuzz-wiring-fixed-inputs-invalid',
     '/request/wiring/fixed_inputs'),
    ('raw-fixed-malformed', 'compiled-rfuzz-wiring-fixed-inputs-invalid',
     '/request/wiring/document/fixed_inputs'),
    ('raw-document-malformed', 'compiled-rfuzz-wiring-fixed-inputs-invalid',
     '/request/wiring/document'),
])
def test_compiled_f4_admission_fails_closed_on_wiring_fixed_input_copies(
        spi_d2_d3, shape, expected_code, expected_pointer):
    from dataclasses import replace

    from myfuzz.integration.compiled_f4 import admit_f4
    from myfuzz.scenario.compiled_paths import WiringFixedInput, compile_paths

    _generated, _sidecars, artifacts, inputs = spi_d2_d3
    fixed = WiringFixedInput('peripheral', 'spi_sdi0', 0, 1, 1,
                             'test-fixed-input-copy')
    wiring = inputs['request'].wiring
    document = dict(wiring.document)
    if shape == 'typed-nonempty':
        wiring = replace(wiring, fixed_inputs=(fixed,))
    elif shape == 'raw-nonempty':
        document['fixed_inputs'] = [{
            'component_instance': 'peripheral', 'port': 'spi_sdi0',
            'bit_offset': 0, 'width': 1, 'constant': 1,
            'source': 'test-fixed-input-copy'}]
        wiring = replace(wiring, document=document)
    elif shape == 'typed-malformed':
        wiring = replace(wiring, fixed_inputs=None)
    elif shape == 'raw-fixed-malformed':
        document['fixed_inputs'] = None
        wiring = replace(wiring, document=document)
    else:
        wiring = replace(wiring, document=None)
    request = replace(inputs['request'], wiring=wiring)
    compiled = compile_paths(request)
    with pytest.raises(ValueError) as refused:
        admit_f4(artifacts=artifacts, compiled_inputs={**inputs,
            'request': request, 'compiled': compiled})
    assert refused.value.code == expected_code
    assert refused.value.pointer == expected_pointer


def test_generic_compiled_admission_keeps_fixed_input_semantics(
        spi_d2_d3):
    from dataclasses import replace

    from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
    from myfuzz.scenario.compiled_paths import WiringFixedInput, compile_paths

    _generated, _sidecars, artifacts, inputs = spi_d2_d3
    fixed = WiringFixedInput('peripheral', 'spi_sdi0', 0, 1, 1,
                             'non-f4-scope-control')
    wiring = replace(inputs['request'].wiring, fixed_inputs=(fixed,))
    request = replace(inputs['request'], wiring=wiring)
    compiled = compile_paths(request)
    assert any(path['flow_id'] == 'F4' and path['status'] == 'executable'
               for path in compiled['paths'])
    admission = admit_compiled_artifacts(artifacts=artifacts, request=request,
        compiled=compiled, ownership=inputs['ownership'],
        physical_port_map=inputs['physical_port_map'])
    assert admission['status'] == 'compatible', admission['refusals']


def test_prepare_compiled_execution_files_rejects_conflicting_composition_fixed_input(
        tmp_path):
    from myfuzz.integration.compiled_execution_files import (
        prepare_compiled_execution_files)

    config = tmp_path / 'config'
    requests = config / 'requests'
    requests.mkdir(parents=True)
    for name in ('processor.json', 'peripheral.json'):
        shutil.copy(CONFIG / 'requests' / name, requests / name)
    compose = _json(CONFIG / 'compose.json')
    compose['fixed_inputs'] = [{
        'component_instance': 'peripheral', 'port': 'spi_sdi0',
        'width': 1, 'constant': 1}]
    compose_path = config / 'compose.json'
    compose_path.write_text(json.dumps(compose), encoding='utf-8')
    supplement = {
        'schema_version': 'compiled_execution_file_supplement.v1',
        'request_supplements': {},
        'ownership': {'fields': [], 'owners': []},
        'physical_port_map': [],
    }
    supplement_path = tmp_path / 'supplement.json'
    supplement_path.write_text(json.dumps(supplement), encoding='utf-8')

    _artifacts, _inputs, support = prepare_compiled_execution_files(
        base_dir=ROOT, compose_path=compose_path,
        capability_paths=[CONFIG / 'test_capability.json'],
        supplement_path=supplement_path, generated_dir=tmp_path / 'generated')
    assert support['status'] == 'unsupported', support
    assert support['execution_supported'] == 0
    assert support['reason'].startswith(
        'compiled-rfuzz-fixed-input-unsupported at /request/wiring/fixed_inputs')


def test_compiled_f4_register_version_issuer_uses_selected_register():
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime

    class RecordingAuthority:
        def issue(self, *, register, reset_epoch):
            return dict(register=register, reset_epoch=reset_epoch)

    runtime = CompiledF4Runtime.__new__(CompiledF4Runtime)
    runtime.authority = RecordingAuthority()
    runtime.register_name = 'SPICMD'

    assert runtime._issue_register_version(reset_epoch=0) == {
        'register': 'SPICMD', 'reset_epoch': 0}


def test_compiled_f4_routes_each_version_issuance_through_selected_register():
    import ast
    import inspect

    from myfuzz.integration.compiled_f4 import CompiledF4Runtime

    tree = ast.parse(inspect.getsource(CompiledF4Runtime))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)]
    issue_calls = [node for node in calls if node.func.attr == 'issue']
    helper_calls = [node for node in calls
                    if node.func.attr == '_issue_register_version']

    # Every issuance site must go through the selected authority and pass the
    # selected register as a ``self`` attribute -- never a literal register
    # name.  The mixed F2+F4 runtime has two sites (the F2 pre-read and the F4
    # helper); the single-flow runtime had one.  Both must satisfy the same
    # property, so the check is per site rather than a call count.
    assert issue_calls
    for issue in issue_calls:
        assert isinstance(issue.func.value, ast.Attribute)
        assert issue.func.value.attr == 'authority'
        register = next(keyword.value for keyword in issue.keywords
                        if keyword.arg == 'register')
        assert isinstance(register, ast.Attribute)
        assert register.value.id == 'self'
        assert register.attr == 'register_name'
    assert len(helper_calls) == 4
