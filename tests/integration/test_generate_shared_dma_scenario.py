"""One CPU and one DMA request are enough to assemble the shared prototype."""
import json
import tempfile
from pathlib import Path

import pytest

from scripts.generate_shared_dma_scenario import generate_scenario
from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.local_harness.harness_set import load_compose

ROOT = Path(__file__).resolve().parents[2]
CPU = 'configs/scenarios/compiled-f6-ibex-wbdmac-storage/requests/cpu.json'
CV = 'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared/requests/cpu.json'
DMA = 'configs/scenarios/compiled-f6-ibex-wbdmac-storage/requests/dma.json'
ZIP = 'configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-shared/requests/dma.json'
DMA_CAP = 'configs/scenarios/compiled-f6-ibex-wbdmac-storage/dma.test_capability.json'
ZIP_CAP = 'configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-shared/dma.test_capability.json'
PROFILE_ONLY = 'configs/peripherals/profile_only_idle_i2c/component_profile.json'
PROFILE_CAP = 'configs/peripherals/profile_only_idle_i2c/test_capability.json'
PROFILE_CPU = 'configs/cpus/shared_profile_cpu/component_profile.json'
PROFILE_DMA = 'configs/peripherals/shared_profile_dma/component_profile.json'


@pytest.mark.parametrize('mode,control,master', [
    ('wishbone_dma_edge_v1', 'dma-full-word-no-select', 'dma-full-word-no-select'),
    ('wishbone_dma_selected_edge_v1', 'dma-selected', 'dma-selected'),
    ('wishbone_dma_control_selected_edge_v1', 'dma-selected', 'dma-full-word-no-select'),
    ('wishbone_dma_master_selected_edge_v1', 'dma-full-word-no-select', 'dma-selected'),
])
def test_dma_control_and_master_templates_are_independent(mode, control, master):
    from scripts.generate_shared_dma_scenario import _dma_variants
    assert _dma_variants({'local_runtime_variant': mode}) == (control, master)


def test_declared_irq_shared_slot_plan_uses_timer_behavior():
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        generate_scenario({'name': 'timer-shared-irq-plan', 'cpu_profile': PROFILE_CPU,
            'dma_profile': PROFILE_DMA,
            'declared_irq_behavior': 'configs/peripherals/pulp_timer/irq_behavior.json',
            'declared_irq_base': 0x40003000, 'declared_irq_plan_only': True},
            base_dir=ROOT, output=out)
        plan = json.loads((out / 'declared_irq_shared_slot_plan.json').read_text())
        assert plan['runtime_status'] == 'not_integrated'
        assert plan['source']['port'] == 'irq_o' and plan['source']['bit_offset'] == 0
        assert plan['irq_group_member'] == {'source_component': 'timer', 'source_port': 'irq_o',
            'mode': 'pulse', 'pulse_width_ticks': 16, 'source_bit_offset': 0,
            'source_adapter': 'declared-output.v1'}
        assert plan['trigger_writes'] == [[4, 0], [8, 0], [0, 4294967295]]
        assert plan['status_offsets'] == [0] and plan['trigger_instruction_hex']
        assert plan['internal_cause'] == 'unknown' and plan['reward_eligible'] is False


def test_declared_irq_slot_materializes_phase_and_profile_trigger():
    from myfuzz.integration.shared_declared_irq import compile_declared_irq_slot
    from myfuzz.integration.rv32_fixed_firmware import _lui_addi_load, _sw
    plan = {'schema_version': 'shared_declared_irq_contract.v1', 'runtime_status': 'not_integrated',
            'slot_base': 69632, 'slot_count': 8, 'phase_address': 159744,
            'trigger_instruction_hex': '13000000'}
    slot = compile_declared_irq_slot(plan, 2)
    expected = [*_lui_addi_load(6, 159744), *_lui_addi_load(7, 1), _sw(7, 6, 0)]
    assert slot['address'] == 69632 + 2 * 256 and len(bytes.fromhex(slot['code_hex'])) == 128
    assert slot['code_hex'].startswith(b''.join(x.to_bytes(4, 'little') for x in expected).hex() + '13000000')
    assert slot['source_origin'] == 'unknown' and slot['reward_eligible'] is False


def test_declared_irq_timer_is_wired_into_shared_preparation(tmp_path):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    marker = dict(phase_address=159744, scratch_address=159808, result_address=159872,
                  dma_handler_address=66208, target_handler_address=66816, group_id='shared-external')
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'timer-shared-irq', 'cpu_profile': PROFILE_CPU,
            'dma_profile': PROFILE_DMA, 'declared_irq_behavior': 'configs/peripherals/pulp_timer/irq_behavior.json',
            'declared_irq_base': 0x40004000, 'declared_irq_prepare_only': marker,
            'declared_irq_capability': 'configs/peripherals/pulp_timer_irq/test_capability.json'},
            base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        supplement = json.loads(desc.supplement.read_text())
        owners = supplement['ownership']['owners']
        assert all(owner['kind'] == 'fixed' for owner in owners if owner['component_id'] == 'peripheral')
        assert not supplement['request_supplements']['environment_links']
        assert {d['producer_instance'] for d in supplement['request_supplements']['deliveries']} == {'dma','timer'}
        assert {'component_instance':'peripheral','port':'gpio_in','bit_offset':0,'width':32,'constant':0} in supplement['request_supplements']['fixed_inputs']
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared = create_preparation(base_dir=ROOT, compose_path=desc.compose,
                capability_paths=desc.capability, supplement_path=desc.supplement,
                generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)
            try:
                artifacts, inputs = dict(prepared.artifacts), prepared.compiled_inputs()
                f5, = [p for p in inputs['compiled']['paths'] if p['flow_id'] == 'F5']
                assert f5['status'] == 'executable'
                assert f5['direction'] == 'CPU_TO_IP'
                f4, = [p for p in inputs['compiled']['paths'] if p['flow_id'] == 'F4']
                assert not any(s['kind']=='external_pin' for s in f4['sources'])
                assert any(e['instance_id'] == 'timer' for e in f5['endpoints'])
                from myfuzz.local_harness.compiled_artifact_admission import _f5_irq_bound
                producer, = [b for b in f5['bound_inputs'] if b['kind']=='ip_irq']
                owner = dict(component_id='cpu', bit_offset=0, width=1, producer_ref=producer['input_id'])
                assert _f5_irq_bound(f5,inputs['request'],inputs['compiled'],artifacts,owner,'irq_external_i')
                from copy import deepcopy
                forged = deepcopy(inputs['compiled'])
                forged_f6, = [p for p in forged['paths'] if p['flow_id']=='F6']
                wrong = forged_f6['execution_contract']['program_contract']['declared_irq']
                wrong['source']['bit_offset'] = 1
                wrong['irq_group_member']['source_bit_offset'] = 1
                assert not _f5_irq_bound(f5,inputs['request'],forged,artifacts,owner,'irq_external_i')
                admission = admit_compiled_f6_runtime_path(artifacts=artifacts,
                    compiled_inputs=inputs, base_dir=ROOT)
                from myfuzz.integration.shared_slot_paths import validate_shared_flow_admission
                validate_shared_flow_admission(admission)
                saved = json.loads(json.dumps(admission))
                validate_shared_flow_admission(saved)
                altered = deepcopy(saved)
                altered['shared_flow_paths']['F5']['irq_group']['members'][1]['source_port'] = 'forged'
                with pytest.raises(ValueError):
                    validate_shared_flow_admission(altered)
                contract = admission['execution_contract']
                ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],
                    cpu_id='cpu', dma_id='dma'), contract, artifacts, base_dir=ROOT)
                assembly = build_f6_assembly(contract=contract, artifacts=artifacts,
                    request=inputs['request'], ownership=ownership, base_dir=ROOT, cache_dir=tmp_path)
                assert {'cpu', 'dma', 'peripheral', 'timer'} == set(assembly.runner.sessions)
                assert contract['program_contract']['declared_irq']['runtime_status'] == 'not_integrated'
                assert contract['program_contract']['park_address'] == contract['program_contract']['slot_base'] - 4
                timer_mapping = [v for b, v in assembly.runner._irq_group_adapters.items()
                                 if b.source_component == 'timer']
                assert len(timer_mapping) == 1 and timer_mapping[0]['transport_only'] is True
                assert timer_mapping[0]['reward_eligible'] is False
                assert all(session.process is None for session in assembly.runner.sessions.values())
            finally:
                prepared.close()


def test_embedded_profile_capabilities_materialize_and_bind(tmp_path):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    dma = 'configs/peripherals/embedded_profile_dma/component_profile.json'
    target = 'configs/peripherals/embedded_profile_target/component_profile.json'
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'embedded-capabilities', 'cpu_profile': PROFILE_CPU,
            'dma_profile': dma, 'target': {'profile': target, 'base': 0x40003000,
                                           'write_values': [85]}}, base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        for role, profile_path in [('dma', dma), ('target', target)]:
            profile = load_component_profile(ROOT / profile_path)
            document = json.loads((out / (role + '_test_capability.json')).read_text())
            assert document['component_id'] == profile.component_id
            assert document['profile_fingerprint'] == profile.profile_fingerprint
            load_ip_test_capability(document, profile=profile)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared = create_preparation(base_dir=ROOT, compose_path=desc.compose,
                capability_paths=desc.capability, supplement_path=desc.supplement,
                generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)
            try:
                assert set(prepared.artifacts) == {'cpu', 'dma', 'peripheral', 'target'}
                artifacts, inputs = dict(prepared.artifacts), prepared.compiled_inputs()
                contract = admit_compiled_f6_runtime_path(artifacts=artifacts,
                    compiled_inputs=inputs, base_dir=ROOT)['execution_contract']
                ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],
                    cpu_id='cpu', dma_id='dma'), contract, artifacts, base_dir=ROOT)
                assembly = build_f6_assembly(contract=contract, artifacts=artifacts,
                    request=inputs['request'], ownership=ownership, base_dir=ROOT, cache_dir=tmp_path)
                assert assembly.companion_document()['target']['reward_eligible'] is False
            finally:
                prepared.close()


@pytest.mark.parametrize('corruption', ['identity', 'unknown_endpoint'])
def test_invalid_embedded_capability_is_rejected(corruption, tmp_path):
    from dataclasses import replace
    from copy import deepcopy
    from myfuzz.composition.component_profile import load_component_profile
    from scripts.generate_shared_dma_scenario import _capability
    profile = load_component_profile(ROOT / 'configs/peripherals/embedded_profile_target/component_profile.json')
    evidence = deepcopy(profile.evidence)
    embedded = evidence['embedded_test_capability']
    if corruption == 'identity':
        embedded['profile_fingerprint'] = 'sha256:' + '0' * 64
    else:
        embedded['endpoint_capabilities'][0]['endpoint_id'] = 'missing.endpoint'
    profile = replace(profile, evidence=evidence)
    with pytest.raises(ValueError):
        _capability(profile, None, 'target', ROOT, tmp_path)


def test_cpu_dma_profile_requests_and_capability_reference(tmp_path):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'profile-cpu-dma', 'cpu_profile': PROFILE_CPU,
            'dma_profile': PROFILE_DMA,
            'target': {'profile': 'configs/peripherals/shared_profile_target/component_profile.json',
                       'base': 0x40003000, 'write_values': [85]}}, base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        compose = json.loads(desc.compose.read_text())
        for name in ('cpu', 'dma'):
            request = json.loads((out / (name + '_request.json')).read_text())
            assert request['instance_id'] == name
            assert (request['reset_assert_ticks'], request['reset_release_ticks'],
                    request['max_wait_cycles']) == (8, 8, 16)
        assert compose['cpu']['request'].endswith('cpu_request.json')
        assert compose['devices'][0]['request'].endswith('dma_request.json')
        assert any(str(p).endswith('shared_profile_dma/test_capability.json') for p in desc.capability)
        assert any(str(p).endswith('shared_profile_target/test_capability.json') for p in desc.capability)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared = create_preparation(base_dir=ROOT, compose_path=desc.compose,
                capability_paths=desc.capability, supplement_path=desc.supplement,
                generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)
            try:
                artifacts = dict(prepared.artifacts)
                inputs = prepared.compiled_inputs()
                contract = admit_compiled_f6_runtime_path(artifacts=artifacts,
                    compiled_inputs=inputs, base_dir=ROOT)['execution_contract']
                ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],
                    cpu_id='cpu', dma_id='dma'), contract, artifacts, base_dir=ROOT)
                assembly = build_f6_assembly(contract=contract, artifacts=artifacts,
                    request=inputs['request'], ownership=ownership, base_dir=ROOT, cache_dir=tmp_path)
                assert assembly.companion_document()['target']['cross_case_origin'] == 'unknown'
                from scripts.generate_shared_dma_scenario import _declared_irq_shared_slot_plan
                from myfuzz.local_harness.request import load_local_harness_request
                from myfuzz.integration.shared_declared_irq import bind_declared_irq_group
                from myfuzz.integration.shared_f6_assembly import shared_irq_group
                from tests.local_harness.test_pulp_timer_irq_contract import _actual_timer_session
                plan = _declared_irq_shared_slot_plan(load_local_harness_request(
                    json.loads((out / 'cpu_request.json').read_text())),
                    'configs/peripherals/pulp_timer/irq_behavior.json',
                    contract['program_contract'], ROOT, 0x40004000)
                timer = _actual_timer_session()
                sessions = dict(assembly.runner.sessions, timer=timer)
                bound, mappings = bind_declared_irq_group(shared_irq_group(contract, artifacts,
                    base_dir=ROOT), plan, sessions)
                assert {m.source_component for m in bound.members} == {'dma', 'peripheral', 'timer'}
                assert mappings[bound.member_bindings()[-1]]['reward_eligible'] is False
            finally:
                prepared.close()


def test_cpu_profile_without_declared_timing_is_rejected():
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        with pytest.raises(ValueError, match='local.harness'):
            generate_scenario({'name': 'missing-timing',
                'cpu_profile': 'configs/cpus/cv32e20/component_profile.json',
                'dma_profile': PROFILE_DMA}, base_dir=ROOT, output=Path(tmp) / 'scenario')


def test_profile_capability_fingerprint_is_enforced():
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        with pytest.raises(ValueError, match='profile-mismatch'):
            generate_scenario({'name': 'mismatched-capability', 'cpu_profile': PROFILE_CPU,
                'dma_profile': PROFILE_DMA, 'dma_capability': ZIP_CAP},
                base_dir=ROOT, output=Path(tmp) / 'scenario')


def test_profile_only_target_generates_request_and_shared_assembly(tmp_path):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'profile-target', 'cpu_request': CV,
            'dma_request': ZIP, 'dma_capability': ZIP_CAP,
            'target': {'profile': PROFILE_ONLY, 'capability': PROFILE_CAP,
                       'base': 0x40003000, 'write_values': [85, 170]}}, base_dir=ROOT, output=out)
        request = json.loads((out / 'target_request.json').read_text())
        assert request['profile_path'] == PROFILE_ONLY and request['instance_id'] == 'target'
        assert request['tuning']['endpoint_policies'][0]['endpoint_id'] == 'i2c.bus'
        desc = load_descriptor(path, base_dir=ROOT)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared = create_preparation(base_dir=ROOT, compose_path=desc.compose,
                capability_paths=desc.capability, supplement_path=desc.supplement,
                generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)
            try:
                assert prepared.artifacts['target'].plan.profile.component_id == 'profile_only_i2c'
                wrapper = (Path(tmp) / 'generated/target/wrapper.sv').read_text()
                assert ".scl_pad_i(dut_p_11)" in wrapper and ".sda_pad_i(dut_p_14)" in wrapper
                assert "assign dut_p_11[0:0] = 1'd1;" in wrapper
                assert "assign dut_p_14[0:0] = 1'd1;" in wrapper
                inputs = prepared.compiled_inputs()
                artifacts = dict(prepared.artifacts)
                contract = admit_compiled_f6_runtime_path(artifacts=artifacts,
                    compiled_inputs=inputs, base_dir=ROOT)['execution_contract']
                ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],
                    cpu_id='cpu', dma_id='dma'), contract, artifacts, base_dir=ROOT)
                assembly = build_f6_assembly(contract=contract, artifacts=artifacts,
                    request=inputs['request'], ownership=ownership, base_dir=ROOT, cache_dir=tmp_path)
                target = assembly.companion_document()['target']
                assert target['register'] == 'PRESCALER' and target['cross_case_origin'] == 'unknown'
                assert target['reward_eligible'] is False
            finally:
                prepared.close()


def test_profile_only_target_refuses_undeclared_pin_drivers():
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'missing-pins', 'cpu_request': CV,
            'dma_request': ZIP, 'dma_capability': ZIP_CAP,
            'target': {'profile': 'configs/peripherals/profile_only_i2c/component_profile.json',
                       'capability': 'configs/peripherals/profile_only_i2c/test_capability.json',
                       'base': 0x40003000, 'write_values': [85]}}, base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            with pytest.raises(GenericRuntimeRefused):
                create_preparation(base_dir=ROOT, compose_path=desc.compose,
                    capability_paths=desc.capability, supplement_path=desc.supplement,
                    generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)


@pytest.mark.parametrize('cpu,dma,cap,variant,trigger,boot', [
    (CPU, DMA, DMA_CAP, 'dma-full-word-no-select', 'pulse', 0x10080),
    (CPU, ZIP, ZIP_CAP, 'dma-selected', 'level', 0x10080),
    (CV, ZIP, ZIP_CAP, 'dma-selected', 'level', 0x10000),
])
def test_generate_composable_dma_scenario(cpu, dma, cap, variant, trigger, boot):
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'generated-dma', 'cpu_request': cpu,
                                  'dma_request': dma, 'dma_capability': cap},
                                 base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        compose = load_compose(desc.compose, base_dir=ROOT)
        supplement = json.loads(desc.supplement.read_text())
        assert desc.shared_slots and set(desc.flow_ids) == {f'F{i}' for i in range(1, 7)}
        assert compose['devices'][0]['template']['variant_id'] == variant
        assert {b['initiator_template']['variant_id'] for b in compose['dma_master_route_bindings']} == {variant}
        assert supplement['request_supplements']['deliveries'][0]['trigger'] == trigger
        assert supplement['request_supplements']['f6_execution']['program']['boot_address'] == boot
        assert len(json.loads((out / 'acceptance_sequence.json').read_text())) == 8


def test_dma_capability_must_match_its_profile():
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        with pytest.raises(ValueError):
            generate_scenario({'name': 'bad', 'cpu_request': CPU, 'dma_request': ZIP,
                               'dma_capability': DMA_CAP}, base_dir=ROOT,
                              output=Path(tmp) / 'scenario')


def test_shared_dma_request_accepts_nondefault_instance_id(tmp_path):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        request = json.loads((ROOT / ZIP).read_text())
        request['instance_id'] = 'dma_engine'
        request_path = Path(tmp) / 'dma.json'
        request_path.write_text(json.dumps(request))
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'named-dma', 'cpu_request': CV,
            'dma_request': str(request_path.relative_to(ROOT)), 'dma_capability': ZIP_CAP},
            base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        compose = json.loads(desc.compose.read_text())
        assert compose['devices'][0]['instance_id'] == 'dma_engine'
        assert all(r['initiator_instance'] == 'dma_engine' for r in compose['dma_master_routes']['routes'])
        supplement = json.loads(desc.supplement.read_text())
        assert supplement['request_supplements']['deliveries'][0]['producer_instance'] == 'dma_engine'
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared = create_preparation(base_dir=ROOT, compose_path=desc.compose,
                capability_paths=desc.capability, supplement_path=desc.supplement,
                generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)
            try:
                assert 'dma_engine' in prepared.artifacts
                artifacts, inputs = dict(prepared.artifacts), prepared.compiled_inputs()
                contract = admit_compiled_f6_runtime_path(artifacts=artifacts,
                    compiled_inputs=inputs, base_dir=ROOT)['execution_contract']
                ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'],
                    cpu_id='cpu', dma_id='dma_engine'), contract, artifacts, base_dir=ROOT)
                build_f6_assembly(contract=contract, artifacts=artifacts,
                    request=inputs['request'], ownership=ownership, base_dir=ROOT, cache_dir=tmp_path)
            finally:
                prepared.close()


def test_generate_shared_scenario_with_separate_profile_target():
    """F2/F4 use the selected IP while GPIO remains the F5 IRQ source."""
    target = 'configs/peripherals/pulp_timer/shared_target_request.json'
    cap = 'configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json'
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'generated-target', 'cpu_request': CV,
            'dma_request': ZIP, 'dma_capability': ZIP_CAP,
            'target': {'request': target, 'capability': cap, 'base': 0x40003000,
                       'write_values': [85, 170]}}, base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        compose = load_compose(desc.compose, base_dir=ROOT)
        supplement = json.loads(desc.supplement.read_text())['request_supplements']
        assert {d['instance_id'] for d in compose['devices']} == {'dma', 'peripheral', 'target'}
        assert supplement['f6_execution']['shared_slots']['component'] == 'target'
        assert supplement['f6_execution']['shared_slots']['register'] == 'TIMER0_CTRL'
        assert supplement['f6_execution']['shared_slots']['read_register'] == 'TIMER0_CTRL'
        assert supplement['f6_execution']['gpio_irq']['component'] == 'peripheral'
        records = json.loads((out / 'acceptance_sequence.json').read_text())
        assert 'F4:55000000' in records and 'F2:04300040' in records
        assert len(records) == 8 and {r[:2] for r in records} == {f'F{i}' for i in range(1, 7)}
        search = json.loads((out / 'search_scenario.json').read_text())
        assert search['descriptor'] == str(path.relative_to(ROOT))
        assert search['records'] == records and search['flow'] == 'mixed'
        from myfuzz.search.descriptor_search import preflight_scenario
        search_report = preflight_scenario(search, ROOT)
        assert search_report['search_backend'] == 'live-shared-ram-target'
        assert search_report['consumption_provider'] == 'installed_shared_slot_ram.v1'


@pytest.mark.parametrize('target_request,capability,register,f2', [
    ('configs/peripherals/pulp_i2c/shared_target_request.json',
     'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/test_capability.json', 'PRESCALER', 'F2:00300040'),
    ('configs/peripherals/pulp_spi/shared_target_request.json',
     'configs/scenarios/compiled-f2-f4-obi-apb-spi-mmio-ibex/test_capability.json', 'SPICMD', 'F2:08300040'),
    ('configs/peripherals/profile_only_i2c/shared_target_request.json',
     'configs/peripherals/profile_only_i2c/test_capability.json', 'PRESCALER', 'F2:00300040'),
])
def test_generate_shared_scenario_for_bus_only_profile(target_request, capability, register, f2):
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'generic-apb-target', 'cpu_request': CV,
            'dma_request': ZIP, 'dma_capability': ZIP_CAP,
            'target': {'request': target_request,
                'capability': capability,
                'base': 0x40003000, 'write_values': [85, 170]}}, base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        slots = json.loads(desc.supplement.read_text())['request_supplements']['f6_execution']['shared_slots']
        assert slots['component'] == 'target' and slots['register'] == register
        assert slots['read_register'] == register and slots['observation_mode'] == 'bus'
        assert f2 in json.loads((out/'acceptance_sequence.json').read_text())


@pytest.mark.parametrize('target_request,target_cap,register,bus_only', [
    ('configs/peripherals/pulp_timer/shared_target_request.json',
     'configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json', 'TIMER0_CTRL', False),
    ('configs/peripherals/pulp_i2c/shared_target_request.json',
     'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/test_capability.json', 'PRESCALER', True),
    ('configs/peripherals/pulp_spi/shared_target_request.json',
     'configs/scenarios/compiled-f2-f4-obi-apb-spi-mmio-ibex/test_capability.json', 'SPICMD', True),
    ('configs/peripherals/profile_only_i2c/shared_target_request.json',
     'configs/peripherals/profile_only_i2c/test_capability.json', 'PRESCALER', True),
])
def test_separate_target_and_gpio_are_both_bound_to_the_same_runtime(tmp_path, monkeypatch,
        target_request, target_cap, register, bus_only):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly, shared_irq_ownership
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from tests.integration.test_compiled_f6_runtime import _install_software_process_boundary

    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'two-companions', 'cpu_request': CV,
            'dma_request': ZIP, 'dma_capability': ZIP_CAP,
            'target': {'request': target_request,
                       'capability': target_cap,
                       'base': 0x40003000, 'write_values': [85, 170]}}, base_dir=ROOT, output=out)
        desc = load_descriptor(path, base_dir=ROOT)
        with host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
            prepared = create_preparation(base_dir=ROOT, compose_path=desc.compose,
                capability_paths=desc.capability, supplement_path=desc.supplement,
                generated_dir=Path(tmp) / 'generated', flow_ids=desc.flow_ids)
            try:
                inputs = prepared.compiled_inputs()
                artifacts = dict(prepared.artifacts)
                admission = admit_compiled_f6_runtime_path(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
                contract = admission['execution_contract']
                ownership = shared_irq_ownership(_f6_runner_ownership(inputs['ownership'], cpu_id='cpu', dma_id='dma'),
                    contract, artifacts, base_dir=ROOT)
                assembly = build_f6_assembly(contract=contract, artifacts=artifacts, request=inputs['request'],
                    ownership=ownership, base_dir=ROOT, cache_dir=tmp_path)
                assert ('target' not in assembly.companion_authorities) is bus_only
                assert assembly.companion_document()['target']['register'] == register
                if bus_only:
                    target_doc = assembly.companion_document()['target']
                    assert target_doc['schema_version'] == 'compiled_F6_mmio_companion.v1'
                    assert target_doc['storage_operations'] == 'unknown'
                    assert target_doc['cross_case_origin'] == 'unknown'
                    assert target_doc['reward_eligible'] is False
                with monkeypatch.context() as patch:
                    _install_software_process_boundary(patch)
                    runtime = CompiledF6Runtime(artifacts=artifacts,
                        compiled_inputs=inputs, base_dir=ROOT, shared_assembly=assembly,
                        cache_dir=tmp_path, max_cases=8, defer_begin=True)
                    bound = dict(runtime.bound_topology.runtime_compilation._sessions)
                    assert set(bound) == {'cpu', 'dma', 'peripheral', 'target'}
                    assert all(runtime.runner.sessions[name] is session for name, session in bound.items())
                    assert runtime.runtime_path_admission['shared_flow_paths']['F2']['component'] == 'target'
                    assert runtime.runtime_path_admission['shared_flow_paths']['F5']['component'] == 'peripheral'
                    from myfuzz.search.shared_slot_ram_adapter import SharedSlotSelector, shared_slot_records
                    records = json.loads((out / 'acceptance_sequence.json').read_text())
                    assert shared_slot_records(records)
                    wrong = [r if not r.startswith('F2:') else 'F2:04100040' for r in records]
                    bad = SharedSlotSelector(None, flow='mixed', records=wrong, policy='state', seed=7, cases=8)
                    with pytest.raises(ValueError, match='outside the declared target'):
                        bad.attach_runtime(runtime)
                    selector = SharedSlotSelector(None, flow='mixed', records=records, policy='state', seed=7, cases=8)
                    selector.attach_runtime(runtime)
                    assert selector._pin_mode is False and selector._pin_handle is None
                    assert selector._handle is not None
                    runtime.runner.sessions['peripheral'] = bound['target']
                    with pytest.raises(ValueError, match='session|topology'):
                        runtime.bound_topology.validate_topology()
                    runtime.runner.sessions['peripheral'] = bound['peripheral']
            finally:
                prepared.close()


def test_zipdma_shared_preflight_uses_shared_runtime_contract():
    from myfuzz.runtime.descriptor_preflight import inspect_descriptor
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs') as tmp:
        out = Path(tmp) / 'scenario'
        path = generate_scenario({'name': 'generated-zipdma', 'cpu_request': CV,
                                  'dma_request': ZIP, 'dma_capability': ZIP_CAP},
                                 base_dir=ROOT, output=out)
        descriptor = load_descriptor(path, base_dir=ROOT)
        report = inspect_descriptor(descriptor, base_dir=ROOT, generated_dir=Path(tmp) / 'preflight')
        assert report['preparation'] == 'complete'
        support = report['flows']['F6']['static_support']
        assert support['execution_supported'] == 1
        assert support['runtime_admitted'] is False
        assert support['executor'] == 'compiled_f6_cpu_dma'
