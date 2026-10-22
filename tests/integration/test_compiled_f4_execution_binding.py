"""Explicit identity binding for the bounded compiled F4 executor."""
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from myfuzz.integration import compiled_f4
from tests.integration.test_compiled_f4_storage_producer import (
    ROOT, timer_loaded, f4_path)


@pytest.fixture(scope='module')
def timer_generated(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('f4-execution-binding'))


def test_execution_binding_names_the_complete_selected_f4_contract(timer_generated):
    artifacts, inputs = timer_generated

    binding = compiled_f4.derive_f4_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    document = binding.document()
    path = f4_path(inputs['compiled'])

    assert document['schema_version'] == 'compiled_F4_execution_binding.v1'
    assert document['path_id'] == path['path_id']
    assert document['selected_path_sha256']
    assert document['compiled_document_sha256'] == \
        compiled_f4.compiled_document_sha256(inputs['compiled'])
    assert set(document['artifact_identities']) == {'processor', 'peripheral'}
    assert document['artifact_identities']['processor']['source_revision'] == \
        artifacts['processor'].plan.profile.source.revision
    assert set(document['artifact_identities']['processor']['generated_files_sha256']) == {
        'abi.json', 'artifact.json', 'driver.cpp', 'runtime.sv',
        'source_verification.json', 'wrapper.sv'}
    assert document['artifact_identities']['peripheral']['source_revision'] == \
        artifacts['peripheral'].plan.profile.source.revision
    assert document['candidate_layout']['digest']
    assert document['target']['protocol'] == ['apb', '3']
    assert document['target']['template'] == {
        'template_id': 'target.apb3', 'template_version': '1',
        'variant_id': 'full-word'}
    assert document['target']['window'] == {
        'device_id': 'peripheral', 'target_instance': 'peripheral',
        'base': 0x40001000, 'size': 4096,
        'register_address': 0x40001004, 'register_offset': 4}
    assert document['target']['source_contract_id'] == \
        'pulp-apb-timer.ctrl0.source.v1'
    assert document['producer_binding']['register']['name'] == 'TIMER0_CTRL'
    assert document['prerequisites_sha256']
    assert document['assertions_sha256']
    assert binding.digest == document['binding_sha256']


def test_execution_binding_refuses_a_similarly_named_component_identity(
        timer_generated, tmp_path):
    artifacts, inputs = timer_generated
    target = artifacts['peripheral']
    profile = replace(target.plan.profile, component_id='pulp_timer_like')
    binding = replace(target.plan.binding, component_id='pulp_timer_like')
    plan = replace(target.plan, profile=profile, binding=binding)
    wrong_target = replace(target, plan=plan)
    with patch('subprocess.Popen',
               side_effect=AssertionError('native process must not start')) as popen:
        with pytest.raises(ValueError, match='compiled-F4|compiled-runtime'):
            compiled_f4.CompiledF4Runtime(
                artifacts={**artifacts, 'peripheral': wrong_target},
                compiled_inputs=inputs,
                base_dir=ROOT, cache_dir=tmp_path / 'cache')
    popen.assert_not_called()


@pytest.mark.parametrize('mutation', ('assertion', 'window'))
def test_execution_binding_refuses_path_or_window_drift_before_native(
        timer_generated, tmp_path, mutation):
    artifacts, inputs = timer_generated
    wrong_inputs = inputs
    if mutation == 'assertion':
        compiled = deepcopy(inputs['compiled'])
        f4_path(compiled)['assertions'][0]['expectation_id'] = \
            'cross_component.similarly_named_target'
        wrong_inputs = {**inputs, 'compiled': compiled}
    else:
        request = inputs['request']
        windows = tuple(replace(window, base=window.base + 0x1000)
                        for window in request.wiring.windows)
        wrong_request = replace(request,
            wiring=replace(request.wiring, windows=windows))
        wrong_inputs = {**inputs, 'request': wrong_request}

    with patch('subprocess.Popen',
               side_effect=AssertionError('native process must not start')) as popen:
        with pytest.raises(ValueError, match='compiled-runtime-input-refused'):
            compiled_f4.CompiledF4Runtime(
                artifacts=artifacts, compiled_inputs=wrong_inputs,
                base_dir=ROOT, cache_dir=tmp_path / 'cache')
    popen.assert_not_called()


def test_execution_binding_refuses_wrong_apb_template_before_native(
        timer_generated, tmp_path):
    artifacts, inputs = timer_generated
    target = artifacts['peripheral']
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    tuning_document = target.plan.request.tuning.document()
    tuning_document['endpoint_policies'][0]['variant_id'] = 'half-word'
    wrong_request = replace(target.plan.request,
        tuning=load_local_harness_tuning(tuning_document))
    wrong_plan = replace(target.plan, request=wrong_request)
    with patch('subprocess.Popen',
               side_effect=AssertionError('native process must not start')) as popen:
        with pytest.raises(ValueError,
                           match='compiled-F4-producer-template-unsupported'):
            compiled_f4.CompiledF4Runtime(
                artifacts={**artifacts,
                           'peripheral': replace(target, plan=wrong_plan)},
                compiled_inputs=inputs, base_dir=ROOT,
                cache_dir=tmp_path / 'cache')
    popen.assert_not_called()


def test_execution_binding_refuses_similarly_named_wrong_shape_target_before_native(
        timer_generated, tmp_path):
    artifacts, inputs = timer_generated
    target = artifacts['peripheral']
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    from myfuzz.scenario.compiled_paths import compile_paths

    profile = replace(target.plan.profile, component_id='pulp_timer_like')
    target_component = replace(inputs['request'].devices[0], profile=profile)
    request = replace(inputs['request'], devices=(target_component,))
    tuning_document = target.plan.request.tuning.document()
    tuning_document['endpoint_policies'][0]['variant_id'] = 'half-word'
    tuning = load_local_harness_tuning(tuning_document)
    target_request = replace(target.plan.request, tuning=tuning)
    target_plan = replace(target.plan, profile=profile,
        binding=replace(target.plan.binding, component_id='pulp_timer_like'),
        request=target_request)
    wrong_target = replace(target, plan=target_plan)
    wrong_inputs = {**inputs, 'request': request,
                    'compiled': compile_paths(request)}

    with patch('subprocess.Popen',
               side_effect=AssertionError('native process must not start')) as popen:
        with pytest.raises(ValueError,
                           match='compiled-F4-producer-template-unsupported'):
            compiled_f4.CompiledF4Runtime(
                artifacts={**artifacts, 'peripheral': wrong_target},
                compiled_inputs=wrong_inputs, base_dir=ROOT,
                cache_dir=tmp_path / 'cache')
    popen.assert_not_called()


def test_execution_binding_changes_when_generated_artifact_bytes_change(timer_generated):
    artifacts, inputs = timer_generated
    binding = compiled_f4.derive_f4_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)

    modified = dict(artifacts)
    modified['processor'] = replace(artifacts['processor'],
        cpp_text=artifacts['processor'].cpp_text + '\n// byte-identity mutation\n')
    with patch('subprocess.Popen',
               side_effect=AssertionError('native process must not start')):
        changed = compiled_f4.derive_f4_execution_binding(
            artifacts=modified, compiled_inputs=inputs, base_dir=ROOT)
    assert changed.digest != binding.digest
    before = binding.document()['artifact_identities']['processor']
    after = changed.document()['artifact_identities']['processor']
    assert before['artifact_digest'] == after['artifact_digest']
    assert before['generated_artifact_bytes_sha256'] != \
        after['generated_artifact_bytes_sha256']
    assert before['generated_files_sha256']['driver.cpp'] != \
        after['generated_files_sha256']['driver.cpp']
