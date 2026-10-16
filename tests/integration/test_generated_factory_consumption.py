"""P7 supplied artifacts reach real session constructors; full D4 stays refused."""
from unittest.mock import patch

import pytest

from myfuzz.local_harness.generated_execution_admission import (
    GeneratedExecutionRefused, select_factory_artifacts, require_runtime_projection)
from myfuzz.scenario import ibex_pulp_dual_source as shared
from myfuzz.scenario.cv32e40p_pulp_dual_source import make_cv32e40p_pulp_dual_source_factory
from tests.integration.test_compiled_artifact_admission import loaded


@pytest.mark.parametrize('factory_builder', [shared.make_ibex_pulp_dual_source_factory,
                                            make_cv32e40p_pulp_dual_source_factory])
def test_supplied_objects_reach_session_constructors_without_regeneration(loaded, factory_builder, tmp_path):
    artifacts, _, _, _ = loaded
    cpu_profile = artifacts['cpu'].plan.request.profile_path
    if ('cv32e40p' in cpu_profile) != (factory_builder is make_cv32e40p_pulp_dual_source_factory):
        pytest.skip('CPU factory/profile pairing checked by separate negative')
    gpio = artifacts['gpio']
    supplied = {'cpu': artifacts['cpu']}
    # Use the real trusted rendering recipe for each declared instance identity.
    for instance in ('gpio_a', 'gpio_b'):
        from myfuzz.local_harness.generated_artifact_admission import _reconstruct
        request = gpio.plan.request.document()
        request['instance_id'] = instance
        supplied[instance] = _reconstruct(request, base_dir=shared.ROOT)
    with patch.object(shared, '_artifact', side_effect=AssertionError('must consume supplied artifacts')), \
         patch('subprocess.Popen', side_effect=AssertionError('no runtime process')):
        factory = factory_builder(tmp_path, generated_artifacts=supplied)
        runner = factory()
    assert isinstance(runner.sessions['cpu'], shared.GeneratedCve2Session)
    assert isinstance(runner.sessions['gpio_a'], shared.GeneratedPulpGpioSession)
    assert isinstance(runner.sessions['gpio_b'], shared.GeneratedPulpGpioSession)
    assert runner.sessions['cpu'].artifact is supplied['cpu']
    assert runner.sessions['gpio_a'].artifact is supplied['gpio_a']
    assert runner.sessions['gpio_b'].artifact is supplied['gpio_b']
    assert supplied['cpu'].plan.request.reset_assert_ticks == 2


def test_wrong_cpu_profile_cannot_borrow_artifacts_by_similar_name(loaded):
    artifacts, _, _, _ = loaded
    expected = {'cpu': ('configs/cpus/cv32e20/component_profile.json', 'obi_cpu'),
                'gpio': ('configs/peripherals/pulp_gpio/component_profile.json', 'apb_gpio')}
    with pytest.raises(GeneratedExecutionRefused, match='generated-runtime-profile-mismatch'):
        select_factory_artifacts(artifacts, expected=expected, base_dir=shared.ROOT)


def test_structural_d3_compatibility_never_silently_enables_fixed_runtime(loaded):
    from myfuzz.scenario.ownership import compile_ownership
    artifacts, request, compiled, _ = loaded
    with pytest.raises(GeneratedExecutionRefused, match='compiled-runtime-projection-undeclared') as error:
        require_runtime_projection(artifacts=artifacts, compiled_inputs=dict(request=request,
            compiled=compiled, ownership=compile_ownership((), ()), physical_port_map={}))
    assert error.value.detail['admission']['status'] == 'compatible'


def test_changed_compiled_constraint_refuses_before_runtime_projection(loaded):
    import copy
    from myfuzz.scenario.ownership import compile_ownership
    artifacts, request, compiled, _ = loaded
    changed = copy.deepcopy(compiled)
    changed['paths'][0]['seed'] = None
    with pytest.raises(GeneratedExecutionRefused, match='compiled-runtime-input-refused'):
        require_runtime_projection(artifacts=artifacts, compiled_inputs=dict(request=request,
            compiled=changed, ownership=compile_ownership((), ()), physical_port_map={}))


@pytest.mark.parametrize('module_name,builder_name', [
    ('myfuzz.integration.ibex_pulp_online', 'make_ibex_pulp_online_runtime'),
    ('myfuzz.integration.cv32e40p_pulp_online', 'make_cv32e40p_pulp_online_runtime')])
def test_runtime_entry_refuses_generated_inputs_before_factory_or_process(loaded, tmp_path,
                                                                        module_name, builder_name):
    import importlib
    from myfuzz.scenario.ownership import compile_ownership
    module = importlib.import_module(module_name)
    builder = getattr(module, builder_name)
    artifacts, request, compiled, _ = loaded
    with patch.object(shared, '_artifact', side_effect=AssertionError('no rendering')), \
         patch('subprocess.Popen', side_effect=AssertionError('no process')):
        with pytest.raises(GeneratedExecutionRefused, match='compiled-runtime-input-required'):
            builder(cache_dir=tmp_path, run_id='refused', generated_artifacts=artifacts)
        with pytest.raises(GeneratedExecutionRefused, match='compiled-runtime-projection-undeclared'):
            builder(cache_dir=tmp_path, run_id='refused', generated_artifacts=artifacts,
                compiled_inputs=dict(request=request, compiled=compiled,
                    ownership=compile_ownership((), ()), physical_port_map={}))


def test_supplied_artifact_kind_and_instance_are_checked_before_consumption(loaded):
    from dataclasses import replace
    artifacts, _, _, _ = loaded
    expected = {name: (a.plan.request.profile_path, a.runtime_document['kind'])
                for name, a in artifacts.items()}
    selected = select_factory_artifacts(artifacts, expected=expected, base_dir=shared.ROOT)
    assert all(selected[name] is artifact for name, artifact in artifacts.items())
    bad = dict(artifacts)
    artifact = artifacts['cpu']
    bad['cpu'] = replace(artifact, runtime_document={**artifact.runtime_document, 'kind': 'wrong'})
    with pytest.raises(GeneratedExecutionRefused, match='generated-runtime-kind-mismatch'):
        select_factory_artifacts(bad, expected=expected, base_dir=shared.ROOT)
    bad['cpu'] = replace(artifact, plan=replace(artifact.plan,
        request=replace(artifact.plan.request, instance_id='cpu_similar')))
    with pytest.raises(GeneratedExecutionRefused, match='generated-runtime-instance-mismatch'):
        select_factory_artifacts(bad, expected=expected, base_dir=shared.ROOT)
