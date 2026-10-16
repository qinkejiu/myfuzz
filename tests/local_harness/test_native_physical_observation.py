"""Explicit native v2 raw observations; construction only, no RTL."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.request import load_local_harness_request
from myfuzz.local_harness.tuning import load_local_harness_tuning


def make_request(path, tuning):
    return load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path=path, instance_id='subject', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16, tuning=tuning))


def test_raw_tick_policy_roundtrips_only_when_declared():
    assert 'raw_tick_stream' not in load_local_harness_tuning({}).document()
    tuning = load_local_harness_tuning({'raw_tick_stream': [{'sampling': 'pre_post'}]})
    assert tuning.document()['raw_tick_stream'] == [{'sampling': 'pre_post'}]
    assert load_local_harness_tuning(tuning.document()) == tuning


@pytest.mark.parametrize('rows', ([{'sampling': 'post'}], [{'sampling': True}],
    [{'sampling': 'pre_post', 'script': 'arbitrary'}],
    [{'sampling': 'pre_post'}, {'sampling': 'pre_post'}]))
def test_raw_tick_policy_is_closed_and_rejects_duplicate(rows):
    with pytest.raises(ValueError):
        load_local_harness_tuning({'raw_tick_stream': rows})


@pytest.fixture(scope='module', params=(
    'configs/cpus/ibex_obi_local/component_profile.json',
    'configs/peripherals/pulp_gpio/component_profile.json'))
def native_artifacts(request):
    from tests.local_harness.test_renderer import real_plan, ROOT
    from myfuzz.local_harness import render_local_harness, verify_local_source_lock, render_local_runtime
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.plan import plan_local_harness
    path = request.param
    plan = real_plan(path, 'subject')
    changed = plan_local_harness(make_request(path,
        {'raw_tick_stream': [{'sampling': 'pre_post'}]}), base_dir=ROOT)
    def render(plan):
        return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
    return render(plan), render(changed)


def test_native_raw_policy_preserves_executor_and_declares_exports(native_artifacts):
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    old, new = native_artifacts
    assert new.runtime_document['kind'] == old.runtime_document['kind']
    assert new.runtime_document['kind'] in ('obi_cpu', 'apb_gpio')
    assert new.runtime_document['physical_exports'] == old.runtime_document['physical_exports']
    assert 'native_physical_observation_contract' not in old.runtime_document
    assert new.runtime_document['base_event_schema_version'] == 'ip_base_event.v1'
    assert new.runtime_document['raw_observation_schema_version'] == 'ip_raw_observation.v1'
    assert verify_native_physical_observation(new) is True


def test_native_raw_contract_installs_physical_projector(native_artifacts):
    from myfuzz.scenario.runner import ScenarioRunner
    _, artifact = native_artifacts
    runner = object.__new__(ScenarioRunner)
    runner._ip_base_event_normalizers = {}
    local = SimpleNamespace(artifact=artifact, _physical_tick_samples_enabled=True,
                            drain_tick_samples=lambda: [])
    normalizer = runner._ip_base_event_normalizer('subject', local)
    assert normalizer is not None
    assert normalizer.component_id == artifact.plan.profile.component_id


def test_disabled_native_cpu_stream_remains_rejected_on_retry(native_artifacts):
    from myfuzz.scenario.runner import ScenarioRunner
    _, artifact = native_artifacts
    if artifact.runtime_document['kind'] != 'obi_cpu':
        return
    runner = object.__new__(ScenarioRunner)
    runner._ip_base_event_normalizers = {}
    local = SimpleNamespace(artifact=artifact, _physical_tick_samples_enabled=False,
                            drain_tick_samples=lambda: [])
    for _ in range(2):
        with pytest.raises(ValueError, match='stream-disabled'):
            runner._ip_base_event_normalizer('subject', local)
    local._physical_tick_samples_enabled = True
    assert runner._ip_base_event_normalizer('subject', local) is not None


def test_native_raw_observations_are_real_export_values(native_artifacts):
    from myfuzz.scenario.runner import ScenarioRunner
    _, artifact = native_artifacts
    runner = object.__new__(ScenarioRunner)
    runner._ip_base_event_normalizers = {}
    normalizer = runner._ip_base_event_normalizer('subject', SimpleNamespace(
        artifact=artifact, _physical_tick_samples_enabled=True, drain_tick_samples=lambda: []))
    physical = {e['runtime_name']: (('0' * ((e['width'] + 3) // 4))
                    if e.get('encoding') == 'fixed_width_hex' else 0)
                for e in artifact.runtime_document['physical_exports']}
    events = normalizer.consume_local_tick(dict(event_id=1, component='subject',
        kind='local_tick_sample', local_tick=1, phase='pre', outputs={'physical': physical}), reset_epoch=0)
    assert events
    assert all(e['raw_event_refs'] == [1] for e in events)
    assert all(e['payload']['value'] == 0 for e in events)


def test_raw_policy_cannot_silently_ignore_additional_drive_tuning():
    from myfuzz.local_harness.native_physical_observation import native_physical_observation_requested
    value = make_request('configs/cpus/ibex_obi_local/component_profile.json', {
        'raw_tick_stream': [{'sampling': 'pre_post'}],
        'fixed_inputs': [{'endpoint_id': 'irq', 'role': 'irq', 'value': 0}]})
    with pytest.raises(ValueError, match='unsupported-tuning'):
        native_physical_observation_requested(value)


@pytest.mark.parametrize('mutation', ('export', 'contract', 'request'))
def test_native_contract_drift_rejected(native_artifacts, mutation):
    from copy import deepcopy
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    old, new = native_artifacts
    document = deepcopy(new.runtime_document)
    if mutation == 'export':
        document['physical_exports'][0]['runtime_name'] += '_changed'
    elif mutation == 'contract':
        document['native_physical_observation_contract']['sampling'] = 'post'
    else:
        new = replace(new, plan=old.plan)
    with pytest.raises(ValueError, match='native.*observation'):
        verify_native_physical_observation(replace(new, runtime_document=document))


def test_native_projector_contract_drift_is_not_cached_as_disabled(native_artifacts):
    from copy import deepcopy
    from myfuzz.scenario.runner import ScenarioRunner
    _, artifact = native_artifacts
    runner = object.__new__(ScenarioRunner)
    runner._ip_base_event_normalizers = {}
    document = deepcopy(artifact.runtime_document)
    document['native_physical_observation_contract']['sampling'] = 'post'
    local = SimpleNamespace(artifact=replace(artifact, runtime_document=document),
                            _physical_tick_samples_enabled=True, drain_tick_samples=lambda: [])
    for _ in range(2):
        with pytest.raises(ValueError, match='native.*observation'):
            runner._ip_base_event_normalizer('subject', local)
    local.artifact = artifact
    assert runner._ip_base_event_normalizer('subject', local) is not None


def test_actual_factory_can_declare_all_native_physical_observations(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    runner = make_ibex_pulp_dual_source_factory(tmp_path, physical_observations=True)()
    assert runner.sessions['cpu']._physical_tick_samples_enabled is True
    for name, local in runner.sessions.items():
        assert local._process is None
        assert local.artifact.plan.request.document()['schema_version'] == 'local_harness.v2'
        assert runner._ip_base_event_normalizer(name, local) is not None


@pytest.mark.parametrize('enabled', (1, 'true'))
def test_native_factory_switch_rejects_before_render(tmp_path, enabled):
    from unittest.mock import patch
    from myfuzz.scenario import ibex_pulp_dual_source as assembly
    with patch.object(assembly, '_artifact') as render:
        with pytest.raises(ValueError, match='physical.*boolean'):
            assembly.make_ibex_pulp_dual_source_factory(tmp_path, physical_observations=enabled)
        render.assert_not_called()


@pytest.mark.parametrize('kind', ('apb3_register_observe', 'unsupported'))
def test_native_policy_cannot_bypass_verification_by_changing_kind(native_artifacts, kind):
    from copy import deepcopy
    from myfuzz.scenario.runner import ScenarioRunner
    _, artifact = native_artifacts
    document = deepcopy(artifact.runtime_document)
    document['kind'] = kind
    local = SimpleNamespace(artifact=replace(artifact, runtime_document=document),
                            _physical_tick_samples_enabled=False, drain_tick_samples=lambda: [])
    runner = object.__new__(ScenarioRunner)
    runner._ip_base_event_normalizers = {}
    for _ in range(2):
        with pytest.raises(ValueError, match='native.*observation'):
            runner._ip_base_event_normalizer('subject', local)


def test_native_scenario_irq_alias_is_explicit_and_uses_actual_raw_port(native_artifacts):
    from myfuzz.scenario.runner import ScenarioRunner
    _, artifact = native_artifacts
    document = artifact.runtime_document
    mapping = document.get('native_physical_observation_mapping')
    assert mapping is not None
    aliases = mapping['aliases']
    assert len(aliases) == 1 and aliases[0]['port'] == 'irq'
    actual_port = 'irq_external_i' if document['kind'] == 'obi_cpu' else 'interrupt'
    assert aliases[0]['physical_port'] == actual_port
    runner = object.__new__(ScenarioRunner)
    runner._ip_base_event_normalizers = {}
    normalizer = runner._ip_base_event_normalizer('subject', SimpleNamespace(
        artifact=artifact, _physical_tick_samples_enabled=True, drain_tick_samples=lambda: []))
    row = next(e for e in normalizer._exports if e['physical_port'] == actual_port)
    assert row['width'] == 1 and row['clock_domain'] is not None
    values = {e['runtime_name']: ('0' * ((e['width'] + 3) // 4)
              if e.get('encoding') == 'fixed_width_hex' else 0)
              for e in document['physical_exports']}
    values[row['runtime_name']] = 1
    raw = dict(event_id=1, kind='local_tick_sample', local_tick=1,
               phase='pre', outputs={'physical': values})
    before = __import__('copy').deepcopy(raw)
    event = next(e for e in normalizer.consume_local_tick(raw, reset_epoch=0)
                 if e['physical_port'] == actual_port)
    assert event['payload']['value'] == 1 and event['raw_event_refs'] == [1]
    assert raw == before


def test_native_alias_mapping_cannot_be_relabelled_even_with_recomputed_digest(native_artifacts):
    from copy import deepcopy
    from myfuzz.local_harness.native_physical_observation import (
        native_physical_observation_contract, verify_native_physical_observation)
    _, artifact = native_artifacts
    document = deepcopy(artifact.runtime_document)
    mapping = document.get('native_physical_observation_mapping')
    assert mapping is not None
    mapping['aliases'][0]['physical_port'] = 'different'
    document['native_physical_observation_contract'] = native_physical_observation_contract(
        document['physical_exports'], mapping)
    with pytest.raises(ValueError, match='native.*observation'):
        verify_native_physical_observation(replace(artifact, runtime_document=document))
