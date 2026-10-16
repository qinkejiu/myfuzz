"""Native APB admission and raw projection without executing RTL."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import compile_ownership


@pytest.fixture(scope='module')
def artifacts():
    from tests.local_harness.test_renderer import real_plan, ROOT
    from myfuzz.local_harness import render_local_harness, verify_local_source_lock, render_local_runtime
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.plan import plan_local_harness
    from tests.local_harness.test_native_physical_observation import make_request
    path = 'configs/peripherals/pulp_gpio/component_profile.json'
    def render(plan):
        return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
    return (render(real_plan(path, 'subject')), render(plan_local_harness(make_request(path,
        {'raw_tick_stream': [{'sampling': 'pre_post'}]}), base_dir=ROOT)))


def runner_session(artifact):
    session = SimpleNamespace(artifact=artifact, reset_epoch=3, samples=[])
    def drain():
        rows, session.samples = session.samples, []
        return rows
    session.drain_tick_samples = drain
    runner = ScenarioRunner(sessions={'gpio': session},
                            ownership=compile_ownership((), ()), bindings=())
    return runner, session


@pytest.mark.parametrize('helper', ('_ip_protocol_event_normalizer', '_ip_protocol_checker'))
def test_real_native_apb_artifact_admitted_and_cached(artifacts, helper):
    old, artifact = artifacts
    runner, session = runner_session(artifact)
    projector = getattr(runner, helper)('gpio', session)
    assert projector is not None
    assert getattr(runner, helper)('gpio', session) is projector
    legacy_runner, legacy = runner_session(old)
    assert getattr(legacy_runner, helper)('gpio', legacy) is None


@pytest.mark.parametrize('helper', ('_ip_protocol_event_normalizer', '_ip_protocol_checker'))
@pytest.mark.parametrize('mutation', ('missing_trace', 'signal', 'kind', 'contract'))
def test_native_trace_drift_rejected_and_retry_not_cached(artifacts, helper, mutation):
    _, artifact = artifacts
    document = deepcopy(artifact.runtime_document)
    if mutation == 'missing_trace':
        document.pop('base_protocol_trace', None)
    elif mutation == 'signal':
        document.setdefault('base_protocol_trace', {'signals': {}})['signals']['psel'] = 'invented'
    elif mutation == 'kind':
        document['kind'] = 'apb3_register_observe'
    else:
        document['native_physical_observation_contract']['sampling'] = 'post'
    runner, session = runner_session(replace(artifact, runtime_document=document))
    for _ in range(2):
        with pytest.raises(ValueError, match='native.*observation'):
            getattr(runner, helper)('gpio', session)
    session.artifact = artifact
    assert getattr(runner, helper)('gpio', session) is not None


def test_runner_projects_native_apb_raw_receipts_with_provenance(artifacts):
    _, artifact = artifacts
    runner, session = runner_session(artifact)
    trace = artifact.runtime_document.get('base_protocol_trace')
    assert trace is not None
    physical = {row['runtime_name']: ('0' * ((row['width'] + 3) // 4)
                if row.get('encoding') == 'fixed_width_hex' else 0)
                for row in artifact.runtime_document['physical_exports']}
    def outputs(**roles):
        values = dict.fromkeys(trace['signals'], 0)
        values.update(roles)
        return {'backend': {trace['signals'][role]: value for role, value in values.items()},
                'physical': deepcopy(physical)}
    session.samples = [dict(local_tick=1,
        pre=outputs(psel=1, penable=0, pwrite=0, paddr=4),
        post=outputs(psel=1, penable=0, pwrite=0, paddr=4)),
        dict(local_tick=2,
        pre=outputs(psel=1, penable=1, pwrite=0, paddr=4, pready=1, prdata=17),
        post=outputs())]
    runner.local_ticks['gpio'] = 2
    runner._drain_tick_samples(producer_event_id=7)
    rows = list(runner._events)
    raw = {row['event_id']: row for row in rows if row['kind'] == 'local_tick_sample'}
    projected = [row for row in rows if row.get('event_type') == 'transaction_response']
    assert len(projected) == 1
    assert projected[0]['reset_epoch'] == 3
    assert projected[0]['transaction_key'] is None
    assert all(ref in raw for ref in projected[0]['raw_event_refs'])
    assert all(row['producer_event_id'] == 7 for row in raw.values())
    assert not any(row.get('event_type') == 'protocol_violation' for row in rows)


def test_invalid_native_trace_is_rejected_before_receipt_drain(artifacts):
    _, artifact = artifacts
    document = deepcopy(artifact.runtime_document)
    document.pop('base_protocol_trace')
    runner, session = runner_session(replace(artifact, runtime_document=document))
    drained = []
    session.drain_tick_samples = lambda: drained.append(True) or []
    with pytest.raises(ValueError, match='native.*observation'):
        runner._drain_tick_samples(producer_event_id=1)
    assert drained == []
    assert list(runner._events) == []


def test_native_cpu_remains_physical_only():
    from tests.local_harness.test_renderer import ROOT
    from tests.local_harness.test_native_physical_observation import make_request
    from myfuzz.local_harness import render_local_harness, verify_local_source_lock, render_local_runtime
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.plan import plan_local_harness
    plan = plan_local_harness(make_request('configs/cpus/ibex_obi_local/component_profile.json',
        {'raw_tick_stream': [{'sampling': 'pre_post'}]}), base_dir=ROOT)
    artifact = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
    runner, session = runner_session(artifact)
    session._physical_tick_samples_enabled = True
    assert runner._ip_base_event_normalizer('gpio', session) is not None
    assert runner._ip_protocol_event_normalizer('gpio', session) is None
    assert runner._ip_protocol_checker('gpio', session) is None
