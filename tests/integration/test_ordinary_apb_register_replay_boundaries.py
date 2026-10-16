"""Independent closed ordinary replay option boundaries; no RTL processes."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from myfuzz.integration.ibex_pulp_register_replay import (
    make_register_assembly, validate_register_assembly, _sources,
)
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.session_runtime import ScenarioSession
from tests.scenario.test_register_program_replay import actual_factory, adapter


@pytest.mark.parametrize('value', (None, True, 256, [], {}, {'max_records': True},
    {'max_records': 0}, {'max_records': 65537}, {'max_records': 1.0},
    {'max_records': 1, 'provider': 'saved.module'}))
def test_ordinary_assembly_closed_option_rejects_before_factory(value):
    with pytest.raises(ValueError):
        make_register_assembly(ordinary_apb_access_evidence=value)


def test_default_assembly_and_source_closures_remain_optional_and_detached():
    off = make_register_assembly()
    assert 'ordinary_apb_access_evidence' not in off
    assert len(_sources(off)) == 38
    capability = make_register_assembly(requested_minimum_level=None)
    assert len(_sources(capability)) == 40
    enabled = make_register_assembly(ordinary_apb_access_evidence={'max_records': 1})
    detached = validate_register_assembly(enabled)
    detached['ordinary_apb_access_evidence']['max_records'] = 2
    assert enabled['ordinary_apb_access_evidence'] == {'max_records': 1}


def session(actual_factory):
    current = ScenarioSession(ScenarioGenome('ordinary-replay','CPU_TO_IP',
        'register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    current.declare_instruction_slots('cpu',0x11000,32)
    return current


def test_invalid_second_actual_target_cannot_partially_install_optional_channel(actual_factory):
    current = session(actual_factory)
    a, b = (current.runner.sessions[name] for name in ('gpio_a','gpio_b'))
    original = b.artifact
    document = deepcopy(original.runtime_document)
    document['native_physical_observation_contract']['sampling'] = 'post'
    b.artifact = replace(original, runtime_document=document)
    before = current.runner.sessions['cpu'].memory.generation
    with pytest.raises(ValueError):
        current.configure_ordinary_apb_access_evidence(max_records=1)
    assert current.runner._ordinary_apb_access_evidence is None
    assert a._ordinary_apb_receipts is None and b._ordinary_apb_receipts is None
    assert current.runner._status == 'created' and not current._begun
    assert current.runner.events == () and current.cases == ()
    assert current.runner.sessions['cpu'].memory.generation == before
    assert all(target.process is None for target in current.runner.sessions.values())


@pytest.mark.parametrize('value', (True, 0, 65537, 1.0, '1'))
def test_session_capacity_types_refuse_without_identity_or_helper_mutation(actual_factory, value):
    current = session(actual_factory)
    identity = json.dumps(current.runner.identity_document(), sort_keys=True)
    with pytest.raises(ValueError):
        current.configure_ordinary_apb_access_evidence(max_records=value)
    assert json.dumps(current.runner.identity_document(), sort_keys=True) == identity
    assert current.runner._ordinary_apb_access_evidence is None
    assert all(current.runner.sessions[name]._ordinary_apb_receipts is None for name in ('gpio_a','gpio_b'))


def test_actual_startup_optional_configuration_detaches_and_rejects_changed_reinstall(actual_factory):
    current = session(actual_factory)
    report = current.configure_ordinary_apb_access_evidence(max_records=1)
    snapshot = deepcopy(current.runner.ordinary_apb_access_evidence_snapshot())
    report.clear()
    assert current.runner.ordinary_apb_access_evidence_snapshot() == snapshot
    with pytest.raises(ValueError):
        current.configure_ordinary_apb_access_evidence(max_records=2)
    assert current.runner.ordinary_apb_access_evidence_snapshot() == snapshot
    assert current.runner.events == () and current.cases == ()


def test_rehashed_saved_terminal_state_never_restores_live_evidence(actual_factory):
    import hashlib
    from myfuzz.scenario.session_runtime import replay_online_session
    current = session(actual_factory)
    current.configure_ordinary_apb_access_evidence(max_records=1)
    adapter(current)
    current.begin()
    reference = current.finish()
    document = json.loads(current.encode_plan())
    saved = document['register_programs']['ordinary_apb_access_evidence']['state']
    saved['status'] = 'incomplete'
    saved['reason'] = 'caller_saved_claim'
    changed = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    reference = replace(reference, genome_sha256=hashlib.sha256(changed).hexdigest())
    fresh = []
    def install(candidate):
        candidate.configure_ordinary_apb_access_evidence(max_records=1)
        runtime = adapter(candidate)
        fresh.append(candidate)
        return runtime
    try:
        comparison = replay_online_session(changed, actual_factory, reference, register_runtime_factory=install)
    except ValueError:
        pass  # Closed preflight may reject before fresh execution.
    else:
        assert comparison.matches is False
    for candidate in fresh:
        state = candidate.runner.ordinary_apb_access_evidence_snapshot()
        assert state['records'] == [] and state['status'] == 'complete'
