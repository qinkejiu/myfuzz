"""Independent actual-object software boundaries; never start RTL."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from myfuzz.composition.ip_test_levels import MinimumCapabilityLevelError
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
from myfuzz.scenario.session_runtime import ScenarioSession


@pytest.fixture(scope='module')
def actual_factory(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    return make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('independent-capability-render'),
        memory_commit_receipts=True, physical_observations=True,
        persistent_memory_runtime_contract_sha256='a' * 64)


def installed(factory, size=64):
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    session = ScenarioSession(ScenarioGenome('capability-boundary', 'CPU_TO_IP',
        'register_program', ('cpu', 'gpio_a', 'gpio_b'), 144, ()), runner)
    session.declare_instruction_slots('cpu', 0x11000, 64)
    adapter = RegisterProgramRuntime(session, cpu_component='cpu',
        sidecars={'gpio_a': SIDECAR, 'gpio_b': SIDECAR},
        advance_rounds=1, max_program_bytes=size)
    return adapter, session, runner


def untouched(session, runner, adapter):
    cpu = runner.sessions['cpu']
    return deepcopy((session.prerequisite_gate.document(), cpu.memory.state_summary(),
        adapter.snapshot(), runner.command_epoch, cpu._waiting_instr,
        cpu.router.acceptances, cpu.router.deliveries, session._cases,
        session._instruction_slots, session._register_capability_preflight_json,
        session._register_capability_sources_json, tuple(s.process for s in runner.sessions.values())))


def req(**changes):
    row = dict(schema_version='register_program_request.v1', case_id='boundary-case',
        action_id='boundary-action', target_instance='gpio_a', endpoint_id='gpio.bus',
        register='PADOUT', field='value', operation='register_write', value=1,
        allow_side_effect=False, result_address=None, read_modify_write=False)
    row.update(changes)
    return row


def conditions(doc, alias='gpio_a'):
    return doc['targets'][alias]['operation_conditions']


def test_complete_sidecar_partial_support_cannot_meet_aggregate_l2_without_mutation(actual_factory):
    adapter, session, runner = installed(actual_factory)
    before = untouched(session, runner, adapter)
    doc = adapter.capability_preflight()
    assert set(doc['targets']) == {'gpio_a', 'gpio_b'}
    assert doc['verification'] is None and doc['grants_functional'] is False
    for alias, target in doc['targets'].items():
        assert target['target_instance'] == alias
        assessment = target['assessment']
        assert assessment['effective_level'] == 'L1'
        assert assessment['verified_level'] is None
        assert all(row['verified'] is False and row['evidence_refs'] == []
                   for row in assessment['support_matrix'])
        assert any(row['level'] == 'L2' and row['declared'] and not row['effective']
                   for row in assessment['support_matrix'])
    with pytest.raises(MinimumCapabilityLevelError):
        adapter.capability_preflight(requested_minimum_level='L2')
    with pytest.raises(MinimumCapabilityLevelError):
        session.configure_register_capability_preflight(requested_minimum_level='L2')
    assert untouched(session, runner, adapter) == before


def test_rmw_and_narrow_read_conditions_use_actual_program_budget(actual_factory):
    small, _, _ = installed(actual_factory, size=16)
    large, _, _ = installed(actual_factory, size=64)
    for adapter, expected in [(small, False), (large, True)]:
        doc = adapter.capability_preflight()
        narrow = [c for c in conditions(doc) if c['scope'] == 'INTTYPE_LOW.pin0'
                  and c['operation'] == 'register_write']
        assert bool(narrow) is expected
        if narrow:
            assert narrow[0]['read_modify_write'] is True and narrow[0]['program_bytes'] == 36
        reads=[c for c in conditions(doc) if c['scope']=='INTTYPE_LOW.pin0'
               and c['operation']=='register_read']
        assert bool(reads) is expected
        if reads:assert reads[0]['program_bytes']==20 and reads[0]['read_modify_write'] is False


def test_same_profile_targets_cannot_swap_actual_router_authority(actual_factory):
    adapter, session, runner = installed(actual_factory)
    assert runner.sessions['gpio_a'].artifact.plan.profile.profile_fingerprint == \
        runner.sessions['gpio_b'].artifact.plan.profile.profile_fingerprint
    doc = adapter.capability_preflight()
    cpu = runner.sessions['cpu']; windows = cpu.router.windows
    cpu.router.windows = tuple(replace(w, target=runner.sessions['gpio_b'])
        if w.device_id == 'gpio_a' else w for w in windows)
    for _ in range(2):
        with pytest.raises(ValueError): adapter.capability_preflight()
    cpu.router.windows = windows
    assert adapter.capability_preflight() == doc
    assert session.prerequisite_gate.action_ids == ()


def test_detached_forged_assessment_cannot_modify_actual_preflight_or_grant_verification(actual_factory):
    adapter, session, runner = installed(actual_factory)
    original = adapter.capability_preflight()
    forged = deepcopy(original)
    for target in forged['targets'].values():
        target['assessment']['effective_level'] = 'L2'
        target['assessment']['verified_level'] = 'L2'
        for row in target['assessment']['support_matrix']:
            row['effective'] = row['verified'] = True
            row['evidence_refs'] = ['dependency_evidence:saved-foreign-reference']
    assert adapter.capability_preflight() == original
    with pytest.raises(MinimumCapabilityLevelError):
        session.configure_register_capability_preflight(requested_minimum_level='L2')
    assert session.prerequisite_gate.action_ids == ()


def test_preflight_query_default_off_keeps_saved_plan_byte_layout(actual_factory):
    adapter, session, _ = installed(actual_factory)
    before = session.encode_plan()
    adapter.capability_preflight()
    assert session.encode_plan() == before
    plan = json.loads(before)
    assert 'capability_preflight' not in plan['register_programs']
    assert 'register_capability_preflight' not in plan
    assert 'requested_minimum_level' not in adapter.configuration()


@pytest.mark.parametrize('declaration', [req(register='INTTYPE_LOW', field='pin0', value=2),
    req(register='PADOUTSET', field='bits', value=1)])
def test_effective_operation_does_not_replace_per_request_consent(actual_factory, declaration):
    adapter, session, runner = installed(actual_factory)
    adapter.capability_preflight()
    cpu = runner.sessions['cpu']; cpu._case_id = 'independent-stream'
    assert cpu._serve('instr', 0, 0x11000, 0, 15) is None
    session._begun = True; runner._status = 'running'
    before = untouched(session, runner, adapter)
    with pytest.raises(ValueError): adapter.prepare(declaration)
    assert untouched(session, runner, adapter) == before


def test_failed_source_closure_capture_does_not_publish_half_configured_preflight(actual_factory, monkeypatch):
    import myfuzz.scenario.session_runtime as runtime
    adapter, session, runner = installed(actual_factory)
    before = untouched(session, runner, adapter)
    real = runtime._register_capability_source_files
    def missing_closure():
        raise FileNotFoundError('capability source vanished before startup publication')
    monkeypatch.setattr(runtime, '_register_capability_source_files', missing_closure)
    with pytest.raises(FileNotFoundError):
        session.configure_register_capability_preflight(requested_minimum_level='L1')
    assert untouched(session, runner, adapter) == before
    monkeypatch.setattr(runtime, '_register_capability_source_files', real)
    assert session.configure_register_capability_preflight(requested_minimum_level='L1')['requested_minimum_level'] == 'L1'


@pytest.mark.parametrize('phase', ['prepare', 'submit', 'retry'])
def test_capability_source_identity_drift_after_begin_refuses_before_registration(actual_factory, monkeypatch, phase):
    import myfuzz.scenario.session_runtime as runtime
    adapter, session, runner = installed(actual_factory)
    session.configure_register_capability_preflight(requested_minimum_level='L1')
    cpu = runner.sessions['cpu']; cpu._case_id = 'independent-stream'
    assert cpu._serve('instr', 0, 0x11000, 0, 15) is None
    session._begun = True; runner._status = 'running'
    monkeypatch.setattr(runner, 'step_batch', lambda order: None)
    if phase == 'retry':
        adapter.submit(req())
    before = untouched(session, runner, adapter)
    source_files = deepcopy(runtime._register_capability_source_files())
    source_files[0]['sha256'] = '0' * 64
    monkeypatch.setattr(runtime, '_register_capability_source_files', lambda: deepcopy(source_files))
    with pytest.raises(ValueError, match='capability|configuration'):
        getattr(adapter, 'submit' if phase == 'retry' else phase)(req())
    assert untouched(session, runner, adapter) == before


def test_actual_legacy_without_native_trace_reports_only_valid_capability_gaps(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    from myfuzz.scenario.register_program_capabilities import validate_register_capability_preflight_document
    legacy = make_ibex_pulp_dual_source_factory(tmp_path / 'legacy-render',
        memory_commit_receipts=True, physical_observations=False,
        persistent_memory_runtime_contract_sha256='a' * 64)
    adapter, session, runner = installed(legacy)
    assert all(target.artifact.runtime_document.get('base_protocol_trace') is None
               for target in (runner.sessions['gpio_a'], runner.sessions['gpio_b']))
    before = untouched(session, runner, adapter)
    report = adapter.capability_preflight()
    assert validate_register_capability_preflight_document(
        report, configuration=adapter.configuration()) == report
    assert report['verification'] is None
    for target in report['targets'].values():
        assert target['operation_conditions'] == []
        assert target['assessment']['effective_level'] is None
        assert target['assessment']['verified_level'] is None
        assert target['assessment']['gaps']
        assert all(not row['effective'] and not row['verified']
                   for row in target['assessment']['support_matrix'])
    assert untouched(session, runner, adapter) == before
