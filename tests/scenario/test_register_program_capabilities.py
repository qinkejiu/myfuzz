import pytest
from tests.scenario.test_register_program_runtime import factory, installed


def test_actual_preflight_is_detached_without_waiting_or_effects(factory):
    adapter, session, runner = installed(factory, max_program_bytes=36)
    cpu = runner.sessions['cpu']
    cpu._waiting_instr = None
    before = (session.prerequisite_gate.document(), cpu.memory.state_summary(), runner.command_epoch)
    doc = adapter.capability_preflight()
    assert doc['schema_version'] == 'register_program_capability_preflight.v1'
    assert doc['verification'] is None
    assessment = doc['targets']['gpio_a']['assessment']
    assert assessment['declared_level'] == 'L2'
    assert assessment['effective_level'] == 'L1'
    assert assessment['verified_level'] is None
    rows = assessment['support_matrix']
    assert any(r['scope'] == 'INTTYPE_LOW.pin0' and r['operation'] == 'register_write' and r['effective'] for r in rows)
    assert any(r['scope'] == 'INTTYPE_LOW.pin0' and r['operation'] == 'register_read' and r['effective'] for r in rows)
    assert (session.prerequisite_gate.document(), cpu.memory.state_summary(), runner.command_epoch) == before
    doc['targets'].clear()
    assert adapter.capability_preflight()['targets']


def test_actual_minimum_and_rmw_capacity_are_honest(factory):
    adapter, _, _ = installed(factory)
    doc = adapter.capability_preflight(requested_minimum_level='L1')
    rows = doc['targets']['gpio_a']['assessment']['support_matrix']
    assert not any(r['scope'] == 'INTTYPE_LOW.pin0' and r['effective'] for r in rows)
    for level in ('L2', 'L3'):
        with pytest.raises(ValueError, match='requested-minimum-not-met'):
            adapter.capability_preflight(requested_minimum_level=level)
    for level in (True, 1, 'L0'):
        with pytest.raises(ValueError): adapter.capability_preflight(requested_minimum_level=level)


def test_preflight_rechecks_actual_configuration(factory):
    adapter, session, _ = installed(factory)
    adapter.capability_preflight()
    session._instruction_slots.clear()
    with pytest.raises(ValueError, match='binding-drift'): adapter.capability_preflight()


def test_saved_preflight_validator_is_closed_and_configuration_bound(factory):
    from copy import deepcopy
    from myfuzz.scenario.register_program_capabilities import validate_register_capability_preflight_document
    adapter, _, _ = installed(factory, max_program_bytes=36)
    doc = adapter.capability_preflight()
    assert validate_register_capability_preflight_document(doc, configuration=adapter.configuration()) == doc
    for mutate in (
        lambda d: d.update(extra=True),
        lambda d: d.update(verification={}),
        lambda d: d.update(configuration_sha256='0'*64),
        lambda d: d['targets']['gpio_a']['assessment'].update(verified_level='L2'),
        lambda d: d['targets']['gpio_a']['assessment']['support_matrix'][0].update(evidence_refs=['saved']),
        lambda d: d['targets']['gpio_a']['operation_conditions'][0].update(program_bytes=True),
    ):
        bad = deepcopy(doc); mutate(bad)
        with pytest.raises(ValueError): validate_register_capability_preflight_document(bad, configuration=adapter.configuration())


def test_exhausted_slots_do_not_report_register_operations(factory):
    adapter, session, runner = installed(factory,max_program_bytes=36)
    memory = runner.sessions['cpu'].memory
    for address in range(0x11000,0x11080,4):
        memory.accept_instructions(address,b'\x13\x00\x00\x00',source_event_id='materialize')
    doc = adapter.capability_preflight()
    assert not doc['targets']['gpio_a']['operation_conditions']


def test_full_gate_capacity_does_not_claim_new_register_programs(factory):
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    session = ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    session.prerequisite_gate.max_actions = 1
    adapter = RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR,'gpio_b':SIDECAR},
        advance_rounds=1,max_program_bytes=36)
    before = adapter.capability_preflight()
    assert set(before['targets']) == {'gpio_a','gpio_b'}
    # A genuine compiled action fills the actual installed gate's capacity.
    # Use an actual prepared action instead of altering provider documents.
    cpu = runner.sessions['cpu']; cpu._case_id='stream'
    cpu._serve('instr',0,0x11000,0,15)
    session._begun=True; runner._status='running'
    from tests.scenario.test_register_program_runtime import request
    prepared = adapter.prepare(request(target_instance='gpio_a'))
    from myfuzz.scenario.source_actions import SourceAction
    session.prerequisite_gate.register(SourceAction.from_document(prepared.document()['source_action']))
    after = adapter.capability_preflight()
    assert all(not target['operation_conditions'] for target in after['targets'].values())


@pytest.mark.parametrize('change', ['unknown_operation','condition_scope_object','claim_scope','minimum','row_level'])
def test_saved_preflight_rejects_nonclosed_claims(factory,change):
    from myfuzz.scenario.register_program_capabilities import validate_register_capability_preflight_document
    adapter,_,_ = installed(factory,max_program_bytes=36)
    doc = adapter.capability_preflight()
    target = doc['targets']['gpio_a']
    if change == 'unknown_operation': target['assessment']['support_matrix'][0]['operation']='arbitrary'
    elif change == 'condition_scope_object': target['operation_conditions'][0]['scope']={}
    elif change == 'claim_scope':
        claim = next(c for c in target['runtime_support']['endpoint_operations'] if c['scope'])
        claim['scope']='not-a-field'
    elif change == 'minimum':
        doc['requested_minimum_level']='L2';target['assessment']['requested_minimum_level']='L2';target['assessment']['minimum_level_met']=True
    else: target['assessment']['support_matrix'][0]['level']='L3'
    with pytest.raises(ValueError): validate_register_capability_preflight_document(doc,configuration=adapter.configuration())
