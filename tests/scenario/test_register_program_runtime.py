import pytest

from myfuzz.scenario.register_program_runtime import validate_register_request, RegisterProgramRuntime


def request(**changes):
    row = dict(schema_version='register_program_request.v1', case_id='case',
        action_id='action', target_instance='A', endpoint_id='gpio.bus',
        register='PADOUT', field='value', operation='register_write', value=1,
        allow_side_effect=True, result_address=None, read_modify_write=False)
    row.update(changes)
    return row


def test_closed_request_detaches_and_rejects_authority_fields():
    original = request()
    validated = validate_register_request(original)
    original['value'] = 3
    assert validated['value'] == 1
    with pytest.raises(ValueError): validate_register_request(request(address_base=0))


@pytest.mark.parametrize('changes', [dict(value=True), dict(result_address=True),
    dict(allow_side_effect=1), dict(case_id=''), dict(operation='LW'),
    dict(operation='register_read', value=1, result_address=0x30000),
    dict(value=None), dict(result_address=0x30000)])
def test_request_strict_types_and_operation_shape(changes):
    with pytest.raises(ValueError): validate_register_request(request(**changes))


@pytest.fixture(scope='module')
def factory(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    return make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('render-only'),
        memory_commit_receipts=True, physical_observations=True,
        persistent_memory_runtime_contract_sha256='a'*64)


def installed(factory, *, max_program_bytes=16, images=()):
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    session = ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,(),initial_images=images),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    cpu = runner.sessions['cpu']
    cpu._case_id = 'stream'
    assert cpu._serve('instr',0,0x11000,0,15) is None
    adapter = RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},
        advance_rounds=1,max_program_bytes=max_program_bytes)
    session._begun = True
    runner._status = 'running'
    return adapter,session,runner


def test_actual_context_prepare_is_detached_and_has_no_effects(factory):
    adapter,session,runner = installed(factory)
    gate = session.prerequisite_gate
    before = (gate.document(),runner.sessions['cpu'].memory.state_summary())
    prepared = adapter.prepare(request(target_instance='gpio_a'))
    assert prepared.source.address == 0x11000
    assert prepared.document()['context']['address_base'] == runner.sessions['cpu'].router.windows[0].base
    assert len(prepared.document()['admitted_action']['prerequisites']) == 4
    prepared.document()['context'].clear()
    assert (gate.document(),runner.sessions['cpu'].memory.state_summary()) == before
    adapter.prepare(request(target_instance='gpio_a'),prepared.document())


def test_saved_context_reset_and_sidecar_drift_reject_before_registration(factory):
    adapter,session,runner = installed(factory)
    row = request(target_instance='gpio_a')
    manifest = adapter.prepare(row).document()
    runner.command_epoch += 1
    with pytest.raises(ValueError,match='manifest'): adapter.submit(row,manifest)
    assert session.prerequisite_gate.action_ids == ()
    assert adapter.snapshot()['records'] == []


def test_registration_failure_is_recorded_and_permanently_uncertain(factory,monkeypatch):
    adapter,session,runner = installed(factory)
    def fail(action): raise RuntimeError('after mutation')
    monkeypatch.setattr(session.prerequisite_gate._slot_policy,'_reserve',fail)
    with pytest.raises(RuntimeError): adapter.submit(request(target_instance='gpio_a'))
    assert adapter.snapshot()['records'][0]['status'] == 'uncertain'
    assert session.prerequisite_gate.action_ids == ('action',)
    with pytest.raises(ValueError,match='uncertain'): adapter.prepare(request(target_instance='gpio_a'))
    assert session.cases == ()


@pytest.mark.parametrize('failure', ['returned_action', 'session'])
def test_post_registration_failures_cannot_reuse_authority(factory,monkeypatch,failure):
    from dataclasses import replace
    adapter,session,runner = installed(factory)
    if failure == 'returned_action':
        original = session.prerequisite_gate.register
        def altered(action): return replace(original(action),source_id='altered',action_sha256='')
        monkeypatch.setattr(session.prerequisite_gate,'register',altered)
    else:
        def reject(case): raise ValueError('late precommand refusal')
        monkeypatch.setattr(session,'submit_case',reject)
    with pytest.raises(ValueError): adapter.submit(request(target_instance='gpio_a'))
    assert adapter.snapshot()['uncertain'] is True
    assert len(adapter.snapshot()['records']) == 1
    with pytest.raises(ValueError,match='uncertain'): adapter.submit(request(target_instance='gpio_a',action_id='new'))


@pytest.mark.parametrize('drift',['memory','gate','route','slot','artifact'])
def test_binding_drift_rejected_without_registration(factory,drift):
    from dataclasses import replace
    adapter,session,runner = installed(factory)
    cpu = runner.sessions['cpu']
    if drift == 'memory': cpu.service.memory = object()
    elif drift == 'gate': runner.persistent_memory_prerequisite_gate = object()
    elif drift == 'route': cpu.router = object()
    elif drift == 'slot': session._instruction_slots.append(('cpu',0x20000,4))
    else: runner.sessions['gpio_a'].artifact.runtime_document['drift'] = True
    with pytest.raises((ValueError,AttributeError)): adapter.prepare(request(target_instance='gpio_a'))
    assert adapter.snapshot()['records'] == []
    if drift == 'artifact': runner.sessions['gpio_a'].artifact.runtime_document.pop('drift')


@pytest.mark.parametrize('result',[0x11000,0x11070,0x40001000])
def test_read_result_cannot_cover_any_slot_or_mmio(factory,result):
    adapter,session,runner = installed(factory)
    with pytest.raises(ValueError,match='overlaps'):
        adapter.prepare(request(target_instance='gpio_a',operation='register_read',value=None,result_address=result))
    assert session.prerequisite_gate.action_ids == ()


def test_actual_session_admission_without_rtl_and_exact_retry(factory,monkeypatch):
    adapter,session,runner = installed(factory)
    cpu = runner.sessions['cpu']
    monkeypatch.setattr(runner,'step_batch',lambda schedule: None)
    row = request(target_instance='gpio_a')
    manifest = adapter.prepare(row).document()
    result = adapter.submit(row,manifest)
    assert len(session.cases) == 1
    assert result['manifest'] == manifest
    assert not cpu.memory.instruction_slot_unmaterialized(0x11000)
    assert adapter.submit(row,manifest)['receipt'] == result['receipt']
    assert len(adapter.snapshot()['records']) == 1
    runner.command_epoch += 1
    with pytest.raises(ValueError): adapter.submit(row,manifest)


def test_explicit_rmw_requires_live_larger_slot_and_budget(factory):
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    adapter,session,runner = installed(factory)
    row = request(target_instance='gpio_a',register='INTTYPE_LOW',field='pin0',
        value=2,read_modify_write=True)
    with pytest.raises(ValueError): adapter.prepare(row)
    larger,session,runner = installed(factory,max_program_bytes=36)
    prepared = larger.prepare(row)
    assert len(prepared.source.data) == 36
    assert len(prepared.document()['admitted_action']['prerequisites']) == 9


def test_fixed_image_result_refusal_and_uninitialized_ram_allowed(factory):
    from dataclasses import replace
    from myfuzz.scenario.genome import MemoryImage
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    actual,session,runner = installed(factory,images=(MemoryImage('boot','cpu',0x13000,'13000000'),))
    row = request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x13000)
    with pytest.raises(ValueError,match='overlaps'): actual.prepare(row)
    prepared = actual.prepare({**row,'result_address':0x14000})
    assert prepared.document()['program']['result_storage']['address'] == 0x14000


def test_adapter_cannot_adopt_post_begin_changed_artifacts(factory):
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    adapter,session,runner = installed(factory)
    with pytest.raises(ValueError,match='before-begin'):
        RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1)


def test_actual_initial_image_without_template_cannot_be_read_result(factory):
    adapter,session,runner = installed(factory)
    memory = runner.sessions['cpu'].memory
    memory.preload(0x13000,b'\x13\x00\x00\x00')
    before = memory.state_summary()
    with pytest.raises(ValueError,match='owned'):
        adapter.prepare(request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x13000))
    assert memory.state_summary() == before


def test_typed_cpu_profile_drift_preserving_plan_digest_is_rejected(factory):
    from dataclasses import replace
    adapter,session,runner = installed(factory)
    cpu = runner.sessions['cpu']
    original = cpu.artifact
    cpu.artifact = replace(original,plan=replace(original.plan,
        profile=replace(original.plan.profile,capabilities={**original.plan.profile.capabilities,'forged':True})))
    with pytest.raises(ValueError,match='drift'): adapter.prepare(request(target_instance='gpio_a'))
    assert session.prerequisite_gate.action_ids == ()


def test_startup_typed_profile_cannot_be_adopted_as_new_baseline(factory):
    from dataclasses import replace
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    cpu = runner.sessions['cpu']
    cpu.artifact = replace(cpu.artifact,plan=replace(cpu.artifact.plan,
        profile=replace(cpu.artifact.plan.profile,capabilities={**cpu.artifact.plan.profile.capabilities,'forged':True})))
    session = ScenarioSession(ScenarioGenome('s','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    with pytest.raises(ValueError):
        RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1)


def test_startup_route_overlap_cannot_be_adopted(factory):
    from dataclasses import replace
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    router = runner.sessions['cpu'].router
    router.windows = (router.windows[0],replace(router.windows[1],base=router.windows[0].base))
    session = ScenarioSession(ScenarioGenome('s','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    with pytest.raises(ValueError):
        RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1)


def test_waiting_key_must_match_actual_accepted_fetch(factory):
    from dataclasses import replace
    adapter,session,runner = installed(factory)
    cpu = runner.sessions['cpu']
    key,address = cpu._waiting_instr
    cpu._waiting_instr = (replace(key,source_sequence=key.source_sequence+1),address)
    with pytest.raises(ValueError,match='waiting'):
        adapter.prepare(request(target_instance='gpio_a'))
    assert session.prerequisite_gate.action_ids == ()


@pytest.mark.parametrize('changes',[dict(max_program_bytes=True),dict(advance_rounds=True),dict(max_records=True)])
def test_configuration_bounds_require_exact_integer(factory,changes):
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    session = ScenarioSession(ScenarioGenome('s','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    args = dict(cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1)
    args.update(changes)
    with pytest.raises(ValueError): RegisterProgramRuntime(session,**args)


def test_capacity_and_duplicate_preflight_never_mutate_gate(factory):
    adapter,session,runner = installed(factory)
    gate = session.prerequisite_gate
    gate.max_actions = 0
    before = (dict(gate._slot_policy._counters),dict(gate._actions))
    with pytest.raises(ValueError): adapter.submit(request(target_instance='gpio_a'))
    assert (gate._slot_policy._counters,gate._actions) == before
    gate.max_actions = 256
    session._source_ids.add('action')
    with pytest.raises(ValueError): adapter.submit(request(target_instance='gpio_a'))
    assert (gate._slot_policy._counters,gate._actions) == before


def test_late_native_gpio_contract_change_is_rejected_and_recoverable(factory):
    from dataclasses import replace
    adapter,session,runner = installed(factory)
    artifact = runner.sessions['gpio_a'].artifact
    profile = artifact.plan.profile
    runner.sessions['gpio_a'].artifact = replace(artifact,plan=replace(artifact.plan,
        profile=replace(profile,port_actions=tuple(a for a in profile.port_actions if a.port!='interrupt'))))
    with pytest.raises(ValueError): adapter.prepare(request(target_instance='gpio_a'))
    assert session.prerequisite_gate.action_ids == ()
    runner.sessions['gpio_a'].artifact = artifact
    adapter.prepare(request(target_instance='gpio_a'))


def test_startup_gate_boolean_capacity_cannot_be_adopted(factory):
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner = factory()
    runner.persistent_memory_prerequisite_gate.max_actions = True
    session = ScenarioSession(ScenarioGenome('s','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    with pytest.raises(ValueError):
        RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1)

@pytest.mark.parametrize('failure,phase', [('reservation','registration'),
    ('returned_action','registration_verification'),('session','session_submission'),
    ('appended_session','session_submission')])
def test_attempt_records_exact_phase_and_actual_case_boundary(factory,monkeypatch,failure,phase):
    from dataclasses import replace
    adapter,session,runner = installed(factory)
    if failure == 'reservation':
        def fail(action): raise RuntimeError('partial reservation')
        monkeypatch.setattr(session.prerequisite_gate._slot_policy,'_reserve',fail)
    elif failure == 'returned_action':
        original = session.prerequisite_gate.register
        def altered(action): return replace(original(action),source_id='altered',action_sha256='')
        monkeypatch.setattr(session.prerequisite_gate,'register',altered)
    else:
        def fail(case):
            if failure == 'appended_session': session._cases.append(case)
            raise RuntimeError('submission refused')
        monkeypatch.setattr(session,'submit_case',fail)
    with pytest.raises((RuntimeError,ValueError)):
        adapter.submit(request(target_instance='gpio_a'))
    record = adapter.snapshot()['records'][0]
    assert record['phase'] == phase
    assert record['case_index'] == (0 if failure == 'appended_session' else None)
    assert record['error_type'] == ('ValueError' if failure == 'returned_action' else 'RuntimeError')
    record['manifest'].clear()
    assert adapter.snapshot()['records'][0]['manifest']
    assert not adapter._successful


def test_success_records_only_actual_submitted_case_index(factory,monkeypatch):
    adapter,session,runner = installed(factory)
    monkeypatch.setattr(runner,'step_batch',lambda schedule: None)
    adapter.submit(request(target_instance='gpio_a'))
    record = adapter.snapshot()['records'][0]
    assert record['status'] == record['phase'] == 'submitted'
    assert record['case_index'] == 0
    assert 'error_type' not in record


def test_runtime_enrolls_in_session_before_begin(factory):
    adapter,session,runner = installed(factory)
    assert session._register_program_runtime is adapter


@pytest.mark.parametrize('failure',[False,True])
def test_submission_token_exists_only_during_actual_session_call(factory,monkeypatch,failure):
    adapter,session,runner = installed(factory)
    row = request(target_instance='gpio_a')
    seen=[]
    original=session.submit_case
    monkeypatch.setattr(runner,'step_batch',lambda schedule: None)
    def submit(case):
        seen.append(adapter._active_submission)
        assert adapter._active_submission[0] is case
        assert adapter._active_submission[1] == adapter._records[-1]['manifest']
        if failure: raise ValueError('submission boundary')
        return original(case)
    monkeypatch.setattr(session,'submit_case',submit)
    assert adapter._active_submission is None
    if failure:
        with pytest.raises(ValueError,match='boundary'): adapter.submit(row)
    else: adapter.submit(row)
    assert len(seen)==1
    assert adapter._active_submission is None


@pytest.mark.parametrize('key',['case_id','action_id','target_instance','endpoint_id','register','field'])
def test_request_text_is_bounded_before_any_runtime_action(key):
    with pytest.raises(ValueError,match='request-text'):
        validate_register_request(request(**{key:'x'*257}))
    assert validate_register_request(request(**{key:'x'*256}))[key]=='x'*256


def test_uncertain_registration_halts_other_session_commands(factory,monkeypatch):
    adapter,session,runner = installed(factory)
    def fail(action): raise RuntimeError('partial reserve')
    monkeypatch.setattr(session.prerequisite_gate._slot_policy,'_reserve',fail)
    with pytest.raises(RuntimeError): adapter.submit(request(target_instance='gpio_a'))
    assert session._halted
    assert session._halt_reason=='uncertain_effect'
    with pytest.raises(RuntimeError,match='active pre-case'):
        session.advance_initial(session.template.schedule_order)


@pytest.mark.parametrize('changes',[
    dict(register='PADCFG_0',field='pin7',value=5,read_modify_write=True,allow_side_effect=False),
    dict(operation='register_read',value=None,result_address=0x14000,allow_side_effect=False)])
def test_narrow_rmw_and_read_admissions_have_valid_closed_saved_projection(factory,monkeypatch,changes):
    import json
    from myfuzz.scenario.session_runtime import validate_register_program_plan,validate_register_program_state
    adapter,session,runner = installed(factory,max_program_bytes=64)
    monkeypatch.setattr(runner,'step_batch',lambda order:None)
    adapter.submit(request(target_instance='gpio_a',**changes))
    document=json.loads(session.encode_plan())
    assert document['schema_version']==16
    registers=validate_register_program_plan(document)
    assert validate_register_program_state(adapter.snapshot(),registers)==adapter.snapshot()
