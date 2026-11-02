import pytest

@pytest.fixture(scope='module', autouse=True)
def discovery_scope():
    from myfuzz.local_harness.build import host_source_discovery_scope
    with host_source_discovery_scope(reuse_nested=True):
        yield


def test_external_declarations_are_closed_and_rebuilt():
    from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder, validate_external_sources
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    declarations = external_pin_sources_from_decoder(make_ibex_pulp_dual_source_online_decoder())
    assert declarations[0].document()['source']['source_id'] == 'gpio_b.external_pin8'
    assert validate_external_sources([d.document() for d in declarations]) == tuple(d.document() for d in declarations)
    bad = [dict(declarations[0].document(), arbitrary_permission=True)]
    with pytest.raises(ValueError):
        validate_external_sources(bad)


def test_external_request_has_no_authority_fields():
    from myfuzz.scenario.mixed_external_runtime import validate_external_request
    request = dict(schema_version='external_pin_request.v1', case_id='pin', action_id='pin:source',
                   source_id='gpio_b.external_pin8', value=1)
    assert validate_external_request(request) == request
    for change in ({'value': True}, {'address': 0}, {'source_id': ''}):
        with pytest.raises(ValueError):
            validate_external_request(dict(request, **change))

@pytest.fixture(scope='module')
def factory(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_online_decoder
    return make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('mixed-render'),
        memory_commit_receipts=True,physical_observations=True,
        persistent_memory_runtime_contract_sha256=make_ibex_pulp_dual_source_online_decoder().runtime_contract.identity_sha256)



def test_external_prepare_uses_actual_waiting_slots_and_gate(factory):
    from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder, validate_external_manifest
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.genome import ScenarioGenome
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    runner=factory()
    session=ScenarioSession(ScenarioGenome('mixed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    cpu._serve('instr',0,0x11000,0,15)
    runtime=RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR,'gpio_b':SIDECAR},
        advance_rounds=1,external_sources=external_pin_sources_from_decoder(make_ibex_pulp_dual_source_online_decoder()))
    session._begun=True;runner._status='running'
    request=dict(schema_version='external_pin_request.v1',case_id='pin',action_id='pin:source',source_id='gpio_b.external_pin8',value=1)
    prepared=runtime.prepare_external(request)
    assert prepared.case.support_instructions[0].address==0x11000
    assert session.prerequisite_gate.action_ids==()
    validate_external_manifest(prepared.document(),runtime.configuration())
    from dataclasses import replace
    from myfuzz.scenario.source_actions import SourceAction, instruction_slot_unmaterialized_prerequisite
    altered=prepared.document()
    support_action=SourceAction.from_document(altered['support_actions'][0])
    prerequisites=list(support_action.prerequisites)
    prerequisites[0]=instruction_slot_unmaterialized_prerequisite('cpu',0x11100,'wrong-reservation')
    altered['support_actions']=[replace(support_action,prerequisites=tuple(prerequisites),action_sha256='').document()]
    with pytest.raises(ValueError,match='support'):
        validate_external_manifest(altered,runtime.configuration())
    # Exercise the real gate and session guard, stopping before any native command.
    gate=session.prerequisite_gate
    gate.register(__import__('myfuzz.scenario.source_actions',fromlist=['SourceAction']).SourceAction.from_document(prepared.document()['source_action']))
    support=gate.register_support_instruction(prepared.case.support_instructions[0],flow_id='F5',local_step_budget=3)
    assert support.document()==prepared.document()['support_actions'][0]
    cpu._waiting_instr=None
    with pytest.raises(ValueError,match='waiting'):
        runtime.prepare_external(dict(request,case_id='other',action_id='other'))

@pytest.fixture(scope='module')
def actual_factory(factory):
    def software():
        runner=factory()
        def begin(case_id):
            runner._status='running'
            cpu=runner.sessions['cpu'];cpu._case_id='stream'
            cpu._serve('instr',0,0x11000,0,15)
        runner.begin_test=begin
        runner.step_batch=lambda order:None
        runner.finalize=lambda:None
        return runner
    return software



def test_external_submit_exports_and_fresh_rebuilds_full_prefix(actual_factory):
    import json
    from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session
    from myfuzz.scenario.genome import ScenarioGenome
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    def install(session):
        return RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR,'gpio_b':SIDECAR},
            advance_rounds=3,external_sources=external_pin_sources_from_decoder(make_ibex_pulp_dual_source_online_decoder()))
    session=ScenarioSession(ScenarioGenome('mixed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime=install(session);session.begin()
    request=dict(schema_version='external_pin_request.v1',case_id='pin',action_id='pin:source',source_id='gpio_b.external_pin8',value=1)
    result=runtime.submit_external(request,stop_after_advance=lambda index:index==0)
    assert result['manifest']['schema_version']=='external_pin_runtime_manifest.v2'
    assert result['manifest']['configuration_sha256']==runtime.configuration_sha256
    assert 'configuration' not in result['manifest']
    assert len(session.cases)==1
    assert runtime.submit_external(request)==result
    trace=session.finish();plan=session.encode_plan()
    assert len(json.loads(plan)['cases'][0]['advances'])==1
    config_schema='\"schema_version\":\"register_program_runtime_configuration.v1\"'
    assert plan.decode().count(config_schema)==1
    state_text=json.dumps(runtime.snapshot(),sort_keys=True,separators=(',',':'))
    assert state_text.count(config_schema)==1
    assert replay_online_session(plan,actual_factory,trace,register_runtime_factory=install).matches
    # Even a fully rehashed saved plan cannot use the reference as authority.
    from dataclasses import replace
    from hashlib import sha256
    changed=json.loads(plan)
    changed['register_programs']['case_manifests'][0]['configuration_sha256']='0'*64
    damaged=json.dumps(changed,sort_keys=True,separators=(',',':')).encode()
    forged_reference=replace(trace,genome_sha256=sha256(damaged).hexdigest())
    def forbidden_factory():
        raise AssertionError('bad saved reference must fail before construction')
    with pytest.raises(ValueError,match='configuration'):
        replay_online_session(damaged,forbidden_factory,forged_reference,register_runtime_factory=install)


def test_saved_external_declaration_cannot_install_live_binding():
    from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder, bind_external_sources
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    decoder=make_ibex_pulp_dual_source_online_decoder()
    declarations=external_pin_sources_from_decoder(decoder)
    with pytest.raises(ValueError,match='live'):
        bind_external_sources(tuple(d.document() for d in declarations))
    decoder.support_words+=1
    with pytest.raises(ValueError,match='drift'):
        bind_external_sources(declarations)


def new_mixed_session(factory):
    from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.genome import ScenarioGenome
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    session=ScenarioSession(ScenarioGenome('mixed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime=RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR,'gpio_b':SIDECAR},advance_rounds=1,
        external_sources=external_pin_sources_from_decoder(make_ibex_pulp_dual_source_online_decoder()))
    session.begin()
    return runtime,session


def pin_request(**changes):
    row=dict(schema_version='external_pin_request.v1',case_id='pin',action_id='pin:source',source_id='gpio_b.external_pin8',value=1)
    return dict(row,**changes)


def test_prepared_external_document_never_grants_direct_submission(actual_factory):
    runtime,session=new_mixed_session(actual_factory)
    prepared=runtime.prepare_external(pin_request())
    with pytest.raises(ValueError,match='direct-byte'):
        session.submit_case(prepared.case)
    assert runtime.snapshot()['records']==[]
    assert session.prerequisite_gate.action_ids==()


@pytest.mark.parametrize('failure',['support_registration','step'])
def test_external_uncertain_prefix_replays_without_authorizing_saved_bytes(actual_factory,failure):
    import json
    from myfuzz.scenario.session_runtime import replay_online_session
    def fresh_factory():
        runner=actual_factory()
        def fail(*args,**kwargs):
            raise RuntimeError('software failure')
        if failure=='support_registration':
            runner.persistent_memory_prerequisite_gate._slot_policy._reserve=fail
        else:
            runner.step_batch=fail
        return runner
    runtime,session=new_mixed_session(fresh_factory)
    with pytest.raises(RuntimeError,match='software failure'):
        runtime.submit_external(pin_request())
    assert runtime.snapshot()['uncertain']
    assert len(session.cases)==(0 if failure=='support_registration' else 1)
    with pytest.raises(ValueError,match='uncertain'):
        runtime.prepare_external(pin_request(case_id='retry',action_id='retry'))
    trace=session.finish();plan=session.encode_plan()
    assert json.loads(plan)['register_programs']['terminal_attempt']['status']=='uncertain'
    def install(fresh_session):
        from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
        from myfuzz.scenario.mixed_external_runtime import external_pin_sources_from_decoder
        from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
        from tests.composition.test_pulp_gpio_test_capability import SIDECAR
        return RegisterProgramRuntime(fresh_session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR,'gpio_b':SIDECAR},advance_rounds=1,
            external_sources=external_pin_sources_from_decoder(make_ibex_pulp_dual_source_online_decoder()))
    assert replay_online_session(plan,fresh_factory,trace,register_runtime_factory=install).matches


def test_external_requires_original_runtime_contract_and_actual_ownership(actual_factory):
    runtime,session=new_mixed_session(actual_factory)
    original=runtime.external_sources
    runtime.external_sources=tuple(dict(row,runtime_contract_sha256='b'*64) for row in original)
    with pytest.raises(ValueError,match='drift'):
        runtime.prepare_external(pin_request())
    runtime.external_sources=original
    cpu=session.runner.sessions['cpu']
    cpu._request_evidence['instr']['aligned_address']+=4
    with pytest.raises(ValueError,match='waiting'):
        runtime.prepare_external(pin_request())
    assert runtime.snapshot()['records']==[]


def test_mixed_cpu_manifest_is_compact_and_pinned_to_outer_configuration(actual_factory):
    from tests.scenario.test_register_program_runtime import request
    from myfuzz.scenario.session_runtime import _validate_register_manifest
    runtime,session=new_mixed_session(actual_factory)
    prepared=runtime.prepare(request(target_instance='gpio_a'))
    manifest=prepared.document()
    assert manifest['schema_version']=='register_program_runtime_manifest.v2'
    assert manifest['configuration_sha256']==runtime.configuration_sha256
    assert 'configuration' not in manifest
    config=runtime.configuration()
    _validate_register_manifest(manifest,config)
    for value in ('0'*64,True,'invalid'):
        altered=dict(manifest,configuration_sha256=value)
        with pytest.raises(ValueError,match='configuration'):
            _validate_register_manifest(altered,config)
    with pytest.raises(ValueError,match='configuration'):
        _validate_register_manifest(dict(manifest,configuration=config),config)


def test_compact_schema_does_not_enable_ordinary_register_mode():
    from myfuzz.scenario.mixed_external_runtime import normalize_manifest_configuration
    with pytest.raises(ValueError,match='configuration'):
        normalize_manifest_configuration(dict(schema_version='register_program_runtime_manifest.v2',
            configuration_sha256='0'*64),dict(external_sources=[]))


def test_ordinary_register_manifest_keeps_original_v1_shape(factory):
    from tests.scenario.test_register_program_runtime import installed, request
    runtime,session,runner=installed(factory)
    manifest=runtime.prepare(request(target_instance='gpio_a')).document()
    assert manifest['schema_version']=='register_program_runtime_manifest.v1'
    assert manifest['configuration']==runtime.configuration()
    assert 'configuration_sha256' not in manifest
