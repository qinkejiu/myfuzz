"""Closed ordinary observation opt-in; software-only integration."""
from copy import deepcopy
from unittest.mock import Mock,patch
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api

def test_default_assembly_unchanged_explicit_ordinary_config_closed():
    default=api.make_register_assembly()
    assert 'ordinary_apb_access_evidence' not in default
    enabled=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':256})
    assert enabled['ordinary_apb_access_evidence']=={'max_records':256}
    for bad in (None,False,True,{}, {'max_records':True},{'max_records':0},{'max_records':65537},{'max_records':1,'provider':'arbitrary'}):
        with pytest.raises(ValueError):api.make_register_assembly(ordinary_apb_access_evidence=bad)

def test_installer_ordinary_configuration_precedes_actual_adapter():
    assembly=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8})
    order=[];session=Mock()
    session.configure_ordinary_apb_access_evidence.side_effect=lambda **kwargs:order.append(('ordinary',kwargs))
    with patch('myfuzz.scenario.register_program_runtime.RegisterProgramRuntime',side_effect=lambda *args,**kwargs:order.append(('adapter',kwargs)) or Mock()):
        api.make_register_runtime_factory(assembly)(session)
    assert [kind for kind,_ in order]==['ordinary','adapter']
    assert order[0][1]=={'max_records':8}

def test_ordinary_channel_must_agree_before_factory_or_directory_creation():
    assembly=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8})
    for declaration,plan,manifest in ((assembly,{'register_programs':{}},{}),
        (api.make_register_assembly(),{'register_programs':{'ordinary_apb_access_evidence':{}}},{})):
        with pytest.raises(ValueError,match='presence'):
            api._verify_ordinary_channel(declaration,plan,manifest)

def test_ordinary_source_closure_is_conditional_and_default_unchanged():
    default=api.make_register_assembly()
    assert api._sources(default)==api._sources()
    enabled=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8})
    paths={row['path'] for row in api._sources(enabled)}
    assert 'src/myfuzz/local_harness/ordinary_apb_access_receipts.py' in paths
    assert 'src/myfuzz/scenario/ordinary_apb_access_evidence.py' in paths
    assert {row['path'] for row in api._sources()}<=paths

def test_ordinary_option_combines_with_capability_without_changing_default_result():
    assembly=api.make_register_assembly(requested_minimum_level='L1',
        ordinary_apb_access_evidence={'max_records':8})
    assert api.validate_register_assembly(assembly)==assembly
    result=api.RegisterReplayResult(Mock(),None,('existing_scope',))
    assert result.verification_scope==('existing_scope',)
    assert result.ordinary_apb_access_evidence is None

def test_consistently_changed_target_report_cannot_strip_foreign_identity():
    import hashlib
    trace={'actual':'native trace'}
    config={'target_instance':'gpio_a','native_trace_sha256':hashlib.sha256(api._json(trace).encode()).hexdigest()}
    identity={'ordinary_apb_access_receipts':deepcopy(config),'runtime_artifact':{'base_protocol_trace':trace}}
    # Both copies agree, but the artifact trace remains the independently bound input.
    identity['ordinary_apb_access_receipts']['native_trace_sha256']='0'*64
    forged=deepcopy(identity['ordinary_apb_access_receipts'])
    with pytest.raises(ValueError,match='target observation identity mismatch'):
        api._verify_ordinary_gpio_identity('gpio_a',identity,forged)
    forged=deepcopy(config)
    forged['target_instance']='gpio_b';identity['ordinary_apb_access_receipts']=deepcopy(forged)
    with pytest.raises(ValueError,match='target observation identity mismatch'):
        api._verify_ordinary_gpio_identity('gpio_a',identity,forged)

def test_writer_checks_target_identity_before_creating_directory(tmp_path):
    import json
    assembly=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8})
    configuration={}
    plan={'schema_version':16,'register_programs':{'configuration':configuration,
        'ordinary_apb_access_evidence':{'configuration':{'targets':{'gpio_a':{'target_instance':'gpio_a'}}}}}}
    manifest={'checker':None,'runtime_paths':None,'register_program_configuration':configuration,
        'runner':{'sessions':{'gpio_a':{'identity':{
            'ordinary_apb_access_receipts':{'target_instance':'gpio_b'},
            'runtime_artifact':{'base_protocol_trace':{}}}}}}}
    state={'configuration':configuration}
    output=tmp_path/'must_not_exist'
    # Isolate writer sequencing; selector's shared semantic verifier is real.
    with patch.object(api,'_validate_reference'),patch.object(api,'_verify_assembly_configuration'), \
         patch.object(api,'_validate_saved_register_documents',return_value=state), \
         patch.object(api,'_verify_capability_channel'),patch.object(api,'_verify_ordinary_channel'):
        with pytest.raises(ValueError,match='target observation identity mismatch'):
            api.save_ibex_pulp_register_bundle(output_dir=output,assembly=assembly,
                session_manifest=manifest,plan_bytes=json.dumps(plan).encode(),trace=Mock(),runtime_state=state)
    assert not output.exists()

def software_factory(factory):
    """Decode the admitted closed word fragment as a software bus driver, never RTL."""
    from tests.scenario.test_ordinary_apb_access_runner import physical_transport
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    def create():
        runner=factory();executed=set()
        for name in ('gpio_a','gpio_b'):
            target=runner.sessions[name];target.step_local=lambda inputs:{}
        def begin(case_id):
            for name in ('gpio_a','gpio_b'):physical_transport(runner.sessions[name])
            runner._status='running';cpu=runner.sessions['cpu'];cpu._case_id='stream'
            cpu._serve('instr',0,bootstrap.instruction_start,0,15)
        def steps(order):
            adapter=runner._test_session._register_program_runtime
            active=adapter._active_submission
            if active is None:return
            source=active[1]['program']['source']
            if source['action_id'] in executed:return
            executed.add(source['action_id']);registers=[0]*32;cpu=runner.sessions['cpu']
            raw=bytes.fromhex(source['data_hex'])
            for offset in range(0,len(raw),4):
                word=int.from_bytes(raw[offset:offset+4],'little');opcode=word&127
                rd=(word>>7)&31;rs1=(word>>15)&31;rs2=(word>>20)&31
                if opcode==0x37:registers[rd]=word&0xfffff000
                elif opcode==0x13:
                    immediate=word>>20;immediate-=4096 if immediate&2048 else 0
                    registers[rd]=(registers[rs1]+immediate)&0xffffffff
                elif opcode in (0x23,0x03):
                    immediate=((word>>25)<<5)|((word>>7)&31) if opcode==0x23 else word>>20
                    immediate-=4096 if immediate&2048 else 0
                    address=(registers[rs1]+immediate)&0xffffffff
                    cpu._pending_data=None
                    response=cpu._serve('data',int(opcode==0x23),address,registers[rs2] if opcode==0x23 else 0,15)
                    runner._append_external_events('cpu',len(runner._events))
                    if cpu.router.owns(address):
                        window=next(window for window in cpu.router.windows if window.base<=address<window.base+window.size)
                        runner._step_once(window.device_id)
                        response=cpu._pending_data
                    if opcode==0x03:registers[rd]=response[0]
                    cpu._pending_data=None
                else:raise AssertionError('software fixture only supports compiler closed LUI/ADDI/SW/LW')
        runner.begin_test=begin;runner.step_batch=steps;runner.finalize=lambda:None
        return runner
    return create


def test_nonempty_actual_association_survives_authenticated_bundle_and_fresh_requests(tmp_path,monkeypatch):
    import hashlib,json
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    from tests.scenario.test_register_program_runtime import request
    assembly=api.make_register_assembly(advance_rounds=1,ordinary_apb_access_evidence={'max_records':8})
    factory=software_factory(api.make_register_factory(cache_dir=tmp_path/'render',assembly=assembly))
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    adapter=api.make_register_runtime_factory(assembly)(session)
    session.begin();adapter.submit(request(target_instance='gpio_a',value=9));trace=session.finish();plan=session.encode_plan()
    state=session.runner.ordinary_apb_access_evidence_snapshot()
    assert state['counts']['cpu_delivery_confirmed']==1
    assert state['records'][0]['raw_event_refs'] and state['records'][0]['base_event_refs']
    assert state['records'][0]['grants_verified'] is False
    # Authenticated envelopes do not make malformed comparison data admissible.
    document=json.loads(plan)
    bad=deepcopy(document)
    bad['register_programs']['ordinary_apb_access_evidence']['state']['records'][0]['raw_event_refs']=[True]
    with pytest.raises(ValueError):
        api._verify_ordinary_channel(assembly,bad,session.manifest_document)
    bad_manifest=deepcopy(session.manifest_document)
    bad_manifest['ordinary_apb_access_source_files'][0]['sha256']='0'*64
    with pytest.raises(ValueError,match='source mismatch'):
        api._verify_ordinary_channel(assembly,document,bad_manifest)
    bundle=tmp_path/'bundle'
    api.save_ibex_pulp_register_bundle(output_dir=bundle,assembly=assembly,session_manifest=session.manifest_document,plan_bytes=plan,trace=trace,runtime_state=adapter.snapshot())
    manifest_path=bundle/'online_session_manifest.json'
    original_manifest=manifest_path.read_bytes()
    saved_identity=json.loads((bundle/'online_run_identity.json').read_bytes())['identity']
    for field,value in (('target_instance','gpio_b'),('max_records',7)):
        changed=json.loads(original_manifest)
        changed['runner']['sessions']['gpio_a']['identity']['ordinary_apb_access_receipts'][field]=value
        raw=api._json(changed).encode();manifest_path.write_bytes(raw)
        rehashed=deepcopy(saved_identity)
        rehashed['artifacts']['online_session_manifest.json']=hashlib.sha256(raw).hexdigest()
        try:
            with pytest.raises(ValueError,match='target observation identity mismatch'):
                api._verified_register_bundle(bundle,rehashed,plan)
        finally:
            manifest_path.write_bytes(original_manifest)
    original=api.make_register_runtime_factory
    def installer(declaration):
        install=original(declaration)
        def create(fresh):fresh.runner._test_session=fresh;return install(fresh)
        return create
    monkeypatch.setattr(api,'make_register_runtime_factory',installer)
    monkeypatch.setattr(api,'make_register_factory',lambda **kwargs:factory)
    result=api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'unused',output_dir=bundle)
    assert result.matches
    assert result.ordinary_apb_access_evidence==state
