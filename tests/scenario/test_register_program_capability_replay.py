"""Capability opt-in saved-data wiring; software-only harness commands."""
import pytest
from myfuzz.scenario.session_runtime import ScenarioSession


def test_session_exposes_explicit_prebegin_capability_hook():
    assert callable(getattr(ScenarioSession,'configure_register_capability_preflight',None)), 'Session capability hook missing'

from copy import deepcopy
import hashlib,json
from dataclasses import replace
from tests.scenario.test_register_program_replay import actual_factory,adapter
from tests.scenario.test_register_program_runtime import request
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.session_runtime import replay_online_session


def configured(actual_factory,minimum=None):
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime=adapter(session)
    document=session.configure_register_capability_preflight(requested_minimum_level=minimum)
    return session,runtime,document


def test_startup_report_is_detached_persisted_and_fresh_recomputed(actual_factory):
    session,runtime,report=configured(actual_factory,'L1')
    assert report['verification'] is None
    assert report['targets']['gpio_a']['assessment']['effective_level']=='L1'
    report['targets'].clear()
    session.begin();runtime.submit(request(target_instance='gpio_a'));trace=session.finish()
    plan=session.encode_plan();document=json.loads(plan)
    saved=document['register_programs']['capability_preflight']
    assert saved==session.manifest_document['register_capability_preflight']
    assert saved['targets']['gpio_a']['assessment']['verified_level'] is None
    def install(fresh):
        result=adapter(fresh);fresh.configure_register_capability_preflight('L1');return result
    assert replay_online_session(plan,actual_factory,trace,register_runtime_factory=install).matches


def test_minimum_l2_refuses_before_any_command(actual_factory):
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32);adapter(session)
    with pytest.raises(ValueError):session.configure_register_capability_preflight('L2')
    assert session.runner._status=='created' and not session._begun
    assert session.cases==()


def test_saved_rehashed_assessment_is_not_runtime_authority(actual_factory):
    session,runtime,_=configured(actual_factory,'L1')
    session.begin();runtime.submit(request(target_instance='gpio_a'));trace=session.finish()
    doc=json.loads(session.encode_plan())
    cap=doc['register_programs']['capability_preflight']
    cap['requested_minimum_level']='L2'
    for target in cap['targets'].values():
        target['assessment']['requested_minimum_level']='L2'
        target['assessment']['effective_level']='L2'
        target['assessment']['minimum_level_met']=True
    changed=json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
    reference=replace(trace,genome_sha256=hashlib.sha256(changed).hexdigest())
    starts=[]
    def factory():
        runner=actual_factory();original=runner.begin_test
        def begin(case_id):starts.append(case_id);return original(case_id)
        runner.begin_test=begin;return runner
    def install(fresh):
        result=adapter(fresh);fresh.configure_register_capability_preflight('L1');return result
    with pytest.raises(ValueError):replay_online_session(changed,factory,reference,register_runtime_factory=install)
    assert starts==[]


def test_consumed_startup_slots_export_uses_pin(actual_factory,monkeypatch):
    session=ScenarioSession(ScenarioGenome('exhausted','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,4)
    runtime=adapter(session)
    report=session.configure_register_capability_preflight('L1')
    session.begin();runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004))
    assert all(not session.runner.sessions['cpu'].memory.instruction_slot_unmaterialized(address) for address in range(0x11000,0x11010,4))
    def forbidden(**kwargs):raise AssertionError('capacity must not be rederived after begin')
    monkeypatch.setattr(runtime,'capability_preflight',forbidden)
    session.finish();doc=json.loads(session.encode_plan())
    assert doc['register_programs']['capability_preflight']==report


@pytest.mark.parametrize('phase',['registration','step'])
def test_capability_schema17_uncertain_export_and_natural_replay(actual_factory,phase):
    session,runtime,report=configured(actual_factory,'L1')
    def fail(*args):raise RuntimeError('natural '+phase+' failure')
    if phase=='registration':session.prerequisite_gate._slot_policy._reserve=fail
    else:session.runner.step_batch=fail
    session.begin()
    with pytest.raises(RuntimeError):runtime.submit(request(target_instance='gpio_a'))
    trace=session.finish();plan=session.encode_plan()
    assert json.loads(plan)['schema_version']==17
    assert json.loads(plan)['register_programs']['capability_preflight']==report
    def factory():
        runner=actual_factory()
        if phase=='registration':runner.persistent_memory_prerequisite_gate._slot_policy._reserve=fail
        return runner
    def install(fresh):
        result=adapter(fresh);fresh.configure_register_capability_preflight('L1')
        if phase=='step':fresh.runner.step_batch=fail
        return result
    assert replay_online_session(plan,factory,trace,register_runtime_factory=install).matches

def test_source_failure_does_not_publish_partial_configuration(actual_factory,monkeypatch):
    from myfuzz.scenario import session_runtime as api
    session=ScenarioSession(ScenarioGenome('source_fail','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    adapter(session)
    def fail(): raise OSError('source unavailable')
    monkeypatch.setattr(api,'_register_capability_source_files',fail)
    with pytest.raises(OSError): session.configure_register_capability_preflight('L1')
    assert session._register_capability_preflight_json is None
    assert session._register_capability_sources_json is None
