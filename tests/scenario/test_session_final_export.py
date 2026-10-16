"""Final export orchestration and pure state checks; no restored authority."""
import hashlib
import inspect
from types import SimpleNamespace
import pytest
from myfuzz.scenario import session_runtime as module


def state_pair():
    configuration={'max_records':16,'slots':[['ram',index] for index in range(126464)]}
    state={'schema_version':'register_program_runtime_state.v1','configuration':configuration,
           'uncertain':False,'records':[]}
    registers={'configuration':configuration,'terminal_attempt':None,'case_manifests':[]}
    return state,registers


def test_internal_state_validation_does_not_detach_large_actual_slot_shape(monkeypatch):
    state,registers=state_pair()
    calls=[]
    original=module.json.loads
    def loads(value,*args,**kwargs):
        calls.append(len(value))
        return original(value,*args,**kwargs)
    monkeypatch.setattr(module.json,'loads',loads)
    check=getattr(module,'_validate_register_program_state',module.validate_register_program_state)
    check(state,registers)
    assert calls==[], 'internal export must not copy the ignored validated state'


def test_public_state_validation_remains_detached():
    state,registers=state_pair()
    result=module.validate_register_program_state(state,registers)
    result['configuration']['slots'][0][1]=999
    assert state['configuration']['slots'][0][1]==0


@pytest.mark.parametrize('mutation',[
    lambda s:s.update(unknown=True),lambda s:s.update(uncertain=0),
    lambda s:s['configuration'].update(max_records=False),
    lambda s:s['records'].append({'manifest':{},'status':'submitted','phase':'submitted','case_index':0}),
])
def test_internal_state_validator_preserves_closed_checks(mutation):
    import copy
    state,registers=state_pair();registers=copy.deepcopy(registers)
    mutation(state)
    with pytest.raises(ValueError):
        module._validate_register_program_state(state,registers)


def final_session():
    from tests.scenario.test_online_session_partial_replay import _factory, _template
    session=module.ScenarioSession(_template(),_factory())
    session.begin()
    log=[]
    original=session.runner.finalize
    def finalize():
        log.append('finalize')
        original()
        session.runner._events.append({'kind':'finalized'})
    session.runner.finalize=finalize
    return session,log


def test_finish_export_finalizes_then_encodes_once_and_uses_exact_bytes():
    import json
    import sys
    session,log=final_session()
    calls=[]
    code=module.ScenarioSession.encode_plan.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code:calls.append('encode')
    old=sys.getprofile();sys.setprofile(profile)
    try:plan,trace=session.finish_export()
    finally:sys.setprofile(old)
    assert log==['finalize'] and calls==['encode']
    assert type(plan) is bytes and trace.genome_sha256==hashlib.sha256(plan).hexdigest()
    assert trace.events[-1]=={'kind':'finalized'}
    assert trace.status=='complete'
    assert json.loads(plan)['cases']==[]
    with pytest.raises(RuntimeError):session.finish_export()


def test_finish_export_accepts_no_saved_plan_or_hash():
    session,_=final_session()
    assert set(inspect.signature(session.finish_export).parameters)=={'defer_semantic_hash'}
    with pytest.raises(TypeError):session.finish_export(genome_sha256='b'*64)
    with pytest.raises(TypeError):session.finish_export(plan=b'{}')


def test_finish_export_does_not_hide_postfinalize_guard_failure():
    session,log=final_session()
    original=session.runner.finalize
    def finalize():original();session._uncertain_reset=True
    session.runner.finalize=finalize
    with pytest.raises(ValueError,match='uncertain or unrecorded reset'):session.finish_export()
    assert log==['finalize'] and session._finished


@pytest.mark.parametrize('name',['encode_plan','trace'])
@pytest.mark.parametrize('location',['instance','class','finalizer'])
def test_final_export_refuses_method_replacements_before_and_after_finalize(monkeypatch,name,location):
    session,log=final_session()
    if location=='instance':monkeypatch.setattr(session,name,lambda **kw:b'caller')
    elif location=='class':monkeypatch.setattr(module.ScenarioSession,name,lambda *a,**kw:b'caller')
    else:
        original=session.runner.finalize
        def finalize():original();monkeypatch.setattr(session,name,lambda **kw:b'caller')
        session.runner.finalize=finalize
    with pytest.raises(ValueError,match='session-final-export-method-drift'):session.finish_export()
    assert log==(['finalize'] if location=='finalizer' else [])


def test_old_finish_still_returns_trace():
    session,log=final_session()
    trace=session.finish()
    assert log==['finalize'] and trace.status=='complete'


from tests.scenario.test_register_program_replay import actual_factory, adapter


@pytest.mark.parametrize('failure',[None,'registration','step'])
def test_actual_register_final_export_keeps_schema_and_checks_once(actual_factory,failure):
    import json
    import sys
    from myfuzz.scenario.genome import ScenarioGenome
    from tests.scenario.test_register_program_runtime import request
    session=module.ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime=adapter(session)
    if failure=='registration':
        def reserve(action):raise RuntimeError('reservation interrupted')
        session.prerequisite_gate._slot_policy._reserve=reserve
    elif failure=='step':
        def step(order):raise ValueError('step interrupted')
        session.runner.step_batch=step
    session.begin()
    if failure is None:runtime.submit(request(target_instance='gpio_a'))
    else:
        with pytest.raises((RuntimeError,ValueError)):runtime.submit(request(target_instance='gpio_a'))
    counts={'encode':0,'plan':0,'state':0}
    codes={module.ScenarioSession.encode_plan.__code__:'encode',
           module.validate_register_program_plan.__code__:'plan',
           module._validate_register_program_state.__code__:'state'}
    def profile(frame,event,arg):
        if event=='call' and frame.f_code in codes:counts[codes[frame.f_code]]+=1
    old=sys.getprofile();sys.setprofile(profile)
    try:plan,trace=session.finish_export()
    finally:sys.setprofile(old)
    assert counts=={'encode':1,'plan':1,'state':1}
    document=json.loads(plan)
    assert document['schema_version']==(17 if failure else 16)
    assert trace.genome_sha256==hashlib.sha256(plan).hexdigest()
    assert plan==session.encode_plan()
    state=runtime.snapshot()
    module.validate_register_program_plan(document)
    detached=module.validate_register_program_state(state,document['register_programs'])
    assert detached==state
    detached['records'][0]['manifest']['request']['case_id']='changed'
    assert state['records'][0]['manifest']['request']['case_id']!='changed'


@pytest.mark.parametrize('drift',['sidecar','slots'])
def test_actual_finalize_runtime_static_drift_is_rejected_without_extra_channels(actual_factory,tmp_path,drift):
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    from tests.scenario.test_register_program_runtime import request
    path=tmp_path/'capability.json';path.write_bytes(SIDECAR.read_bytes())
    session=module.ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime=RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':path},advance_rounds=1)
    session.begin();runtime.submit(request(target_instance='gpio_a'))
    def finalize():
        if drift=='sidecar':path.write_bytes(path.read_bytes()+b'\n')
        else:
            slots=session.runner.sessions['cpu'].memory._instruction_slots
            removed=next(iter(slots));slots.remove(removed);slots.add((removed[0],removed[1]+65536))
    session.runner.finalize=finalize
    with pytest.raises(ValueError,match='drift'):session.finish_export()
