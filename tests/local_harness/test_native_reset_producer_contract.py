"""Closed class/reset source-only admission, never native build eligibility."""
from pathlib import Path
import pytest
from tests.local_harness.test_generic_apb_identity import generated
from tests.local_harness.test_apb_storage_probe_generation import selected
ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture
def storage(generated,monkeypatch,tmp_path):
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    artifact,_=generated
    if artifact.plan.profile.source.top_module!='apb_timer':
        pytest.skip('timer-only registered source; GPIO mechanics tested separately')
    artifact=render_local_driver(selected(generated),base_dir=ROOT)
    owner=GeneratedApb3RegisterSession(artifact,base_dir=ROOT,cache_dir=tmp_path)
    # Restore real trusted Python producers after saved-port generation only.
    monkeypatch.undo()
    return owner


def test_registered_generic_can_observe_but_has_no_native_issuance(storage):
    from myfuzz.local_harness.session import _native_reset_native_eligible
    config=storage.configure_native_reset_observation()
    assert config['grants_storage'] is False
    assert config['grants_version_dependency'] is False
    assert _native_reset_native_eligible(storage)==(False,None)


@pytest.mark.parametrize('field,value', [('setup_writes',((4,1),)),('probe_offsets',(4,)),('_dynamic',{'fake':1}),('_bound',{'fake':1})])
def test_setup_or_unproved_input_producer_refused(storage,field,value):
    setattr(storage,field,value)
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


@pytest.mark.parametrize('name', ['begin_case','reset_local','_command_impl','_take','_access'])
@pytest.mark.parametrize('where', ['class','instance'])
def test_resolved_methods_cannot_be_replaced(storage,monkeypatch,name,where):
    original=getattr(type(storage),name)
    def wrapper(self,*a,**kw):return original(self,*a,**kw)
    if where=='class':monkeypatch.setattr(type(storage),name,wrapper)
    else:monkeypatch.setattr(storage,name,wrapper.__get__(storage,type(storage)))
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_subclass_refused(storage):
    class Other(type(storage)):pass
    storage.__class__=Other
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_canonical_dependency_override_refused(storage,monkeypatch):
    from myfuzz.local_harness import apb_storage_probe_contract as module
    original=module.generate_storage_probe
    monkeypatch.setattr(module,'generate_storage_probe',lambda *a,**kw:original(*a,**kw))
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_probe_drift_poisons_observer(storage):
    storage.configure_native_reset_observation()
    storage.artifact.runtime_document['storage_observation']['hierarchy_verified']=True
    with pytest.raises(ValueError):storage.native_reset_observation_snapshot()
    assert storage._native_reset_observation._status=='incomplete'


def test_postparse_consumer_failure_is_permanent(storage):
    from types import SimpleNamespace
    storage.configure_native_reset_observation()
    with pytest.raises((AttributeError,ValueError,KeyError)):
        storage._take(SimpleNamespace(payload={}))
    assert storage._native_reset_observation._status=='incomplete'


def test_public_build_like_tuple_does_not_issue_native_eligibility(storage):
    from myfuzz.local_harness.session import _native_reset_native_eligible
    storage.configure_native_reset_observation()
    storage._native_reset_build_issuance=(object(),storage,storage.artifact,None,'0'*64,'{}')
    with pytest.raises(ValueError):_native_reset_native_eligible(storage)


def test_unselected_generic_artifact_cannot_observe(generated,monkeypatch):
    _,owner=generated
    owner.setup_writes=();owner.probe_offsets=()
    monkeypatch.undo()
    with pytest.raises(ValueError):owner.configure_native_reset_observation()


def test_registry_dispatch_replacement_refused(storage,monkeypatch):
    from myfuzz.local_harness import native_reset_producer_contract as module
    monkeypatch.setattr(module,'check_producer',lambda owner:'apb_storage')
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_instance_operation_shadow_refused(storage):
    storage.access_operation='ACCESS_APB3_REG'
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_replacing_both_class_and_table_pin_sides_cannot_rebaseline(storage,monkeypatch):
    from types import MappingProxyType
    from myfuzz.local_harness import apb3_register_session as module
    original=type(storage)
    alternate=type('Alternate',(original,),{key:value for key,value in vars(original).items() if key not in ('__dict__','__weakref__')})
    declarations=MappingProxyType(dict(vars(alternate)))
    resolved=MappingProxyType({name:(getattr(alternate,name),getattr(alternate,name).__code__) for name in dir(alternate) if hasattr(getattr(alternate,name),'__code__')})
    for name,value in [('GeneratedApb3RegisterSession',alternate),('_NATIVE_RESET_APB_CLASS',alternate),('_NATIVE_RESET_APB_DECLARATIONS',declarations),('_NATIVE_RESET_APB_DECLARATIONS_PIN',declarations),('_NATIVE_RESET_APB_RESOLVED',resolved),('_NATIVE_RESET_APB_RESOLVED_PIN',resolved)]:
        monkeypatch.setattr(module,name,value)
    storage.__class__=alternate
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_sealed_checker_and_pin_replacement_refused(storage,monkeypatch):
    from myfuzz.local_harness import native_reset_producer_contract as module
    fake=lambda owner:'apb_storage'
    monkeypatch.setattr(module,'_check_origin',fake)
    monkeypatch.setattr(module,'_CHECK_ORIGIN',(fake,fake.__code__))
    with pytest.raises(ValueError):storage.configure_native_reset_observation()


def test_foreign_sealing_call_cannot_register(storage):
    from myfuzz.local_harness.native_reset_producer_contract import _seal_code_owned_producer
    with pytest.raises(ValueError):_seal_code_owned_producer(type(storage))


def test_actual_generic_python_wire_lifecycle_remains_mechanical_only(storage,tmp_path):
    """A Python wire peer exercises producer frames, never a native RTL model."""
    import json
    digest,asserted,released,_=storage._expected_ready()
    physical={row['runtime_name']:0 for row in storage.artifact.runtime_document['physical_exports']}
    worker=tmp_path/'mechanical-apb-peer.py'
    worker.write_text('''#!/usr/bin/env python3
import json,sys
print(READY,flush=True)
tick=0
for line in sys.stdin:
 p=line.split()
 if p[0]=='END':break
 if p[0]=='ACK':
  print('ACKED '+p[1]+' '+p[2]+' '+format(tick,'x'),flush=True);continue
 _,execution,sequence,operation,*fields=p
 before=tick;tick+=1
 state=dict(backend={},physical=PHYSICAL)
 payload=dict(schema_version='local_driver_result.v1',kind='apb3_register_observe',samples=[dict(local_tick=tick,pre=state,post=state)],observations=state,pre_backend={},rdata=0,error=0)
 print('RESULT '+execution+' '+sequence+' '+format(before,'x')+' '+format(tick,'x')+' '+json.dumps(payload,sort_keys=True,separators=(',',':')).encode().hex(),flush=True)
'''.replace('READY',repr(f'READY local_driver.v1 {digest} {asserted:x} {released:x}')).replace('PHYSICAL',repr(physical)))
    worker.chmod(0o700);storage._binary=worker
    storage.configure_native_reset_observation()
    try:
        storage.begin_case('mechanical-generic')
        storage.write_register(4,9)
        assert storage.native_reset_observation_commands()[0]['operation']=='ACCESS_APB3_REG'
        first=storage.process
        storage.reset_local()
        rows=storage.native_reset_observation_lifecycles()
        assert first.poll() is not None and storage.process is not first
        assert len(rows)==2 and all(row['native_eligible'] is False for row in rows)
    finally:storage.end_case()
    assert storage.native_reset_observation_snapshot()['status']=='complete'


@pytest.mark.parametrize('field', ['_dynamic','_bound','_dynamic_values','_bound_values'])
def test_empty_nonmapping_cannot_impersonate_input_registry(storage,field):
    setattr(storage,field,None)
    with pytest.raises(ValueError):storage.configure_native_reset_observation()
