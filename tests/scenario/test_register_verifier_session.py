"""Verifier Session opt-in uses actual rendered objects; no RTL execution."""
import json
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session, observed_factory
from tests.scenario.test_register_program_verifier import read_result_factory
from tests.scenario.test_register_program_runtime import request


def installed(actual_factory):
    result=session(actual_factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result)
    return result,runtime


def test_default_off_preserves_register_plan_and_manifest_layout(actual_factory):
    result,runtime=installed(actual_factory)
    result.begin();result.finish()
    registers=json.loads(result.encode_plan())['register_programs']
    assert 'register_program_verifier' not in registers
    assert 'register_program_verifier_configuration' not in result.manifest_document
    assert 'register_program_verifier_source_files' not in result.manifest_document
    assert result.runner._register_program_verifier is None


def test_actual_beforebegin_install_pins_configuration_and_closed_empty_wrapper(actual_factory):
    result,runtime=installed(actual_factory)
    configuration=result.configure_register_program_verifier(max_records=4)
    verifier=result.runner._register_program_verifier
    assert verifier.runtime is runtime and configuration==verifier.configuration()
    assert configuration['max_records']==4
    configuration['max_records']=999
    assert verifier.configuration()['max_records']==4
    result.begin();result.finish()
    manifest=result.manifest_document
    assert manifest['register_program_verifier_configuration']==verifier.configuration()
    assert manifest['register_program_verifier_source_files']
    assert any(row['path']=='src/myfuzz/scenario/register_program_verifier.py'
        for row in manifest['register_program_verifier_source_files'])
    wrapper=json.loads(result.encode_plan())['register_programs']['register_program_verifier']
    assert set(wrapper)=={'schema_version','configuration','state','verified_capabilities'}
    assert wrapper['schema_version']=='register_program_verifier_session.v1'
    assert wrapper['configuration']==verifier.configuration()
    assert wrapper['state']==verifier.report()
    assert wrapper['state']['historical_certificates']==[]
    assert set(wrapper['verified_capabilities'])=={'gpio_a'}
    assert wrapper['verified_capabilities']['gpio_a']['operations']==[]


@pytest.mark.parametrize('bound',[True,0,65537])
def test_invalid_bound_does_not_register_authority_consumer(actual_factory,bound):
    result,runtime=installed(actual_factory)
    authority=result.runner._memory_commit_authority
    before=set(authority._consumers)
    with pytest.raises(ValueError):result.configure_register_program_verifier(max_records=bound)
    assert authority._consumers==before
    assert result.runner._register_program_verifier is None and result.runner.event_count==0


def test_requires_actual_adapter_and_ordinary_mode_before_publication(actual_factory):
    result=session(actual_factory)
    with pytest.raises(ValueError):result.configure_register_program_verifier(max_records=4)
    assert result.runner._register_program_verifier is None
    runtime=adapter(result)
    with pytest.raises(ValueError):result.configure_register_program_verifier(max_records=4)
    assert result.runner._register_program_verifier is None


def test_late_and_repeat_install_refused_without_replacing_verifier(actual_factory):
    result,runtime=installed(actual_factory)
    result.configure_register_program_verifier(max_records=4)
    verifier=result.runner._register_program_verifier
    with pytest.raises(ValueError):result.configure_register_program_verifier(max_records=4)
    assert result.runner._register_program_verifier is verifier
    result.begin()
    with pytest.raises(ValueError):result.configure_register_program_verifier(max_records=4)
    assert result.runner._register_program_verifier is verifier


def test_nonempty_actual_read_state_is_saved_without_installing_from_report(actual_factory):
    result,runtime=installed(read_result_factory(actual_factory))
    result.configure_register_program_verifier(max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,
        result_address=0x10004,allow_side_effect=False))
    result.finish()
    wrapper=json.loads(result.encode_plan())['register_programs']['register_program_verifier']
    assert len(wrapper['state']['historical_certificates'])==1
    assert len(wrapper['state']['current_certificates'])==1
    assert len(wrapper['verified_capabilities']['gpio_a']['operations'])==1
    assert wrapper['state']['grants_storage'] is False
    assert wrapper['state']['grants_functional'] is False


def test_schema17_exports_actual_incomplete_prefix_with_no_current_proof(actual_factory):
    result,runtime=installed(observed_factory(actual_factory,callback_failure=True))
    result.configure_register_program_verifier(max_records=4)
    result.begin()
    with pytest.raises(TypeError):runtime.submit(request(target_instance='gpio_a'))
    result.finish();document=json.loads(result.encode_plan())
    assert document['schema_version']==17
    wrapper=document['register_programs']['register_program_verifier']
    assert wrapper['state']['status']=='incomplete'
    assert wrapper['state']['current_certificates']==[]
    assert wrapper['verified_capabilities']['gpio_a']['operations']==[]


def test_source_closure_failure_precedes_consumer_registration(actual_factory,monkeypatch):
    import myfuzz.scenario.session_runtime as module
    result,runtime=installed(actual_factory)
    authority=result.runner._memory_commit_authority
    original=authority._consumers;before=set(original)
    def missing(*args):raise OSError('missing verifier dependency')
    monkeypatch.setattr(module,'_register_program_verifier_source_files',missing)
    with pytest.raises(OSError):result.configure_register_program_verifier(max_records=4)
    assert authority._consumers is original and original==before
    assert result.runner._register_program_verifier is None
    assert result._register_verifier is None


def test_late_source_drift_refuses_prepare_and_retry_before_mutation(actual_factory,monkeypatch):
    import myfuzz.scenario.session_runtime as module
    result,runtime=installed(actual_factory)
    result.configure_register_program_verifier(max_records=4)
    result.begin()
    original=module._register_program_verifier_source_files
    def changed(paths=None):
        rows=original(paths);rows[0]['sha256']='0'*64;return rows
    before=runtime.snapshot()
    monkeypatch.setattr(module,'_register_program_verifier_source_files',changed)
    with pytest.raises(ValueError,match='source-drift'):runtime.prepare(request(target_instance='gpio_a'))
    assert runtime.snapshot()==before
    with pytest.raises(ValueError,match='source-drift'):result.advance_initial(('cpu',))
    monkeypatch.setattr(module,'_register_program_verifier_source_files',original)
    runtime.submit(request(target_instance='gpio_a'))
    before=runtime.snapshot()
    monkeypatch.setattr(module,'_register_program_verifier_source_files',changed)
    with pytest.raises(ValueError,match='source-drift'):runtime.submit(request(target_instance='gpio_a'))
    assert runtime.snapshot()==before


def test_fresh_original_request_recomputes_whole_verifier_wrapper(actual_factory):
    from myfuzz.scenario.session_runtime import replay_online_session
    factory=read_result_factory(actual_factory)
    result,runtime=installed(factory)
    result.configure_register_program_verifier(max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,
        result_address=0x10004,allow_side_effect=False))
    trace=result.finish();plan=result.encode_plan()
    def install(fresh):
        fresh.configure_ordinary_apb_access_evidence(max_records=4)
        current=adapter(fresh)
        fresh.configure_register_program_verifier(max_records=4)
        return current
    comparison=replay_online_session(plan,factory,trace,register_runtime_factory=install)
    assert comparison.matches
