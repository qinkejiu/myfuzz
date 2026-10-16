"""The fast export still derives once from live, pinned evidence."""
import json
import sys
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session
from tests.scenario.test_register_program_verifier import read_result_factory
from tests.scenario.test_register_program_runtime import request


@pytest.fixture(scope='module')
def live(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(read_result_factory(actual_factory))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result)
    verifier=RegisterProgramVerifier(runtime,max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,
        result_address=0x10004,allow_side_effect=False))
    return runtime,verifier


def test_export_uses_exactly_one_live_report_and_valid_closed_projection(live):
    from myfuzz.scenario.register_program_verifier import validate_register_program_verifier_session_document
    runtime,verifier=live
    calls=[]
    code=type(verifier).report.__code__
    previous=sys.getprofile()
    def observe(frame,event,arg):
        if event=='call' and frame.f_code is code and frame.f_locals.get('self') is verifier:
            calls.append(1)
    try:
        sys.setprofile(observe)
        document=verifier.session_document()
    finally:
        sys.setprofile(previous)
    assert len(calls)==1
    normalized=json.loads(json.dumps(document))
    assert len(normalized['state']['current_certificates'])==1
    assert set(normalized['verified_capabilities'])==set(runtime.sidecars)
    assert validate_register_program_verifier_session_document(normalized,
        configuration=json.loads(json.dumps(runtime.configuration())))==normalized


def test_fast_export_detaches_report_and_snapshot(live):
    _,verifier=live
    original=verifier.session_document()
    changed=verifier.session_document()
    changed['state']['historical_certificates'][0]['grants_functional']=True
    changed['verified_capabilities']['gpio_a']['operations']=()
    changed['configuration']['max_records']=65536
    assert verifier.session_document()==original


@pytest.mark.parametrize('name',['_report_and_snapshots','session_document'])
def test_new_export_method_override_is_rejected_by_live_validation(live,name):
    _,verifier=live
    setattr(verifier,name,lambda: {})
    try:
        with pytest.raises(ValueError,match='method-drift'):
            verifier.report()
    finally:
        delattr(verifier,name)
