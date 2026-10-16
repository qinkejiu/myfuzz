"""One live verifier report supplies a complete Session evidence export."""
import sys
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session


def test_session_export_computes_live_report_once(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    adapter(result)
    result.configure_register_program_verifier(max_records=4)
    count=[]
    def observe(frame,event,arg):
        if event=='call' and frame.f_code is RegisterProgramVerifier.report.__code__:count.append(1)
    previous=sys.getprofile()
    sys.setprofile(observe)
    try:document=result.register_program_verifier_document()
    finally:sys.setprofile(previous)
    assert document['state']['historical_certificates']==[]
    assert set(document['verified_capabilities'])=={'gpio_a'}
    assert len(count)==1
