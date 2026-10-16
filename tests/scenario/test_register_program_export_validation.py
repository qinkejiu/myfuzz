"""Export validates each actual ordinary wrapper once without weakening saved parsing."""
import sys
import pytest
from tests.scenario.test_register_program_replay import actual_factory,adapter
from tests.scenario.test_ordinary_apb_access_session import session
from myfuzz.scenario.session_runtime import validate_ordinary_apb_access_session_document


def installed(factory):
    result=session(factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    adapter(result)
    return result


def test_encode_plan_has_one_closed_ordinary_validation(actual_factory):
    result=installed(actual_factory)
    calls=[];code=validate_ordinary_apb_access_session_document.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code:calls.append(1)
    before=sys.getprofile()
    try:
        sys.setprofile(profile);result.encode_plan()
    finally:sys.setprofile(before)
    assert len(calls)==1


def test_public_ordinary_document_still_has_closed_validation(actual_factory):
    result=installed(actual_factory)
    calls=[];code=validate_ordinary_apb_access_session_document.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code:calls.append(1)
    before=sys.getprofile()
    try:
        sys.setprofile(profile);result._ordinary_apb_document()
    finally:sys.setprofile(before)
    assert len(calls)==1


def test_final_plan_validator_rejects_internal_wrapper_extra_fields(actual_factory,monkeypatch):
    result=installed(actual_factory)
    original=result._ordinary_apb_document
    def changed(*args,**kwargs):
        row=original(*args,**kwargs);row['caller_verified']=True;return row
    monkeypatch.setattr(result,'_ordinary_apb_document',changed)
    with pytest.raises(ValueError):result.encode_plan()
