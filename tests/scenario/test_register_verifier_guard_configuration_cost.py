"""Verifier hot-path checks use the authenticated configuration without copying it."""
import json
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session


def configured(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result)
    return runtime,RegisterProgramVerifier(runtime,max_records=4)


def test_validation_does_not_decode_full_runtime_configuration(actual_factory,monkeypatch):
    runtime,verifier=configured(actual_factory)
    original=json.loads
    copied=[]
    def traced(value,*args,**kwargs):
        if value is runtime._static_json:copied.append(value)
        return original(value,*args,**kwargs)
    monkeypatch.setattr(json,'loads',traced)
    verifier._validate()
    assert copied==[]


def test_runtime_configuration_accessor_override_is_rejected(actual_factory):
    runtime,verifier=configured(actual_factory)
    saved=runtime.configuration()
    runtime.configuration=lambda:saved
    with pytest.raises(ValueError):verifier._validate()


@pytest.mark.parametrize('method',['validate','validate_static_configuration'])
def test_runtime_validation_method_override_is_rejected(actual_factory,method):
    runtime,verifier=configured(actual_factory)
    setattr(runtime,method,lambda:None)
    with pytest.raises(ValueError):verifier._validate()
