"""Real validation call counts without replacing pinned verifier methods."""
import sys
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session


@pytest.mark.parametrize('allow_incomplete',[False,True])
def test_runner_guard_validates_exactly_once(actual_factory,allow_incomplete):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from myfuzz.scenario.runner import guard_register_program_verifier
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=4)
    verifier=RegisterProgramVerifier(adapter(result),max_records=4)
    calls=[];code=RegisterProgramVerifier._validate.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code and frame.f_locals.get('self') is verifier:
            calls.append(frame)
    prior=sys.getprofile();sys.setprofile(profile)
    try:guard_register_program_verifier(result.runner,allow_incomplete=allow_incomplete)
    finally:sys.setprofile(prior)
    assert len(calls)==1
