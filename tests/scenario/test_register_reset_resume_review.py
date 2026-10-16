"""Independent dispatch/closed-codec review, not runtime proof authority."""
import pytest
from myfuzz.scenario import session_runtime as module
from tests.scenario.test_register_reset_resume_boundaries import _resume_unit_session


@pytest.mark.parametrize('scope',['instance','class'])
def test_resume_export_serializer_drift_cannot_pass_current_guard(monkeypatch,scope):
    session=_resume_unit_session()
    session.advance_after_reset(('cpu',))
    fake=lambda *args: [{'after_cases':1,'policy':'cold_all','advances':[['cpu','cpu']]}]
    if scope=='instance':session._encoded_reset_operations=fake
    else:monkeypatch.setattr(module.ScenarioSession,'_encoded_reset_operations',fake)
    with pytest.raises(ValueError,match='drift'):
        module._RESET_RESUME_GUARD(session,allow_incomplete=True)


@pytest.mark.parametrize('rows',[
    [{'after_cases':1,'policy':'warm_all','advances':(('cpu',),)}],
    [{'after_cases':1,'policy':'warm_all','advances':[['cpu',True]]}],
    [{'after_cases':1,'policy':'warm_all','advances':[['cpu']]},
     {'after_cases':0,'policy':'cold_all','advances':[]}],
])
def test_closed_resume_rows_reject_nonjson_schedule_and_backwards_boundary(rows):
    with pytest.raises(ValueError,match='reset'):
        module._validate_register_reset_operations(rows,schema=18,case_count=2,
            components=('cpu',),max_steps=4,terminal=None)


def test_schema19_prior_committed_boundary_remains_valid_but_failed_case_does_not():
    row={'after_cases':1,'policy':'warm_all','advances':[['cpu']]}
    module._validate_register_reset_operations([row],schema=19,case_count=2,
        components=('cpu',),max_steps=4,terminal={'case_index':1})
    with pytest.raises(ValueError,match='reset'):
        module._validate_register_reset_operations([dict(row,after_cases=2)],schema=19,case_count=2,
            components=('cpu',),max_steps=4,terminal={'case_index':1})


def test_checker_class_callable_replacement_is_method_drift_before_resume(monkeypatch):
    session=_resume_unit_session()
    class Checker:
        def __call__(self,receipt):return ()
    checker=Checker()
    session.checker=session._resume_checker=checker
    session._resume_checker_implementation=module._reset_resume_checker_identity(checker)
    module._RESET_RESUME_GUARD(session)  # original callable control
    # Actual object identity remains fixed while the code dispatched by a
    # callable instance changes. This is a dispatch test, not an evidence grant.
    monkeypatch.setattr(Checker,'__call__',lambda self,receipt:())
    with pytest.raises(ValueError,match='drift'):
        session.advance_after_reset(('cpu',))
    assert session.runner.local_ticks['cpu']==0
