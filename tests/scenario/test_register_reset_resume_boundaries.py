"""Closed reset-resume codec boundaries; actual lifecycle tests live separately."""
import pytest
from myfuzz.scenario import session_runtime as module


def test_resume_api_exists():
    assert callable(getattr(module.ScenarioSession, 'advance_after_reset', None))


@pytest.mark.parametrize('rows', [
    [{'after_cases': True, 'policy': 'warm_all', 'advances': [['cpu']]}],
    [{'after_cases': 1, 'policy': 'warm_all', 'advances': []}],
    [{'after_cases': 1, 'policy': 'warm_all', 'advances': [['foreign']]}],
    [{'after_cases': 1, 'policy': 'warm_all', 'advances': [['cpu']]*3}],
    [{'after_cases': 1, 'policy': 'warm_all', 'advances': [['cpu']], 'extra': 1}],
])
def test_closed_resume_timeline_rejects_invalid_rows(rows):
    with pytest.raises(ValueError, match='reset'):
        module._validate_register_reset_operations(rows, schema=18, case_count=1,
            components=('cpu',), max_steps=2, terminal=None)


def test_resume_timeline_accepts_mixed_empty_rows():
    module._validate_register_reset_operations([
        {'after_cases': 1, 'policy': 'warm_all', 'advances': []},
        {'after_cases': 1, 'policy': 'cold_all', 'advances': [['cpu', 'cpu']]},
    ], schema=18, case_count=1, components=('cpu',), max_steps=2, terminal=None)


def test_appended_uncertain_case_cannot_be_reset():
    with pytest.raises(ValueError, match='reset'):
        module._validate_register_reset_operations([
            {'after_cases': 1, 'policy': 'warm_all', 'advances': [['cpu']]},
        ], schema=19, case_count=1, components=('cpu',), max_steps=2,
            terminal={'case_index': 0})


def test_legacy_reset_rows_remain_two_keys():
    module._validate_register_reset_operations([
        {'after_cases': 1, 'policy': 'warm_all'},
    ], schema=16, case_count=1, components=('cpu',), max_steps=2, terminal=None)
    with pytest.raises(ValueError, match='reset'):
        module._validate_register_reset_operations([
            {'after_cases': 1, 'policy': 'warm_all', 'advances': []},
        ], schema=16, case_count=1, components=('cpu',), max_steps=2, terminal=None)


def test_unappended_terminal_allows_prior_resume():
    module._validate_register_reset_operations([
        {'after_cases': 1, 'policy': 'warm_all', 'advances': [['cpu']]},
    ], schema=19, case_count=1, components=('cpu',), max_steps=2,
        terminal={'case_index': None})


def test_reset_rows_cannot_move_backwards():
    with pytest.raises(ValueError, match='reset'):
        module._validate_register_reset_operations([
            {'after_cases': 2, 'policy': 'warm_all', 'advances': [['cpu']]},
            {'after_cases': 1, 'policy': 'warm_all', 'advances': []},
        ], schema=18, case_count=2, components=('cpu',), max_steps=2, terminal=None)


def _resume_unit_session(*, step_effect=None):
    # A dispatch-only unit fixture, never native/semantic evidence authority.
    from types import SimpleNamespace
    class Runner:
        persistent_memory_prerequisite_gate = None
        # The reset-default guard reads this on the runner as well as on the
        # session, and both are None in the default configuration: this unit
        # exercises reset-resume, not register-reset-default evidence.
        _register_reset_default_verifier = None
        _status = 'running'
        command_epoch = 1
        _next_command_sequence = 1
        failure_status = None
        sessions = {'cpu': object(), 'foreign': object()}
        local_ticks = {'cpu': 0}
        event_count = 0
        def step_batch(self, schedule):
            self.local_ticks['cpu'] += len(schedule)
            if step_effect: step_effect(session)
        def events_since(self, start): return ()
        def retire_step_receipts_through(self, epoch, sequence): pass
    class Adapter:
        _uncertain = False
        _active_submission = None
        def validate_static_configuration(self): pass
    session = module.ScenarioSession.__new__(module.ScenarioSession)
    runner = Runner(); adapter = Adapter()
    adapter.session = session; adapter.runner = runner
    session.runner = runner; session.template = SimpleNamespace(schedule_order=('cpu',), max_steps=10, testcase_id='unit')
    session._register_reset_default_binding = None
    session._register_reset_default_verifier = None
    session._register_program_runtime = adapter
    session._register_export_runtime_binding = (adapter, Adapter, Adapter.validate_static_configuration, '')
    session._begun = True; session._finished = False; session._halted = False
    session._uncertain_reset = False; session._uncertain_reset_advance = False
    session._reset_operations = [{'after_cases': 1, 'policy': 'warm_all'}]
    session._reset_resume_advances = {}; session._cases = [object()]
    session._halt_reason = None; session.checker = None; session._resume_checker = None
    session._resume_checker_implementation = module._reset_resume_checker_identity(None)
    session._prerequisite_gate = None; session._resume_gate = None; session._resume_gate_observe = None
    session._resume_runner_methods = {name:(getattr(Runner,name),getattr(runner,name))
        for name in ('step_batch','retire_step_receipts_through')}
    session._register_capability_preflight = lambda **kwargs: None
    return session


def test_resume_receipt_ordinal_is_contiguous():
    session = _resume_unit_session()
    receipts = [session.advance_after_reset(('cpu',)) for _ in range(3)]
    assert [item.case_id for item in receipts] == ['unit:reset:0:advance:1',
        'unit:reset:0:advance:2', 'unit:reset:0:advance:3']


def test_resume_schedule_uses_template_components_before_effect():
    session = _resume_unit_session()
    with pytest.raises(ValueError, match='schedule'):
        session.advance_after_reset(('foreign',))
    assert session.runner.local_ticks['cpu'] == 0


def test_last_step_checker_identity_drift_halts_and_refuses_export():
    session = _resume_unit_session(step_effect=lambda s:setattr(s, 'checker', lambda receipt:()))
    with pytest.raises(ValueError, match='drift'):
        session.advance_after_reset(('cpu',))
    assert session._halted and session._uncertain_reset_advance
    with pytest.raises(ValueError, match='uncertain'):
        session.encode_plan()


def test_checker_callback_drift_is_rechecked_after_callback():
    session = _resume_unit_session()
    def checker(receipt):
        session.runner.step_batch = lambda schedule: None
        return ()
    session.checker = session._resume_checker = checker
    session._resume_checker_implementation = module._reset_resume_checker_identity(checker)
    with pytest.raises(ValueError, match='drift'):
        session.advance_after_reset(('cpu',))
    assert session._halted and session._uncertain_reset_advance


def test_gate_observe_drift_is_rechecked_after_actual_pinned_call():
    session = _resume_unit_session()
    class Gate:
        def observe(self, receipt):
            self.observe = lambda receipt: None
    gate = Gate()
    session.runner.persistent_memory_prerequisite_gate = gate
    session._resume_gate = gate; session._resume_gate_observe = gate.observe
    with pytest.raises(ValueError, match='drift'):
        session.advance_after_reset(('cpu',))
    assert session._halted and session._uncertain_reset_advance


@pytest.mark.parametrize('method', ['_guard_reset_resume', 'advance_after_reset'])
def test_used_resume_encode_rejects_instance_method_drift(method):
    session = _resume_unit_session()
    session.advance_after_reset(('cpu',))
    setattr(session, method, lambda **kwargs: None)
    with pytest.raises(ValueError, match='drift'):
        session.encode_plan()


def test_checker_inplace_code_replacement_refuses_before_effect():
    session = _resume_unit_session()
    def checker(receipt): return ()
    def replacement(receipt): return ('unexpected',)
    session.checker = session._resume_checker = checker
    session._resume_checker_implementation = module._reset_resume_checker_identity(checker)
    checker.__code__ = replacement.__code__
    with pytest.raises(ValueError, match='implementation drift'):
        session.advance_after_reset(('cpu',))
    assert session.runner.local_ticks['cpu'] == 0
