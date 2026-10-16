"""Actual reset-resume prefix and reproducible fail-only terminal injection."""
import json
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.session_runtime import ScenarioSession,replay_online_session
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
from tests.scenario.test_register_reset_resume import lifecycle_factory
from tests.scenario.test_register_program_runtime import request


@pytest.mark.parametrize('phase',['registration','session_submission'])
def test_actual_resumed_uncertain_terminal_schema19_and_natural_fresh(tmp_path,phase):
    assembly=api.make_register_assembly(advance_rounds=1,
        ordinary_apb_access_evidence={'max_records':32},register_program_verifier={'max_records':8})
    base=lifecycle_factory(api.make_register_factory(cache_dir=tmp_path/'render',assembly=assembly),tmp_path)
    def factory():
        runner=base();step=runner.step_batch
        # Installed before Session construction/begin pins; never issue a fake receipt.
        def advance(order):
            runtime=runner._test_session._register_program_runtime
            if phase=='session_submission' and runtime._active_submission is not None and runtime._active_submission[1]['request']['action_id']=='terminal':
                raise ValueError('controlled terminal step failure')
            return step(order)
        runner.step_batch=advance
        return runner
    def install(session):
        session.runner._test_session=session
        runtime=api.make_register_runtime_factory(assembly)(session)
        reserve=session.prerequisite_gate._slot_policy._reserve
        def reserve_or_fail(action):
            if phase=='registration' and action.action_id=='terminal':
                raise RuntimeError('controlled terminal reservation failure')
            return reserve(action)
        session.prerequisite_gate._slot_policy._reserve=reserve_or_fail
        return runtime
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory())
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    runtime=install(session)
    try:
        session.begin()
        for _ in range(128):
            if session.runner.sessions['cpu'].waiting_instruction_address is not None:break
            session.advance_initial(bootstrap.template.schedule_order)
        else:raise AssertionError('bootstrap did not defer actual fetch')
        runtime.submit(request(case_id='before',action_id='before',target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False))
        session.reset('warm_all')
        for _ in range(128):
            if session.runner.sessions['cpu'].waiting_instruction_address is not None:break
            session.advance_after_reset(bootstrap.template.schedule_order)
        else:raise AssertionError('resume did not defer actual fetch')
        with pytest.raises((ValueError,RuntimeError)):
            runtime.submit(request(case_id='terminal',action_id='terminal',target_instance='gpio_a',operation='register_read',value=None,result_address=0x10008,allow_side_effect=False))
        record=runtime.snapshot()['records'][-1]
        assert record['status']=='uncertain' and record['phase']==phase
        assert record['case_index']==(None if phase=='registration' else 1)
        plan,trace=session.finish_export();document=json.loads(plan)
        assert document['schema_version']==19 and document['reset_operations'][0]['advances']
        assert any(row.get('kind')=='ordinary_apb_access_association' for row in trace.events)
        fresh=replay_online_session(plan,factory,trace,register_runtime_factory=install)
        assert fresh.matches
    finally:
        for target in session.runner.sessions.values():target.end_case()
