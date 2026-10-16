"""Authenticated fresh file replay after actual software process reset lifecycle."""
import json
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
from tests.scenario.test_register_reset_resume import lifecycle_factory
from tests.scenario.test_register_program_runtime import request
from tests.integration.test_register_field_read_replay import install_software


@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_actual_reset_resume_authenticated_files_fresh_original_requests(tmp_path,monkeypatch,policy):
    assembly=api.make_register_assembly(advance_rounds=1,
        ordinary_apb_access_evidence={'max_records':32},register_program_verifier={'max_records':8})
    factory=lifecycle_factory(api.make_register_factory(cache_dir=tmp_path/'render',assembly=assembly),tmp_path)
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    runtime=api.make_register_runtime_factory(assembly)(session)
    def read(case_id,address):
        return request(case_id=case_id,action_id='read-'+case_id,target_instance='gpio_a',
            operation='register_read',value=None,result_address=address,allow_side_effect=False)
    try:
        session.begin()
        for _ in range(128):
            if session.runner.sessions['cpu'].waiting_instruction_address==bootstrap.instruction_start:break
            session.advance_initial(bootstrap.template.schedule_order)
        else:raise AssertionError('bootstrap did not reach actual deferred fetch')
        runtime.submit(read('before',0x10004))
        epochs={name:target.reset_epoch for name,target in session.runner.sessions.items()}
        session.reset(policy)
        assert all(target.reset_epoch==epochs[name]+1 for name,target in session.runner.sessions.items())
        for _ in range(128):
            if session.runner.sessions['cpu'].waiting_instruction_address is not None:break
            session.advance_after_reset(bootstrap.template.schedule_order)
        else:raise AssertionError('resume did not reach actual deferred fetch')
        runtime.submit(read('after',0x10008))
        plan,trace=session.finish_export();document=json.loads(plan)
        assert document['schema_version']==18
        operation,=document['reset_operations']
        assert operation['policy']==policy and operation['after_cases']==1 and operation['advances']
        ordinary=session.runner.ordinary_apb_access_evidence_snapshot()
        assert ordinary['records'] and all(r['raw_event_refs'] and r['base_event_refs'] for r in ordinary['records'])
        assert {r['target_reset_epoch'] for r in ordinary['records']}=={0,1}
        assert any(row.get('kind')=='memory_write_commit' for row in trace.events)
        verifier=session.register_program_verifier_document()
        bundle=tmp_path/'bundle'
        api.save_ibex_pulp_register_bundle(output_dir=bundle,assembly=assembly,
            session_manifest=session.manifest_document,plan_bytes=plan,trace=trace,runtime_state=runtime.snapshot())
        install_software(monkeypatch,dict(factory=factory))
        result=api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'unused',output_dir=bundle)
        assert result.matches and result.register_program_verifier==verifier
        assert result.ordinary_apb_access_evidence==ordinary
        assert result.comparison.actual_trace.semantic_sha256==trace.semantic_sha256
        assert len(result.comparison.actual_trace.events)==len(trace.events)
    finally:
        for target in session.runner.sessions.values():target.end_case()
