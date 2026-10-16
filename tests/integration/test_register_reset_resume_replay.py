"""Closed writer resume codec TDD; saved-model comparison, no authority/RTL."""
from copy import deepcopy
import json
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api


@pytest.fixture(scope='module')
def captured_register_model(tmp_path_factory):
    # Generate a current nonempty model through actual private CPU/router/RAM
    # services and a software word driver. No ignored runs artifact is needed.
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    from tests.integration.test_register_field_read_replay import field_factory
    from tests.scenario.test_register_program_runtime import request
    root=tmp_path_factory.mktemp('closed-resume-model')
    assembly=api.make_register_assembly(advance_rounds=1,max_records=4)
    factory=field_factory(api.make_register_factory(cache_dir=root/'render',assembly=assembly))
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    runtime=api.make_register_runtime_factory(assembly)(session)
    try:
        session.begin()
        runtime.submit(request(case_id='codec-read',action_id='codec-action',target_instance='gpio_a',
            register='PADOUT',field='value',operation='register_read',value=None,
            result_address=0x10004,allow_side_effect=False))
        plan_bytes,trace=session.finish_export()
        assert any(event.get('kind')=='memory_write_commit' for event in trace.events)
        plan=json.loads(plan_bytes);state=runtime.snapshot()
        api._validate_saved_register_documents(plan,state)
        return plan,state,assembly,session.manifest_document
    finally:
        for target in session.runner.sessions.values():target.end_case()


def resume_shape(captured):
    plan,state,assembly,manifest=deepcopy(captured)
    plan['schema_version']=18
    plan['reset_operations']=[dict(after_cases=len(plan['cases']),policy='warm_all',
                                   advances=[list(plan['template']['schedule_order'])])]
    # These values are a closed saved-data model, not asserted actual reset facts.
    # Real reset occurrence is tested by fresh replay in separate actual fixtures.
    return plan,state,assembly,manifest


def test_schema18_writer_reaches_channel_checks_through_real_closed_validator(captured_register_model,tmp_path,monkeypatch):
    plan,state,assembly,manifest=resume_shape(captured_register_model)
    output=tmp_path/'must_not_be_created'
    class ChannelCheckpoint(Exception):pass
    def checkpoint(*args):raise ChannelCheckpoint('closed validator and version admission reached')
    monkeypatch.setattr(api,'_validate_reference',lambda trace:None)
    monkeypatch.setattr(api,'_verify_capability_channel',checkpoint)
    with pytest.raises(ChannelCheckpoint):
        api._save_ibex_pulp_register_bundle(output_dir=output,assembly=assembly,
            session_manifest=manifest,plan_bytes=api._json(plan).encode(),trace=object(),runtime_state=state)
    assert not output.exists()


@pytest.mark.parametrize('mutation',['unknown_row','bool_boundary','missing_advances','nonlist_advances',
    'unknown_component','no_reset','empty_commands'])
def test_resume_malformed_rows_refused_by_closed_writer_before_mkdir(captured_register_model,tmp_path,monkeypatch,mutation):
    plan,state,assembly,manifest=resume_shape(captured_register_model)
    row=plan['reset_operations'][0]
    if mutation=='unknown_row':row['saved_epoch']=1
    elif mutation=='bool_boundary':row['after_cases']=True
    elif mutation=='missing_advances':del row['advances']
    elif mutation=='nonlist_advances':row['advances']={}
    elif mutation=='unknown_component':row['advances']=[['foreign_provider']]
    elif mutation=='no_reset':plan['reset_operations']=[]
    else:row['advances']=[]
    output=tmp_path/mutation
    monkeypatch.setattr(api,'_validate_reference',lambda trace:None)
    with pytest.raises(ValueError):
        api._save_ibex_pulp_register_bundle(output_dir=output,assembly=assembly,
            session_manifest=manifest,plan_bytes=api._json(plan).encode(),trace=object(),runtime_state=state)
    assert not output.exists()
