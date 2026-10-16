"""Nonempty source-bound alias saved-file replay; software transport, never RTL."""
import json
from copy import deepcopy
import shutil
from unittest.mock import Mock
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
from tests.scenario.test_register_alias_verifier import alias_factory
from tests.scenario.test_register_program_runtime import request
from tests.integration.test_register_field_read_replay import install_software, reauthenticate


@pytest.mark.parametrize('source,mask,expected',[('PADOUTSET',0x80000001,0x92345679),('PADOUTCLR',0x10000008,0x02345670)])
def test_actual_alias_bracket_authenticated_original_request_fresh_replay(tmp_path,monkeypatch,source,mask,expected):
    assembly=api.make_register_assembly(advance_rounds=1,
        ordinary_apb_access_evidence={'max_records':16},register_program_verifier={'max_records':16})
    factory=alias_factory(api.make_register_factory(cache_dir=tmp_path/'render',assembly=assembly))
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    runtime=api.make_register_runtime_factory(assembly)(session)
    rows=[request(case_id='before',action_id='read-before',target_instance='gpio_a',register='PADOUT',field='value',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False),
          request(case_id='alias',action_id='write-alias',target_instance='gpio_a',register=source,field='bits',operation='register_write',value=mask,allow_side_effect=True),
          request(case_id='after',action_id='read-after',target_instance='gpio_a',register='PADOUT',field='value',operation='register_read',value=None,result_address=0x10008,allow_side_effect=False)]
    session.begin()
    for row in rows:runtime.submit(row)
    trace=session.finish();plan=session.encode_plan();wrapper=session.register_program_verifier_document()
    state=session.runner.ordinary_apb_access_evidence_snapshot()
    assert state['counts']==dict(records=3,pending=0,cpu_delivery_confirmed=3)
    assert all(r['raw_event_refs'] and r['base_event_refs'] for r in state['records'])
    commits=[e for e in trace.events if e.get('kind')=='memory_write_commit'];assert len(commits)==2
    writes=[e for e in trace.events if e.get('kind')=='memory_write']
    assert [(e['address'],e['value']) for e in writes]==[(0x10004,0x12345678),(0x10008,expected)]
    certificates=[c for c in wrapper['state']['current_certificates'] if c['case_id']=='alias']
    assert len(certificates)==1,wrapper['state']['gaps']
    assert certificates[0]['rule']=='ordinary_register_alias_readback.v1'
    assert json.loads(plan)['register_programs']['register_program_verifier']==wrapper
    bundle=tmp_path/'bundle'
    api.save_ibex_pulp_register_bundle(output_dir=bundle,assembly=assembly,session_manifest=session.manifest_document,plan_bytes=plan,trace=trace,runtime_state=runtime.snapshot())
    install_software(monkeypatch,dict(factory=factory))
    fresh=api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'unused',output_dir=bundle)
    assert fresh.matches and fresh.register_program_verifier==wrapper
    assert fresh.ordinary_apb_access_evidence==state

    # Authenticating malformed comparison facts never enables a provider.
    for mutation in ('unknown_relation_key','missing_ram_event'):
        bad=json.loads(plan)
        report=bad['register_programs']['register_program_verifier']['state']
        for collection in ('current_certificates','historical_certificates'):
            for certificate in report[collection]:
                if certificate['case_id']=='alias':
                    if mutation=='unknown_relation_key':
                        certificate['result']['alias_relation']['authority']=True
                    else:
                        certificate['result']['after_result_commit']['event_id']=999999999
        rejected=tmp_path/('writer-'+mutation)
        with pytest.raises(ValueError):
            api.save_ibex_pulp_register_bundle(output_dir=rejected,assembly=assembly,
                session_manifest=session.manifest_document,plan_bytes=json.dumps(bad),
                trace=trace,runtime_state=runtime.snapshot())
        assert not rejected.exists(), 'writer must reject before mkdir'
        changed=tmp_path/('saved-'+mutation);shutil.copytree(bundle,changed)
        reauthenticate(changed,{'online_plan.json':bad})
        forbidden=Mock(side_effect=AssertionError('saved facts cannot start a factory'))
        with monkeypatch.context() as isolated:
            isolated.setattr(api,'make_register_factory',forbidden)
            with pytest.raises(ValueError):
                api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'forbidden',output_dir=changed)
        forbidden.assert_not_called()
