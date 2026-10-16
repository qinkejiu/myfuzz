"""Actual private access/generation boundaries; software transport only."""
import pytest
from tests.scenario.test_register_alias_verifier import alias_environments, alias_factory, alias_fixture
from tests.scenario.test_register_program_runtime import request
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime


def test_equal_value_unselected_actual_cpu_write_breaks_alias_interval(alias_environments):
    factory,sidecar=alias_environments[False]
    runner=alias_factory(factory)()
    original=runner.step_batch
    injected=[]
    def step(order):
        active=runner._test_session._register_program_runtime._active_submission
        if active and active[1]['request']['case_id']=='after' and not injected:
            injected.append(True)
            cpu=runner.sessions['cpu']
            window=next(w for w in cpu.router.windows if w.device_id=='gpio_a')
            cpu._pending_data=None
            # Preserve the expected SET result exactly; only actual write
            # chronology changes, without registering another SourceAction.
            cpu._serve('data',1,window.base+12,0x92345679,15)
            runner._append_external_events('cpu',len(runner.events))
            runner._step_once('gpio_a')
            cpu._pending_data=None
        original(order)
    runner.step_batch=step
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,runner);runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    session.configure_ordinary_apb_access_evidence(max_records=16)
    runtime=RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':sidecar},advance_rounds=1,max_records=16)
    session.configure_register_program_verifier(max_records=16)
    def row(label,**kwargs):return request(case_id=label,action_id='boundary-'+label,target_instance='gpio_a',**kwargs)
    read=dict(register='PADOUT',field='value',operation='register_read',value=None,allow_side_effect=False)
    session.begin()
    for item in (row('before',result_address=0x10004,**read),
                 row('alias',register='PADOUTSET',field='bits',operation='register_write',value=0x80000001,allow_side_effect=True),
                 row('after',result_address=0x10008,**read)):
        runtime.submit(item)
    report=runner._register_program_verifier.report()
    assert injected==[True]
    accesses=runner._ordinary_apb_access_evidence.completed_accesses()
    assert len(accesses)==4
    assert accesses[-1]['cpu_response'][0]==0x92345679
    assert not any(c['case_id']=='alias' for c in report['current_certificates'])
    assert dict(case_id='alias',reason='intervening_target_write') in report['gaps']


def test_actual_memory_cold_reset_clears_alias_current_without_restoring_history(alias_environments):
    fixture=alias_fixture(alias_environments)
    verifier=fixture['verifier'];before=verifier.report()
    assert any(c['case_id']=='alias' for c in before['current_certificates'])
    memory=fixture['session'].runner.sessions['cpu'].service.memory
    generation=memory.generation
    memory.cold_reset()
    assert memory.generation!=generation
    after=verifier.report()
    assert after['current_certificates']==[]
    assert after['historical_certificates']==before['historical_certificates']
    assert verifier.snapshot('gpio_a').operations==()


@pytest.mark.parametrize('version',['ip_test_capability.v1','ip_test_capability.v2'])
def test_legacy_effect_rule_gap_remains_compatible(alias_environments,tmp_path,version):
    import json
    factory,sidecar=alias_environments[False]
    document=json.loads(sidecar.read_bytes())
    document['schema_version']=version
    if version.endswith('.v2'):
        from tests.composition.test_register_alias_capability import feature_contract
        document['feature_contract']=feature_contract(document)
    document.pop('register_aliases')
    legacy=tmp_path/'legacy-sidecar.json';legacy.write_text(json.dumps(document))
    fixture=alias_fixture({False:(factory,legacy)})
    report=fixture['verifier'].report()
    assert not any(c['case_id']=='alias' for c in report['current_certificates'])
    assert dict(case_id='alias',reason='unsupported_effect_rule') in report['gaps']
