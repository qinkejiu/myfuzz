"""Closed verifier opt-in; software-only production replay integration."""
from unittest.mock import Mock, patch
import pytest
from myfuzz.integration import ibex_pulp_register_replay as api


def test_verifier_assembly_closed_and_requires_ordinary():
    assert 'register_program_verifier' not in api.make_register_assembly()
    with pytest.raises(ValueError, match='ordinary'):
        api.make_register_assembly(register_program_verifier={'max_records':8})
    for bad in (None,False,{}, {'max_records':True},{'max_records':0},
                {'max_records':65537},{'max_records':8,'authority':True}):
        with pytest.raises(ValueError):
            api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8},register_program_verifier=bad)
    for size in (1,65536):
        d=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8},register_program_verifier={'max_records':size})
        assert d['register_program_verifier']=={'max_records':size}


def test_verifier_installer_order():
    d=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8},requested_minimum_level='L1',register_program_verifier={'max_records':8})
    order=[];session=Mock()
    session.configure_ordinary_apb_access_evidence.side_effect=lambda **kw:order.append('ordinary')
    session.configure_register_capability_preflight.side_effect=lambda *a:order.append('capability')
    session.configure_register_program_verifier.side_effect=lambda **kw:order.append('verifier')
    with patch('myfuzz.scenario.register_program_runtime.RegisterProgramRuntime',side_effect=lambda *a,**kw:order.append('runtime') or Mock()):
        api.make_register_runtime_factory(d)(session)
    assert order==['ordinary','runtime','capability','verifier']


def test_verifier_channel_presence_rejected_before_factory():
    enabled=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8},register_program_verifier={'max_records':8})
    with pytest.raises(ValueError,match='presence'):
        api._verify_register_verifier_channel(enabled,{'register_programs':{}},{})
    with pytest.raises(ValueError,match='presence'):
        api._verify_register_verifier_channel(api.make_register_assembly(),{'register_programs':{'register_program_verifier':{}}},{})


def test_default_replay_result_has_no_verifier_report():
    assert api.RegisterReplayResult(Mock()).register_program_verifier is None


def test_source_closure_optin_verifier_utility_only():
    d=api.make_register_assembly(ordinary_apb_access_evidence={'max_records':8},register_program_verifier={'max_records':8})
    with patch('myfuzz.scenario.session_runtime._register_program_verifier_source_files',create=True,return_value=[{'path':'src/myfuzz/scenario/register_program_verifier.py','sha256':'unused'}]) as utility:
        paths={r['path'] for r in api._sources(d)}
        utility.assert_called_once_with()
    assert 'src/myfuzz/scenario/register_program_verifier.py' in paths


def test_fresh_verifier_wrapper_is_compared_exactly():
    session=Mock();session.register_program_verifier_document.return_value={'state':{'actual':1}}
    assert api._fresh_register_verifier(session,{'register_program_verifier':{'state':{'actual':1}}})=={'state':{'actual':1}}
    with pytest.raises(ValueError,match='terminal state'):
        api._fresh_register_verifier(session,{'register_program_verifier':{'state':{'actual':True}}})
    session.register_program_verifier_document.return_value=None
    assert api._fresh_register_verifier(session,{}) is None


def test_cli_emits_only_optin_fresh_observational_wrapper():
    import io,json
    from contextlib import redirect_stdout
    from types import SimpleNamespace
    from tests.integration.test_register_capability_cli import cli_module
    module=cli_module();wrapper={'schema_version':'register_program_verifier_session.v1','state':{'actual':'comparison'}}
    result=SimpleNamespace(matches=True,verification_scope=('register_program_reconstruction',),register_program_verifier=wrapper,
        comparison=SimpleNamespace(first_difference=None,difference_context=None,actual_trace=SimpleNamespace(events=(),semantic_sha256='a'*64)))
    output=io.StringIO()
    with patch.object(module,'replay_ibex_pulp_register_files',return_value=result),redirect_stdout(output):
        assert module.main(['replay-register-programs','--cache-dir','cache','--run-dir','saved'])==0
    assert json.loads(output.getvalue())['register_program_verifier']==wrapper


def test_nonempty_actual_private_read_ram_authenticated_fresh_replay(tmp_path,monkeypatch):
    """Software machine-word driver, never a DUT/RTL oracle."""
    import json
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    from tests.integration.test_register_field_read_replay import field_factory,install_software
    from tests.scenario.test_register_program_runtime import request
    assembly=api.make_register_assembly(advance_rounds=1,ordinary_apb_access_evidence={'max_records':8},register_program_verifier={'max_records':8})
    factory=field_factory(api.make_register_factory(cache_dir=tmp_path/'render',assembly=assembly))
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap();session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    adapter=api.make_register_runtime_factory(assembly)(session);session.begin()
    row=request(case_id='pin7',action_id='read-pin7',target_instance='gpio_a',register='PADCFG_0',field='pin7',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False)
    adapter.submit(row);trace=session.finish();plan=session.encode_plan();wrapper=session.register_program_verifier_document()
    assert wrapper['state']['status']=='complete'
    assert any(e.get('kind')=='memory_write_commit' for e in trace.events)
    assert session.runner.ordinary_apb_access_evidence_snapshot()['counts']['cpu_delivery_confirmed']==1
    assert json.loads(plan)['register_programs']['register_program_verifier']==wrapper
    bundle=tmp_path/'bundle';api.save_ibex_pulp_register_bundle(output_dir=bundle,assembly=assembly,session_manifest=session.manifest_document,plan_bytes=plan,trace=trace,runtime_state=adapter.snapshot())
    install_software(monkeypatch,dict(factory=factory))
    result=api.replay_ibex_pulp_register_files(cache_dir=tmp_path/'unused',output_dir=bundle)
    assert result.matches and result.register_program_verifier==wrapper
