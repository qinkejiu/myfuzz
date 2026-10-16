"""Actual object admission for ordinary register semantics, software only."""
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session


def test_actual_beforebegin_empty_report_is_detached_and_has_no_verification(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory)
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result)
    verifier=RegisterProgramVerifier(runtime,max_records=4)
    report=verifier.report()
    assert report['historical_certificates']==[] and report['current_certificates']==[]
    assert report['grants_functional'] is False
    report['configuration']['max_records']=999
    assert verifier.configuration()['max_records']==4
    assert verifier.snapshot('gpio_a').operations==()


@pytest.mark.parametrize('bound',[True,0,65537])
def test_bound_rejected_without_actual_commands(actual_factory,bound):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result)
    with pytest.raises(ValueError):RegisterProgramVerifier(runtime,max_records=bound)
    assert result.runner.event_count==0


def test_requires_installed_live_collector(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory);runtime=adapter(result)
    with pytest.raises(ValueError):RegisterProgramVerifier(runtime)


def test_actual_read_without_cpu_ram_result_commit_remains_gap(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_ordinary_apb_access_session import observed_factory
    from tests.scenario.test_register_program_runtime import request
    result=session(observed_factory(actual_factory));result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result);verifier=RegisterProgramVerifier(runtime,max_records=4)
    result.begin();runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False))
    report=verifier.report()
    assert report['current_certificates']==[]
    assert report['gaps']==[{'case_id':'case','reason':'missing_actual_cpu_result_commit'}]
    assert verifier.snapshot('gpio_a').operations==()


def read_result_factory(actual_factory, *, stored_value=17):
    from tests.scenario.test_ordinary_apb_access_session import observed_factory
    base=observed_factory(actual_factory)
    def factory():
        runner=base();step=runner.step_batch
        def execute(order):
            step(order)
            cpu=runner.sessions['cpu']
            assert cpu._pending_data[0]==17
            cpu._pending_data=None
            cpu._serve('data',1,0x10004,stored_value,15)
            runner._append_external_events('cpu',1)
        runner.step_batch=execute
        return runner
    return factory


@pytest.mark.parametrize('stored_value,verified',[(17,True),(18,False)])
def test_actual_requested_read_requires_actual_cpu_ram_commit_value(actual_factory,stored_value,verified):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_register_program_runtime import request
    result=session(read_result_factory(actual_factory,stored_value=stored_value))
    result.configure_ordinary_apb_access_evidence(max_records=4);runtime=adapter(result)
    verifier=RegisterProgramVerifier(runtime,max_records=4);result.begin()
    runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False))
    report=verifier.report()
    assert bool(report['current_certificates']) is verified
    if verified:
        cert=report['current_certificates'][0]
        assert cert['rule']=='ordinary_register_read_result.v1'
        assert cert['proof_scope']=='observed_cpu_register_readback_consistency'
        assert cert['grants_storage'] is False and cert['grants_version_dependency'] is False
        assert len(verifier.snapshot('gpio_a').operations)==1
    else:assert report['gaps'][0]['reason']=='missing_actual_cpu_result_commit'


def test_own_instance_method_override_is_rejected(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=4)
    verifier=RegisterProgramVerifier(adapter(result),max_records=4)
    verifier._consume_actual_commit=lambda logged,token:None
    with pytest.raises(ValueError,match='method-drift'):verifier.report()


def write_readback_factory(actual_factory, *, later=1, intervening=False, rmw=False, written=1):
    from tests.local_harness.test_ordinary_apb_access_receipts import software_transport
    def factory():
        runner=actual_factory();begin=runner.begin_test
        def start(case_id):
            begin(case_id);software_transport(runner.sessions['gpio_a'],rdata=later)
        runner.begin_test=start
        def step(order):
            cpu=runner.sessions['cpu'];target=runner.sessions['gpio_a']
            window=next(w for w in cpu.router.windows if w.target is target)
            offset=40 if rmw else 12
            operations=([(0,window.base+offset,0)] if rmw else [])+[(1,window.base+offset,written)]
            if intervening:operations.append((1,window.base+16,1))
            operations.append((0,window.base+offset,0))
            for write,address,value in operations:
                cpu._pending_data=None
                cpu._serve('data',write,address,value,15)
                runner._ordinary_apb_access_evidence.preflight_access(cpu.router,target)
                cpu.router.drain_one('gpio_a')
                runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
                runner.local_ticks['gpio_a']=target.local_ticks;runner._drain_tick_samples(1)
                runner._finalize_ordinary_apb_access(cpu.router,target)
        runner.step_batch=step
        return runner
    return factory


@pytest.mark.parametrize('later,intervening,verified',[(1,False,True),(2,False,False),(1,True,False)])
def test_actual_write_requires_later_readback_without_intervening_alias(actual_factory,later,intervening,verified):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_register_program_runtime import request
    result=session(write_readback_factory(actual_factory,later=later,intervening=intervening))
    result.configure_ordinary_apb_access_evidence(max_records=4);runtime=adapter(result)
    verifier=RegisterProgramVerifier(runtime,max_records=4);result.begin()
    runtime.submit(request(target_instance='gpio_a',allow_side_effect=False))
    report=verifier.report()
    assert bool(report['current_certificates']) is verified
    if verified:assert report['current_certificates'][0]['rule']=='ordinary_register_write_readback.v1'


@pytest.mark.parametrize('written,verified',[(17,True),(1,False)])
def test_rmw_checks_actual_initial_read_and_preserves_unaffected_bits(actual_factory,written,verified):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
    from tests.scenario.test_register_program_replay import SIDECAR
    from tests.scenario.test_register_program_runtime import request
    result=session(write_readback_factory(actual_factory,later=17,rmw=True,written=written))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=RegisterProgramRuntime(result,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1,max_program_bytes=64)
    verifier=RegisterProgramVerifier(runtime,max_records=4);result.begin()
    runtime.submit(request(target_instance='gpio_a',register='PADCFG_0',field='pin0',read_modify_write=True,allow_side_effect=False))
    report=verifier.report()
    assert bool(report['current_certificates']) is verified
    if verified:assert report['current_certificates'][0]['rule']=='ordinary_register_rmw_readback.v1'


def test_successful_manifest_drift_disagrees_with_actual_submitted_record(actual_factory):
    import json
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_register_program_runtime import request
    result=session(read_result_factory(actual_factory));result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result);verifier=RegisterProgramVerifier(runtime,max_records=4);result.begin()
    runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False))
    encoded,receipt=runtime._successful['case'];document=json.loads(encoded)
    document['request']['register']='PADDIR'
    runtime._successful['case']=(json.dumps(document,sort_keys=True,separators=(',',':')),receipt)
    with pytest.raises(ValueError,match='successful-case-binding'):verifier.report()


def test_real_uncertain_callback_prefix_cannot_preflight_more_commands(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_ordinary_apb_access_session import observed_factory
    from tests.scenario.test_register_program_runtime import request
    result=session(observed_factory(actual_factory,callback_failure=True));result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result);verifier=RegisterProgramVerifier(runtime,max_records=4);result.begin()
    with pytest.raises(TypeError):runtime.submit(request(target_instance='gpio_a'))
    assert verifier.report()['current_certificates']==[]
    with pytest.raises(ValueError,match='incomplete'):verifier._preflight_command()


def test_full_record_capacity_allows_remaining_ticks_but_refuses_new_operation(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.scenario.test_register_program_runtime import request
    result=session(read_result_factory(actual_factory));result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result);verifier=RegisterProgramVerifier(runtime,max_records=1);result.begin()
    runtime.submit(request(target_instance='gpio_a',operation='register_read',value=None,result_address=0x10004,allow_side_effect=False))
    assert len(verifier.report()['historical_certificates'])==1
    verifier._preflight_command()
    with pytest.raises(ValueError,match='capacity'):verifier._preflight_command(new_operation=True)
    with pytest.raises(ValueError):verifier._preflight_command(new_operation=1)
    assert len(verifier.report()['historical_certificates'])==1


def test_actual_bootstrap_commit_is_consumed_without_retaining_semantic_candidate(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime=adapter(result);verifier=RegisterProgramVerifier(runtime,max_records=1)
    cpu=result.runner.sessions['cpu'];cpu._case_id='bootstrap-commit'
    cpu._serve('data',1,0x10004,17,15)
    result.runner._append_external_events('cpu',1)
    assert result.runner._memory_commit_authority.pending_count==0
    assert verifier._commits=={}
    verifier._preflight_command(new_operation=True)

