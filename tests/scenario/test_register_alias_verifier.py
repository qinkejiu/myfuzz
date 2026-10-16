"""Next alias rule TDD using actual private services; software transport, no RTL."""
from copy import deepcopy
from dataclasses import replace
import json
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import ExitStack
import pytest
from myfuzz.local_harness.wire import parse_driver_receipt
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
from tests.composition.test_register_alias_capability import documents
from tests.integration.test_register_field_read_replay import field_factory
from tests.scenario.test_register_program_runtime import request


def alias_factory(factory, *, initial=0x12345678, after_override=None, missing_before_commit=False):
    """Reuse admitted RV32I interpreter; install one stateful parsed transport."""
    base=field_factory(factory)
    def create():
        runner=base();begin=runner.begin_test;execute=runner.step_batch;incomplete_read=set()
        def start(case_id):
            begin(case_id)
            for name in ('gpio_a','gpio_b'):
                target=runner.sessions[name]
                _alias_transport(target,initial=initial,after_override=after_override)
        def steps(order):
            active=runner._test_session._register_program_runtime._active_submission
            if (not missing_before_commit or active is None
                    or active[1]['request']['case_id']!='before'):
                return execute(order)
            source=active[1]['program']['source']
            if source['action_id'] in incomplete_read:return
            incomplete_read.add(source['action_id'])
            cpu=runner.sessions['cpu'];manifest=active[1]
            # Model an actual CPU prefix stopping before result STORE. No issue
            # token exists; do not replace or manufacture commit authority.
            address=manifest['context']['address_base']+manifest['program']['operation_plan']['offset']
            cpu._pending_data=None;cpu._serve('data',0,address,0,15)
            runner._append_external_events('cpu',len(runner._events))
            window=next(w for w in cpu.router.windows if w.base<=address<w.base+w.size)
            runner._step_once(window.device_id)
            cpu._pending_data=None;cpu._pending_instr=None
            cpu._serve('instr',0,source['address']+len(bytes.fromhex(source['data_hex'])),0,15)
            runner._append_external_events('cpu',len(runner._events))
        runner.begin_test=start;runner.step_batch=steps
        return runner
    return create


def _alias_transport(target, *, initial, after_override):
    # Each target owns a persistent execution and driver sequence; no re-install
    # per access. The simulated register state is not registered as authority.
    target._case_id='alias-software';target._execution='0123456789abcdef0123456789abcdef'
    storage={'value':initial,'writes':0}
    def command(operation,fields):
        write,address,value=fields[1:4]
        if write:
            if address==12:storage['value']=value
            elif address==16:storage['value']|=value
            elif address==20:storage['value']&=(~value&0xffffffff)
            storage['writes']+=1
        rdata=storage['value'] if address==12 else 0
        if after_override is not None and address==12 and storage['writes']:rdata=after_override
        before=target.local_ticks-target._tick_base;sequence=target._sequence+1
        observed=dict(gpio_out=0,gpio_dir=0,gpio_in_sync=0,gpio_padcfg='0'*32,interrupt=0,
            backend={},physical={r['runtime_name']:0 for r in target.artifact.runtime_document['physical_exports']})
        samples=[]
        for index in range(3):
            state=deepcopy(observed)
            state['backend']=dict(trace_psel=int(index<2),trace_penable=int(index==1),
                trace_pready=1,trace_pslverr=0,trace_paddr=address,trace_pwrite=write,
                trace_pwdata=value,trace_prdata=rdata)
            samples.append(dict(local_tick=before+index+1,pre=state,post=deepcopy(state)))
        payload=dict(schema_version='local_driver_result.v1',kind='apb_gpio',samples=samples,
            observations=observed,pre_backend={},rdata=rdata,error=0)
        encoded=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode().hex()
        receipt=parse_driver_receipt(f'RESULT {target._execution} {sequence:x} {before:x} {before+3:x} {encoded}',
            execution=target._execution,sequence=sequence,current_tick=before,kind='apb_gpio')
        target._sequence=sequence;target.local_ticks=target._tick_base+receipt.tick_after
        return receipt
    target.command=command


@pytest.fixture(scope='module')
def alias_environments(tmp_path_factory):
    from myfuzz.scenario import ibex_pulp_dual_source as wiring
    environments={}
    workspace=Path(__file__).resolve().parents[2]
    with ExitStack() as cleanup:
        for renamed in (False,True):
            root=tmp_path_factory.mktemp('alias-renamed' if renamed else 'alias-ordinary')
            raw,profile,capability=documents(renamed=renamed)
            if renamed:
                # Actual native source-lock still selects pulp_gpio. This tests
                # generic register/endpoint names, not a new source component.
                from myfuzz.composition.component_profile import load_component_profile
                raw['component_id']='pulp_gpio';profile=load_component_profile(raw)
                capability['component_id']=profile.component_id
                capability['profile_fingerprint']=profile.profile_fingerprint
            profile_dir=Path(cleanup.enter_context(TemporaryDirectory(dir=workspace/'configs',prefix='.alias-test-')))
            profile_path=profile_dir/'component_profile.json';profile_path.write_text(json.dumps(raw))
            sidecar=root/'capability.json';sidecar.write_text(json.dumps(capability))
            original=wiring.dual_source_wiring
            def actual_wiring(*args,**kwargs):return replace(original(*args,**kwargs),gpio_profile=profile_path.relative_to(workspace).as_posix())
            with patch.object(wiring,'dual_source_wiring',actual_wiring):
                factory=wiring.make_ibex_pulp_dual_source_factory(root/'render',physical_observations=True,
                    memory_commit_receipts=True,persistent_memory_runtime_contract_sha256='a'*64)
            environments[renamed]=(factory,sidecar)
        yield environments


def alias_fixture(environments, *, renamed=False, operation='set_bits',initial=0x12345678,
                  written=0x80000001,after_override=None,intervening=False,missing_before=False,
                  missing_before_commit=False,foreign_after_case=False,fail_alias_callback=False):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    factory,sidecar=environments[renamed]
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,alias_factory(factory,initial=initial,after_override=after_override,missing_before_commit=missing_before_commit)())
    session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    session.configure_ordinary_apb_access_evidence(max_records=16)
    runtime=RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':sidecar},advance_rounds=1,max_records=16)
    session.configure_register_program_verifier(max_records=16)
    verifier=session.runner._register_program_verifier
    destination='DATA' if renamed else 'PADOUT';endpoint='register.bus' if renamed else 'gpio.bus'
    source=('DATA_SET' if renamed else 'PADOUTSET') if operation=='set_bits' else ('DATA_CLEAR' if renamed else 'PADOUTCLR')
    def row(label,**changes):
        return request(case_id=label,action_id='action-'+label,target_instance='gpio_a',endpoint_id=endpoint,**changes)
    read=dict(register=destination,field='value',operation='register_read',value=None,allow_side_effect=False)
    requests=[]
    if not missing_before:requests.append(row('before',result_address=0x10004,**read))
    requests.append(row('alias',register=source,field='bits',operation='register_write',value=written,allow_side_effect=True))
    if intervening:requests.append(row('intervening',register=destination,field='value',operation='register_write',value=initial,allow_side_effect=False))
    requests.append(row('after',result_address=0x10008,**read))
    session.begin()
    for item in requests:
        cpu=session.runner.sessions['cpu']
        if item['case_id']=='after' and foreign_after_case:
            cpu._case_id='other-real-cpu-case'
            # The actual ledger refuses a new testcase with the old channel's
            # sequence. Do not fabricate/reset private counters to bypass it.
            with pytest.raises(ValueError,match='out_of_order_transaction'):runtime.submit(item)
            break
        if item['case_id']=='alias' and fail_alias_callback:
            verifier.report()  # Preserve completed before-READ history first.
            cpu.mmio_write_count='actual completed callback TypeError'
            with pytest.raises(TypeError):runtime.submit(item)
            break
        runtime.submit(item)
    return dict(session=session,runtime=runtime,verifier=verifier,requests=requests,initial=initial,written=written)


@pytest.mark.parametrize('renamed',[False,True])
@pytest.mark.parametrize('operation',['set_bits','clear_bits'])
def test_source_bound_alias_interval_verifies_only_actual_selected_write(alias_environments,renamed,operation):
    fixture=alias_fixture(alias_environments,renamed=renamed,operation=operation)
    report=fixture['verifier'].report()
    certificates=[r for r in report['current_certificates'] if r['case_id']=='alias']
    assert len(certificates)==1, report['gaps']
    cert=certificates[0]
    assert cert['rule']=='ordinary_register_alias_readback.v1'
    result=cert['result'];assert result['alias_relation']['operation']==operation
    expected=(fixture['initial']|fixture['written']) if operation=='set_bits' else fixture['initial']&(~fixture['written']&0xffffffff)
    assert result['expected_value']==expected
    assert result['before_readback_access']['ordinal']<cert['observed_accesses'][0]['ordinal']
    assert cert['observed_accesses'][0]['ordinal']<result['after_readback_access']['ordinal']
    assert result['before_result_commit'] and result['after_result_commit']
    assert cert['operation']=='register_write' and cert['proof_scope']=='observed_cpu_register_readback_consistency'
    assert all(cert[k] is False for k in ('grants_storage','grants_version_dependency','grants_prerequisites','grants_functional'))
    operations=fixture['verifier'].snapshot('gpio_a').operations
    assert any(r.scope==fixture['requests'][1]['register']+'.bits' and r.operation=='register_write' for r in operations)


@pytest.mark.parametrize('variant',['missing_before','intervening','wrong_untouched_bits'])
def test_invalid_alias_interval_remains_explicit_gap(alias_environments,variant):
    changes={'missing_before':True} if variant=='missing_before' else {'intervening':True} if variant=='intervening' else {'after_override':0x80000001}
    fixture=alias_fixture(alias_environments,**changes);report=fixture['verifier'].report()
    assert not any(c['case_id']=='alias' for c in report['current_certificates'])
    gap=next(r for r in report['gaps'] if r['case_id']=='alias')
    assert gap['reason'] in {'missing_alias_before_readback','intervening_target_write','actual_alias_readback_mismatch'}


def test_before_read_without_actual_private_ram_issue_cannot_support_alias(alias_environments):
    fixture=alias_fixture(alias_environments,missing_before_commit=True)
    report=fixture['verifier'].report()
    assert not any(c['case_id']=='alias' for c in report['current_certificates'])
    assert next(g for g in report['gaps'] if g['case_id']=='alias')['reason']=='missing_alias_before_readback'
    assert not any(c['case_id']=='before' for c in report['current_certificates'])


def test_after_read_from_other_actual_cpu_case_cannot_support_alias(alias_environments):
    fixture=alias_fixture(alias_environments,foreign_after_case=True)
    report=fixture['verifier'].report()
    assert not any(c['case_id']=='alias' for c in report['current_certificates'])
    assert not any(c['case_id']=='alias' for c in report['historical_certificates'])
    assert report['status']=='incomplete' and report['reason']=='runtime_uncertain'


def test_actual_alias_callback_failure_keeps_read_history_and_clears_current(alias_environments):
    fixture=alias_fixture(alias_environments,fail_alias_callback=True)
    report=fixture['verifier'].report()
    assert len(report['historical_certificates'])==1
    assert report['historical_certificates'][0]['case_id']=='before'
    assert report['current_certificates']==[] and report['status']=='incomplete'
    assert report['reason'] in ('runtime_uncertain','ordinary_observation_incomplete')
    assert fixture['verifier'].snapshot('gpio_a').operations==()


def resettable_alias_factory(factory, worker_root):
    """Real READY/END processes for lifecycle only, not a GPIO/CPU RTL emulator."""
    create=alias_factory(factory)
    def runner_factory():
        runner=create();software_begin=runner.begin_test;processes=[]
        for name,local in runner.sessions.items():
            digest,asserted,released,_=local._expected_ready()
            worker=worker_root/(name+'-ready-end.py')
            worker.write_text('#!/usr/bin/env python3\nimport sys\n'
                +f'print("READY local_driver.v1 {digest} {asserted:x} {released:x}",flush=True)\n'
                +'for line in sys.stdin:\n    if line.strip()=="END":break\n')
            worker.chmod(0o700)
            local._binary=worker
        def begin(case_id):
            software_begin(case_id)
            for local in runner.sessions.values():
                local.begin_case('stream')
                processes.append(local.process)
            # Actual CPU.begin_case cleared the prior software waiting state.
            from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
            address=make_ibex_pulp_dual_source_stream_bootstrap().instruction_start
            runner.sessions['cpu']._serve('instr',0,address,0,15)
        runner.begin_test=begin
        runner._alias_lifecycle_processes=processes
        return runner
    return runner_factory


@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_actual_session_reset_lifecycle_breaks_alias_interval_and_clears_old_current(alias_environments,tmp_path,policy):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    factory,sidecar=alias_environments[False];bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    result=ScenarioSession(bootstrap.template,resettable_alias_factory(factory,tmp_path)())
    result.runner._test_session=result
    result.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    result.configure_ordinary_apb_access_evidence(max_records=16)
    runtime=RegisterProgramRuntime(result,cpu_component='cpu',sidecars={'gpio_a':sidecar},advance_rounds=1,max_records=16)
    result.configure_register_program_verifier(max_records=16);verifier=result.runner._register_program_verifier
    def row(label,**changes):return request(case_id=label,action_id='reset-'+label,target_instance='gpio_a',**changes)
    read=dict(register='PADOUT',field='value',operation='register_read',value=None,allow_side_effect=False)
    processes=[]
    try:
        result.begin();cpu=result.runner.sessions['cpu'];target=result.runner.sessions['gpio_a']
        processes=list(result.runner._alias_lifecycle_processes)
        assert len(processes)==3 and all(p.poll() is None for p in processes)
        runtime.submit(row('before',result_address=0x10004,**read))
        assert len(verifier.report()['current_certificates'])==1
        next_slot=cpu.waiting_instruction_address
        old_generation=cpu.memory.generation
        old_epochs={name:local.reset_epoch for name,local in result.runner.sessions.items()}
        result.reset(policy)
        assert all(p.poll() is not None for p in processes)
        new_processes=[local.process for local in result.runner.sessions.values()]
        assert all(p.poll() is None for p in new_processes)
        assert all(new is not old for new,old in zip(new_processes,processes))
        assert all(local.reset_epoch==old_epochs[name]+1 for name,local in result.runner.sessions.items())
        assert cpu.memory.generation==old_generation+int(policy=='cold_all')
        report=verifier.report()
        assert len(report['historical_certificates'])==1 and report['current_certificates']==[]
        assert any(event.get('kind')=='reset_barrier' for event in result.runner.events)
        # New epoch, actual deferred fetch, an unused declared physical slot.
        cpu._serve('instr',0,next_slot,0,15)
        result.runner._append_external_events('cpu',len(result.runner._events))
        runtime.submit(row('alias',register='PADOUTSET',field='bits',operation='register_write',value=1,allow_side_effect=True))
        runtime.submit(row('after',result_address=0x10008,**read))
        report=verifier.report()
        assert not any(c['case_id']=='alias' for c in report['historical_certificates'])
        assert next(g for g in report['gaps'] if g['case_id']=='alias')['reason']=='alias_scope_mismatch'
        assert [c['case_id'] for c in report['current_certificates']]==['after']
    finally:
        current=[local.process for local in result.runner.sessions.values()]
        for local in result.runner.sessions.values():local.end_case()
        assert all(p is None or p.poll() is not None for p in current)
