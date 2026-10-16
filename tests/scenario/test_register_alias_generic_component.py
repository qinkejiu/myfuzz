"""Fully renamed IP on actual private CPU/router services; software only."""
import json
from dataclasses import replace
import pytest
from tests.local_harness.test_register_alias_generic_source_profile import source_verified_generic_artifact
from tests.scenario.test_register_alias_verifier import alias_factory
from tests.scenario.test_register_program_runtime import request
from myfuzz.composition.test_capability import _canonical_value
from myfuzz.local_harness import (GeneratedPulpGpioSession, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime


@pytest.fixture(scope='module')
def generic_private_factory(source_verified_generic_artifact,tmp_path_factory):
    from myfuzz.scenario import ibex_pulp_dual_source as wiring_api
    base,original,capability=source_verified_generic_artifact
    cache=tmp_path_factory.mktemp('generic-private-no-build')
    wiring=wiring_api.dual_source_wiring(cpu_profile=wiring_api.CPU_PROFILE)
    cpu_artifact=wiring_api._artifact(wiring.cpu_profile,'cpu',physical_observations=True)
    targets={}
    for alias in ('gpio_a','gpio_b'):
        req=replace(original.plan.request,instance_id=alias)
        plan=plan_local_harness(req,base_dir=base)
        structural=render_local_harness(plan)
        actual=verify_local_source_lock(plan.profile,base_dir=base)
        targets[alias]=render_local_driver(render_local_runtime(plan,structural,actual,base_dir=base),base_dir=base)
    sidecar=base/'configs/generic/test_capability.json'
    sidecar.parent.mkdir(parents=True,exist_ok=True)
    sidecar.write_text(json.dumps(_canonical_value(capability.source_document),sort_keys=True))
    def create():
        memory=PersistentMemory(regions=wiring.memory_regions,
            initialization_seed=wiring.memory_initialization_seed,
            max_initialized_bytes=wiring.max_initialized_bytes)
        devices={name:GeneratedPulpGpioSession(artifact,base_dir=base,cache_dir=cache)
                 for name,artifact in targets.items()}
        router=DataflowRouter(tuple(DeviceWindow(device_id,address,size,devices[component])
            for device_id,address,size,component in wiring.windows))
        cpu=GeneratedCve2Session(cpu_artifact,base_dir=wiring_api.ROOT,cache_dir=cache,
            memory=memory,router=router,defer_mmio=True,memory_commit_receipts=True,
            memory_readback_receipts=True,physical_tick_samples=True)
        sessions={'cpu':cpu,**devices}
        runner=ScenarioRunner(sessions={name:sessions[name] for name in wiring.sessions},
            ownership=compile_ownership(wiring.ownership_fields,wiring.ownership_owners),
            bindings=wiring.bindings,irq_pulses=dict(wiring.irq_pulse_widths))
        wiring_api.install_host_ram_commit_journal(runner,component=wiring.memory_component,service=cpu.service)
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64)
        runner.configure_persistent_memory_prerequisites(instruction_slot_policy=dict(
            component=wiring.memory_component,first_address=wiring_api.ONLINE_INSTRUCTION_START,
            last_address=wiring_api.ONLINE_INSTRUCTION_END,
            reservation_ref_prefix=wiring_api.ONLINE_SLOT_RESERVATION_PREFIX),
            prerequisite_gate_type=wiring_api.PulpLiveMemoryPrerequisiteGate)
        return runner
    return alias_factory(create),sidecar


@pytest.mark.parametrize('operation',['set_bits','clear_bits'])
def test_fully_renamed_component_bracket_uses_actual_private_chain(generic_private_factory,operation):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
    factory,sidecar=generic_private_factory
    bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
    session=ScenarioSession(bootstrap.template,factory());session.runner._test_session=session
    session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
    session.configure_ordinary_apb_access_evidence(max_records=16)
    runtime=RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':sidecar},advance_rounds=1,max_records=16)
    session.configure_register_program_verifier(max_records=16)
    def row(label,**kwargs):
        return request(case_id=label,action_id='generic-'+label,target_instance='gpio_a',endpoint_id='register.bus',**kwargs)
    read=dict(register='DATA',field='value',operation='register_read',value=None,allow_side_effect=False)
    source='DATA_SET' if operation=='set_bits' else 'DATA_CLEAR'
    rows=[row('before',result_address=0x10004,**read),row('alias',register=source,field='bits',
        operation='register_write',value=0x80000001,allow_side_effect=True),row('after',result_address=0x10008,**read)]
    session.begin()
    for item in rows:runtime.submit(item)
    report=session.runner._register_program_verifier.report()
    certs=[r for r in report['current_certificates'] if r['case_id']=='alias']
    assert len(certs)==1,report['gaps']
    cert=certs[0]
    assert cert['rule']=='ordinary_register_alias_readback.v1'
    assert cert['register']==source and cert['field']=='bits'
    assert cert['result']['alias_relation']['operation']==operation
    assert cert['result']['before_result_commit'] and cert['result']['after_result_commit']
    assert session.runner.sessions['gpio_a'].artifact.plan.profile.component_id=='generic_register_device'
    assert session.runner.sessions['gpio_a'].artifact.source_verification['source_status']=='source_verified'
    assert all(cert[key] is False for key in ('grants_storage','grants_version_dependency','grants_prerequisites','grants_functional'))
    assert len([r for r in session.runner.events if r.get('kind')=='memory_write_commit'])==2
    assert session.runner.ordinary_apb_access_evidence_snapshot()['counts']['cpu_delivery_confirmed']==3
