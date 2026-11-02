"""Shared F5 admission and submit run on the existing persistent objects."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.runtime.preparation import create_preparation
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from tests.integration.test_compiled_f5_crosswalk import ROOT


@pytest.fixture(scope='module')
def prepared(tmp_path_factory):
    config = ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'
    context = create_preparation(base_dir=ROOT, compose_path=config/'compose.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=config/'execution_supplement.json',
        generated_dir=tmp_path_factory.mktemp('shared-f5')/'generated',
        flow_ids=('F1','F3','F4','F5'))
    yield context
    context.close()


@pytest.fixture(scope='module')
def prepared_irq(tmp_path_factory):
    config=ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'
    context=create_preparation(base_dir=ROOT,compose_path=config/'compose_irq.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=config/'execution_supplement.json',
        generated_dir=tmp_path_factory.mktemp('shared-irq')/'generated',
        flow_ids=('F1','F3','F4','F5'))
    yield context
    context.close()


def world(prepared, tmp_path):
    from myfuzz.integration.shared_f5_runtime import PhysicalIrqCpuSession, prepare_shared_f5
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    memory = PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x30000),),
        initialization_seed=0,max_initialized_bytes=0x30000)
    target = GeneratedPulpGpioSession(prepared.artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path)
    cpu = PhysicalIrqCpuSession(prepared.artifacts['processor'], base_dir=ROOT,
        cache_dir=tmp_path, memory=memory,
        router=DataflowRouter((DeviceWindow('peripheral',0x40001000,4096,target),)),
        irq_input_port='irq_external_i')
    binding = prepare_shared_f5(preparation=prepared, artifacts=prepared.artifacts,
        compiled_inputs=prepared.compiled_inputs(), cpu_id='processor', target_id='peripheral',
        cpu=cpu,target=target)
    runner = ScenarioRunner(sessions={'processor':cpu,'peripheral':target},
        ownership=binding.ownership,bindings=(binding.binding,),irq_pulses={binding.binding:4})
    return binding, runner


def test_shared_path_binds_actual_physical_irq_before_begin(prepared,tmp_path):
    binding,runner = world(prepared,tmp_path)
    binding.validate(runner)
    assert binding.prepared.bind(runner)
    assert binding.binding.source_port == 'interrupt'
    assert binding.binding.target_port == 'irq_external_i'
    assert all(tick == 0 for tick in runner.local_ticks.values())


def test_physical_cpu_irq_maps_to_existing_component_adapter(prepared,tmp_path):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    _,runner=world(prepared,tmp_path)
    with patch.object(GeneratedCve2Session,'_step_local',return_value={'observed':1}) as step:
        assert runner.sessions['processor'].step_local({'irq_external_i':1}) == {'observed':1}
        assert step.call_args.args == ({'irq':1},)


def test_timer_like_session_cannot_claim_irq(prepared,tmp_path):
    from myfuzz.integration.shared_f5_runtime import prepare_shared_f5
    with pytest.raises(ValueError):
        prepare_shared_f5(preparation=prepared, artifacts=prepared.artifacts,
            compiled_inputs=prepared.compiled_inputs(), cpu_id='processor',target_id='peripheral',
            cpu=SimpleNamespace(),target=SimpleNamespace())


def test_changed_actual_irq_pulse_is_rejected(prepared,tmp_path):
    binding,runner=world(prepared,tmp_path)
    runner._irq_pulses[binding.binding].width_ticks=3
    with pytest.raises(ValueError):binding.validate(runner)


def test_shared_adapter_module_exports_live_prepare():
    from myfuzz.integration.shared_f5_runtime import prepare_shared_f5
    assert callable(prepare_shared_f5)


@pytest.mark.parametrize('irq_firmware',[False,True])
def test_existing_runtime_constructs_one_session_with_shared_f5(prepared,tmp_path,monkeypatch,irq_firmware,request):
    if irq_firmware:prepared=request.getfixturevalue('prepared_irq')
    import myfuzz.integration.compiled_f4 as f4
    import myfuzz.integration.compiled_f2 as f2
    from myfuzz.local_harness.session import GeneratedLocalSession
    monkeypatch.setattr(GeneratedLocalSession,'prepare_local',lambda self:None)
    monkeypatch.setattr(GeneratedLocalSession,'configure_built_executable_receipt',lambda self:None)
    monkeypatch.setattr(GeneratedLocalSession,'validate_built_executable_receipt',lambda self:{})
    monkeypatch.setattr(f4,'validate_built_receipts',lambda *a:None)
    monkeypatch.setattr(f2,'validate_built_receipts',lambda *a:None)
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    monkeypatch.setattr(f4,'build_storage_producer',lambda binding,artifact,base_dir,cache_dir,max_cases:
        (GeneratedPulpGpioSession(artifact,base_dir=base_dir,cache_dir=cache_dir),SimpleNamespace()))
    import subprocess
    real_popen=subprocess.Popen
    def source_only_popen(args,*a,**k):
        if isinstance(args,(tuple,list)) and args and args[0]=='git':return real_popen(args,*a,**k)
        raise AssertionError('native forbidden')
    with patch('subprocess.Popen',side_effect=source_only_popen):
        runtime=f4.CompiledF4Runtime(artifacts=prepared.artifacts,compiled_inputs=prepared.compiled_inputs(),
            base_dir=ROOT,cache_dir=tmp_path,defer_begin=True,mixed_flows=True,memory_flows=True,
            f5_preparation=prepared,irq_firmware=irq_firmware)
    assert runtime.runner.sessions[runtime.cpu_id].native_irq_receipts_enabled is irq_firmware
    if irq_firmware:
        slots=runtime.session._instruction_slots
        assert len(slots)==1 and slots[0][1]==runtime.start+0x1000
        assert runtime.runner.gpio_irq_dependency_evidence_report()['pin']==8
        from myfuzz.integration.shared_irq_firmware import firmware_images,expected_boot_fetch
        fw=runtime.irq_firmware
        assert fw['first_fetch']==expected_boot_fetch(runtime)
        assert runtime.session.template.initial_images==firmware_images(runtime,fw)
        cpu=runtime.runner.sessions[runtime.cpu_id]
        with patch('subprocess.Popen',side_effect=AssertionError('native forbidden')):
            for image in runtime.session.template.initial_images:
                runtime.runner.preload_image(image)
        assert cpu.memory.instruction_slot_unmaterialized(fw['dynamic_start'])
        assert cpu.memory.read(fw['handler'],4,transaction_id='fixed-handler-check').value==int.from_bytes(bytes.fromhex(next(s for s in fw['segments'] if s['name']=='handler')['data_hex'])[:4],'little')
        with pytest.raises(ValueError):
            runtime.runner.preload_image(runtime.session.template.initial_images[0])
        with pytest.raises(ValueError):
            cpu.accept_instructions(fw['handler'],b'\x13\x00\x00\x00',source_event_id='overwrite-fixed-handler')
    assert runtime.session.runner is runtime.runner
    assert runtime.runner.sessions[runtime.cpu_id].memory is runtime.runner.sessions['processor'].memory
    assert runtime.f5_binding.prepared.runtime_paths[0] in runtime.session._runtime_prepared.runtime_paths
    assert runtime.runner.bindings == (runtime.f5_binding.binding,)
    assert not runtime._begun


def submission_world(prepared,tmp_path):
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey
    binding,runner=world(prepared,tmp_path)
    cpu=runner.sessions['processor']
    cpu.declare_instruction_slots(0x10000,16)
    key=TransactionKey(execution_id='execution',testcase_id='test',source_component='processor',
        channel_id='instr',source_epoch=cpu.reset_epoch,source_sequence=1)
    cpu._waiting_instr=(key,0x10000)
    cpu._request_evidence={'instr':{'transaction':asdict(key),'aligned_address':0x10000}}
    cases=[]
    session=SimpleNamespace(submit_case=lambda case:(cases.append(case) or
        SimpleNamespace(status='running',violations=())))
    runtime=SimpleNamespace(_stable=lambda:binding.validate(runner),runner=runner,session=session,
        cpu_id='processor',cursor=0x10000,result=0x3fffc,_memory_flows=True,
        records=[],max_cases=4,run_id='shared',rounds=2,f5_binding=binding)
    return runtime,cases


def test_shared_f5_submit_keeps_existing_runner_memory_and_raw8(prepared,tmp_path):
    from myfuzz.integration.shared_f5_runtime import submit_shared_f5
    runtime,cases=submission_world(prepared,tmp_path)
    memory=runtime.runner.sessions['processor'].memory
    result=submit_shared_f5(runtime,bytes.fromhex('0000000100000000'),testcase_id='pin-case')
    assert result['irq_consumption']=='unknown'
    assert runtime.runner.sessions['processor'].memory is memory
    assert runtime.records[0]['flow']=='F5'
    assert runtime.records[0]['raw']=='0000000100000000'
    assert cases[0].source.value==1 and cases[0].case_id=='pin-case'
    assert cases[0].support_instructions[0].address==0x10000
    assert runtime.cursor==0x10010


def test_shared_f5_submit_rejects_missing_real_waiting_evidence(prepared,tmp_path):
    from myfuzz.integration.shared_f5_runtime import submit_shared_f5
    runtime,cases=submission_world(prepared,tmp_path)
    runtime.runner.sessions['processor']._request_evidence={}
    with pytest.raises(ValueError):submit_shared_f5(runtime,b'\0'*8)
    assert not cases and not runtime.records


def test_shared_f5_submit_failure_does_not_commit_record_or_cursor(prepared,tmp_path):
    from myfuzz.integration.shared_f5_runtime import submit_shared_f5
    runtime,_=submission_world(prepared,tmp_path)
    runtime.session.submit_case=lambda _:SimpleNamespace(status='failed',violations=('bad',))
    with pytest.raises(ValueError):submit_shared_f5(runtime,b'\0'*8)
    assert runtime.cursor==0x10000 and not runtime.records


def test_shared_uses_original_exact_cpu_adapter(prepared,tmp_path):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    _,runner=world(prepared,tmp_path)
    assert type(runner.sessions['processor']) is GeneratedCve2Session


def test_cpu_default_irq_and_unknown_physical_port_behavior(prepared,tmp_path):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    _,runner=world(prepared,tmp_path)
    actual=runner.sessions['processor']
    kwargs=dict(base_dir=ROOT,cache_dir=tmp_path,memory=actual.memory,router=actual.router)
    default=GeneratedCve2Session(prepared.artifacts['processor'],**kwargs)
    with patch.object(GeneratedCve2Session,'_step_local',return_value={}) as step:
        default.step_local({'irq':1})
        assert step.call_args.args==({'irq':1},)
        actual.step_local({'irq_external_i':1})
        assert step.call_args.args==({'irq':1},)
        with pytest.raises(ValueError):actual.step_local({'irq':1})
    with pytest.raises(ValueError):
        GeneratedCve2Session(prepared.artifacts['processor'],irq_input_port='unknown',**kwargs)
