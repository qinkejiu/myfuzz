"""Reuse existing CV32E40P OBI and causal GPIO adapters; no native clocks."""
import json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
CONFIG=ROOT/'configs/scenarios/compiled-f1-f4-cv32e40p-gpio-shared'


@pytest.fixture(scope='module')
def prepared(tmp_path_factory):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    descriptor=load_descriptor(CONFIG/'generic_scenario.json',base_dir=ROOT)
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        context=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,),supplement_path=descriptor.supplement,
            generated_dir=tmp_path_factory.mktemp('cv32-gpio')/'generated',flow_ids=descriptor.flow_ids)
    yield context
    context.close()


def test_actual_four_flow_plan_and_GPIO_candidate_layout(prepared):
    from tests.runtime.test_plan_compiler import compile_from_context
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout,CandidateLayoutError
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    compiled=prepared.compiled_inputs()['compiled']
    paths={r['flow_id']:r for r in compiled['paths']}
    assert all(paths[f]['status']=='executable' for f in ('F1','F2','F3','F4'))
    assert paths['F2']['execution_contract']['register']=='PADIN'
    layout=compile_candidate_layout(paths['F4'])
    assert layout.byte_length==5
    stream,=[r for r in layout.slices if r.kind=='cpu_mmio_stream']
    pin,=[r for r in layout.slices if r.kind=='external_pin']
    assert pin.bit_offset==8 and pin.width==1
    assert layout.encode({stream.source_id:256,pin.source_id:0}).hex()=='0001000000'
    assert layout.encode({stream.source_id:256,pin.source_id:1}).hex()=='0001000001'
    assert layout.encode({stream.source_id:257,pin.source_id:0}).hex()=='0101000000'
    with pytest.raises(CandidateLayoutError,match='record-length'):layout.decode(bytes.fromhex('00010000'))
    assert compile_f2_candidate_layout(paths['F2']).classify(bytes.fromhex('08100040')).accepted
    plan=compile_from_context(prepared).plan.document()
    assert {r['flow_id'] for r in plan['paths']}=={'F1','F2','F3','F4'}
    assert prepared.compiled_inputs()['request'].wiring.deliveries==()


def test_actual_adapters_use_original_CPU_and_GPIO_authority(prepared,tmp_path):
    from myfuzz.integration.compiled_storage_producer import select_storage_producer,build_storage_producer
    from myfuzz.integration.compiled_f2_consumer import select_f2_read_producer
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority,_AUTHORITIES
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from myfuzz.scenario.router import DataflowRouter,DeviceWindow
    inputs=prepared.compiled_inputs();artifacts=dict(prepared.artifacts)
    binding=select_storage_producer(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    assert binding.row=='gpio_causal_abi' and binding.document()['register']['name']=='GPIOEN'
    f2=select_f2_read_producer(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    assert f2.document()['register']['name']=='PADIN'
    target,authority=build_storage_producer(binding,artifact=artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path,max_cases=8)
    memory=PersistentMemory(regions=(MemoryRegion('ram',65536,196608),),initialization_seed=0,max_initialized_bytes=196608)
    cpu=GeneratedCve2Session(artifacts['processor'],base_dir=ROOT,cache_dir=tmp_path,memory=memory,
        router=DataflowRouter((DeviceWindow('peripheral',1073745920,4096,target),)),defer_mmio=True,
        memory_commit_receipts=True,memory_readback_receipts=True)
    assert cpu.artifact.plan.profile.component_id=='cv32e40p'
    assert type(cpu) is GeneratedCve2Session and type(target) is GeneratedPulpGpioSession
    assert type(authority) is GpioRegisterVersionAuthority and _AUTHORITIES[target] is authority
    assert authority.target is target and cpu.memory is memory
    assert cpu.process is target.process is None
    assert cpu.native_irq_receipts_enabled is False
    assert cpu.memory_commit_receipts_enabled and cpu.memory_readback_receipts_enabled


def test_actual_prepared_pin_case_resolves_without_an_IRQ_or_MMIO_cause(prepared):
    from dataclasses import replace
    from myfuzz.integration.compiled_f4_runtime_path import admit_compiled_f4_runtime_path
    from myfuzz.scenario.session_runtime import OnlineCase,_resolve_case_source
    from myfuzz.scenario.batch import BatchSourceEvent,BatchAdvance
    inputs=prepared.compiled_inputs()
    path,=[r for r in inputs['compiled']['paths'] if r['flow_id']=='F4' and r['status']=='executable']
    pin,=[r for r in path['sources'] if r['kind']=='external_pin']
    admission=admit_compiled_f4_runtime_path(request=inputs['request'],compiled=inputs['compiled'])
    direction,pid=admission.external_pin_path(pin['source_id'])
    assert pid!=path['path_id'] and pid!=admission.runtime_path_id
    primary=admission.prepared.resolve_path_id(admission.runtime_path_id)[1]
    assert len(primary.source_ids)==1 and len(primary.edges)==2  # CPU image/MMIO only
    assert admission.prepared.resolve_path_id(pid)[1].edges==()  # independent drive, no causal claim
    case=OnlineCase('pin-prestart',direction,pid,
        BatchSourceEvent('pin-input',pin['component'],pin['port'],1,pin['bit_offset'],pin['width']),
        (BatchAdvance((pin['component'],)),))
    assert _resolve_case_source(admission.prepared,case)==pin['source_id']
    with pytest.raises(ValueError):_resolve_case_source(admission.prepared,replace(case,path_id=path['path_id']))
    with pytest.raises(ValueError):
        _resolve_case_source(admission.prepared,replace(case,source=replace(case.source,bit_offset=7)))
