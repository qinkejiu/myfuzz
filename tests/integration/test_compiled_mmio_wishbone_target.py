from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import json
import os
import pytest

from myfuzz.integration.compiled_mmio import _target_adapter

ROOT=Path(__file__).resolve().parents[2]


def test_unified_mmio_selects_real_wishbone_target_and_checks_trace():
    from myfuzz.local_harness import (load_local_harness_request,plan_local_harness,
        render_local_driver,render_local_harness,render_local_runtime,verify_local_source_lock)
    from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
    from myfuzz.integration.wishbone_mmio_target import observe_wishbone_mmio_bus
    target=load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path='configs/peripherals/zipcpu_uart/component_profile.json',instance_id='peripheral',
        reset_assert_ticks=2,reset_release_ticks=2,max_wait_cycles=16,
        tuning={'endpoint_policies':[dict(endpoint_id='uart.bus',template_id='target.wishbone',
            template_version='1',variant_id='word-addressed-registered-ack',max_outstanding=1)],
            'fixed_inputs':[dict(endpoint_id='uart.pins',role='rx',value=1),
                            dict(endpoint_id='uart.pins',role='cts_n',value=0)]}))
    plan=plan_local_harness(target,base_dir=ROOT)
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
    row={'target_instance':'peripheral','endpoint_id':'uart.bus',
         'template':'target.wishbone','variant_id':'word-addressed-registered-ack'}
    request=SimpleNamespace(wiring=SimpleNamespace(document={'windows':[row]}),base_dir=ROOT)
    access={'target_component':'peripheral','target_endpoint':'uart.bus'}
    protocol,session,bank,observer=_target_adapter(artifact,access,request)
    assert protocol=='wishbone' and session is GeneratedWishboneRegisterSession
    assert observer is observe_wishbone_mmio_bus
    assert bank.document()['internal_storage_version']=='unknown'
    damaged=deepcopy(artifact.runtime_document)
    damaged['base_protocol_trace']['signals']['ack']='forged_ack'
    with pytest.raises(ValueError,match='native-trace-mismatch'):
        _target_adapter(replace(artifact,runtime_document=damaged),access,request)


def test_wishbone_cpu_and_target_use_existing_mmio_runtime_without_starting():
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration.compiled_mmio import CompiledMmioRuntime
    from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
    from myfuzz.runtime.preparation import create_preparation
    source=ROOT/'configs/scenarios/compiled-f4-obi-wb-uart-setup'
    with TemporaryDirectory(prefix='wb-mmio-preparation-',dir=ROOT/'runs') as tmp:
        folder=Path(tmp)
        compose=json.loads((source/'compose.json').read_text())
        compose['cpu']['request']=os.path.relpath(source/'requests/processor.json',folder)
        compose['devices'][0]['request']='target.json'
        target=json.loads((source/'requests/peripheral.json').read_text())
        target['profile_path']='configs/peripherals/zipcpu_uart/component_profile.json'
        target['tuning'].pop('wishbone_storage_observations')
        capability=json.loads((source/'test_capability.json').read_text())
        capability['profile_fingerprint']=load_component_profile(ROOT/target['profile_path']).profile_fingerprint
        (folder/'compose.json').write_text(json.dumps(compose))
        (folder/'target.json').write_text(json.dumps(target))
        (folder/'capability.json').write_text(json.dumps(capability))
        (folder/'supplement.json').write_text((source/'execution_supplement.json').read_text())
        prep=create_preparation(base_dir=ROOT,compose_path=folder/'compose.json',
            capability_paths=(folder/'capability.json',),supplement_path=folder/'supplement.json',
            generated_dir=folder/'generated',flow_ids=('F2','F4'))
        try:
            runtime=CompiledMmioRuntime(artifacts=prep.artifacts,compiled_inputs=prep.compiled_inputs(),
                base_dir=ROOT,cache_dir=folder/'cache',run_id='wishbone-mmio-combination',
                max_cases=2,defer_begin=True,mixed_flows=True)
            assert runtime.cpu_adapter.protocol=='wishbone' and runtime.target_protocol=='wishbone'
            assert type(runtime.runner.sessions['peripheral']) is GeneratedWishboneRegisterSession
            assert set(runtime.paths)=={'F2','F4'}
            assert all(session.process is None for session in runtime.runner.sessions.values())
        finally:prep.close()


def test_profile_only_wishbone_example_prepares_f1_to_f4_without_native():
    from scripts.generate_mmio_scenario import generate_scenario
    from myfuzz.integration.compiled_mmio import CompiledMmioRuntime
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    config=json.loads((ROOT/'configs/scenarios/mmio-profile-examples/uart-picorv32-wb.json').read_text())
    with TemporaryDirectory(prefix='wb-mmio-profile-',dir=ROOT/'runs') as tmp:
        folder=Path(tmp)
        descriptor=load_descriptor(generate_scenario(config,base_dir=ROOT,output=folder/'scenario'),base_dir=ROOT)
        prep=create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,),supplement_path=descriptor.supplement,
            generated_dir=folder/'generated',flow_ids=descriptor.flow_ids)
        try:
            runtime=CompiledMmioRuntime(artifacts=prep.artifacts,compiled_inputs=prep.compiled_inputs(),
                base_dir=ROOT,cache_dir=folder/'cache',run_id='wishbone-profile',
                max_cases=2,defer_begin=True,mixed_flows=True,memory_flows=True)
            assert descriptor.flow_ids==('F1','F2','F3','F4')
            assert runtime.cpu_adapter.protocol==runtime.target_protocol=='wishbone'
            assert set(runtime.memory_bindings)=={'F1','F3'} and set(runtime.paths)=={'F2','F4'}
            assert all(session.process is None for session in runtime.runner.sessions.values())
        finally:prep.close()


def test_uart_side_effect_and_write_mask_must_be_explicit():
    from scripts.generate_mmio_scenario import generate_scenario
    config=json.loads((ROOT/'configs/scenarios/mmio-profile-examples/uart-picorv32-wb.json').read_text())
    with TemporaryDirectory(prefix='wb-mmio-declaration-',dir=ROOT/'runs') as tmp:
        folder=Path(tmp)
        missing=dict(config);missing.pop('allow_side_effectful_register')
        with pytest.raises(ValueError,match='register'):
            generate_scenario(missing,base_dir=ROOT,output=folder/'missing')
        invalid=dict(config,write_values=[0x80000000])
        with pytest.raises(ValueError,match='write_values'):
            generate_scenario(invalid,base_dir=ROOT,output=folder/'invalid')
