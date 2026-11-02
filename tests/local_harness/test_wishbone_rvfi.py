"""Post-edge RVFI observations are real fields, not IRQ-source proof."""
from types import SimpleNamespace
import pytest
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.scenario.contracts import ProtocolEnvironmentError


def subject():
    s=object.__new__(GeneratedWishboneCpuSession)
    s._rvfi_contract={'fields': {'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32}}
    s._last_retire_order=None
    s.reset_epoch=0
    s.local_ticks=5
    s.source_component='cpu'
    s.cpu_events=[]
    return s


def fields(valid=1,order=7):
    return dict(rvfi_valid=valid,rvfi_order=order,rvfi_insn=0x00100093,rvfi_pc_rdata=0x100)


def test_retirement_only_from_valid_post_and_order():
    s=subject();s._observe_rvfi_retirement(fields(valid=0));assert s.cpu_events == []
    s._observe_rvfi_retirement(fields());s._observe_rvfi_retirement(fields())
    assert len(s.cpu_events)==1
    e=s.cpu_events[0]
    assert (e['kind'],e['order'],e['insn'],e['pc_rdata']) == ('cpu_retire',7,0x00100093,0x100)
    assert e['observation']['sampling_edge']=='post_rising'
    assert 'machine_external_take' not in e and 'source_attribution' not in e
    with pytest.raises(ProtocolEnvironmentError,match='order'):
        s._observe_rvfi_retirement(fields(order=6))


def test_incomplete_or_out_of_range_rvfi_never_emits():
    s=subject()
    for value in ({'rvfi_valid':1}, {**fields(),'rvfi_insn':1<<32}):
        with pytest.raises(ProtocolEnvironmentError,match='RVFI'):
            s._observe_rvfi_retirement(value)
    assert s.cpu_events == []


def test_declared_profile_receives_only_post_sample(tmp_path, monkeypatch):
    from pathlib import Path
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.wire import DriverReceipt
    from myfuzz.local_harness.wishbone_cpu_session import _LIMITS
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    root=Path.cwd()
    request=load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/picorv32_wb_irq_rvfi/component_profile.json',instance_id='cpu_wb',
        reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16))
    plan=plan_local_harness(request,base_dir=root)
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=root),base_dir=root),base_dir=root)
    cpu=GeneratedWishboneCpuSession(artifact,base_dir=root,cache_dir=tmp_path,
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),initialization_seed=3,max_initialized_bytes=4096),
        router=DataflowRouter(()), memory_commit_receipts=True, memory_readback_receipts=True,
        physical_tick_samples=True, custom_irq_observations=True)
    cpu._case_id='testcase'
    physical={r['runtime_name']:0 for r in artifact.runtime_document['physical_exports']}
    runtime_names={r['physical_port']:r['runtime_name'] for r in artifact.runtime_document['physical_exports']}
    pre=dict(physical);post=dict(physical)
    post.update({runtime_names['rvfi_valid']:1,runtime_names['rvfi_order']:3,
                 runtime_names['rvfi_insn']:0x00100093,runtime_names['rvfi_pc_rdata']:0x100})
    backend={name:0 for name in _LIMITS}
    sample={'local_tick':1,'pre':{'backend':backend,'physical':pre},
            'post':{'backend':backend,'physical':post}}
    payload={'kind':'wishbone_cpu','pre_backend':backend,'samples':[sample],'observations':sample['post']}
    def command(*args):
        cpu.local_ticks=1
        return DriverReceipt('result','a'*32,1,0,1,1,payload)
    monkeypatch.setattr(cpu,'command',command)
    cpu.step_local({})
    assert len(cpu.cpu_events)==1
    assert (cpu.cpu_events[0]['pc_rdata'],cpu.cpu_events[0]['insn'],cpu.cpu_events[0]['order'])==(0x100,0x00100093,3)
    assert cpu.cpu_events[0]['observation']['sampling_edge']=='post_rising'
    from myfuzz.scenario.contracts import _verify_generated_session
    assert _verify_generated_session(cpu.identity_document()).runtime_document == artifact.runtime_document
    from myfuzz.integration.shared_custom_irq_cpu import build_shared_custom_irq_cpu
    shared = build_shared_custom_irq_cpu(artifact=artifact, base_dir=root, cache_dir=tmp_path,
        memory=cpu.memory, router=cpu.router, irq_sources=(('dma','irq',3),('gpio','irq',4)))
    identity = shared.cpu.identity_document()
    assert identity['cpu_observation_schema_version'] == 'rvfi_observation.v1'
    assert shared.contract['retirement'] == 'unknown'
    assert _verify_generated_session(identity).runtime_document == artifact.runtime_document


def test_rvfi_closure_file_matches_inline_evidence_and_lock():
    import hashlib
    import json
    from pathlib import Path
    lock = json.loads(Path('configs/soc/sources.lock.json').read_text())
    record = next(row for row in lock['components'] if row['id'] == 'picorv32_wb_irq_rvfi')
    raw = Path(record['elaboration']['evidence']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == record['elaboration']['evidence_sha256']
    assert json.loads(raw) == lock['elaboration_closures'][record['id']]


def test_shared_generator_selects_rvfi_profile_by_configuration():
    import json
    import tempfile
    from pathlib import Path
    from scripts.generate_shared_dma_scenario import generate_scenario
    from myfuzz.runtime.generic_campaign import load_descriptor
    root=Path.cwd()
    config=json.loads((root/'configs/scenarios/shared-dma-profile-examples/picorv32-custom-zipdma-i2c-gpio-rvfi.json').read_text())
    with tempfile.TemporaryDirectory(dir=root/'runs') as directory:
        output=Path(directory)/'scenario'
        desc=load_descriptor(generate_scenario(config,base_dir=root,output=output),base_dir=root)
        compose=json.loads(desc.compose.read_text())
        request=json.loads((output/compose['cpu']['request']).resolve().read_text())
        assert request['profile_path']==config['cpu_profile']
        assert set(desc.flow_ids)=={'F1','F2','F3','F4','F5','F6'}
        supplement=json.loads(desc.supplement.read_text())
        irq=supplement['request_supplements']['f6_execution']
        assert (irq['custom_irq_bit'],irq['gpio_irq']['irq_bit'])==(3,4)
