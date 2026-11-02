"""Small native Pico RVFI retirement smoke (one CPU, no IP or F6)."""
from pathlib import Path
from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter


def test_real_pico_wishbone_reports_retired_instruction(tmp_path):
    root=Path.cwd()
    request=load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/picorv32_wb_irq_rvfi/component_profile.json',instance_id='cpu_wb',
        reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16))
    plan=plan_local_harness(request,base_dir=root)
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=root),base_dir=root),base_dir=root)
    memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),initialization_seed=3,max_initialized_bytes=4096)
    memory.preload(0,bytes.fromhex('930010006f000000'))  # addi x1,x0,1; jal x0,0
    cpu=GeneratedWishboneCpuSession(artifact,base_dir=root,cache_dir=tmp_path/'cache',
                                   memory=memory,router=DataflowRouter(()))
    try:
        cpu.begin_case('rvfi-smoke')
        for _ in range(160):
            cpu.step_local({})
            if any(row.get('pc_rdata')==0 and row.get('insn')==0x00100093 for row in cpu.cpu_events):
                break
        assert any(row.get('pc_rdata')==0 and row.get('insn')==0x00100093
                   and row.get('observation',{}).get('sampling_edge')=='post_rising'
                   for row in cpu.cpu_events)
    finally:
        if cpu.process is not None:
            cpu.end_case()
