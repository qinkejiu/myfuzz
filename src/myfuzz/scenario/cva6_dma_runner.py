"""Unstarted RV64 AXI CPU and Wishbone DMA on shared noncacheable RAM."""
from pathlib import Path

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)
from .cva6_dma_example import MAIN, DMA_BASE, cva6_dma_images
from .cvw_gpio_example import ROOT, _artifact
from .memory import MemoryRegion, PersistentMemory
from .ownership import compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner


def _cpu_artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/cva6/component_profile.json',
        instance_id='cpu', reset_assert_ticks=16, reset_release_ticks=20,
        max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def make_cva6_dma_runner(*, cache_dir: Path, start_key: int = 0xfed):
    """All source/configuration writes are actual CPU stores after startup."""
    images = cva6_dma_images(start_key=start_key)
    memory = PersistentMemory(
        regions=(MemoryRegion('ram', MAIN, 0x10000),),
        initialization_seed=17, max_initialized_bytes=0x10000)
    for address, image in images.items():
        memory.preload(address, image)

    created = []
    try:
        dma = GeneratedWishboneDmaScenarioSession(_artifact(
            'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            command_timeout_seconds=30)
        created.append(dma)
        router = DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),))
        cpu = GeneratedCva6Axi4Session(_cpu_artifact(), base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=30)
        created.append(cpu)
        return ScenarioRunner(sessions={'cpu': cpu, 'dma': dma},
            ownership=compile_ownership((), ()), bindings=())
    except BaseException:
        for session in reversed(created):
            try:
                session.end_case()
            except BaseException:
                pass
        raise
