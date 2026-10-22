"""Unstarted CVW CPU-programmed ZipCPU DMA RAM composition.

The AHB CPU and Wishbone DMA share versioned software RAM. CPU instructions
perform all source and control writes; this fixture supplies only initial code
and zero destination/result bytes. It declares no CPU interrupt input.
"""
from pathlib import Path

from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)
from .cvw_dma_example import MAIN, DMA_BASE, cvw_dma_images
from .cvw_gpio_example import ROOT, _artifact
from .memory import MemoryRegion, PersistentMemory
from .ownership import compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner


def make_cvw_dma_runner(*, cache_dir: Path, start_key: int = 0xfed):
    """Construct real generated sessions without starting native processes."""
    images = cvw_dma_images(start_key=start_key)
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
        cpu = GeneratedAhbMemorySession(_artifact(
            'configs/cpus/cvw/component_profile.json', 'cpu'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
            command_timeout_seconds=30)
        created.append(cpu)
        return ScenarioRunner(sessions={'cpu': cpu, 'dma': dma},
            ownership=compile_ownership((), ()), bindings=())
    except BaseException:
        # Preserve the construction error while attempting every cleanup.
        for session in reversed(created):
            try:
                session.end_case()
            except BaseException:
                pass
        raise
