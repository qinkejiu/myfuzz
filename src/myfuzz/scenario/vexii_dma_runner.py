"""Unstarted reduced-AXI CPU and Wishbone DMA on shared versioned RAM."""
from pathlib import Path

from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)
from .cvw_gpio_example import ROOT, _artifact
from .memory import MemoryRegion, PersistentMemory
from .ownership import compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner
from .vexii_dma_example import MAIN, DMA_BASE, vexii_dma_images
from .vexii_pulp_gpio_fixed import _render_artifact


def make_vexii_dma_runner(*, cache_dir: Path, start_key: int = 0xfed):
    """All DMA programming and source data are CPU stores after startup."""
    images = vexii_dma_images(start_key=start_key)
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
        cpu = GeneratedReducedAxiCpuSession(_render_artifact(
            'configs/cpus/vexiiriscv/component_profile.json', 'cpu'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            mmio_router=router, command_timeout_seconds=30)
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
