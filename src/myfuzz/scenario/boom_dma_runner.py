"""Unstarted BOOM uncached-data and ZipCPU DMA composition."""
import json
from pathlib import Path

from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)
from .boom_dma_example import MAIN, SOURCE, DESTINATION, RESULT, DMA_BASE, boom_dma_images
from .cvw_gpio_example import ROOT, _artifact
from .memory import MemoryRegion, PersistentMemory
from .ownership import compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner
from myfuzz.local_harness.boom_shared_memory import (
    BoomSharedMemoryContract, BoomSharedMemoryService,
)


class _BoomDmaWindow(DeviceWindow):
    """Permit only the pinned BOOM control subpage in generic Router."""

    def __post_init__(self):
        if (self.device_id != 'dma' or self.base != DMA_BASE or self.size != 16
                or self.target is None):
            raise ValueError('BOOM DMA window must be exactly 0x4400/16')


def make_boom_dma_runner(*, repo: Path, cpu_output: Path, cache_dir: Path,
                         start_key: int = 0xfed) -> ScenarioRunner:
    """Compose prebuilt BOOM with DMA on three exact shared data regions.

    This factory never builds or starts the CPU or DMA processes. The program
    is loaded by the native BOOM session before its first simulated edge.
    """
    if not isinstance(repo, Path) or repo.resolve() != ROOT:
        raise ValueError('BOOM repository must be the current authenticated project root')
    if not isinstance(cpu_output, Path) or not isinstance(cache_dir, Path):
        raise TypeError('cpu_output and cache_dir must be Path objects')
    cpu_output = cpu_output.resolve()
    artifact_path = cpu_output / 'session-artifact.json'
    if not artifact_path.is_file():
        raise ValueError('prebuilt BOOM session artifact is required')
    artifact_document = json.loads(artifact_path.read_text())
    if (type(artifact_document) is not dict
            or artifact_document.get('schema_version') != 'generated_boom_session.v1'):
        raise ValueError('generated prebuilt BOOM session artifact is required')
    images = boom_dma_images(start_key=start_key)
    memory = PersistentMemory(
        regions=(MemoryRegion('boom-dma-source', SOURCE, 16),
                 MemoryRegion('boom-dma-destination', DESTINATION, 16),
                 MemoryRegion('boom-dma-result', RESULT, 24)),
        initialization_seed=17, max_initialized_bytes=56)
    memory.preload(DESTINATION, bytes(16))
    memory.preload(RESULT, bytes(24))
    contract = BoomSharedMemoryContract()
    shared = BoomSharedMemoryService(memory, contract)

    created = []
    try:
        dma = GeneratedWishboneDmaScenarioSession(_artifact(
            'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            command_timeout_seconds=30)
        created.append(dma)
        router = DataflowRouter((_BoomDmaWindow('dma', DMA_BASE, 16, dma),))
        cpu = GeneratedBoomScenarioSession(cpu_output, repo=repo, router=router,
            program=images[MAIN], shared_memory_service=shared,
            command_timeout_seconds=30)
        created.append(cpu)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma},
            ownership=compile_ownership((), ()), bindings=())
        window, = router.windows
        shared.validate_binding()
        cpu._validate_shared_service()
        if (memory.identity_document()['regions'] != [
                {'memory_id': 'boom-dma-source', 'base': SOURCE, 'size': 16,
                 'aliases': (), 'readable': True, 'writable': True},
                {'memory_id': 'boom-dma-destination', 'base': DESTINATION, 'size': 16,
                 'aliases': (), 'readable': True, 'writable': True},
                {'memory_id': 'boom-dma-result', 'base': RESULT, 'size': 24,
                 'aliases': (), 'readable': True, 'writable': True}]
                or memory.initialized_bytes != 40
                or memory.generation != 0
                or dma.memory is not memory
                or dma.memory_service.memory is not memory
                or cpu.memory is not memory
                or cpu.service is not shared.service
                or cpu.shared_memory_service is not shared
                or cpu.router is not router or window.target is not dma
                or (window.device_id, window.base, window.size) != ('dma', DMA_BASE, 16)
                or cpu.identity_document().get('external_range') != (0x4000, 0x5000)
                or cpu._native is not None or cpu.process is not None
                or dma.process is not None
                or cpu.pending_responses != 0 or dma.pending_responses != 0
                or router.pending_target_counts):
            raise RuntimeError('BOOM DMA fixture failed its unstarted binding invariants')
        if runner.sessions.get('cpu') is not cpu or runner.sessions.get('dma') is not dma:
            raise RuntimeError('BOOM DMA fixture runner registration changed target identity')
        return runner
    except BaseException as primary:
        cleanup_errors = []
        for session in reversed(created):
            try:
                session.end_case()
            except BaseException as cleanup:
                cleanup_errors.append(cleanup)
        for cleanup in cleanup_errors[1:]:
            primary.add_note(f'additional BOOM fixture cleanup failure: {cleanup!r}')
        if cleanup_errors:
            raise primary from cleanup_errors[0]
        raise
