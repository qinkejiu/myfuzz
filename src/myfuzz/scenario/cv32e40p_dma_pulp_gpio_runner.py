"""Unstarted CV32E40P → ZipCPU DMA → PULP GPIO fixture."""
from dataclasses import dataclass
from pathlib import Path

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    verify_local_source_lock,
)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.dma_artifact_endpoint_links import (
    PROVIDER_ID, render_dma_linked_runtime,
)
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow

from .boom_gpio_example import _gpio_artifact
from .cv32e40p_dma_pulp_gpio_example import (
    SOURCE_VALUE, cv32e40p_dma_pulp_gpio_images,
)
from .ibex_dma_example import ROOT, _artifact
from .ibex_dma_pulp_gpio_example import GPIO_BASE, PADOUT_ADDRESS
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

ROM_BASE = 0x10000
ROM_SIZE = 0x8000
RAM_BASE = 0x20000
RAM_SIZE = 0x20000
DMA_BASE = 0x40002000
GPIO_SIZE = 0x1000


@dataclass(frozen=True)
class Cv32e40pPulpDmaFixture:
    runner: ScenarioRunner
    dma_endpoint_links: dict


def make_cv32e40p_dma_pulp_gpio_runner(*, cache_dir: Path,
        destination_address: int = PADOUT_ADDRESS) -> Cv32e40pPulpDmaFixture:
    """Build isolated generated sessions around one shared RAM image."""
    images = cv32e40p_dma_pulp_gpio_images(
        destination_address=destination_address)
    memory = PersistentMemory(
        regions=(MemoryRegion('rom0', ROM_BASE, ROM_SIZE, writable=False),
                 MemoryRegion('ram', RAM_BASE, RAM_SIZE)),
        initialization_seed=17,
        max_initialized_bytes=ROM_SIZE + RAM_SIZE)
    for address, image in images.items():
        memory.preload(address, image)

    dma_request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipcpu_wbdmac/component_profile.json',
        instance_id='dma', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    dma_plan = plan_local_harness(dma_request, base_dir=ROOT)
    issued_dma = render_dma_linked_runtime(dma_plan,
        render_local_harness(dma_plan),
        verify_local_source_lock(dma_plan.profile, base_dir=ROOT),
        base_dir=ROOT, provider_id=PROVIDER_ID)

    created = []
    try:
        gpio = GeneratedPulpGpioSession(_gpio_artifact(ROOT), base_dir=ROOT,
            cache_dir=cache_dir, command_timeout_seconds=30)
        created.append(gpio)
        gpio_window = MasterTargetWindow('gpio', GPIO_BASE, GPIO_SIZE, gpio,
            (GPIO_PADOUT_OFFSET,), (SOURCE_VALUE,))
        dma = GeneratedWishboneDmaScenarioSession(issued_dma.artifact,
            base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            master_targets=(gpio_window,), command_timeout_seconds=30)
        created.append(dma)
        router = DataflowRouter((
            DeviceWindow('dma', DMA_BASE, 16, dma),
            DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, gpio),
        ))
        cpu = GeneratedCve2Session(_artifact(
            'configs/cpus/cv32e40p/component_profile.json', 'cpu'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
            defer_mmio=True, command_timeout_seconds=30)
        created.append(cpu)

        binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('gpio', 'gpio_in', 32)),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
             InputOwner('gpio', 'gpio_in', 0, 32, 'fixed', 'constant_zero')))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'gpio': gpio},
            ownership=ownership, bindings=(binding,), irq_pulses={binding: 16})
        return Cv32e40pPulpDmaFixture(runner,
            {'dma': issued_dma.endpoint_links_document()})
    except BaseException:
        for session in reversed(created):
            session.end_case()
        raise
