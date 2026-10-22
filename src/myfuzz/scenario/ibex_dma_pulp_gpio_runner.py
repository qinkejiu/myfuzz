"""Real Ibex → ZipCPU DMA → PULP GPIO ScenarioRunner assembly."""
from pathlib import Path

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)

from .boom_gpio_example import _gpio_artifact
from .genome import MemoryImage, ScenarioGenome
from .ibex_dma_example import (
    ROOT, DMA_BASE, SOURCE, _artifact,
)
from .ibex_dma_pulp_gpio_example import (
    GPIO_BASE, PADOUT_ADDRESS, ibex_dma_pulp_gpio_images,
)
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .pulp_gpio_dma_paths import (
    GPIO_PADOUT_OFFSET, PulpGpioDmaRuntimePaths,
    compile_pulp_gpio_dma_runtime_paths,
)
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

RAM_BASE = 0x10000
RAM_SIZE = 0x20000
GPIO_SIZE = 0x1000
TESTCASE_ID = 'ibex-wbdmac-pulp-padout-isr'


def make_ibex_dma_pulp_gpio_runner(*, cache_dir: Path,
        source_value: int = 0x5AA55AA5,
        destination_address: int = PADOUT_ADDRESS
        ) -> tuple[ScenarioRunner, PulpGpioDmaRuntimePaths]:
    """Create an unstarted native CPU/DMA/GPIO Runner and bind its route.

    The returned paths compile only the selected source RAM word to the exact
    PULP PADOUT window. `destination_address` is firmware data, allowing the
    native negative case to issue a PADOUT+4 request against this same policy.
    """
    images = ibex_dma_pulp_gpio_images(source_value=source_value,
        destination_address=destination_address)
    memory = PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=17, max_initialized_bytes=RAM_SIZE)
    for address, image in images.items():
        memory.preload(address, image)

    created = []
    try:
        gpio = GeneratedPulpGpioSession(_gpio_artifact(ROOT), base_dir=ROOT,
            cache_dir=cache_dir, command_timeout_seconds=30)
        created.append(gpio)
        gpio_window = MasterTargetWindow(
            'gpio', GPIO_BASE, GPIO_SIZE, gpio, (GPIO_PADOUT_OFFSET,),
            range(0, 1 << 32))
        dma = GeneratedWishboneDmaScenarioSession(_artifact(
            'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            master_targets=(gpio_window,), command_timeout_seconds=30)
        created.append(dma)
        router = DataflowRouter((
            DeviceWindow('dma', DMA_BASE, 16, dma),
            DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, gpio),
        ))
        cpu = GeneratedCve2Session(_artifact(
            'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
            defer_mmio=True, native_irq_receipts=True,
            command_timeout_seconds=30)
        created.append(cpu)

        binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('gpio', 'gpio_in', 32)),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
             InputOwner('gpio', 'gpio_in', 0, 32, 'fixed', 'constant_zero')))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'gpio': gpio},
            ownership=ownership, bindings=(binding,), irq_pulses={binding: 16})
        paths = compile_pulp_gpio_dma_runtime_paths(runner,
            memory_component='cpu', resource_id='ram', image_id='dma_payload',
            image_address=SOURCE)
        genome = ScenarioGenome(TESTCASE_ID, 'CPU_TO_IP', paths.path_id,
            ('cpu', 'dma', 'gpio'), 1, (), initial_images=(MemoryImage(
                'dma_payload', 'cpu', SOURCE,
                images[SOURCE].hex()),))
        paths.validate_source_genomes((genome,))
        return runner, paths
    except BaseException:
        for session in reversed(created):
            session.end_case()
        raise
