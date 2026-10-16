"""CPU-configured real DMA under the shared ScenarioRunner scheduler."""
from pathlib import Path

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from .ibex_dma_example import ROOT, DMA_BASE, _artifact, ibex_dma_images
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner


def make_ibex_dma_runner(*, cache_dir: Path, start_key=0xfed):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in ibex_dma_images(start_key=start_key).items():
        memory.preload(address, image)
    dma = GeneratedWishboneDmaScenarioSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory, command_timeout_seconds=30)
    router = DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),))
    cpu = GeneratedCve2Session(_artifact(
        'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
        defer_mmio=True, native_irq_receipts=True, command_timeout_seconds=30)
    binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
    ownership = compile_ownership((InputField('cpu', 'irq', 1),),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),))
    return ScenarioRunner(sessions={'cpu': cpu, 'dma': dma}, ownership=ownership,
        bindings=(binding,), irq_pulses={binding: 16})


def make_ibex_dma_uart_rx_runner(*, cache_dir: Path):
    from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from .ibex_dma_uart_rx_example import ibex_dma_uart_rx_images, UART_BASE

    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in ibex_dma_uart_rx_images().items():
        memory.preload(address, image)
    uart = GeneratedOpentitanUartSession(_artifact(
        'configs/peripherals/opentitan_uart_fifo_local/component_profile.json', 'uart'),
        base_dir=ROOT, cache_dir=cache_dir, source=None,
        read_rx_after_source=False, command_timeout_seconds=30)
    window = MasterTargetWindow('uart', UART_BASE, 0x1000, uart, (), (),
        readable_offsets=(0x18,))
    dma = GeneratedWishboneDmaScenarioSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(window,), command_timeout_seconds=30)
    router = DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),
        DeviceWindow('uart', UART_BASE, 0x1000, uart)))
    cpu = GeneratedCve2Session(_artifact(
        'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
        defer_mmio=True, native_irq_receipts=True, command_timeout_seconds=30)
    binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
    ownership = compile_ownership((InputField('cpu', 'irq', 1),
        InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'external-serial-byte')))
    return ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'uart': uart},
        ownership=ownership, bindings=(binding,), irq_pulses={binding: 16})
