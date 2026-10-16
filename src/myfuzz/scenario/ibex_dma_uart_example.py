"""Real Ibex -> wbdmac -> OpenTitan UART WDATA/TX -> native IRQ fixture.

The UART register write is caused only by an accepted DMA master beat.  The
CPU writes the source RAM byte and all DMA control registers in real RTL.
"""

from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from .ibex_dma_example import (_addi, _bne, _csr, _lui, _lw, _sw,
    DMA_BASE, SOURCE, RESULT, MAIN, ISR, advance_ibex_dma)
from .memory import PersistentMemory, MemoryRegion
from .router import DataflowRouter, DeviceWindow


ROOT = Path(__file__).resolve().parents[3]
UART_BASE = 0x50000000
UART_WDATA = UART_BASE + 0x1c
TX_BYTE = 0xa5


def ibex_dma_uart_images(*, source_word=TX_BYTE, destination=UART_WDATA,
                         start_key=0xfed):
    if type(source_word) is not int or not 0 <= source_word <= 0x7ff:
        raise ValueError('source word must fit a positive ADDI immediate')
    if type(destination) is not int or destination not in (
            UART_WDATA, UART_BASE + 0x20):
        raise ValueError('unsupported DMA UART destination experiment')
    if type(start_key) is not int or not 0 <= start_key <= 0xfff:
        raise ValueError('DMA start key must be 12 bits')
    main = [_lui(1, DMA_BASE), _lui(2, SOURCE), _lui(4, UART_BASE),
            _lui(5, RESULT), _addi(3, 0, source_word), _sw(3, 2, 0),
            _lui(3, 0x80000000), _addi(3, 3, 3), _sw(3, 4, 0x10),
            _lui(7, 0x10000), _addi(7, 7, 0x200), _csr(0x305, 7),
            _lui(7, 0x1000), _addi(7, 7, -0x800), _csr(0x304, 7),
            _addi(7, 0, 8), _csr(0x300, 7),
            _sw(2, 1, 8), _addi(6, 4, destination - UART_BASE),
            _sw(6, 1, 12), _addi(3, 0, 1), _sw(3, 1, 4),
            _lui(3, start_key << 16), _addi(3, 3, 1), _sw(3, 1, 0),
            0x0000006f]
    # For this one-word transfer, wbdmac's readback is idle=0, error=0,
    # nread=0, blocklen_sub_one=0.  The four-word RAM example reads 3 because
    # its blocklen_sub_one is 3; that is not a generic completion code.
    isr = [_csr(0x342, 0, 6), _sw(6, 5, 0), _lw(7, 1, 0),
           _sw(7, 5, 4), _addi(8, 0, 0)]
    branch = len(isr)
    isr += [0, _addi(3, 0, 1), _sw(3, 5, 8), 0x30200073]
    failure = len(isr)
    isr += [_addi(3, 0, -1), _sw(3, 5, 8), 0x0000006f]
    isr[branch] = _bne(7, 8, (failure - branch) * 4)
    encode = lambda words: b''.join(word.to_bytes(4, 'little') for word in words)
    return {MAIN: encode(main), ISR: encode(isr), RESULT: bytes(12)}


def _artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)


def make_ibex_dma_uart_chain(*, cache_dir, source_word=TX_BYTE,
                             destination=UART_WDATA, start_key=0xfed):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in ibex_dma_uart_images(source_word=source_word,
            destination=destination, start_key=start_key).items():
        memory.preload(address, image)
    uart = GeneratedOpentitanUartSession(_artifact(
        'configs/peripherals/opentitan_uart_fifo_local/component_profile.json', 'uart'),
        base_dir=ROOT, cache_dir=cache_dir, source=b'', command_timeout_seconds=30)
    target = MasterTargetWindow(component='uart', base=UART_BASE, size=0x1000,
        endpoint=uart, writable_offsets=(0x1c,), accepted_write_values=range(256),
        byte_enable=15)
    dma = GeneratedWishboneDmaSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(target,), command_timeout_seconds=30)
    router = DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),
        DeviceWindow('uart', UART_BASE, 0x1000, uart)))
    cpu = GeneratedCve2Session(_artifact(
        'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
        defer_mmio=True, native_irq_receipts=True, command_timeout_seconds=30)
    return cpu, dma, uart, router, memory


def advance_ibex_dma_uart(cpu, dma, uart, router, *, step, irq_latch):
    # Reuse the measured DMA/native IRQ/CPU scheduler order. UART receives its
    # own real clock edge and the CPU's routed CTRL access every iteration.
    router.drain_one('uart')
    uart_output = uart.step_local({})
    row = advance_ibex_dma(cpu, dma, router, step=step, irq_latch=irq_latch)
    return {**row, 'uart_tick': uart.local_ticks, 'uart_output': uart_output}
