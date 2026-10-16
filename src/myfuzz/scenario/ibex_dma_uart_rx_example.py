"""Ibex-configured wbdmac reads real UART RX FIFO and writes RAM."""

from pathlib import Path

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from .ibex_dma_example import (_addi, _bne, _csr, _lui, _lw, _sw,
    _artifact, advance_ibex_dma, DMA_BASE, DESTINATION, RESULT, MAIN, ISR)
from .ibex_dma_uart_example import UART_BASE
from .memory import PersistentMemory, MemoryRegion
from .router import DataflowRouter, DeviceWindow


UART_RDATA = UART_BASE + 0x18
RX_BYTE = 0x5a


def ibex_dma_uart_rx_images(*, source=UART_RDATA):
    if source not in (UART_RDATA, UART_BASE + 0x20):
        raise ValueError('unsupported DMA UART RX source experiment')
    main = [_lui(1, DMA_BASE), _lui(2, UART_BASE), _lui(4, DESTINATION),
        _lui(5, RESULT), _lui(3, 0x80000000), _addi(3, 3, 3),
        _sw(3, 2, 0x10),
        _lui(7, 0x10000), _addi(7, 7, 0x200), _csr(0x305, 7),
        _lui(7, 0x1000), _addi(7, 7, -0x800), _csr(0x304, 7),
        _addi(7, 0, 8), _csr(0x300, 7),
        _addi(6, 2, source - UART_BASE), _sw(6, 1, 8),
        _sw(4, 1, 12), _addi(3, 0, 1), _sw(3, 1, 4),
        _lui(3, 0x0fed0000), _addi(3, 3, 1), _sw(3, 1, 0),
        0x0000006f]
    isr = [_csr(0x342, 0, 6), _sw(6, 5, 0), _lw(7, 1, 0),
        _sw(7, 5, 4), _lw(8, 4, 0), _sw(8, 5, 8),
        _addi(9, 0, RX_BYTE)]
    value_branch = len(isr)
    isr += [0, _addi(9, 0, 0)]
    status_branch = len(isr)
    isr += [0, _addi(3, 0, 1), _sw(3, 5, 12), 0x30200073]
    failure = len(isr)
    isr += [_addi(3, 0, -1), _sw(3, 5, 12), 0x0000006f]
    isr[value_branch] = _bne(8, 9, (failure - value_branch) * 4)
    isr[status_branch] = _bne(7, 9, (failure - status_branch) * 4)
    encode = lambda words: b''.join(word.to_bytes(4, 'little') for word in words)
    return {MAIN: encode(main), ISR: encode(isr), DESTINATION: bytes(4),
            RESULT: bytes(16)}


def make_ibex_dma_uart_rx_chain(*, cache_dir: Path, source=UART_RDATA):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in ibex_dma_uart_rx_images(source=source).items():
        memory.preload(address, image)
    uart = GeneratedOpentitanUartSession(_artifact(
        'configs/peripherals/opentitan_uart_fifo_local/component_profile.json',
        'uart'), base_dir=Path(__file__).resolve().parents[3], cache_dir=cache_dir,
        source=None, read_rx_after_source=False, command_timeout_seconds=30)
    target = MasterTargetWindow(component='uart', base=UART_BASE, size=0x1000,
        endpoint=uart, writable_offsets=(), accepted_write_values=(),
        readable_offsets=(0x18,))
    dma = GeneratedWishboneDmaSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
        base_dir=Path(__file__).resolve().parents[3], cache_dir=cache_dir,
        memory=memory, master_targets=(target,), command_timeout_seconds=30)
    router = DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),
        DeviceWindow('uart', UART_BASE, 0x1000, uart)))
    cpu = GeneratedCve2Session(_artifact(
        'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=Path(__file__).resolve().parents[3], cache_dir=cache_dir,
        memory=memory, router=router, defer_mmio=True,
        native_irq_receipts=True, command_timeout_seconds=30)
    return cpu, dma, uart, router, memory


def advance_ibex_dma_uart_rx(cpu, dma, uart, router, *, step, state):
    """Pause the CPU after its CTRL beat until actual UART FIFO occupancy."""
    if state['phase'] == 'cpu_ctrl':
        before = len(router.deliveries)
        router.drain_one('uart')
        delivered = router.deliveries[before:]
        if delivered:
            if len(delivered) != 1 or (delivered[0]['device_id'],
                    delivered[0]['offset'], delivered[0]['write']) != (
                    'uart', 0x10, True):
                raise RuntimeError('unexpected UART control delivery')
            uart.admit_source_event('uart_rx_byte', RX_BYTE, bit_offset=0,
                width=8, action_id='dma-uart-rx-source-1')
            uart.step_local({'uart_rx_byte': RX_BYTE})
            state['phase'] = 'await_fifo'
            return dict(step=step, phase='source_start', uart_tick=uart.local_ticks)
        row = advance_ibex_dma(cpu, dma, router, step=step,
            irq_latch=state['irq_latch'])
        return {**row, 'phase': 'cpu_ctrl', 'uart_tick': uart.local_ticks}
    if state['phase'] == 'await_fifo':
        uart.step_local({})
        latest = next(event for event in reversed(uart.uart_events)
            if event['kind'] == 'uart_tick_observation')
        frame = [event for event in uart.source_events
            if event['kind'] == 'uart_source_frame_end'
            and event['waveform_matched']]
        depth = latest['post'].get('probe_uart_fifo_depth', 0)
        if depth and frame and uart.register_access_conflict() is None:
            state['phase'] = 'dma_run'
        return dict(step=step, phase='await_fifo', uart_tick=uart.local_ticks,
            fifo_depth=depth, source_frame_matched=bool(frame))
    uart.step_local({})
    row = advance_ibex_dma(cpu, dma, router, step=step,
        irq_latch=state['irq_latch'])
    return {**row, 'phase': 'dma_run', 'uart_tick': uart.local_ticks}
