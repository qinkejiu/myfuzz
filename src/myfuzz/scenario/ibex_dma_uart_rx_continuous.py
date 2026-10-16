"""Static reset-free UART RX/DMA firmware; expected bytes live only in the checker."""
from pathlib import Path

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from .ibex_dma_example import (ROOT, MAIN, ISR, RESULT, DESTINATION, DMA_BASE,
    _addi, _lui, _lw, _sw, _csr, _bne, _artifact)
from .ibex_dma_uart_example import UART_BASE
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

# Pinned profile source: third_party/soc-opentitan/hw/ip/uart/rtl/
# uart_reg_pkg.sv UART_STATUS_OFFSET=0x14; uart_reg_top.sv RXEMPTY=bit5;
# uart_core.sv hw2reg.status.rxempty.d = ~rx_fifo_rvalid.
UART_STATUS_OFFSET = 0x14
UART_RXEMPTY_MASK = 1 << 5
COMPLETED = RESULT + 12


def _andi(rd, rs, immediate):
    return (immediate & 0xfff) << 20 | rs << 15 | 7 << 12 | rd << 7 | 0x13


def continuous_uart_rx_images():
    """Boot once, poll STATUS, transfer one word, wait for the real ISR counter.

    x1/x2/x4/x5 are device/result pointers. Main owns x10/x11, ISR uses
    x6/x7/x8/x9. ISR waits at least 32 CPU instructions before returning so
    the Runner's 16 CPU tick IRQ pulse expires while hardware MIE is clear.
    No expected source byte is embedded in this program.
    """
    main = [_lui(1, DMA_BASE), _lui(2, UART_BASE), _lui(4, DESTINATION),
        _lui(5, RESULT), _lui(3, 0x80000000), _addi(3, 3, 3),
        _sw(3, 2, 0x10), _lui(7, 0x10000), _addi(7, 7, 0x200),
        _csr(0x305, 7), _lui(7, 0x1000), _addi(7, 7, -0x800),
        _csr(0x304, 7), _addi(7, 0, 8), _csr(0x300, 7)]
    poll = len(main)
    main += [_lw(11, 2, UART_STATUS_OFFSET), _andi(11, 11, UART_RXEMPTY_MASK)]
    main += [_bne(11, 0, (poll - len(main)) * 4),
        _lw(10, 5, 12), _addi(3, 2, 0x18), _sw(3, 1, 8),
        _sw(4, 1, 12), _addi(3, 0, 1), _sw(3, 1, 4),
        _lui(3, 0x0fed0000), _addi(3, 3, 1), _sw(3, 1, 0)]
    wait = len(main)
    main += [_lw(11, 5, 12), _bne(11, 10, (poll - (wait + 1)) * 4),
        _bne(3, 0, -8)]
    isr = [_csr(0x342, 0, 6), _sw(6, 5, 0), _lw(7, 1, 0),
        _sw(7, 5, 4), _lw(8, 4, 0), _sw(8, 5, 8), _addi(9, 0, 32)]
    isr += [_addi(9, 9, -1), _bne(9, 0, -4),
        _lw(9, 5, 12), _addi(9, 9, 1), _sw(9, 5, 12), 0x30200073]
    encode = lambda words: b''.join(word.to_bytes(4, 'little') for word in words)
    if MAIN + 4 * len(main) > ISR:
        raise ValueError('continuous main overlaps native vectored ISR')
    return {MAIN: encode(main), ISR: encode(isr), DESTINATION: bytes(4),
        RESULT: bytes(16)}


def make_continuous_uart_rx_runner(*, cache_dir: Path):
    """Use the same native components and declared edges as the fixed RX gate."""
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in continuous_uart_rx_images().items():
        memory.preload(address, image)
    uart = GeneratedOpentitanUartSession(_artifact(
        'configs/peripherals/opentitan_uart_fifo_local/component_profile.json', 'uart'),
        base_dir=ROOT, cache_dir=cache_dir, source=None, read_rx_after_source=False,
        command_timeout_seconds=30)
    dma = GeneratedWishboneDmaScenarioSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(MasterTargetWindow('uart', UART_BASE, 0x1000, uart,
            (), (), readable_offsets=(0x18,)),), command_timeout_seconds=30)
    cpu = GeneratedCve2Session(_artifact(
        'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        router=DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),
            DeviceWindow('uart', UART_BASE, 0x1000, uart))),
        defer_mmio=True, native_irq_receipts=True, command_timeout_seconds=30)
    binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
    ownership = compile_ownership((InputField('cpu', 'irq', 1),
        InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'external-serial-byte')))
    return ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'uart': uart},
        ownership=ownership, bindings=(binding,), irq_pulses={binding: 16})
