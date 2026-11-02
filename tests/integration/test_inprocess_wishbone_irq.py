from scripts.inprocess_wishbone_irq import custom_irq_segments
from scripts.run_inprocess_f1f6 import build_firmware, build_layout, declared_windows
from scripts.run_inprocess_f1f6 import f5_declaration, render_bindings
from tests.integration.test_inprocess_f1f6_entry import (
    CONFIG, DMA, LAYOUT, WB_CONFIG, dma_document, ip_document,
    timer_profile, wb_cpu_document, wb_cpu_profile,
)


def test_wishbone_irq_firmware_uses_declared_custom_vector():
    config = dict(image_start=0, image_end=0x20000,
                  target_window=dict(base=0x40000000, size=0x1000))
    layout = build_layout(declared_windows(config, None), 0)
    fw = build_firmware(layout, irq=None, dma=None, interrupt_bootstrap=False,
                        custom_irq=dict(irq_bit=3, handler_address=16))
    assert set((0, 16, 64, layout['handler'])) <= set(fw['images'])
    assert fw['images'][layout['handler']][-4:] == bytes.fromhex('0b000004')


def test_declared_wishbone_custom_irq_exposes_f5():
    irq, refusal = f5_declaration(CONFIG, timer_profile(), 'apb3',
                                  cpu_bus_kind='wishbone', cpu_irq_bits=32,
                                  cpu_custom_irq=True)
    assert refusal is None and irq['port'] == 'irq_o'


def test_wishbone_dma_header_binds_declared_custom_interrupt():
    custom = dict(irq_bit=3, handler_address=16, eoi_runtime_name='eoi')
    header = render_bindings(WB_CONFIG, wb_cpu_document(), ip_document(), dma_document(),
                             LAYOUT, wb_cpu_profile(), irq=None, dma=DMA,
                             dma_irq=DMA['irq'], custom_irq=custom)
    assert '#define CPU_CUSTOM_IRQ 1' in header
    assert '#define CPU_CUSTOM_IRQ_BIT 3u' in header
    assert '#define CPU_IRQ_EOI eoi' in header
    assert '#define CPU_IRQ_WIRED 1' in header
    assert '#define HAVE_DMA 1' in header


def test_custom_irq_bootstraps_declared_bit_and_saves_handler_registers():
    layout = dict(boot=0, main=0x1000, handler=0x400, mailbox=0x3000,
                  result=0x5000)
    segments = custom_irq_segments(layout, irq_bit=3, vector=0x10,
                                   status=0, result=4, clear=8,
                                   clear_value=12, flag=16)
    assert set(segments) == {0, 0x10, 0x40, 0x400}
    assert int.from_bytes(segments[0], 'little') & 0x7f == 0x6f
    boot = [int.from_bytes(segments[0x40][i:i+4], 'little')
            for i in range(0, len(segments[0x40]), 4)]
    assert 0x0601e00b in boot  # maskirq x0,x3
    handler = [int.from_bytes(segments[0x400][i:i+4], 'little')
               for i in range(0, len(segments[0x400]), 4)]
    assert handler[0] == 0x020fa10b  # setq q2,x31
    assert handler[-2] == 0x00014f8b  # getq x31,q2
    assert handler[-1] == 0x0400000b  # retirq
    assert sum(word & 0x7f == 0x23 for word in handler) >= 6
