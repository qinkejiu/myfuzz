"""RV32I firmware layout for the cacheless32 reduced-dual-AXI Vexii CPU."""
from .dma_ram_firmware import dma_ram_images

MAIN = 0x80000000
BOOT_BYTES = 512
# The pinned generated core permits LSU MMIO only in this 4-KiB PMA page.
DMA_BASE = 0x40000000
SOURCE = 0x80001000
DESTINATION = 0x80002000
RESULT = 0x80003000
WORDS = (0x135, 0x246, 0x357, 0x468)


def vexii_dma_images(*, start_key=0xfed):
    """Supply only the declared Vexii address layout to the shared builder."""
    return dma_ram_images(main=MAIN, source=SOURCE, destination=DESTINATION,
        result=RESULT, dma_base=DMA_BASE, words=WORDS, boot_bytes=BOOT_BYTES,
        start_key=start_key)
