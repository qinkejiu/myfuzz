"""Ordered word-operation DMA firmware for the pinned RV64 CVA6 low NC RAM.

These low positive addresses and words allow the shared RV32I subset on RV64.
Fences drain pending stores; they do not imply cache invalidation or coherence.
"""
from .dma_ram_firmware import dma_ram_images

MAIN = 0x10000
BOOT_BYTES = 512
DMA_BASE = 0x40002000
SOURCE = 0x11000
DESTINATION = 0x12000
RESULT = 0x13000
WORDS = (0x135, 0x246, 0x357, 0x468)


def cva6_dma_images(*, start_key=0xfed):
    """Return only boot and zero destination/result images; CPU supplies source."""
    return dma_ram_images(main=MAIN, source=SOURCE, destination=DESTINATION,
        result=RESULT, dma_base=DMA_BASE, words=WORDS, boot_bytes=BOOT_BYTES,
        start_key=start_key, ordered_stores=True)
