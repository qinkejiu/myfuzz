"""RV32I firmware for CPU-programmed CVW/ZipCPU DMA RAM composition.

Only code and zero destination/result images are host supplied. All source and
DMA register stores are executed by the CPU; no interrupt contract is assumed.
"""
MAIN = 0xC0000000
BOOT_BYTES = 512
DMA_BASE = 0xCFFF1000
SOURCE = 0xC0001000
DESTINATION = 0xC0002000
RESULT = 0xC0003000
WORDS = (0x135, 0x246, 0x357, 0x468)


from .dma_ram_firmware import (
    _addi, _bne, _lui, _lw, _srli, _sw, dma_ram_images,
)


def cvw_dma_images(*, start_key=0xfed):
    """Return the accepted CVW boot, zero destination and zero result images."""
    return dma_ram_images(main=MAIN, source=SOURCE, destination=DESTINATION,
        result=RESULT, dma_base=DMA_BASE, words=WORDS, boot_bytes=BOOT_BYTES,
        start_key=start_key)
