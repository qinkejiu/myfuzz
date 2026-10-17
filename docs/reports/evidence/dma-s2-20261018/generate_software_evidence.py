"""Read-only S2 software evidence generator (no RTL, no execution claim).

Recomputes the fixed firmware layout, the declared control words and the
declared DMA program of every S2 gate case directly from the source modules and
writes ``descriptor-program.json``.  Running it never builds or starts RTL.
"""
import json
from pathlib import Path

from myfuzz.integration.dma_uart_descriptor_runtime import (
    DescriptorCase, descriptor_windows)
from myfuzz.scenario import ibex_dma_uart_descriptor as firmware

CASES = (
    DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1),
    DescriptorCase.create('RX_TO_RAM', dst_index=1, payload=0xA5, length=3),
    DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x00, length=1),
    DescriptorCase.create('RAM_TO_RAM', dst_index=2, payload=0x7E, length=2),
    DescriptorCase.create('RAM_TO_TX', dst_index=3, payload=0xFF, length=1),
    DescriptorCase.create('RAM_TO_TX', dst_index=0, payload=0x33, length=2),
)


def control_bits(word):
    return dict(word=word, hex=f'0x{word:08x}',
        start_key=(word >> firmware.CONTROL_KEY_SHIFT) & 0xFFF,
        inc_s_n=(word >> 29) & 1, inc_d_n=(word >> 28) & 1,
        block_length_sub_one=word & 0x3FF)


def main():
    root = Path(__file__).resolve().parent
    document = dict(
        schema_version='descriptor_dma_software_evidence.v1',
        claim=dict(real_rtl_evidence=False,
            note='fixed firmware layout and declared DMA programs only; '
                 'the native gate is queued until the source tree is frozen'),
        firmware=dict(
            main=firmware.MAIN, mtvec_base=firmware.MTVEC_BASE,
            isr=firmware.ISR,
            main_words=len(firmware.MAIN_WORDS),
            main_bytes=4 * len(firmware.MAIN_WORDS),
            main_end=firmware.MAIN + 4 * len(firmware.MAIN_WORDS),
            isr_words=len(firmware.ISR_WORDS),
            isr_end=firmware.ISR + 4 * len(firmware.ISR_WORDS),
            labels=dict(main={name: f'0x{address:08x}'
                              for name, address in firmware.MAIN_PCS.items()},
                        isr={name: f'0x{address:08x}'
                             for name, address in firmware.ISR_PCS.items()}),
            images={f'0x{address:08x}': len(image) for address, image
                    in firmware.descriptor_uart_images().items()},
            boot_seed_words=list(firmware.BOOT_SEED_WORDS),
            result_layout=dict(mcause=firmware.RESULT,
                status=firmware.RESULT + 4, length=firmware.RESULT + 8,
                witness=firmware.WITNESS,
                counter=firmware.COMPLETED,
                witness_pointer=firmware.WITNESS_POINTER),
            source_ram=firmware.SOURCE_RAM,
            destination_ram=firmware.DESTINATION,
            uart=dict(base=firmware.UART_BASE,
                status_offset=firmware.UART_STATUS_OFFSET,
                rxempty_mask=firmware.UART_RXEMPTY_MASK,
                rdata=firmware.UART_RDATA, wdata=firmware.UART_WDATA),
            illegal_target=firmware.ILLEGAL_TARGET),
        control_words={name: control_bits(word)
                       for name, word in firmware.CONTROL_WORDS.items()},
        declared_windows={name: list(window)
                          for name, window in descriptor_windows().items()},
        cases=[dict(case_index=index, spec=case.to_document(),
                    source_bytes=[f'0x{byte:02x}' for byte in case.source_bytes],
                    program={**{name: (list(value) if isinstance(value, tuple)
                                        else value)
                                for name, value in case.program().items()},
                             'control_hex': f'0x{case.program()["control"]:08x}'})
               for index, case in enumerate(CASES, 1)])
    (root / 'descriptor-program.json').write_text(
        json.dumps(document, sort_keys=True, indent=1), encoding='utf-8')
    print(json.dumps(dict(main_words=document['firmware']['main_words'],
        isr_words=document['firmware']['isr_words'],
        main_end=document['firmware']['main_end'],
        isr_end=document['firmware']['isr_end'],
        cases=len(document['cases'])), sort_keys=True))


if __name__ == '__main__':
    main()
