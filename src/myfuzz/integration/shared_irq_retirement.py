"""Check observed DMA dispatch against a separately rebuilt fixed image."""


def validate_dma_dispatch_retirements(document, image, rows):
    path = document['stages']['dma_dispatch_path'] + [document['stages']['dma']['address']]
    if len(rows) != len(path):
        raise ValueError('shared IRQ DMA dispatch retirement count')
    previous = None
    for pc, row in zip(path, rows):
        offset = pc - document['entry_address']
        if (offset < 0 or offset + 4 > len(image) or row['pc'] != pc
                or row['instruction'] != int.from_bytes(image[offset:offset+4], 'little')):
            raise ValueError('shared IRQ DMA dispatch instruction path')
        if previous is not None and (
                row['rvfi_order'] != previous['rvfi_order'] + 1
                or row['receipt_id']['execution'] != previous['receipt_id']['execution']
                or row['receipt_id']['sequence'] <= previous['receipt_id']['sequence']):
            raise ValueError('shared IRQ DMA dispatch retirement chronology')
        previous = row
