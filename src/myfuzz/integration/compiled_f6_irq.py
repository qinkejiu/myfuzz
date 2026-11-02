"""Resolve the admitted F6 IRQ export without guessing a runtime alias."""

from collections.abc import Mapping


def f6_dma_irq_runtime_name(dma, irq_contract):
    """Return the physical sample key bound to the logical F6 IRQ source.

    The execution contract names the protocol signal and endpoint. Generated
    harnesses may expose that physical signal under a wrapper-specific runtime
    name, so raw samples must be read through the uniquely admitted export.
    """
    if (not isinstance(irq_contract, Mapping)
            or type(irq_contract.get('producer_port')) is not str
            or not irq_contract['producer_port']
            or type(irq_contract.get('producer_endpoint_id')) is not str
            or not irq_contract['producer_endpoint_id']):
        raise ValueError('compiled-F6-DMA-IRQ-contract-invalid')
    artifact = getattr(dma, 'artifact', None)
    runtime_document = getattr(artifact, 'runtime_document', None)
    exports = (runtime_document.get('physical_exports')
        if isinstance(runtime_document, Mapping) else None)
    if not isinstance(exports, (list, tuple)):
        raise ValueError('compiled-F6-DMA-IRQ-runtime-exports-invalid')
    matches = [row for row in exports if isinstance(row, Mapping)
        and row.get('physical_port') == irq_contract['producer_port']
        and row.get('endpoint_id') == irq_contract['producer_endpoint_id']
        and row.get('direction') == 'output' and row.get('role') == 'irq'
        and row.get('width') == 1 and row.get('disposition') == 'functional']
    if len(matches) != 1:
        raise ValueError('compiled-F6-DMA-IRQ-runtime-export-not-unique')
    runtime_name = matches[0].get('runtime_name')
    if (type(runtime_name) is not str or not runtime_name
            or getattr(dma, '_irq_runtime_name', None) != runtime_name):
        raise ValueError('compiled-F6-DMA-IRQ-runtime-export-drift')
    expected_instance = irq_contract.get('producer_instance')
    if (expected_instance is not None
            and getattr(dma, 'source_component', None) != expected_instance):
        raise ValueError('compiled-F6-DMA-IRQ-runtime-owner-drift')
    return runtime_name
