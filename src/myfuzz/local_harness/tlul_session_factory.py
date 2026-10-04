"""Select a generated TL-UL register service from admitted artifact tuning."""
from __future__ import annotations

from .request import LocalHarnessRequestV2
from .tlul_register_session import GeneratedTlulRegisterSession
from .tlul_register_template import serial_peer_policy
from .tlul_uart_peer_session import GeneratedTlulUartPeerSession
from .tlul_spi_mode0_peer_session import GeneratedTlulSpiMode0PeerSession


def create_generated_tlul_session(artifact, *, base_dir, cache_dir):
    """Construct a generic register session or its declared serial peer.

    The caller supplies no component name, pin role, baud ratio, or register
    setup.  Those facts are part of the admitted, replay-hashed artifact.
    """
    document = getattr(artifact, 'runtime_document', None)
    plan = getattr(artifact, 'plan', None)
    if (not isinstance(document, dict) or document.get('kind') != 'tlul_register_observe'
            or document.get('driver_status') != 'generated' or plan is None
            or not isinstance(plan.request, LocalHarnessRequestV2)):
        raise ValueError('generated TL-UL v2 register artifact required')
    expected = serial_peer_policy(plan)
    if document.get('serial_peer') != expected:
        raise ValueError('TL-UL serial peer tuning differs from artifact')
    if expected is None:
        return GeneratedTlulRegisterSession(artifact, base_dir=base_dir,
                                            cache_dir=cache_dir)
    writes = tuple(tuple(row) for row in expected['startup_writes'])
    if expected['format'] == 'mode0-single':
        return GeneratedTlulSpiMode0PeerSession(
            artifact, base_dir=base_dir, cache_dir=cache_dir,
            clock_input=expected['clock_input'],
            select_input=expected['select_input'],
            data_input=expected['data_input'],
            data_output=expected['data_output'],
            enable_output=expected['enable_output'],
            source_id=expected['source_id'], source_port=expected['source_port'],
            source_bytes=expected['source_bytes'],
            prefix=bytes.fromhex(expected['prefix_hex']),
            read_count=expected['read_count'],
            mosi_lane=expected['mosi_lane'], miso_lane=expected['miso_lane'],
            half_period=expected['half_period'], setup_writes=writes)
    if expected['format'] != '8N1':
        raise ValueError('unknown generated TL-UL serial peer format')
    return GeneratedTlulUartPeerSession(
        artifact, base_dir=base_dir, cache_dir=cache_dir,
        rx_port=expected['rx_port'], tx_port=expected['tx_port'],
        source_id=expected['source_id'],
        clocks_per_bit=expected['clocks_per_bit'], idle_bits=expected['idle_bits'],
        setup_writes=writes)
