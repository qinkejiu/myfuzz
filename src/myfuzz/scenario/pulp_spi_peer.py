"""Explicit single-CS PULP mode-0 external pin peer, not a runtime backend.

Drive SDI1 before each real HCLK tick and observe all actual pre/post pin
snapshots afterward. A batched ACCESS command cannot use this Python peer
unless the backend exchanges pin states between its internal ticks. This
helper neither creates a DUT response nor predicts events_o.
"""
from __future__ import annotations

from collections.abc import Mapping

from .spi_peer import SpiPeer


class PulpSpiMode0Peer:
    """Single-line MSB-first frames and raw native event transition receipts."""

    def __init__(self, payload: bytes = b'', *, chip_select: int = 0):
        if type(chip_select) is not int or not 0 <= chip_select < 4:
            raise ValueError('invalid PULP SPI chip select')
        self.chip_select = chip_select
        self._peer = SpiPeer(payload)
        self.reset_case()

    def reset_case(self, payload: bytes | None = None) -> None:
        self._peer.reset_case(payload)
        self._last_position = (0, 1)
        self._last_selected = False
        self._selected_has_edge = False
        self._last_sck = 0
        self._last_mode = 0
        self._event_levels = 0
        self.events: list[dict] = []

    def queue_payload(self, payload: bytes) -> None:
        self._peer.queue_payload(payload)

    def drive_inputs(self) -> dict[str, int]:
        return {'spi_sdi0': 0, 'spi_sdi1': self._peer.miso if self._last_mode == 0 else 0,
                'spi_sdi2': 0, 'spi_sdi3': 0}

    @property
    def completed_frames(self) -> tuple[bytes, ...]:
        return self._peer.completed_frames

    @property
    def sample_count(self) -> int:
        return self._peer.sample_count

    @property
    def incomplete_frame_count(self) -> int:
        return self._peer.incomplete_frame_count

    @property
    def payload_index(self) -> int:
        return self._peer.payload_index

    def observe(self, pins: Mapping[str, int], *, local_tick: int, phase: str) -> None:
        """Accept one real sampled state; rising SCK captures, falling updates.

        Receipt positions must strictly increase. Idle spi_mode can be 2 (the
        controller's reset value). Its selected idle-low setup transient may
        also show 2; clocked transfers require mode 0.
        Simultaneous selection and rising SCK cannot establish a setup bit and
        is refused. Each events_o bit is recorded exactly when its level changes.
        """
        phase_index = {'pre': 0, 'post': 1}.get(phase)
        if (type(local_tick) is not int or local_tick < 1 or phase_index is None
                or (local_tick, phase_index) <= self._last_position):
            raise ValueError('invalid PULP SPI receipt position')
        required = {'spi_clk', 'spi_csn0', 'spi_csn1', 'spi_csn2', 'spi_csn3',
                    'spi_mode', 'spi_sdo0', 'events_o'}
        if not isinstance(pins, Mapping) or not required <= pins.keys():
            raise ValueError('missing PULP SPI pin observation')
        for name in required:
            maximum = 3 if name in {'spi_mode', 'events_o'} else 1
            if type(pins[name]) is not int or not 0 <= pins[name] <= maximum:
                raise ValueError('invalid PULP SPI pin observation: ' + name)
        selected_cs = [index for index in range(4) if pins['spi_csn' + str(index)] == 0]
        if selected_cs and selected_cs != [self.chip_select]:
            raise ValueError('unsupported PULP SPI chip selection')
        selected = bool(selected_cs)
        edge = selected and self._last_selected and pins['spi_clk'] != self._last_sck
        setup_transient = (pins['spi_mode'] == 2 and pins['spi_clk'] == 0
                           and not self._selected_has_edge and not edge)
        if selected and pins['spi_mode'] != 0 and not setup_transient:
            raise ValueError('PULP SPI peer supports selected single-line mode only')
        if selected and not self._last_selected and pins['spi_clk'] != 0:
            raise ValueError('PULP SPI selection requires idle-low SCK setup')
        self._peer.observe(sck=pins['spi_clk'], csb=0 if selected else 1,
                           mosi=pins['spi_sdo0'])
        levels = pins['events_o']
        for bit in range(2):
            if (levels ^ self._event_levels) & (1 << bit):
                self.events.append({'kind': 'native_spi_event', 'port': 'events_o',
                                    'bit': bit, 'local_tick': local_tick, 'phase': phase,
                                    'level': (levels >> bit) & 1})
        self._event_levels = levels
        self._last_position = (local_tick, phase_index)
        self._selected_has_edge = (self._selected_has_edge or edge) if selected else False
        self._last_sck = pins["spi_clk"]
        self._last_mode = pins["spi_mode"]
        self._last_selected = selected
