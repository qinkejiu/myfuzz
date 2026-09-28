"""Stateful external SPI peer for the OpenTitan SPI Host's single-line mode 0.

The caller supplies MISO (SD1) to the Host before each local tick and reports
the Host's observed SCK, CSB, and MOSI (SD0) afterward. No elapsed-cycle count
can advance this peer: only selected SCK edges move its transfer state.
"""

from __future__ import annotations


class SpiPeer:
    """Drive queued bytes MSB first, keeping completed transactions across CSB.

    ``queue_payload`` appends bytes for later transactions. A byte is consumed
    only after eight selected rising SCK edges. An interrupted byte starts over
    at its first bit on the next selection. ``reset_case`` is for an explicit
    testcase or RTL reset, not for a new command within one testcase.
    """

    def __init__(self, payload: bytes = b"", *, cpol: int = 0,
                 cpha: int = 0) -> None:
        if (cpol, cpha) != (0, 0):
            raise ValueError("SpiPeer currently supports only CPOL=0, CPHA=0")
        self._payload = bytearray(payload)
        self.reset_case()

    def reset_case(self, payload: bytes | None = None) -> None:
        """Reset transfer state, optionally replacing the queued payload."""
        if payload is not None:
            self._payload = bytearray(payload)
        self._payload_index = 0
        self._last_sck = 0
        self._last_csb = 1
        self._miso = 0
        self._rx_byte = 0
        self._bit_index = 0
        self._current_frame = bytearray()
        self._completed_frames: list[bytes] = []
        self.sample_count = 0
        self.incomplete_frame_count = 0

    def queue_payload(self, payload: bytes) -> None:
        """Append fuzzable source bytes without changing the active bit."""
        self._payload.extend(payload)

    @property
    def sd_i(self) -> int:
        """Four-bit Host input word, with only SD1 (MISO) driven."""
        return self._miso << 1

    @property
    def miso(self) -> int:
        return self._miso

    @property
    def bit_index(self) -> int:
        """Next bit index to sample within the current byte, from 0 to 7."""
        return self._bit_index

    @property
    def payload_index(self) -> int:
        """Number of complete payload bytes consumed since testcase reset."""
        return self._payload_index

    @property
    def completed_frames(self) -> tuple[bytes, ...]:
        """Complete MOSI bytes grouped by closed CSB selection."""
        return tuple(self._completed_frames)

    def _payload_bit(self) -> int:
        if self._payload_index >= len(self._payload):
            return 0
        return (self._payload[self._payload_index] >> (7 - self._bit_index)) & 1

    def observe(self, *, sck: int, csb: int, mosi: int) -> None:
        """Consume one observed Host pin state after a local RTL tick."""
        if sck not in (0, 1) or csb not in (0, 1) or mosi not in (0, 1):
            raise ValueError("SPI pins must be binary")

        was_selected = self._last_csb == 0
        selected = csb == 0
        if selected and not was_selected:
            self._rx_byte = 0
            self._bit_index = 0
            self._current_frame = bytearray()
            self._miso = self._payload_bit()
        elif was_selected and not selected:
            if self._bit_index:
                self.incomplete_frame_count += 1
            if self._current_frame:
                self._completed_frames.append(bytes(self._current_frame))
            self._current_frame = bytearray()
            self._rx_byte = 0
            self._bit_index = 0
            self._miso = 0
        elif selected:
            if not self._last_sck and sck:
                self._rx_byte = (self._rx_byte << 1) | mosi
                self._bit_index += 1
                self.sample_count += 1
                if self._bit_index == 8:
                    self._current_frame.append(self._rx_byte)
                    self._payload_index += 1
                    self._rx_byte = 0
                    self._bit_index = 0
            elif self._last_sck and not sck:
                # Mode 0 samples the bit already presented on rising SCK. The
                # next bit becomes visible only on the following falling edge.
                self._miso = self._payload_bit()

        self._last_sck = sck
        self._last_csb = csb
