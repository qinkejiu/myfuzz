"""Stateful external I2C target on OpenTitan's open-drain pin interface.

Call ``observe`` after each RTL tick with ``cio_scl_en_o`` and
``cio_sda_en_o``. The returned ``scl_i`` and ``sda_i`` properties are the
resolved pulled-up bus levels to supply as ``cio_scl_i``/``cio_sda_i`` before
the next tick. An enable of one means pull low; neither side drives high.
"""

from __future__ import annotations


class I2cPeer:
    """Seven-bit target with queued read data and acknowledged write bytes."""

    def __init__(self, payload: bytes = b"", *, address: int = 0x50,
                 stretch_cycles: int = 0) -> None:
        if not 0 <= address <= 0x7f:
            raise ValueError("I2C target address must be seven bits")
        if stretch_cycles < 0:
            raise ValueError("stretch_cycles must be nonnegative")
        self.address = address
        self.stretch_cycles = stretch_cycles
        self._payload = bytearray(payload)
        self.reset_case()

    def reset_case(self, payload: bytes | None = None) -> None:
        """Reset all bus/protocol state, optionally replacing read payload."""
        if payload is not None:
            self._payload = bytearray(payload)
        self._payload_index = 0
        self._host_scl_low = False
        self._host_sda_low = False
        self._peer_scl_low = False
        self._peer_sda_low = False
        self._stretch_left = 0
        self._state = "idle"
        self._bit_index = 0
        self._rx_byte = 0
        self._read_byte = 0
        self._ack_pending = False
        self._after_ack = "idle"
        self._master_acked = False
        self._current_write = bytearray()
        self._completed_writes: list[bytes] = []
        self._sampled_bytes: list[int] = []
        self.start_count = 0
        self.stop_count = 0
        self.ack_count = 0

    def queue_payload(self, payload: bytes) -> None:
        """Append read bytes without changing the bit currently on the bus."""
        self._payload.extend(payload)

    @property
    def scl_i(self) -> int:
        return int(not (self._host_scl_low or self._peer_scl_low))

    @property
    def sda_i(self) -> int:
        return int(not (self._host_sda_low or self._peer_sda_low))

    @property
    def peer_scl_low(self) -> bool:
        return self._peer_scl_low

    @property
    def peer_sda_low(self) -> bool:
        return self._peer_sda_low

    @property
    def payload_index(self) -> int:
        """Number of complete queued bytes transmitted since reset."""
        return self._payload_index

    @property
    def completed_writes(self) -> tuple[bytes, ...]:
        return tuple(self._completed_writes)

    @property
    def sampled_bytes(self) -> tuple[int, ...]:
        """Complete address and write bytes sampled on SCL rising edges."""
        return tuple(self._sampled_bytes)

    def _close_write(self) -> None:
        if self._current_write:
            self._completed_writes.append(bytes(self._current_write))
            self._current_write.clear()

    def _start(self) -> None:
        self._close_write()
        self.start_count += 1
        self._state = "address"
        self._bit_index = 0
        self._rx_byte = 0
        self._peer_sda_low = False

    def _stop(self) -> None:
        self._close_write()
        self.stop_count += 1
        self._state = "idle"
        self._peer_sda_low = False
        self._bit_index = 0

    def _rising(self) -> None:
        if self._state in ("address", "write"):
            self._rx_byte = (self._rx_byte << 1) | self.sda_i
            self._bit_index += 1
            if self._bit_index == 8:
                value = self._rx_byte
                self._sampled_bytes.append(value)
                if self._state == "address":
                    matched = value >> 1 == self.address
                    is_read = bool(value & 1)
                    self._ack_pending = matched and (
                        not is_read or self._payload_index < len(self._payload)
                    )
                    self._after_ack = ("read" if is_read else "write") if self._ack_pending else "idle"
                else:
                    self._current_write.append(value)
                    self._ack_pending = True
                    self._after_ack = "write"
                self._state = "target_ack_wait"
                self._bit_index = 0
                self._rx_byte = 0
        elif self._state == "target_ack":
            if self._ack_pending:
                self.ack_count += 1
            self._state = "target_ack_done"
        elif self._state == "read":
            self._bit_index += 1
            if self._bit_index == 8:
                if self._payload_index < len(self._payload):
                    self._payload_index += 1
                self._state = "master_ack_wait"
                self._bit_index = 0
        elif self._state == "master_ack":
            self._master_acked = self.sda_i == 0
            self._state = "master_ack_done"

    def _set_read_bit(self) -> None:
        if self._payload_index < len(self._payload):
            self._read_byte = self._payload[self._payload_index]
        else:
            # A target cannot NACK a data phase. An exhausted queue releases
            # SDA, yielding 0xff if the host insists on more clocks.
            self._read_byte = 0xff
        self._peer_sda_low = not bool((self._read_byte >> (7 - self._bit_index)) & 1)

    def _falling(self) -> None:
        if self._state == "target_ack_wait":
            self._peer_sda_low = self._ack_pending
            self._state = "target_ack"
        elif self._state == "target_ack_done":
            self._peer_sda_low = False
            self._state = self._after_ack
            if self._state == "read":
                self._set_read_bit()
        elif self._state == "read":
            self._set_read_bit()
        elif self._state == "master_ack_wait":
            self._peer_sda_low = False
            self._state = "master_ack"
        elif self._state == "master_ack_done":
            self._state = "read" if self._master_acked else "idle"
            if self._state == "read":
                self._set_read_bit()

    def observe(self, *, scl_en: int, sda_en: int) -> None:
        """Advance on actual resolved bus edges after one local RTL tick."""
        if scl_en not in (0, 1) or sda_en not in (0, 1):
            raise ValueError("I2C output enables must be binary")
        old_scl, old_sda = self.scl_i, self.sda_i
        old_host_scl_low = self._host_scl_low
        self._host_scl_low = bool(scl_en)
        self._host_sda_low = bool(sda_en)

        if self._host_scl_low:
            self._peer_scl_low = False
            self._stretch_left = 0
        elif old_host_scl_low and self.stretch_cycles and self._state != "idle":
            self._peer_scl_low = True
            self._stretch_left = self.stretch_cycles
        elif self._peer_scl_low:
            self._stretch_left -= 1
            if self._stretch_left == 0:
                self._peer_scl_low = False

        new_scl, new_sda = self.scl_i, self.sda_i
        if old_scl == new_scl == 1 and old_sda != new_sda:
            if new_sda == 0:
                self._start()
            else:
                self._stop()
        elif old_scl == 0 and new_scl == 1:
            self._rising()
        elif old_scl == 1 and new_scl == 0:
            self._falling()
