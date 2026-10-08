"""Bounded 8N1 serial peer driven by clocks and observed DUT TX pin levels."""

from __future__ import annotations

from bisect import bisect_left, bisect_right


class Uart8N1Peer:
    def __init__(self, source: bytes, *, clocks_per_bit: int = 25):
        if (not isinstance(source, bytes) or len(source) > 64
                or type(clocks_per_bit) is not int or not 16 <= clocks_per_bit <= 4096):
            raise ValueError('invalid UART serial source')
        self.source = source
        self.clocks_per_bit = clocks_per_bit
        self.reset_case()

    def reset_case(self) -> None:
        self.source_start_tick: int | None = None
        self._source_starts: list[int] = []
        self._source_segments: list[bytes] = []
        self.last_line = 1
        self.start_tick: int | None = None
        self.next_sample = 0
        self.bits: list[int] = []
        self.captured: list[int] = []
        self.last_observed_tick = -1

    def start_source(self, tick: int) -> None:
        if self.source_start_tick is not None or type(tick) is not int or tick < 0:
            raise ValueError('UART source already scheduled')
        self.source_start_tick = tick
        self._source_starts.append(tick)
        self._source_segments.append(self.source)

    def append_source(self, source: bytes, tick: int) -> None:
        """Schedule another real RX waveform after at least one idle bit."""
        if (self.source_start_tick is None or not isinstance(source, bytes)
                or not 1 <= len(source) <= 64 or type(tick) is not int
                or tick < self.source_end_tick + self.clocks_per_bit):
            raise ValueError('invalid or overlapping UART source frame')
        self._source_starts.append(tick)
        self._source_segments.append(source)

    @property
    def source_end_tick(self) -> int:
        if not self._source_starts:
            return 0
        return (self._source_starts[-1]
                + 10 * self.clocks_per_bit * len(self._source_segments[-1]))

    def source_active(self, tick: int) -> bool:
        index = bisect_right(self._source_starts, tick) - 1
        return (index >= 0 and tick < self._source_starts[index]
                + 10 * self.clocks_per_bit * len(self._source_segments[index]))

    def source_overlaps(self, start: int, end: int) -> bool:
        """Whether a half-open local tick window intersects an RX waveform."""
        if start >= end:
            return False
        index = bisect_left(self._source_starts, end) - 1
        return (index >= 0 and self._source_starts[index]
                + 10 * self.clocks_per_bit * len(self._source_segments[index]) > start)

    def drive_rx(self, tick: int) -> int:
        index = bisect_right(self._source_starts, tick) - 1
        if index < 0:
            return 1
        slot = (tick - self._source_starts[index]) // self.clocks_per_bit
        source = self._source_segments[index]
        if slot >= 10 * len(source):
            return 1
        byte = source[slot // 10]
        bit = slot % 10
        return 0 if bit == 0 else 1 if bit == 9 else (byte >> (bit - 1)) & 1

    def observe_tx(self, tick: int, line: int) -> None:
        if type(tick) is not int or tick <= self.last_observed_tick or line not in (0, 1):
            raise ValueError('invalid UART TX observation')
        self.last_observed_tick = tick
        if self.start_tick is None and self.last_line == 1 and line == 0:
            self.start_tick = tick
            self.next_sample = 0
            self.bits = []
        if self.start_tick is not None:
            while self.next_sample < 10:
                sample_tick = (self.start_tick + self.clocks_per_bit // 2
                               + self.next_sample * self.clocks_per_bit)
                if tick < sample_tick:
                    break
                self.bits.append(line)
                self.next_sample += 1
            if self.next_sample == 10:
                if self.bits[0] != 0 or self.bits[9] != 1:
                    raise ValueError('invalid observed UART 8N1 frame')
                self.captured.append(sum(bit << index for index, bit in
                                         enumerate(self.bits[1:9])))
                self.start_tick = None
        self.last_line = line
