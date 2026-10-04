"""Reusable single-line SPI mode-0 master over a generated TL-UL register harness.

The master only supplies a declared external frame and physical pin waveform.
MISO, output enable, IRQ, and register responses are observed from real RTL.
"""
from __future__ import annotations

from collections.abc import Mapping

from .session import GeneratedLocalSession
from .tlul_register_session import GeneratedTlulRegisterSession


class GeneratedTlulSpiMode0PeerSession(GeneratedTlulRegisterSession):
    """Drive one source-owned frame through declared pins, with local timing."""

    def __init__(self, artifact, *, base_dir, cache_dir, clock_input: str,
                 select_input: str, data_input: str, data_output: str,
                 enable_output: str, source_id: str, source_port: str,
                 source_bytes: int, prefix: bytes, read_count: int,
                 mosi_lane: int, miso_lane: int, half_period: int = 8,
                 setup_writes=(), **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         setup_writes=setup_writes, **kwargs)
        inputs = (clock_input, select_input, data_input)
        if (len(set(inputs)) != 3 or set(self._dynamic) != set(inputs) or
                any(self._dynamic[name][2] != source_id for name in inputs) or
                self._dynamic[clock_input][1] != 1 or
                self._dynamic[select_input][1] != 1 or self._bound or
                data_output not in self._outputs or
                enable_output not in self._outputs or
                self._outputs[data_output][1] != self._outputs[enable_output][1] or
                type(source_id) is not str or not source_id or
                type(source_port) is not str or not source_port or
                type(source_bytes) is not int or not 1 <= source_bytes <= 4 or
                type(prefix) is not bytes or len(prefix) > 4 or
                type(read_count) is not int or not 0 <= read_count <= 8 or
                type(half_period) is not int or not 2 <= half_period <= 32 or
                type(mosi_lane) is not int or not 0 <= mosi_lane < self._dynamic[data_input][1] or
                type(miso_lane) is not int or not 0 <= miso_lane < self._outputs[data_output][1]):
            raise ValueError('SPI peer needs three declared source pins and real MISO outputs')
        self.clock_input = clock_input
        self.select_input = select_input
        self.data_input = data_input
        self.data_output = data_output
        self.enable_output = enable_output
        self.source_id = source_id
        self.source_port = source_port
        self.source_bytes = source_bytes
        self.prefix = prefix
        self.read_count = read_count
        self.mosi_lane = mosi_lane
        self.miso_lane = miso_lane
        self.half_period = half_period
        self._selected_frame: int | None = None
        self.last_response = b''
        self.miso_enabled_samples = 0
        # One scenario step may contain a complete local serial exchange.
        total_bytes = len(prefix) + source_bytes + read_count
        self.max_local_ticks_per_step = (self.max_local_ticks_per_step +
            total_bytes * 8 * (2 * half_period + 4) + 2 * half_period + 32)

    def identity_document(self):
        return {**super().identity_document(),
                'dynamic_input_initial_policy': 'spi_cs_idle_high_at_case_start',
                'spi_mode0_peer': {
                    'schema_version': 'generated_tlul_spi_mode0_peer.v1',
                    'clock_input': self.clock_input,
                    'select_input': self.select_input,
                    'data_input': self.data_input,
                    'data_output': self.data_output,
                    'enable_output': self.enable_output,
                    'source_id': self.source_id,
                    'source_port': self.source_port,
                    'source_bytes': self.source_bytes,
                    'prefix_hex': self.prefix.hex(),
                    'read_count': self.read_count,
                    'mosi_lane': self.mosi_lane,
                    'miso_lane': self.miso_lane,
                    'half_period': self.half_period,
                    'frame_policy': 'one_source_frame_per_testcase',
                    'chip_select_idle': 1}}

    def validate_scenario_ownership(self, component_id, ownership):
        document = ownership.document()
        width = 8 * self.source_bytes
        fields = [row for row in document['fields']
                  if row['component_id'] == component_id]
        owners = [row for row in document['owners']
                  if row['component_id'] == component_id]
        if (fields != [dict(component_id=component_id, port=self.source_port,
                            width=width)] or
                owners != [dict(component_id=component_id, port=self.source_port,
                                bit_offset=0, width=width, kind='source',
                                producer_ref=self.source_id)]):
            raise ValueError('SPI master frame source ownership must match declared pins')

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._selected_frame = None
        self.last_response = b''
        self.miso_enabled_samples = 0
        # The generic driver initializes dynamic fields to zero.  A SPI slave
        # needs deselected CS before APB configuration and before any SCK edge.
        index, _, _ = self._dynamic[self.select_input]
        self._take(self.command('SOURCE_TLUL_REG', (index, 1)))
        self._dynamic_values[self.select_input] = 1

    def _phase(self, clock: int, selected: int, mosi: int):
        inputs = {self.clock_input: clock,
                  self.select_input: 0 if selected else 1,
                  self.data_input: mosi << self.mosi_lane}
        observed = None
        for _ in range(self.half_period):
            observed = super().step_local(inputs)
        return observed

    def _transfer(self, payload: bytes):
        received = bytearray()
        self._phase(0, 1, 0)
        try:
            for sent in payload + bytes(self.read_count):
                captured = 0
                for shift in range(7, -1, -1):
                    bit = (sent >> shift) & 1
                    self._phase(0, 1, bit)
                    observed = self._phase(1, 1, bit)
                    enabled = (observed[self.enable_output] >> self.miso_lane) & 1
                    if enabled:
                        self.miso_enabled_samples += 1
                    captured = (captured << 1) | (
                        (observed[self.data_output] >> self.miso_lane) & 1 if enabled else 0)
                received.append(captured)
            self._phase(0, 1, 0)
        finally:
            self._phase(0, 0, 0)
        self.last_response = bytes(received[len(payload):])

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or set(inputs) - {self.source_port}:
            raise ValueError('SPI peer expects only its declared master frame source')
        if self.source_port in inputs:
            value = inputs[self.source_port]
            if type(value) is not int or not 0 <= value < 1 << (8 * self.source_bytes):
                raise ValueError('SPI master frame exceeds declared source width')
            if self._selected_frame is None:
                self._selected_frame = value
                self._transfer(self.prefix + value.to_bytes(self.source_bytes, 'big'))
            elif value != self._selected_frame:
                raise ValueError('SPI master frame cannot change after transfer')
        observed = super().step_local({})
        return {**observed,
                'serial_miso_value': int.from_bytes(self.last_response, 'big'),
                'serial_miso_bytes': len(self.last_response),
                'serial_miso_enabled_samples': self.miso_enabled_samples,
                'serial_frame_done': int(self._selected_frame is not None)}

    def step_local_routed(self, source_inputs: Mapping[str, int],
                          bound_inputs: Mapping[str, int]):
        if bound_inputs:
            raise ValueError('SPI external master has no real upstream binding')
        return self.step_local(source_inputs)

    def reset_local(self):
        result = GeneratedLocalSession.reset_local(self)
        self._started = False
        self.local_transactions.clear()
        return result
