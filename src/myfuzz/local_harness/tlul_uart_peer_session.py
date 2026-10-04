"""Reusable 8N1 peer over the generated TL-UL register-observe artifact.

The peer supplies one Fuzzer-owned RX byte as a waveform on a declared
external pin.  Every TX byte comes from sampled DUT output; register and IRQ
results remain the generic session's real RTL observations.
"""
from __future__ import annotations

from collections.abc import Mapping

from myfuzz.scenario.uart_peer import Uart8N1Peer

from .session import GeneratedLocalSession
from .tlul_register_session import GeneratedTlulRegisterSession


class GeneratedTlulUartPeerSession(GeneratedTlulRegisterSession):
    """Add a parameterized serial peer without selecting a component kind."""

    def __init__(self, artifact, *, base_dir, cache_dir, rx_port: str,
                 tx_port: str, source_id: str, clocks_per_bit: int,
                 idle_bits: int = 17, setup_writes=(), **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         setup_writes=setup_writes, **kwargs)
        if (type(rx_port) is not str or type(tx_port) is not str or
                type(source_id) is not str or not source_id or
                rx_port not in self._dynamic or
                self._dynamic[rx_port][1:] != (1, source_id) or
                len(self._dynamic) != 1 or
                tx_port not in self._outputs or self._outputs[tx_port][1] != 1 or
                type(idle_bits) is not int or not 1 <= idle_bits <= 64 or
                self._bound):
            raise ValueError('UART peer requires one declared RX source and real TX output')
        self.rx_port = rx_port
        self.tx_port = tx_port
        self.source_id = source_id
        self.idle_bits = idle_bits
        self.peer = Uart8N1Peer(b'', clocks_per_bit=clocks_per_bit)
        self._selected_byte: int | None = None

    def identity_document(self):
        return {**super().identity_document(),
                'dynamic_input_initial_policy': 'uart_rx_idle_high_at_case_start',
                'uart_peer': {'schema_version': 'generated_tlul_uart_peer.v1',
                              'rx_port': self.rx_port, 'tx_port': self.tx_port,
                              'source_id': self.source_id,
                              'source_port': 'uart_rx_byte',
                              'clocks_per_bit': self.peer.clocks_per_bit,
                              'idle_bits': self.idle_bits}}

    def validate_scenario_ownership(self, component_id, ownership):
        document = ownership.document()
        fields = [row for row in document['fields'] if row['component_id'] == component_id]
        owners = [row for row in document['owners'] if row['component_id'] == component_id]
        if (fields != [dict(component_id=component_id, port='uart_rx_byte', width=8)] or
                owners != [dict(component_id=component_id, port='uart_rx_byte',
                               bit_offset=0, width=8, kind='source',
                               producer_ref=self.source_id)]):
            raise ValueError('UART frame source ownership must match declared RX source')

    @property
    def pending_events(self):
        return (max(0, self.peer.source_end_tick - self.local_ticks)
                if self.peer.source_start_tick is not None else 0)

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.peer.reset_case()
        self.peer.source = b''
        self._selected_byte = None
        # UART idle is a physical logic one, including before first setup write.
        index, _, _ = self._dynamic[self.rx_port]
        self._take(self.command('SOURCE_TLUL_REG', (index, 1)))
        self._dynamic_values[self.rx_port] = 1

    def _take(self, reply, *, step=False):
        observations = super()._take(reply, step=step)
        runtime_name, _ = self._outputs[self.tx_port]
        for sample in reply.payload['samples']:
            line = sample['post']['physical'][runtime_name]
            self.peer.observe_tx(self._tick_base + sample['local_tick'], line)
        return observations

    def step_local(self, inputs: Mapping[str, int]):
        if (not isinstance(inputs, Mapping) or set(inputs) - {'uart_rx_byte'} or
                'uart_rx_byte' in inputs and
                (type(inputs['uart_rx_byte']) is not int or
                 not 0 <= inputs['uart_rx_byte'] <= 255)):
            raise ValueError('UART peer expects only a Fuzzer-owned RX byte')
        if 'uart_rx_byte' in inputs:
            byte = inputs['uart_rx_byte']
            if self._selected_byte is None:
                self._selected_byte = byte
                self.peer.source = bytes((byte,))
            elif byte != self._selected_byte:
                raise ValueError('UART RX source cannot change within the frame')
        line = self.peer.drive_rx(self.local_ticks + 1)
        observations = super().step_local({self.rx_port: line})
        if self._selected_byte is not None and self.peer.source_start_tick is None:
            self.peer.start_source(self.local_ticks +
                                   self.idle_bits * self.peer.clocks_per_bit + 1)
        return {**observations,
                'serial_tx_count': len(self.peer.captured),
                'serial_tx_last': self.peer.captured[-1] if self.peer.captured else 0}

    def step_local_routed(self, source_inputs: Mapping[str, int],
                          bound_inputs: Mapping[str, int]):
        if bound_inputs:
            raise ValueError('UART peer RX has no real upstream binding')
        return self.step_local(source_inputs)

    def reset_local(self):
        result = GeneratedLocalSession.reset_local(self)
        self._started = False
        self.local_transactions.clear()
        self._dynamic_values[self.rx_port] = 1
        return result
