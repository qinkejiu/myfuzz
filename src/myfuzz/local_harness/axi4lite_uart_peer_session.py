"""Reusable 8N1 peer over the generated AXI4-Lite register-observe artifact.

The peer supplies one Fuzzer-owned RX byte as a waveform on a declared external
pin.  Every TX byte comes from sampled DUT output; register and interrupt
results remain the generic session's real RTL observations.  Nothing here names
a component: the RX pin, the TX pin, the byte source and the baud ratio all come
from the admitted artifact tuning, exactly as they do for the TL-UL member.

This is the serial half of the generic path.  The register member alone can
perform accesses but cannot put a frame on a wire, so without this a real
serial peripheral could only be driven through its IP-specific shell.
"""
from __future__ import annotations

from collections.abc import Mapping

from myfuzz.scenario.uart_peer import Uart8N1Peer

from .session import GeneratedLocalSession
from .axi4lite_register_session import GeneratedAxi4LiteRegisterSession


class GeneratedAxi4LiteUartPeerSession(GeneratedAxi4LiteRegisterSession):
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
            raise ValueError('AXI4-Lite UART peer requires one declared RX source '
                             'and one real TX output')
        self.rx_port = rx_port
        self.tx_port = tx_port
        self.source_id = source_id
        self.idle_bits = idle_bits
        self.peer = Uart8N1Peer(b'', clocks_per_bit=clocks_per_bit)
        self._selected_byte: int | None = None
        # Monotonic cursor over `_samples`; see `_observe_tx`.
        self._observed_samples = 0

    def _access(self, write, offset, value=0, be=15):
        """Refuse a register access that would land inside the RX waveform.

        A direct access is issued as its own command, so it drives the receive
        pin from the command's own field rather than from the peer's waveform.
        Allowing one mid-frame would freeze the pin and corrupt the frame with
        no diagnostic; the IP-specific member refuses it, and this generic
        member must refuse it too or it is not an equivalent replacement.
        """
        start = self.local_ticks + 1
        end = start + self.max_local_ticks_per_register_access
        if self.peer.source and self.peer.source_overlaps(start, end):
            raise RuntimeError(
                'AXI access during serial source waveform is unsupported')
        return super()._access(write, offset, value, be)

    def identity_document(self):
        return {**super().identity_document(),
                'dynamic_input_initial_policy': 'uart_rx_idle_high_at_case_start',
                'uart_peer': {
                    'schema_version': 'generated_axi4lite_uart_peer.v1',
                    'rx_port': self.rx_port, 'tx_port': self.tx_port,
                    'source_id': self.source_id,
                    'source_port': 'uart_rx_byte',
                    'clocks_per_bit': self.peer.clocks_per_bit,
                    'idle_bits': self.idle_bits}}

    def validate_scenario_ownership(self, component_id, ownership):
        document = ownership.document()
        fields = [row for row in document['fields']
                  if row['component_id'] == component_id]
        owners = [row for row in document['owners']
                  if row['component_id'] == component_id]
        if (fields != [dict(component_id=component_id, port='uart_rx_byte', width=8)] or
                owners != [dict(component_id=component_id, port='uart_rx_byte',
                                bit_offset=0, width=8, kind='source',
                                producer_ref=self.source_id)]):
            raise ValueError('UART frame source ownership must match declared '
                             'AXI4-Lite RX source')

    @property
    def pending_events(self):
        return (max(0, self.peer.source_end_tick - self.local_ticks)
                if self.peer.source_start_tick is not None else 0)

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.peer.reset_case()
        self.peer.source = b''
        self._selected_byte = None
        self._observed_samples = 0
        # UART idle is a physical logic one, including before the first write.
        index, _, _ = self._dynamic[self.rx_port]
        self._take(self.command(self.source_operation, (index, 1)))
        self._dynamic_values[self.rx_port] = 1

    def _observe_tx(self) -> None:
        """Feed every not-yet-observed decoded tick to the peer, in order.

        The register member already decodes each tick's own phase samples and
        keeps them in order, so the peer reads the real RTL line from there
        rather than from the raw transport reply.  Progress is tracked by a
        monotonic cursor rather than by a caller-supplied start, because ticks
        are produced by *every* reply - an ordinary register access included -
        and not only by `step_local`.  Observing only inside `step_local` left
        the ticks of a routed CPU access undecoded, which shifts the sampling
        grid and can silently decode a different byte.
        """
        runtime_name, _ = self._outputs[self.tx_port]
        samples = list(self._samples)
        for sample in samples[self._observed_samples:]:
            line = sample['post']['physical'][runtime_name]
            self.peer.observe_tx(sample['local_tick'], line)
        self._observed_samples = len(samples)

    def _take(self, reply, *, step=False):
        """Observe the TX pin of every reply, whatever produced it.

        Observing only when `step` is set was the original defect: a routed CPU
        access issues `write_register`/`read_register` directly, so the ticks of
        its reply were never decoded. That shifts the sampling grid and can
        silently decode a different byte, which is strictly worse than failing.
        """
        observations = super()._take(reply, step=step)
        self._observe_tx()
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
        self._observe_tx()
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
        self._observed_samples = len(self._samples)
        return result
