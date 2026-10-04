"""Generated Wishbone UART target with a measured 8N1 serial peer."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from myfuzz.scenario.uart_peer import Uart8N1Peer

from .session import GeneratedLocalSession


class GeneratedWishboneUartSession(GeneratedLocalSession):
    artifact_kind = 'wishbone_uart'

    def __init__(self, artifact, *, base_dir, cache_dir,
                 source: bytes | None = b'', startup_writes: tuple[tuple[int, int, int], ...] = (),
                 read_rx_after_source: bool = False, cpu_routed_mode: bool = False,
                 **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated Wishbone UART artifact required')
        if source is not None and (not isinstance(source, bytes) or len(source) > 1):
            raise ValueError('UART peer supports at most one source byte')
        if (type(startup_writes) is not tuple or len(startup_writes) > 4
                or any(type(row) is not tuple or len(row) != 3
                       or row not in ((0, 25, 15),)
                       and not (type(row[0]) is int and row[0] == 12
                                and type(row[1]) is int and 0 <= row[1] <= 255
                                and type(row[2]) is int and row[2] == 1)
                       for row in startup_writes)):
            raise ValueError('invalid Wishbone UART startup writes')
        if (type(read_rx_after_source) is not bool
                or read_rx_after_source and source == b''):
            raise ValueError('UART RX read requires a serial source')
        if (type(cpu_routed_mode) is not bool
                or cpu_routed_mode and (source is not None or startup_writes
                                        or read_rx_after_source)):
            raise ValueError('CPU-routed UART requires genome RX and CPU MMIO setup')
        self.source = source
        self.source_mode = 'genome' if source is None else 'constructor'
        self.startup_writes = startup_writes
        self.read_rx_after_source = read_rx_after_source
        self.cpu_routed_mode = cpu_routed_mode
        self.peer = Uart8N1Peer(source or b'')
        self._started = False
        self._rx_read = False
        self._rx_word = 0
        self._samples: deque[dict] = deque()
        self.local_transactions: list[dict[str, int]] = []
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = (1 + (len(startup_writes)
            + int(read_rx_after_source)) * self.max_local_ticks_per_register_access)

    def identity_document(self):
        return {**super().identity_document(),
                'wb_uart_service_schema_version': ('generated_wb_uart_8n1.v3'
                    if self.cpu_routed_mode else 'generated_wb_uart_8n1.v2'
                    if self.source_mode == 'genome' else 'generated_wb_uart_8n1.v1'),
                'source_component': self.artifact.plan.request.instance_id,
                'source_hex': (self.source or b'').hex(),
                **({'cpu_routed_mode': True} if self.cpu_routed_mode else {}),
                **({'source_mode': 'genome'} if self.source_mode == 'genome' else {}),
                'startup_writes': [list(row) for row in self.startup_writes],
                'read_rx_after_source': self.read_rx_after_source}

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.peer.reset_case()
        if self.source_mode == 'genome':
            self.peer.source = b''
        self._started = False
        self._rx_read = False
        self._rx_word = 0
        self._samples.clear()
        self.local_transactions.clear()

    def max_transaction_events_for_step(self, inputs: Mapping[str, int]) -> int:
        if not self._started:
            return len(self.startup_writes)
        return int(self.read_rx_after_source and not self._rx_read
                   and self.local_ticks + 1 >= self.peer.source_end_tick + 50)

    @property
    def pending_responses(self):
        return 0

    @property
    def pending_events(self):
        if not self._started:
            return len(self.startup_writes) + (1 if self.source_mode == 'genome'
                                               else len(self.source))
        return (max(0, self.peer.source_end_tick - self.local_ticks)
                + int((self.read_rx_after_source or self.cpu_routed_mode)
                      and not self._rx_read))

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated Wishbone UART process is not running')

    def _take(self, reply, *, operation):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated Wishbone UART protocol error: '
                               + str(reply.error_code))
        payload = reply.payload
        samples = payload.get('samples')
        if (not isinstance(samples, list) or not 1 <= len(samples) <=
                self.max_local_ticks_per_register_access
                or len(self._samples) + len(samples) > 65536):
            raise ValueError('invalid UART driver tick evidence')
        if operation == 'STEP_WB_UART' and len(samples) != 1:
            raise ValueError('UART step did not advance one tick')
        for sample in samples:
            post = sample['post']
            line = post['uart_tx']
            if type(line) is not int or line not in (0, 1):
                raise ValueError('invalid physical UART TX pin')
            self.peer.observe_tx(sample['local_tick'], line)
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        if operation == 'ACCESS_WB_UART':
            if type(payload['rdata']) is not int or not 0 <= payload['rdata'] <= 0xffffffff:
                raise ValueError('invalid Wishbone UART read data')
            if type(payload['error']) is not int or not 0 <= payload['error'] <= 1:
                raise ValueError('invalid Wishbone UART response')
        return payload

    def drain_tick_samples(self):
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping):
            raise ValueError('UART inputs must be a mapping')
        if self.source_mode == 'genome':
            if (set(inputs) != {'uart_rx_byte'}
                    or type(inputs['uart_rx_byte']) is not int
                    or not 0 <= inputs['uart_rx_byte'] <= 255):
                raise ValueError('UART genome source needs one byte')
            byte = inputs['uart_rx_byte']
            if not self._started:
                self.peer.source = bytes((byte,))
            elif self.peer.source != bytes((byte,)):
                raise ValueError('UART source cannot change after serial frame starts')
        elif inputs:
            raise ValueError('UART peer source is selected at case start')
        if not self._started:
            self._started = True
            for offset, value, be in self.startup_writes:
                self.write_register(offset, value, be=be)
                self.local_transactions.append({'offset': offset, 'write_value': value,
                                                'byte_enable': be})
            # rxuart requires an idle mark for its 16-bit-cell synchronization
            # counter before accepting the first start bit after reset.
            self.peer.start_source(self.local_ticks + 17 * self.peer.clocks_per_bit + 1)
        rx = self.peer.drive_rx(self.local_ticks + 1)
        payload = self._take(self.command('STEP_WB_UART', (rx, 0)),
                             operation='STEP_WB_UART')
        if (self.read_rx_after_source and not self._rx_read
                and self.local_ticks >= self.peer.source_end_tick + 50):
            self._rx_word = self.read_register(8)
            self._rx_read = True
            self.local_transactions.append({'offset': 8, 'read_value': self._rx_word,
                                            'byte_enable': 15})
        return {name: value for name, value in payload['observations'].items()
                if name not in ('backend', 'physical')} | {
            'serial_tx_count': len(self.peer.captured),
            'serial_tx_last': self.peer.captured[-1] if self.peer.captured else 0,
            'serial_rx_read': int(self._rx_read), 'serial_rx_word': self._rx_word}

    @staticmethod
    def _offset(offset):
        if type(offset) is not int or offset not in (0, 4, 8, 12):
            raise ValueError('invalid Wishbone UART register offset')

    def _access(self, write, offset, value, be):
        self._offset(offset)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid Wishbone UART register value')
        if type(be) is not int or not 0 <= be <= 15:
            raise ValueError('invalid Wishbone UART byte strobe')
        if (self.peer.source_start_tick is not None and self.peer.source
                and self.local_ticks < self.peer.source_end_tick
                and self.local_ticks + self.max_local_ticks_per_register_access
                >= self.peer.source_start_tick):
            raise RuntimeError('Wishbone access during serial source waveform is unsupported')
        payload = self._take(self.command('ACCESS_WB_UART',
            (1, 0, int(write), offset, value, be)), operation='ACCESS_WB_UART')
        pre = [sample['pre']['backend'] for sample in payload['samples']]
        if sum(bool(row['uart_target_stb']) for row in pre) != 1:
            raise RuntimeError('Wishbone UART target received duplicate or missing strobe')
        if payload['error']:
            raise RuntimeError('Wishbone UART slave response error')
        return payload['rdata']

    def write_register(self, offset: int, value: int, *, be: int = 15):
        if not ((offset, value, be) == (0, 25, 15)
                or offset == 12 and type(value) is int and 0 <= value <= 255
                and type(be) is int and be == 1):
            raise ValueError('unsupported UART setup, break, or register write')
        self._access(True, offset, value, be)

    def read_register(self, offset: int) -> int:
        value = self._access(False, offset, 0, 15)
        if self.cpu_routed_mode and offset == 8:
            self._rx_word = value
            self._rx_read = True
        return value

    def reset_local(self):
        result = super().reset_local()
        self.peer.reset_case()
        if self.source_mode == 'genome':
            self.peer.source = b''
        self._started = False
        self._rx_read = False
        self._rx_word = 0
        self._samples.clear()
        return result
