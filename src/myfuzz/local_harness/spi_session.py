"""Generated PULP APB SPI with an actual edge driven mode 0 peer."""
from __future__ import annotations

from collections import deque

from myfuzz.scenario.pulp_spi_peer import PulpSpiMode0Peer

from .session import GeneratedLocalSession


class GeneratedPulpSpiSession(GeneratedLocalSession):
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir, source: bytes,
                 chip_select: int = 0, startup_writes: tuple[tuple[int, int], ...] = (),
                 read_rx_on_eot: bool = False, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != 'apb_spi':
            raise ValueError('generated SPI session requires apb_spi artifact')
        if not isinstance(source, bytes) or len(source) > 512:
            raise ValueError('SPI source must be at most 512 literal bytes')
        self.source = source
        self.peer = PulpSpiMode0Peer(source, chip_select=chip_select)
        self.chip_select = chip_select
        if (type(startup_writes) is not tuple or len(startup_writes) > 16
                or any(type(row) is not tuple or len(row) != 2
                       or type(row[0]) is not int or type(row[1]) is not int
                       or row[0] < 0 or row[0] > 4092 or row[0] % 4
                       or row[1] < 0 or row[1] > 0xffffffff for row in startup_writes)
                or type(read_rx_on_eot) is not bool):
            raise ValueError('invalid declarative SPI startup plan')
        self.startup_writes = startup_writes
        self.read_rx_on_eot = read_rx_on_eot
        self._started = False
        self._rx_word = 0
        self._rx_read = False
        self._samples: deque[dict[str, object]] = deque()
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        # The first scenario step performs the declarative APB startup plan;
        # one later step may read RXFIFO after an observed EOT. Reserve both
        # cases before budgeted execution begins.
        self.max_local_ticks_per_step = (1 +
            (len(startup_writes) + int(read_rx_on_eot)) *
            self.max_local_ticks_per_register_access)

    def identity_document(self):
        return {**super().identity_document(),
                'spi_peer_schema_version': 'pulp_spi_mode0_source.v1',
                'source_component': self.artifact.plan.request.instance_id,
                'chip_select': self.chip_select, 'source_hex': self.source.hex(),
                'startup_writes': [list(row) for row in self.startup_writes],
                'read_rx_on_eot': self.read_rx_on_eot}

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self.peer.reset_case(self.source)
        self._samples.clear()
        self._started = False
        self._rx_word = 0
        self._rx_read = False
        for start in range(0, len(self.source), 4):
            chunk = self.source[start:start + 4]
            value = int.from_bytes(chunk, 'big')
            self._take(self.command('SOURCE_SPI', (self.chip_select, value, 8 * len(chunk))))

    def _take(self, reply):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated SPI protocol error: ' + str(reply.error_code))
        payload = reply.payload
        if len(self._samples) + len(payload['samples']) > 65536:
            raise RuntimeError('generated SPI tick evidence capacity exceeded')
        for sample in payload['samples']:
            for phase in ('pre', 'post'):
                state = sample[phase]
                pins = {name: state[name] for name in
                        ('spi_clk', 'spi_csn0', 'spi_csn1', 'spi_csn2', 'spi_csn3',
                         'spi_mode', 'spi_sdo0', 'events_o')}
                self.peer.observe(pins, local_tick=sample['local_tick'], phase=phase)
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        return payload

    def drain_tick_samples(self):
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs):
        if not isinstance(inputs, dict) or inputs:
            raise ValueError('SPI peer source is selected at case start')
        if not self._started:
            self._started = True
            for offset, value in self.startup_writes:
                self.write_register(offset, value)
        observed = self._take(self.command('STEP_SPI', (0,)))['observations']
        if (self.read_rx_on_eot and not self._rx_read
                and any(e['bit'] == 1 and e['level'] == 1 for e in self.peer.events)):
            self._rx_word = self.read_register(0x20)
            self._rx_read = True
        return {name: value for name, value in observed.items()
                if name not in ('backend', 'physical')} | {
                    'spi_sample_count': self.peer.sample_count,
                    'spi_rx_word': self._rx_word, 'spi_rx_read': int(self._rx_read)}

    @staticmethod
    def _offset(offset):
        if type(offset) is not int or offset < 0 or offset > 4092 or offset % 4:
            raise ValueError('invalid generated SPI register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid SPI write value')
        if type(be) is not int or be != 15:
            raise ValueError('PULP SPI APB3 requires a full-word write')
        result = self._take(self.command('ACCESS_SPI', (1, offset, value, be)))
        if result['error']:
            raise RuntimeError(f'generated SPI APB write error at {offset:#x}')

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        result = self._take(self.command('ACCESS_SPI', (0, offset, 0, 15)))
        if result['error']:
            raise RuntimeError(f'generated SPI APB read error at {offset:#x}')
        return result['rdata']

    def reset_local(self):
        result = super().reset_local()
        self.peer.reset_case(self.source)
        self._samples.clear()
        self._started = False
        self._rx_word = 0
        self._rx_read = False
        return result
