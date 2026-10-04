"""Generated OpenTitan SPI Host TL-UL session with real register and pad observations."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from myfuzz.scenario.spi_peer import SpiPeer

from .session import GeneratedLocalSession


_ALLOWED_WRITES = frozenset((0x04, 0x10, 0x18, 0x1c, 0x34))
_ALLOWED_READS = frozenset((0x00, 0x04, 0x10, 0x14, 0x18, 0x1c, 0x30, 0x34))


class GeneratedOpentitanSpiHostSession(GeneratedLocalSession):
    artifact_kind = 'tlul_spi_host'

    def __init__(self, artifact, *, base_dir, cache_dir,
                 setup_writes: tuple[tuple[int, int], ...] = (),
                 probe_offsets: tuple[int, ...] = (), **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated OpenTitan SPI Host artifact required')
        if (type(setup_writes) is not tuple or len(setup_writes) > 8
                or any(type(row) is not tuple or len(row) != 2
                       or row[0] not in _ALLOWED_WRITES
                       or type(row[1]) is not int or not 0 <= row[1] <= 0xffffffff
                       for row in setup_writes)):
            raise ValueError('invalid OpenTitan SPI Host setup writes')
        if (type(probe_offsets) is not tuple or len(probe_offsets) > 8
                or any(offset not in _ALLOWED_READS for offset in probe_offsets)):
            raise ValueError('invalid OpenTitan SPI Host probe offsets')
        self.setup_writes = setup_writes
        self.probe_offsets = probe_offsets
        self.peer = SpiPeer()
        self._started = False
        self._samples: deque[dict] = deque()
        self.local_transactions: list[dict[str, int | bool]] = []
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = (1 +
            (len(setup_writes) + len(probe_offsets)) * self.max_local_ticks_per_register_access)
        self._physical = {}
        for role in ('sd_i', 'sck', 'csb', 'sd_o', 'sd_en', 'event', 'error'):
            endpoint = ('spi_host.interrupts' if role in ('event', 'error')
                        else 'spi_host.pins')
            rows = [row for row in artifact.runtime_document['physical_exports']
                    if row['endpoint_id'] == endpoint and row['role'] == role]
            if len(rows) != 1:
                raise ValueError('missing SPI Host physical field: ' + role)
            self._physical[role] = rows[0]['runtime_name']

    def identity_document(self):
        return {**super().identity_document(),
                'tlul_spi_host_service_schema_version': 'generated_tlul_spi_host_registers.v1',
                'source_component': self.artifact.plan.request.instance_id,
                'setup_writes': [list(row) for row in self.setup_writes],
                'probe_offsets': list(self.probe_offsets)}

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.peer.reset_case()
        self._started = False
        self._samples.clear()
        self.local_transactions = []

    @property
    def pending_responses(self):
        return 0

    @property
    def pending_events(self):
        return 0

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated OpenTitan SPI Host process is not running')

    def max_transaction_events_for_step(self, inputs):
        return 0 if self._started else len(self.setup_writes) + len(self.probe_offsets)

    def _take(self, reply, *, step=False):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated OpenTitan SPI Host protocol error: '
                               + str(reply.error_code))
        payload = reply.payload
        samples = payload['samples']
        if (not isinstance(samples, list) or not 1 <= len(samples) <=
                self.max_local_ticks_per_register_access
                or step and len(samples) != 1 or len(self._samples) + len(samples) > 65536):
            raise ValueError('invalid SPI Host local tick evidence')
        for sample in samples:
            outputs = sample['post']['physical']
            sck = outputs[self._physical['sck']]
            csb = outputs[self._physical['csb']]
            sd_o = outputs[self._physical['sd_o']]
            sd_en = outputs[self._physical['sd_en']]
            if (type(sck) is not int or sck not in (0, 1)
                    or type(csb) is not int or csb not in (0, 1)
                    or type(sd_o) is not int or not 0 <= sd_o <= 15
                    or type(sd_en) is not int or not 0 <= sd_en <= 15):
                raise ValueError('invalid OpenTitan SPI Host pad observation')
            self.peer.observe(sck=sck, csb=csb, mosi=(sd_o & 1) if sd_en & 1 else 0)
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        if type(payload['rdata']) is not int or not 0 <= payload['rdata'] <= 0xffffffff:
            raise ValueError('invalid OpenTitan SPI Host read response')
        if type(payload['error']) is not int or payload['error'] not in (0, 1):
            raise ValueError('invalid OpenTitan SPI Host TL-UL error response')
        return payload

    def drain_tick_samples(self):
        samples = list(self._samples)
        self._samples.clear()
        return samples

    def _access(self, write, offset, value=0, be=15):
        if (type(offset) is not int or offset not in
                (_ALLOWED_WRITES if write else _ALLOWED_READS)
                or type(value) is not int or not 0 <= value <= 0xffffffff
                or type(be) is not int or not 0 <= be <= 15):
            raise ValueError('unsupported OpenTitan SPI Host register access')
        reply = self.command('ACCESS_TLUL_SPI_HOST',
                             (self.peer.sd_i, int(write), offset, value, be))
        payload = self._take(reply)
        if payload['error']:
            raise RuntimeError('OpenTitan SPI Host TL-UL response error')
        return payload['rdata']

    def write_register(self, offset, value, *, be=15):
        self._access(True, offset, value, be)

    def read_register(self, offset):
        return self._access(False, offset)

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('undeclared generated OpenTitan SPI Host source input')
        observations = {}
        if not self._started:
            self._started = True
            for offset, value in self.setup_writes:
                self.write_register(offset, value)
                self.local_transactions.append({'offset': offset, 'write': True,
                                                'write_value': value, 'byte_enable': 15})
            for offset in self.probe_offsets:
                read_value = self.read_register(offset)
                self.local_transactions.append({'offset': offset, 'write': False,
                                                'read_value': read_value})
                observations[f'reg_{offset:02x}'] = read_value
        payload = self._take(self.command('STEP_TLUL_SPI_HOST', (self.peer.sd_i,)), step=True)
        return {**payload['observations'], **observations,
                'spi_peer_samples': self.peer.sample_count}

    def reset_local(self):
        result = super().reset_local()
        self.peer.reset_case()
        self._started = False
        self._samples.clear()
        return result
