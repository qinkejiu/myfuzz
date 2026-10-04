"""Persistent generated OpenTitan TL-UL I2C with one open-drain target byte."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from .session import GeneratedLocalSession


class GeneratedOpentitanI2cSession(GeneratedLocalSession):
    """The real controller runs every local tick; the peer owns resolved pads."""

    artifact_kind = 'tlul_i2c'
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated OpenTitan I2C requires tlul_i2c artifact')
        wait = artifact.runtime_document['effective_max_wait_cycles']
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid TL-UL I2C wait bound')
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self._samples: deque[dict[str, object]] = deque()
        self._peer_response: int | None = None
        self._irq_level = 0
        self._transfer_pending = False

    def identity_document(self):
        identity = super().identity_document()
        identity.update(tlul_i2c_service_schema_version='generated_tlul_i2c_service.v1',
                        source_component=self.artifact.plan.request.instance_id,
                        peer_mode='single_slave_0x50_one_byte_no_stretch')
        return identity

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._samples.clear()
        self._peer_response = None
        self._irq_level = 0
        self._transfer_pending = False

    @property
    def pending_events(self) -> int:
        return int(self._transfer_pending)

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated OpenTitan I2C process is not running')

    def _take(self, reply):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated OpenTitan I2C protocol error: ' + str(reply.error_code))
        payload = reply.payload
        samples = payload['samples']
        if len(self._samples) + len(samples) > 65536:
            raise RuntimeError('generated OpenTitan I2C tick evidence capacity exceeded')
        for sample in samples:
            for phase in ('pre', 'post'):
                row = sample[phase]
                for name in ('scl_i', 'scl_o', 'scl_en_o', 'sda_i',
                             'sda_o', 'sda_en_o'):
                    if type(row.get(name)) is not int or row[name] not in (0, 1):
                        raise ValueError('invalid native OpenTitan I2C pad: ' + name)
                if row['scl_o'] or row['sda_o']:
                    raise ValueError('OpenTitan I2C pad is not open drain')
                irq = row.get('irq_o')
                if type(irq) is not int or not 0 <= irq < 1 << 15:
                    raise ValueError('invalid native OpenTitan I2C IRQ')
                self._irq_level = irq
                if irq & (1 << 9):
                    self._transfer_pending = False
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        observed = payload['observations']
        if type(observed.get('irq_o')) is not int:
            raise ValueError('invalid generated OpenTitan I2C observation')
        return payload

    def drain_tick_samples(self):
        rows = list(self._samples)
        self._samples.clear()
        return rows

    def configure_peer_response(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError('OpenTitan I2C peer response must be 8-bit')
        if self._peer_response is not None:
            if self._peer_response != value:
                raise ValueError('OpenTitan I2C permits one response byte per testcase')
            return
        self._take(self.command('SOURCE_TLUL_I2C', (value,)))
        self._peer_response = value

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or set(inputs) - {'peer_response'}:
            raise ValueError('OpenTitan I2C resolved pad inputs are bound to the peer')
        if 'peer_response' in inputs:
            self.configure_peer_response(inputs['peer_response'])
        observed = self._take(self.command('STEP_TLUL_I2C', ()))['observations']
        return {name: observed[name] for name in
                ('irq_o', 'scl_i', 'scl_o', 'scl_en_o',
                 'sda_i', 'sda_o', 'sda_en_o')}

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or offset < 0 or offset > 124 or offset % 4:
            raise ValueError('invalid OpenTitan I2C register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        if offset == 0x1c and self._peer_response is None:
            raise ValueError('OpenTitan I2C peer response source required before FDATA')
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid OpenTitan I2C write value')
        if type(be) is not int or not 0 <= be <= 15:
            raise ValueError('invalid OpenTitan I2C byte enable')
        payload = self._take(self.command('ACCESS_TLUL_I2C', (1, offset, value, be)))
        if payload['error']:
            raise RuntimeError(f'OpenTitan I2C TL-UL write error at {offset:#x}')
        if offset == 0x1c:
            self._transfer_pending = True

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        payload = self._take(self.command('ACCESS_TLUL_I2C', (0, offset, 0, 15)))
        if payload['error']:
            raise RuntimeError(f'OpenTitan I2C TL-UL read error at {offset:#x}')
        return payload['rdata']

    def reset_local(self):
        result = super().reset_local()
        self._samples.clear()
        self._peer_response = None
        self._irq_level = 0
        self._transfer_pending = False
        return result
