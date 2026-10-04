"""Generated pinned PULP APB I2C master and one electrical slave peer."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from .session import GeneratedLocalSession


class GeneratedPulpI2cSession(GeneratedLocalSession):
    """A 0x42 slave ACKs writes and supplies one testcase-owned read byte."""

    artifact_kind = 'apb_i2c'
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != 'apb_i2c':
            raise ValueError('generated I2C session requires apb_i2c artifact')
        wait = artifact.runtime_document['effective_max_wait_cycles']
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid APB wait bound')
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self._samples: deque[dict[str, object]] = deque()
        self.irq_edges: list[dict[str, int | str]] = []
        self._irq_level = 0
        self._write_stage = 0
        self._peer_response: int | None = None

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._samples.clear()
        self.irq_edges.clear()
        self._irq_level = 0
        self._write_stage = 0
        self._peer_response = None

    @property
    def pending_events(self) -> int:
        return int(self._write_stage in (4, 6) and self._irq_level == 0)

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated PULP I2C process is not running')

    def _take(self, reply):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated I2C protocol error: ' + str(reply.error_code))
        payload = reply.payload
        samples = payload['samples']
        if len(self._samples) + len(samples) > 65536:
            raise RuntimeError('generated I2C tick evidence capacity exceeded')
        for sample in samples:
            for phase in ('pre', 'post'):
                snapshot = sample[phase]
                for name in ('interrupt_o', 'scl_pad_i', 'scl_pad_o',
                             'scl_padoen_o', 'sda_pad_i', 'sda_pad_o', 'sda_padoen_o'):
                    if type(snapshot.get(name)) is not int or snapshot[name] not in (0, 1):
                        raise ValueError('invalid native I2C pin observation: ' + name)
                irq = snapshot['interrupt_o']
                if irq != self._irq_level:
                    self.irq_edges.append({'local_tick': self._tick_base + sample['local_tick'],
                                           'phase': phase, 'level': irq})
                self._irq_level = irq
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        if type(payload['observations'].get('interrupt_o')) is not int:
            raise ValueError('invalid native I2C IRQ observation')
        return payload

    def drain_tick_samples(self):
        result = list(self._samples)
        self._samples.clear()
        return result

    def configure_peer_response(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError('PULP I2C response byte must be 8-bit')
        if self._peer_response is not None:
            if self._peer_response != value:
                raise ValueError('PULP I2C permits a single response byte per testcase')
            return
        self._take(self.command('SOURCE_I2C', (value,)))
        self._peer_response = value

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or set(inputs) - {'peer_response'}:
            raise ValueError('PULP I2C peer owns both electrical pad inputs')
        if 'peer_response' in inputs:
            self.configure_peer_response(inputs['peer_response'])
        if self._peer_response is None:
            raise ValueError('PULP I2C peer_response source must be selected before step')
        observed = self._take(self.command('STEP_I2C', (0,)))['observations']
        return {key: observed[key] for key in
                ('interrupt_o', 'scl_pad_i', 'scl_padoen_o',
                 'sda_pad_i', 'sda_padoen_o')}

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or offset < 0 or offset > 4092 or offset % 4:
            raise ValueError('invalid generated I2C register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        if self._peer_response is None:
            raise ValueError('PULP I2C peer_response source must be selected before APB transaction')
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid I2C write value')
        if type(be) is not int or be != 15:
            raise ValueError('PULP I2C APB3 requires a full-word write')
        accepted = ((0, lambda number: 2 <= number <= 16),
                    (4, lambda number: number == 0xc0),
                    (16, lambda number: number == 0x85),
                    (20, lambda number: number == 0x90),
                    (20, lambda number: number == 1),
                    (20, lambda number: number == 0x68))
        if (self._write_stage >= len(accepted)
                or offset != accepted[self._write_stage][0]
                or not accepted[self._write_stage][1](value)):
            raise ValueError('unsupported PULP I2C single-byte read mode or command order')
        if self._write_stage == 4 and self._irq_level != 1:
            raise ValueError('PULP I2C address completion IRQ is required before IACK')
        if self._write_stage == 5 and self._irq_level != 0:
            raise ValueError('PULP I2C IACK must clear IRQ before read command')
        payload = self._take(self.command('ACCESS_I2C', (1, offset, value, be)))
        if payload['error']:
            raise RuntimeError(f'generated I2C APB write error at {offset:#x}')
        self._write_stage += 1

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        if self._peer_response is None:
            raise ValueError('PULP I2C peer_response source must be selected before APB transaction')
        payload = self._take(self.command('ACCESS_I2C', (0, offset, 0, 15)))
        if payload['error']:
            raise RuntimeError(f'generated I2C APB read error at {offset:#x}')
        return payload['rdata']

    def reset_local(self):
        result = super().reset_local()
        self._samples.clear()
        self.irq_edges.clear()
        self._irq_level = 0
        self._write_stage = 0
        self._peer_response = None
        return result
