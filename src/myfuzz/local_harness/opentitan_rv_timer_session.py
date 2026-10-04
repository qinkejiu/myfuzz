"""Persistent generated OpenTitan RV Timer TL-UL process."""
from __future__ import annotations

from collections import deque
from typing import Mapping

from .session import GeneratedLocalSession
from .wire import DriverReceipt


_WORD = (1 << 32) - 1
_MAX_PENDING_SAMPLES = 65_536


def _uint(value: object, name: str, width: int) -> int:
    if type(value) is not int or not 0 <= value < 1 << width:
        raise ValueError('invalid RTL RV Timer observation: ' + name)
    return value


class GeneratedOpentitanRvTimerSession(GeneratedLocalSession):
    """One real timer instance persists for the full testcase."""

    artifact_kind = 'tlul_timer'
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir,
                 startup_writes: tuple[tuple[int, int], ...] = (), **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != 'tlul_timer':
            raise ValueError('generated OpenTitan RV Timer requires tlul_timer artifact')
        wait = artifact.runtime_document.get('effective_max_wait_cycles')
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid TL-UL wait bound')
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self._samples: deque[dict[str, object]] = deque()
        if (type(startup_writes) is not tuple or len(startup_writes) > 16
                or any(type(row) is not tuple or len(row) != 2
                       or type(row[0]) is not int or row[0] < 0 or row[0] > 4092
                       or row[0] % 4 or type(row[1]) is not int or not 0 <= row[1] <= _WORD
                       for row in startup_writes)):
            raise ValueError('invalid TL-UL RV Timer startup writes')
        self.startup_writes = startup_writes
        exports = artifact.runtime_document['physical_exports']
        self._observed = {}
        for port, width in [('alert_tx_o', 2), ('racl_error_o', 37)]:
            rows = [row for row in exports if row['physical_port'] == port and
                    row['width'] == width and row['direction'] == 'output' and
                    row['disposition'] == 'observe']
            if len(rows) != 1:
                raise ValueError('missing OpenTitan RV Timer observation: ' + port)
            self._observed[port] = (rows[0]['runtime_name'], width)

    def identity_document(self) -> dict[str, object]:
        identity = super().identity_document()
        identity.update(tlul_timer_service_schema_version='generated_tlul_timer_service.v1',
                        source_component=self.artifact.plan.request.instance_id,
                        startup_writes=[list(row) for row in self.startup_writes])
        return identity

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        for offset, value in self.startup_writes:
            self.write_register(offset, value)

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        return 0

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated OpenTitan RV Timer process is not running')

    def _take(self, reply: DriverReceipt) -> dict[str, int]:
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated OpenTitan RV Timer protocol error: ' + str(reply.error_code))
        payload = reply.payload
        observed = payload['observations']
        if not isinstance(observed, dict):
            raise ValueError('invalid generated RV Timer observations')
        irq = _uint(observed.get('irq'), 'irq', 1)
        physical = observed.get('physical')
        if not isinstance(physical, dict):
            raise ValueError('invalid generated RV Timer physical observations')
        values = {'irq': irq, 'interrupt': irq,
                  'rdata': _uint(payload['rdata'], 'rdata', 32),
                  'error': _uint(payload['error'], 'error', 1)}
        for port, (name, width) in self._observed.items():
            values[port] = _uint(physical.get(name), port, width)
        samples = payload['samples']
        if len(self._samples) + len(samples) > _MAX_PENDING_SAMPLES:
            raise RuntimeError('generated RV Timer tick evidence capacity exceeded')
        for sample in samples:
            self._samples.append({**sample, 'local_tick': self._tick_base + sample['local_tick']})
        return values

    def drain_tick_samples(self) -> list[dict[str, object]]:
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('undeclared generated OpenTitan RV Timer input')
        return self._take(self.command('STEP_TLUL_TIMER', ()))

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or not 0 <= offset <= 4092 or offset % 4:
            raise ValueError('invalid OpenTitan RV Timer register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        _uint(value, 'write value', 32)
        _uint(be, 'byte enable', 4)
        result = self._take(self.command('ACCESS_TLUL_TIMER', (1, offset, value, be)))
        if result['error']:
            raise RuntimeError(f'generated OpenTitan RV Timer TL-UL write error at {offset:#x}')

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        result = self._take(self.command('ACCESS_TLUL_TIMER', (0, offset, 0, 15)))
        if result['error']:
            raise RuntimeError(f'generated OpenTitan RV Timer TL-UL read error at {offset:#x}')
        return result['rdata']

    def reset_local(self) -> dict[str, int]:
        result = super().reset_local()
        self._samples.clear()
        return result
