"""Persistent generated ZipCPU ziptimer over its real addressless Wishbone pins."""
from __future__ import annotations

from collections import deque
from typing import Mapping

from .session import GeneratedLocalSession
from .wire import DriverReceipt


_WORD = 0xffffffff
_MAX_PENDING_SAMPLES = 65_536


class GeneratedZipTimerSession(GeneratedLocalSession):
    """Expose a one-word timer register and its native one-clock IRQ pulse."""

    artifact_kind = 'wishbone_timer'
    max_local_ticks_per_step = 37

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated ZipCPU timer requires wishbone_timer artifact')
        wait = artifact.runtime_document.get('effective_max_wait_cycles')
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid timer Wishbone wait bound')
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = 2 * wait + 6
        self._samples: deque[dict[str, object]] = deque()
        self._load_seen: int | None = None
        self._await_irq = False

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        return int(self._await_irq)

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._load_seen = None
        self._await_irq = False
        self._samples.clear()

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated ZipCPU timer process is not running')

    def _take(self, reply: DriverReceipt) -> dict[str, int]:
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated ZipCPU timer protocol error: ' + str(reply.error_code))
        payload = reply.payload
        observed = payload['observations']
        if (not isinstance(observed, dict) or type(observed.get('interrupt')) is not int
                or observed['interrupt'] not in (0, 1)):
            raise ValueError('invalid generated ZipCPU timer IRQ observation')
        error = payload['error']
        rdata = payload['rdata']
        if type(error) is not int or error not in (0, 1) or type(rdata) is not int or not 0 <= rdata <= _WORD:
            raise ValueError('invalid generated ZipCPU timer response')
        samples = payload['samples']
        if len(self._samples) + len(samples) > _MAX_PENDING_SAMPLES:
            raise RuntimeError('generated timer tick evidence capacity exceeded')
        for sample in samples:
            self._samples.append({**sample, 'local_tick': self._tick_base + sample['local_tick']})
            if sample['pre']['interrupt'] or sample['post']['interrupt']:
                self._await_irq = False
        if observed['interrupt']:
            self._await_irq = False
        return {'interrupt': observed['interrupt'], 'irq': observed['interrupt'],
                'rdata': rdata, 'error': error}

    def drain_tick_samples(self) -> list[dict[str, object]]:
        result = list(self._samples)
        self._samples.clear()
        return result

    def write_register(self, value: int, *, offset: int = 0, be: int = 15) -> None:
        if type(offset) is not int or offset != 0:
            raise ValueError('timer has exactly one addressless register')
        if type(value) is not int or not 0 <= value <= _WORD:
            raise ValueError('invalid timer count')
        if type(be) is not int or not 0 <= be <= 15:
            raise ValueError('invalid timer byte enable')
        self._await_irq = value != 0 and value < (1 << 31)
        result = self._take(self.command('ACCESS_WB_TIMER', (1, offset, value, be)))
        if result['error']:
            raise RuntimeError('generated timer Wishbone write error')

    def read_register(self, offset: int = 0) -> int:
        if type(offset) is not int or offset != 0:
            raise ValueError('timer has exactly one addressless register')
        result = self._take(self.command('ACCESS_WB_TIMER', (0, offset, 0, 15)))
        if result['error']:
            raise RuntimeError('generated timer Wishbone read error')
        return result['rdata']

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if not isinstance(inputs, Mapping) or set(inputs) - {'load_count'}:
            raise ValueError('undeclared generated timer input')
        if 'load_count' in inputs:
            value = inputs['load_count']
            if type(value) is not int or not 0 <= value < (1 << 31):
                raise ValueError('invalid one-shot timer load')
            if value != self._load_seen:
                self.write_register(value)
                self._load_seen = value
        return self._take(self.command('STEP_WB_TIMER', ()))

    def reset_local(self) -> dict[str, int]:
        result = super().reset_local()
        self._load_seen = None
        self._await_irq = False
        self._samples.clear()
        return result
