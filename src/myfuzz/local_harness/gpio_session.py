"""PULP GPIO's native APB3 and external pins over a generated local driver."""
from __future__ import annotations

from collections import deque
from typing import Mapping

from .session import GeneratedLocalSession
from .wire import DriverReceipt


_WORD = (1 << 32) - 1
_MAX_PENDING_SAMPLES = 65_536
_GPIO_FIELDS = ('gpio_out', 'gpio_dir', 'gpio_in_sync', 'interrupt')


def _word(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _WORD:
        raise ValueError('invalid RTL GPIO observation: ' + name)
    return value


class GeneratedPulpGpioSession(GeneratedLocalSession):
    """One actual PULP apb_gpio process, reset only on testcase/reset policy."""

    artifact_kind = 'apb_gpio'
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != 'apb_gpio':
            raise ValueError('generated GPIO session requires apb_gpio artifact')
        wait = artifact.runtime_document.get('effective_max_wait_cycles')
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid APB wait bound')
        # Match the generator's conservative per-command sample reservation.
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self._gpio_in = 0
        self._pin_settle_until = 0
        self._samples: deque[dict[str, object]] = deque()

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        # This only schedules remaining synchronizer clocks; it predicts no IRQ.
        return max(0, self._pin_settle_until - self.local_ticks)

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated GPIO process is not running')

    def _take(self, reply: DriverReceipt) -> dict[str, int]:
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated GPIO protocol error: ' + str(reply.error_code))
        payload = reply.payload
        observed = payload['observations']
        if not isinstance(observed, dict):
            raise ValueError('invalid generated GPIO observations')
        values = {name: _word(observed.get(name), name) for name in _GPIO_FIELDS}
        padcfg = observed.get('gpio_padcfg')
        if (type(padcfg) is not str or len(padcfg) != 32
                or any(character not in '0123456789abcdef' for character in padcfg)):
            raise ValueError('invalid RTL GPIO padcfg observation')
        values['gpio_padcfg'] = int(padcfg, 16)
        values['irq'] = values['interrupt']
        values['rdata'] = _word(payload['rdata'], 'rdata')
        values['error'] = payload['error']
        samples = payload['samples']
        if len(self._samples) + len(samples) > _MAX_PENDING_SAMPLES:
            raise RuntimeError('generated GPIO tick evidence capacity exceeded')
        for sample in samples:
            # The wire tick is process-local; public sample ticks are lifetime
            # local ticks, including explicit component reset epochs.
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        return values

    def drain_tick_samples(self) -> list[dict[str, object]]:
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if not isinstance(inputs, Mapping) or set(inputs) - {'gpio_in'}:
            raise ValueError('undeclared generated GPIO input')
        value = inputs.get('gpio_in', self._gpio_in)
        _word(value, 'gpio_in')
        if value != self._gpio_in:
            self._pin_settle_until = self.local_ticks + 4
        self._gpio_in = value
        return self._take(self.command('STEP_GPIO', (value,)))

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or not 0 <= offset <= 4092 or offset % 4:
            raise ValueError('invalid generated GPIO register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        _word(value, 'write value')
        if be != 15 or type(be) is not int:
            raise ValueError('PULP GPIO APB3 requires a full-word write')
        result = self._take(self.command('ACCESS_GPIO',
                                         (self._gpio_in, 1, offset, value, be)))
        if result['error']:
            raise RuntimeError(f'generated GPIO APB write error at {offset:#x}')

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        result = self._take(self.command('ACCESS_GPIO',
                                         (self._gpio_in, 0, offset, 0, 15)))
        if result['error']:
            raise RuntimeError(f'generated GPIO APB read error at {offset:#x}')
        return result['rdata']

    def reset_local(self) -> dict[str, int]:
        result = super().reset_local()
        self._samples.clear()
        self._gpio_in = 0
        self._pin_settle_until = self.local_ticks
        return result
