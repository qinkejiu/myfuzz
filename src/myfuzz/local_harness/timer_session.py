"""Generated pinned PULP APB timer with native IRQ pin receipts."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from .session import GeneratedLocalSession


class GeneratedPulpTimerSession(GeneratedLocalSession):
    """One two-channel timer RTL process per testcase/reset epoch."""

    artifact_kind = 'apb_timer'
    max_local_ticks_per_step = 1
    max_final_state_growth_bytes_per_operation = 32768

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != 'apb_timer':
            raise ValueError('generated timer session requires apb_timer artifact')
        wait = artifact.runtime_document['effective_max_wait_cycles']
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid APB wait bound')
        self.max_local_ticks_per_register_access = 2 * wait + 5
        reservation = artifact.runtime_document['driver_limits']['reply_reservation_bytes']
        if type(reservation) is not int or not 0 < reservation <= 2 * 1024 * 1024 + 512:
            raise ValueError('invalid generated timer reply reservation')
        self.max_evidence_record_bytes = 4 * reservation + 32768
        self._samples: deque[dict[str, object]] = deque()
        self._irq_levels = 0
        self.irq_edges: list[dict[str, int | str]] = []

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._samples.clear()
        self._irq_levels = 0
        self.irq_edges.clear()

    def _take(self, reply):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated timer protocol error: ' + str(reply.error_code))
        payload = reply.payload
        if len(self._samples) + len(payload['samples']) > 65536:
            raise RuntimeError('generated timer tick evidence capacity exceeded')
        for sample in payload['samples']:
            for phase in ('pre', 'post'):
                value = sample[phase].get('irq_o')
                if type(value) is not int or not 0 <= value < 16:
                    raise ValueError('invalid native timer IRQ observation')
                for bit in range(4):
                    if (value ^ self._irq_levels) & (1 << bit):
                        self.irq_edges.append({'local_tick': self._tick_base + sample['local_tick'],
                                               'phase': phase, 'bit': bit,
                                               'level': (value >> bit) & 1})
                self._irq_levels = value
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        observed = payload['observations']
        if type(observed.get('irq_o')) is not int or not 0 <= observed['irq_o'] < 16:
            raise ValueError('invalid native timer IRQ observation')
        return payload

    def drain_tick_samples(self):
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('PULP timer has no external input')
        return {'irq_o': self._take(self.command('STEP_TIMER', (0,)))['observations']['irq_o']}

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or offset < 0 or offset > 4092 or offset % 4:
            raise ValueError('invalid generated timer register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid timer write value')
        if type(be) is not int or be != 15:
            raise ValueError('PULP timer APB3 requires a full-word write')
        payload = self._take(self.command('ACCESS_TIMER', (1, offset, value, be)))
        if payload['error']:
            raise RuntimeError(f'generated timer APB write error at {offset:#x}')

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        payload = self._take(self.command('ACCESS_TIMER', (0, offset, 0, 15)))
        if payload['error']:
            raise RuntimeError(f'generated timer APB read error at {offset:#x}')
        return payload['rdata']

    def reset_local(self):
        result = super().reset_local()
        self._samples.clear()
        self._irq_levels = 0
        self.irq_edges.clear()
        return result
