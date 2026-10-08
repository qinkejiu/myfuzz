"""Bounded pin8 source to observed CPU interrupt input/take certificates."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping

from .gpio_consumption import is_authenticated_gpio_tick
from .pin8_irq_certificates import Pin8IrqCertificates


def _endpoint(event: Mapping) -> bool:
    return (event.get('source') in (['gpio_b', 'irq'], ('gpio_b', 'irq'))
        and event.get('target') in (['cpu', 'irq'], ('cpu', 'irq'))
        and all(type(event.get(key)) is int and event[key] == expected
                for key, expected in (('source_bit_offset', 0),
                                      ('target_bit_offset', 0), ('width', 1))))


def _reference(event: Mapping) -> dict | None:
    ref = event.get('source_trigger')
    if (not isinstance(ref, Mapping) or set(ref) != {
            'trigger_id', 'trigger_event_id', 'observation_event_id',
            'sample_event_id'}
        or type(ref['trigger_id']) is not str or not ref['trigger_id']
        or any(type(ref[key]) is not int or ref[key] < 1 for key in (
            'trigger_event_id', 'observation_event_id', 'sample_event_id'))):
        return None
    return dict(ref)


class Pin8CpuIrqCertificates:
    """Join only exact native, pulse, CPU step and acceptance identities.

    The terminal is CPU interrupt acceptance. ISR execution, MMIO, and final
    GPIO output are outside this certificate.
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096):
        if (type(max_pending) is not int or max_pending < 1 or
                type(max_event_gap) is not int or max_event_gap < 1):
            raise ValueError('certificate bounds must be positive integers')
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self._native = Pin8IrqCertificates(max_pending=max_pending,
                                            max_event_gap=max_event_gap)
        self._last_event_id = 0
        self._last_source_id = 0
        self._raw: OrderedDict[int, Mapping] = OrderedDict()
        self._samples: OrderedDict[int, Mapping] = OrderedDict()
        self._steps: OrderedDict[int, Mapping] = OrderedDict()
        self._certified_native: OrderedDict[str, tuple[int, dict]] = OrderedDict()
        self._sources: OrderedDict[int, dict] = OrderedDict()

    def _limit(self, cache: OrderedDict) -> None:
        while len(cache) > self.max_pending:
            cache.popitem(last=False)

    def _expire(self, event_id: int) -> None:
        for cache in (self._raw, self._samples, self._steps,
                      self._certified_native, self._sources):
            while cache:
                key, value = next(iter(cache.items()))
                born = value[0] if cache is self._certified_native else (
                    value['born'] if cache is self._sources else key)
                if event_id - born <= self.max_event_gap:
                    break
                cache.popitem(last=False)

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        result = []
        for event in events:
            if (not isinstance(event, Mapping) or
                    type(event.get('event_id')) is not int or
                    event['event_id'] != self._last_event_id + 1):
                raise ValueError('certificate journal must be contiguous')
            event_id = event['event_id']
            self._last_event_id = event_id
            self._expire(event_id)
            kind = event.get('kind')
            if kind in ('reset_barrier', 'gpio_reset_resource', 'cpu_reset'):
                self._raw.clear(); self._samples.clear(); self._steps.clear()
                self._certified_native.clear(); self._sources.clear()
            else:
                if kind == 'gpio_tick_observation' and event.get('component') == 'gpio_b':
                    if is_authenticated_gpio_tick(dict(event)):
                        self._raw[event_id] = event
                        self._limit(self._raw)
                elif kind == 'local_tick_sample' and event.get('component') == 'gpio_b':
                    self._samples[event_id] = event
                    self._limit(self._samples)
                elif kind is None and event.get('component') == 'cpu' and 'inputs' in event:
                    self._steps[event_id] = event
                    self._limit(self._steps)
                elif kind == 'source_start':
                    self._source(event)
                elif kind == 'pulse_start':
                    self._pulse(event)
                elif kind == 'cpu_irq_input':
                    self._input(event)
                elif kind == 'cpu_irq_taken':
                    self._taken(event)
                elif kind == 'irq_overrun':
                    for key in ('source_event_id', 'active_source_event_id'):
                        self._sources.pop(event.get(key), None)
                elif kind in ('pulse_cancelled_by_reset', 'pulse_expired',
                              'expired_masked'):
                    self._sources.pop(event.get('source_event_id'), None)
            for native in self._native.ingest((event,)):
                self._certified_native[native['trigger_id']] = (event_id, native)
                self._limit(self._certified_native)
            for source_id, state in tuple(self._sources.items()):
                certificate = self._complete(source_id, state)
                if certificate is not None:
                    result.append(certificate)
                    del self._sources[source_id]
                    self._certified_native.pop(certificate['trigger_id'], None)
        return tuple(result)

    def _source(self, event: Mapping) -> None:
        if not _endpoint(event):
            return
        source_id = event.get('source_event_id')
        if type(source_id) is not int or source_id <= self._last_source_id:
            return
        self._last_source_id = source_id
        ref = _reference(event)
        if ref is None:
            return
        raw = self._raw.get(ref['observation_event_id'])
        sample = self._samples.get(ref['sample_event_id'])
        if (source_id in self._sources or raw is None or sample is None or
                ref['trigger_event_id'] >= event['event_id'] or
                not ref['observation_event_id'] < ref['trigger_event_id'] <
                    ref['sample_event_id'] < event['event_id'] or
                type(event.get('cpu_tick')) is not int or event['cpu_tick'] < 0 or
                raw.get('component') != 'gpio_b' or
                sample.get('component') != 'gpio_b' or
                sample.get('phase') != 'post' or
                sample.get('local_tick') != raw.get('local_tick') or
                event.get('source_tick') != raw.get('local_tick') or
                not isinstance(sample.get('outputs'), Mapping) or
                type(sample['outputs'].get('interrupt')) is not int or
                sample['outputs']['interrupt'] != 1 or
                raw['pre'].get('gpio_probe_native_irq') != 0 or
                raw['post'].get('gpio_probe_native_irq') != 1):
            return
        self._sources[source_id] = {
            'born': event['event_id'], 'ref': ref,
            'source_start_event_id': event['event_id'],
            'source_tick': event['source_tick'],
            'source_cpu_tick': event['cpu_tick'],
            'source_epoch': raw['reset_epoch'],
            'pulse_start_event_id': None,
            'input_event_id': None, 'taken_event_id': None}
        self._limit(self._sources)

    def _pulse(self, event: Mapping) -> None:
        state = self._sources.get(event.get('source_event_id'))
        if state is None:
            return
        start, end = event.get('start_cpu_tick'), event.get('end_cpu_tick_exclusive')
        if (not _endpoint(event) or _reference(event) != state['ref'] or
                state['pulse_start_event_id'] is not None or
                type(start) is not int or type(end) is not int or
                start != state['source_cpu_tick'] + 1 or end != start + 4 or
                event['event_id'] <= state['source_start_event_id']):
            del self._sources[event['source_event_id']]
            return
        state['pulse_start_event_id'] = event['event_id']
        state['pulse_start_tick'] = start
        state['pulse_end_tick'] = end

    def _input(self, event: Mapping) -> None:
        state = self._sources.get(event.get('source_event_id'))
        if state is None:
            return
        step_id = event.get('cpu_step_event_id')
        step = self._steps.get(step_id)
        tick = event.get('cpu_tick')
        if (state['pulse_start_event_id'] is None or
                not _endpoint(event) or _reference(event) != state['ref'] or
                type(event.get('value')) is not int or event['value'] != 1 or
                type(tick) is not int or
                not state['pulse_start_tick'] <= tick < state['pulse_end_tick'] or
                type(step_id) is not int or step is None or
                step.get('local_tick') != tick or
                not isinstance(step.get('inputs'), Mapping) or
                type(step['inputs'].get('irq')) is not int or
                step['inputs']['irq'] != 1 or
                event['event_id'] <= step_id):
            del self._sources[event['source_event_id']]
            return
        state['input_event_id'] = event['event_id']
        state['cpu_step_event_id'] = step_id
        state['cpu_tick'] = tick

    def _taken(self, event: Mapping) -> None:
        state = self._sources.get(event.get('source_event_id'))
        if state is None:
            return
        step = self._steps.get(state.get('cpu_step_event_id'))
        if (state['input_event_id'] is None or
                not _endpoint(event) or _reference(event) != state['ref'] or
                event.get('cpu_tick') != state['cpu_tick'] or
                event.get('cpu_step_event_id') != state['cpu_step_event_id'] or
                step is None or not isinstance(step.get('outputs'), Mapping) or
                type(step['outputs'].get('irq_taken_pre')) is not int or
                step['outputs']['irq_taken_pre'] != 1 or
                event['event_id'] <= state['input_event_id']):
            del self._sources[event['source_event_id']]
            return
        state['taken_event_id'] = event['event_id']

    def _complete(self, source_id: int, state: dict) -> dict | None:
        if state['taken_event_id'] is None:
            return None
        entry = self._certified_native.get(state['ref']['trigger_id'])
        if entry is None:
            return None
        native = entry[1]
        if (native['trigger_event_id'] != state['ref']['trigger_event_id'] or
                native['trigger_tick_event_id'] != state['ref']['observation_event_id'] or
                native['reset_epoch'] != state['source_epoch'] or
                native['trigger_event_id'] >= state['source_start_event_id']):
            return None
        return dict(schema_version='pin8_cpu_irq_certificate.v1',
                    scope='pin8_admission_to_cpu_irq_taken',
                    proof_scope='authenticated_native_irq_pulse_and_cpu_step',
                    admission_id=native['admission_id'],
                    action_id=native['action_id'],
                    source_case=native['source_case'],
                    consumer_case=native['consumer_case'],
                    trigger_id=native['trigger_id'],
                    trigger_event_id=native['trigger_event_id'],
                    trigger_tick_event_id=native['trigger_tick_event_id'],
                    native_observation_event_id=native['observation_event_id'],
                    source_start_event_id=state['source_start_event_id'],
                    pulse_start_event_id=state['pulse_start_event_id'],
                    cpu_irq_input_event_id=state['input_event_id'],
                    cpu_step_event_id=state['cpu_step_event_id'],
                    cpu_irq_taken_event_id=state['taken_event_id'],
                    source_event_id=source_id)
