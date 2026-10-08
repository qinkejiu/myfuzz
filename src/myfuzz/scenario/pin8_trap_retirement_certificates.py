"""Bounded, weaker architectural correlation of pin8 IRQ and RVFI trap.

No hardware source token exists on RVFI retirement. A result here must never
be promoted to a source identity certificate or full propagation chain.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping

from .pin8_cpu_irq_certificates import Pin8CpuIrqCertificates


def _uint(value: object) -> bool:
    return type(value) is int and value >= 0


class Pin8TrapRetirementCertificates:
    def __init__(self, *, max_event_gap: int = 1024,
                 require_native_receipts: bool = False):
        if not _uint(max_event_gap) or max_event_gap < 1:
            raise ValueError('max_event_gap must be positive integer')
        if type(require_native_receipts) is not bool:
            raise ValueError('require_native_receipts must be boolean')
        self.max_event_gap = max_event_gap
        self.require_native_receipts = require_native_receipts
        self._cpu = Pin8CpuIrqCertificates()
        self._steps: OrderedDict[int, Mapping] = OrderedDict()
        self._native_samples: OrderedDict[int, Mapping] = OrderedDict()
        self._native_takes: OrderedDict[int, Mapping] = OrderedDict()
        self._pending: dict | None = None

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        result = []
        for event in events:
            # The exact upstream certificate validates contiguity and source
            # identity independently of this weaker architectural bridge.
            upstream = self._cpu.ingest((event,))
            event_id = event['event_id']
            while self._steps and event_id - next(iter(self._steps)) > self.max_event_gap:
                self._steps.popitem(last=False)
            for cache in (self._native_samples, self._native_takes):
                while cache and event_id - next(iter(cache.values()))['event_id'] > self.max_event_gap:
                    cache.popitem(last=False)
            if self._pending and event_id - self._pending['born'] > self.max_event_gap:
                self._pending = None
            kind = event.get('kind')
            if kind is None and event.get('component') == 'cpu' and 'outputs' in event:
                self._steps[event_id] = event
                if self._pending is not None:
                    self._pending['steps'].append(event)
            elif kind == 'cpu_external_irq_sample':
                self._native_samples[event_id] = event
                if self._pending is not None:
                    self._pending['samples'].append(event)
            elif kind == 'cpu_external_irq_taken':
                if _uint(event.get('producer_event_id')):
                    self._native_takes[event['producer_event_id']] = event
                if self._pending is not None:
                    self._pending = None
            elif kind in ('reset_barrier', 'cpu_reset', 'cpu_flush'):
                self._pending = None
                self._native_samples.clear()
                self._native_takes.clear()
            elif kind == 'cpu_irq_taken':
                # Any second observed acceptance makes the one-pending-IRQ
                # architectural relationship ambiguous.
                if self._pending is not None:
                    self._pending = None
                elif len(upstream) == 1:
                    proof = upstream[0]
                    step = self._steps.get(proof['cpu_step_event_id'])
                    outputs = step.get('outputs') if step else None
                    order = outputs.get('rvfi_order') if isinstance(outputs, Mapping) else None
                    if _uint(order):
                        native = self._native_takes.get(proof['cpu_step_event_id'])
                        sample_id = native.get('sample_event_id') if native else None
                        sample = self._native_samples.get(sample_id) if _uint(sample_id) else None
                        if (not self.require_native_receipts or
                                self._valid_take(event, step, native, sample)):
                            self._pending = {'born': event_id, 'upstream': proof,
                                             'acceptance_order': order,
                                             'native_take': native,
                                             'steps': [step], 'samples': [sample]}
            elif kind == 'cpu_retire' and self._pending is not None:
                candidate = self._retirement(event, self._pending)
                if candidate is not None and (not self.require_native_receipts or
                        self._valid_native_interval(event, self._pending)):
                    if self.require_native_receipts:
                        candidate.update(proof_scope='native_receipt_bounded_architectural_trap_relation',
                                         native_take_event_id=self._pending['native_take']['event_id'],
                                         native_sample_event_id=self._pending['samples'][0]['event_id'],
                                         acceptance_to_retirement_ticks=len(self._pending['steps']) - 1)
                    result.append(candidate)
                # The first retired instruction after acceptance consumes the
                # candidate even if its fields do not support a trap relation.
                self._pending = None
        return tuple(result)

    @staticmethod
    def _valid_take(taken: Mapping, step: Mapping, native: Mapping | None,
                    sample: Mapping | None) -> bool:
        if not isinstance(native, Mapping) or not isinstance(sample, Mapping):
            return False
        epoch = sample.get('reset_epoch')
        return (sample.get('event_id') < native.get('event_id') < taken['event_id']
                and sample.get('kind') == 'cpu_external_irq_sample'
                and native.get('kind') == 'cpu_external_irq_taken'
                and type(epoch) is int and epoch >= 0
                and sample.get('source_epoch') == epoch
                and isinstance(sample.get('execution_id'), str)
                and bool(sample['execution_id'])
                and sample.get('component') == sample.get('source_component') == 'cpu'
                and sample.get('tick') == sample.get('local_tick')
                and native.get('sample_event_id') == sample['event_id']
                and native.get('producer_event_id') == sample.get('producer_event_id') == step['event_id']
                and native.get('sample_ref') == {
                    'command_scope': sample.get('command_scope'),
                    'local_tick': sample.get('local_tick')}
                and all(native.get(k) == sample.get(k) for k in
                        ('receipt_id', 'receipt_ticks', 'command_scope', 'local_tick',
                         'execution_id', 'reset_epoch', 'source_epoch',
                         'component', 'source_component', 'tick', 'phase',
                         'actual_pre_input', 'actual_post_input', 'expected_input',
                         'irq_masked_pre', 'irq_taken_pre', 'notification_pre',
                         'notification_post', 'actual_post_ref',
                         'observation_contract'))
                and all(type(sample.get(k)) is int and sample[k] == 1 for k in
                        ('actual_pre_input', 'actual_post_input', 'irq_taken_pre'))
                and type(native.get('irq_taken_pre')) is int and native['irq_taken_pre'] == 1
                and isinstance(sample.get('notification_post'), Mapping)
                and type(sample['notification_post'].get('rvfi_valid')) is int
                and sample['notification_post']['rvfi_valid'] == 0
                and sample.get('local_tick') == taken.get('cpu_tick') == step.get('local_tick'))

    @staticmethod
    def _valid_native_interval(retire: Mapping, pending: Mapping) -> bool:
        steps, samples = pending['steps'], pending['samples']
        if len(steps) != len(samples) or len(steps) < 2:
            return False
        first = samples[0]
        receipt = first.get('receipt_id')
        scope = first.get('command_scope')
        if not isinstance(receipt, Mapping) or not isinstance(scope, Mapping):
            return False
        execution = receipt.get('execution')
        epoch = scope.get('reset_epoch')
        outer_execution = first.get('execution_id')
        if (type(epoch) is not int or epoch < 0 or
                not isinstance(outer_execution, str) or not outer_execution or
                first.get('source_epoch') != epoch or first.get('reset_epoch') != epoch):
            return False
        previous_tick = None
        previous_sequence = None
        for step, sample in zip(steps, samples):
            if not isinstance(sample, Mapping):
                return False
            tick = sample.get('local_tick')
            command = sample.get('command_scope')
            rid = sample.get('receipt_id')
            ticks = sample.get('receipt_ticks')
            contract = sample.get('observation_contract')
            notification = sample.get('notification_post')
            outputs = step.get('outputs')
            widths = (contract.get('notification_widths')
                      if isinstance(contract, Mapping) else None)
            if (not _uint(tick) or not isinstance(command, Mapping)
                    or not isinstance(rid, Mapping) or not isinstance(ticks, Mapping)
                    or contract != first.get('observation_contract')
                    or not isinstance(widths, Mapping)
                    or not isinstance(notification, Mapping)
                    or not isinstance(outputs, Mapping)
                    or set(notification) != set(widths)
                    or any(type(width) is not int or not 0 < width <= 64
                           or type(notification[name]) is not int
                           or not 0 <= notification[name] < (1 << width)
                           or type(outputs.get(name)) is not int
                           or outputs[name] != notification[name]
                           for name, width in widths.items())
                    or sample.get('kind') != 'cpu_external_irq_sample'
                    or sample.get('producer_event_id') != step.get('event_id')
                    or step.get('component') != 'cpu' or step.get('local_tick') != tick
                    or sample.get('component') != 'cpu'
                    or sample.get('source_component') != 'cpu'
                    or sample.get('execution_id') != outer_execution
                    or sample.get('reset_epoch') != epoch
                    or sample.get('source_epoch') != epoch
                    or sample.get('tick') != tick
                    or type(sample.get('irq_taken_pre')) is not int
                    or (previous_tick is not None and sample['irq_taken_pre'] != 0)
                    or command.get('component') != 'cpu'
                    or command.get('reset_epoch') != epoch
                    or rid.get('execution') != execution
                    or not _uint(rid.get('sequence'))
                    or command.get('command_sequence') != rid['sequence']
                    or ticks.get('tick_after') != tick
                    or ticks.get('tick_before') != tick - 1
                    or ticks.get('new_ticks') != 1
                    or (previous_tick is not None and tick != previous_tick + 1)
                    or (previous_sequence is not None and rid['sequence'] != previous_sequence + 1)):
                return False
            previous_tick, previous_sequence = tick, rid['sequence']
        last = samples[-1]
        return (retire.get('producer_event_id') == steps[-1].get('event_id')
                and all(retire.get(k) == last.get(k) for k in
                        ('receipt_id', 'receipt_ticks', 'command_scope', 'local_tick',
                         'execution_id', 'reset_epoch', 'source_epoch',
                         'component', 'source_component', 'tick',
                         'observation_contract'))
                and retire.get('schema_version') == 'cpu_retire.v2'
                and retire.get('phase') == 'post'
                and retire.get('actual_post_ref') == {
                    'command_scope': last.get('command_scope'),
                    'local_tick': last.get('local_tick'), 'phase': 'post'})

    def _retirement(self, event: Mapping, pending: dict) -> dict | None:
        order = pending['acceptance_order']
        producer_id = event.get('producer_event_id')
        step = self._steps.get(producer_id) if _uint(producer_id) else None
        outputs = step.get('outputs') if step else None
        observation = event.get('observation')
        physical = observation.get('physical') if isinstance(observation, Mapping) else None
        if (not isinstance(outputs, Mapping) or not isinstance(physical, Mapping)
                or event.get('component') != 'cpu'
                or not _uint(event.get('order')) or event['order'] != order + 1
                or type(event.get('intr')) is not int or event['intr'] != 1
                or type(event.get('trap')) is not int or event['trap'] != 0
                or type(event.get('valid')) is not int or event['valid'] != 1
                or type(event.get('pc_wdata')) is not int or event['pc_wdata'] != 0x10200
                or step.get('component') != 'cpu'
                or not _uint(step.get('local_tick'))
                or any(type(outputs.get(name)) is not int or outputs[name] != value
                       for name, value in (('rvfi_valid', 1), ('rvfi_intr', 1),
                                           ('rvfi_order', event['order']),
                                           ('rvfi_pc_wdata', event['pc_wdata'])))
                or any(type(physical.get('rvfi_' + name)) is not int
                       or physical['rvfi_' + name] != value
                       for name, value in (('valid', 1), ('intr', 1),
                                           ('order', event['order']),
                                           ('pc_wdata', event['pc_wdata'])))):
            return None
        upstream = pending['upstream']
        return dict(schema_version='pin8_trap_retirement_relation.v1',
                    scope='pin8_cpu_irq_taken_to_trap_retirement',
                    proof_scope='single_pending_irq_architectural_trap_relation',
                    explicit_source_token_on_retirement=False,
                    admission_id=upstream['admission_id'],
                    action_id=upstream['action_id'],
                    trigger_id=upstream['trigger_id'],
                    cpu_irq_taken_event_id=upstream['cpu_irq_taken_event_id'],
                    source_event_id=upstream['source_event_id'],
                    acceptance_order=order,
                    retirement_event_id=event['event_id'],
                    retirement_step_event_id=producer_id,
                    retirement_order=event['order'],
                    retirement_pc_wdata=event['pc_wdata'])
