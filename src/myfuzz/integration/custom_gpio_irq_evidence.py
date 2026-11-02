"""Compact, case-local observations of a GPIO IRQ vector route.

These ordered observations do not prove why the GPIO asserted, that an ISR
retired, or that the EOI was caused by this particular delivery.
"""


class CustomGpioIrqObserver:
    def __init__(self, *, cpu_id, gpio_id, gpio_irq_port, gpio_irq_name, gpio_irq_bit):
        self.cpu_id, self.gpio_id = cpu_id, gpio_id
        self.gpio_irq_port, self.gpio_irq_name = gpio_irq_port, gpio_irq_name
        self.gpio_irq_bit = gpio_irq_bit
        self.source_sample = None
        self.result = dict(gpio_input=None, gpio_irq=None, delivery=None, pulse=None, cpu_irq=None,
                  cpu_eoi=None, source_attribution='unknown', retirement='unknown',
                  certificate='not_granted', reward_eligible=False)

    def observe(self, event):
        result = self.result
        cpu_id, gpio_id = self.cpu_id, self.gpio_id
        gpio_irq_port, gpio_irq_name = self.gpio_irq_port, self.gpio_irq_name
        gpio_irq_bit = self.gpio_irq_bit
        mask = 1 << gpio_irq_bit
        if not isinstance(event, dict):
            return
        event_id = event.get('event_id')
        if type(event_id) is not int:
            return
        kind, component = event.get('kind'), event.get('component')
        if component == gpio_id:
            if (kind == 'gpio_input_applied' and event.get('status') == 'observed'
                    and result['gpio_input'] is None):
                result['gpio_input'] = {k: event.get(k) for k in
                    ('event_id', 'local_tick', 'actual_input_value', 'requested_input_value')}
            if kind == 'local_tick_sample':
                physical = event.get('outputs', {}).get('physical', {})
                if physical.get(gpio_irq_name) == 1:
                    self.source_sample = {k: event.get(k) for k in ('event_id', 'local_tick', 'phase')}
                    self.source_sample.update(port=gpio_irq_name, value=1)
                    if result['gpio_irq'] is None:
                        result['gpio_irq'] = self.source_sample
                else:
                    self.source_sample = None
        if (result['delivery'] is None and self.source_sample is not None
                and kind == 'dataflow_delivery'
                and event.get('producer_event_id') == self.source_sample['event_id']
                and event.get('source') in ((gpio_id, gpio_irq_port), [gpio_id, gpio_irq_port])
                and event.get('target') in ((cpu_id, 'irq'), [cpu_id, 'irq'])
                and event.get('target_bit_offset') == gpio_irq_bit and event.get('value') == 1):
            result['gpio_irq'] = self.source_sample
            result['delivery'] = {k: event.get(k) for k in
                ('event_id', 'producer_event_id', 'target_bit_offset', 'value', 'target_value')}
        if (kind == 'source_start' and self.source_sample is not None
                and event.get('source') in ((gpio_id, gpio_irq_port), [gpio_id, gpio_irq_port])
                and event.get('target') in ((cpu_id, 'irq'), [cpu_id, 'irq'])
                and event.get('target_bit_offset') == gpio_irq_bit
                and isinstance(event.get('source_trigger'), dict)
                and event['source_trigger'].get('sample_event_id') == self.source_sample['event_id']
                and result['pulse'] is None):
            result['pulse'] = {k: event.get(k) for k in
                ('event_id', 'source_event_id', 'source_trigger', 'target_bit_offset')}
        if component == cpu_id:
            observation = event.get('outputs', {}).get('custom_irq_observation')
            if not isinstance(observation, dict):
                return
            for signal in ('irq', 'eoi'):
                key = 'cpu_' + signal
                if result[key] is None and (signal == 'irq' or result['cpu_irq'] is not None):
                    pre, post = observation.get(signal + '_pre'), observation.get(signal + '_post')
                    if any(type(value) is int and value & mask for value in (pre, post)):
                        result[key] = dict(event_id=event_id, local_tick=event.get('local_tick'),
                                           bit=gpio_irq_bit, pre=pre, post=post)


def observe_custom_gpio_irq(events, **kwargs):
    observer = CustomGpioIrqObserver(**kwargs)
    for event in events:
        observer.observe(event)
    return observer.result
