from myfuzz.integration.custom_gpio_irq_evidence import observe_custom_gpio_irq


def test_observes_real_gpio_delivery_and_cpu_vector_without_claiming_causation():
    events = [
        {'event_id': 1, 'kind': 'gpio_input_applied', 'component': 'gpio',
         'status': 'observed', 'actual_input_value': 256},
        {'event_id': 2, 'kind': 'local_tick_sample', 'component': 'gpio',
         'phase': 'post', 'outputs': {'physical': {'gpio_irq': 1}}},
        {'event_id': 3, 'kind': 'dataflow_delivery', 'producer_event_id': 2,
         'source': ('gpio', 'interrupt'), 'target': ('cpu', 'irq'),
         'target_bit_offset': 4, 'value': 1},
        {'event_id': 4, 'component': 'cpu', 'outputs': {'custom_irq_observation':
         {'irq_pre': 16, 'irq_post': 16, 'eoi_pre': 0, 'eoi_post': 0}}},
        {'event_id': 5, 'component': 'cpu', 'outputs': {'custom_irq_observation':
         {'irq_pre': 0, 'irq_post': 0, 'eoi_pre': 0, 'eoi_post': 16}}},
    ]
    result = observe_custom_gpio_irq(events, cpu_id='cpu', gpio_id='gpio',
        gpio_irq_port='interrupt', gpio_irq_name='gpio_irq', gpio_irq_bit=4)
    assert [result[k]['event_id'] for k in ('gpio_input', 'gpio_irq', 'delivery', 'cpu_irq', 'cpu_eoi')] == [1, 2, 3, 4, 5]
    assert result['delivery']['producer_event_id'] == 2
    assert result['source_attribution'] == result['retirement'] == 'unknown'
    assert result['certificate'] == 'not_granted' and result['reward_eligible'] is False


def test_does_not_associate_wrong_vector_or_unlinked_delivery():
    events = [
        {'event_id': 1, 'kind': 'local_tick_sample', 'component': 'gpio',
         'outputs': {'physical': {'gpio_irq': 1}}},
        {'event_id': 2, 'kind': 'dataflow_delivery', 'producer_event_id': 9,
         'source': ('gpio', 'interrupt'), 'target': ('cpu', 'irq'),
         'target_bit_offset': 4, 'value': 1},
        {'event_id': 3, 'component': 'cpu', 'outputs': {'custom_irq_observation':
         {'irq_pre': 8, 'irq_post': 8, 'eoi_pre': 8, 'eoi_post': 8}}},
    ]
    result = observe_custom_gpio_irq(events, cpu_id='cpu', gpio_id='gpio',
        gpio_irq_port='interrupt', gpio_irq_name='gpio_irq', gpio_irq_bit=4)
    assert result['delivery'] is result['cpu_irq'] is result['cpu_eoi'] is None


def test_pulse_source_requires_actual_sample_reference_and_vector_bit():
    sample = {'event_id': 1, 'kind': 'local_tick_sample', 'component': 'gpio',
              'outputs': {'physical': {'gpio_irq': 1}}}
    pulse = {'event_id': 2, 'kind': 'source_start', 'source_event_id': 1,
             'source': ('gpio', 'interrupt'), 'target': ('cpu', 'irq'),
             'target_bit_offset': 4, 'source_trigger': {'sample_event_id': 1}}
    kwargs = dict(cpu_id='cpu', gpio_id='gpio', gpio_irq_port='interrupt',
                  gpio_irq_name='gpio_irq', gpio_irq_bit=4)
    assert observe_custom_gpio_irq([sample, pulse], **kwargs)['pulse']['event_id'] == 2
    assert observe_custom_gpio_irq([sample, {**pulse, 'source_trigger': None}], **kwargs)['pulse'] is None
    assert observe_custom_gpio_irq([sample, {**pulse, 'target_bit_offset': 3}], **kwargs)['pulse'] is None
