from types import SimpleNamespace
import pytest
from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction


def test_level_delivery_requires_open_ended_same_source_binding():
    case = object.__new__(_Case)
    case.contract = {'irq': {'delivery_policy': 'level', 'delivery_id': 'irq-delivery', 'producer_port': 'o_interrupt'}}
    case.cpu_id = 'cpu'; case.dma_id = 'dma'
    case.cpu = SimpleNamespace(reset_epoch=0); case.dma = SimpleNamespace(reset_epoch=0)
    case.attempt = {'irq_output': 7}
    output = {'event_id': 7, 'source_output_key': ['dma', 0, 'o_interrupt', 4]}
    case.reference = lambda *args: output
    delivery = {'event_id': 8, 'delivery_id': 'irq-delivery', 'target_component': 'cpu',
                'target_epoch': 0, 'start_local_tick': 5, 'end_local_tick': None,
                'source_event_id': 7, 'source_output_key': output['source_output_key']}
    case.independent_irq_delivery(delivery)
    with pytest.raises(_Contradiction):
        case.independent_irq_delivery({**delivery, 'end_local_tick': 21})
    with pytest.raises(_Contradiction):
        case.independent_irq_delivery({**delivery, 'source_output_key': ['dma', 1, 'o_interrupt', 4]})


def test_level_clear_absence_is_missing_and_cannot_pass(monkeypatch):
    from myfuzz.integration import compiled_f6, compiled_f6_consumer
    case = object.__new__(_Case)
    case.attempt = {'_runner_event_start': 0, '_observer_event_start': 0}
    case.runtime = SimpleNamespace(runner=object())
    monkeypatch.setattr(compiled_f6_consumer, '_borrow_events', lambda *args: [])
    monkeypatch.setattr(compiled_f6, '_f6_level_clear_tick', lambda *args: None)
    with pytest.raises(compiled_f6_consumer._Missing, match='actual low sample'):
        case.level_irq_clear({'event_id': 1}, {'event_id': 2}, {'local_tick': 20})


def test_level_clear_requires_actual_low_before_mret(monkeypatch):
    from myfuzz.integration import compiled_f6, compiled_f6_consumer
    from myfuzz.scenario.ledger import TransactionKey
    case = object.__new__(_Case)
    case.attempt = {'_runner_event_start': 0, '_observer_event_start': 0}
    case.runtime = SimpleNamespace(runner=object())
    case.cpu_id = 'cpu'; case.cpu = SimpleNamespace(reset_epoch=0)
    case.contract = {'control': {'base': 0x40000000}, 'dma': {'behavior': {
        'irq_clear': {'method': 'write', 'offset': 0, 'value': 0x80000000, 'byte_enable': 15}}}}
    key = TransactionKey('local-execution', 'case', 'cpu', 0, 'data', 1)
    accept = {'event_id': 10, 'component': 'cpu', 'kind': 'data_accept', 'address': 0x40000000,
              'write': 1, 'wdata': 0x80000000}
    low = {'event_id': 11, 'component': 'cpu', 'kind': 'cpu_external_irq_sample',
           'local_tick': 15, 'reset_epoch': 0, 'expected_input': 0, 'actual_pre_input': 0, 'actual_post_input': 0}
    response = {'event_id': 12, 'response_tick': 14}
    delivered = {'event_id': 13}
    case.index = {('cpu', 10): [accept], ('cpu', 11): [low]}
    case.reference = lambda event_id, *args: {10: accept, 11: low}[event_id]
    case.live_cpu = lambda row: None
    case.cpu_key = lambda row: key
    case.unique = lambda owner, kind, key: response if kind == 'data_response' else delivered
    case.cpu_response = lambda *args, **kwargs: None
    case.control_delivery = lambda *args, **kwargs: None
    monkeypatch.setattr(compiled_f6_consumer, '_borrow_events', lambda *args: [])
    monkeypatch.setattr(compiled_f6, '_f6_level_clear_tick', lambda *args: 15)
    result = case.level_irq_clear({'event_id': 8}, {'event_id': 9}, {'event_id': 20, 'local_tick': 20})
    assert result['low_cpu_sample_event_id'] == 11
    low['actual_pre_input'] = 1
    with pytest.raises(_Contradiction, match='low sample'):
        case.level_irq_clear({'event_id': 8}, {'event_id': 9}, {'event_id': 20, 'local_tick': 20})
    low['actual_pre_input'] = 0
    with pytest.raises(_Contradiction, match='precede MRET'):
        case.level_irq_clear({'event_id': 8}, {'event_id': 9}, {'event_id': 20, 'local_tick': 15})


def test_level_sample_requires_real_high_input_and_unique_dma_group():
    case = object.__new__(_Case)
    case.contract = {'irq': {'delivery_policy': 'level', 'delivery_id': 'irq-delivery', 'producer_port': 'o_interrupt'}}
    case.cpu_id = 'cpu'; case.dma_id = 'dma'
    case.cpu = SimpleNamespace(reset_epoch=0, _execution='native-exec')
    case.dma = SimpleNamespace(reset_epoch=0)
    case.attempt = {'irq_output': 7}
    source = ['dma', 0, 'o_interrupt', 4]
    output = {'event_id': 7, 'source_output_key': source}
    case.reference = lambda *args: output
    case.live_cpu = lambda row: None
    binding = SimpleNamespace(source_component='dma', source_port='irq')
    runner = SimpleNamespace(irq_group_for=lambda b: object(),
        irq_group_delivery=lambda b, cpu_tick: {'value': 1, 'unique_source': 'dma.irq'})
    case.runtime = SimpleNamespace(runner=runner, _irq_binding=binding)
    delivery = {'event_id': 8, 'delivery_id': 'irq-delivery', 'target_component': 'cpu',
                'target_epoch': 0, 'start_local_tick': 5, 'end_local_tick': None,
                'source_event_id': 7, 'source_output_key': source}
    sample = {'component': 'cpu', 'local_tick': 6, 'reset_epoch': 0,
        'receipt_id': {'execution': 'native-exec', 'sequence': 1},
        'command_scope': {'component': 'cpu', 'reset_epoch': 0, 'command_sequence': 1},
        'expected_input': 1, 'actual_pre_input': 1, 'actual_post_input': 1,
        'binding_delivery_event_id': 8, 'source_output_key': source,
        'input_context': {'binding_delivery_event_id': 8, 'source_output_key': source,
                          'target_component': 'cpu', 'target_epoch': 0, 'expected_input': 1}}
    case.independent_irq_input(sample, delivery)
    with pytest.raises(_Contradiction):
        case.independent_irq_input({**sample, 'actual_post_input': 0}, delivery)
    runner.irq_group_delivery = lambda b, cpu_tick: {'value': 1, 'unique_source': None}
    with pytest.raises(_Contradiction, match='unique DMA'):
        case.independent_irq_input(sample, delivery)
