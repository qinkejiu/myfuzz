from copy import deepcopy
from tests.scenario.test_uart_native_irq_versions import accepted
from tests.scenario.test_uart_native_irq_binding import configured, delivery


def sample(event_id=500):
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    return dict(kind='cpu_external_irq_sample', schema_version='cpu_external_irq_sample.v1', event_id=event_id, component='cpu',
        reset_epoch=0, local_tick=1, command_scope=dict(component='cpu', reset_epoch=0,
        command_sequence=1), receipt_id=dict(execution='cpu-process', sequence=1),
        observation_contract=ibex_irq_receipt_contract(), binding_delivery_event_id=400,
        source_output_key=['uart', 0, 'rx_watermark', 1],
        input_context=dict(schema_version='native_irq_input_context.v1',
            binding_delivery_event_id=400, expected_input=1,
            source_output_key=['uart', 0, 'rx_watermark', 1],
            target_component='cpu', target_epoch=0),
        expected_input=1, actual_pre_input=1, actual_post_input=1,
        irq_masked_pre=0, irq_taken_pre=1)


def test_unknown_sample_schema_fails_closed():
    tracker, resource = configured(); tracker.consume(delivery(resource))
    event = sample(); event['schema_version'] = 'cpu_external_irq_sample.v2'
    assert any(record.get('status') == 'incomplete' for record in tracker.consume(event))
    assert not accepted(tracker.consume(taken()), 'cpu_external_irq_taken')


def test_deleted_or_tampered_native_context_and_top_version_fail_closed():
    for mutation in ('delete_context', 'none_context', 'delete_top', 'extra_context',
                     'delete_nested', 'null_binding',
                     'bool_epoch', 'float_input', 'replacement', 'float_top'):
        tracker, resource = configured(); tracker.consume(delivery(resource))
        event = sample()
        if mutation == 'delete_context': event.pop('input_context')
        elif mutation == 'none_context': event['input_context'] = None
        elif mutation == 'delete_top': event.pop('source_output_key')
        elif mutation == 'extra_context': event['input_context']['unexpected'] = 1
        elif mutation == 'delete_nested': event['input_context'].pop('source_output_key')
        elif mutation == 'null_binding': event['binding_delivery_event_id'] = None
        elif mutation == 'bool_epoch': event['input_context']['target_epoch'] = False
        elif mutation == 'float_input': event['input_context']['expected_input'] = 1.0
        elif mutation == 'replacement': event['input_context']['source_output_key'][-1] = 2
        else: event['source_output_key'][-1] = 1.0
        assert any(record.get('status') == 'incomplete' for record in tracker.consume(event))
        assert not accepted(tracker.consume(taken()), 'cpu_external_irq_taken')


def taken(event_id=501):
    event = sample()
    return dict(kind='cpu_external_irq_taken', schema_version='cpu_external_irq_taken.v1',
        event_id=event_id, component='cpu', reset_epoch=0, local_tick=1,
        sample_event_id=500, command_scope=event['command_scope'],
        receipt_id=event['receipt_id'], observation_contract=event['observation_contract'],
        sample_ref=dict(command_scope=event['command_scope'], local_tick=1), take_key=['cpu', 0, 1])


def test_exact_delivery_sample_and_taken_only_accept_after_complete_chain():
    tracker, resource = configured()
    tracker.consume(delivery(resource))
    records = tracker.consume(sample())
    assert not accepted(records, 'cpu_external_irq_taken')
    records = tracker.consume(taken())
    proofs = accepted(records, 'cpu_external_irq_taken')
    assert len(proofs) == 1
    assert proofs[0]['graph_path_certified'] is False
    assert proofs[0]['operand_origin'] == proofs[0]['generic_isr_origin'] == 'unknown'


def test_masked_bool_unknown_delivery_and_wrong_sample_never_promote():
    for field in ('irq_masked_pre', 'actual_pre_input', 'binding_delivery_event_id', 'irq_taken_pre'):
        tracker, resource = configured()
        tracker.consume(delivery(resource))
        event = sample()
        event[field] = 0 if field == 'actual_pre_input' else True if field == 'irq_taken_pre' else 1
        tracker.consume(event)
        records = tracker.consume(taken())
        assert not accepted(records, 'cpu_external_irq_taken')


def test_missing_taken_contract_and_unhashable_sample_ids_are_total():
    tracker, resource = configured()
    tracker.consume(delivery(resource)); tracker.consume(sample())
    event = taken(); event.pop('observation_contract')
    assert not accepted(tracker.consume(event), 'cpu_external_irq_taken')
    for kind, field in (('cpu_external_irq_sample', 'binding_delivery_event_id'),
                        ('cpu_external_irq_taken', 'sample_event_id')):
        tracker, resource = configured(); tracker.consume(delivery(resource))
        event = sample() if kind == 'cpu_external_irq_sample' else taken()
        event[field] = []
        assert not accepted(tracker.consume(event), 'cpu_external_irq_taken')


def test_late_source_proof_appends_taken_without_rewriting_sample():
    from tests.scenario.test_uart_native_irq_versions import join, raw, update, retention
    tracker, admission = join(); event = raw()
    tracker.consume(event); tracker.consume(update(event))
    resource = tracker.output_at('uart', 0, 1, 'post', 'rx_watermark')
    tracker.consume(delivery(resource)); measured = sample(); original = deepcopy(measured)
    tracker.consume(measured)
    assert not accepted(tracker.consume(taken()), 'cpu_external_irq_taken')
    certificate = retention(admission); certificate['event_id'] = 502
    records = tracker.consume(certificate)
    assert len(accepted(records, 'cpu_external_irq_taken')) == 1
    assert measured == original


def test_initial_unbound_sample_is_unknown_without_poisoning_later_native_chain():
    tracker, resource = configured()
    event = sample(); event['event_id'] = 450
    event.pop('binding_delivery_event_id'); event.pop('source_output_key'); event['input_context'] = None
    records = tracker.consume(event)
    assert not accepted(records, 'cpu_external_irq_taken')
    tracker.consume(delivery(resource))
    event = sample(); event['local_tick'] = 2
    event['command_scope']['command_sequence'] = event['receipt_id']['sequence'] = 2
    tracker.consume(event)
    actual = taken(); actual['local_tick'] = 2
    actual['command_scope']['command_sequence'] = actual['receipt_id']['sequence'] = 2
    actual['sample_ref'] = dict(command_scope=actual['command_scope'], local_tick=2)
    assert len(accepted(tracker.consume(actual), 'cpu_external_irq_taken')) == 1


def test_more_than_capacity_consumed_takes_do_not_exhaust_live_witness_cache():
    tracker, resource = configured(); tracker.consume(delivery(resource))
    for tick in range(1, 1101):
        event = sample(50000 + tick * 10); event['local_tick'] = tick
        event['command_scope']['command_sequence'] = event['receipt_id']['sequence'] = tick
        tracker.consume(event)
        actual = taken(50001 + tick * 10); actual.update(local_tick=tick,
            sample_event_id=event['event_id'], take_key=['cpu', 0, tick])
        actual['command_scope']['command_sequence'] = actual['receipt_id']['sequence'] = tick
        actual['sample_ref'] = dict(command_scope=actual['command_scope'], local_tick=tick)
        assert len(accepted(tracker.consume(actual), 'cpu_external_irq_taken')) == 1
    assert tracker._global_bad is False
    assert len(tracker._takes) < 10 and len(tracker._samples) < 10


def test_upstream_fifo_certainty_loss_blocks_subsequent_native_taken():
    tracker, resource = configured()
    tracker.consume(dict(kind='uart_consumption_match', event_id=350,
        component='uart', reset_epoch=0, local_tick=2, status='incomplete',
        reason='uart_fifo_transition_mismatch', proof_scope='uart_fifo_retention'))
    tracker.consume(delivery(resource)); tracker.consume(sample())
    assert not accepted(tracker.consume(taken()), 'cpu_external_irq_taken')


def test_reset_requires_measured_hardware_fact_and_advanced_epoch():
    for component, epoch, physical in (([], 1, True), ('uart', True, True),
                                        ('uart', 1, 1), ('uart', 0, True)):
        tracker, _ = configured()
        records = tracker.consume(dict(kind='uart_reset', event_id=600,
            component=component, reset_epoch=epoch, physical_reset=physical))
        assert any(record.get('status') == 'incomplete' for record in records)
    tracker, _ = configured()
    tracker.consume(dict(kind='uart_consumption_match', event_id=350,
        component='uart', reset_epoch=0, status='incomplete', reason='uart_fifo_transition_mismatch'))
    records = tracker.consume(dict(kind='uart_reset', event_id=600, component='uart',
        reset_epoch=1, local_tick=0, physical_reset=True))
    assert records[0]['kind'] == 'native_irq_reset'
    assert tracker.output_at('uart', 0, 1, 'post', 'rx_watermark') is None
    assert tracker._sources['uart']['bad'] is False


def test_wrong_reset_kind_or_unknown_role_never_creates_state():
    for kind, component in (('uart_reset', 'cpu'), ('cpu_reset', 'uart'),
                             ('uart_reset', 'unknown'), ('cpu_reset', 'unknown')):
        tracker, _ = configured()
        before_sources, before_cpus = set(tracker._sources), set(tracker._cpus)
        records = tracker.consume(dict(kind=kind, event_id=601, component=component,
            reset_epoch=1, local_tick=0, physical_reset=True))
        assert any(record.get('status') == 'incomplete' for record in records)
        assert set(tracker._sources) == before_sources
        assert set(tracker._cpus) == before_cpus


def test_reset_rejects_wrong_width_owner_and_unrelated_binding_producer():
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from tests.scenario.test_uart_native_irq_versions import authority
    registry, _, _ = authority()
    for width, owner_kind, producer, reset_kind, component in (
            (7, 'source', 'uart.uart_rx_watermark', 'uart_reset', 'uart'),
            (8, 'bound', 'uart.uart_rx_watermark', 'uart_reset', 'uart'),
            (8, 'source', 'uart.uart_tx_watermark', 'cpu_reset', 'cpu'),
            (8, 'source', 'unknown.uart_rx_watermark', 'cpu_reset', 'cpu')):
        ownership = compile_ownership((InputField('uart', 'uart_rx_byte', width),
            InputField('cpu', 'irq', 1)), (InputOwner('uart', 'uart_rx_byte', 0, width,
                owner_kind, 'rx'), InputOwner('cpu', 'irq', 0, 1, 'bound', producer)))
        tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry)
        records = tracker.consume(dict(kind=reset_kind, event_id=601, component=component,
            reset_epoch=1, local_tick=0, physical_reset=True))
        assert any(record.get('status') == 'incomplete' for record in records)
        assert not tracker._sources and not tracker._cpus
