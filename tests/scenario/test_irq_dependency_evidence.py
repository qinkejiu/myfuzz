"""Independent native receipt scopes with raw software fixtures, no DUT claim."""
import pytest

from tests.scenario.test_uart_native_irq_versions import authority, raw, update
from tests.scenario.test_uart_native_irq_binding import delivery
from tests.scenario.test_uart_native_irq_taken import sample, taken
from tests.scenario.test_irq_serial_certificates import serial_observation, retirement_event


def consumer(**bounds):
    from myfuzz.scenario.irq_dependency_evidence import IrqDependencyEvidenceConsumer
    registry, ownership, _ = authority()
    return IrqDependencyEvidenceConsumer(ownership=ownership, admission_registry=registry,
        source_component='uart', target_component='cpu', runtime_contract_sha256='a' * 64, **bounds)


def events(*, epoch=0, start=1):
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    registry, ownership, _ = authority()
    native = UartNativeIrqJoin(ownership=ownership, admission_registry=registry)
    tick = raw(); tick.update(event_id=start, reset_epoch=epoch)
    tick['command_scope']['reset_epoch'] = epoch
    version = update(tick, entries=[['uart', epoch, 0, 1]]); version['event_id'] = start + 1
    version['reset_epoch'] = epoch
    native.consume(tick); native.consume(version)
    resource = native.output_at('uart', epoch, 1, 'post', 'rx_watermark')
    delivered = delivery(resource, event_id=start + 2)
    delivered.update(source_epoch=epoch, target_epoch=epoch, dataflow_delivery_event_id=start + 1)
    measured = sample(start + 3); measured['binding_delivery_event_id'] = start + 2
    measured['reset_epoch'] = measured['command_scope']['reset_epoch'] = epoch
    measured['source_output_key'] = resource['source_output_key']
    measured['input_context']['source_output_key'] = resource['source_output_key']
    measured['input_context']['target_epoch'] = epoch
    measured['input_context']['binding_delivery_event_id'] = start + 2
    measured.update(execution_id='execution', source_component='cpu', source_epoch=epoch,
                    tick=1, producer_event_id=start + 2,
                    irq_serial_observation=serial_observation(decision=7, retirement=0))
    accepted = taken(start + 4)
    accepted['reset_epoch'] = accepted['command_scope']['reset_epoch'] = epoch
    accepted['sample_ref']['command_scope']['reset_epoch'] = epoch
    accepted['take_key'] = ['cpu', epoch, 1]
    accepted.update(sample_event_id=start + 3, execution_id='execution',
        source_component='cpu', source_epoch=epoch, tick=1, producer_event_id=start + 2,
        irq_taken_pre=1, irq_serial_observation=serial_observation(decision=7, retirement=0))
    retired = retirement_event(serial=7, execution='execution', epoch=epoch); retired['event_id'] = start + 5
    return [tick, version, delivered, measured, accepted, retired]


def ingest(c, rows):
    for row in rows: c.consume(row)
    return c.report()


def test_delivery_acceptance_and_serial_retirement_have_distinct_historical_scopes():
    c = consumer()
    rows = events()
    report = ingest(c, rows[:4])
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=0, cpu_retirement=0)
    report = ingest(c, rows[4:5])
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=1, cpu_retirement=0)
    report = ingest(c, rows[5:])
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=1, cpu_retirement=1)
    assert {r['scope'] for r in report['ledger']['records']['verified']} == {
        'irq_delivery', 'irq_acceptance', 'cpu_retirement'}
    assert all(r['validity'] == 'historical' for r in report['ledger']['records']['verified'])
    assert report['grants_prerequisites'] is False
    assert all(p['source_origin'] == 'unknown' for p in report['certificates'])


@pytest.mark.parametrize('mutation', ['delivery', 'sample', 'take', 'serial', 'epoch', 'masked'])
def test_missing_or_wrong_evidence_never_grants_later_scope(mutation):
    c = consumer(); rows = events()
    if mutation == 'delivery': rows[2] = dict(event_id=3, kind='annotation')
    elif mutation == 'sample': rows[3] = dict(event_id=4, kind='annotation')
    elif mutation == 'take': rows[4] = dict(event_id=5, kind='annotation')
    elif mutation == 'serial': rows[5]['irq_serial_observation']['retirement']['value'] = 8
    elif mutation == 'epoch': rows[4]['reset_epoch'] = 1
    else: rows[3]['irq_masked_pre'] = 1
    report = ingest(c, rows)
    assert report['counts']['cpu_retirement'] == 0
    if mutation != 'serial': assert report['counts']['irq_acceptance'] == 0


def test_only_serial_without_authenticated_native_take_never_promotes():
    from tests.scenario.test_irq_serial_certificates import decision_event, journal
    report = ingest(consumer(), journal(decision_event(), retirement_event()))
    assert report['counts']['cpu_retirement'] == 0


def test_accepted_certificate_annotation_is_not_a_raw_irq_provider():
    report = ingest(consumer(), [dict(event_id=1, kind='uart_consumption_match',
        status='accepted', proof_scope='cpu_external_irq_taken', cpu_component='cpu'),
        dict(event_id=2, kind='irq_serial_certificate', status='accepted')])
    assert sum(report['counts'].values()) == 0


def test_same_id_conflict_blocks_future_scope_but_preserves_history():
    c = consumer(); rows = events()
    ingest(c, rows[:4]); c.consume({**rows[3], 'annotation': 'changed'})
    report = ingest(c, rows[4:])
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=0, cpu_retirement=0)
    assert report['journal_integrity'] is False


def test_reports_detached_and_capacity_preserves_existing_history():
    c = consumer(max_records=1)
    report = ingest(c, events())
    assert sum(report['counts'].values()) == 1
    assert report['status'] == 'incomplete'
    report['certificates'].clear()
    assert len(c.report()['certificates']) == 1


def test_expired_acceptance_cannot_be_completed_by_later_retirement():
    c = consumer(max_event_gap=1); rows = events()
    ingest(c, rows[:5])
    c.consume(dict(event_id=6, kind='annotation'))
    c.consume({**rows[5], 'event_id': 7})
    assert c.report()['counts']['cpu_retirement'] == 0


def test_expired_source_or_delivery_cannot_prove_new_native_scope():
    report = ingest(consumer(max_event_gap=2), events())
    assert sum(report['counts'].values()) == 0
    assert report['status'] == 'incomplete'


def test_unused_annotations_are_not_retained_in_native_evidence_state():
    c = consumer(); rows = events()
    for row in rows: row['unused_annotation'] = 'x' * 100000
    report = ingest(c, rows)
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=1, cpu_retirement=1)
    assert 'unused_annotation' not in c._native._sources['uart']['raw']


def test_shared_edge_ingest_keeps_irq_scope_report_separate():
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    registry, ownership, _ = authority()
    edge = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    configure = getattr(edge, 'configure_irq_events', None)
    assert configure is not None
    configure(ownership=ownership, admission_registry=registry,
              source_component='uart', target_component='cpu')
    edge.ingest(events())
    assert edge.irq_evidence_report()['counts'] == dict(irq_delivery=1, irq_acceptance=1, cpu_retirement=1)
    with pytest.raises(ValueError):
        configure(ownership=ownership, admission_registry=registry,
                  source_component='uart', target_component='cpu')


def test_irq_configuration_cannot_follow_even_rejected_ingest():
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    edge = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    report = getattr(edge, 'irq_evidence_report', None)
    assert report is not None and report()['status'] == 'not_configured'
    edge.ingest([None])
    registry, ownership, _ = authority()
    with pytest.raises(ValueError):
        edge.configure_irq_events(ownership=ownership, admission_registry=registry,
                                  source_component='uart', target_component='cpu')


def test_same_cpu_receipt_with_different_sample_and_take_serial_never_retires():
    rows = events()
    rows[4]['irq_serial_observation']['decision']['value'] = 8
    rows[5]['irq_serial_observation']['retirement']['value'] = 8
    report = ingest(consumer(), rows)
    assert report['counts']['irq_acceptance'] == 1
    assert report['counts']['cpu_retirement'] == 0


@pytest.mark.parametrize('prefix', [4, 5])
def test_runner_reset_barrier_cancels_pending_native_and_serial_evidence(prefix):
    c = consumer(); rows = events()
    before = ingest(c, rows[:prefix])['counts']
    c.consume(dict(event_id=prefix + 1, kind='reset_barrier', policy='cold_all'))
    remaining = [{**row, 'event_id': row['event_id'] + 1} for row in rows[prefix:]]
    report = ingest(c, remaining)
    assert report['counts'] == before
    assert report['counts']['cpu_retirement'] == 0


@pytest.mark.parametrize('reset_before_barrier', [True, False])
def test_new_measured_epochs_can_prove_new_boundaries_after_barrier(reset_before_barrier):
    c = consumer(); ingest(c, events()[:5])
    barrier = dict(kind='reset_barrier', policy='cold_all')
    resets = [dict(kind='uart_reset', component='uart', reset_epoch=1, physical_reset=True),
              dict(kind='cpu_reset', component='cpu', reset_epoch=1, physical_reset=True)]
    middle = resets + [barrier] if reset_before_barrier else [barrier] + resets
    ingest(c, [{**row, 'event_id': 6 + i} for i, row in enumerate(middle)])
    report = ingest(c, events(epoch=1, start=9))
    assert report['counts'] == dict(irq_delivery=2, irq_acceptance=2, cpu_retirement=1)
    assert report['awaiting_native_reset_components'] == []
