"""Independent software review: GC must retain unresolved real-resource roots."""
from copy import deepcopy
from tests.scenario.test_uart_native_irq_versions import join, raw, update, retention, accepted
from tests.scenario.test_uart_native_irq_binding import delivery
from tests.scenario.test_uart_native_irq_taken import sample, taken
from tests.scenario.test_uart_consumption import lifecycle_tracker


def test_old_unresolved_take_survives_more_than_1024_new_source_versions():
    model, admission = join()
    initial = raw();model.consume(initial);model.consume(update(initial))
    resource = model.output_at('uart', 0, 1, 'post', 'rx_watermark')
    model.consume(delivery(resource));model.consume(sample());model.consume(taken())
    for tick in range(2, 1103):
        event=raw(tick,prior=1);event['event_id']=10000+tick*10
        model.consume(event)
        derived=update(event);derived['event_id']=event['event_id']+1
        model.consume(derived)
    assert not model._global_bad
    assert model.output_at('uart',0,1,'post','rx_watermark') is None
    assert 501 in model._takes and 500 in model._samples and 400 in model._deliveries
    certificate=retention(admission);certificate['event_id']=50000
    reports=model.consume(certificate)
    proofs=accepted(reports,'cpu_external_irq_taken')
    assert len(proofs)==1 and proofs[0]['cpu_take_event_id']==501
    assert proofs[0]['source_output_key']==resource['source_output_key']
    assert not accepted(model.consume(certificate),'cpu_external_irq_taken')


def test_real_unresolved_take_capacity_loss_is_a_certainty_barrier():
    model, admission=join();model.max_entry_refs=3
    initial=raw();model.consume(initial);model.consume(update(initial))
    resource=model.output_at('uart',0,1,'post','rx_watermark');model.consume(delivery(resource))
    for tick in range(1,7):
        measured=sample(1000+tick*10);measured['local_tick']=tick
        measured['command_scope']['command_sequence']=measured['receipt_id']['sequence']=tick
        model.consume(measured)
        actual=taken(1001+tick*10);actual.update(local_tick=tick,sample_event_id=measured['event_id'],take_key=['cpu',0,tick])
        actual['command_scope']['command_sequence']=actual['receipt_id']['sequence']=tick
        actual['sample_ref']={'command_scope':deepcopy(actual['command_scope']),'local_tick':tick}
        model.consume(actual)
    assert model._global_bad
    assert not accepted(model.consume(retention(admission)),'cpu_external_irq_taken')


def test_delayed_read_origin_survives_260_other_completed_reads():
    tracker, fixture=lifecycle_tracker()
    old_validation,_=fixture.receive(validate=False)
    old_access,_=fixture.read()
    for _ in range(260):
        fixture.receive();fixture.read()
    state=tracker._states['uart']
    assert not state['degraded']
    assert old_validation['frame_id'] in state['frames']
    reports=tracker.consume(old_validation)
    reads=[r for r in reports if r.get('status')=='accepted' and r.get('proof_scope')=='uart_fifo_read_consumption']
    assert len(reads)==1 and reads[0]['frame_id']==old_validation['frame_id']
    assert not any(r.get('status')=='accepted' for r in tracker.consume(old_access))
    assert not any(r.get('status')=='accepted' for r in tracker.consume(old_validation))


def test_reset_releases_unresolved_take_without_late_certificate_upgrade():
    model,admission=join();event=raw();model.consume(event);model.consume(update(event))
    model.consume(delivery(model.output_at('uart',0,1,'post','rx_watermark')))
    model.consume(sample());model.consume(taken())
    model.consume(dict(kind='cpu_reset',event_id=600,component='cpu',reset_epoch=1,local_tick=1,physical_reset=True))
    assert not accepted(model.consume(retention(admission)),'cpu_external_irq_taken')


def test_unknown_cpu_prefix_over_1024_samples_stays_unpoisoned():
    model,admission=join()
    for tick in range(1,1101):
        event=sample(60000+tick);event.pop('binding_delivery_event_id');event.pop('source_output_key',None);event['input_context']=None
        event['local_tick']=tick
        event['command_scope']['command_sequence']=event['receipt_id']['sequence']=tick
        reports=model.consume(event)
        assert not accepted(reports,'cpu_external_irq_taken')
    assert not model._global_bad and not model._cpus['cpu']['bad']
    assert len(model._samples)==1


def test_delayed_certificate_from_another_source_case_never_promotes_old_take():
    model,admission=join();event=raw();model.consume(event);model.consume(update(event))
    model.consume(delivery(model.output_at('uart',0,1,'post','rx_watermark')))
    model.consume(sample());model.consume(taken())
    proof=retention(admission);proof['source_admission']['case_id']='source-B'
    reports=model.consume(proof)
    assert not accepted(reports,'cpu_external_irq_taken')
    assert any(r.get('reason')=='untrusted_uart_irq_entry_certificate' for r in reports)
