"""Reducer hardening: acceptance flag, gpio_reset, and post-reset epoch floors.

Each case is derived from a real journal shape (the registered serial document),
never from the reducer's own output. The reducers here consume saved evidence
only; they grant no live authority.
"""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

SERIAL_SCHEMA = 'ibex_irq_serial_observation.v1'
ZERO_SEMANTICS = 'no_provable_source_lineage'


def _role(port, phase, value):
    return {'physical_port': port, 'phase': phase,
            'value': value, 'status': 'observed'}


def _serial(decision, retirement):
    return {'schema_version': SERIAL_SCHEMA, 'sampling': 'pre_post_rising',
            'width_bits': 64, 'zero_semantics': ZERO_SEMANTICS,
            'decision': _role('irq_decision_serial', 'pre', decision),
            'retirement': _role('irq_retirement_serial', 'post', retirement)}


def _base(kind, *, producer, component='cpu', epoch=0, **fields):
    return {'kind': kind, 'component': component, 'source_component': component,
            'execution_id': 'local-execution', 'reset_epoch': epoch,
            'source_epoch': epoch, 'tick': 2,
            'producer_event_id': producer, **fields}


def decision(*, serial=4, producer=10, epoch=0, taken=1, take_key=('cpu', 0, 1)):
    fields = {'irq_taken_pre': taken,
              'irq_serial_observation': _serial(serial, 0)}
    if take_key is not None:
        fields['take_key'] = list(take_key)
    return _base('cpu_external_irq_taken', producer=producer, epoch=epoch, **fields)


def retirement(*, serial=4, producer=20, epoch=0, intr=1, order=3):
    return _base('cpu_retire', producer=producer, epoch=epoch,
                 valid=1, intr=intr, order=order, pc_rdata=0x10000, insn=0x13,
                 irq_serial_observation=_serial(0, serial))


def journal(*events):
    return [{**event, 'event_id': index} for index, event in enumerate(events, start=1)]


def reasons(consumer):
    return [record['reason'] for record in consumer.rejections()]


def test_a_serial_token_without_native_acceptance_cannot_certify():
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    consumer = IrqSerialCertificates()
    events = journal(decision(taken=0), retirement())
    assert consumer.ingest(events) == ()
    assert 'decision_without_native_acceptance' in reasons(consumer)
    assert consumer.pending_count == 0
    # The same events with the real acceptance flag certify exactly one join.
    accepted = IrqSerialCertificates()
    assert len(accepted.ingest(journal(decision(taken=1), retirement()))) == 1


@pytest.mark.parametrize('kind', ['gpio_reset', 'gpio_reset_resource',
                                  'cpu_reset', 'reset_barrier'])
def test_every_measured_reset_clears_pending_credit(kind):
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    consumer = IrqSerialCertificates()
    reset = ({'kind': kind, 'policy': 'cold_all'} if kind == 'reset_barrier'
             else {'kind': kind, 'component': 'peripheral', 'reset_epoch': 1,
                   'source_epoch': 1})
    events = journal(decision(epoch=0), {**reset, 'producer_event_id': 1},
                     retirement(epoch=1, producer=2))
    assert consumer.ingest(events) == ()
    assert consumer.pending_count == 0
    assert 'unmatched_retirement_serial' in reasons(consumer)


def test_post_reset_pair_restamped_with_the_old_epoch_is_refused():
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    consumer = IrqSerialCertificates()
    barrier = {'kind': 'reset_barrier', 'policy': 'cold_all'}
    stale = journal(decision(epoch=0), {**barrier, 'producer_event_id': 1},
                    decision(epoch=0, producer=11, take_key=('cpu', 0, 2)),
                    retirement(epoch=0, producer=21))
    assert consumer.ingest(stale) == ()
    assert 'epoch_without_advanced_reset' in reasons(consumer)
    assert consumer.pending_count == 0
    # A typed reset names its own epoch and still refuses the old one.
    typed = IrqSerialCertificates()
    events = journal(decision(epoch=0),
                     {**{'kind': 'cpu_reset', 'component': 'cpu',
                         'reset_epoch': 1, 'source_epoch': 1},
                      'producer_event_id': 1},
                     decision(epoch=0, producer=11), retirement(epoch=0, producer=21))
    assert typed.ingest(events) == ()
    assert 'epoch_without_advanced_reset' in reasons(typed)


def test_fresh_epoch_after_reset_certifies_and_old_take_identity_is_refused():
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    barrier = {'kind': 'reset_barrier', 'policy': 'cold_all'}
    consumer = IrqSerialCertificates()
    events = journal({**barrier, 'producer_event_id': 1},
                     decision(epoch=1, producer=11, take_key=('cpu', 1, 1)),
                     retirement(epoch=1, producer=21))
    certificates = consumer.ingest(events)
    assert len(certificates) == 1 and certificates[0]['reset_epoch'] == 1
    stale_take = IrqSerialCertificates()
    events = journal({**barrier, 'producer_event_id': 1},
                     decision(epoch=1, producer=11, take_key=('cpu', 0, 1)),
                     retirement(epoch=1, producer=21))
    assert stale_take.ingest(events) == ()
    assert 'take_key_scope_mismatch' in reasons(stale_take)


def test_a_startup_barrier_imposes_no_floor_before_any_observation():
    """A run begins with a barrier; nothing has been observed to advance from."""
    from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
    consumer = IrqSerialCertificates()
    barrier = {'kind': 'reset_barrier', 'policy': 'cold_all', 'producer_event_id': 1}
    events = journal(barrier, decision(epoch=0), retirement(epoch=0))
    certificates = consumer.ingest(events)
    assert len(certificates) == 1 and certificates[0]['reset_epoch'] == 0
    assert not consumer._epoch_floor
