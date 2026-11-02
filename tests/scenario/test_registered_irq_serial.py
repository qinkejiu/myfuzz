from copy import deepcopy
from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates
from myfuzz.local_harness.cv32e20_irq_receipt_contract import cv32e20_irq_receipt_contract
from tests.scenario.test_irq_serial_certificates import decision_event,retirement_event


def events():
    rows=[decision_event(),retirement_event()]
    for index,row in enumerate(rows,1):
        row['event_id']=index
        row['observation_contract']=cv32e20_irq_receipt_contract()
        row['irq_serial_observation']['schema_version']='cpu_irq_serial_observation.v1'
    return rows


def test_registered_E20_serial_joins_keep_their_own_schema():
    tracker=IrqSerialCertificates()
    certificate=tracker.ingest(events())[0]
    assert certificate['decision_serial']==certificate['retirement_serial']==7
    assert certificate['irq_serial_observation_schema']=='cpu_irq_serial_observation.v1'


def test_generic_serial_schema_requires_registered_actual_provider():
    rows=events();rows[0].pop('observation_contract')
    tracker=IrqSerialCertificates();certificates=tracker.ingest(rows)
    assert not certificates
