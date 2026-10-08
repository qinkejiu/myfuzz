"""Runner forwards measured records, without rescanning or editing raw evidence."""
from copy import deepcopy
from types import SimpleNamespace

from tests.scenario.test_uart_native_irq_runner import fixture


def test_retirement_stream_is_normalized_and_forwarded_before_logged_certificate():
    runner, _, _ = fixture()
    consumed = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda e: consumed.append(deepcopy(e)) or ())
    raw = {'kind': 'cpu_retire', 'schema_version': 'cpu_retire.v2',
        'receipt_id': {'execution': 'real-process', 'sequence': 1}}
    runner.sessions['cpu'].cpu_events = [raw]
    runner._append_external_events('cpu', 1)
    assert consumed[0]['receipt_id']['execution'] == 'local-driver:cpu:1'
    assert raw['receipt_id']['execution'] == 'real-process'


def test_raw_uart_precedes_consumption_certificate_for_read_linker():
    runner, _, _ = fixture()
    consumed = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda e: consumed.append(deepcopy(e)) or ())
    runner._uart_consumption_tracker = SimpleNamespace(consume=lambda e: ({
        'kind': 'uart_consumption_match', 'proof_scope': 'uart_fifo_read_consumption'},))
    raw = {'event_id': 1, 'kind': 'uart_rdata_access'}
    runner._events.append(raw)
    runner._append_uart_consumption(raw)
    assert [e['kind'] for e in consumed] == ['uart_rdata_access', 'uart_consumption_match']
    assert consumed[1]['producer_event_id'] == 1


def test_controlled_entry_receives_raw_cpu_and_native_certificates():
    runner, _, native = fixture()
    consumed = []
    runner._controlled_irq_entry_join = SimpleNamespace(consume=lambda e: consumed.append(deepcopy(e)) or ())
    runner._native_irq_join.consume = lambda e: ({'kind': 'uart_consumption_match',
        'proof_scope': 'cpu_external_irq_taken'},) if e['kind'] == 'cpu_external_irq_taken' else ()
    runner.sessions['cpu'].cpu_events = [{'kind': 'instr_response'},
        {'kind': 'cpu_external_irq_taken'}]
    runner._append_external_events('cpu', 1)
    assert [e['kind'] for e in consumed] == ['instr_response', 'cpu_external_irq_taken', 'uart_consumption_match']
    assert consumed[2]['producer_event_id'] == consumed[1]['event_id']
