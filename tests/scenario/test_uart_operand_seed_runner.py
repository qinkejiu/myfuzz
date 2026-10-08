"""The operand seed sees the same measured stream as the retired-read linker."""
from copy import deepcopy
from types import SimpleNamespace

from tests.scenario.test_uart_native_irq_runner import fixture


def test_runner_forwards_raw_and_internal_certificate_to_operand_seed():
    runner, _, _ = fixture()
    seen = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda event: ({
        'kind': 'uart_retired_read_match', 'status': 'accepted'},))
    runner._uart_operand_seed_tracker = SimpleNamespace(
        consume=lambda event: seen.append(deepcopy(event)) or ({
            'kind': 'uart_operand_seed', 'status': 'accepted'},))

    raw = {'event_id': 1, 'kind': 'uart_rdata_access', 'source_component': 'uart'}
    runner._events.append(raw)
    runner._append_uart_retired_read(raw)

    assert [event['kind'] for event in seen] == ['uart_rdata_access']
    assert [event['kind'] for event in runner.events] == [
        'uart_rdata_access', 'uart_retired_read_match', 'uart_operand_seed']
    assert runner.events[-1]['producer_event_id'] == raw['event_id']


def test_operand_seed_does_not_consume_saved_accepted_read_label():
    runner, _, _ = fixture()
    seen = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda event: ())
    runner._uart_operand_seed_tracker = SimpleNamespace(
        consume=lambda event: seen.append(event) or ())

    forged = {'event_id': 1, 'kind': 'uart_retired_read_match',
        'status': 'accepted'}
    runner._events.append(forged)
    runner._append_uart_retired_read(forged)

    assert seen == []
