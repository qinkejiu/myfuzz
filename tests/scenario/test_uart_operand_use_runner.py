"""A later operand-use join receives measured records, never saved seed labels."""
from copy import deepcopy
from types import SimpleNamespace

from tests.scenario.test_uart_native_irq_runner import fixture


def test_operand_use_receives_raw_retirement_before_logged_read_and_seed():
    runner, _, _ = fixture()
    seen = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda event: ({
        'kind': 'uart_retired_read_match', 'status': 'accepted'},))
    runner._uart_operand_seed_tracker = SimpleNamespace(consume=lambda event: ({
        'kind': 'uart_operand_seed', 'status': 'accepted'},))
    runner._uart_operand_use_tracker = SimpleNamespace(
        consume=lambda event: seen.append(deepcopy(event)) or ({
            'kind': 'uart_operand_use', 'status': 'accepted'},))

    raw = {'event_id': 1, 'kind': 'cpu_retire', 'source_component': 'cpu'}
    runner._events.append(raw)
    runner._append_uart_retired_read(raw)

    assert [event['kind'] for event in seen] == ['cpu_retire']
    assert [event['kind'] for event in runner.events] == [
        'cpu_retire', 'uart_retired_read_match', 'uart_operand_seed',
        'uart_operand_use']
    assert runner.events[-1]['producer_event_id'] == 1


def test_saved_seed_label_cannot_be_forwarded_to_operand_use():
    runner, _, _ = fixture()
    seen = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda event: ())
    runner._uart_operand_seed_tracker = SimpleNamespace(consume=lambda event: ())
    runner._uart_operand_use_tracker = SimpleNamespace(
        consume=lambda event: seen.append(event) or ())
    forged = {'event_id': 1, 'kind': 'uart_operand_seed', 'status': 'accepted'}
    runner._events.append(forged)
    runner._append_uart_retired_read(forged)
    assert seen == []
