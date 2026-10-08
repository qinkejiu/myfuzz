"""Independent negative review of Runner native receipt bridges (software only)."""
from copy import deepcopy
import pytest
from tests.scenario.test_uart_native_irq_runner import fixture, deliver


def observations():
    scope = {'component': 'cpu', 'reset_epoch': 0, 'command_sequence': 1}
    sample = {'kind': 'cpu_external_irq_sample', 'reset_epoch': 0, 'local_tick': 1,
              'command_scope': scope, 'receipt_id': {'execution': 'a' * 32, 'sequence': 1}}
    taken = {**deepcopy(sample), 'kind': 'cpu_external_irq_taken',
             'sample_ref': {'command_scope': deepcopy(scope), 'local_tick': 1},
             'sample_event_id': 999}
    return sample, taken


@pytest.mark.parametrize('path,value', [
    (('receipt_id', 'execution'), 'b' * 32),
    (('receipt_id', 'sequence'), True),
    (('receipt_id', 'sequence'), 1.0),
    (('command_scope', 'reset_epoch'), True),
    (('command_scope', 'command_sequence'), 1.0),
    (('sample_ref', 'local_tick'), True),
    (('sample_ref', 'local_tick'), 1.0),
    (('reset_epoch',), False),
    (('local_tick',), 1.0),
])
def test_changed_receipt_scope_cannot_bridge_claimed_sample_id(path, value):
    runner, resources, consumed = fixture()
    sample, taken = observations()
    cursor = taken
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    runner.sessions['cpu'].cpu_events = [sample, taken]
    runner._append_external_events('cpu', 1)
    assert 'sample_event_id' not in consumed[-1]
    assert sample['receipt_id']['execution'] == 'a' * 32


def test_cpu_reset_event_clears_last_sample_and_binding_context():
    runner, resources, consumed = fixture()
    deliver(runner, resources, tick=1, phase='post', value=1, version=4)
    sample, taken = observations()
    runner.sessions['cpu'].cpu_events = [sample, {'kind': 'cpu_reset', 'reset_epoch': 1}, taken]
    runner._append_external_events('cpu', 1)
    assert not runner._native_cpu_samples
    assert runner._native_irq_input_context('cpu', 1) is None
    assert 'sample_event_id' not in consumed[-1]


def test_unknown_initial_and_last_missing_resource_stage_none():
    runner, resources, consumed = fixture()
    staged = []
    runner.sessions['cpu'].set_next_irq_input_context = staged.append
    runner.begin_test('review')
    runner._step_once('cpu')
    assert staged == [None]
    deliver(runner, resources, tick=1, phase='pre', value=1, version=4)
    deliver(runner, resources, tick=1, phase='post', value=1, version=5, available=False)
    runner._step_once('cpu')
    assert staged[-1] is None


def test_context_return_is_detached_and_noninteger_input_is_unknown():
    runner, resources, consumed = fixture()
    deliver(runner, resources, tick=1, phase='post', value=1, version=4)
    context = runner._native_irq_input_context('cpu', 1)
    context['source_output_key'][3] = 999
    assert runner._native_irq_input_context('cpu', 1)['source_output_key'][3] == 4
    assert runner._native_irq_input_context('cpu', True) is None
    assert runner._native_irq_input_context('cpu', 1.0) is None


def test_partial_reset_failure_stops_future_steps():
    runner, resources, consumed = fixture()
    runner.begin_test('partial-reset-review')
    deliver(runner, resources, tick=1, phase='post', value=1, version=4)
    def reset_cpu():
        runner.sessions['cpu'].reset_epoch = 1
        return {'cancelled_responses': 0}
    def fail_uart():
        raise RuntimeError('partial reset')
    runner.sessions['cpu'].reset_local = reset_cpu
    runner.sessions['uart'].reset_local = fail_uart
    with pytest.raises(RuntimeError, match='partial reset'):
        runner.reset_all('warm_all')
    assert runner._native_irq_input_context('cpu', 1) is None
    with pytest.raises(RuntimeError):
        runner._step_once('cpu')
    assert runner.events[-1]['kind'] == 'reset_failure'
