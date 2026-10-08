"""Runner bridges exact native resources; fixture metadata is not RTL evidence."""
from types import SimpleNamespace

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


class Session:
    reset_epoch = 0
    def identity_document(self): return {'fixture': 'native_irq_runner.v1'}
    def begin_case(self, testcase): pass
    def end_case(self): pass
    def step_local(self, inputs): return {}


def fixture():
    uart, cpu = Session(), Session()
    uart.uart_fifo_observation_enabled = True
    cpu.native_irq_receipts_enabled = True
    ownership = compile_ownership(
        (InputField('uart', 'uart_rx_byte', 8), InputField('cpu', 'irq', 1)),
        (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'rx'),
         InputOwner('cpu', 'irq', 0, 1, 'bound', 'uart.uart_rx_watermark')))
    runner = ScenarioRunner(sessions={'uart': uart, 'cpu': cpu}, ownership=ownership,
        bindings=(Binding('uart', 'uart_rx_watermark', 'cpu', 'irq', 1),))
    resources, consumed = {}, []
    runner._native_irq_join = SimpleNamespace(
        output_at=lambda *key: resources.get(key),
        consume=lambda event: consumed.append(event) or ())
    return runner, resources, consumed


def deliver(runner, resources, *, tick, phase, value, version, available=True):
    event_id = len(runner.events) + 1
    runner._events.append({'event_id': event_id, 'kind': 'local_tick_sample',
        'component': 'uart', 'local_tick': tick, 'phase': phase,
        'outputs': {'uart_rx_watermark': value}})
    if available:
        resources[('uart', 0, tick, phase, 'rx_watermark')] = {
            'source_output_key': ['uart', 0, 'rx_watermark', version],
            'source_observation_event_id': event_id,
            'source_receipt_ref': {'command_scope': {'component': 'uart',
                'reset_epoch': 0, 'command_sequence': tick}, 'local_tick': tick},
            'value': value}
    runner._route_observed_outputs('uart', {'uart_rx_watermark': value}, event_id, tick, phase)


def test_native_delivery_uses_exact_phase_and_latest_applied_resource():
    runner, resources, consumed = fixture()
    deliver(runner, resources, tick=1, phase='pre', value=1, version=7)
    native = [e for e in runner.events if e.get('kind') == 'native_irq_binding_delivery']
    assert len(native) == 1
    assert native[0]['source_output_key'] == ['uart', 0, 'rx_watermark', 7]
    assert native[0]['dataflow_delivery_event_id'] < native[0]['event_id']
    deliver(runner, resources, tick=1, phase='post', value=0, version=8)
    assert runner._native_irq_input_context('cpu', 0)['source_output_key'] == ['uart', 0, 'rx_watermark', 8]
    assert runner._native_irq_input_context('cpu', 1) is None
    assert consumed[-1]['value'] == 0


def test_missing_exact_resource_clears_prior_delivery_without_guessing():
    runner, resources, consumed = fixture()
    deliver(runner, resources, tick=1, phase='pre', value=1, version=7)
    deliver(runner, resources, tick=2, phase='post', value=1, version=8, available=False)
    assert runner._native_irq_input_context('cpu', 1) is None
    assert len([e for e in runner.events if e.get('kind') == 'native_irq_binding_delivery']) == 1


def test_equal_levels_preserve_distinct_applied_version():
    runner, resources, consumed = fixture()
    deliver(runner, resources, tick=1, phase='post', value=1, version=7)
    before = runner._native_irq_input_context('cpu', 1)
    deliver(runner, resources, tick=2, phase='post', value=1, version=8)
    after = runner._native_irq_input_context('cpu', 1)
    assert before['binding_delivery_event_id'] != after['binding_delivery_event_id']
    assert after['source_output_key'] == ['uart', 0, 'rx_watermark', 8]


def test_cpu_take_bridges_exact_sample_without_changing_raw_nonce():
    from copy import deepcopy
    runner, resources, consumed = fixture()
    scope = {'component': 'cpu', 'reset_epoch': 0, 'command_sequence': 1}
    sample = {'kind': 'cpu_external_irq_sample', 'reset_epoch': 0, 'local_tick': 1,
              'command_scope': scope, 'receipt_id': {'execution': 'actual-driver', 'sequence': 1}}
    taken = {**deepcopy(sample), 'kind': 'cpu_external_irq_taken',
             'sample_ref': {'command_scope': deepcopy(scope), 'local_tick': 1},
             'sample_event_id': 999}
    runner.sessions['cpu'].cpu_events = [sample, taken]
    runner._append_external_events('cpu', 1)
    assert consumed[-1]['sample_event_id'] == consumed[-2]['event_id']
    assert sample['receipt_id']['execution'] == 'actual-driver'
    assert consumed[-1]['receipt_id']['execution'] == 'local-driver:cpu:1'
    malformed = deepcopy(taken)
    malformed['sample_ref']['local_tick'] = True
    runner.sessions['cpu'].cpu_events.append(malformed)
    runner._append_external_events('cpu', 1)
    assert 'sample_event_id' not in consumed[-1]


def test_cpu_step_stages_only_the_last_actually_applied_irq_delivery():
    runner, resources, consumed = fixture()
    contexts = []
    runner.sessions['cpu'].set_next_irq_input_context = contexts.append
    runner.begin_test('native-context')
    deliver(runner, resources, tick=1, phase='pre', value=1, version=7)
    deliver(runner, resources, tick=1, phase='post', value=0, version=8)
    runner._step_once('cpu')
    assert contexts[-1]['expected_input'] == 0
    assert contexts[-1]['source_output_key'] == ['uart', 0, 'rx_watermark', 8]
    runner.sessions['cpu'].reset_epoch = 1
    runner._step_once('cpu')
    assert contexts[-1] is None
