"""Receipt samples, including CPU-driven target clocks, are consumed once."""
import unittest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.scheduler import DependencyScheduler
from tests.scenario.test_irq_delivery import RecordingSession


class SampleGpio(RecordingSession):
    def __init__(self):
        super().__init__()
        self.samples = []
        self.accesses = 0

    def advance(self, levels):
        previous = 0
        for level in levels:
            self.local_ticks += 1
            self.samples.append({'local_tick': self.local_ticks,
                                 'pre': {'interrupt': previous, 'gpio_out': previous},
                                 'post': {'interrupt': level, 'gpio_out': level}})
            previous = level

    def write_register(self, offset, value, *, be=15):
        self.accesses += 1
        self.advance((0, 1, 0))

    def drain_tick_samples(self):
        result, self.samples = self.samples, []
        return result

    def step_local(self, inputs):
        self.advance((0,))
        return {'irq': 0, 'gpio_out': 0}


class ReceiptDeliveryTests(unittest.TestCase):
    def make_runner(self, *, begin=True):
        gpio = SampleGpio()
        router = DataflowRouter((DeviceWindow('gpio', 0x1000, 4096, gpio),))
        cpu = RecordingSession()
        cpu.router = router
        ledger = TransactionLedger()
        def step(inputs):
            cpu.inputs.append(dict(inputs))
            cpu.local_ticks += 1
            key = TransactionKey('exec', 'case', 'cpu', 0, 'data', cpu.local_ticks)
            router.transact(ledger, key, address=0x1000, write=True,
                            wdata=1, be=15, beat_bytes=4)
            return {}
        cpu.step_local = step
        sink = RecordingSession()
        irq = Binding('gpio', 'irq', 'cpu', 'irq', 1)
        out = Binding('gpio', 'gpio_out', 'sink', 'pins', 1)
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('sink', 'pins', 1)),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'gpio.irq'),
             InputOwner('sink', 'pins', 0, 1, 'bound', 'gpio.gpio_out')))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio, 'sink': sink},
                                ownership=ownership, bindings=(irq, out),
                                irq_pulses={irq: 1})
        if begin:
            runner.begin_test('samples')
        return runner, cpu, gpio

    def test_scheduler_treats_tick_samples_as_part_of_one_step(self):
        runner, _, _ = self.make_runner(begin=False)
        genome = ScenarioGenome(testcase_id='samples', direction='CPU_TO_IP',
                                path_id='native-samples',
                                schedule_order=('gpio', 'cpu', 'sink'),
                                max_steps=3, actions=())
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual('complete', result.status)

    def test_cpu_apb_access_preserves_intermediate_irq_and_output(self):
        runner, cpu, gpio = self.make_runner()
        runner.step('cpu')
        starts = [e for e in runner.events if e.get('kind') == 'source_start']
        self.assertEqual([2], [e['source_tick'] for e in starts])
        self.assertEqual([3], [e['source_tick'] for e in runner.events
                               if e.get('kind') == 'source_end'])
        self.assertEqual([0, 0, 0, 1, 1, 0],
                         [e['value'] for e in runner.events
                          if e.get('kind') == 'dataflow_delivery'])
        self.assertEqual([], gpio.samples)
        runner.step('sink')
        self.assertEqual(0, runner.sessions['sink'].inputs[-1]['pins'])
        cpu.step_local = lambda inputs: RecordingSession.step_local(cpu, inputs)
        runner.step('cpu')
        self.assertEqual([0, 1], [i['irq'] for i in cpu.inputs])

    def test_cached_command_does_not_repeat_samples_or_target_effect(self):
        runner, cpu, gpio = self.make_runner()
        payload = runner._effective_inputs('cpu')
        receipt = runner.execute_step('cpu', execution_id=runner.execution_id,
                                      command_sequence=1, epoch=0,
                                      expected_inputs=payload)
        events = tuple(runner.events)
        replay = runner.execute_step('cpu', execution_id=runner.execution_id,
                                     command_sequence=1, epoch=0,
                                     expected_inputs=payload)
        self.assertEqual(receipt, replay)
        self.assertEqual(events, tuple(runner.events))
        self.assertEqual(1, gpio.accesses)
        self.assertEqual(1, sum(e.get('kind') == 'source_start' for e in events))

    def test_direct_gpio_step_uses_pre_post_not_final_level(self):
        runner, cpu, gpio = self.make_runner()
        def step(inputs):
            gpio.advance((1,))
            return {'irq': 0, 'gpio_out': 0}
        gpio.step_local = step
        runner.step('gpio')
        self.assertEqual(1, sum(e.get('kind') == 'source_start' for e in runner.events))
        self.assertEqual(1, runner._inputs['sink']['pins'])

    def test_queued_access_samples_after_target_step_are_consumed(self):
        runner, cpu, gpio = self.make_runner()
        ledger = TransactionLedger()
        key = TransactionKey('queued', 'case', 'cpu', 0, 'data', 1)
        replies = []
        cpu.router.enqueue(ledger, key, address=0x1000, write=True,
                           wdata=1, be=15, beat_bytes=4, callback=replies.append)
        runner.step('gpio')
        self.assertEqual([(0, 0)], replies)
        self.assertEqual([3], [e['source_tick'] for e in runner.events
                               if e.get('kind') == 'source_start'])
        self.assertEqual([], gpio.samples)
        self.assertEqual(4, runner.local_ticks['gpio'])

    def test_failure_retains_actual_target_samples_without_cpu_acceptance(self):
        runner, cpu, gpio = self.make_runner()
        original = cpu.step_local
        def fail(inputs):
            original(inputs)
            raise RuntimeError('lost CPU reply after target reply')
        cpu.step_local = fail
        with self.assertRaisesRegex(RuntimeError, 'lost CPU reply'):
            runner.step('cpu')
        self.assertEqual(1, sum(e.get('kind') == 'source_start' for e in runner.events))
        self.assertEqual(0, sum(e.get('kind') == 'cpu_irq_taken' for e in runner.events))
        self.assertEqual(0, runner.final_state_document()['irq_delivery'][0]['last_cpu_tick'])
        self.assertEqual([], gpio.samples)

    def test_zero_irq_receipts_do_not_create_expected_interrupt(self):
        runner, cpu, gpio = self.make_runner()
        gpio.write_register = lambda *args, **kwargs: gpio.advance((0, 0, 0))
        runner.step('cpu')
        self.assertFalse(any(e.get('kind') == 'source_start' for e in runner.events))
        self.assertEqual(0, runner._effective_inputs('cpu')['irq'])

    def test_two_real_native_pulses_in_one_access_report_overrun(self):
        runner, cpu, gpio = self.make_runner()
        gpio.write_register = lambda *args, **kwargs: gpio.advance((1, 0, 1, 0))
        runner.step('cpu')
        self.assertEqual('unsupported_irq_overrun', runner.failure_status)
        self.assertEqual(2, sum(e.get('kind') == 'source_start' for e in runner.events))
        self.assertEqual(1, sum(e.get('kind') == 'irq_overrun' for e in runner.events))

    def test_repeated_or_backwards_sample_tick_is_rejected(self):
        runner, cpu, gpio = self.make_runner()
        runner.step('gpio')
        sample = {'local_tick': 1, 'pre': {'interrupt': 1}, 'post': {'interrupt': 0}}
        gpio.step_local = lambda inputs: gpio.samples.append(sample) or {'irq': 0}
        with self.assertRaisesRegex(ValueError, 'tick sample'):
            runner.step('gpio')


if __name__ == '__main__':
    unittest.main()
