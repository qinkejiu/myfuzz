"""Repeated source actions remain distinct in a reset-free online transcript."""

import json
import hashlib
from dataclasses import replace
import unittest

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession, replay_online_session


class _SerialHarness:
    def __init__(self):
        self.local_ticks = 0
        self.started = False
        self.queued = []

    def begin_case(self, testcase_id):
        self.local_ticks = 0

    def admit_source_event(self, port, value, *, bit_offset, width, action_id):
        if self.started:
            self.queued.append(value)
            return self.local_ticks + 1
        return None

    def step_local(self, inputs):
        if not self.started:
            self.queued.append(inputs['rx'])
            self.started = True
        self.local_ticks += 1
        value = self.queued.pop(0) if self.queued else -1
        return {'rx_data': value}

    def end_case(self):
        pass


def _factory():
    ownership = compile_ownership(
        (InputField('uart', 'rx', 8),),
        (InputOwner('uart', 'rx', 0, 8, 'source', 'external'),))
    return ScenarioRunner(sessions={'uart': _SerialHarness()},
                          ownership=ownership, bindings=())


def _template():
    return ScenarioGenome(testcase_id='uart-online', direction='IP_TO_CPU',
        path_id='uart-rx', schedule_order=('uart',), max_steps=2, actions=())


class OnlineUartSourceEventTests(unittest.TestCase):
    def test_each_action_queues_one_frame_and_replay_checks_schedule(self):
        session = ScenarioSession(_template(), _factory())
        session.begin()
        for index, value in enumerate((0x5a, 0xa6, 0xa6)):
            case = OnlineCase(f'case-{index}', 'IP_TO_CPU', 'uart-rx',
                BatchSourceEvent(f'source-{index}', 'uart', 'rx', value),
                (BatchAdvance(('uart',)),))
            receipt = session.submit_case(case)
            self.assertEqual(value, next(event['outputs']['rx_data']
                for event in receipt.events if 'outputs' in event))
        plan = session.encode_plan()
        trace = session.finish()
        source_records = [event for event in trace.events
                          if event.get('kind') == 'source_injection']
        self.assertEqual([None, 2, 3],
                         [event.get('scheduled_local_tick') for event in source_records])
        self.assertEqual([None, 2, 3], [case['source'].get('scheduled_local_tick')
            for case in json.loads(plan)['cases']])
        replay = replay_online_session(plan, _factory, trace)
        self.assertTrue(replay.matches, replay.difference_context)
        changed = json.loads(plan)
        changed['cases'][1]['source']['scheduled_local_tick'] += 1
        changed_plan = json.dumps(changed, sort_keys=True, separators=(',', ':')).encode()
        changed_identity = replace(trace,
            genome_sha256=hashlib.sha256(changed_plan).hexdigest())
        mismatch = replay_online_session(changed_plan, _factory, changed_identity)
        self.assertFalse(mismatch.matches)

    def test_failed_source_hook_leaves_runner_input_and_events_unchanged(self):
        runner = _factory()
        runner.begin_test('failed-hook')
        serial = runner.sessions['uart']
        serial.started = True
        serial.admit_source_event = lambda *args, **kwargs: (_ for _ in ()).throw(
            ValueError('bad source event'))
        count = runner.event_count
        with self.assertRaisesRegex(ValueError, 'bad source event'):
            runner.inject_source('uart', 'rx', 0x5a, direction='IP_TO_CPU',
                                 action_id='rejected')
        self.assertEqual(count, runner.event_count)
        self.assertEqual({}, runner._inputs['uart'])
        runner.finalize()


if __name__ == '__main__':
    unittest.main()
