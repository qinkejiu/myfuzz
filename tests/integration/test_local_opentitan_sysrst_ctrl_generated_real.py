"""Real OpenTitan sysrst_ctrl key0 H2L event, native IRQ and fresh replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSysrstCtrlSession,
    compile_generated_register_ownership, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/opentitan_sysrst_ctrl_local/component_profile.json'
KEY0 = 'opentitan_sysrst_ctrl.pins.key0'


def _artifact():
    fixed = [
        ('ac_present', 0), ('ec_rst_l', 1), ('key1', 0), ('key2', 0),
        ('pwrb', 0), ('lid_open', 0), ('flash_wp_l', 1),
    ]
    request = load_local_harness_request({
        'schema_version': 'local_harness.v2', 'profile_path': PROFILE,
        'instance_id': 'sysrst_ctrl_generated', 'reset_assert_ticks': 120,
        'reset_release_ticks': 1, 'max_wait_cycles': 16,
        'tuning': {
            'endpoint_policies': [dict(endpoint_id='opentitan_sysrst_ctrl.mmio',
                template_id='target.tl-ul', template_version='1',
                variant_id='user-integrity', max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id='opentitan_sysrst_ctrl.pins',
                role=role, value=value) for role, value in fixed],
            'environment_bindings': [dict(endpoint_id='opentitan_sysrst_ctrl.pins',
                role='key0', source_id='sysrst_key0_environment')],
        },
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned OpenTitan RTL')
class GeneratedOpentitanSysrstCtrlRealTests(unittest.TestCase):
    def test_key0_h2l_status_native_irq_and_fresh_replay(self):
        artifact = _artifact()
        schedule = artifact.runtime_document['clock_schedule']
        aon = next(row for row in schedule['clocks'] if row['domain'] == 'aon')
        core = next(row for row in schedule['clocks'] if row['domain'] == 'core')
        self.assertEqual((120, 60), (aon['ratio'], aon['first_rising_fast_tick']))
        self.assertEqual((1, 1), (core['ratio'], core['first_rising_fast_tick']))
        ownership = compile_generated_register_ownership({'sysrst': artifact})
        genome = ScenarioGenome(testcase_id='opentitan-sysrst-key0-h2l',
            direction='IP_TO_CPU', path_id='key0-pin-to-native-irq',
            schedule_order=('sysrst',), max_steps=1600,
            actions=(
                Action('key0_start_high', 'sysrst', KEY0, 1, 'IP_TO_CPU',
                       Trigger('AFTER_OUTPUT', 'sysrst', 'intr_event_detected_o', 1, 0)),
                Action('key0_h2l', 'sysrst', KEY0, 0, 'IP_TO_CPU',
                       Trigger('AFTER_OUTPUT', 'sysrst', 'intr_event_detected_o', 1, 0),
                       delay_component='sysrst', delay_ticks=360),
            ))
        sessions = []

        def factory():
            session = GeneratedOpentitanSysrstCtrlSession(
                artifact, base_dir=ROOT, cache_dir=Path(self._tmp) / 'cache')
            sessions.append(session)
            return ScenarioRunner(sessions={'sysrst': session},
                                  ownership=ownership, bindings=())

        with tempfile.TemporaryDirectory(prefix='myfuzz-generated-sysrst-') as directory:
            self._tmp = directory
            trace = record_scenario(genome, factory)
            self.assertEqual('complete', trace.status, trace.events[-5:])
            transactions = [event for event in trace.events
                            if event.get('kind') == 'local_register_transaction']
            initial = {(event.get('offset'), event.get('read_value'))
                       for event in transactions if not event.get('write')
                       and event.get('reason') is None}
            self.assertIn((0xa8, 0), initial)
            self.assertIn((0x00, 0), initial)
            initial_probe_ids = [event['event_id'] for event in transactions
                                 if not event.get('write')
                                 and event.get('offset') in (0xa8, 0x00)
                                 and event.get('reason') is None]
            high_action = next(event for event in trace.events
                               if event.get('kind') == 'source_injection'
                               and event.get('action_id') == 'key0_start_high')
            high_baseline = next(event for event in transactions
                                 if event.get('reason') == 'key0_high_pin_readback')
            self.assertTrue(initial_probe_ids)
            self.assertLess(max(initial_probe_ids), high_baseline['event_id'])
            self.assertLess(max(initial_probe_ids), high_action['event_id'])
            high_pin = [event for event in transactions
                        if event.get('reason') == 'key0_high_pin_readback']
            self.assertEqual(1, len(high_pin))
            self.assertEqual(2, high_pin[0]['read_value'] & 2)
            low_pin = [event for event in transactions
                       if event.get('reason') == 'key0_low_pin_readback']
            self.assertEqual(1, len(low_pin))
            self.assertEqual(0, low_pin[0]['read_value'] & 2)
            native_irq = [event for event in trace.events
                          if event.get('kind') == 'local_tick_sample'
                          and event.get('component') == 'sysrst'
                          and event.get('outputs', {}).get('intr_event_detected_o') == 1]
            self.assertTrue(native_irq, 'the RTL native aggregate IRQ was never observed')
            low_action = next(event for event in trace.events
                              if event.get('kind') == 'source_injection'
                              and event.get('action_id') == 'key0_h2l')
            before_irq = [event for event in trace.events
                          if event.get('kind') == 'local_tick_sample'
                          and event.get('component') == 'sysrst'
                          and event['event_id'] < low_action['event_id']]
            self.assertTrue(before_irq)
            self.assertTrue(all(event.get('outputs', {}).get('intr_event_detected_o') == 0
                                for event in before_irq))
            self.assertGreater(native_irq[0]['event_id'], low_action['event_id'])
            post = [event for event in transactions
                    if event.get('reason') == 'native_irq_readback']
            self.assertEqual([(0xa8, 2), (0x00, 1), (0x40, 0xc0)],
                [(event['offset'], event['read_value']) for event in post])
            self.assertTrue(any(event.get('kind') == 'source_injection'
                                and event.get('port') == KEY0
                                and event.get('value') == 0 for event in trace.events))
            replay = replay_scenario(genome, factory, trace)
            self.assertTrue(replay.matches, replay)
            self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
