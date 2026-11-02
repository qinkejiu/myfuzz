"""Real WBUART SETUP Wishbone target: stable word write/read and fresh replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedWishboneRegisterSession, compile_generated_register_ownership,
    load_local_harness_request, plan_local_harness, render_local_driver,
    render_local_harness, render_local_runtime, verify_local_source_lock,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'


def request():
    return load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='uart_setup', reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
            endpoint_id='uart.bus', template_id='target.wishbone',
            template_version='1', variant_id='word-addressed-registered-ack',
            max_outstanding=1)],
            'fixed_inputs': [
                dict(endpoint_id='uart.pins', role='rx', value=1),
                dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))


def artifact():
    plan = plan_local_harness(request(), base_dir=ROOT)
    top = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class WishboneSetupStorageRealTests(unittest.TestCase):
    def test_setup_word_write_read_persistent_fresh(self):
        generated = artifact()
        self.assertEqual('wishbone_register_observe',
                         generated.runtime_document['kind'])
        trace = generated.runtime_document['base_protocol_trace']
        self.assertEqual('wishbone', trace['protocol'])
        self.assertEqual('uart.bus', trace['endpoint_id'])
        self.assertTrue({'cyc', 'stb', 'we', 'adr', 'ack', 'stall', 'dat_w',
                         'sel', 'dat_r'} <= set(trace['signals']))

        with tempfile.TemporaryDirectory(prefix='wishbone-setup-') as directory:
            work = Path(directory)
            sessions = []

            def factory():
                session = GeneratedWishboneRegisterSession(
                    generated, base_dir=ROOT, cache_dir=work / 'build',
                    setup_writes=((0, 0x55),), probe_offsets=(0,))
                sessions.append(session)
                return ScenarioRunner(
                    sessions={'dut': session},
                    ownership=compile_generated_register_ownership(
                        {'dut': generated}), bindings=())

            genome = ScenarioGenome(
                testcase_id='wishbone-setup-storage', direction='IP_TO_IP',
                path_id='wishbone-register-observe', schedule_order=('dut',),
                max_steps=8, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertEqual(2, len(sessions[0].local_transactions))
            self.assertEqual(0x55,
                             sessions[0].local_transactions[-1]['read_value'] & 0x7fffffff)
            self.assertTrue(any('o_uart_tx' in event.get('outputs', {})
                                for event in trace.events))
            strobes = [event for event in trace.events
                       if event.get('kind') == 'local_tick_sample'
                       and event.get('phase') == 'pre'
                       and event.get('outputs', {}).get('backend', {}).get('reg_target_stb')]
            self.assertEqual(2, len(strobes))
            self.assertGreater(sessions[0].local_ticks, 8)
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
