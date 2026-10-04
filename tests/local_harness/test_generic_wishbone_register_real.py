"""One Wishbone register template on two pinned, physically different targets."""
from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedWishboneRegisterSession, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.local_harness.wishbone_register_template import register_observe_policy


ROOT = Path(__file__).resolve().parents[2]


def request(name, *, fixed=()):
    endpoint = 'timer.bus' if name == 'zipcpu_timer' else 'uart.bus'
    variant = ('addressless-select-ignored' if name == 'zipcpu_timer'
               else 'word-addressed-registered-ack')
    return load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path=f'configs/peripherals/{name}/component_profile.json',
        instance_id='generic_' + name, reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id=endpoint,
            template_id='target.wishbone', template_version='1',
            variant_id=variant, max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id=e, role=r, value=v)
                             for e, r, v in fixed]}))


def artifact(req):
    plan = plan_local_harness(req, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


class GenericWishboneContractTests(unittest.TestCase):
    def test_plan_policy_rejects_missing_stall_before_runtime_render(self):
        for name in ('zipcpu_timer', 'zipcpu_uart'):
            with self.subTest(name=name):
                plan = plan_local_harness(request(name), base_dir=ROOT)
                endpoint = next(e for e in plan.binding.endpoints
                                if e.protocol == ('wishbone', 'classic'))
                no_stall = replace(endpoint,
                    fields=tuple(field for field in endpoint.fields if field.role != 'stall'))
                bad = replace(plan, binding=replace(plan.binding, endpoints=tuple(
                    no_stall if e.endpoint_id == endpoint.endpoint_id else e
                    for e in plan.binding.endpoints)))
                with self.assertRaisesRegex(ValueError, 'template-selection-refused'):
                    register_observe_policy(bad)

    def test_two_variants_share_one_kind_and_unowned_pins_fail_closed(self):
        timer = artifact(request('zipcpu_timer'))
        self.assertEqual('wishbone_register_observe', timer.runtime_document['kind'])
        with self.assertRaisesRegex(ValueError, 'unowned-input'):
            artifact(request('zipcpu_uart'))
        uart = artifact(request('zipcpu_uart', fixed=(
            ('uart.pins', 'rx', 1), ('uart.pins', 'cts_n', 0))))
        self.assertEqual(timer.runtime_document['kind'], uart.runtime_document['kind'])
        self.assertEqual({'rx', 'cts_n'},
                         {row['role'] for row in uart.runtime_document['fixed_physical_inputs']})
        self.assertEqual('wishbone_register_only_pin_observe_no_serial',
                         uart.runtime_document['functional_scope'])


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericWishboneRealTests(unittest.TestCase):
    def test_timer_and_uart_registers_and_fresh_replay(self):
        cases = (
            ('zipcpu_timer', (), ((0, 256),), (0,), 'o_int'),
            ('zipcpu_uart', (('uart.pins', 'rx', 1),
                             ('uart.pins', 'cts_n', 0)),
             ((0, 25),), (0,), 'o_uart_tx'),
        )
        with tempfile.TemporaryDirectory(prefix='generic-wb-') as directory:
            work = Path(directory)
            for name, fixed, writes, probes, observed in cases:
                with self.subTest(name=name):
                    generated = artifact(request(name, fixed=fixed))
                    sessions = []

                    def factory():
                        session = GeneratedWishboneRegisterSession(generated,
                            base_dir=ROOT, cache_dir=work / name,
                            setup_writes=writes, probe_offsets=probes)
                        sessions.append(session)
                        return ScenarioRunner(sessions={'dut': session},
                            ownership=compile_ownership((), ()), bindings=())

                    genome = ScenarioGenome(testcase_id='generic-' + name,
                        direction='IP_TO_IP', path_id='wishbone-register-observe',
                        schedule_order=('dut',), max_steps=8, actions=())
                    bundle = work / ('evidence-' + name)
                    trace = save_evidence_bundle(genome, factory, bundle, budget=None)
                    self.assertEqual('complete', trace.status, trace.events[-3:])
                    self.assertEqual(2, len(sessions[0].local_transactions))
                    read_value = sessions[0].local_transactions[-1]['read_value']
                    if name == 'zipcpu_timer':
                        self.assertTrue(0 < read_value < 256)
                    else:
                        self.assertEqual(25, read_value & 0xffffff)
                    self.assertTrue(any(observed in e.get('outputs', {})
                                        for e in trace.events))
                    strobes = [e for e in trace.events
                               if e.get('kind') == 'local_tick_sample'
                               and e.get('phase') == 'pre'
                               and e.get('outputs', {}).get('backend', {}).get('reg_target_stb')]
                    self.assertEqual(2, len(strobes))
                    self.assertGreater(sessions[0].local_ticks, 8)
                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
